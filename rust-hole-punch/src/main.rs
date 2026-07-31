mod protocol;
mod session;
mod stun;

use protocol::{Candidate, CandidateKind, PeerDescription, ProtocolError};
use session::{Command, Event, NetworkConfig, Stats};
use std::env;
use std::io::{self, BufRead};
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;

type AppResult<T> = Result<T, Box<dyn std::error::Error>>;
const MAX_INPUT_LINE: usize = 2048;

#[derive(Debug)]
struct Cli {
    stun_server: String,
    stun_only: bool,
}

fn main() -> AppResult<()> {
    let cli = parse_cli()?;
    let stun_servers = stun::resolve_ipv4_all(&cli.stun_server)?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let local_socket = socket.local_addr()?;

    println!("Учебная проверка прямого UDP-пути (HP2)");
    println!("ВНИМАНИЕ: relay и шифрования прикладных данных нет.");
    println!(
        "Session code раскрывает IP-кандидаты и секрет сеанса — отправляйте его только второй стороне."
    );
    println!("Не передавайте через этот PoC пароли, команды, экран или файлы.");
    println!("Внутренний bind: {local_socket} (это не адрес для обмена)");
    println!("STUN {} ...", stun_servers[0]);

    let discovery = stun::discover(&socket, &stun_servers)?;
    let local_candidate = discover_local_candidate(discovery.server, local_socket.port()).ok();
    println!(
        "STUN OK: public candidate {} (сервер {}, RTT {} ms)",
        discovery.public_address,
        discovery.server,
        discovery.rtt.as_millis()
    );
    if let Some(candidate) = local_candidate {
        println!("LAN candidate: {candidate}");
    }

    let mut candidates = vec![Candidate {
        kind: CandidateKind::ServerReflexive,
        address: discovery.public_address,
    }];
    if let Some(address) = local_candidate {
        if address != discovery.public_address {
            candidates.push(Candidate {
                kind: CandidateKind::Host,
                address,
            });
        }
    }
    let mut local_description = PeerDescription::new(candidates)?;

    if cli.stun_only {
        println!("Процесс завершается; этот mapping после выхода использовать нельзя.");
        return Ok(());
    }

    print_code(&local_description, "ТЕКУЩИЙ SESSION CODE");
    println!("Код действует, пока программа открыта и сеть не изменилась.");
    println!("Вставьте код второй машины или команду /help.");

    let (command_tx, command_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();
    let network = session::spawn(
        socket,
        NetworkConfig {
            local: local_description.clone(),
            public_address: discovery.public_address,
            stun_servers,
        },
        command_rx,
        event_tx,
    );

    let (input_tx, input_rx) = mpsc::channel();
    thread::Builder::new()
        .name("stdin-reader".to_owned())
        .spawn(move || read_input(input_tx))?;

    let mut should_stop = false;
    while !should_stop {
        loop {
            match input_rx.try_recv() {
                Ok(InputEvent::Line(line)) => {
                    if handle_input(&line, &command_tx, &mut local_description)? {
                        should_stop = true;
                        break;
                    }
                }
                Ok(InputEvent::TooLong) => {
                    println!("[INPUT] строка длиннее {MAX_INPUT_LINE} байт и отброшена.");
                }
                Ok(InputEvent::Eof) => {
                    should_stop = true;
                    break;
                }
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            }
        }
        if should_stop {
            break;
        }

        match event_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(event) => match event {
                Event::Info(message) => println!("[INFO] {message}"),
                Event::MappingChanged { address } => {
                    replace_public_candidate(&mut local_description, address);
                    println!("[CODE EXPIRED] NAT изменил public mapping на {address}.");
                    print_code(&local_description, "НОВЫЙ SESSION CODE");
                }
                Event::CheckingStarted { candidates } => {
                    println!(
                        "[CHECKING] проверяю {candidates} remote candidates, максимум 30 секунд."
                    );
                }
                Event::Progress { elapsed, stats } => print_progress(elapsed, stats),
                Event::Connected { source, kind, rtt } => println!(
                    "[OK] Получен ответ на наш probe через {} ({source}), RTT {} ms.",
                    kind.label(),
                    rtt.as_millis()
                ),
                Event::PingResult(rtt) => println!("[PING] round-trip {} ms.", rtt.as_millis()),
                Event::Disconnected { reason, stats } => {
                    println!("[DISCONNECTED] {reason}");
                    print_progress(Duration::ZERO, stats);
                    println!("Сессия вернулась в rechecking; данные не передаются.");
                }
                Event::Failed { stats } => {
                    println!("[NOT CONNECTED] подтверждённый ответ не получен за 30 секунд.");
                    print_progress(Duration::from_secs(30), stats);
                    println!("Команды: /retry, /replace-code, /status, /quit");
                }
                Event::Status {
                    state,
                    peer,
                    kind,
                    stats,
                } => {
                    println!("[STATUS] state={state}, selected={peer:?} ({kind:?})");
                    print_progress(Duration::ZERO, stats);
                }
                Event::Fatal(message) => {
                    println!("[ERROR SOCKET] {message}");
                    should_stop = true;
                }
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => should_stop = true,
        }
    }

    let _ = command_tx.send(Command::Shutdown);
    if network.join().is_err() {
        eprintln!("[ERROR] network thread завершился panic");
    }
    println!("Сеанс завершён; UDP-сокет закрыт.");
    Ok(())
}

fn parse_cli() -> AppResult<Cli> {
    let mut stun_server = stun::DEFAULT_STUN_SERVER.to_owned();
    let mut stun_only = false;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--stun" => {
                stun_server = args.next().ok_or("после --stun нужен адрес host:port")?;
            }
            "--stun-only" => stun_only = true,
            "-h" | "--help" => {
                println!("rust-hole-punch [--stun host:port] [--stun-only]");
                println!("После обычного запуска обменяйтесь HP2-кодами через доверенный канал.");
                std::process::exit(0);
            }
            _ => return Err(format!("неизвестный аргумент: {arg}").into()),
        }
    }
    Ok(Cli {
        stun_server,
        stun_only,
    })
}

fn discover_local_candidate(server: SocketAddr, port: u16) -> io::Result<SocketAddr> {
    let probe = UdpSocket::bind("0.0.0.0:0")?;
    probe.connect(server)?;
    Ok(SocketAddr::new(probe.local_addr()?.ip(), port))
}

fn replace_public_candidate(description: &mut PeerDescription, address: SocketAddr) {
    if let Some(candidate) = description
        .candidates
        .iter_mut()
        .find(|candidate| candidate.kind == CandidateKind::ServerReflexive)
    {
        candidate.address = address;
    }
}

fn print_code(description: &PeerDescription, label: &str) {
    match description.encode() {
        Ok(code) => {
            println!("----- BEGIN {label} -----");
            println!("{code}");
            println!("----- END {label} -----");
        }
        Err(error) => println!("[ERROR CODE] не удалось сформировать код: {error}"),
    }
}

fn handle_input(
    line: &str,
    commands: &mpsc::Sender<Command>,
    local: &mut PeerDescription,
) -> AppResult<bool> {
    let value = line.trim();
    match value {
        "/quit" | "/exit" => return Ok(true),
        "/help" => {
            println!("Команды: /status, /ping, /retry, /replace-code, /quit");
        }
        "/status" => {
            commands.send(Command::Status)?;
        }
        "/ping" => {
            commands.send(Command::Ping)?;
        }
        "/retry" => {
            commands.send(Command::Retry)?;
        }
        "/replace-code" => {
            commands.send(Command::ClearPeer)?;
            println!("Вставьте актуальный HP2-код второй машины:");
        }
        "" => {}
        code => match PeerDescription::parse(code) {
            Ok(peer) => {
                if let Err(error) = peer.validate_remote(local) {
                    println!("[ERROR CODE] {error}");
                } else {
                    commands.send(Command::SetPeer(peer))?;
                }
            }
            Err(ProtocolError::InvalidDescription(message))
            | Err(ProtocolError::InvalidPacket(message)) => println!("[ERROR CODE] {message}"),
            Err(ProtocolError::AuthenticationFailed) => {
                println!("[ERROR CODE] код не прошёл проверку.")
            }
        },
    }
    Ok(false)
}

fn print_progress(elapsed: Duration, stats: Stats) {
    println!(
        "[STATS +{}s] probes sent={}, datagrams received={}, authenticated={}, invalid={}, rtt={:?}",
        elapsed.as_secs(),
        stats.probes_sent,
        stats.datagrams_received,
        stats.authenticated,
        stats.invalid,
        stats
            .selected_rtt
            .map(|rtt| format!("{}ms", rtt.as_millis()))
    );
}

enum InputEvent {
    Line(String),
    TooLong,
    Eof,
}

fn read_input(sender: mpsc::Sender<InputEvent>) {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    loop {
        match read_bounded_line(&mut reader, MAX_INPUT_LINE) {
            Ok(Some((line, too_long))) => {
                let event = if too_long {
                    InputEvent::TooLong
                } else {
                    InputEvent::Line(line)
                };
                if sender.send(event).is_err() {
                    return;
                }
            }
            Ok(None) => {
                let _ = sender.send(InputEvent::Eof);
                return;
            }
            Err(error) => {
                eprintln!("[ERROR INPUT] {error}");
                let _ = sender.send(InputEvent::Eof);
                return;
            }
        }
    }
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
) -> io::Result<Option<(String, bool)>> {
    let mut output = Vec::new();
    let mut too_long = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            if output.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        let bytes = newline.map_or(buffer, |index| &buffer[..index]);
        if output.len() < limit {
            let remaining = limit - output.len();
            let take = remaining.min(bytes.len());
            output.extend_from_slice(&bytes[..take]);
            if take < bytes.len() {
                too_long = true;
            }
        } else if !bytes.is_empty() {
            too_long = true;
        }
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }
    let line = String::from_utf8_lossy(&output)
        .trim_end_matches('\r')
        .to_owned();
    Ok(Some((line, too_long)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_input_drains_oversized_line() {
        let mut reader = Cursor::new(b"123456789\nnext\n".to_vec());
        let first = read_bounded_line(&mut reader, 4).unwrap().unwrap();
        assert_eq!(first, ("1234".to_owned(), true));
        let second = read_bounded_line(&mut reader, 4).unwrap().unwrap();
        assert_eq!(second, ("next".to_owned(), false));
    }
}
