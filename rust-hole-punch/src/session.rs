use crate::protocol::{
    CandidateKind, ControlPacket, PacketKind, PeerDescription, TransactionId,
    candidate_kind_for_source, decode_control, encode_control, random_transaction_id,
};
use crate::stun::{self, BindingResponse};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

const TICK: Duration = Duration::from_millis(50);
const STUN_KEEPALIVE: Duration = Duration::from_secs(15);
const PROBE_INTERVAL: Duration = Duration::from_millis(500);
const CHECKING_DEADLINE: Duration = Duration::from_secs(30);
const CONSENT_INTERVAL: Duration = Duration::from_secs(5);
const CONSENT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PENDING: usize = 256;

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub local: PeerDescription,
    pub public_address: SocketAddr,
    pub stun_servers: Vec<SocketAddr>,
}

#[derive(Debug)]
pub enum Command {
    SetPeer(PeerDescription),
    ClearPeer,
    Retry,
    Ping,
    Status,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub probes_sent: u64,
    pub datagrams_received: u64,
    pub authenticated: u64,
    pub invalid: u64,
    pub selected_rtt: Option<Duration>,
}

#[derive(Debug)]
pub enum Event {
    Info(String),
    MappingChanged {
        address: SocketAddr,
    },
    CheckingStarted {
        candidates: usize,
    },
    Progress {
        elapsed: Duration,
        stats: Stats,
    },
    Connected {
        source: SocketAddr,
        kind: CandidateKind,
        rtt: Duration,
    },
    PingResult(Duration),
    Disconnected {
        reason: String,
        stats: Stats,
    },
    Failed {
        stats: Stats,
    },
    Status {
        state: &'static str,
        peer: Option<SocketAddr>,
        kind: Option<CandidateKind>,
        stats: Stats,
    },
    Fatal(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Waiting,
    Checking,
    Connected,
    Failed,
}

impl State {
    fn label(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Checking => "checking",
            Self::Connected => "connected",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbePurpose {
    Connectivity,
    Consent,
    ManualPing,
}

#[derive(Clone, Copy, Debug)]
struct PendingProbe {
    target: SocketAddr,
    sent_at: Instant,
    purpose: ProbePurpose,
}

#[derive(Clone, Copy, Debug)]
struct PendingStun {
    server: SocketAddr,
    transaction_id: stun::TransactionId,
    sent_at: Instant,
    deadline: Instant,
    attempt: u8,
}

#[derive(Clone, Copy, Debug)]
struct SelectedPath {
    source: SocketAddr,
    kind: CandidateKind,
    last_success: Instant,
    consent_pending: Option<TransactionId>,
}

pub fn spawn(
    socket: UdpSocket,
    config: NetworkConfig,
    commands: Receiver<Command>,
    events: Sender<Event>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("udp-network".to_owned())
        .spawn(move || run(socket, config, commands, events))
        .expect("network thread must start")
}

fn run(
    socket: UdpSocket,
    config: NetworkConfig,
    commands: Receiver<Command>,
    events: Sender<Event>,
) {
    if let Err(error) = socket.set_read_timeout(Some(TICK)) {
        let _ = events.send(Event::Fatal(format!(
            "не удалось настроить UDP receive: {error}"
        )));
        return;
    }

    let local = config.local;
    let mut current_public_address = config.public_address;
    let mut peer: Option<PeerDescription> = None;
    let mut state = State::Waiting;
    let mut stats = Stats::default();
    let mut pending = HashMap::<TransactionId, PendingProbe>::new();
    let mut selected = None::<SelectedPath>;
    let mut checking_started = None::<Instant>;
    let mut next_probe = Instant::now();
    let mut next_progress = Instant::now() + Duration::from_secs(5);
    let mut next_stun = Instant::now() + STUN_KEEPALIVE;
    let mut pending_stun = None::<PendingStun>;
    let mut stun_index = 0_usize;
    let mut datagram = vec![0_u8; 65_535];

    'runtime: loop {
        loop {
            match commands.try_recv() {
                Ok(Command::SetPeer(candidate)) => {
                    if let Err(error) = candidate.validate_remote(&local) {
                        let _ = events.send(Event::Info(format!("КОД ОТКЛОНЁН: {error}")));
                        continue;
                    }
                    peer = Some(candidate);
                    pending.clear();
                    selected = None;
                    stats = Stats::default();
                    state = State::Checking;
                    checking_started = Some(Instant::now());
                    next_probe = Instant::now();
                    next_progress = Instant::now() + Duration::from_secs(5);
                    let _ = events.send(Event::CheckingStarted {
                        candidates: peer.as_ref().unwrap().candidates.len(),
                    });
                }
                Ok(Command::ClearPeer) => {
                    peer = None;
                    pending.clear();
                    selected = None;
                    state = State::Waiting;
                    checking_started = None;
                    let _ = events.send(Event::Info(
                        "Ожидаю новый session code второй машины.".to_owned(),
                    ));
                }
                Ok(Command::Retry) => {
                    if peer.is_some() {
                        pending.clear();
                        selected = None;
                        state = State::Checking;
                        checking_started = Some(Instant::now());
                        next_probe = Instant::now();
                        stats = Stats::default();
                        let _ = events.send(Event::Info("Повторяю candidate checks.".to_owned()));
                    } else {
                        let _ = events.send(Event::Info(
                            "Сначала вставьте session code второй машины.".to_owned(),
                        ));
                    }
                }
                Ok(Command::Ping) => {
                    if let Some(path) = selected {
                        if let Some(remote) = &peer {
                            let _ = send_probe(
                                &socket,
                                &local,
                                remote,
                                path.source,
                                ProbePurpose::ManualPing,
                                &mut pending,
                                &mut stats,
                            );
                        }
                    } else {
                        let _ = events.send(Event::Info(
                            "/ping доступен после подтверждённого round-trip.".to_owned(),
                        ));
                    }
                }
                Ok(Command::Status) => {
                    let _ = events.send(Event::Status {
                        state: state.label(),
                        peer: selected.map(|path| path.source),
                        kind: selected.map(|path| path.kind),
                        stats,
                    });
                }
                Ok(Command::Shutdown) => break 'runtime,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break 'runtime,
            }
        }

        let now = Instant::now();
        if now >= next_stun && pending_stun.is_none() && !config.stun_servers.is_empty() {
            let server = config.stun_servers[stun_index % config.stun_servers.len()];
            stun_index = stun_index.wrapping_add(1);
            let transaction_id = stun::random_transaction_id();
            let request = stun::build_binding_request(transaction_id);
            if let Err(error) = socket.send_to(&request, server) {
                let _ = events.send(Event::Info(format!("STUN keepalive send error: {error}")));
            } else {
                pending_stun = Some(PendingStun {
                    server,
                    transaction_id,
                    sent_at: now,
                    deadline: now + Duration::from_millis(500),
                    attempt: 0,
                });
            }
            next_stun = now + STUN_KEEPALIVE;
        }

        if let Some(stun_transaction) = pending_stun {
            if now >= stun_transaction.deadline {
                if stun_transaction.attempt < 2 {
                    let request = stun::build_binding_request(stun_transaction.transaction_id);
                    if socket.send_to(&request, stun_transaction.server).is_ok() {
                        pending_stun = Some(PendingStun {
                            server: stun_transaction.server,
                            transaction_id: stun_transaction.transaction_id,
                            sent_at: stun_transaction.sent_at,
                            deadline: now + Duration::from_secs(1_u64 << stun_transaction.attempt),
                            attempt: stun_transaction.attempt + 1,
                        });
                    }
                } else {
                    pending_stun = None;
                }
            }
        }

        if state == State::Checking {
            if let Some(started) = checking_started {
                if now.duration_since(started) >= CHECKING_DEADLINE {
                    state = State::Failed;
                    let _ = events.send(Event::Failed { stats });
                }
            }
            if state == State::Checking && now >= next_probe {
                if let Some(remote) = &peer {
                    for candidate in &remote.candidates {
                        if pending.len() >= MAX_PENDING {
                            break;
                        }
                        let _ = send_probe(
                            &socket,
                            &local,
                            remote,
                            candidate.address,
                            ProbePurpose::Connectivity,
                            &mut pending,
                            &mut stats,
                        );
                    }
                }
                next_probe = now + PROBE_INTERVAL;
            }
            if now >= next_progress {
                let _ = events.send(Event::Progress {
                    elapsed: checking_started
                        .map(|value| now.duration_since(value))
                        .unwrap_or_default(),
                    stats,
                });
                next_progress = now + Duration::from_secs(5);
            }
        }

        if let Some(path) = selected {
            if state == State::Connected {
                if now.duration_since(path.last_success) >= CONSENT_TIMEOUT {
                    state = State::Checking;
                    checking_started = Some(now);
                    selected = None;
                    pending.clear();
                    next_probe = now;
                    let _ = events.send(Event::Disconnected {
                        reason: "consent checks не получили ответа 15 секунд".to_owned(),
                        stats,
                    });
                } else if path.consent_pending.is_none()
                    && now.duration_since(path.last_success) >= CONSENT_INTERVAL
                {
                    if let Some(remote) = &peer {
                        let mut next_path = path;
                        if let Some(transaction_id) = send_probe(
                            &socket,
                            &local,
                            remote,
                            path.source,
                            ProbePurpose::Consent,
                            &mut pending,
                            &mut stats,
                        ) {
                            next_path.consent_pending = Some(transaction_id);
                            selected = Some(next_path);
                        }
                    }
                }
            }
        }

        pending.retain(|_, probe| now.duration_since(probe.sent_at) < Duration::from_secs(4));
        if let Some(mut path) = selected {
            if path
                .consent_pending
                .is_some_and(|transaction_id| !pending.contains_key(&transaction_id))
            {
                path.consent_pending = None;
                selected = Some(path);
            }
        }

        match socket.recv_from(&mut datagram) {
            Ok((size, source)) => {
                stats.datagrams_received = stats.datagrams_received.saturating_add(1);
                if let Some(transaction) = pending_stun {
                    if source == transaction.server {
                        match stun::parse_binding_response(
                            &datagram[..size],
                            transaction.transaction_id,
                        ) {
                            Ok(BindingResponse::Success(address)) => {
                                pending_stun = None;
                                if address != current_public_address {
                                    current_public_address = address;
                                    let _ = events.send(Event::MappingChanged { address });
                                }
                            }
                            Ok(BindingResponse::ServerError { code, reason }) => {
                                pending_stun = None;
                                let _ = events.send(Event::Info(format!(
                                    "STUN keepalive error {code}: {reason}"
                                )));
                            }
                            Err(_) => {}
                        }
                        continue;
                    }
                }

                let Some(remote) = &peer else { continue };
                if size != crate::protocol::CONTROL_PACKET_LEN {
                    stats.invalid = stats.invalid.saturating_add(1);
                    continue;
                }
                let packet = match decode_control(
                    &datagram[..size],
                    remote.session_id,
                    local.session_id,
                    &remote.key,
                ) {
                    Ok(packet) => packet,
                    Err(_) => {
                        stats.invalid = stats.invalid.saturating_add(1);
                        continue;
                    }
                };
                stats.authenticated = stats.authenticated.saturating_add(1);
                match packet.kind {
                    PacketKind::Check => {
                        if !_is_unicast(source) {
                            stats.invalid = stats.invalid.saturating_add(1);
                            continue;
                        }
                        let response = ControlPacket {
                            kind: PacketKind::CheckOk,
                            source_session: local.session_id,
                            destination_session: remote.session_id,
                            transaction_id: packet.transaction_id,
                        };
                        if socket
                            .send_to(&encode_control(response, &local.key), source)
                            .is_err()
                        {
                            let _ = events
                                .send(Event::Info("не удалось отправить CHECK_OK".to_owned()));
                        }
                    }
                    PacketKind::CheckOk => {
                        let Some(probe) = pending.get(&packet.transaction_id).copied() else {
                            continue;
                        };
                        let source_allowed = match probe.purpose {
                            ProbePurpose::Connectivity => {
                                source == probe.target || _is_unicast(source)
                            }
                            ProbePurpose::Consent | ProbePurpose::ManualPing => {
                                source == probe.target
                            }
                        };
                        if !source_allowed {
                            continue;
                        }
                        pending.remove(&packet.transaction_id);
                        let rtt = probe.sent_at.elapsed();
                        let kind = candidate_kind_for_source(source, &remote.candidates);
                        match probe.purpose {
                            ProbePurpose::Connectivity => {
                                if state == State::Checking {
                                    state = State::Connected;
                                    selected = Some(SelectedPath {
                                        source,
                                        kind,
                                        last_success: Instant::now(),
                                        consent_pending: None,
                                    });
                                    stats.selected_rtt = Some(rtt);
                                    let _ = events.send(Event::Connected { source, kind, rtt });
                                }
                            }
                            ProbePurpose::Consent => {
                                if let Some(mut path) = selected {
                                    if path.source == source || kind == CandidateKind::PeerReflexive
                                    {
                                        path.last_success = Instant::now();
                                        path.consent_pending = None;
                                        selected = Some(path);
                                    }
                                }
                            }
                            ProbePurpose::ManualPing => {
                                let _ = events.send(Event::PingResult(rtt));
                            }
                        }
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
                ) =>
            {
                // Windows may report ICMP Port Unreachable as WSAECONNRESET while
                // probing a peer that has not opened its socket yet. Continue probing.
            }
            Err(error) => {
                let _ = events.send(Event::Fatal(format!("UDP receive error: {error}")));
                break 'runtime;
            }
        }
    }
}

fn send_probe(
    socket: &UdpSocket,
    local: &PeerDescription,
    remote: &PeerDescription,
    target: SocketAddr,
    purpose: ProbePurpose,
    pending: &mut HashMap<TransactionId, PendingProbe>,
    stats: &mut Stats,
) -> Option<TransactionId> {
    let transaction_id = random_transaction_id();
    let packet = ControlPacket {
        kind: PacketKind::Check,
        source_session: local.session_id,
        destination_session: remote.session_id,
        transaction_id,
    };
    if socket
        .send_to(&encode_control(packet, &local.key), target)
        .is_err()
    {
        return None;
    }
    pending.insert(
        transaction_id,
        PendingProbe {
            target,
            sent_at: Instant::now(),
            purpose,
        },
    );
    stats.probes_sent = stats.probes_sent.saturating_add(1);
    Some(transaction_id)
}

fn _is_unicast(source: SocketAddr) -> bool {
    match source.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn two_loopback_sessions_complete_authenticated_round_trip() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address_a = socket_a.local_addr().unwrap();
        let address_b = socket_b.local_addr().unwrap();
        let description_a = PeerDescription::new(vec![crate::protocol::Candidate {
            kind: CandidateKind::Host,
            address: address_a,
        }])
        .unwrap();
        let description_b = PeerDescription::new(vec![crate::protocol::Candidate {
            kind: CandidateKind::Host,
            address: address_b,
        }])
        .unwrap();

        let (commands_a, receiver_a) = mpsc::channel();
        let (events_a, observer_a) = mpsc::channel();
        let (commands_b, receiver_b) = mpsc::channel();
        let (events_b, observer_b) = mpsc::channel();
        let thread_a = spawn(
            socket_a,
            NetworkConfig {
                local: description_a.clone(),
                public_address: address_a,
                stun_servers: Vec::new(),
            },
            receiver_a,
            events_a,
        );
        let thread_b = spawn(
            socket_b,
            NetworkConfig {
                local: description_b.clone(),
                public_address: address_b,
                stun_servers: Vec::new(),
            },
            receiver_b,
            events_b,
        );
        commands_a.send(Command::SetPeer(description_b)).unwrap();
        commands_b.send(Command::SetPeer(description_a)).unwrap();

        let connected_a = wait_for_connected(&observer_a);
        let connected_b = wait_for_connected(&observer_b);
        assert!(connected_a && connected_b, "both peers need a CHECK_OK");

        commands_a.send(Command::Ping).unwrap();
        let pinged = std::iter::from_fn(|| observer_a.recv_timeout(Duration::from_secs(1)).ok())
            .any(|event| matches!(event, Event::PingResult(_)));
        assert!(pinged, "manual ping needs a correlated CHECK_OK");

        commands_a.send(Command::Shutdown).unwrap();
        commands_b.send(Command::Shutdown).unwrap();
        thread_a.join().unwrap();
        thread_b.join().unwrap();
    }

    #[test]
    fn forged_session_descriptor_is_rejected_before_probing() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address_a = socket_a.local_addr().unwrap();
        let address_b = socket_b.local_addr().unwrap();
        let description_a = PeerDescription::new(vec![crate::protocol::Candidate {
            kind: CandidateKind::Host,
            address: address_a,
        }])
        .unwrap();
        let mut forged_b = PeerDescription::new(vec![crate::protocol::Candidate {
            kind: CandidateKind::Host,
            address: address_b,
        }])
        .unwrap();
        forged_b.session_id = description_a.session_id;
        let (commands, receiver) = mpsc::channel();
        let (events, observer) = mpsc::channel();
        let worker = spawn(
            socket_a,
            NetworkConfig {
                local: description_a.clone(),
                public_address: address_a,
                stun_servers: Vec::new(),
            },
            receiver,
            events,
        );

        // The worker must reject a self/forged descriptor before sending probes.
        commands.send(Command::SetPeer(forged_b)).unwrap();
        let rejected = observer
            .recv_timeout(Duration::from_secs(1))
            .ok()
            .is_some_and(
                |event| matches!(event, Event::Info(message) if message.contains("КОД ОТКЛОНЁН")),
            );
        assert!(rejected);
        commands.send(Command::Shutdown).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn clear_peer_returns_worker_to_waiting_state() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let local = PeerDescription::new(vec![crate::protocol::Candidate {
            kind: CandidateKind::Host,
            address,
        }])
        .unwrap();
        let peer = PeerDescription::new(vec![crate::protocol::Candidate {
            kind: CandidateKind::Host,
            address: "127.0.0.1:9".parse().unwrap(),
        }])
        .unwrap();
        let (commands, receiver) = mpsc::channel();
        let (events, observer) = mpsc::channel();
        let worker = spawn(
            socket,
            NetworkConfig {
                local,
                public_address: address,
                stun_servers: Vec::new(),
            },
            receiver,
            events,
        );
        commands.send(Command::SetPeer(peer)).unwrap();
        let started = observer
            .recv_timeout(Duration::from_secs(1))
            .ok()
            .is_some_and(|event| matches!(event, Event::CheckingStarted { candidates: 1 }));
        assert!(started);
        commands.send(Command::ClearPeer).unwrap();
        let cleared = observer
            .recv_timeout(Duration::from_secs(1))
            .ok()
            .is_some_and(
                |event| matches!(event, Event::Info(message) if message.contains("Ожидаю новый")),
            );
        assert!(cleared);
        commands.send(Command::Shutdown).unwrap();
        worker.join().unwrap();
    }

    fn wait_for_connected(events: &Receiver<Event>) -> bool {
        for _ in 0..20 {
            if matches!(
                events.recv_timeout(Duration::from_millis(100)),
                Ok(Event::Connected { .. })
            ) {
                return true;
            }
        }
        false
    }
}
