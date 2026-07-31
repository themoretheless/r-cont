use rand::random;
use std::error::Error;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

pub const DEFAULT_STUN_SERVER: &str = "stun.cloudflare.com:3478";
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_MESSAGE_INTEGRITY_SHA256: u16 = 0x001c;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

pub type TransactionId = [u8; 12];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Discovery {
    pub public_address: SocketAddr,
    pub server: SocketAddr,
    pub rtt: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingResponse {
    Success(SocketAddr),
    ServerError { code: u16, reason: String },
}

pub fn resolve_ipv4_all(server: &str) -> io::Result<Vec<SocketAddr>> {
    let mut addresses = Vec::new();
    for address in server.to_socket_addrs()? {
        if address.is_ipv4() && !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("у {server} не найден IPv4-адрес"),
        ));
    }
    Ok(addresses)
}

pub fn discover(socket: &UdpSocket, servers: &[SocketAddr]) -> io::Result<Discovery> {
    if servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "список STUN-серверов пуст",
        ));
    }

    let mut failures = Vec::new();
    for server in servers {
        match query_one(socket, *server) {
            Ok(discovery) => {
                socket.set_read_timeout(None)?;
                return Ok(discovery);
            }
            Err(error) => failures.push(format!("{server}: {error}")),
        }
    }
    socket.set_read_timeout(None)?;
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "ни один STUN IPv4 endpoint не ответил в быстром профиле: {}",
            failures.join("; ")
        ),
    ))
}

fn query_one(socket: &UdpSocket, server: SocketAddr) -> io::Result<Discovery> {
    let transaction_id = random_transaction_id();
    let request = build_binding_request(transaction_id);
    let started = Instant::now();
    let mut last_parse_error = None;

    // Быстрый CLI-профиль. Это намеренно короче полного RFC 8489 schedule.
    for rto in [
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(2),
    ] {
        socket.send_to(&request, server)?;
        let last_sent = Instant::now();
        let deadline = last_sent + rto;

        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            if remaining.is_zero() {
                break;
            }
            socket.set_read_timeout(Some(remaining))?;
            let mut datagram = [0_u8; 2048];
            match socket.recv_from(&mut datagram) {
                Ok((size, source)) => {
                    if source != server {
                        continue;
                    }
                    match parse_binding_response(&datagram[..size], transaction_id) {
                        Ok(BindingResponse::Success(public_address)) => {
                            return Ok(Discovery {
                                public_address,
                                server,
                                rtt: last_sent.elapsed(),
                            });
                        }
                        Ok(BindingResponse::ServerError { code, reason }) => {
                            return Err(io::Error::other(format!(
                                "STUN server error {code}: {reason}"
                            )));
                        }
                        Err(error) => last_parse_error = Some(error.to_string()),
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(error) => return Err(error),
            }
        }
    }

    let detail = last_parse_error
        .map(|error| format!("; последний ответ отклонён: {error}"))
        .unwrap_or_default();
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "нет корректного Binding response за {:.1}s{detail}",
            started.elapsed().as_secs_f32()
        ),
    ))
}

pub fn random_transaction_id() -> TransactionId {
    loop {
        let transaction_id = random();
        if transaction_id != [0_u8; 12] {
            return transaction_id;
        }
    }
}

pub fn build_binding_request(transaction_id: TransactionId) -> [u8; 20] {
    let mut request = [0_u8; 20];
    request[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    request[2..4].copy_from_slice(&0_u16.to_be_bytes());
    request[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(&transaction_id);
    request
}

pub fn parse_binding_response(
    packet: &[u8],
    transaction_id: TransactionId,
) -> Result<BindingResponse, ParseError> {
    if packet.len() < 20 {
        return Err(ParseError::Malformed(
            "STUN-пакет короче 20-байтного заголовка".to_owned(),
        ));
    }
    if packet[0] & 0b1100_0000 != 0 {
        return Err(ParseError::Malformed(
            "старшие два бита STUN message type должны быть нулевыми".to_owned(),
        ));
    }

    let message_type = u16::from_be_bytes([packet[0], packet[1]]);
    let message_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if message_len & 3 != 0 {
        return Err(ParseError::Malformed(
            "длина STUN message не кратна четырём".to_owned(),
        ));
    }
    let message_end = 20_usize
        .checked_add(message_len)
        .ok_or_else(|| ParseError::Malformed("переполнение длины STUN message".to_owned()))?;
    if message_end != packet.len() {
        return Err(ParseError::Malformed(format!(
            "заголовок объявляет {message_end} байт, получено {}",
            packet.len()
        )));
    }
    if u32::from_be_bytes(packet[4..8].try_into().unwrap()) != MAGIC_COOKIE {
        return Err(ParseError::NotThisTransaction(
            "неверный STUN magic cookie".to_owned(),
        ));
    }
    if packet[8..20] != transaction_id {
        return Err(ParseError::NotThisTransaction(
            "STUN transaction ID не совпадает".to_owned(),
        ));
    }
    if !matches!(message_type, BINDING_SUCCESS | BINDING_ERROR) {
        return Err(ParseError::Malformed(format!(
            "неожиданный STUN message type: 0x{message_type:04x}"
        )));
    }

    let mut offset = 20_usize;
    let mut xor_mapped = None;
    let mut error_code = None;
    let mut semantic_attributes = true;

    while offset < message_end {
        let header_end = offset.checked_add(4).ok_or_else(|| {
            ParseError::Malformed("переполнение заголовка STUN attribute".to_owned())
        })?;
        if header_end > message_end {
            return Err(ParseError::Malformed(
                "обрезанный заголовок STUN attribute".to_owned(),
            ));
        }

        let attribute_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let attribute_len = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
        let value_end = header_end
            .checked_add(attribute_len)
            .ok_or_else(|| ParseError::Malformed("переполнение длины STUN attribute".to_owned()))?;
        if value_end > message_end {
            return Err(ParseError::Malformed(format!(
                "STUN attribute 0x{attribute_type:04x} выходит за границу message"
            )));
        }
        let value = &packet[header_end..value_end];

        if semantic_attributes {
            match attribute_type {
                ATTR_XOR_MAPPED_ADDRESS if xor_mapped.is_none() => {
                    xor_mapped = Some(parse_mapped_address(value, transaction_id)?);
                }
                ATTR_ERROR_CODE if message_type == BINDING_ERROR => {
                    error_code = Some(parse_error_code(value)?);
                }
                kind if kind < 0x8000 && !is_known_required_attribute(kind) => {
                    return Err(ParseError::Malformed(format!(
                        "неизвестный обязательный STUN attribute: 0x{kind:04x}"
                    )));
                }
                _ => {}
            }
        }

        if matches!(
            attribute_type,
            ATTR_MESSAGE_INTEGRITY | ATTR_MESSAGE_INTEGRITY_SHA256
        ) {
            // RFC 8489: обычные attributes после integrity boundary семантически
            // игнорируются (кроме другого integrity и FINGERPRINT, которые этот
            // unauthenticated Binding usage не проверяет).
            semantic_attributes = false;
        }

        let padded_len = attribute_len
            .checked_add(3)
            .ok_or_else(|| ParseError::Malformed("переполнение STUN padding".to_owned()))?
            & !3;
        offset = header_end
            .checked_add(padded_len)
            .ok_or_else(|| ParseError::Malformed("переполнение позиции STUN TLV".to_owned()))?;
        if offset > message_end {
            return Err(ParseError::Malformed(
                "обрезанный padding STUN attribute".to_owned(),
            ));
        }
    }

    if message_type == BINDING_ERROR {
        let (code, reason) = error_code.ok_or_else(|| {
            ParseError::Malformed("Binding Error не содержит ERROR-CODE".to_owned())
        })?;
        return Ok(BindingResponse::ServerError { code, reason });
    }

    xor_mapped.map(BindingResponse::Success).ok_or_else(|| {
        ParseError::Malformed("Binding Success не содержит XOR-MAPPED-ADDRESS".to_owned())
    })
}

fn is_known_required_attribute(kind: u16) -> bool {
    matches!(
        kind,
        ATTR_MAPPED_ADDRESS
            | 0x0006 // USERNAME
            | ATTR_MESSAGE_INTEGRITY
            | ATTR_ERROR_CODE
            | 0x000a // UNKNOWN-ATTRIBUTES
            | 0x0014 // REALM
            | 0x0015 // NONCE
            | ATTR_MESSAGE_INTEGRITY_SHA256
            | 0x001d // PASSWORD-ALGORITHM
            | 0x001e // USERHASH
            | ATTR_XOR_MAPPED_ADDRESS
    )
}

fn parse_error_code(value: &[u8]) -> Result<(u16, String), ParseError> {
    if value.len() < 4 {
        return Err(ParseError::Malformed(
            "ERROR-CODE короче четырёх байт".to_owned(),
        ));
    }
    if value[0] != 0 || value[1] != 0 || value[2] & 0xf8 != 0 {
        return Err(ParseError::Malformed(
            "reserved-биты ERROR-CODE должны быть нулевыми".to_owned(),
        ));
    }
    let class = value[2] & 0x07;
    let number = value[3];
    if !(3..=6).contains(&class) || number > 99 {
        return Err(ParseError::Malformed(
            "ERROR-CODE class/number вне допустимого диапазона".to_owned(),
        ));
    }
    let reason = std::str::from_utf8(&value[4..])
        .map_err(|_| ParseError::Malformed("ERROR-CODE reason не UTF-8".to_owned()))?;
    let escaped = reason.chars().flat_map(char::escape_default).collect();
    Ok((class as u16 * 100 + number as u16, escaped))
}

fn parse_mapped_address(
    value: &[u8],
    transaction_id: TransactionId,
) -> Result<SocketAddr, ParseError> {
    if value.len() < 4 {
        return Err(ParseError::Malformed(
            "XOR-MAPPED-ADDRESS короче четырёх байт".to_owned(),
        ));
    }
    // value[0] зарезервирован: отправитель ставит 0, получатель MUST ignore.
    let port = u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    if port == 0 {
        return Err(ParseError::Malformed("STUN вернул нулевой порт".to_owned()));
    }

    let ip = match value[1] {
        0x01 => {
            if value.len() != 8 {
                return Err(ParseError::Malformed(
                    "IPv4 XOR-MAPPED-ADDRESS должен иметь длину 8".to_owned(),
                ));
            }
            let raw = u32::from_be_bytes(value[4..8].try_into().unwrap());
            IpAddr::V4(Ipv4Addr::from(raw ^ MAGIC_COOKIE))
        }
        0x02 => {
            if value.len() != 20 {
                return Err(ParseError::Malformed(
                    "IPv6 XOR-MAPPED-ADDRESS должен иметь длину 20".to_owned(),
                ));
            }
            let mut address: [u8; 16] = value[4..20].try_into().unwrap();
            let mut mask = [0_u8; 16];
            mask[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(&transaction_id);
            for (byte, mask_byte) in address.iter_mut().zip(mask) {
                *byte ^= mask_byte;
            }
            IpAddr::V6(Ipv6Addr::from(address))
        }
        family => {
            return Err(ParseError::Malformed(format!(
                "неизвестное семейство XOR-MAPPED-ADDRESS: {family}"
            )));
        }
    };
    Ok(SocketAddr::new(ip, port))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    NotThisTransaction(String),
    Malformed(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotThisTransaction(message) | Self::Malformed(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    const RFC_TRANSACTION_ID: TransactionId = [
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ];

    fn rfc5769_ipv4_response() -> Vec<u8> {
        vec![
            0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34,
            0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74,
            0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01,
            0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, 0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99,
            0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b,
            0xe7, 0xd7, 0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
        ]
    }

    #[test]
    fn extracts_xor_mapped_from_rfc5769_vector() {
        assert_eq!(
            parse_binding_response(&rfc5769_ipv4_response(), RFC_TRANSACTION_ID).unwrap(),
            BindingResponse::Success("192.0.2.1:32853".parse().unwrap())
        );
    }

    #[test]
    fn reserved_address_byte_is_ignored() {
        let mut packet = rfc5769_ipv4_response();
        packet[40] = 0xff;
        assert!(matches!(
            parse_binding_response(&packet, RFC_TRANSACTION_ID),
            Ok(BindingResponse::Success(_))
        ));
    }

    #[test]
    fn decodes_ipv6_xor_mapped_address() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let expected: SocketAddr = "[2001:db8:1234:5678:11:2233:4455:6677]:45678"
            .parse()
            .unwrap();
        let mut value = vec![0, 2];
        value.extend_from_slice(&(45678_u16 ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());

        let mut address = match expected.ip() {
            IpAddr::V6(ip) => ip.octets(),
            _ => unreachable!(),
        };
        let mut mask = [0_u8; 16];
        mask[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        mask[4..].copy_from_slice(&transaction_id);
        for (byte, mask_byte) in address.iter_mut().zip(mask) {
            *byte ^= mask_byte;
        }
        value.extend_from_slice(&address);

        assert_eq!(
            parse_mapped_address(&value, transaction_id).unwrap(),
            expected
        );
    }

    #[test]
    fn mapped_address_without_xor_is_rejected() {
        let transaction_id = [1_u8; 12];
        let mut packet = build_binding_request(transaction_id).to_vec();
        packet[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        packet[2..4].copy_from_slice(&12_u16.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x12, 0x34, 192, 0, 2, 1]);
        assert!(
            parse_binding_response(&packet, transaction_id)
                .unwrap_err()
                .to_string()
                .contains("XOR-MAPPED")
        );
    }

    #[test]
    fn xor_after_message_integrity_is_ignored() {
        let transaction_id = [2_u8; 12];
        let mut packet = build_binding_request(transaction_id).to_vec();
        packet[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        packet[2..4].copy_from_slice(&36_u16.to_be_bytes());
        packet.extend_from_slice(&[
            0x00, 0x08, 0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0x12, 0x34, 1, 2, 3, 4,
        ]);
        assert!(
            parse_binding_response(&packet, transaction_id)
                .unwrap_err()
                .to_string()
                .contains("XOR-MAPPED")
        );
    }

    #[test]
    fn arbitrary_lengths_never_panic() {
        for length in 0..=256 {
            let packet = vec![0xa5; length];
            let _ = parse_binding_response(&packet, [3_u8; 12]);
        }
    }

    #[test]
    fn local_fake_server_observes_identical_retry_then_succeeds() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let server_address = server.local_addr().unwrap();
        let fake = thread::spawn(move || {
            let mut buffer = [0_u8; 256];
            let (first_size, first_source) = server.recv_from(&mut buffer).unwrap();
            let first_request = buffer[..first_size].to_vec();

            // Потерять первый request и дождаться retry той же транзакции.
            let (second_size, second_source) = server.recv_from(&mut buffer).unwrap();
            assert_eq!(first_source, second_source);
            assert_eq!(first_request, buffer[..second_size]);

            let transaction_id: TransactionId = buffer[8..20].try_into().unwrap();
            let SocketAddr::V4(mapped) = second_source else {
                unreachable!();
            };
            let mut response = Vec::with_capacity(32);
            response.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
            response.extend_from_slice(&12_u16.to_be_bytes());
            response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
            response.extend_from_slice(&transaction_id);
            response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
            response.extend_from_slice(&8_u16.to_be_bytes());
            response.extend_from_slice(&[0, 1]);
            response
                .extend_from_slice(&(mapped.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
            response.extend_from_slice(&(u32::from(*mapped.ip()) ^ MAGIC_COOKIE).to_be_bytes());
            server.send_to(&response, second_source).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let expected = client.local_addr().unwrap();
        let discovery = discover(&client, &[server_address]).unwrap();
        assert_eq!(discovery.public_address, expected);
        assert_eq!(discovery.server, server_address);
        assert_eq!(client.read_timeout().unwrap(), None);
        fake.join().unwrap();
    }
}
