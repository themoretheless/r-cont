use hmac::{Hmac, KeyInit, Mac};
use rand::random;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

pub const SESSION_CODE_VERSION: &str = "HP2";
pub const MAX_SESSION_CODE_LEN: usize = 512;
pub const MAX_CANDIDATES: usize = 8;
pub const CONTROL_PACKET_LEN: usize = 84;

const WIRE_MAGIC: &[u8; 4] = b"HP02";
const SIGNED_HEADER_LEN: usize = 52;
const AUTH_TAG_LEN: usize = 32;

pub type SessionId = [u8; 16];
pub type SessionKey = [u8; 32];
pub type TransactionId = [u8; 12];

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CandidateKind {
    Host,
    ServerReflexive,
    PeerReflexive,
}

impl CandidateKind {
    fn code(self) -> &'static str {
        match self {
            Self::Host => "h",
            Self::ServerReflexive => "s",
            Self::PeerReflexive => "p",
        }
    }

    fn parse(value: &str) -> Result<Self, ProtocolError> {
        match value {
            "h" => Ok(Self::Host),
            "s" => Ok(Self::ServerReflexive),
            // Peer-reflexive candidates are learned on the wire and are never
            // accepted from an untrusted pasted descriptor.
            "p" => Err(ProtocolError::InvalidDescription(
                "peer-reflexive candidate нельзя объявлять в коде".to_owned(),
            )),
            _ => Err(ProtocolError::InvalidDescription(format!(
                "неизвестный тип candidate: {value}"
            ))),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Host => "LAN",
            Self::ServerReflexive => "PUBLIC",
            Self::PeerReflexive => "PEER-REFLEXIVE",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerDescription {
    pub session_id: SessionId,
    pub key: SessionKey,
    pub candidates: Vec<Candidate>,
}

impl PeerDescription {
    pub fn new(candidates: Vec<Candidate>) -> Result<Self, ProtocolError> {
        let session_id = loop {
            let value = random();
            if value != [0_u8; 16] {
                break value;
            }
        };
        let key = loop {
            let value = random();
            if value != [0_u8; 32] {
                break value;
            }
        };
        let description = Self {
            session_id,
            key,
            candidates,
        };
        description.validate()?;
        Ok(description)
    }

    pub fn encode(&self) -> Result<String, ProtocolError> {
        self.validate()?;
        let candidate_text = self
            .candidates
            .iter()
            .map(|candidate| format!("{}@{}", candidate.kind.code(), candidate.address))
            .collect::<Vec<_>>()
            .join(",");
        let prefix = format!(
            "{SESSION_CODE_VERSION}|{}|{}|{candidate_text}",
            hex_encode(&self.session_id),
            hex_encode(&self.key)
        );
        Ok(format!("{prefix}|{}", hex_encode(&checksum(&prefix))))
    }

    pub fn parse(input: &str) -> Result<Self, ProtocolError> {
        let code = extract_code(input)?;
        if code.len() > MAX_SESSION_CODE_LEN {
            return Err(ProtocolError::InvalidDescription(format!(
                "код длиннее {MAX_SESSION_CODE_LEN} байт"
            )));
        }

        let parts = code.split('|').collect::<Vec<_>>();
        if parts.len() != 5 || parts[0] != SESSION_CODE_VERSION {
            return Err(ProtocolError::InvalidDescription(
                "ожидался код HP2 из пяти частей".to_owned(),
            ));
        }

        let prefix = parts[..4].join("|");
        let expected_checksum = hex_decode_array::<4>(parts[4], "checksum")?;
        if checksum(&prefix) != expected_checksum {
            return Err(ProtocolError::InvalidDescription(
                "checksum не совпадает: код повреждён или скопирован не полностью".to_owned(),
            ));
        }

        let session_id = hex_decode_array::<16>(parts[1], "session id")?;
        let key = hex_decode_array::<32>(parts[2], "session key")?;
        let candidate_parts = parts[3].split(',').collect::<Vec<_>>();
        if candidate_parts.is_empty() || candidate_parts.len() > MAX_CANDIDATES {
            return Err(ProtocolError::InvalidDescription(format!(
                "нужно от 1 до {MAX_CANDIDATES} candidates"
            )));
        }

        let mut candidates = Vec::with_capacity(candidate_parts.len());
        for value in candidate_parts {
            let (kind, address) = value.split_once('@').ok_or_else(|| {
                ProtocolError::InvalidDescription(format!(
                    "candidate должен иметь вид type@ip:port: {value}"
                ))
            })?;
            candidates.push(Candidate {
                kind: CandidateKind::parse(kind)?,
                address: SocketAddr::from_str(address).map_err(|error| {
                    ProtocolError::InvalidDescription(format!(
                        "некорректный candidate {address}: {error}"
                    ))
                })?,
            });
        }

        let description = Self {
            session_id,
            key,
            candidates,
        };
        description.validate()?;
        Ok(description)
    }

    pub fn validate_remote(&self, local: &Self) -> Result<(), ProtocolError> {
        self.validate()?;
        if self.session_id == local.session_id {
            return Err(ProtocolError::InvalidDescription(
                "это собственный session code (session id совпадает)".to_owned(),
            ));
        }
        if self.key == local.key {
            return Err(ProtocolError::InvalidDescription(
                "это собственный session code (session key совпадает)".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.session_id.iter().all(|byte| *byte == 0) {
            return Err(ProtocolError::InvalidDescription(
                "session id не может быть нулевым".to_owned(),
            ));
        }
        if self.key.iter().all(|byte| *byte == 0) {
            return Err(ProtocolError::InvalidDescription(
                "session key не может быть нулевым".to_owned(),
            ));
        }
        if self.candidates.is_empty() || self.candidates.len() > MAX_CANDIDATES {
            return Err(ProtocolError::InvalidDescription(format!(
                "нужно от 1 до {MAX_CANDIDATES} candidates"
            )));
        }

        let mut addresses = HashSet::new();
        for candidate in &self.candidates {
            validate_address(candidate.address)?;
            if candidate.kind == CandidateKind::PeerReflexive {
                return Err(ProtocolError::InvalidDescription(
                    "peer-reflexive candidate нельзя объявлять в коде".to_owned(),
                ));
            }
            if !addresses.insert(candidate.address) {
                return Err(ProtocolError::InvalidDescription(format!(
                    "candidate {} повторяется",
                    candidate.address
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketKind {
    Check = 1,
    CheckOk = 2,
}

impl PacketKind {
    fn from_byte(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::Check),
            2 => Ok(Self::CheckOk),
            _ => Err(ProtocolError::InvalidPacket(format!(
                "неизвестный packet kind: {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPacket {
    pub kind: PacketKind,
    pub source_session: SessionId,
    pub destination_session: SessionId,
    pub transaction_id: TransactionId,
}

pub fn random_transaction_id() -> TransactionId {
    loop {
        let transaction_id = random();
        if transaction_id != [0_u8; 12] {
            return transaction_id;
        }
    }
}

pub fn encode_control(packet: ControlPacket, key: &SessionKey) -> [u8; CONTROL_PACKET_LEN] {
    let mut output = [0_u8; CONTROL_PACKET_LEN];
    output[0..4].copy_from_slice(WIRE_MAGIC);
    output[4] = packet.kind as u8;
    output[5] = 0; // flags
    output[6..8].copy_from_slice(&0_u16.to_be_bytes());
    output[8..24].copy_from_slice(&packet.source_session);
    output[24..40].copy_from_slice(&packet.destination_session);
    output[40..52].copy_from_slice(&packet.transaction_id);

    let tag = authentication_tag(key, &output[..SIGNED_HEADER_LEN]);
    output[SIGNED_HEADER_LEN..SIGNED_HEADER_LEN + AUTH_TAG_LEN].copy_from_slice(&tag);
    output
}

pub fn decode_control(
    datagram: &[u8],
    expected_source: SessionId,
    expected_destination: SessionId,
    peer_key: &SessionKey,
) -> Result<ControlPacket, ProtocolError> {
    if datagram.len() != CONTROL_PACKET_LEN {
        return Err(ProtocolError::InvalidPacket(format!(
            "control packet должен иметь длину {CONTROL_PACKET_LEN}, получено {}",
            datagram.len()
        )));
    }
    if &datagram[0..4] != WIRE_MAGIC {
        return Err(ProtocolError::InvalidPacket(
            "неверная версия/magic control packet".to_owned(),
        ));
    }
    if datagram[5] != 0 || datagram[6..8] != [0, 0] {
        return Err(ProtocolError::InvalidPacket(
            "неизвестные flags/reserved control packet".to_owned(),
        ));
    }

    let source_session: SessionId = datagram[8..24].try_into().unwrap();
    let destination_session: SessionId = datagram[24..40].try_into().unwrap();
    if source_session != expected_source || destination_session != expected_destination {
        return Err(ProtocolError::InvalidPacket(
            "session id control packet не совпадает".to_owned(),
        ));
    }

    let transaction_id: TransactionId = datagram[40..52].try_into().unwrap();
    if transaction_id == [0_u8; 12] {
        return Err(ProtocolError::InvalidPacket(
            "нулевой transaction id запрещён".to_owned(),
        ));
    }

    let mut mac = HmacSha256::new_from_slice(peer_key).expect("HMAC принимает 32-byte key");
    mac.update(&datagram[..SIGNED_HEADER_LEN]);
    mac.verify_slice(&datagram[SIGNED_HEADER_LEN..])
        .map_err(|_| ProtocolError::AuthenticationFailed)?;

    Ok(ControlPacket {
        kind: PacketKind::from_byte(datagram[4])?,
        source_session,
        destination_session,
        transaction_id,
    })
}

pub fn candidate_kind_for_source(source: SocketAddr, advertised: &[Candidate]) -> CandidateKind {
    advertised
        .iter()
        .find(|candidate| candidate.address == source)
        .map(|candidate| candidate.kind)
        .unwrap_or(CandidateKind::PeerReflexive)
}

fn authentication_tag(key: &SessionKey, message: &[u8]) -> [u8; AUTH_TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC принимает 32-byte key");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn checksum(value: &str) -> [u8; 4] {
    Sha256::digest(value.as_bytes())[..4].try_into().unwrap()
}

fn extract_code(input: &str) -> Result<&str, ProtocolError> {
    let start = input.find("HP2|").ok_or_else(|| {
        ProtocolError::InvalidDescription("в строке не найдено начало HP2|".to_owned())
    })?;
    input[start..]
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| ProtocolError::InvalidDescription("после HP2| нет session code".to_owned()))
}

fn validate_address(address: SocketAddr) -> Result<(), ProtocolError> {
    if address.port() == 0 {
        return Err(ProtocolError::InvalidDescription(
            "candidate port не может быть нулевым".to_owned(),
        ));
    }
    match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() => {
            Err(ProtocolError::InvalidDescription(
                "unspecified/multicast/broadcast IPv4 candidate запрещён".to_owned(),
            ))
        }
        IpAddr::V4(_) => Ok(()),
        IpAddr::V6(_) => Err(ProtocolError::InvalidDescription(
            "эта итерация HP2 поддерживает только IPv4".to_owned(),
        )),
    }
}

fn hex_encode(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_decode_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], ProtocolError> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(ProtocolError::InvalidDescription(format!(
            "{label} должен содержать {} hex-символов",
            N * 2
        )));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).unwrap();
        output[index] = u8::from_str_radix(text, 16).map_err(|_| {
            ProtocolError::InvalidDescription(format!("{label} содержит не-hex символ"))
        })?;
    }
    Ok(output)
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidDescription(String),
    InvalidPacket(String),
    AuthenticationFailed,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDescription(message) | Self::InvalidPacket(message) => {
                formatter.write_str(message)
            }
            Self::AuthenticationFailed => formatter.write_str("HMAC authentication failed"),
        }
    }
}

impl Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn description() -> PeerDescription {
        PeerDescription {
            session_id: [1_u8; 16],
            key: [2_u8; 32],
            candidates: vec![
                Candidate {
                    kind: CandidateKind::Host,
                    address: "192.168.50.10:40123".parse().unwrap(),
                },
                Candidate {
                    kind: CandidateKind::ServerReflexive,
                    address: "203.0.113.8:50123".parse().unwrap(),
                },
            ],
        }
    }

    #[test]
    fn session_code_round_trip_and_label_paste() {
        let expected = description();
        let code = expected.encode().unwrap();
        let pasted = format!("МОЙ КОД: {code} trailing text");
        assert_eq!(PeerDescription::parse(&pasted).unwrap(), expected);
    }

    #[test]
    fn session_code_checksum_detects_corruption() {
        let mut code = description().encode().unwrap().into_bytes();
        let index = code.iter().rposition(|byte| *byte == b'|').unwrap() - 1;
        code[index] = if code[index] == b'1' { b'2' } else { b'1' };
        let error = PeerDescription::parse(std::str::from_utf8(&code).unwrap()).unwrap_err();
        assert!(error.to_string().contains("checksum"));
    }

    #[test]
    fn own_session_code_is_rejected() {
        let local = description();
        let error = local.validate_remote(&local).unwrap_err();
        assert!(error.to_string().contains("собственный"));
    }

    #[test]
    fn authenticated_packet_round_trip() {
        let packet = ControlPacket {
            kind: PacketKind::Check,
            source_session: [3_u8; 16],
            destination_session: [4_u8; 16],
            transaction_id: [5_u8; 12],
        };
        let key = [6_u8; 32];
        let encoded = encode_control(packet, &key);
        assert_eq!(
            decode_control(&encoded, [3_u8; 16], [4_u8; 16], &key).unwrap(),
            packet
        );
    }

    #[test]
    fn modified_packet_or_wrong_key_fails_authentication() {
        let packet = ControlPacket {
            kind: PacketKind::CheckOk,
            source_session: [7_u8; 16],
            destination_session: [8_u8; 16],
            transaction_id: [9_u8; 12],
        };
        let mut encoded = encode_control(packet, &[10_u8; 32]);
        encoded[40] ^= 1;
        assert_eq!(
            decode_control(&encoded, [7_u8; 16], [8_u8; 16], &[10_u8; 32]),
            Err(ProtocolError::AuthenticationFailed)
        );

        let encoded = encode_control(packet, &[10_u8; 32]);
        assert_eq!(
            decode_control(&encoded, [7_u8; 16], [8_u8; 16], &[11_u8; 32]),
            Err(ProtocolError::AuthenticationFailed)
        );
    }

    #[test]
    fn arbitrary_packet_lengths_never_panic() {
        let key = [1_u8; 32];
        for length in 0..=256 {
            let bytes = vec![0xa5; length];
            let _ = decode_control(&bytes, [2_u8; 16], [3_u8; 16], &key);
        }
    }
}
