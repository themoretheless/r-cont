# NAT traversal pipeline

Этот документ разделяет учебный HP2 и production-решение. HP2 проверяет только путь `UDP CHECK → CHECK_OK`; он не является ICE, VPN, relay или защищённым remote-desktop transport.

## Reference pipeline

```text
Identity / keys
      ↓
Gather host + IPv6 + STUN + UPnP/PCP + relay candidates
      ↓
Exchange authenticated descriptors (signaling / rendezvous)
      ↓
Start relay path if available ──────────────────────┐
      ↓                                             │
Paced connectivity checks over all candidate pairs  │
      ↓                                             │
Nominate one bidirectional pair                     │
      ↓                                             │
Secure handshake (DTLS / Noise / QUIC-TLS)          │
      ↓                                             │
Data + consent/liveness monitoring                   │
      ↓                                             │
Path failure → recheck → migrate or relay fallback ┘
```

## Что делает HP2

1. Один UDP-сокет получает server-reflexive адрес через STUN и строит host-кандидат.
2. Один HP2-код содержит оба кандидата, session id и 256-битный session key.
3. Стороны вручную обмениваются кодами через доверенный канал — это signaling.
4. Один network worker проверяет все remote-кандидаты.
5. `CHECK_OK` принимается только для свежего txid и корректного HMAC.
6. Первый подтверждённый round-trip становится выбранным путём.
7. Consent checks поддерживают путь; после 15 секунд тишины начинается rechecking.

В HP2 нет шифрования прикладных данных, TURN/DERP fallback, nomination между несколькими успешными парами, ICE role/tie-breaker, peer discovery и NAT rebinding migration. Поэтому через него нельзя передавать команды удалённого управления, экран, файлы или пароли.

## Сравнение с open-source подходами

| Стадия | HP2 | WebRTC / ICE | libp2p | Tailscale | RustDesk |
|---|---|---|---|---|---|
| Signaling | Ручной код | Offer/answer приложения | Relay/control path | Coordination + DERP | `hbbs` rendezvous |
| Candidates | Host + STUN IPv4 | Host, srflx, prflx, TURN | Observed addresses + Circuit Relay | Интерфейсы, direct endpoints, DERP | Direct + relay |
| Checks | HMAC `CHECK/OK` | STUN checklist, triggered checks | DCUtR synchronization | DISCO probes | Direct attempt |
| Selection | Первый round-trip | Controlling agent nominates pair | Direct upgrade over relay | Direct preferred over DERP | Direct preferred over `hbbr` |
| Data protection | Нет | DTLS/SCTP или SRTP | Noise/TLS | WireGuard | E2E protocol |
| Fallback | Нет | TURN | Circuit Relay v2 | DERP / Peer Relay | `hbbr` |
| Recovery | Consent + recheck | ICE restart/consent freshness | Relay remains available | Continuous path upgrade | Rendezvous/relay retry |

Общий production-паттерн: side channel знакомит пиры, direct checks выполняются параллельно с relay, выбранный путь защищается стандартным транспортом, а relay остаётся fallback. «Без собственного signaling-сервера» в нашем примере означает ручной signaling через мессенджер, а не отсутствие третьей стороны вообще.

## Roadmap

- Подключить настоящий ICE-библиотечный стек вместо самодельного checklist.
- Добавить signaling/rendezvous с коротким TTL, отзывом ключей и candidate updates.
- Добавить TURN/Circuit Relay/DERP с authentication, quotas, expiry и anti-amplification.
- После выбора UDP-пути поверх него поднять Noise или QUIC/TLS; не изобретать шифрование самостоятельно.
- Для remote desktop отдельно определить поток экрана, ввод, clipboard, ACL и audit logging.

## Первичные источники

- [RFC 8489 — STUN](https://www.rfc-editor.org/rfc/rfc8489)
- [RFC 8445 — ICE](https://www.rfc-editor.org/rfc/rfc8445)
- [WebRTC specification](https://www.w3.org/TR/webrtc/)
- [libp2p DCUtR](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md)
- [libp2p Circuit Relay](https://libp2p.io/docs/circuit-relay/)
- [Tailscale connection types](https://tailscale.com/docs/reference/connection-types)
- [RustDesk self-host architecture](https://rustdesk.com/docs/en/self-host/)

