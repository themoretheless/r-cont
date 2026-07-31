# UDP hole punching на Rust — HP2

Учебный диагностический PoC для двух машин за NAT. Он не передаёт пользовательские данные: задача — проверить, существует ли сейчас прямой UDP round-trip.

Что внутри:

- один `UdpSocket` и один network worker;
- STUN Binding Request по RFC 8489;
- public и LAN candidates в одном session code;
- HMAC-SHA256 control packets;
- свежие transaction IDs для `CHECK/CHECK_OK`;
- bounded checking на 30 секунд;
- RTT, progress, consent checks и rechecking;
- fake STUN, parser, protocol и loopback integration tests.

## Запуск

На обеих машинах:

```bash
cd rust-hole-punch
cargo run
```

Порядок:

1. Дождитесь `STUN OK` и блока `BEGIN SESSION CODE`.
2. Передайте весь HP2-код второй машине через доверенный канал.
3. Вставьте код второй машины в каждую программу.
4. Дождитесь `[OK] Получен ответ на наш probe`.
5. Используйте `/status`, `/ping`, `/retry`, `/replace-code`, `/quit`.

Код содержит IP-кандидаты и секрет сеанса. Не публикуйте его. Он не даёт шифрования; не передавайте через этот PoC пароли, команды, экран, файлы или клавиатурный ввод.

Если NAT изменил внешний порт, появится `[CODE EXPIRED]`: передайте новый код. Если за 30 секунд нет ответа, это не доказывает поломку конкретного роутера — строгий NAT, CGNAT, client isolation, VPN или блокировка UDP могут требовать relay.

Только проверить STUN:

```bash
cargo run -- --stun-only
```

`--stun-only` намеренно не печатает код для обмена: после завершения процесса mapping закрывается.

Другой STUN endpoint:

```bash
cargo run -- --stun stun.example.org:3478
```

## Проверки

```bash
cargo +stable fmt -- --check
cargo +stable test
cargo +stable clippy --all-targets -- -D warnings
```

Живой STUN-запрос требует UDP-доступа к `stun.cloudflare.com:3478`. Системный firewall должен разрешить сетевой доступ самому бинарю; отключать firewall целиком не нужно.

## Ограничения

HP2 не реализует полный ICE: нет signaling-сервиса, TURN/DERP/Circuit Relay fallback, IPv6 peer-кандидатов, UPnP/PCP, controlling/controlled nomination, NAT rebinding migration и защищённого data transport. Подробная схема и сравнение с WebRTC, libp2p, Tailscale и RustDesk находятся в [PIPELINE.md](PIPELINE.md).

