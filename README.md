# DirectLink

Статическая WebRTC-страница для ручного соединения двух машин через NAT. GitHub Pages раздаёт только HTML/CSS/JS; signaling заменён копированием offer/answer, а данные после подключения идут через WebRTC DataChannel.

## Как соединиться

1. Откройте один и тот же HTTPS-адрес DirectLink на обеих машинах.
2. На первой машине выберите «Первая машина» и создайте приглашение.
3. Передайте код второй машине приватным способом.
4. На второй машине выберите «Вторая машина», вставьте приглашение и создайте ответ.
5. Верните ответ первой машине и нажмите «Завершить соединение».
6. Сверьте одинаковый код безопасности, затем проверьте канал через ping или чат.

В кодах уже находятся все ICE-кандидаты, поэтому отдельный signaling-сервер и `addIceCandidate()` не нужны.

## Локальный запуск

```bash
npm ci
npm run dev
```

Откройте `http://localhost:3000/`. Localhost считается безопасным контекстом для WebRTC.

Проверка обеих сборок и тестов:

```bash
npm test
```

Статический экспорт для GitHub Pages:

```bash
npm run build:pages
```

Результат появится в `out/`.

## Публикация на GitHub Pages

В проекте есть workflow `.github/workflows/deploy-pages.yml`. После push в ветку `main`:

1. Откройте **Settings → Pages** в репозитории.
2. В **Build and deployment → Source** выберите **GitHub Actions**.
3. Запустите workflow вручную или сделайте новый push.

Сборка автоматически учитывает подпуть репозитория, например `https://username.github.io/directlink/`.

## Что происходит в сети

- STUN: `stun:stun.cloudflare.com:3478` сообщает браузеру NAT mapping.
- Signaling: offer и answer переносятся вручную между машинами.
- Transport: браузеры пробуют ICE-кандидаты и прямой UDP-путь.
- Data: чат и ping идут в зашифрованном WebRTC DataChannel.

## Ограничения

TURN намеренно не настроен. Поэтому прямое соединение не гарантируется при symmetric NAT, строгом CGNAT и блокировке UDP. Это ожидаемый предел полностью бесплатной статической схемы: для гарантированного соединения понадобится публичный relay/TURN.

Коды содержат IP-адреса, порты, ICE credentials и DTLS fingerprint. Не публикуйте их и не храните в URL. Код сверки подтверждает, что обе машины видят одну пару DTLS fingerprints, но сам по себе не устанавливает личность собеседника.

Полезные первичные источники: [Cloudflare STUN/TURN](https://developers.cloudflare.com/realtime/turn/), [WebRTC specification](https://www.w3.org/TR/webrtc/), [GitHub Pages HTTPS](https://docs.github.com/en/pages/getting-started-with-github-pages/securing-your-github-pages-site-with-https).

## Вариант на Rust без WebRTC

В каталоге [`rust-hole-punch`](./rust-hole-punch/) есть консольный HP2 PoC: ручной STUN, один descriptor с LAN/public candidates, HMAC-проверенные connectivity checks, автоматический выбор прямого UDP-пути и consent/recheck state machine. Подробное сравнение с ICE, libp2p, Tailscale и RustDesk находится в [`PIPELINE.md`](./rust-hole-punch/PIPELINE.md).
