"use client";

import { FormEvent, useEffect, useRef, useState } from "react";

type Role = "host" | "guest";
type BusyAction = "offer" | "answer" | "apply" | "probe" | null;

type SignalPayload = {
  app: "directlink";
  version: 1;
  sessionId: string;
  createdAt: number;
  description: {
    type: RTCSdpType;
    sdp: string;
  };
};

type Endpoint = {
  address: string;
  port: string;
  protocol: string;
  type: string;
};

type PathInfo = {
  direct: boolean;
  label: string;
  local: string;
  remote: string;
  protocol: string;
};

type ChatMessage = {
  id: string;
  direction: "out" | "in";
  text: string;
  time: string;
};

const PEER_CONFIG: RTCConfiguration = {
  iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }],
  iceCandidatePoolSize: 4,
};

const SIGNAL_PREFIX = "DIRECTLINK1.";
const MAX_SIGNAL_LENGTH = 150_000;
const GATHER_TIMEOUT_MS = 15_000;

const connectionLabels: Record<string, string> = {
  new: "Ожидание",
  connecting: "Соединяемся",
  connected: "Соединено",
  disconnected: "Связь потеряна",
  failed: "Не удалось",
  closed: "Закрыто",
};

function makeId() {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
}

function bytesToBase64Url(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlToBytes(value: string) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeSignal(description: RTCSessionDescriptionInit, sessionId: string) {
  if (!description.type || !description.sdp) {
    throw new Error("Браузер не создал полное описание соединения.");
  }

  const payload: SignalPayload = {
    app: "directlink",
    version: 1,
    sessionId,
    createdAt: Date.now(),
    description: { type: description.type, sdp: description.sdp },
  };

  return SIGNAL_PREFIX + bytesToBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
}

function decodeSignal(rawValue: string) {
  const value = rawValue.trim();
  if (!value) throw new Error("Сначала вставьте код с другой машины.");
  if (value.length > MAX_SIGNAL_LENGTH) throw new Error("Код слишком большой и выглядит некорректно.");
  if (!value.startsWith(SIGNAL_PREFIX)) throw new Error("Это не код DirectLink.");

  try {
    const json = new TextDecoder().decode(base64UrlToBytes(value.slice(SIGNAL_PREFIX.length)));
    const payload = JSON.parse(json) as Partial<SignalPayload>;

    if (
      payload.app !== "directlink" ||
      payload.version !== 1 ||
      typeof payload.sessionId !== "string" ||
      payload.sessionId.length < 8 ||
      payload.sessionId.length > 128 ||
      typeof payload.createdAt !== "number" ||
      !Number.isFinite(payload.createdAt) ||
      !payload.description?.sdp ||
      !["offer", "answer"].includes(payload.description.type ?? "")
    ) {
      throw new Error("invalid");
    }

    if (Math.abs(Date.now() - payload.createdAt) > 24 * 60 * 60 * 1000) {
      throw new Error("stale");
    }

    return payload as SignalPayload;
  } catch (error) {
    if (error instanceof Error && error.message === "stale") {
      throw new Error("Код неактуален либо часы на машинах расходятся больше чем на сутки.");
    }
    throw new Error("Код повреждён или был скопирован не полностью.");
  }
}

function waitForIceGathering(peer: RTCPeerConnection): Promise<boolean> {
  if (peer.iceGatheringState === "complete") return Promise.resolve(true);

  return new Promise((resolve) => {
    let finished = false;
    const finish = (complete: boolean) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      peer.removeEventListener("icegatheringstatechange", onStateChange);
      peer.removeEventListener("icecandidate", onCandidate);
      resolve(complete);
    };
    const onStateChange = () => {
      if (peer.iceGatheringState === "complete") finish(true);
    };
    const onCandidate = (event: RTCPeerConnectionIceEvent) => {
      if (event.candidate === null) finish(true);
    };
    const timer = window.setTimeout(() => finish(false), GATHER_TIMEOUT_MS);

    peer.addEventListener("icegatheringstatechange", onStateChange);
    peer.addEventListener("icecandidate", onCandidate);
  });
}

function parseCandidates(sdp = "") {
  return sdp
    .split(/\r?\n/)
    .filter((line) => line.startsWith("a=candidate:"))
    .map((line) => {
      const fields = line.slice(2).trim().split(/\s+/);
      const typeIndex = fields.indexOf("typ");
      return {
        address: fields[4] ?? "",
        port: fields[5] ?? "",
        protocol: (fields[2] ?? "udp").toUpperCase(),
        type: typeIndex >= 0 ? fields[typeIndex + 1] : "unknown",
      } satisfies Endpoint;
    })
    .filter((candidate) => candidate.address && candidate.port);
}

function isGlobalIpv6(address: string) {
  const normalized = address.toLowerCase();
  return (
    normalized.includes(":") &&
    !normalized.startsWith("fe80:") &&
    !normalized.startsWith("fc") &&
    !normalized.startsWith("fd") &&
    normalized !== "::1"
  );
}

function publicCandidates(sdp = "") {
  const candidates = parseCandidates(sdp).filter(
    (candidate) => candidate.type === "srflx" || (candidate.type === "host" && isGlobalIpv6(candidate.address)),
  );
  const unique = new Map(candidates.map((candidate) => [`${candidate.address}:${candidate.port}`, candidate]));
  return [...unique.values()];
}

function formatEndpoint(endpoint: Endpoint) {
  const address = endpoint.address.includes(":") ? `[${endpoint.address}]` : endpoint.address;
  return `${address}:${endpoint.port}`;
}

function extractFingerprint(sdp = "") {
  return sdp.match(/^a=fingerprint:\S+\s+(.+)$/m)?.[1]?.trim() ?? "";
}

async function safetyCode(peer: RTCPeerConnection) {
  const fingerprints = [
    extractFingerprint(peer.localDescription?.sdp),
    extractFingerprint(peer.remoteDescription?.sdp),
  ]
    .filter(Boolean)
    .sort();

  if (fingerprints.length !== 2 || !globalThis.crypto?.subtle) return "";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(fingerprints.join("|")));
  const compact = [...new Uint8Array(digest)]
    .slice(0, 8)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
  return compact.match(/.{1,4}/g)?.join("-") ?? compact;
}

function candidateLabel(candidate: Record<string, unknown> | undefined) {
  if (!candidate) return "не определён";
  const address = String(candidate.address ?? candidate.ip ?? "адрес скрыт");
  const port = candidate.port ? `:${candidate.port}` : "";
  const type = candidate.candidateType ? ` (${candidate.candidateType})` : "";
  return `${address}${port}${type}`;
}

async function readSelectedPath(peer: RTCPeerConnection): Promise<PathInfo | null> {
  const stats = await peer.getStats();
  let pair: Record<string, unknown> | undefined;

  stats.forEach((report) => {
    const item = report as unknown as Record<string, unknown>;
    if (item.type === "transport" && item.selectedCandidatePairId) {
      pair = stats.get(String(item.selectedCandidatePairId)) as unknown as Record<string, unknown>;
    }
  });

  if (!pair) {
    stats.forEach((report) => {
      const item = report as unknown as Record<string, unknown>;
      if (
        item.type === "candidate-pair" &&
        item.state === "succeeded" &&
        (item.nominated === true || item.selected === true)
      ) {
        pair = item;
      }
    });
  }

  if (!pair) return null;
  const local = stats.get(String(pair.localCandidateId)) as unknown as Record<string, unknown> | undefined;
  const remote = stats.get(String(pair.remoteCandidateId)) as unknown as Record<string, unknown> | undefined;
  const direct = local?.candidateType !== "relay" && remote?.candidateType !== "relay";
  const localType = String(local?.candidateType ?? "unknown");
  const remoteType = String(remote?.candidateType ?? "unknown");

  return {
    direct,
    label: direct ? `Прямой путь · ${localType} ↔ ${remoteType}` : "Через relay",
    local: candidateLabel(local),
    remote: candidateLabel(remote),
    protocol: String(local?.protocol ?? pair.protocol ?? "udp").toUpperCase(),
  };
}

export default function Home() {
  const [role, setRole] = useState<Role>("host");
  const [busy, setBusy] = useState<BusyAction>(null);
  const [localCode, setLocalCode] = useState("");
  const [remoteCode, setRemoteCode] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [copied, setCopied] = useState("");
  const [connectionState, setConnectionState] = useState<RTCPeerConnectionState>("new");
  const [iceState, setIceState] = useState<RTCIceConnectionState>("new");
  const [channelState, setChannelState] = useState<RTCDataChannelState>("closed");
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [path, setPath] = useState<PathInfo | null>(null);
  const [verificationCode, setVerificationCode] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [messageText, setMessageText] = useState("");
  const [roundTrip, setRoundTrip] = useState<number | null>(null);

  const peerRef = useRef<RTCPeerConnection | null>(null);
  const channelRef = useRef<RTCDataChannel | null>(null);
  const activeRoleRef = useRef<Role | null>(null);
  const sessionIdRef = useRef("");
  const lastPingRef = useRef<{ id: string; sentAt: number } | null>(null);

  const connected = connectionState === "connected" && channelState === "open";

  function closeTransport() {
    if (channelRef.current) {
      channelRef.current.onopen = null;
      channelRef.current.onclose = null;
      channelRef.current.onerror = null;
      channelRef.current.onmessage = null;
      channelRef.current.close();
    }
    if (peerRef.current) {
      peerRef.current.onconnectionstatechange = null;
      peerRef.current.oniceconnectionstatechange = null;
      peerRef.current.onicecandidateerror = null;
      peerRef.current.ondatachannel = null;
      peerRef.current.close();
    }
    channelRef.current = null;
    peerRef.current = null;
    activeRoleRef.current = null;
    setConnectionState("new");
    setIceState("new");
    setChannelState("closed");
    setPath(null);
    setVerificationCode("");
    setMessages([]);
    setRoundTrip(null);
  }

  useEffect(() => () => {
    channelRef.current?.close();
    peerRef.current?.close();
  }, []);

  useEffect(() => {
    if (connectionState !== "connected" || !peerRef.current) return;
    const peer = peerRef.current;
    let cancelled = false;

    const refresh = async () => {
      try {
        const selected = await readSelectedPath(peer);
        if (!cancelled && selected) setPath(selected);
      } catch {
        // Some browsers expose the selected pair a moment after connection.
      }
    };

    void refresh();
    const interval = window.setInterval(refresh, 3_000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [connectionState]);

  function addMessage(direction: ChatMessage["direction"], text: string) {
    setMessages((current) => [
      ...current.slice(-49),
      { id: makeId(), direction, text, time: new Date().toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" }) },
    ]);
  }

  function bindChannel(channel: RTCDataChannel) {
    channelRef.current = channel;
    setChannelState(channel.readyState);

    channel.onopen = () => {
      if (channelRef.current !== channel) return;
      setChannelState("open");
      setNotice("Канал открыт. Можно проверить задержку или отправить сообщение.");
    };
    channel.onclose = () => {
      if (channelRef.current === channel) setChannelState("closed");
    };
    channel.onerror = () => {
      if (channelRef.current === channel) setError("Ошибка канала данных. Создайте новое соединение.");
    };
    channel.onmessage = (event) => {
      if (channelRef.current !== channel) return;
      if (typeof event.data !== "string" || event.data.length > 8_000) return;
      try {
        const payload = JSON.parse(event.data) as Record<string, unknown>;
        if (payload.type === "chat" && typeof payload.text === "string") {
          addMessage("in", payload.text.slice(0, 1_000));
        } else if (payload.type === "ping" && typeof payload.id === "string" && typeof payload.sentAt === "number") {
          channel.send(JSON.stringify({ type: "pong", id: payload.id, sentAt: payload.sentAt }));
        } else if (payload.type === "pong" && typeof payload.id === "string") {
          const ping = lastPingRef.current;
          if (ping?.id === payload.id) setRoundTrip(Date.now() - ping.sentAt);
        }
      } catch {
        // Ignore malformed peer messages instead of rendering them as markup.
      }
    };
  }

  function createPeer(nextRole: Role) {
    closeTransport();
    const peer = new RTCPeerConnection(PEER_CONFIG);
    peerRef.current = peer;
    activeRoleRef.current = nextRole;
    setConnectionState(peer.connectionState);
    setIceState(peer.iceConnectionState);

    peer.onconnectionstatechange = () => {
      if (peerRef.current !== peer) return;
      setConnectionState(peer.connectionState);
      if (peer.connectionState === "failed") {
        setError("Прямое соединение не получилось. Вероятен строгий NAT, CGNAT или блокировка UDP.");
      }
    };
    peer.oniceconnectionstatechange = () => {
      if (peerRef.current === peer) setIceState(peer.iceConnectionState);
    };
    peer.onicecandidateerror = (event) => {
      if (peerRef.current !== peer) return;
      const iceError = event as RTCPeerConnectionIceErrorEvent;
      setNotice(
        iceError.errorCode === 701
          ? "STUN-сервер недоступен из этой сети. Код может содержать только локальный адрес."
          : `STUN сообщил об ошибке ${iceError.errorCode}.`,
      );
    };
    peer.ondatachannel = (event) => {
      if (peerRef.current !== peer) {
        event.channel.close();
        return;
      }
      bindChannel(event.channel);
    };
    return peer;
  }

  async function discoverAddress() {
    setBusy("probe");
    setError("");
    setNotice("");
    setEndpoints([]);
    const probe = new RTCPeerConnection(PEER_CONFIG);

    try {
      probe.createDataChannel("probe");
      await probe.setLocalDescription(await probe.createOffer());
      const complete = await waitForIceGathering(probe);
      const found = publicCandidates(probe.localDescription?.sdp);
      setEndpoints(found);
      if (!complete) setNotice("Проверка остановлена по таймауту: STUN мог быть заблокирован.");
      if (!found.length) {
        setNotice("Публичный кандидат не найден. Возможно, STUN заблокирован или браузер не получил маршрут.");
      }
    } catch {
      setError("Не удалось выполнить STUN-проверку в этом браузере.");
    } finally {
      probe.close();
      setBusy(null);
    }
  }

  async function createOffer() {
    setBusy("offer");
    setError("");
    setNotice("");
    setEndpoints([]);
    setLocalCode("");
    setRemoteCode("");

    try {
      const peer = createPeer("host");
      const channel = peer.createDataChannel("directlink", { ordered: true });
      bindChannel(channel);
      const sessionId = makeId();
      sessionIdRef.current = sessionId;

      await peer.setLocalDescription(await peer.createOffer());
      const complete = await waitForIceGathering(peer);
      if (!peer.localDescription) throw new Error("empty");
      setLocalCode(encodeSignal(peer.localDescription, sessionId));
      setEndpoints(publicCandidates(peer.localDescription.sdp));
      setNotice(
        complete
          ? "Приглашение готово. Передайте код второй машине приватным способом."
          : "Код создан по таймауту. Если в нём нет публичного адреса, соединение может не состояться.",
      );
    } catch {
      closeTransport();
      setError("Не удалось создать приглашение. Проверьте поддержку WebRTC и доступ к UDP.");
    } finally {
      setBusy(null);
    }
  }

  async function createAnswer() {
    setBusy("answer");
    setError("");
    setNotice("");
    setEndpoints([]);
    setLocalCode("");

    try {
      const offer = decodeSignal(remoteCode);
      if (offer.description.type !== "offer") throw new Error("Нужен код приглашения, а не ответ.");
      const peer = createPeer("guest");
      sessionIdRef.current = offer.sessionId;
      await peer.setRemoteDescription(offer.description);
      await peer.setLocalDescription(await peer.createAnswer());
      const complete = await waitForIceGathering(peer);
      if (!peer.localDescription) throw new Error("empty");

      setLocalCode(encodeSignal(peer.localDescription, offer.sessionId));
      setEndpoints(publicCandidates(peer.localDescription.sdp));
      setVerificationCode(await safetyCode(peer));
      setNotice(
        complete
          ? "Ответ готов. Верните этот код на первую машину."
          : "Ответ создан по таймауту. Соединение может не пройти через строгий NAT.",
      );
    } catch (caught) {
      closeTransport();
      setError(caught instanceof Error ? caught.message : "Не удалось обработать приглашение.");
    } finally {
      setBusy(null);
    }
  }

  async function applyAnswer() {
    setBusy("apply");
    setError("");
    setNotice("");

    try {
      const answer = decodeSignal(remoteCode);
      const peer = peerRef.current;
      if (!peer || activeRoleRef.current !== "host" || !sessionIdRef.current) {
        throw new Error("Сначала создайте новое приглашение на этой машине.");
      }
      if (answer.description.type !== "answer") throw new Error("Нужен код ответа со второй машины.");
      if (answer.sessionId !== sessionIdRef.current) throw new Error("Этот ответ относится к другому приглашению.");
      if (peer.signalingState !== "have-local-offer") throw new Error("Это приглашение уже использовано или устарело.");

      await peer.setRemoteDescription(answer.description);
      setVerificationCode(await safetyCode(peer));
      setNotice("Ответ принят. WebRTC проверяет доступные маршруты между машинами.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Не удалось применить ответ.");
    } finally {
      setBusy(null);
    }
  }

  async function copyCode(value: string, key: string) {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = value;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    setCopied(key);
    window.setTimeout(() => setCopied(""), 1_500);
  }

  function changeRole(nextRole: Role) {
    if (role === nextRole || busy !== null) return;
    closeTransport();
    setRole(nextRole);
    setLocalCode("");
    setRemoteCode("");
    setError("");
    setNotice("");
    setEndpoints([]);
    sessionIdRef.current = "";
  }

  function sendMessage(event: FormEvent) {
    event.preventDefault();
    const text = messageText.trim().slice(0, 1_000);
    const channel = channelRef.current;
    if (!text || channel?.readyState !== "open") return;
    channel.send(JSON.stringify({ type: "chat", text }));
    addMessage("out", text);
    setMessageText("");
  }

  function sendPing() {
    const channel = channelRef.current;
    if (channel?.readyState !== "open") return;
    const ping = { id: makeId(), sentAt: Date.now() };
    lastPingRef.current = ping;
    setRoundTrip(null);
    channel.send(JSON.stringify({ type: "ping", ...ping }));
  }

  return (
    <main>
      <header className="site-header">
        <a className="brand" href="#top" aria-label="DirectLink — в начало">
          <span className="brand-mark" aria-hidden="true"><i /><i /></span>
          <span>DIRECTLINK</span>
        </a>
        <div className="header-note"><span /> Без аккаунта · без backend</div>
      </header>

      <section className="hero" id="top">
        <div className="hero-copy">
          <p className="eyebrow">WEBRTC / UDP HOLE PUNCHING</p>
          <h1>Соедините две машины <em>напрямую</em></h1>
          <p className="hero-lead">
            Откройте эту страницу на двух устройствах, обменяйтесь двумя кодами — и браузеры попробуют
            построить зашифрованный P2P-канал через NAT.
          </p>
          <a className="primary-link" href="#connect">Начать соединение <span>↓</span></a>
        </div>

        <aside className="address-card" aria-labelledby="address-title">
          <div className="card-kicker">STUN CHECK</div>
          <h2 id="address-title">Ваш адрес в интернете</h2>
          <div className={`address-display ${endpoints.length ? "has-value" : ""}`} aria-live="polite">
            {busy === "probe" ? (
              <span className="scanning">Ищем публичный маршрут…</span>
            ) : endpoints.length ? (
              endpoints.map((endpoint) => (
                <span className="endpoint" key={`${endpoint.address}:${endpoint.port}`}>
                  <strong>{formatEndpoint(endpoint)}</strong>
                  <small>{endpoint.protocol} · {endpoint.type === "srflx" ? "NAT mapping" : "public IPv6"}</small>
                </span>
              ))
            ) : (
              <span>Пока не проверен</span>
            )}
          </div>
          <button className="secondary-button full" onClick={discoverAddress} disabled={busy !== null}>
            {busy === "probe" ? "Проверяем…" : "Узнать через STUN"}
          </button>
          <p>Порт относится только к текущему WebRTC-сокету и может измениться при следующей проверке.</p>
        </aside>
      </section>

      <section className="how-strip" aria-label="Как проходит соединение">
        <div><span>01</span><strong>Страница</strong><small>загружает интерфейс</small></div>
        <b aria-hidden="true">→</b>
        <div><span>02</span><strong>STUN</strong><small>находит NAT mapping</small></div>
        <b aria-hidden="true">→</b>
        <div><span>03</span><strong>WebRTC</strong><small>пробует прямой UDP</small></div>
        <b aria-hidden="true">→</b>
        <div><span>04</span><strong>DataChannel</strong><small>несёт ваши данные</small></div>
      </section>

      <section className="connect-section" id="connect">
        <div className="section-heading">
          <p className="eyebrow">РУЧНОЙ SIGNALING</p>
          <h2>Кем будет эта машина?</h2>
          <p>Коды можно передать в любом мессенджере. Сайт их не получает и не хранит.</p>
        </div>

        <div className="role-switch" role="tablist" aria-label="Роль этой машины">
          <button
            className={role === "host" ? "active" : ""}
            onClick={() => changeRole("host")}
            disabled={busy !== null}
            role="tab"
            aria-selected={role === "host"}
          >
            <span>A</span>
            <strong>Первая машина</strong>
            <small>создаёт приглашение</small>
          </button>
          <button
            className={role === "guest" ? "active" : ""}
            onClick={() => changeRole("guest")}
            disabled={busy !== null}
            role="tab"
            aria-selected={role === "guest"}
          >
            <span>B</span>
            <strong>Вторая машина</strong>
            <small>создаёт ответ</small>
          </button>
        </div>

        <div className="status-bar" aria-live="polite">
          <div className={`status-dot ${connected ? "online" : connectionState === "failed" ? "failed" : ""}`} />
          <div>
            <small>СОСТОЯНИЕ</small>
            <strong>{connected ? "Канал открыт" : connectionLabels[connectionState] ?? connectionState}</strong>
          </div>
          <div className="status-meta"><span>ICE: {iceState}</span><span>DATA: {channelState}</span></div>
        </div>

        {role === "host" ? (
          <div className="steps-grid">
            <article className="step-card">
              <div className="step-heading"><span>1</span><div><h3>Создайте приглашение</h3><p>Мы соберём адреса и упакуем offer вместе с ICE-кандидатами.</p></div></div>
              <button className="primary-button" onClick={createOffer} disabled={busy !== null}>
                {busy === "offer" ? "Собираем ICE-кандидаты…" : "Создать код приглашения"}
              </button>
              <label htmlFor="host-offer">Код для второй машины</label>
              <div className="code-box">
                <textarea id="host-offer" value={localCode} readOnly spellCheck={false} placeholder="Код появится здесь" />
                <button onClick={() => copyCode(localCode, "offer")} disabled={!localCode}>
                  {copied === "offer" ? "Скопировано" : "Копировать"}
                </button>
              </div>
            </article>

            <article className="step-card">
              <div className="step-heading"><span>2</span><div><h3>Примите ответ</h3><p>Вставьте код, который создала вторая машина.</p></div></div>
              <label htmlFor="host-answer">Код ответа</label>
              <textarea
                id="host-answer"
                className="input-code"
                value={remoteCode}
                onChange={(event) => setRemoteCode(event.target.value)}
                spellCheck={false}
                placeholder="DIRECTLINK1.…"
              />
              <button className="primary-button" onClick={applyAnswer} disabled={busy !== null || !remoteCode.trim() || !localCode}>
                {busy === "apply" ? "Проверяем маршрут…" : "Завершить соединение"}
              </button>
            </article>
          </div>
        ) : (
          <div className="steps-grid guest-grid">
            <article className="step-card">
              <div className="step-heading"><span>1</span><div><h3>Вставьте приглашение</h3><p>Получите код с первой машины и вставьте его целиком.</p></div></div>
              <label htmlFor="guest-offer">Код приглашения</label>
              <textarea
                id="guest-offer"
                className="input-code"
                value={remoteCode}
                onChange={(event) => setRemoteCode(event.target.value)}
                spellCheck={false}
                placeholder="DIRECTLINK1.…"
              />
              <button className="primary-button" onClick={createAnswer} disabled={busy !== null || !remoteCode.trim()}>
                {busy === "answer" ? "Собираем ICE-кандидаты…" : "Создать код ответа"}
              </button>
            </article>

            <article className="step-card">
              <div className="step-heading"><span>2</span><div><h3>Верните ответ</h3><p>Скопируйте результат обратно на первую машину.</p></div></div>
              <label htmlFor="guest-answer">Код для первой машины</label>
              <div className="code-box tall">
                <textarea id="guest-answer" value={localCode} readOnly spellCheck={false} placeholder="Ответ появится здесь" />
                <button onClick={() => copyCode(localCode, "answer")} disabled={!localCode}>
                  {copied === "answer" ? "Скопировано" : "Копировать"}
                </button>
              </div>
            </article>
          </div>
        )}

        {(error || notice) && (
          <div className={`message-banner ${error ? "error" : ""}`} role={error ? "alert" : "status"}>
            <span aria-hidden="true">{error ? "!" : "i"}</span>{error || notice}
          </div>
        )}
      </section>

      <section className="proof-section">
        <div className="proof-copy">
          <p className="eyebrow">ПРОВЕРКА КАНАЛА</p>
          <h2>Убедитесь, что машины действительно связались</h2>
          <p>После подключения отправьте ping или короткое сообщение. Это данные внутри WebRTC DataChannel, а не запрос к GitHub Pages.</p>

          <div className="path-card">
            <div className="path-title">
              <span className={path?.direct ? "route-direct" : "route-wait"} aria-hidden="true" />
              <div><small>ВЫБРАННЫЙ МАРШРУТ</small><strong>{path?.label ?? "Появится после соединения"}</strong></div>
            </div>
            {path && <dl><div><dt>Локально</dt><dd>{path.local}</dd></div><div><dt>Удалённо</dt><dd>{path.remote}</dd></div><div><dt>Протокол</dt><dd>{path.protocol}</dd></div></dl>}
          </div>

          {verificationCode && (
            <div className="verify-card">
              <small>КОД СВЕРКИ</small>
              <strong>{verificationCode}</strong>
              <p>На обеих машинах должен быть одинаковым. Сверьте его голосом или в другом канале.</p>
            </div>
          )}
        </div>

        <div className={`chat-card ${connected ? "ready" : ""}`}>
          <div className="chat-head">
            <div><span className="terminal-dots" aria-hidden="true"><i /><i /><i /></span><strong>CHANNEL TEST</strong></div>
            <span>{connected ? "ONLINE" : "OFFLINE"}</span>
          </div>
          <div className="chat-log" aria-live="polite">
            {messages.length ? messages.map((message) => (
              <div className={`chat-message ${message.direction}`} key={message.id}>
                <small>{message.direction === "out" ? "Эта машина" : "Другая машина"} · {message.time}</small>
                <p>{message.text}</p>
              </div>
            )) : (
              <div className="chat-empty"><span>↔</span><p>{connected ? "Канал готов. Отправьте первое сообщение." : "Сначала завершите обмен кодами на обеих машинах."}</p></div>
            )}
          </div>
          <div className="ping-row">
            <button onClick={sendPing} disabled={!connected}>PING</button>
            <span>{roundTrip === null ? "RTT —" : `RTT ${roundTrip} ms`}</span>
          </div>
          <form className="chat-form" onSubmit={sendMessage}>
            <label className="sr-only" htmlFor="chat-message">Сообщение второй машине</label>
            <input
              id="chat-message"
              value={messageText}
              onChange={(event) => setMessageText(event.target.value)}
              disabled={!connected}
              maxLength={1_000}
              placeholder={connected ? "Напишите сообщение…" : "Канал ещё не открыт"}
            />
            <button disabled={!connected || !messageText.trim()} aria-label="Отправить сообщение">→</button>
          </form>
        </div>
      </section>

      <section className="limits-section">
        <div><span>✓</span><h3>Что здесь бесплатно</h3><p>GitHub Pages раздаёт статическую страницу, а публичный STUN помогает узнать NAT mapping. Отдельный signaling-сервер заменён ручным обменом кодов.</p></div>
        <div><span>!</span><h3>Когда не сработает</h3><p>Без TURN нет гарантии для symmetric NAT, строгого CGNAT и сетей, где UDP заблокирован. Тогда нужен relay-сервер.</p></div>
        <div><span>→</span><h3>Что будет дальше</h3><p>Сейчас это безопасный proof of concept: чат и ping. Экран, управление и передача файлов потребуют отдельного приложения и явного разрешения пользователя.</p></div>
      </section>

      <footer>
        <span>DIRECTLINK / P2P LAB</span>
        <p>Коды содержат сетевые адреса. Передавайте их только тому, с кем хотите соединиться.</p>
      </footer>
    </main>
  );
}
