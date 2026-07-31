import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function renderWorker() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("renders the DirectLink connection workflow", async () => {
  const response = await renderWorker();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>DirectLink — P2P через NAT в браузере<\/title>/i);
  assert.match(html, /Соедините две машины/);
  assert.match(html, /Создать код приглашения/);
  assert.match(html, /Вторая машина/);
  assert.match(html, /CHANNEL TEST/);
  assert.match(html, /Без TURN нет гарантии/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("contains non-trickle WebRTC and defensive manual signaling", async () => {
  const source = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.match(source, /stun:stun\.cloudflare\.com:3478/);
  assert.match(source, /iceGatheringState === "complete"/);
  assert.match(source, /event\.candidate === null/);
  assert.match(source, /createDataChannel\("directlink"/);
  assert.match(source, /Создать код ответа/);
  assert.match(source, /setRemoteDescription/);
  assert.match(source, /DIRECTLINK1\./);
  assert.match(source, /MAX_SIGNAL_LENGTH/);
  assert.match(source, /answer\.sessionId !== sessionIdRef\.current/);
  assert.doesNotMatch(source, /innerHTML|localStorage|sessionStorage/);
});

test("exports a GitHub Pages-ready static site and social card", async () => {
  const [html, image] = await Promise.all([
    readFile(new URL("../out/index.html", import.meta.url), "utf8"),
    readFile(new URL("../out/og.png", import.meta.url)),
  ]);

  assert.match(html, /<html lang="ru">/);
  assert.match(html, /_next\/static\/chunks\/app\/page-/);
  assert.match(html, /property="og:image"/);
  assert.equal(image.subarray(1, 4).toString(), "PNG");
  assert.equal(image.readUInt32BE(16), 1200);
  assert.equal(image.readUInt32BE(20), 630);
});
