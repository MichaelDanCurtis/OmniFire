import { env, SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

const MESH = 'a'.repeat(32);
const DEV_A = '1'.repeat(32);
const DEV_B = '2'.repeat(32);
const BROADCAST = new Uint8Array(16);

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function frame(dest: Uint8Array, body: string): ArrayBuffer {
  const bodyBytes = new TextEncoder().encode(body);
  const out = new Uint8Array(16 + bodyBytes.length);
  out.set(dest, 0);
  out.set(bodyBytes, 16);
  return out.buffer;
}

async function connect(device: string): Promise<WebSocket> {
  const res = await SELF.fetch(
    `https://relay/v1/mesh/${MESH}/ws?device=${device}`,
    { headers: { Upgrade: 'websocket' } },
  );
  expect(res.status).toBe(101);
  const ws = res.webSocket!;
  ws.accept();
  return ws;
}

function nextMessage(ws: WebSocket): Promise<ArrayBuffer> {
  return new Promise((resolve) => {
    ws.addEventListener('message', (e) => resolve(e.data as ArrayBuffer), {
      once: true,
    });
  });
}

describe('relay', () => {
  it('reports health', async () => {
    const res = await SELF.fetch('https://relay/v1/health');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it('rejects a malformed mesh id', async () => {
    const res = await SELF.fetch(
      `https://relay/v1/mesh/NOT-HEX/ws?device=${DEV_A}`,
      { headers: { Upgrade: 'websocket' } },
    );
    expect(res.status).toBe(400);
  });

  it('rejects a missing device id', async () => {
    const res = await SELF.fetch(`https://relay/v1/mesh/${MESH}/ws`, {
      headers: { Upgrade: 'websocket' } },
    );
    expect(res.status).toBe(400);
  });

  it('rejects a non-websocket request to the ws path', async () => {
    const res = await SELF.fetch(
      `https://relay/v1/mesh/${MESH}/ws?device=${DEV_A}`,
    );
    expect(res.status).toBe(426);
  });

  it('routes a directed frame to the addressed device only', async () => {
    const a = await connect(DEV_A);
    const b = await connect(DEV_B);
    const received = nextMessage(b);
    a.send(frame(hexToBytes(DEV_B), 'ciphertext'));
    const got = new TextDecoder().decode(
      (await received) as ArrayBuffer,
    );
    expect(got.slice(16)).toBe('ciphertext');
  });

  it('broadcasts to every peer except the sender', async () => {
    const a = await connect(DEV_A);
    const b = await connect(DEV_B);
    const received = nextMessage(b);
    a.send(frame(BROADCAST, 'to everyone'));
    const got = new TextDecoder().decode((await received) as ArrayBuffer);
    expect(got.slice(16)).toBe('to everyone');
  });

  it('does not deliver a frame to an unrelated mesh', async () => {
    const other = await SELF.fetch(
      `https://relay/v1/mesh/${'b'.repeat(32)}/ws?device=${DEV_B}`,
      { headers: { Upgrade: 'websocket' } },
    );
    const otherWs = other.webSocket!;
    otherWs.accept();

    let delivered = false;
    otherWs.addEventListener('message', () => { delivered = true; });

    const a = await connect(DEV_A);
    a.send(frame(BROADCAST, 'mesh-local'));
    await new Promise((r) => setTimeout(r, 50));
    expect(delivered).toBe(false);
  });

  it('drops a frame shorter than the 16-byte header', async () => {
    const a = await connect(DEV_A);
    const b = await connect(DEV_B);
    let delivered = false;
    b.addEventListener('message', () => { delivered = true; });
    a.send(new Uint8Array(8).buffer);
    await new Promise((r) => setTimeout(r, 50));
    expect(delivered).toBe(false);
  });

  it('closes the socket on an oversized frame', async () => {
    const a = await connect(DEV_A);
    const closed = new Promise<number>((resolve) => {
      a.addEventListener('close', (e) => resolve(e.code), { once: true });
    });
    a.send(new Uint8Array(1048576 + 32).buffer);
    expect(await closed).toBe(1009);
  });
});
