const HEADER_BYTES = 16;
const MAX_FRAME_BYTES = 1048576;
const BROADCAST = new Uint8Array(HEADER_BYTES);

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function isBroadcast(header: Uint8Array): boolean {
  return header.every((b) => b === 0);
}

/// One instance per mesh. Holds the connected sockets and forwards opaque
/// frames between them. It cannot decrypt anything and does not try.
export class MeshDurableObject implements DurableObject {
  constructor(private state: DurableObjectState, private env: unknown) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const device = url.searchParams.get('device');
    if (!device || !/^[0-9a-f]{32}$/.test(device)) {
      return new Response(null, { status: 400 });
    }
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response(null, { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // Hibernation: the DO can be evicted between messages and the socket
    // survives, so an idle mesh costs nothing.
    this.state.acceptWebSocket(server, [device]);

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(
    ws: WebSocket,
    message: ArrayBuffer | string,
  ): Promise<void> {
    if (typeof message === 'string') return;
    if (message.byteLength > MAX_FRAME_BYTES) {
      ws.close(1009, 'frame too large');
      return;
    }
    if (message.byteLength < HEADER_BYTES) return;

    const bytes = new Uint8Array(message);
    const header = bytes.slice(0, HEADER_BYTES);
    const destination = isBroadcast(header) ? null : bytesToHex(header);

    for (const peer of this.state.getWebSockets()) {
      if (peer === ws) continue;
      if (destination !== null) {
        const tags = this.state.getTags(peer);
        if (!tags.includes(destination)) continue;
      }
      try {
        peer.send(message);
      } catch {
        // A peer that died mid-forward is not the sender's problem.
      }
    }
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    try {
      ws.close();
    } catch {
      // Already closed.
    }
  }
}
