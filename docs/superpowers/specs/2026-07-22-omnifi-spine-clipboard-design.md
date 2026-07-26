# OmniFi — Project 1: Transport Spine + Universal Clipboard

**Date:** 2026-07-22
**Status:** Approved design
**Scope:** Project 1 of 4. Later projects (iMessage bridge, audio bridge, video bridge) are out of scope and get their own specs.

---

## 1. Context

OmniFi bridges iPhone capabilities to any machine. The full product vision spans four largely independent subsystems:

1. **Transport + pairing spine** — device identity, discovery, encrypted channel, reconnection *(this spec)*
2. **iMessage bridge** — macOS acts as relay server; reads `chat.db`, drives the send path
3. **Audio bridge** — iPhone mic → PC virtual input device; PC text → Neural Engine TTS → audio back
4. **Video bridge** — iPhone camera → PC virtual webcam device

Projects 3 and 4 each require writing kernel-adjacent driver code on Windows (virtual audio device, virtual camera device). That work is unrelated to iPhones and is the single largest schedule risk in the overall product.

**This project builds the spine, using universal clipboard as the proving payload.** Clipboard is not the product; it is the integration test that validates pairing, encryption, link failover, and reconnection before weeks are committed to a harder feature.

### Decisions already made

| Decision | Choice | Rationale |
|---|---|---|
| Messaging target | iMessage specifically, Mac-relayed | No sanctioned iMessage API exists; a Mac reading local `chat.db` is the only durable path |
| Audience | Self + a handful of people | Needs pairing and config UI; no App Store, accounts, or billing |
| First feature | Transport spine + clipboard | Proves the spine end-to-end in days, not weeks; zero driver risk |
| Networking | LAN-direct preferred, Cloudflare relay fallback | Works everywhere; keeps low-latency direct path available for later media features |
| Client stack | Flutter (macOS, Windows, iOS) | One protocol implementation in Dart across all three targets |

### Known constraint on the overall product

Apple provides no iMessage API. The Mac app will be a **required server**, not an optional peer, and must be distributed directly (notarized, outside the Mac App Store) because Full Disk Access to `chat.db` is incompatible with App Sandbox. This constrains project 2, not this one, but it is why the transport is designed to tolerate one always-on desktop peer.

---

## 2. Architecture

```
┌─────────────┐         ┌─────────────┐        ┌─────────────┐
│  macOS app  │         │ Windows app │        │   iOS app   │
│ (menu bar)  │         │   (tray)    │        │             │
└──────┬──────┘         └──────┬──────┘        └──────┬──────┘
       │                       │                      │
       └───────── omnifi_core (Dart package) ─────────┘
                   identity · pairing · crypto
                   framing · link manager · sync
       ┌───────────────────┴───────────────────┐
       │                                       │
   LanLink                                RelayLink
   mDNS + TCP                            WSS → Cloudflare
   (preferred)                        Worker + Durable Object
```

### Components

**`omnifi_core`** — Pure Dart package, **zero Flutter dependency**. Owns device identity, pairing handshake, frame encryption, message envelope format, and link-selection state machine. This is the only security-critical code in the project and it exists exactly once. The Flutter independence is what makes the protocol unit-testable without a UI, network, or devices.

**`omnifi_app`** — One Flutter codebase, three build targets. Platform differences sit behind narrow interfaces (`ClipboardWatcher`, `SecureStore`, `Autostart`, `PowerEvents`) with a native implementation per platform via platform channels. macOS ships as a menu-bar agent, Windows as a tray app, iOS as a normal foreground app.

**`omnifi_relay`** — Cloudflare Worker plus one Durable Object per mesh. Devices connect by mesh ID; the DO holds the WebSocket set and fans out frames. Forwards ciphertext only; never holds a key. WebSocket hibernation means an idle mesh costs nothing.

**Platform native layers** — Thin Swift (macOS/iOS) and C++/C# (Windows) shims behind the interfaces above. No protocol logic lives here.

### Architectural rule: the relay is dumb

The relay routes opaque bytes by mesh ID and does nothing else. Rationale is practical, not purist: the moment the relay understands payloads, it becomes a service with uptime obligations and a breach surface — and projects 3/4 will need to bypass it entirely for latency. Keeping it dumb now is what keeps direct-path media features possible later.

### `Link` is an interface

```dart
abstract class Link {
  Stream<Uint8List> get inbound;
  void send(Uint8List frame);
  LinkQuality get quality;   // latency estimate, direct vs relayed
  Stream<LinkState> get state;
}
```

`LanLink` and `RelayLink` are two implementations. `LinkManager` races them, prefers LAN, and fails over transparently. Adding Tailscale or a direct WebRTC path later means writing one more implementation, touching nothing above it.

---

## 3. Identity, pairing, and security

### Device identity

On first launch a device generates a long-term X25519 keypair and a random device ID. The private key goes to Keychain (macOS/iOS) or Windows Credential Manager, DPAPI-backed — never to a file, never to Cloudflare. **The public key is the device's identity.** There are no usernames, no passwords, and no account server.

### Mesh

A mesh is one user's set of devices, named by a random 128-bit mesh ID. Every device stores the roster: for each peer, its device ID, public key, and display name. No server-side copy of the roster exists; the relay sees the mesh ID only as a routing key.

Expected mesh size is 2–6 devices. Keys are pairwise, not group — simpler and safer at this scale.

### Pairing flow

The new device is the one that scans.

1. An already-paired device displays a QR code containing `{meshId, inviterPublicKey, ephemeralSecret, relayHint}`.
2. The new device scans it. **Desktop fallback:** an 8-word typed phrase, since not every PC has a webcam.
3. Both derive a session key from the ephemeral secret and exchange long-term public keys over it.
4. **Both screens display the same 5-word short authentication string (SAS); the user confirms they match.**
5. On confirmation, the inviter sends the full roster; the new device is broadcast to remaining peers.

**Step 4 is not optional.** The QR channel authenticates the exchange, so an observer or relay of that QR can insert themselves. The SAS makes that failure visible in ~2 seconds of user attention. It is the difference between "encrypted" and "encrypted to the right person."

### Session encryption

After pairing, each device pair establishes a session over whichever link is up, using ephemeral keys authenticated by the stored long-term keys. This gives forward secrecy: a stolen device key cannot decrypt captured past traffic.

Frames are AEAD-sealed with a per-session key and a monotonic counter as nonce. The receiver enforces strict counter advancement, which rejects replay.

### OPEN RESEARCH ITEM — handshake construction

The intended construction is **Noise IK**. The open question is whether a trustworthy Dart implementation exists. Three acceptable outcomes, to be decided by research task R1 before any transport code is written:

- **(a)** Depend on an existing, reviewable Dart Noise package
- **(b)** Port the `snow` IK pattern, validated against published Noise test vectors
- **(c)** Fall back to a smaller, explicitly-specified construction built from the `cryptography` package's primitives, with the full construction written down and reviewed

Hand-rolled handshakes are where security bugs live. This is front-loaded in the plan because everything else in the transport sits on top of it. **No transport work begins until R1 resolves.**

### Revocation

Removing a device from any peer broadcasts a roster update; peers drop the key and refuse its sessions.

**Accepted limitation:** a device offline at revocation time will not learn of it until it reconnects, and until then can still talk to peers that also missed the update. For a mesh of the user's own devices this window is acceptable. No revocation ledger is being built for a 4-device system.

### Threat model — what Cloudflare can observe

| Visible to relay | Not visible to relay |
|---|---|
| Mesh ID | Message content |
| Device connection timing | Device identities / public keys |
| Frame sizes | Which feature is in use |
| Traffic patterns | Clipboard data of any kind |

This is the intended and enforced ceiling.

---

## 4. Transport and reconnection

### Link racing

On startup a device advertises `_omnifi._tcp` over mDNS with its device ID, and simultaneously opens a WebSocket to the relay. Both paths are attempted for every peer; whichever completes a session first wins, LAN wins ties. When a LAN path appears mid-session, traffic migrates to it; the relay socket stays open but idle as a warm standby.

### Migration happens above the link

Sessions are keyed to the **device pair**, not the socket. Switching from relay to LAN does not renegotiate crypto or drop queued frames.

This matters more than it sounds: without it, carrying a laptop into the house causes a visible reconnect stutter, and in project 3 an audio stream would break outright.

### Reconnection

Exponential backoff with jitter, capped at 30s, reset on success. Both links reconnect independently.

User-visible state is exactly one of: `connected (direct)` · `connected (relay)` · `reconnecting` · `offline`. Shown in the menu bar/tray icon, because when this misbehaves the first question is always "is it even connected."

### Sleep is the normal case

macOS and Windows suspend sockets on sleep without notifying the peer, leaving a socket that looks alive and is not.

- Application-level heartbeats every **15s**, liveness timeout **45s**
- Platform sleep/wake notifications force immediate teardown-and-reconnect on wake rather than waiting out the timeout

### Offline queueing

Bounded per-peer outbox: **50 frames or 5MB**, whichever comes first, dropping oldest. Clipboard updates collapse — only the newest survives, since nobody wants four stale clipboards on reconnect. In-memory only; a restart loses it, which is correct for this data.

### Relay Durable Object

One DO per mesh. Holds the WebSocket set, forwards frames to the addressed device or broadcasts, hibernates when idle. Enforces a frame size cap and per-mesh rate limit — not against strangers (the mesh ID is required to reach it at all) but to stop a buggy client running up the bill.

### iOS is a second-class peer — accepted for v1

iOS will not keep a socket alive in the background. The iOS app connects when foregrounded and disconnects shortly after backgrounding.

**v1 behavior:** iOS is a device you pull clipboard from and push to *while it is open*. It does not participate continuously.

Improving this requires silent push notifications waking the app for brief sync windows — APNs setup, push routing through the relay, background execution budget management. **Explicitly out of scope for project 1.** iOS will remain a second-class peer for anything continuous.

---

## 5. Clipboard sync

### Watching

| Platform | Mechanism |
|---|---|
| macOS | `NSPasteboard.changeCount` poll at 500ms (no change event exists) |
| Windows | `AddClipboardFormatListener` (real event) |
| iOS | `UIPasteboard` read on foreground only; iOS 16+ paste permission prompt is accepted, not worked around |

### Payload

- **Text** (UTF-8) and **images** (PNG) in v1
- **Files are out of scope** — chunking, resumption, and progress UI make it its own project
- **1MB cap.** Above that, sync a "too large" marker so the user sees why nothing arrived instead of silence

### Loop prevention

Every device tracks the hash of the last content it applied. When the watcher fires with a hash matching what we just wrote, it is our own write echoing and is dropped.

Without this, two paired machines ping-pong infinitely within seconds of pairing. This is the bug this feature always has.

### Conflicts

Wall-clock timestamp, last-write-wins. Simultaneous copies are rare and the loser losing is fine — a clipboard has no history to corrupt.

### Privacy defaults — on by default, not options

- Password-manager content is skipped (macOS `org.nspasteboard.ConcealedType`, Windows `ExcludeClipboardContentFromMonitorProcessing`)
- Sync pauses on screen lock
- Global pause toggle in the menu

Anything that syncs a clipboard everywhere needs these on by default or it is a liability.

---

## 6. Error handling

Three classes, handled differently:

| Class | Examples | Handling |
|---|---|---|
| **Transient** | Link drop, timeout, relay unreachable | Silent retry with backoff; surfaces only as a status-icon change |
| **Permanent** | SAS mismatch, decryption failure, roster rejection | Notification, then stop. Retrying a decryption failure is pointless or an attack |
| **Degraded** | Relay down but LAN works, oversized payload | Proceed and log |

**Decryption failure specifically** tears down the session and forces a fresh handshake rather than attempting counter resync.

---

## 7. Testing

**Unit (`omnifi_core`, pure Dart)** — protocol, pairing state machine, framing, replay rejection, link-failover logic. Tested with fake links: no UI, no network, no devices. This is the payoff for keeping Flutter out of the core package.

**Known-answer tests** — crypto pinned against fixed vectors so a dependency swap cannot silently change the wire format.

**Integration** — two core instances against a local `wrangler dev` relay, exercising: pair → sync → kill link → reconnect → verify.

**Manual** — only what cannot be automated: real pairing UX, sleep/wake, and the three-platform matrix.

---

## 8. Definition of done

- Three devices paired via QR (and desktop word-phrase fallback), SAS confirmed
- Clipboard round-trips both directions on LAN **and** via relay
- Survives sleep/wake and network loss without user intervention
- Link migration LAN↔relay does not drop the session
- Security-critical paths have tests, including replay rejection and known-answer crypto vectors
- Privacy defaults verified: concealed clipboard skipped, lock pauses sync

---

## 9. Explicitly out of scope

| Item | Deferred to |
|---|---|
| iMessage bridge | Project 2 |
| Audio bridge, Neural Engine TTS/STT, Windows virtual audio driver | Project 3 |
| Video bridge, Windows virtual camera driver | Project 4 |
| File transfer via clipboard | Future |
| iOS background sync via silent push | Future |
| Revocation ledger for offline devices | Not planned at this mesh size |
| Accounts, billing, App Store distribution | Not planned (audience is self + handful) |

---

# Amendment — 2026-07-24: the iPhone is the authority, not the Mac

Supersedes §1's "the Mac app will be a **required server**" and §4's "iOS is a second-class peer".

## The change

The original spec made macOS the hub because iMessage requires reading a local `chat.db`. That reasoning was sound for iMessage and wrong for the product: it made the always-on device a laptop that is frequently closed, when the device actually always present is the phone.

**Two roles were conflated and are now separated:**

| Role | Device | Definition |
|---|---|---|
| **Relay** | Cloudflare Worker / ARC | A dumb byte forwarder. Cannot decrypt anything. Unchanged. |
| **Authority** | **iPhone** | Holds secrets and answers privileged requests. Secure Enclave, Face ID, Neural Engine. |
| **Capability provider** | macOS (optional) | The only device that can read `chat.db`. Have one → iMessage works. Don't → it doesn't. |

The iPhone becomes the **trust root**, not the router. No device is a hub in the routing sense.

## Why the iPhone cannot be a relay

Routing other devices' traffic through the phone would require it to hold a live socket while backgrounded. iOS suspends the app within seconds. The escape hatches were evaluated and rejected:

- **PushKit / VoIP push** — the OS terminates the app unless it reports a CallKit call inside the handler. Also grounds for App Store rejection. Not viable.
- **`NEAppPushProvider`** (Local Push Connectivity) — genuinely persistent, but only on a nominated Wi-Fi SSID, so it does nothing on cellular. Defeats the premise, and the entitlement targets MDM-deployed enterprise apps.
- **`NEPacketTunnelProvider`** — an always-on VPN. Works everywhere; this is how Tailscale persists on iOS. Rejected as scope: it makes the product a VPN, adds a permanent VPN indicator, and needs a Network Extension entitlement.

## Why the request-driven model is sufficient

The privileged operations this design cares about are **human-in-the-loop by nature**. Generating a 2FA code requires the user to authenticate with Face ID, which requires them to be holding the phone. So the phone never needs to act unattended:

```
desktop requests  →  APNs wakes the phone  →  user taps the notification
                  →  app foregrounds  →  Face ID  →  phone answers
                  →  response travels the existing encrypted session
```

The notification is not a workaround for an iOS restriction — it is the interaction.

**Consequence:** iOS's foreground-only constraint stops being a limitation to apologise for and becomes the security model. The phone answers only when its owner is present and has authenticated.

## Threat model change — the relay is no longer fully blind

Waking a backgrounded phone requires an APNs auth key, which cannot be distributed to every desktop. The relay (or an adjacent worker) therefore holds:

- the APNs auth key, and
- a mesh ID → device token mapping.

| Relay can see | Relay still cannot see |
|---|---|
| Mesh IDs | Any message content |
| Device tokens (can wake your phone) | Device identities / public keys |
| Connection timing, frame sizes | Which capability is being invoked |
| | Clipboard data, TOTP seeds, or generated codes |

This is a deliberate, recorded erosion of §3's "the relay is dumb" principle. It is bounded: the relay gains the ability to *wake* a device, never to *read* one.

## Impact on the built code

**None.** Verified 2026-07-24: the core encodes no hub, host, or role concept. `PeerRecord` is `{deviceId, publicKey, displayName, addedAtMs}`; sessions are pair-keyed; `LinkManager` ranks links rather than devices. The mesh was already symmetric, so the pivot costs nothing against the 278 passing tests.

## What this adds

1. **A capability layer** — request/response on top of the existing envelope. Additive: two new `MessageType` wire names.
2. **An APNs wake path** — relay-side key and token registry, iOS-side push handling.
3. **Targeted delivery** — a capability response goes to the **requesting device only**, never broadcast. This is a deliberate departure from clipboard sync's fan-out: a live 2FA code reaching every machine would let a compromised device harvest codes it never asked for.

## Deferred to its own project

**The authenticator** (TOTP seeds in the Keychain under `kSecAccessControlBiometryCurrentSet`, Face-ID-gated generation, targeted delivery) gets its own spec → plan → build cycle after Project 1. It depends on Secure Enclave work, the APNs path, and the capability layer, none of which can be exercised until a mesh can actually pair.
