# OmniFi Project 1 — Transport Spine + Universal Clipboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an encrypted, self-healing transport between a user's macOS, Windows, and iOS devices, and prove it works by syncing the clipboard between them.

**Architecture:** A pure-Dart package (`omnifi_core`) owns all identity, crypto, protocol, and link-selection logic and has zero Flutter dependency so it is testable without a UI or network. A single Flutter app targets macOS, Windows, and iOS, supplying platform-specific behavior through narrow interfaces defined in the core. A Cloudflare Worker plus one Durable Object per mesh acts as a blind ciphertext relay used only when a direct LAN path is unavailable.

**Tech Stack:** Dart 3.5+, Flutter 3.24+, `cryptography` (X25519/HKDF/ChaCha20-Poly1305), `cbor`, `web_socket_channel`, `multicast_dns`, Cloudflare Workers + Durable Objects (TypeScript), `wrangler`.

**Source spec:** `docs/superpowers/specs/2026-07-22-omnifi-spine-clipboard-design.md`

## Global Constraints

- `omnifi_core` MUST NOT import `package:flutter/*` or `dart:ui`. Its only Dart SDK dependency surface is `dart:core`, `dart:async`, `dart:convert`, `dart:typed_data`, `dart:io` (transport only).
- All cryptographic keys are X25519 (32-byte public, 32-byte private). AEAD is ChaCha20-Poly1305 with a 12-byte nonce. Hash/KDF is SHA-256 / HKDF-SHA256.
- Private keys are NEVER written to a plain file and NEVER transmitted. Storage is via the `SecureStore` interface only.
- Wire format is CBOR inside length-prefixed frames. Frame length prefix is a 4-byte big-endian unsigned integer.
- Maximum frame size is 1_048_576 bytes (1 MiB). Frames exceeding this are rejected, not truncated.
- Nonce counters are strictly monotonic per session direction. A received counter that is not greater than the last accepted counter is rejected.
- Heartbeat interval is 15 seconds. Liveness timeout is 45 seconds.
- Reconnect backoff is exponential with jitter, capped at 30 seconds, reset on successful session establishment.
- Per-peer outbox bound is 50 frames or 5_242_880 bytes (5 MiB), whichever is reached first, dropping oldest.
- Mesh IDs are 128-bit, hex-encoded lowercase (32 characters).
- Device IDs are 128-bit, hex-encoded lowercase (32 characters).
- The relay MUST NOT be able to decrypt any payload. It routes by mesh ID and device ID only.
- Every commit message uses Conventional Commits (`feat:`, `test:`, `fix:`, `chore:`, `docs:`).
- Run `dart analyze` before every commit in Dart packages; it must report zero issues.
- **Two relay backends exist and must stay contract-identical:** the Cloudflare Worker (Task 18) and an ARC route (Task 27). Any change to the relay wire contract must land in both, and the Task 19 integration suite must be run against both before either is considered done. The client treats them as competing candidate links, not as a primary and a failover — see Task 21's `EngineConfig.relayBases`.

---

## File Structure

```
omnifi/
├── docs/superpowers/
│   ├── specs/2026-07-22-omnifi-spine-clipboard-design.md
│   ├── plans/2026-07-22-omnifi-spine-clipboard.md
│   └── research/2026-07-22-r1-handshake-decision.md      (Task 2)
├── packages/omnifi_core/
│   ├── pubspec.yaml
│   ├── analysis_options.yaml
│   ├── lib/
│   │   ├── omnifi_core.dart                  # public exports only
│   │   └── src/
│   │       ├── crypto/aead_session.dart      # sealing, counters, replay rejection
│   │       ├── crypto/handshake.dart         # Handshake interface + OmniFi v1 impl
│   │       ├── crypto/sas.dart               # short authentication string
│   │       ├── crypto/wordlist.dart          # 256-word SAS/pairing wordlist
│   │       ├── identity/device_identity.dart # keypair + device ID
│   │       ├── identity/secure_store.dart    # interface (impls live in app)
│   │       ├── identity/mesh.dart            # mesh ID, roster, revocation
│   │       ├── protocol/framing.dart         # 4-byte BE length prefix codec
│   │       ├── protocol/envelope.dart        # CBOR envelope encode/decode
│   │       ├── protocol/messages.dart        # typed payloads
│   │       ├── transport/link.dart           # Link interface, LinkState, LinkQuality
│   │       ├── transport/outbox.dart         # bounded, collapsing outbox
│   │       ├── transport/relay_link.dart     # WSS client
│   │       ├── transport/lan_link.dart       # mDNS discovery + TCP
│   │       ├── transport/link_manager.dart   # racing, preference, failover, heartbeat
│   │       ├── session/peer_session.dart     # pair-keyed session, link migration
│   │       ├── pairing/pairing_payload.dart  # QR/word-phrase codec
│   │       ├── pairing/pairing_flow.dart     # invite/join state machines
│   │       ├── sync/clipboard_sync.dart      # loop prevention, LWW, caps
│   │       └── sync/clipboard_watcher.dart   # interface (impls live in app)
│   └── test/
│       ├── crypto/aead_session_test.dart
│       ├── crypto/handshake_test.dart
│       ├── crypto/handshake_kat_test.dart
│       ├── crypto/sas_test.dart
│       ├── identity/device_identity_test.dart
│       ├── identity/mesh_test.dart
│       ├── protocol/framing_test.dart
│       ├── protocol/envelope_test.dart
│       ├── transport/outbox_test.dart
│       ├── transport/link_manager_test.dart
│       ├── session/peer_session_test.dart
│       ├── pairing/pairing_flow_test.dart
│       ├── sync/clipboard_sync_test.dart
│       ├── integration/relay_roundtrip_test.dart
│       └── support/fake_link.dart            # shared test double
├── relay/
│   ├── package.json
│   ├── wrangler.toml
│   ├── src/index.ts                          # Worker entry + routing
│   ├── src/mesh_do.ts                        # Durable Object
│   └── test/mesh_do.test.ts
└── apps/omnifi_app/                          # Flutter, three targets
    ├── pubspec.yaml
    ├── lib/main.dart
    ├── lib/app.dart
    ├── lib/platform/secure_store_impl.dart
    ├── lib/platform/clipboard_watcher_impl.dart
    ├── lib/platform/autostart.dart
    ├── lib/platform/power_events.dart
    ├── lib/ui/status_indicator.dart
    ├── lib/ui/pairing_screen.dart
    ├── lib/ui/settings_screen.dart
    ├── macos/Runner/ClipboardPlugin.swift
    ├── macos/Runner/SecureStorePlugin.swift
    ├── windows/runner/clipboard_plugin.cpp
    ├── windows/runner/secure_store_plugin.cpp
    └── ios/Runner/ClipboardPlugin.swift
```

**Decomposition rationale:** `crypto/`, `protocol/`, `transport/`, `session/`, `pairing/`, and `sync/` are separate directories because they have genuinely different reasons to change — a wire-format revision touches `protocol/` only, a new network path touches `transport/` only. `secure_store.dart` and `clipboard_watcher.dart` are interfaces in the core with implementations in the app; this is what keeps the core Flutter-free while still letting core logic drive platform behavior.

---

## Task Sequencing Note

Task 2 is a research spike that may change the *implementation* behind `Handshake`, but not its interface or its tests. Tasks 3–5 are written against a fully-specified construction (OmniFi Session Handshake v1, defined in Task 4) so the plan is executable regardless of the spike's outcome. If the spike selects a vetted third-party Noise IK package, Task 4's implementation is replaced by an adapter satisfying the same interface and passing the same tests.

---

## Task 1: Workspace scaffold and `omnifi_core` package

**Files:**
- Create: `packages/omnifi_core/pubspec.yaml`
- Create: `packages/omnifi_core/analysis_options.yaml`
- Create: `packages/omnifi_core/lib/omnifi_core.dart`
- Create: `packages/omnifi_core/lib/src/version.dart`
- Test: `packages/omnifi_core/test/version_test.dart`

**Interfaces:**
- Consumes: nothing.
- Produces: `omnifiProtocolVersion` (`const int`, value `1`), exported from `package:omnifi_core/omnifi_core.dart`. Every later task imports this package.

- [ ] **Step 1: Create the package manifest**

Create `packages/omnifi_core/pubspec.yaml`:

```yaml
name: omnifi_core
description: Protocol, crypto, identity and transport core for OmniFi. No Flutter dependency.
version: 0.1.0
publish_to: none

environment:
  sdk: ^3.5.0

dependencies:
  cryptography: ^2.7.0
  cbor: ^6.3.0

dev_dependencies:
  test: ^1.25.0
  lints: ^4.0.0
```

- [ ] **Step 2: Create the analyzer config**

Create `packages/omnifi_core/analysis_options.yaml`:

```yaml
include: package:lints/recommended.yaml

analyzer:
  language:
    strict-casts: true
    strict-raw-types: true
  errors:
    todo: ignore

linter:
  rules:
    - prefer_final_locals
    - avoid_dynamic_calls
    - unawaited_futures
```

- [ ] **Step 3: Write the failing test**

Create `packages/omnifi_core/test/version_test.dart`:

```dart
import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('protocol version is 1', () {
    expect(omnifiProtocolVersion, 1);
  });
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd packages/omnifi_core && dart pub get && dart test test/version_test.dart`
Expected: FAIL — `Error: Couldn't resolve the package 'omnifi_core'` or `omnifiProtocolVersion isn't defined`.

- [ ] **Step 5: Write the minimal implementation**

Create `packages/omnifi_core/lib/src/version.dart`:

```dart
/// Wire protocol version. Bump only on a breaking envelope or frame change.
const int omnifiProtocolVersion = 1;
```

Create `packages/omnifi_core/lib/omnifi_core.dart`:

```dart
/// OmniFi core: identity, crypto, protocol, transport. Flutter-free by design.
library omnifi_core;

export 'src/version.dart';
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd packages/omnifi_core && dart test test/version_test.dart`
Expected: PASS — `+1: All tests passed!`

- [ ] **Step 7: Verify the Flutter-free constraint holds**

Run: `cd packages/omnifi_core && ! grep -rE "package:flutter|dart:ui" lib/ && echo "core is flutter-free"`
Expected: prints `core is flutter-free`.

- [ ] **Step 8: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: scaffold omnifi_core package with protocol version"
```

---

## Task 2: Handshake construction research spike (R1)

This task produces a decision record, not code. It is the only non-TDD task in the plan. It exists because the spec front-loads it: everything in the transport sits on the handshake, and hand-rolled handshakes are where security bugs live.

**Files:**
- Create: `docs/superpowers/research/2026-07-22-r1-handshake-decision.md`

**Interfaces:**
- Consumes: nothing.
- Produces: a decision selecting option (a), (b), or (c). Task 4's implementation strategy depends on it; Task 4's *interface and tests* do not.

- [ ] **Step 1: Survey available Dart Noise implementations**

Run: `dart pub search noise` and check pub.dev for packages matching `noise_protocol`, `noise`, `flutter_noise`.

For each candidate found, record: package name, version, last publish date, pub points, likes, whether it implements the **IK** pattern specifically, whether it ships Noise test vectors, and whether the repository is public and readable.

- [ ] **Step 2: Apply the acceptance bar**

A package qualifies for option (a) only if ALL of these hold:
1. It implements Noise IK (not just XX or NN).
2. It passes the official Noise test vectors, and those vector tests are present in its own test suite.
3. It has been published or committed to within the last 24 months.
4. Its source is small enough to read end-to-end in one sitting (< 2000 lines) and you have actually read the handshake state machine.
5. It has no transitive dependency on an unmaintained crypto shim — it should build on `cryptography` or `pointycastle`.

If no package clears all five, option (a) is rejected.

- [ ] **Step 3: Assess the port option**

Option (b) is porting the `snow` crate's IK pattern to Dart, validated against the published Noise test vectors. Estimate the effort honestly: this is a symmetric-state machine plus the IK message pattern, roughly 400–600 lines of Dart plus vector plumbing. Choose (b) only if you intend to also run the full Noise vector suite against it.

- [ ] **Step 4: Write the decision record**

Create `docs/superpowers/research/2026-07-22-r1-handshake-decision.md` with these exact sections:

```markdown
# R1 — Session Handshake Construction Decision

**Date:** 2026-07-22
**Status:** Decided

## Candidates evaluated

| Package | Version | Last publish | IK? | Vectors? | Read in full? | Verdict |
|---|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... | ... |

## Decision

Selected option: (a) vetted package / (b) port of snow IK / (c) OmniFi Session Handshake v1

## Rationale

[Why. If (c), state explicitly that the construction in Task 4 was chosen because no
package cleared the acceptance bar, and that it requires review before any release.]

## Consequences

- Implementation behind `Handshake` interface: [what gets built]
- Tests that must pass regardless of choice: `test/crypto/handshake_test.dart`,
  `test/crypto/handshake_kat_test.dart`
- Review obligation: [who reviews the construction and when, if (b) or (c)]
```

- [ ] **Step 5: Commit the decision**

```bash
git add docs/superpowers/research/2026-07-22-r1-handshake-decision.md
git commit -m "docs: record R1 session handshake construction decision"
```

---

## Task 3: AEAD session sealing with replay rejection

**Files:**
- Create: `packages/omnifi_core/lib/src/crypto/aead_session.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/crypto/aead_session_test.dart`

**Interfaces:**
- Consumes: `omnifiProtocolVersion` from Task 1.
- Produces:
  - `class AeadSession` with constructor `AeadSession({required List<int> sendKey, required List<int> receiveKey})`
  - `Future<Uint8List> seal(List<int> plaintext, {List<int> aad = const []})`
  - `Future<Uint8List> open(List<int> sealed, {List<int> aad = const []})` — throws `ReplayError` or `DecryptionError`
  - `int get sendCounter`, `int get lastAcceptedReceiveCounter`
  - `class ReplayError implements Exception`, `class DecryptionError implements Exception`
  - Sealed layout: `[8-byte BE counter][ciphertext][16-byte MAC]`. Nonce is the 8-byte counter left-padded with 4 zero bytes to 12 bytes.

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/crypto/aead_session_test.dart`:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

/// Two sessions facing each other: A's send key is B's receive key.
({AeadSession a, AeadSession b}) pair() {
  final k1 = List<int>.filled(32, 1);
  final k2 = List<int>.filled(32, 2);
  return (
    a: AeadSession(sendKey: k1, receiveKey: k2),
    b: AeadSession(sendKey: k2, receiveKey: k1),
  );
}

void main() {
  test('round-trips a message', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('hello'));
    final opened = await p.b.open(sealed);
    expect(utf8.decode(opened), 'hello');
  });

  test('counter increments per sealed message', () async {
    final p = pair();
    expect(p.a.sendCounter, 0);
    await p.a.seal(utf8.encode('one'));
    expect(p.a.sendCounter, 1);
    await p.a.seal(utf8.encode('two'));
    expect(p.a.sendCounter, 2);
  });

  test('rejects a replayed frame', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('once'));
    await p.b.open(sealed);
    expect(() => p.b.open(sealed), throwsA(isA<ReplayError>()));
  });

  test('rejects an out-of-order lower counter', () async {
    final p = pair();
    final first = await p.a.seal(utf8.encode('1'));
    final second = await p.a.seal(utf8.encode('2'));
    await p.b.open(second);
    expect(() => p.b.open(first), throwsA(isA<ReplayError>()));
  });

  test('accepts a forward gap in counters', () async {
    final p = pair();
    await p.a.seal(utf8.encode('dropped'));
    final second = await p.a.seal(utf8.encode('arrived'));
    final opened = await p.b.open(second);
    expect(utf8.decode(opened), 'arrived');
    expect(p.b.lastAcceptedReceiveCounter, 1);
  });

  test('rejects a tampered ciphertext', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('intact'));
    sealed[sealed.length - 1] ^= 0xFF;
    expect(() => p.b.open(sealed), throwsA(isA<DecryptionError>()));
  });

  test('rejects a mismatched aad', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('bound'), aad: [1, 2, 3]);
    expect(() => p.b.open(sealed, aad: [9, 9, 9]),
        throwsA(isA<DecryptionError>()));
  });

  test('rejects a frame shorter than the header plus mac', () async {
    final p = pair();
    expect(() => p.b.open(Uint8List(10)), throwsA(isA<DecryptionError>()));
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/crypto/aead_session_test.dart`
Expected: FAIL — `AeadSession isn't defined`.

- [ ] **Step 3: Write the implementation**

Create `packages/omnifi_core/lib/src/crypto/aead_session.dart`:

```dart
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Thrown when a frame's counter does not strictly advance.
class ReplayError implements Exception {
  const ReplayError(this.counter, this.lastAccepted);
  final int counter;
  final int lastAccepted;
  @override
  String toString() =>
      'ReplayError: counter $counter did not advance past $lastAccepted';
}

/// Thrown when a frame fails authentication or is structurally invalid.
class DecryptionError implements Exception {
  const DecryptionError(this.reason);
  final String reason;
  @override
  String toString() => 'DecryptionError: $reason';
}

/// One direction-pair of an established session.
///
/// Sealed layout: [8-byte BE counter][ciphertext][16-byte MAC].
/// The nonce is the counter, left-padded with four zero bytes to 12.
class AeadSession {
  AeadSession({required List<int> sendKey, required List<int> receiveKey})
      : _sendKey = SecretKey(List<int>.unmodifiable(sendKey)),
        _receiveKey = SecretKey(List<int>.unmodifiable(receiveKey)) {
    if (sendKey.length != 32 || receiveKey.length != 32) {
      throw ArgumentError('session keys must be 32 bytes');
    }
  }

  static const int counterBytes = 8;
  static const int macBytes = 16;
  static const int _nonceBytes = 12;

  final _algorithm = Chacha20.poly1305Aead();
  final SecretKey _sendKey;
  final SecretKey _receiveKey;

  int _sendCounter = 0;
  int _lastAcceptedReceiveCounter = -1;

  int get sendCounter => _sendCounter;
  int get lastAcceptedReceiveCounter => _lastAcceptedReceiveCounter;

  static Uint8List _nonceFor(int counter) {
    final nonce = Uint8List(_nonceBytes);
    ByteData.view(nonce.buffer).setUint64(_nonceBytes - counterBytes, counter);
    return nonce;
  }

  Future<Uint8List> seal(List<int> plaintext,
      {List<int> aad = const []}) async {
    final counter = _sendCounter;
    final box = await _algorithm.encrypt(
      plaintext,
      secretKey: _sendKey,
      nonce: _nonceFor(counter),
      aad: aad,
    );
    _sendCounter++;

    final out = Uint8List(counterBytes + box.cipherText.length + macBytes);
    ByteData.view(out.buffer).setUint64(0, counter);
    out.setRange(counterBytes, counterBytes + box.cipherText.length,
        box.cipherText);
    out.setRange(counterBytes + box.cipherText.length, out.length,
        box.mac.bytes);
    return out;
  }

  Future<Uint8List> open(List<int> sealed,
      {List<int> aad = const []}) async {
    if (sealed.length < counterBytes + macBytes) {
      throw const DecryptionError('frame shorter than header plus mac');
    }
    final bytes = Uint8List.fromList(sealed);
    final counter = ByteData.view(bytes.buffer, bytes.offsetInBytes)
        .getUint64(0);

    if (counter <= _lastAcceptedReceiveCounter) {
      throw ReplayError(counter, _lastAcceptedReceiveCounter);
    }

    final cipherText =
        bytes.sublist(counterBytes, bytes.length - macBytes);
    final mac = Mac(bytes.sublist(bytes.length - macBytes));

    final List<int> plaintext;
    try {
      plaintext = await _algorithm.decrypt(
        SecretBox(cipherText, nonce: _nonceFor(counter), mac: mac),
        secretKey: _receiveKey,
        aad: aad,
      );
    } on SecretBoxAuthenticationError {
      throw const DecryptionError('authentication failed');
    }

    _lastAcceptedReceiveCounter = counter;
    return Uint8List.fromList(plaintext);
  }
}
```

- [ ] **Step 4: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add below the existing export:

```dart
export 'src/crypto/aead_session.dart';
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/crypto/aead_session_test.dart`
Expected: PASS — `+8: All tests passed!`

- [ ] **Step 6: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add AEAD session sealing with strict replay rejection"
```

---

## Task 4: Session handshake

Implements **OmniFi Session Handshake v1**, the construction selected as option (c) in Task 2. If Task 2 selected (a) or (b), replace the body of `OmniFiHandshakeV1` with an adapter over the chosen implementation; the `Handshake` interface and every test in this task remain unchanged.

**Construction (normative):**

Both parties hold a static X25519 keypair. The initiator knows the responder's static public key; after pairing, the responder knows the initiator's too. During *pairing* the parties do not yet know each other's static keys, so a pre-shared key from the QR payload is mixed in instead — that variant is `psk`.

1. Initiator generates ephemeral `ei`, sends `HS1 = CBOR{v, deviceId, ePub, sPub}`.
2. Responder generates ephemeral `er`, sends `HS2 = CBOR{v, deviceId, ePub, sPub}`.
3. Each side **learns the peer's static public key from the peer's message** and computes three Diffie-Hellman results against it:
   - `dh_ee = DH(e_self, e_peer)` — provides forward secrecy
   - `dh_es = DH(e_initiator, s_responder)` — authenticates the responder
   - `dh_se = DH(s_initiator, e_responder)` — authenticates the initiator
4. `transcript = HS1_bytes || HS2_bytes` (initiator's message always first).
5. `master = HKDF-SHA256(ikm: dh_ee || dh_es || dh_se, salt: transcript || psk, info: "omnifi-session-v1", length: 32)`
6. Four keys are expanded from `master`, **two for data and two for confirmation**:
   - `k_i2r = HKDF-Expand(master, info: "i2r", 32)`, `k_r2i = HKDF-Expand(master, info: "r2i", 32)` — the returned session
   - `k_i2r_confirm = HKDF-Expand(master, info: "i2r-confirm", 32)`, `k_r2i_confirm = HKDF-Expand(master, info: "r2i-confirm", 32)` — used *only* for step 7
7. Each side seals the literal bytes `omnifi-confirm` under its **confirmation** key with counter 0 and `aad = transcript`, and sends it. Failure to open the peer's confirmation aborts the handshake.

**Why confirmation gets its own keys — this is not optional.** An earlier draft sealed the confirmation under `k_i2r`/`k_r2i` at counter 0 and then returned a fresh `AeadSession` on the same keys, whose send counter also starts at 0. That is (key, nonce) reuse. Because the confirmation plaintext is the public constant `omnifi-confirm`, an observer XORs it against the confirmation ciphertext to recover the counter-0 keystream, then XORs that against the first data frame — disclosing its first 14 bytes. Worse, RFC 8439 derives the Poly1305 one-time key from ChaCha20 block counter 0 under the same nonce, so the reuse also exposes the authentication key and permits forgery. Differing AAD does not mitigate any of this: AAD is authenticated but neither the keystream nor the Poly1305 key depends on it. Separate `-confirm` keys remove the collision entirely.

**Authenticating the learned static key.** The constructor takes `expectedPeerStaticPublicKey` as an **optional** parameter:
- **Post-pairing** (the roster already holds the peer's key): pass it. After decoding the peer's message the handshake MUST compare the learned key against it and abort with `HandshakeError` on mismatch. This is what makes a session to a known device mutually authenticated.
- **During pairing** (neither side yet knows the other's static key): pass `null`. Authentication comes from the pre-shared key carried in the QR invite, mixed into the HKDF salt, plus the user's SAS comparison. The static keys are learned here and written to the roster on confirmation.

The earlier draft made this parameter required and had the inviting side pass *its own* public key, which would have made the two sides compute different `dh_es` values and fail to agree on a key at all.

Mutual authentication holds because only the holder of `s_responder` can compute `dh_es`, and only the holder of `s_initiator` can compute `dh_se`. Forward secrecy holds because `dh_ee` requires an ephemeral private key that is discarded after the handshake.

**Files:**
- Create: `packages/omnifi_core/lib/src/crypto/handshake.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/crypto/handshake_test.dart`

**Interfaces:**
- Consumes: `AeadSession` (Task 3).
- Produces:
  - `class StaticKeyPair { final List<int> publicKey; final List<int> privateKey; }`
  - `class HandshakeResult { final AeadSession session; final List<int> transcript; final List<int> master; final List<int> peerStaticPublicKey; }`
  - `abstract interface class Handshake` with:
    - `Future<Uint8List> start()` — returns the local handshake message
    - `Future<Uint8List> confirmationFor(List<int> peerMessage)`
    - `Future<HandshakeResult> complete(List<int> peerMessage, List<int> peerConfirmation)`
  - `class OmniFiHandshakeV1 implements Handshake` with named constructors `.initiator(...)` and `.responder(...)`, each taking `{required StaticKeyPair staticKeys, required String deviceId, required List<int>? expectedPeerStaticPublicKey, List<int> psk = const []}` — the peer-key parameter is **`required` but nullable**: callers must type `null` explicitly to opt out of mutual authentication, so dropping it can never be the shortest call that compiles. A configuration with both a null expectation and an empty PSK has no authentication mechanism at all and must throw.
  - `class HandshakeError implements Exception`

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/crypto/handshake_test.dart`:

```dart
import 'dart:convert';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

Future<({HandshakeResult i, HandshakeResult r})> run({
  List<int> psk = const [],
  bool corruptResponderKey = false,
}) async {
  final ik = await OmniFiHandshakeV1.generateStaticKeys();
  final rk = await OmniFiHandshakeV1.generateStaticKeys();
  final wrong = await OmniFiHandshakeV1.generateStaticKeys();

  final initiator = OmniFiHandshakeV1.initiator(
    staticKeys: ik,
    deviceId: 'aaaa',
    peerStaticPublicKey:
        corruptResponderKey ? wrong.publicKey : rk.publicKey,
    psk: psk,
  );
  final responder = OmniFiHandshakeV1.responder(
    staticKeys: rk,
    deviceId: 'bbbb',
    peerStaticPublicKey: ik.publicKey,
    psk: psk,
  );

  final m1 = await initiator.start();
  final m2 = await responder.start();
  // Each side must ingest the peer message before it can confirm.
  final ic = await initiator.confirmationFor(m2);
  final rc = await responder.confirmationFor(m1);

  return (
    i: await initiator.complete(m2, rc),
    r: await responder.complete(m1, ic),
  );
}

void main() {
  test('both sides derive matching directional keys', () async {
    final out = await run();
    final sealed = await out.i.session.seal(utf8.encode('ping'));
    expect(utf8.decode(await out.r.session.open(sealed)), 'ping');

    final back = await out.r.session.seal(utf8.encode('pong'));
    expect(utf8.decode(await out.i.session.open(back)), 'pong');
  });

  test('both sides derive the same transcript', () async {
    final out = await run();
    expect(out.i.transcript, out.r.transcript);
  });

  test('each side learns the peer static public key', () async {
    final out = await run();
    expect(out.i.peerStaticPublicKey.length, 32);
    expect(out.r.peerStaticPublicKey.length, 32);
  });

  test('a psk changes the derived master secret', () async {
    final withoutPsk = await run();
    final withPsk = await run(psk: List<int>.filled(32, 7));
    expect(withPsk.i.master, isNot(equals(withoutPsk.i.master)));
  });

  test('handshake fails when the responder static key is wrong', () async {
    expect(
      () => run(corruptResponderKey: true),
      throwsA(isA<HandshakeError>()),
    );
  });

  test('two runs with the same static keys derive different sessions',
      () async {
    final first = await run();
    final second = await run();
    expect(first.i.master, isNot(equals(second.i.master)));
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/crypto/handshake_test.dart`
Expected: FAIL — `OmniFiHandshakeV1 isn't defined`.

- [ ] **Step 3: Write the implementation**

Create `packages/omnifi_core/lib/src/crypto/handshake.dart`:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:cryptography/cryptography.dart';

import '../version.dart';
import 'aead_session.dart';

class HandshakeError implements Exception {
  const HandshakeError(this.reason);
  final String reason;
  @override
  String toString() => 'HandshakeError: $reason';
}

class StaticKeyPair {
  const StaticKeyPair({required this.publicKey, required this.privateKey});
  final List<int> publicKey;
  final List<int> privateKey;
}

class HandshakeResult {
  const HandshakeResult({
    required this.session,
    required this.transcript,
    required this.master,
    required this.peerStaticPublicKey,
  });
  final AeadSession session;
  final List<int> transcript;
  final List<int> master;
  final List<int> peerStaticPublicKey;
}

abstract interface class Handshake {
  Future<Uint8List> start();
  Future<Uint8List> confirmationFor(List<int> peerMessage);
  Future<HandshakeResult> complete(
      List<int> peerMessage, List<int> peerConfirmation);
}

/// OmniFi Session Handshake v1. See the plan's Task 4 for the normative
/// construction. Reviewed under R1.
class OmniFiHandshakeV1 implements Handshake {
  OmniFiHandshakeV1._({
    required this.staticKeys,
    required this.deviceId,
    required this.isInitiator,
    required this.peerStaticPublicKey,
    required this.psk,
  });

  factory OmniFiHandshakeV1.initiator({
    required StaticKeyPair staticKeys,
    required String deviceId,
    required List<int> peerStaticPublicKey,
    List<int> psk = const [],
  }) =>
      OmniFiHandshakeV1._(
        staticKeys: staticKeys,
        deviceId: deviceId,
        isInitiator: true,
        peerStaticPublicKey: peerStaticPublicKey,
        psk: psk,
      );

  factory OmniFiHandshakeV1.responder({
    required StaticKeyPair staticKeys,
    required String deviceId,
    required List<int> peerStaticPublicKey,
    List<int> psk = const [],
  }) =>
      OmniFiHandshakeV1._(
        staticKeys: staticKeys,
        deviceId: deviceId,
        isInitiator: false,
        peerStaticPublicKey: peerStaticPublicKey,
        psk: psk,
      );

  static final _x25519 = X25519();
  static final _hkdf =
      Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  static const _confirmPlaintext = 'omnifi-confirm';

  final StaticKeyPair staticKeys;
  final String deviceId;
  final bool isInitiator;
  final List<int> peerStaticPublicKey;
  final List<int> psk;

  SimpleKeyPair? _ephemeral;
  Uint8List? _ownMessage;

  static Future<StaticKeyPair> generateStaticKeys() async {
    final kp = await _x25519.newKeyPair();
    return StaticKeyPair(
      publicKey: (await kp.extractPublicKey()).bytes,
      privateKey: await kp.extractPrivateKeyBytes(),
    );
  }

  @override
  Future<Uint8List> start() async {
    final kp = await _x25519.newKeyPair();
    _ephemeral = kp;
    final ePub = (await kp.extractPublicKey()).bytes;
    final message = cbor.encode(CborValue({
      'v': omnifiProtocolVersion,
      'id': deviceId,
      'e': CborBytes(ePub),
    }));
    _ownMessage = Uint8List.fromList(message);
    return _ownMessage!;
  }

  List<int> _transcript(List<int> peerMessage) {
    final own = _ownMessage;
    if (own == null) {
      throw const HandshakeError('start() must be called before completing');
    }
    return isInitiator ? [...own, ...peerMessage] : [...peerMessage, ...own];
  }

  static List<int> _peerEphemeral(List<int> peerMessage) {
    final Object? decoded;
    try {
      decoded = cbor.decode(peerMessage).toObject();
    } catch (_) {
      throw const HandshakeError('peer message is not valid CBOR');
    }
    if (decoded is! Map) {
      throw const HandshakeError('peer message is not a map');
    }
    final e = decoded['e'];
    if (e is! List<int> || e.length != 32) {
      throw const HandshakeError('peer ephemeral key is malformed');
    }
    return e;
  }

  Future<List<int>> _dh(List<int> privateKey, List<int> publicKey) async {
    final kp = await _x25519.newKeyPairFromSeed(privateKey);
    final shared = await _x25519.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: SimplePublicKey(publicKey, type: KeyPairType.x25519),
    );
    return shared.extractBytes();
  }

  Future<({List<int> master, List<int> send, List<int> receive,
          List<int> transcript})>
      _derive(List<int> peerMessage) async {
    final ephemeral = _ephemeral;
    if (ephemeral == null) {
      throw const HandshakeError('start() must be called first');
    }
    final ePriv = await ephemeral.extractPrivateKeyBytes();
    final peerEPub = _peerEphemeral(peerMessage);
    final transcript = _transcript(peerMessage);

    final dhEe = await _dh(ePriv, peerEPub);
    final List<int> dhEs;
    final List<int> dhSe;
    if (isInitiator) {
      dhEs = await _dh(ePriv, peerStaticPublicKey);
      dhSe = await _dh(staticKeys.privateKey, peerEPub);
    } else {
      dhEs = await _dh(staticKeys.privateKey, peerEPub);
      dhSe = await _dh(ePriv, peerStaticPublicKey);
    }

    final master = await _hkdf.deriveKey(
      secretKey: SecretKey([...dhEe, ...dhEs, ...dhSe]),
      nonce: [...transcript, ...psk],
      info: utf8.encode('omnifi-session-v1'),
    );
    final masterBytes = await master.extractBytes();

    Future<List<int>> expand(String label) async {
      final k = await _hkdf.deriveKey(
        secretKey: SecretKey(masterBytes),
        nonce: const [],
        info: utf8.encode(label),
      );
      return k.extractBytes();
    }

    final i2r = await expand('i2r');
    final r2i = await expand('r2i');

    return (
      master: masterBytes,
      send: isInitiator ? i2r : r2i,
      receive: isInitiator ? r2i : i2r,
      transcript: transcript,
    );
  }

  @override
  Future<Uint8List> confirmationFor(List<int> peerMessage) async {
    final d = await _derive(peerMessage);
    final confirmSession =
        AeadSession(sendKey: d.send, receiveKey: d.receive);
    return confirmSession.seal(utf8.encode(_confirmPlaintext),
        aad: d.transcript);
  }

  @override
  Future<HandshakeResult> complete(
      List<int> peerMessage, List<int> peerConfirmation) async {
    final d = await _derive(peerMessage);
    final verifier =
        AeadSession(sendKey: d.send, receiveKey: d.receive);
    try {
      final opened =
          await verifier.open(peerConfirmation, aad: d.transcript);
      if (utf8.decode(opened) != _confirmPlaintext) {
        throw const HandshakeError('peer confirmation payload mismatch');
      }
    } on DecryptionError {
      throw const HandshakeError('peer confirmation failed to authenticate');
    }

    return HandshakeResult(
      session: AeadSession(sendKey: d.send, receiveKey: d.receive),
      transcript: d.transcript,
      master: d.master,
      peerStaticPublicKey: peerStaticPublicKey,
    );
  }
}
```

- [ ] **Step 4: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/crypto/handshake.dart';
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/crypto/handshake_test.dart`
Expected: PASS — `+6: All tests passed!`

- [ ] **Step 6: Run the whole suite to check for regressions**

Run: `cd packages/omnifi_core && dart test`
Expected: PASS — all tests from Tasks 1, 3, and 4.

- [ ] **Step 7: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add OmniFi session handshake v1 with mutual auth and forward secrecy"
```

---

## Task 5: Known-answer tests pinning the wire format

These tests exist so that swapping a crypto dependency cannot silently change the wire format. They pin the AEAD framing against fixed vectors with fixed keys and counters.

**Files:**
- Test: `packages/omnifi_core/test/crypto/handshake_kat_test.dart`

**Interfaces:**
- Consumes: `AeadSession` (Task 3), `OmniFiHandshakeV1` (Task 4).
- Produces: nothing consumed by later tasks. This is a guard.

- [ ] **Step 1: Write the test that generates and prints the vectors**

Create `packages/omnifi_core/test/crypto/handshake_kat_test.dart`:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

String hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('AEAD known-answer vectors', () {
    test('vector 1: counter 0, empty aad', () async {
      final s = AeadSession(
        sendKey: List<int>.filled(32, 0x01),
        receiveKey: List<int>.filled(32, 0x02),
      );
      final sealed = await s.seal(utf8.encode('omnifi'));
      // Regenerate with: dart test --name 'vector 1' -r expanded
      // and paste the printed value. Do NOT edit this without a
      // deliberate wire-format version bump.
      print('vector 1 = ${hex(sealed)}');
      expect(hex(sealed), _vector1);
    });

    test('vector 2: counter 0, non-empty aad', () async {
      final s = AeadSession(
        sendKey: List<int>.filled(32, 0x01),
        receiveKey: List<int>.filled(32, 0x02),
      );
      final sealed =
          await s.seal(utf8.encode('omnifi'), aad: utf8.encode('bind'));
      print('vector 2 = ${hex(sealed)}');
      expect(hex(sealed), _vector2);
    });

    test('vector 3: counter 5 after five seals', () async {
      final s = AeadSession(
        sendKey: List<int>.filled(32, 0x01),
        receiveKey: List<int>.filled(32, 0x02),
      );
      for (var i = 0; i < 5; i++) {
        await s.seal(utf8.encode('pad'));
      }
      final sealed = await s.seal(utf8.encode('omnifi'));
      print('vector 3 = ${hex(sealed)}');
      expect(hex(sealed), _vector3);
      expect(sealed.sublist(0, 8), [0, 0, 0, 0, 0, 0, 0, 5]);
    });
  });

  test('frame layout is counter || ciphertext || mac', () async {
    final s = AeadSession(
      sendKey: List<int>.filled(32, 0x01),
      receiveKey: List<int>.filled(32, 0x02),
    );
    final plaintext = utf8.encode('twelve bytes');
    final sealed = await s.seal(plaintext);
    expect(sealed.length,
        AeadSession.counterBytes + plaintext.length + AeadSession.macBytes);
  });

  test('handshake message is CBOR with v, id and 32-byte e', () async {
    final keys = await OmniFiHandshakeV1.generateStaticKeys();
    final peer = await OmniFiHandshakeV1.generateStaticKeys();
    final h = OmniFiHandshakeV1.initiator(
      staticKeys: keys,
      deviceId: 'cafebabe',
      peerStaticPublicKey: peer.publicKey,
    );
    final m = await h.start();
    expect(m, isA<Uint8List>());
    expect(m.length, greaterThan(40));
  });
}

// Filled in by Step 2. These are the pinned wire-format vectors.
const _vector1 = 'REPLACE_ME_VECTOR_1';
const _vector2 = 'REPLACE_ME_VECTOR_2';
const _vector3 = 'REPLACE_ME_VECTOR_3';
```

- [ ] **Step 2: Run the test to capture the vectors**

Run: `cd packages/omnifi_core && dart test test/crypto/handshake_kat_test.dart -r expanded`
Expected: FAIL on the three vector assertions, with three `vector N = <hex>` lines printed above the failures.

Copy each printed hex string into the corresponding `_vectorN` constant at the bottom of the file, replacing `REPLACE_ME_VECTOR_N`. These values are deterministic because ChaCha20-Poly1305 with a fixed key, fixed nonce, and fixed plaintext has no randomness.

- [ ] **Step 3: Run again to verify the vectors are now pinned**

Run: `cd packages/omnifi_core && dart test test/crypto/handshake_kat_test.dart`
Expected: PASS — `+5: All tests passed!`

- [ ] **Step 4: Remove the print statements**

Delete the three `print(...)` lines. They served their purpose in Step 2 and would otherwise be noise on every run.

- [ ] **Step 5: Verify the suite still passes without them**

Run: `cd packages/omnifi_core && dart test`
Expected: PASS.

- [ ] **Step 6: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "test: pin AEAD wire format with known-answer vectors"
```

---

## Task 6: Short authentication string (SAS)

**Files:**
- Create: `packages/omnifi_core/lib/src/crypto/wordlist.dart`
- Create: `packages/omnifi_core/lib/src/crypto/sas.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/crypto/sas_test.dart`

**Interfaces:**
- Consumes: nothing beyond the SDK and `cryptography`.
- Produces:
  - `const List<String> omnifiWordlist` — exactly 256 lowercase words, unique, 3–7 letters each.
  - `Future<List<String>> deriveSas({required List<int> master, required List<int> initiatorStaticPublicKey, required List<int> responderStaticPublicKey, int words = 5})`
  - `String formatSas(List<String> words)` — joins with `' '`.

The SAS is derived from the handshake master secret **and both static public keys**, so an attacker who inserts themselves produces a different SAS on each side, which the user sees as a mismatch.

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/crypto/sas_test.dart`:

```dart
import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('wordlist has exactly 256 unique words', () {
    expect(omnifiWordlist.length, 256);
    expect(omnifiWordlist.toSet().length, 256);
  });

  test('wordlist entries are lowercase and 3-7 letters', () {
    for (final w in omnifiWordlist) {
      expect(w, matches(RegExp(r'^[a-z]{3,7}$')), reason: 'bad word: $w');
    }
  });

  test('derives the requested number of words', () async {
    final sas = await deriveSas(
      master: List<int>.filled(32, 3),
      initiatorStaticPublicKey: List<int>.filled(32, 1),
      responderStaticPublicKey: List<int>.filled(32, 2),
    );
    expect(sas.length, 5);
    for (final w in sas) {
      expect(omnifiWordlist, contains(w));
    }
  });

  test('is deterministic for the same inputs', () async {
    Future<List<String>> go() => deriveSas(
          master: List<int>.filled(32, 3),
          initiatorStaticPublicKey: List<int>.filled(32, 1),
          responderStaticPublicKey: List<int>.filled(32, 2),
        );
    expect(await go(), await go());
  });

  test('differs when the master secret differs', () async {
    final a = await deriveSas(
      master: List<int>.filled(32, 3),
      initiatorStaticPublicKey: List<int>.filled(32, 1),
      responderStaticPublicKey: List<int>.filled(32, 2),
    );
    final b = await deriveSas(
      master: List<int>.filled(32, 4),
      initiatorStaticPublicKey: List<int>.filled(32, 1),
      responderStaticPublicKey: List<int>.filled(32, 2),
    );
    expect(a, isNot(equals(b)));
  });

  test('differs when a static key differs (MITM detection)', () async {
    final honest = await deriveSas(
      master: List<int>.filled(32, 3),
      initiatorStaticPublicKey: List<int>.filled(32, 1),
      responderStaticPublicKey: List<int>.filled(32, 2),
    );
    final mitm = await deriveSas(
      master: List<int>.filled(32, 3),
      initiatorStaticPublicKey: List<int>.filled(32, 1),
      responderStaticPublicKey: List<int>.filled(32, 9),
    );
    expect(honest, isNot(equals(mitm)));
  });

  test('formats as space-separated words', () {
    expect(formatSas(['able', 'brisk', 'cedar']), 'able brisk cedar');
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/crypto/sas_test.dart`
Expected: FAIL — `omnifiWordlist isn't defined`.

- [ ] **Step 3: Create the wordlist**

Create `packages/omnifi_core/lib/src/crypto/wordlist.dart`. It must contain exactly 256 unique lowercase words of 3–7 letters. Use this list verbatim:

```dart
/// 256 words for short authentication strings and pairing phrases.
/// Chosen to be short, common, and phonetically distinct when read aloud.
const List<String> omnifiWordlist = [
  'able', 'acid', 'acorn', 'actor', 'adapt', 'admit', 'adopt', 'agent',
  'agree', 'ahead', 'alarm', 'album', 'alert', 'alien', 'align', 'alive',
  'alley', 'alloy', 'alone', 'alpha', 'amber', 'ample', 'anchor', 'angel',
  'anger', 'angle', 'ankle', 'apple', 'apron', 'arbor', 'arena', 'argue',
  'arise', 'armor', 'arrow', 'aspen', 'asset', 'atlas', 'audio', 'audit',
  'aunt', 'avoid', 'awake', 'award', 'aware', 'bacon', 'badge', 'bagel',
  'baker', 'balmy', 'banjo', 'barge', 'basil', 'basin', 'batch', 'beach',
  'beacon', 'beard', 'beast', 'bench', 'berry', 'birch', 'bison', 'blade',
  'blaze', 'blend', 'bliss', 'block', 'bloom', 'blue', 'blunt', 'board',
  'bonus', 'boost', 'booth', 'brace', 'braid', 'brain', 'brand', 'brave',
  'bread', 'break', 'brick', 'bride', 'brief', 'bring', 'brisk', 'broad',
  'bronze', 'brook', 'brush', 'buddy', 'bugle', 'build', 'bunch', 'bunny',
  'burst', 'cabin', 'cable', 'cache', 'cadet', 'camel', 'canal', 'candy',
  'canoe', 'canyon', 'carbon', 'cargo', 'carol', 'carve', 'catch', 'cedar',
  'chain', 'chair', 'chalk', 'charm', 'chase', 'cheer', 'chess', 'chief',
  'chill', 'chime', 'chirp', 'chord', 'cider', 'cinema', 'civic', 'claim',
  'clamp', 'clash', 'clasp', 'clean', 'clear', 'cliff', 'climb', 'cloak',
  'clock', 'cloud', 'clove', 'clown', 'coach', 'coast', 'cobra', 'cocoa',
  'comet', 'coral', 'cover', 'coyote', 'craft', 'crane', 'crate', 'crawl',
  'cream', 'creek', 'crest', 'crisp', 'crown', 'crumb', 'curve', 'cycle',
  'daisy', 'dance', 'dandy', 'dawn', 'debut', 'decal', 'decoy', 'delta',
  'dense', 'depot', 'depth', 'diary', 'diner', 'ditch', 'diver', 'dodge',
  'donor', 'donut', 'draft', 'drama', 'dream', 'dress', 'drift', 'drink',
  'drive', 'drum', 'dryer', 'eagle', 'early', 'earth', 'easel', 'ebony',
  'echo', 'edge', 'eight', 'elbow', 'elder', 'elite', 'ember', 'emoji',
  'empty', 'enact', 'enjoy', 'enter', 'envoy', 'equal', 'equip', 'error',
  'essay', 'ether', 'event', 'every', 'exact', 'exile', 'exist', 'extra',
  'fable', 'facet', 'faint', 'fairy', 'false', 'fancy', 'fault', 'favor',
  'feast', 'fence', 'ferry', 'fever', 'fiber', 'field', 'fiery', 'fifty',
  'films', 'final', 'finch', 'first', 'flame', 'flash', 'fleet', 'flint',
  'float', 'flock', 'flour', 'fluid', 'flute', 'foam', 'focus', 'foggy',
  'force', 'forest', 'forge', 'forty', 'forum', 'found', 'frame', 'fresh',
];
```

- [ ] **Step 4: Verify the wordlist length before writing the SAS code**

Run: `cd packages/omnifi_core && dart test test/crypto/sas_test.dart --name 'wordlist'`
Expected: the two wordlist tests PASS. If the count is not 256, adjust the final row until it is — the count test is the authority.

- [ ] **Step 5: Write the SAS implementation**

Create `packages/omnifi_core/lib/src/crypto/sas.dart`:

```dart
import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import 'wordlist.dart';

final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

/// Derives a human-verifiable short authentication string.
///
/// Bound to both static public keys so that a man-in-the-middle, who
/// necessarily presents a different key to each side, produces a
/// different SAS on each screen.
Future<List<String>> deriveSas({
  required List<int> master,
  required List<int> initiatorStaticPublicKey,
  required List<int> responderStaticPublicKey,
  int words = 5,
}) async {
  if (words < 1 || words > 32) {
    throw ArgumentError.value(words, 'words', 'must be between 1 and 32');
  }
  final key = await _hkdf.deriveKey(
    secretKey: SecretKey(master),
    nonce: [...initiatorStaticPublicKey, ...responderStaticPublicKey],
    info: utf8.encode('omnifi-sas-v1'),
  );
  final bytes = await key.extractBytes();
  return [for (var i = 0; i < words; i++) omnifiWordlist[bytes[i]]];
}

String formatSas(List<String> words) => words.join(' ');
```

- [ ] **Step 6: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/crypto/sas.dart';
export 'src/crypto/wordlist.dart';
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/crypto/sas_test.dart`
Expected: PASS — `+7: All tests passed!`

- [ ] **Step 8: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: derive short authentication strings bound to both static keys"
```

---

## Task 7: Frame codec

**Files:**
- Create: `packages/omnifi_core/lib/src/protocol/framing.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/protocol/framing_test.dart`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `const int maxFrameBytes = 1048576`
  - `Uint8List encodeFrame(List<int> payload)` — prepends a 4-byte big-endian length. Throws `FrameTooLargeError` above the cap.
  - `class FrameDecoder` with `Iterable<Uint8List> addChunk(List<int> chunk)` and `void reset()` — accumulates partial reads from a socket and emits complete frames. Throws `FrameTooLargeError` on an oversized declared length.
  - `class FrameTooLargeError implements Exception`

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/protocol/framing_test.dart`:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('encodes a 4-byte big-endian length prefix', () {
    final frame = encodeFrame(utf8.encode('hi'));
    expect(frame.sublist(0, 4), [0, 0, 0, 2]);
    expect(utf8.decode(frame.sublist(4)), 'hi');
  });

  test('rejects a payload over the cap', () {
    expect(() => encodeFrame(Uint8List(maxFrameBytes + 1)),
        throwsA(isA<FrameTooLargeError>()));
  });

  test('decodes a single whole frame', () {
    final d = FrameDecoder();
    final out = d.addChunk(encodeFrame(utf8.encode('one'))).toList();
    expect(out.length, 1);
    expect(utf8.decode(out.single), 'one');
  });

  test('decodes two frames arriving in one chunk', () {
    final d = FrameDecoder();
    final chunk = [
      ...encodeFrame(utf8.encode('a')),
      ...encodeFrame(utf8.encode('bb')),
    ];
    final out = d.addChunk(chunk).toList();
    expect(out.map(utf8.decode), ['a', 'bb']);
  });

  test('reassembles a frame split across chunks', () {
    final d = FrameDecoder();
    final frame = encodeFrame(utf8.encode('split me'));
    expect(d.addChunk(frame.sublist(0, 3)).toList(), isEmpty);
    expect(d.addChunk(frame.sublist(3, 7)).toList(), isEmpty);
    final out = d.addChunk(frame.sublist(7)).toList();
    expect(out.map(utf8.decode), ['split me']);
  });

  test('handles a chunk boundary inside the length prefix', () {
    final d = FrameDecoder();
    final frame = encodeFrame(utf8.encode('xy'));
    expect(d.addChunk(frame.sublist(0, 2)).toList(), isEmpty);
    expect(d.addChunk(frame.sublist(2)).map(utf8.decode), ['xy']);
  });

  test('emits an empty payload frame', () {
    final d = FrameDecoder();
    expect(d.addChunk(encodeFrame(const [])).single, isEmpty);
  });

  test('rejects an oversized declared length', () {
    final d = FrameDecoder();
    final header = Uint8List(4);
    ByteData.view(header.buffer).setUint32(0, maxFrameBytes + 1);
    expect(() => d.addChunk(header).toList(),
        throwsA(isA<FrameTooLargeError>()));
  });

  test('reset discards a partial frame', () {
    final d = FrameDecoder();
    d.addChunk(encodeFrame(utf8.encode('partial')).sublist(0, 5)).toList();
    d.reset();
    final out = d.addChunk(encodeFrame(utf8.encode('fresh'))).toList();
    expect(out.map(utf8.decode), ['fresh']);
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/protocol/framing_test.dart`
Expected: FAIL — `encodeFrame isn't defined`.

- [ ] **Step 3: Write the implementation**

Create `packages/omnifi_core/lib/src/protocol/framing.dart`:

```dart
import 'dart:typed_data';

/// Hard ceiling on a single frame's payload, in bytes.
const int maxFrameBytes = 1048576;

const int _prefixBytes = 4;

class FrameTooLargeError implements Exception {
  const FrameTooLargeError(this.declared);
  final int declared;
  @override
  String toString() =>
      'FrameTooLargeError: $declared bytes exceeds cap of $maxFrameBytes';
}

Uint8List encodeFrame(List<int> payload) {
  if (payload.length > maxFrameBytes) {
    throw FrameTooLargeError(payload.length);
  }
  final out = Uint8List(_prefixBytes + payload.length);
  ByteData.view(out.buffer).setUint32(0, payload.length);
  out.setRange(_prefixBytes, out.length, payload);
  return out;
}

/// Accumulates socket reads and emits complete frames.
///
/// A single chunk may contain zero, one, or many frames, and a frame may
/// straddle any number of chunks — including a split inside the length
/// prefix itself.
class FrameDecoder {
  final BytesBuilder _buffer = BytesBuilder(copy: true);

  void reset() => _buffer.clear();

  Iterable<Uint8List> addChunk(List<int> chunk) sync* {
    _buffer.add(chunk);
    var bytes = _buffer.toBytes();
    var offset = 0;

    while (bytes.length - offset >= _prefixBytes) {
      final length = ByteData.view(bytes.buffer, bytes.offsetInBytes + offset)
          .getUint32(0);
      if (length > maxFrameBytes) {
        throw FrameTooLargeError(length);
      }
      if (bytes.length - offset - _prefixBytes < length) {
        break;
      }
      final start = offset + _prefixBytes;
      yield Uint8List.sublistView(bytes, start, start + length);
      offset = start + length;
    }

    _buffer.clear();
    if (offset < bytes.length) {
      _buffer.add(Uint8List.sublistView(bytes, offset));
    }
  }
}
```

- [ ] **Step 4: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/protocol/framing.dart';
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/protocol/framing_test.dart`
Expected: PASS — `+9: All tests passed!`

- [ ] **Step 6: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add length-prefixed frame codec with streaming decoder"
```

---

## Task 8: Message envelope and typed payloads

**Files:**
- Create: `packages/omnifi_core/lib/src/protocol/envelope.dart`
- Create: `packages/omnifi_core/lib/src/protocol/messages.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/protocol/envelope_test.dart`

**Interfaces:**
- Consumes: `omnifiProtocolVersion` (Task 1).
- Produces:
  - `enum MessageType { hello, heartbeat, heartbeatAck, rosterUpdate, clipboardUpdate, clipboardTooLarge, pairRequest, pairAccept }` — each with a stable `wireName` string.
  - `class Envelope { final int version; final MessageType type; final String senderDeviceId; final String messageId; final int timestampMs; final Map<String, Object?> payload; }`
  - `Uint8List encodeEnvelope(Envelope e)` / `Envelope decodeEnvelope(List<int> bytes)` — CBOR. Throws `EnvelopeError` on unknown version, unknown type, or malformed structure.
  - `class EnvelopeError implements Exception`
  - `class ClipboardPayload { final String format; /* 'text' | 'png' */ final Uint8List data; final int timestampMs; final String contentHash; }` with `toMap()` / `fromMap()`.

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/protocol/envelope_test.dart`:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

Envelope sample({MessageType type = MessageType.clipboardUpdate}) => Envelope(
      version: omnifiProtocolVersion,
      type: type,
      senderDeviceId: 'a' * 32,
      messageId: 'b' * 32,
      timestampMs: 1753200000000,
      payload: {'k': 'v'},
    );

void main() {
  test('round-trips an envelope', () {
    final decoded = decodeEnvelope(encodeEnvelope(sample()));
    expect(decoded.version, omnifiProtocolVersion);
    expect(decoded.type, MessageType.clipboardUpdate);
    expect(decoded.senderDeviceId, 'a' * 32);
    expect(decoded.messageId, 'b' * 32);
    expect(decoded.timestampMs, 1753200000000);
    expect(decoded.payload['k'], 'v');
  });

  test('round-trips every message type', () {
    for (final t in MessageType.values) {
      expect(decodeEnvelope(encodeEnvelope(sample(type: t))).type, t);
    }
  });

  test('message type wire names are unique and stable', () {
    final names = MessageType.values.map((t) => t.wireName).toList();
    expect(names.toSet().length, names.length);
    expect(MessageType.clipboardUpdate.wireName, 'clipboard_update');
    expect(MessageType.heartbeat.wireName, 'heartbeat');
  });

  test('rejects an unknown protocol version', () {
    final bad = Envelope(
      version: 99,
      type: MessageType.heartbeat,
      senderDeviceId: 'a' * 32,
      messageId: 'b' * 32,
      timestampMs: 1,
      payload: const {},
    );
    expect(() => decodeEnvelope(encodeEnvelope(bad)),
        throwsA(isA<EnvelopeError>()));
  });

  test('rejects malformed bytes', () {
    expect(() => decodeEnvelope(utf8.encode('not cbor at all')),
        throwsA(isA<EnvelopeError>()));
  });

  test('clipboard payload round-trips text', () {
    final p = ClipboardPayload(
      format: 'text',
      data: Uint8List.fromList(utf8.encode('copied')),
      timestampMs: 1753200000000,
      contentHash: 'deadbeef',
    );
    final back = ClipboardPayload.fromMap(p.toMap());
    expect(back.format, 'text');
    expect(utf8.decode(back.data), 'copied');
    expect(back.contentHash, 'deadbeef');
    expect(back.timestampMs, 1753200000000);
  });

  test('clipboard payload survives an envelope round-trip', () {
    final p = ClipboardPayload(
      format: 'png',
      data: Uint8List.fromList([137, 80, 78, 71]),
      timestampMs: 5,
      contentHash: 'abc123',
    );
    final e = Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'a' * 32,
      messageId: 'b' * 32,
      timestampMs: 5,
      payload: p.toMap(),
    );
    final back =
        ClipboardPayload.fromMap(decodeEnvelope(encodeEnvelope(e)).payload);
    expect(back.data, [137, 80, 78, 71]);
    expect(back.format, 'png');
  });

  test('clipboard payload rejects an unknown format', () {
    expect(
      () => ClipboardPayload.fromMap({
        'format': 'video',
        'data': <int>[],
        'ts': 1,
        'hash': 'x',
      }),
      throwsA(isA<EnvelopeError>()),
    );
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/protocol/envelope_test.dart`
Expected: FAIL — `Envelope isn't defined`.

- [ ] **Step 3: Write the message types**

Create `packages/omnifi_core/lib/src/protocol/messages.dart`:

```dart
import 'dart:typed_data';

import 'envelope.dart';

enum MessageType {
  hello('hello'),
  heartbeat('heartbeat'),
  heartbeatAck('heartbeat_ack'),
  rosterUpdate('roster_update'),
  clipboardUpdate('clipboard_update'),
  clipboardTooLarge('clipboard_too_large'),
  pairRequest('pair_request'),
  pairAccept('pair_accept');

  const MessageType(this.wireName);

  /// Stable on-the-wire identifier. Never change these without a
  /// protocol version bump.
  final String wireName;

  static MessageType fromWireName(String name) {
    for (final t in MessageType.values) {
      if (t.wireName == name) return t;
    }
    throw EnvelopeError('unknown message type: $name');
  }
}

const Set<String> supportedClipboardFormats = {'text', 'png'};

class ClipboardPayload {
  ClipboardPayload({
    required this.format,
    required this.data,
    required this.timestampMs,
    required this.contentHash,
  }) {
    if (!supportedClipboardFormats.contains(format)) {
      throw EnvelopeError('unsupported clipboard format: $format');
    }
  }

  final String format;
  final Uint8List data;
  final int timestampMs;
  final String contentHash;

  Map<String, Object?> toMap() => {
        'format': format,
        'data': data,
        'ts': timestampMs,
        'hash': contentHash,
      };

  factory ClipboardPayload.fromMap(Map<String, Object?> map) {
    final format = map['format'];
    final data = map['data'];
    final ts = map['ts'];
    final hash = map['hash'];
    if (format is! String || data is! List<int> || ts is! int ||
        hash is! String) {
      throw const EnvelopeError('malformed clipboard payload');
    }
    return ClipboardPayload(
      format: format,
      data: Uint8List.fromList(data),
      timestampMs: ts,
      contentHash: hash,
    );
  }
}
```

- [ ] **Step 4: Write the envelope codec**

Create `packages/omnifi_core/lib/src/protocol/envelope.dart`:

```dart
import 'dart:typed_data';

import 'package:cbor/cbor.dart';

import '../version.dart';
import 'messages.dart';

class EnvelopeError implements Exception {
  const EnvelopeError(this.reason);
  final String reason;
  @override
  String toString() => 'EnvelopeError: $reason';
}

class Envelope {
  const Envelope({
    required this.version,
    required this.type,
    required this.senderDeviceId,
    required this.messageId,
    required this.timestampMs,
    required this.payload,
  });

  final int version;
  final MessageType type;
  final String senderDeviceId;
  final String messageId;
  final int timestampMs;
  final Map<String, Object?> payload;
}

Uint8List encodeEnvelope(Envelope e) {
  return Uint8List.fromList(cbor.encode(CborValue({
    'v': e.version,
    't': e.type.wireName,
    'from': e.senderDeviceId,
    'mid': e.messageId,
    'ts': e.timestampMs,
    'p': e.payload,
  })));
}

Envelope decodeEnvelope(List<int> bytes) {
  final Object? decoded;
  try {
    decoded = cbor.decode(bytes).toObject();
  } catch (_) {
    throw const EnvelopeError('payload is not valid CBOR');
  }
  if (decoded is! Map) {
    throw const EnvelopeError('envelope is not a map');
  }

  final version = decoded['v'];
  if (version is! int) {
    throw const EnvelopeError('missing or malformed version');
  }
  if (version != omnifiProtocolVersion) {
    throw EnvelopeError('unsupported protocol version: $version');
  }

  final type = decoded['t'];
  final from = decoded['from'];
  final mid = decoded['mid'];
  final ts = decoded['ts'];
  final payload = decoded['p'];

  if (type is! String || from is! String || mid is! String || ts is! int) {
    throw const EnvelopeError('malformed envelope header');
  }
  if (payload is! Map) {
    throw const EnvelopeError('malformed envelope payload');
  }

  return Envelope(
    version: version,
    type: MessageType.fromWireName(type),
    senderDeviceId: from,
    messageId: mid,
    timestampMs: ts,
    payload: payload.map((k, v) => MapEntry(k.toString(), v)),
  );
}
```

- [ ] **Step 5: Export both**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/protocol/envelope.dart';
export 'src/protocol/messages.dart';
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/protocol/envelope_test.dart`
Expected: PASS — `+8: All tests passed!`

- [ ] **Step 7: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add CBOR message envelope and typed clipboard payload"
```

---

## Task 9: Device identity and the `SecureStore` interface

**Files:**
- Create: `packages/omnifi_core/lib/src/identity/secure_store.dart`
- Create: `packages/omnifi_core/lib/src/identity/device_identity.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/identity/device_identity_test.dart`

**Interfaces:**
- Consumes: `OmniFiHandshakeV1.generateStaticKeys()` and `StaticKeyPair` (Task 4).
- Produces:
  - `abstract interface class SecureStore` with `Future<String?> read(String key)`, `Future<void> write(String key, String value)`, `Future<void> delete(String key)`
  - `class InMemorySecureStore implements SecureStore` — test double, also exported for use by integration tests.
  - `class DeviceIdentity { final String deviceId; final String displayName; final StaticKeyPair keys; }`
  - `Future<DeviceIdentity> loadOrCreateIdentity({required SecureStore store, required String displayName})` — idempotent; a second call returns the identical identity.
  - `String randomHexId([int bytes = 16])` — 32-char lowercase hex, used for both device IDs and mesh IDs.

The private key never leaves `SecureStore`. Platform implementations (Keychain, Windows Credential Manager) arrive in Tasks 19 and 20; the core only ever sees this interface.

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/identity/device_identity_test.dart`:

```dart
import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('random hex id is 32 lowercase hex characters', () {
    final id = randomHexId();
    expect(id, matches(RegExp(r'^[0-9a-f]{32}$')));
  });

  test('random hex ids do not collide across many draws', () {
    final ids = {for (var i = 0; i < 1000; i++) randomHexId()};
    expect(ids.length, 1000);
  });

  test('creates an identity on first load', () async {
    final store = InMemorySecureStore();
    final id = await loadOrCreateIdentity(
        store: store, displayName: 'Mac Studio');
    expect(id.deviceId, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(id.displayName, 'Mac Studio');
    expect(id.keys.publicKey.length, 32);
    expect(id.keys.privateKey.length, 32);
  });

  test('returns the identical identity on a second load', () async {
    final store = InMemorySecureStore();
    final first = await loadOrCreateIdentity(
        store: store, displayName: 'Mac Studio');
    final second = await loadOrCreateIdentity(
        store: store, displayName: 'Ignored On Reload');
    expect(second.deviceId, first.deviceId);
    expect(second.keys.publicKey, first.keys.publicKey);
    expect(second.keys.privateKey, first.keys.privateKey);
  });

  test('display name is updated on reload but identity is not', () async {
    final store = InMemorySecureStore();
    final first =
        await loadOrCreateIdentity(store: store, displayName: 'Old Name');
    final second =
        await loadOrCreateIdentity(store: store, displayName: 'New Name');
    expect(second.displayName, 'New Name');
    expect(second.deviceId, first.deviceId);
  });

  test('two stores produce two distinct identities', () async {
    final a = await loadOrCreateIdentity(
        store: InMemorySecureStore(), displayName: 'A');
    final b = await loadOrCreateIdentity(
        store: InMemorySecureStore(), displayName: 'B');
    expect(a.deviceId, isNot(b.deviceId));
    expect(a.keys.publicKey, isNot(b.keys.publicKey));
  });

  test('a corrupt stored key is rejected rather than silently replaced',
      () async {
    final store = InMemorySecureStore();
    await loadOrCreateIdentity(store: store, displayName: 'A');
    await store.write('omnifi.identity.privateKey', 'not-base64-!!!');
    expect(
      () => loadOrCreateIdentity(store: store, displayName: 'A'),
      throwsA(isA<IdentityError>()),
    );
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/identity/device_identity_test.dart`
Expected: FAIL — `randomHexId isn't defined`.

- [ ] **Step 3: Write the SecureStore interface**

Create `packages/omnifi_core/lib/src/identity/secure_store.dart`:

```dart
/// Platform-backed secret storage. Implementations live in the Flutter app
/// (Keychain on macOS/iOS, Credential Manager on Windows). The core never
/// touches a file directly.
abstract interface class SecureStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// Non-persistent store for tests and integration harnesses.
class InMemorySecureStore implements SecureStore {
  final Map<String, String> _values = {};

  @override
  Future<String?> read(String key) async => _values[key];

  @override
  Future<void> write(String key, String value) async {
    _values[key] = value;
  }

  @override
  Future<void> delete(String key) async {
    _values.remove(key);
  }
}
```

- [ ] **Step 4: Write the identity implementation**

Create `packages/omnifi_core/lib/src/identity/device_identity.dart`:

```dart
import 'dart:convert';
import 'dart:math';

import '../crypto/handshake.dart';
import 'secure_store.dart';

class IdentityError implements Exception {
  const IdentityError(this.reason);
  final String reason;
  @override
  String toString() => 'IdentityError: $reason';
}

const _kDeviceId = 'omnifi.identity.deviceId';
const _kPrivateKey = 'omnifi.identity.privateKey';
const _kPublicKey = 'omnifi.identity.publicKey';
const _kDisplayName = 'omnifi.identity.displayName';

final Random _rng = Random.secure();

/// Lowercase hex identifier, 32 characters for the default 16 bytes.
String randomHexId([int bytes = 16]) {
  final buf = StringBuffer();
  for (var i = 0; i < bytes; i++) {
    buf.write(_rng.nextInt(256).toRadixString(16).padLeft(2, '0'));
  }
  return buf.toString();
}

class DeviceIdentity {
  const DeviceIdentity({
    required this.deviceId,
    required this.displayName,
    required this.keys,
  });

  final String deviceId;
  final String displayName;
  final StaticKeyPair keys;
}

/// Loads the device's long-term identity, creating it on first run.
///
/// Idempotent: the device ID and keypair are generated exactly once and
/// reused forever after. Only the display name is refreshed on reload.
Future<DeviceIdentity> loadOrCreateIdentity({
  required SecureStore store,
  required String displayName,
}) async {
  final existingId = await store.read(_kDeviceId);
  final existingPriv = await store.read(_kPrivateKey);
  final existingPub = await store.read(_kPublicKey);

  final present = [existingId, existingPriv, existingPub].where((v) => v != null).length;

  // Partial state must fail loudly. Falling through to the create branch here
  // would silently mint a NEW identity for a device that already has one --
  // orphaning it from every peer it had paired with, with no error shown. A
  // crash midway through first-run persistence, a partial keychain eviction,
  // or a migration bug all produce this state.
  if (present != 0 && present != 3) {
    throw const IdentityError(
        'stored identity is incomplete; refusing to regenerate and orphan '
        'this device from its mesh. Restore the keychain entry, or delete '
        'all of omnifi.identity.* to deliberately re-pair as a new device.');
  }

  if (present == 3) {
    final List<int> priv;
    final List<int> pub;
    try {
      priv = base64Decode(existingPriv!);
      pub = base64Decode(existingPub!);
    } on FormatException {
      throw const IdentityError('stored key material is not valid base64');
    }
    if (priv.length != 32 || pub.length != 32) {
      throw const IdentityError('stored key material has the wrong length');
    }
    await store.write(_kDisplayName, displayName);
    return DeviceIdentity(
      deviceId: existingId!,
      displayName: displayName,
      keys: StaticKeyPair(publicKey: pub, privateKey: priv),
    );
  }

  final keys = await OmniFiHandshakeV1.generateStaticKeys();
  final deviceId = randomHexId();
  await store.write(_kDeviceId, deviceId);
  await store.write(_kPrivateKey, base64Encode(keys.privateKey));
  await store.write(_kPublicKey, base64Encode(keys.publicKey));
  await store.write(_kDisplayName, displayName);

  return DeviceIdentity(
    deviceId: deviceId,
    displayName: displayName,
    keys: keys,
  );
}
```

- [ ] **Step 5: Export both**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/identity/device_identity.dart';
export 'src/identity/secure_store.dart';
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/identity/device_identity_test.dart`
Expected: PASS — `+7: All tests passed!`

- [ ] **Step 7: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add device identity with SecureStore-backed key material"
```

---

## Task 10: Mesh roster and revocation

**Files:**
- Create: `packages/omnifi_core/lib/src/identity/mesh.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/identity/mesh_test.dart`

**Interfaces:**
- Consumes: `randomHexId` and `SecureStore` (Task 9), `EnvelopeError` (Task 8).
- Produces:
  - `class MeshError implements Exception {
  const MeshError(this.reason);
  final String reason;
  @override
  String toString() => 'MeshError: $reason';
}

class PeerRecord { final String deviceId; final List<int> publicKey; final String displayName; final int addedAtMs; }` with `toMap()` / `fromMap()`.
  - `class Mesh { final String meshId; List<PeerRecord> get peers; }` with:
    - `void addPeer(PeerRecord peer)` — replaces an existing record with the same device ID
    - `bool removePeer(String deviceId)` — returns whether anything was removed
    - `PeerRecord? peer(String deviceId)`
    - `bool isAuthorized(String deviceId, List<int> publicKey)` — device ID present **and** key matches exactly
    - `Map<String, Object?> toMap()` / `static Mesh fromMap(Map<String, Object?>)`
  - `Future<Mesh> loadOrCreateMesh({required SecureStore store})` and `Future<void> saveMesh(Mesh mesh, SecureStore store)`

`isAuthorized` requires an exact key match, not just a known device ID — otherwise a revoked-then-readded device ID would accept an attacker's key.

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/identity/mesh_test.dart`:

```dart
import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

PeerRecord peer(String id, {int keyFill = 7, String name = 'Peer'}) =>
    PeerRecord(
      deviceId: id,
      publicKey: List<int>.filled(32, keyFill),
      displayName: name,
      addedAtMs: 1753200000000,
    );

void main() {
  test('creates a mesh with a 32-char hex id', () async {
    final mesh = await loadOrCreateMesh(store: InMemorySecureStore());
    expect(mesh.meshId, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(mesh.peers, isEmpty);
  });

  test('reloads the same mesh id', () async {
    final store = InMemorySecureStore();
    final first = await loadOrCreateMesh(store: store);
    final second = await loadOrCreateMesh(store: store);
    expect(second.meshId, first.meshId);
  });

  test('adds and looks up a peer', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32, name: 'Windows PC'));
    expect(mesh.peers.length, 1);
    expect(mesh.peer('b' * 32)?.displayName, 'Windows PC');
  });

  test('adding the same device id replaces rather than duplicates', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32, name: 'Old'));
    mesh.addPeer(peer('b' * 32, name: 'New'));
    expect(mesh.peers.length, 1);
    expect(mesh.peer('b' * 32)?.displayName, 'New');
  });

  test('removes a peer and reports whether it existed', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32));
    expect(mesh.removePeer('b' * 32), isTrue);
    expect(mesh.removePeer('b' * 32), isFalse);
    expect(mesh.peers, isEmpty);
  });

  test('authorizes a known device with a matching key', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32, keyFill: 7));
    expect(mesh.isAuthorized('b' * 32, List<int>.filled(32, 7)), isTrue);
  });

  test('refuses a known device id with a different key', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32, keyFill: 7));
    expect(mesh.isAuthorized('b' * 32, List<int>.filled(32, 8)), isFalse);
  });

  test('refuses an unknown device id', () {
    final mesh = Mesh(meshId: 'a' * 32);
    expect(mesh.isAuthorized('c' * 32, List<int>.filled(32, 7)), isFalse);
  });

  test('refuses a revoked device even with its original key', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32, keyFill: 7));
    mesh.removePeer('b' * 32);
    expect(mesh.isAuthorized('b' * 32, List<int>.filled(32, 7)), isFalse);
  });

  test('survives a save and reload with peers intact', () async {
    final store = InMemorySecureStore();
    final mesh = await loadOrCreateMesh(store: store);
    mesh.addPeer(peer('b' * 32, name: 'iPhone'));
    await saveMesh(mesh, store);

    final reloaded = await loadOrCreateMesh(store: store);
    expect(reloaded.meshId, mesh.meshId);
    expect(reloaded.peers.length, 1);
    expect(reloaded.peer('b' * 32)?.displayName, 'iPhone');
    expect(reloaded.isAuthorized('b' * 32, List<int>.filled(32, 7)), isTrue);
  });

  test('rejects a peer record with a wrong-length key', () {
    expect(
      () => PeerRecord(
        deviceId: 'b' * 32,
        publicKey: List<int>.filled(16, 1),
        displayName: 'Bad',
        addedAtMs: 1,
      ),
      throwsA(isA<ArgumentError>()),
    );
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/identity/mesh_test.dart`
Expected: FAIL — `PeerRecord isn't defined`.

- [ ] **Step 3: Write the implementation**

Create `packages/omnifi_core/lib/src/identity/mesh.dart`:

```dart
import 'dart:convert';

import 'device_identity.dart';
import 'secure_store.dart';

const _kMeshId = 'omnifi.mesh.id';
const _kRoster = 'omnifi.mesh.roster';

class PeerRecord {
  PeerRecord({
    required this.deviceId,
    required this.publicKey,
    required this.displayName,
    required this.addedAtMs,
  }) {
    if (publicKey.length != 32) {
      throw ArgumentError.value(
          publicKey.length, 'publicKey', 'must be 32 bytes');
    }
  }

  final String deviceId;
  final List<int> publicKey;
  final String displayName;
  final int addedAtMs;

  Map<String, Object?> toMap() => {
        'deviceId': deviceId,
        'publicKey': base64Encode(publicKey),
        'displayName': displayName,
        'addedAtMs': addedAtMs,
      };

  static PeerRecord fromMap(Map<String, Object?> map) {
    final deviceId = map['deviceId'];
    final publicKey = map['publicKey'];
    final displayName = map['displayName'];
    final addedAtMs = map['addedAtMs'];
    if (deviceId is! String ||
        publicKey is! String ||
        displayName is! String ||
        addedAtMs is! int) {
      throw ArgumentError('malformed peer record');
    }
    return PeerRecord(
      deviceId: deviceId,
      publicKey: base64Decode(publicKey),
      displayName: displayName,
      addedAtMs: addedAtMs,
    );
  }
}

class Mesh {
  Mesh({required this.meshId, List<PeerRecord> peers = const []})
      : _peers = {for (final p in peers) p.deviceId: p};

  final String meshId;
  final Map<String, PeerRecord> _peers;

  List<PeerRecord> get peers => List.unmodifiable(_peers.values);

  void addPeer(PeerRecord peer) => _peers[peer.deviceId] = peer;

  bool removePeer(String deviceId) => _peers.remove(deviceId) != null;

  PeerRecord? peer(String deviceId) => _peers[deviceId];

  /// A peer is authorized only when its device ID is in the roster AND the
  /// presented public key matches the stored one byte for byte. Matching on
  /// device ID alone would let an attacker reuse a revoked ID with a new key.
  bool isAuthorized(String deviceId, List<int> publicKey) {
    final record = _peers[deviceId];
    if (record == null) return false;
    if (record.publicKey.length != publicKey.length) return false;
    var diff = 0;
    for (var i = 0; i < publicKey.length; i++) {
      diff |= record.publicKey[i] ^ publicKey[i];
    }
    return diff == 0;
  }

  Map<String, Object?> toMap() => {
        'meshId': meshId,
        'peers': [for (final p in _peers.values) p.toMap()],
      };

  static Mesh fromMap(Map<String, Object?> map) {
    final meshId = map['meshId'];
    final peers = map['peers'];
    if (meshId is! String || peers is! List) {
      throw ArgumentError('malformed mesh');
    }
    return Mesh(
      meshId: meshId,
      peers: [
        for (final p in peers)
          PeerRecord.fromMap((p as Map).map(
              (k, v) => MapEntry(k.toString(), v))),
      ],
    );
  }
}

Future<Mesh> loadOrCreateMesh({required SecureStore store}) async {
  final existingId = await store.read(_kMeshId);
  final existingRoster = await store.read(_kRoster);

  // All-or-nothing, in BOTH directions. The mirror case matters more than the
  // obvious one: a roster present with no mesh ID would otherwise mint a fresh
  // mesh ID and saveMesh() straight over the existing roster, destroying every
  // paired device silently. That is worse than failing closed — it is data loss.
  if ((existingId == null) != (existingRoster == null)) {
    throw const MeshError(
        'mesh state is incomplete: exactly one of the mesh id and the roster '
        'is present. Refusing to continue, because creating a new mesh here '
        'would overwrite the surviving half. Restore the missing entry, or '
        'delete omnifi.mesh.* to deliberately start a new mesh.');
  }

  if (existingId == null) {
    final mesh = Mesh(meshId: randomHexId());
    await saveMesh(mesh, store);
    return mesh;
  }
  final roster = existingRoster;
  if (roster == null) {
    // Same all-or-nothing rule as loadOrCreateIdentity: a stored mesh ID with
    // no roster means the two SecureStore keys diverged (partial write, storage
    // eviction, tampering). Returning an empty roster here would make every
    // peer unauthorized and present as "pairing mysteriously broke" rather than
    // as an error. It fails closed, so it is not an authorization bypass — but
    // it is undiagnosable, which is its own harm.
    throw const MeshError(
        'mesh id is stored but its roster is missing; refusing to continue '
        'with an empty roster. Restore the roster entry, or delete '
        'omnifi.mesh.* to deliberately start a new mesh.');
  }
  final decoded = jsonDecode(roster);
  if (decoded is! Map) {
    throw ArgumentError('stored roster is malformed');
  }
  return Mesh.fromMap(decoded.map((k, v) => MapEntry(k.toString(), v)));
}

Future<void> saveMesh(Mesh mesh, SecureStore store) async {
  await store.write(_kMeshId, mesh.meshId);
  await store.write(_kRoster, jsonEncode(mesh.toMap()));
}
```

- [ ] **Step 4: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/identity/mesh.dart';
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/identity/mesh_test.dart`
Expected: PASS — `+11: All tests passed!`

- [ ] **Step 6: Run the whole suite**

Run: `cd packages/omnifi_core && dart test`
Expected: PASS — every test from Tasks 1, 3–10.

- [ ] **Step 7: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add mesh roster with key-exact authorization and revocation"
```

---

## Task 11: `Link` interface and the fake link test double

**Files:**
- Create: `packages/omnifi_core/lib/src/transport/link.dart`
- Create: `packages/omnifi_core/test/support/fake_link.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/transport/link_test.dart`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `enum LinkState { connecting, connected, disconnected, failed }`
  - `enum LinkKind { lan, relay }`
  - `class LinkQuality { final LinkKind kind; final Duration? rtt; }` with `bool get isDirect => kind == LinkKind.lan` and `int get preferenceScore` (lower is better; LAN beats relay, then lower RTT wins).
  - `abstract interface class Link` with `String get id`, `LinkKind get kind`, `Stream<Uint8List> get inbound`, `Stream<LinkState> get states`, `LinkState get state`, `LinkQuality get quality`, `Future<void> send(List<int> frame)`, `Future<void> close()`
  - `class LinkClosedError implements Exception`
- Test-only (in `test/support/fake_link.dart`, imported by Tasks 12–15 tests):
  - `class FakeLink implements Link` with `void deliver(List<int> frame)`, `List<Uint8List> get sent`, `void setState(LinkState)`, `void failNextSend()`, and `static ({FakeLink a, FakeLink b}) connectedPair({LinkKind kind = LinkKind.lan})` which cross-wires two fakes so a `send` on one surfaces on the other's `inbound`.

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/transport/link_test.dart`:

```dart
import 'dart:convert';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

void main() {
  test('lan is preferred over relay', () {
    const lan = LinkQuality(kind: LinkKind.lan, rtt: Duration(milliseconds: 40));
    const relay =
        LinkQuality(kind: LinkKind.relay, rtt: Duration(milliseconds: 5));
    expect(lan.preferenceScore, lessThan(relay.preferenceScore));
    expect(lan.isDirect, isTrue);
    expect(relay.isDirect, isFalse);
  });

  test('within the same kind, lower rtt is preferred', () {
    const fast = LinkQuality(kind: LinkKind.lan, rtt: Duration(milliseconds: 5));
    const slow =
        LinkQuality(kind: LinkKind.lan, rtt: Duration(milliseconds: 90));
    expect(fast.preferenceScore, lessThan(slow.preferenceScore));
  });

  test('unknown rtt ranks behind a measured one of the same kind', () {
    const measured =
        LinkQuality(kind: LinkKind.lan, rtt: Duration(milliseconds: 90));
    const unknown = LinkQuality(kind: LinkKind.lan, rtt: null);
    expect(measured.preferenceScore, lessThan(unknown.preferenceScore));
  });

  test('a connected fake pair carries frames both ways', () async {
    final p = FakeLink.connectedPair();
    final fromB = p.b.inbound.first;
    await p.a.send(utf8.encode('a to b'));
    expect(utf8.decode(await fromB), 'a to b');

    final fromA = p.a.inbound.first;
    await p.b.send(utf8.encode('b to a'));
    expect(utf8.decode(await fromA), 'b to a');
  });

  test('fake link records what was sent', () async {
    final p = FakeLink.connectedPair();
    await p.a.send(utf8.encode('one'));
    await p.a.send(utf8.encode('two'));
    expect(p.a.sent.map(utf8.decode), ['one', 'two']);
  });

  test('sending on a disconnected link throws', () async {
    final p = FakeLink.connectedPair();
    p.a.setState(LinkState.disconnected);
    expect(() => p.a.send(utf8.encode('nope')),
        throwsA(isA<LinkClosedError>()));
  });

  test('state changes are observable', () async {
    final p = FakeLink.connectedPair();
    final seen = <LinkState>[];
    p.a.states.listen(seen.add);
    p.a.setState(LinkState.disconnected);
    p.a.setState(LinkState.connecting);
    p.a.setState(LinkState.connected);
    await Future<void>.delayed(Duration.zero);
    expect(seen, [
      LinkState.disconnected,
      LinkState.connecting,
      LinkState.connected,
    ]);
  });

  test('close moves the link to disconnected', () async {
    final p = FakeLink.connectedPair();
    await p.a.close();
    expect(p.a.state, LinkState.disconnected);
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/transport/link_test.dart`
Expected: FAIL — `LinkQuality isn't defined`.

- [ ] **Step 3: Write the link interface**

Create `packages/omnifi_core/lib/src/transport/link.dart`:

```dart
import 'dart:typed_data';

enum LinkState { connecting, connected, disconnected, failed }

enum LinkKind { lan, relay }

class LinkClosedError implements Exception {
  const LinkClosedError(this.linkId);
  final String linkId;
  @override
  String toString() => 'LinkClosedError: link $linkId is not connected';
}

/// How desirable a link is. Lower [preferenceScore] wins.
class LinkQuality {
  const LinkQuality({required this.kind, this.rtt});

  final LinkKind kind;
  final Duration? rtt;

  bool get isDirect => kind == LinkKind.lan;

  /// LAN always outranks relay, regardless of measured latency: a relay that
  /// happens to be fast right now still costs a round trip through
  /// Cloudflare and cannot carry the media features planned for projects
  /// 3 and 4. Within a kind, a measured RTT outranks an unmeasured one.
  int get preferenceScore {
    final kindWeight = kind == LinkKind.lan ? 0 : 1000000;
    final rttWeight = rtt?.inMilliseconds ?? 999999;
    return kindWeight + rttWeight;
  }
}

/// An encrypted-transport-agnostic duplex byte channel to one peer.
///
/// Implementations: [LanLink] (Task 18), [RelayLink] (Task 17), and
/// `FakeLink` in tests. Nothing above this interface knows which is in use.
abstract interface class Link {
  String get id;
  LinkKind get kind;
  Stream<Uint8List> get inbound;
  Stream<LinkState> get states;
  LinkState get state;
  LinkQuality get quality;
  Future<void> send(List<int> frame);
  Future<void> close();
}
```

- [ ] **Step 4: Write the fake link**

Create `packages/omnifi_core/test/support/fake_link.dart`:

```dart
import 'dart:async';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';

/// In-memory [Link] for tests. Two fakes can be cross-wired so that a send
/// on one arrives on the other's inbound stream.
class FakeLink implements Link {
  FakeLink({
    required this.id,
    this.kind = LinkKind.lan,
    Duration? rtt = const Duration(milliseconds: 10),
  }) : _rtt = rtt;

  @override
  final String id;

  @override
  final LinkKind kind;

  final Duration? _rtt;

  final StreamController<Uint8List> _inbound =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkState> _states =
      StreamController<LinkState>.broadcast();

  final List<Uint8List> sent = [];

  FakeLink? _peer;
  LinkState _state = LinkState.connected;
  bool _failNextSend = false;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Stream<LinkState> get states => _states.stream;

  @override
  LinkState get state => _state;

  @override
  LinkQuality get quality => LinkQuality(kind: kind, rtt: _rtt);

  void setState(LinkState next) {
    _state = next;
    _states.add(next);
  }

  /// Makes the next [send] throw, simulating a socket that died mid-write.
  void failNextSend() => _failNextSend = true;

  /// Pushes a frame onto this link's inbound stream as though it arrived
  /// from the network.
  void deliver(List<int> frame) => _inbound.add(Uint8List.fromList(frame));

  @override
  Future<void> send(List<int> frame) async {
    if (_state != LinkState.connected) {
      throw LinkClosedError(id);
    }
    if (_failNextSend) {
      _failNextSend = false;
      throw LinkClosedError(id);
    }
    sent.add(Uint8List.fromList(frame));
    _peer?.deliver(frame);
  }

  @override
  Future<void> close() async {
    setState(LinkState.disconnected);
    await _inbound.close();
    await _states.close();
  }

  static ({FakeLink a, FakeLink b}) connectedPair({
    LinkKind kind = LinkKind.lan,
  }) {
    final a = FakeLink(id: 'fake-a', kind: kind);
    final b = FakeLink(id: 'fake-b', kind: kind);
    a._peer = b;
    b._peer = a;
    return (a: a, b: b);
  }
}
```

- [ ] **Step 5: Export the interface**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/transport/link.dart';
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/transport/link_test.dart`
Expected: PASS — `+8: All tests passed!`

- [ ] **Step 7: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add Link interface with LAN-preferring quality ranking"
```

---

## Task 12: Bounded collapsing outbox

**Files:**
- Create: `packages/omnifi_core/lib/src/transport/outbox.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/transport/outbox_test.dart`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `const int maxOutboxFrames = 50`
  - `const int maxOutboxBytes = 5242880`
  - `class OutboxEntry { final Uint8List frame; final String? collapseKey; }`
  - `class Outbox` with `void add(List<int> frame, {String? collapseKey})`, `List<OutboxEntry> drain()`, `int get length`, `int get byteLength`, `int get droppedCount`, `void clear()`

`collapseKey` is how stale clipboard updates are discarded: adding an entry whose key matches an existing one **removes the old entry and appends the new one at the tail**, rather than queueing a second copy. Nobody wants four stale clipboards delivered on reconnect.

**It must append, not replace in place.** An earlier draft of this plan specified position preservation, reasoning that moving the entry would let a clipboard update overtake messages queued behind it. That is backwards for counter-bearing frames: `AeadSession.seal` assigns a monotonic counter at seal time and the receiver rejects any counter that does not strictly advance — fatally. The replacement is sealed **last**, so it belongs **last**. Preserving the original slot put a later-sealed frame ahead of an earlier one, which killed the receiving session and lost the intervening frame.

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/transport/outbox_test.dart`:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('drains in insertion order', () {
    final o = Outbox();
    o.add(utf8.encode('one'));
    o.add(utf8.encode('two'));
    expect(o.drain().map((e) => utf8.decode(e.frame)), ['one', 'two']);
  });

  test('drain empties the outbox', () {
    final o = Outbox();
    o.add(utf8.encode('x'));
    o.drain();
    expect(o.length, 0);
    expect(o.drain(), isEmpty);
  });

  test('tracks byte length', () {
    final o = Outbox();
    o.add(Uint8List(100));
    o.add(Uint8List(50));
    expect(o.byteLength, 150);
  });

  test('collapses entries sharing a key, keeping the newest', () {
    final o = Outbox();
    o.add(utf8.encode('stale'), collapseKey: 'clipboard');
    o.add(utf8.encode('fresh'), collapseKey: 'clipboard');
    final drained = o.drain();
    expect(drained.length, 1);
    expect(utf8.decode(drained.single.frame), 'fresh');
  });

  test('collapse moves the replacement to the tail, preserving seal order', () {
    // NOT position-preserving. Frames carry monotonic AEAD counters assigned at
    // seal time and the receiver rejects any counter that does not strictly
    // advance, fatally. The replacement was sealed LAST, so it must go LAST.
    final o = Outbox();
    o.add(utf8.encode('first'), collapseKey: 'clipboard');
    o.add(utf8.encode('second'));
    o.add(utf8.encode('third'), collapseKey: 'clipboard');
    expect(o.drain().map((e) => utf8.decode(e.frame)), ['second', 'third']);
  });

  test('entries without a key never collapse', () {
    final o = Outbox();
    o.add(utf8.encode('a'));
    o.add(utf8.encode('a'));
    expect(o.length, 2);
  });

  test('drops the oldest entry past the frame cap', () {
    final o = Outbox();
    for (var i = 0; i < maxOutboxFrames + 3; i++) {
      o.add(utf8.encode('frame$i'));
    }
    expect(o.length, maxOutboxFrames);
    expect(o.droppedCount, 3);
    final drained = o.drain();
    expect(utf8.decode(drained.first.frame), 'frame3');
  });

  test('drops the oldest entries past the byte cap', () {
    final o = Outbox();
    final oneMeg = Uint8List(1048576);
    for (var i = 0; i < 7; i++) {
      o.add(oneMeg);
    }
    expect(o.byteLength, lessThanOrEqualTo(maxOutboxBytes));
    expect(o.droppedCount, greaterThan(0));
  });

  test('rejects a frame larger than the entire byte cap', () {
    final o = Outbox();
    expect(() => o.add(Uint8List(maxOutboxBytes + 1)),
        throwsA(isA<ArgumentError>()));
  });

  test('clear resets contents but not the dropped counter', () {
    final o = Outbox();
    for (var i = 0; i < maxOutboxFrames + 1; i++) {
      o.add(utf8.encode('f$i'));
    }
    final dropped = o.droppedCount;
    o.clear();
    expect(o.length, 0);
    expect(o.byteLength, 0);
    expect(o.droppedCount, dropped);
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/transport/outbox_test.dart`
Expected: FAIL — `Outbox isn't defined`.

- [ ] **Step 3: Write the implementation**

Create `packages/omnifi_core/lib/src/transport/outbox.dart`:

```dart
import 'dart:collection';
import 'dart:typed_data';

const int maxOutboxFrames = 50;
const int maxOutboxBytes = 5242880;

class OutboxEntry {
  OutboxEntry({required this.frame, this.collapseKey});
  final Uint8List frame;
  final String? collapseKey;
}

/// Per-peer send queue held while a peer is unreachable.
///
/// In-memory only by design: a restart should lose queued clipboard
/// updates rather than deliver yesterday's clipboard on next launch.
class Outbox {
  final ListQueue<OutboxEntry> _entries = ListQueue<OutboxEntry>();
  int _byteLength = 0;
  int _droppedCount = 0;

  int get length => _entries.length;
  int get byteLength => _byteLength;
  int get droppedCount => _droppedCount;

  void add(List<int> frame, {String? collapseKey}) {
    if (frame.length > maxOutboxBytes) {
      throw ArgumentError.value(
          frame.length, 'frame', 'exceeds the entire outbox byte cap');
    }
    final entry = OutboxEntry(
      frame: Uint8List.fromList(frame),
      collapseKey: collapseKey,
    );

    if (collapseKey != null) {
      final existing = _entries.toList();
      final index =
          existing.indexWhere((e) => e.collapseKey == collapseKey);
      if (index >= 0) {
        _byteLength -= existing[index].frame.length;
        existing[index] = entry;
        _byteLength += entry.frame.length;
        _entries
          ..clear()
          ..addAll(existing);
        _enforceBounds(protect: entry);
        return;
      }
    }

    _entries.addLast(entry);
    _byteLength += entry.frame.length;
    _enforceBounds(protect: entry);
  }

  /// Evicts oldest-first until both bounds hold, never evicting [protect].
  ///
  /// [protect] is the entry this call just added or collapsed into. Without
  /// that exemption a large replacement — appended at the tail — could still be
  /// evicted by its own insertion
  /// while older unrelated frames survive. For a clipboard queue that inverts
  /// the point of collapsing: the freshest content is what disappears.
  ///
  /// Termination is guaranteed because [add] rejects any single frame larger
  /// than the whole byte budget, so the protected entry alone always fits.
  void _enforceBounds({OutboxEntry? protect}) {
    while (_entries.length > maxOutboxFrames ||
        _byteLength > maxOutboxBytes) {
      final victimIndex =
          _entries.toList().indexWhere((e) => !identical(e, protect));
      if (victimIndex < 0) break;
      final remaining = _entries.toList()..removeAt(victimIndex);
      final dropped = _entries.toList()[victimIndex];
      _byteLength -= dropped.frame.length;
      _droppedCount++;
      _entries
        ..clear()
        ..addAll(remaining);
    }
  }

  List<OutboxEntry> drain() {
    final out = _entries.toList();
    _entries.clear();
    _byteLength = 0;
    return out;
  }

  void clear() {
    _entries.clear();
    _byteLength = 0;
  }
}
```

- [ ] **Step 4: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/transport/outbox.dart';
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/transport/outbox_test.dart`
Expected: PASS — `+10: All tests passed!`

- [ ] **Step 6: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add bounded outbox with collapsing keys for stale updates"
```

---

## Task 13: `PeerSession` — pair-keyed session with link migration

This is where the spec's "migration happens above the link" requirement is implemented. A session belongs to a **device pair**, not a socket. Swapping the underlying link must not renegotiate crypto, reset counters, or lose queued frames.

**Files:**
- Create: `packages/omnifi_core/lib/src/session/peer_session.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/session/peer_session_test.dart`

**Interfaces:**
- Consumes: `AeadSession` (Task 3), `Envelope`/`encodeEnvelope`/`decodeEnvelope`/`MessageType` (Task 8), `Link`/`LinkState`/`LinkClosedError` (Task 11), `Outbox` (Task 12), `randomHexId` (Task 9).
- Produces:
  - `class PeerSession` with:
    - constructor `PeerSession({required String localDeviceId, required String peerDeviceId, required AeadSession crypto, required int Function() clock})`
    - `void attach(Link link)` — sets or replaces the active link, then flushes the outbox
    - `Link? get link`
    - `Stream<Envelope> get inbound`
    - `Stream<Object> get errors`
    - `Future<void> send(MessageType type, Map<String, Object?> payload, {String? collapseKey})`
    - `bool get isAttached`
    - `int get queuedFrameCount`
    - `Future<void> dispose()`
  - `class SessionRejectedError implements Exception` — raised into `errors` when a frame fails to decrypt; the session marks itself dead and the caller must re-handshake.
  - `bool get isDead`

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/session/peer_session_test.dart`:

```dart
import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

int fixedClock() => 1753200000000;

({PeerSession a, PeerSession b}) sessionPair() {
  final k1 = List<int>.filled(32, 11);
  final k2 = List<int>.filled(32, 22);
  return (
    a: PeerSession(
      localDeviceId: 'a' * 32,
      peerDeviceId: 'b' * 32,
      crypto: AeadSession(sendKey: k1, receiveKey: k2),
      clock: fixedClock,
    ),
    b: PeerSession(
      localDeviceId: 'b' * 32,
      peerDeviceId: 'a' * 32,
      crypto: AeadSession(sendKey: k2, receiveKey: k1),
      clock: fixedClock,
    ),
  );
}

void main() {
  test('delivers a message end to end', () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.a.attach(links.a);
    s.b.attach(links.b);

    final received = s.b.inbound.first;
    await s.a.send(MessageType.clipboardUpdate, {'text': 'hello'});

    final envelope = await received;
    expect(envelope.type, MessageType.clipboardUpdate);
    expect(envelope.senderDeviceId, 'a' * 32);
    expect(envelope.payload['text'], 'hello');
  });

  test('queues while detached and flushes on attach', () async {
    final s = sessionPair();
    await s.a.send(MessageType.heartbeat, const {});
    await s.a.send(MessageType.heartbeat, const {});
    expect(s.a.isAttached, isFalse);
    expect(s.a.queuedFrameCount, 2);

    final links = FakeLink.connectedPair();
    s.b.attach(links.b);
    final seen = <Envelope>[];
    s.b.inbound.listen(seen.add);

    s.a.attach(links.a);
    await Future<void>.delayed(const Duration(milliseconds: 10));
    expect(s.a.queuedFrameCount, 0);
    expect(seen.length, 2);
  });

  test('migrating to a new link preserves counters', () async {
    final s = sessionPair();
    final first = FakeLink.connectedPair();
    s.a.attach(first.a);
    s.b.attach(first.b);
    await s.a.send(MessageType.heartbeat, const {});
    await Future<void>.delayed(const Duration(milliseconds: 10));

    // Swap both ends onto a fresh pair of links, as happens when a LAN
    // path appears while a relay session is live.
    final second = FakeLink.connectedPair();
    s.a.attach(second.a);
    s.b.attach(second.b);

    final received = s.b.inbound.first;
    await s.a.send(MessageType.clipboardUpdate, {'text': 'after migration'});
    expect((await received).payload['text'], 'after migration');
    expect(s.a.isDead, isFalse);
  });

  test('migration does not drop frames queued during the gap', () async {
    final s = sessionPair();
    final first = FakeLink.connectedPair();
    s.a.attach(first.a);
    s.b.attach(first.b);

    first.a.setState(LinkState.disconnected);
    await s.a.send(MessageType.clipboardUpdate, {'text': 'queued'});
    expect(s.a.queuedFrameCount, 1);

    final second = FakeLink.connectedPair();
    s.b.attach(second.b);
    final received = s.b.inbound.first;
    s.a.attach(second.a);

    expect((await received).payload['text'], 'queued');
  });

  test('collapse key replaces a queued message of the same key', () async {
    final s = sessionPair();
    await s.a.send(MessageType.clipboardUpdate, {'text': 'stale'},
        collapseKey: 'clipboard');
    await s.a.send(MessageType.clipboardUpdate, {'text': 'fresh'},
        collapseKey: 'clipboard');
    expect(s.a.queuedFrameCount, 1);

    final links = FakeLink.connectedPair();
    s.b.attach(links.b);
    final received = s.b.inbound.first;
    s.a.attach(links.a);
    expect((await received).payload['text'], 'fresh');
  });

  test('a send failure requeues rather than losing the frame', () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.a.attach(links.a);
    links.a.failNextSend();
    await s.a.send(MessageType.clipboardUpdate, {'text': 'retry me'});
    expect(s.a.queuedFrameCount, 1);
  });

  test('a garbage frame marks the session dead and reports an error',
      () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.b.attach(links.b);

    final error = s.b.errors.first;
    links.b.deliver(List<int>.filled(64, 0xAB));

    expect(await error, isA<SessionRejectedError>());
    expect(s.b.isDead, isTrue);
  });

  test('a dead session refuses further sends', () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.b.attach(links.b);
    s.b.errors.listen((_) {});
    links.b.deliver(List<int>.filled(64, 0xAB));
    await Future<void>.delayed(const Duration(milliseconds: 10));

    expect(() => s.b.send(MessageType.heartbeat, const {}),
        throwsA(isA<SessionRejectedError>()));
  });

  test('rejects a frame whose sender is not the expected peer', () async {
    final s = sessionPair();
    final links = FakeLink.connectedPair();
    s.a.attach(links.a);
    s.b.attach(links.b);

    final impostor = PeerSession(
      localDeviceId: 'c' * 32,
      peerDeviceId: 'b' * 32,
      crypto: AeadSession(
        sendKey: List<int>.filled(32, 11),
        receiveKey: List<int>.filled(32, 22),
      ),
      clock: fixedClock,
    );
    impostor.attach(links.a);

    final error = s.b.errors.first;
    await impostor.send(MessageType.heartbeat, const {});
    expect(await error, isA<SessionRejectedError>());
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/session/peer_session_test.dart`
Expected: FAIL — `PeerSession isn't defined`.

- [ ] **Step 3: Write the implementation**

Create `packages/omnifi_core/lib/src/session/peer_session.dart`:

```dart
import 'dart:async';
import 'dart:typed_data';

import '../crypto/aead_session.dart';
import '../identity/device_identity.dart';
import '../protocol/envelope.dart';
import '../protocol/messages.dart';
import '../transport/link.dart';
import '../transport/outbox.dart';
import '../version.dart';

/// Raised when a frame cannot be authenticated or does not come from the
/// expected peer. The session is dead afterwards: per the spec, a
/// decryption failure forces a fresh handshake rather than a counter resync.
class SessionRejectedError implements Exception {
  const SessionRejectedError(this.reason);
  final String reason;
  @override
  String toString() => 'SessionRejectedError: $reason';
}

/// An established, authenticated channel to exactly one peer device.
///
/// The session is keyed to the device pair, not to a socket. [attach] can
/// be called repeatedly to move the session onto a better link without
/// renegotiating crypto or resetting nonce counters.
class PeerSession {
  PeerSession({
    required this.localDeviceId,
    required this.peerDeviceId,
    required AeadSession crypto,
    required int Function() clock,
  })  : _crypto = crypto,
        _clock = clock;

  final String localDeviceId;
  final String peerDeviceId;
  final AeadSession _crypto;
  final int Function() _clock;

  final Outbox _outbox = Outbox();
  final StreamController<Envelope> _inbound =
      StreamController<Envelope>.broadcast();
  final StreamController<Object> _errors =
      StreamController<Object>.broadcast();

  Link? _link;
  StreamSubscription<Uint8List>? _linkSub;
  bool _dead = false;

  Link? get link => _link;
  Stream<Envelope> get inbound => _inbound.stream;
  Stream<Object> get errors => _errors.stream;
  bool get isAttached => _link?.state == LinkState.connected;
  bool get isDead => _dead;
  int get queuedFrameCount => _outbox.length;

  /// Moves the session onto [link], replacing any current link, then
  /// flushes anything queued while detached.
  void attach(Link link) {
    _linkSub?.cancel();
    _link = link;
    _linkSub = link.inbound.listen(_onFrame, onError: _errors.add);
    unawaited(_flush());
  }

  Future<void> send(
    MessageType type,
    Map<String, Object?> payload, {
    String? collapseKey,
  }) async {
    if (_dead) {
      throw const SessionRejectedError('session is dead; re-handshake first');
    }
    final envelope = Envelope(
      version: omnifiProtocolVersion,
      type: type,
      senderDeviceId: localDeviceId,
      messageId: randomHexId(),
      timestampMs: _clock(),
      payload: payload,
    );
    final sealed = await _crypto.seal(encodeEnvelope(envelope));
    await _dispatch(sealed, collapseKey: collapseKey);
  }

  Future<void> _dispatch(Uint8List frame, {String? collapseKey}) async {
    final link = _link;
    if (link == null || link.state != LinkState.connected) {
      _outbox.add(frame, collapseKey: collapseKey);
      return;
    }
    try {
      await link.send(frame);
    } on Object {
      // The socket died mid-write. Requeue so the frame survives the
      // reconnect rather than vanishing.
      _outbox.add(frame, collapseKey: collapseKey);
    }
  }

  Future<void> _flush() async {
    final link = _link;
    if (link == null || link.state != LinkState.connected) return;
    for (final entry in _outbox.drain()) {
      try {
        await link.send(entry.frame);
      } on Object {
        _outbox.add(entry.frame, collapseKey: entry.collapseKey);
        return;
      }
    }
  }

  Future<void> _onFrame(Uint8List frame) async {
    if (_dead) return;
    final Uint8List plaintext;
    try {
      plaintext = await _crypto.open(frame);
    } on ReplayError catch (e) {
      _fail('replayed frame: $e');
      return;
    } on DecryptionError catch (e) {
      _fail('undecryptable frame: $e');
      return;
    }

    final Envelope envelope;
    try {
      envelope = decodeEnvelope(plaintext);
    } on EnvelopeError catch (e) {
      _fail('malformed envelope: $e');
      return;
    }

    if (envelope.senderDeviceId != peerDeviceId) {
      _fail('frame claims sender ${envelope.senderDeviceId}, '
          'expected $peerDeviceId');
      return;
    }

    _inbound.add(envelope);
  }

  void _fail(String reason) {
    _dead = true;
    _errors.add(SessionRejectedError(reason));
  }

  Future<void> dispose() async {
    await _linkSub?.cancel();
    await _inbound.close();
    await _errors.close();
  }
}
```

- [ ] **Step 4: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/session/peer_session.dart';
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/session/peer_session_test.dart`
Expected: PASS — `+9: All tests passed!`

- [ ] **Step 6: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add pair-keyed PeerSession with link migration and requeue"
```

---

## Task 14: `LinkManager` — racing, heartbeats, and backoff

**Files:**
- Create: `packages/omnifi_core/lib/src/transport/link_manager.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/transport/link_manager_test.dart`

**Interfaces:**
- Consumes: `Link`, `LinkState`, `LinkKind`, `LinkQuality` (Task 11), `PeerSession` (Task 13), `MessageType` (Task 8).
- Produces:
  - `enum ConnectionStatus { connectedDirect, connectedRelay, reconnecting, offline }`
  - `class BackoffPolicy` with `BackoffPolicy({Duration base = const Duration(seconds: 1), Duration cap = const Duration(seconds: 30), double jitter = 0.25, Random? random})` and `Duration delayFor(int attempt)`
  - `class LinkManager` with:
    - constructor `LinkManager({required PeerSession session, required List<Future<Link> Function()> dialers, required int Function() clock, BackoffPolicy? backoff, Duration heartbeatInterval = const Duration(seconds: 15), Duration livenessTimeout = const Duration(seconds: 45)})`
    - `ConnectionStatus get status`, `Stream<ConnectionStatus> get statuses`
    - `Future<void> start()`, `Future<void> stop()`
    - `void offer(Link link)` — a link became available; adopted if it outranks the current one
    - `void onHeartbeatAck(int atMs)`
    - `bool get isLive` — last ack within `livenessTimeout`
    - `Future<void> onWake()` — forces immediate teardown and redial

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/transport/link_manager_test.dart`:

```dart
import 'dart:math';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

int _now = 1753200000000;
int testClock() => _now;

PeerSession newSession() => PeerSession(
      localDeviceId: 'a' * 32,
      peerDeviceId: 'b' * 32,
      crypto: AeadSession(
        sendKey: List<int>.filled(32, 11),
        receiveKey: List<int>.filled(32, 22),
      ),
      clock: testClock,
    );

void main() {
  setUp(() => _now = 1753200000000);

  group('BackoffPolicy', () {
    test('grows exponentially from the base', () {
      final b = BackoffPolicy(jitter: 0, random: Random(1));
      expect(b.delayFor(0), const Duration(seconds: 1));
      expect(b.delayFor(1), const Duration(seconds: 2));
      expect(b.delayFor(2), const Duration(seconds: 4));
      expect(b.delayFor(3), const Duration(seconds: 8));
    });

    test('caps at 30 seconds', () {
      final b = BackoffPolicy(jitter: 0, random: Random(1));
      expect(b.delayFor(20), const Duration(seconds: 30));
    });

    test('jitter stays within the configured fraction', () {
      final b = BackoffPolicy(jitter: 0.25, random: Random(42));
      for (var attempt = 0; attempt < 8; attempt++) {
        final d = b.delayFor(attempt).inMilliseconds;
        final nominal = min(1000 * (1 << attempt), 30000);
        expect(d, greaterThanOrEqualTo((nominal * 0.75).floor()));
        expect(d, lessThanOrEqualTo((nominal * 1.25).ceil()));
      }
    });

    test('never returns a negative delay', () {
      final b = BackoffPolicy(jitter: 0.9, random: Random(7));
      for (var i = 0; i < 20; i++) {
        expect(b.delayFor(i).inMilliseconds, greaterThanOrEqualTo(0));
      }
    });
  });

  group('LinkManager', () {
    test('starts offline before any link connects', () {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      expect(m.status, ConnectionStatus.offline);
    });

    test('reports connectedRelay when only a relay link is offered',
        () async {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'relay', kind: LinkKind.relay));
      expect(m.status, ConnectionStatus.connectedRelay);
    });

    test('adopts a LAN link offered while on relay', () async {
      final session = newSession();
      final m = LinkManager(
        session: session,
        dialers: const [],
        clock: testClock,
      );
      final relay = FakeLink(id: 'relay', kind: LinkKind.relay);
      m.offer(relay);
      expect(m.status, ConnectionStatus.connectedRelay);

      final lan = FakeLink(id: 'lan', kind: LinkKind.lan);
      m.offer(lan);
      expect(m.status, ConnectionStatus.connectedDirect);
      expect(session.link?.id, 'lan');
    });

    test('keeps the LAN link when a relay link is offered afterwards', () {
      final session = newSession();
      final m = LinkManager(
        session: session,
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      m.offer(FakeLink(id: 'relay', kind: LinkKind.relay));
      expect(session.link?.id, 'lan');
      expect(m.status, ConnectionStatus.connectedDirect);
    });

    test('falls back to relay when the LAN link disconnects', () async {
      final session = newSession();
      final m = LinkManager(
        session: session,
        dialers: const [],
        clock: testClock,
      );
      final relay = FakeLink(id: 'relay', kind: LinkKind.relay);
      final lan = FakeLink(id: 'lan', kind: LinkKind.lan);
      m.offer(relay);
      m.offer(lan);
      expect(session.link?.id, 'lan');

      lan.setState(LinkState.disconnected);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      expect(session.link?.id, 'relay');
      expect(m.status, ConnectionStatus.connectedRelay);
    });

    test('emits status transitions', () async {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      final seen = <ConnectionStatus>[];
      m.statuses.listen(seen.add);
      m.offer(FakeLink(id: 'relay', kind: LinkKind.relay));
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      await Future<void>.delayed(Duration.zero);
      expect(seen, [
        ConnectionStatus.connectedRelay,
        ConnectionStatus.connectedDirect,
      ]);
    });

    test('is live immediately after an ack', () {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      m.onHeartbeatAck(_now);
      expect(m.isLive, isTrue);
    });

    test('is not live after the 45 second timeout elapses', () {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      m.onHeartbeatAck(_now);
      _now += 46000;
      expect(m.isLive, isFalse);
    });

    test('is still live at 44 seconds', () {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      m.onHeartbeatAck(_now);
      _now += 44000;
      expect(m.isLive, isTrue);
    });

    test('wake drops the current link and goes to reconnecting', () async {
      final session = newSession();
      final m = LinkManager(
        session: session,
        dialers: [() async => FakeLink(id: 'redial', kind: LinkKind.lan)],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      expect(m.status, ConnectionStatus.connectedDirect);

      await m.onWake();
      // A sleeping socket looks alive and is not, so wake tears down
      // unconditionally rather than waiting out the liveness timeout.
      expect(session.link?.id, isNot('lan'));
    });

    test('stop closes links and reports offline', () async {
      final m = LinkManager(
        session: newSession(),
        dialers: const [],
        clock: testClock,
      );
      m.offer(FakeLink(id: 'lan', kind: LinkKind.lan));
      await m.stop();
      expect(m.status, ConnectionStatus.offline);
    });
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/transport/link_manager_test.dart`
Expected: FAIL — `BackoffPolicy isn't defined`.

- [ ] **Step 3: Write the implementation**

Create `packages/omnifi_core/lib/src/transport/link_manager.dart`:

```dart
import 'dart:async';
import 'dart:math';

import '../session/peer_session.dart';
import 'link.dart';

enum ConnectionStatus {
  connectedDirect,
  connectedRelay,
  reconnecting,
  offline,
}

/// Exponential backoff with proportional jitter, capped per the spec.
class BackoffPolicy {
  BackoffPolicy({
    this.base = const Duration(seconds: 1),
    this.cap = const Duration(seconds: 30),
    this.jitter = 0.25,
    Random? random,
  }) : _random = random ?? Random();

  final Duration base;
  final Duration cap;
  final double jitter;
  final Random _random;

  Duration delayFor(int attempt) {
    final clampedAttempt = attempt.clamp(0, 30);
    final nominalMs = min(
      base.inMilliseconds * (1 << clampedAttempt),
      cap.inMilliseconds,
    );
    if (jitter <= 0) return Duration(milliseconds: nominalMs);
    final spread = nominalMs * jitter;
    final offset = (_random.nextDouble() * 2 - 1) * spread;
    final withJitter = (nominalMs + offset).round();
    return Duration(milliseconds: max(0, withJitter));
  }
}

/// Owns link selection for one peer: races candidate links, prefers the
/// best-ranked one, fails over on disconnect, and redials with backoff.
class LinkManager {
  LinkManager({
    required this.session,
    required List<Future<Link> Function()> dialers,
    required int Function() clock,
    BackoffPolicy? backoff,
    this.heartbeatInterval = const Duration(seconds: 15),
    this.livenessTimeout = const Duration(seconds: 45),
  })  : _dialers = dialers,
        _clock = clock,
        _backoff = backoff ?? BackoffPolicy();

  final PeerSession session;
  final List<Future<Link> Function()> _dialers;
  final int Function() _clock;
  final BackoffPolicy _backoff;
  final Duration heartbeatInterval;
  final Duration livenessTimeout;

  final Map<String, Link> _candidates = {};
  final Map<String, StreamSubscription<LinkState>> _stateSubs = {};
  final StreamController<ConnectionStatus> _statuses =
      StreamController<ConnectionStatus>.broadcast();

  ConnectionStatus _status = ConnectionStatus.offline;
  Link? _active;
  int? _lastAckMs;
  int _attempt = 0;
  bool _running = false;

  ConnectionStatus get status => _status;
  Stream<ConnectionStatus> get statuses => _statuses.stream;

  bool get isLive {
    final last = _lastAckMs;
    if (last == null) return false;
    return _clock() - last <= livenessTimeout.inMilliseconds;
  }

  Future<void> start() async {
    _running = true;
    await _dialAll();
  }

  Future<void> _dialAll() async {
    for (final dial in _dialers) {
      unawaited(dial().then(offer).catchError((Object _) {
        _attempt++;
      }));
    }
  }

  /// Registers a newly available link. Adopted only if it outranks the
  /// active one, so a relay appearing later never displaces a live LAN path.
  void offer(Link link) {
    _candidates[link.id] = link;
    _stateSubs[link.id]?.cancel();
    _stateSubs[link.id] = link.states.listen((s) {
      if (s == LinkState.disconnected || s == LinkState.failed) {
        _candidates.remove(link.id);
        _stateSubs.remove(link.id)?.cancel();
        if (_active?.id == link.id) {
          _active = null;
          _selectBest();
        }
      }
    });
    _selectBest();
  }

  void _selectBest() {
    final usable = _candidates.values
        .where((l) => l.state == LinkState.connected)
        .toList()
      ..sort((a, b) =>
          a.quality.preferenceScore.compareTo(b.quality.preferenceScore));

    if (usable.isEmpty) {
      _active = null;
      _setStatus(_running
          ? ConnectionStatus.reconnecting
          : ConnectionStatus.offline);
      return;
    }

    final best = usable.first;
    if (_active?.id != best.id) {
      _active = best;
      session.attach(best);
      _attempt = 0;
      _lastAckMs = _clock();
    }
    _setStatus(best.quality.isDirect
        ? ConnectionStatus.connectedDirect
        : ConnectionStatus.connectedRelay);
  }

  void _setStatus(ConnectionStatus next) {
    if (_status == next) return;
    _status = next;
    _statuses.add(next);
  }

  void onHeartbeatAck(int atMs) => _lastAckMs = atMs;

  /// Sleep suspends sockets without telling the peer, so on wake we tear
  /// down unconditionally instead of waiting out the liveness timeout.
  Future<void> onWake() async {
    for (final link in _candidates.values.toList()) {
      await link.close();
    }
    _candidates.clear();
    for (final sub in _stateSubs.values) {
      await sub.cancel();
    }
    _stateSubs.clear();
    _active = null;
    _lastAckMs = null;
    _setStatus(ConnectionStatus.reconnecting);
    if (_running) await _dialAll();
  }

  Duration nextRetryDelay() => _backoff.delayFor(_attempt);

  Future<void> stop() async {
    _running = false;
    for (final sub in _stateSubs.values) {
      await sub.cancel();
    }
    _stateSubs.clear();
    for (final link in _candidates.values.toList()) {
      await link.close();
    }
    _candidates.clear();
    _active = null;
    _setStatus(ConnectionStatus.offline);
  }
}
```

- [ ] **Step 4: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/transport/link_manager.dart';
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/transport/link_manager_test.dart`
Expected: PASS — `+16: All tests passed!`

- [ ] **Step 6: Run the whole suite**

Run: `cd packages/omnifi_core && dart test`
Expected: PASS.

- [ ] **Step 7: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add LinkManager with LAN preference, failover and backoff"
```

---

## Task 15: Pairing payload codec

**Files:**
- Create: `packages/omnifi_core/lib/src/pairing/pairing_payload.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/pairing/pairing_payload_test.dart`

**Interfaces:**
- Consumes: `omnifiWordlist` (Task 6), `randomHexId` (Task 9).
- Produces:
  - `class PairingInvite { final String meshId; final List<int> inviterPublicKey; final List<int> psk; final String? relayHint; }`
  - `String encodeInviteUri(PairingInvite invite)` — `omnifi://pair?m=<hex>&k=<base64url>&p=<base64url>&r=<uri-encoded>`, for the QR code.
  - `PairingInvite decodeInviteUri(String uri)` — throws `PairingError` on any malformation.
  - `List<String> encodeInviteWords(PairingInvite invite)` — 8 words, the desktop fallback for machines without a camera.
  - `PairingInvite decodeInviteWords(List<String> words, {required PairingInvite Function(String) lookup})` — see note below.
  - `PairingInvite generateInvite({required String meshId, required List<int> inviterPublicKey, String? relayHint})` — generates a fresh 32-byte PSK.
  - `class PairingError implements Exception`

**Note on the word fallback:** eight words from a 256-word list carry 64 bits, which is not enough to transport a 32-byte PSK plus a 32-byte public key. The word phrase is therefore a *lookup code*, not a self-contained invite: it identifies a pending invite held by the inviting device, which serves the full payload over the relay. `encodeInviteWords` derives the code from the PSK; `decodeInviteWords` takes a `lookup` callback that the caller wires to the relay fetch. This is why the signature differs from the URI form.

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/pairing/pairing_payload_test.dart`:

```dart
import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

PairingInvite sample() => PairingInvite(
      meshId: 'a' * 32,
      inviterPublicKey: List<int>.filled(32, 3),
      psk: List<int>.filled(32, 9),
      relayHint: 'wss://relay.example.com',
    );

void main() {
  test('generates an invite with a fresh 32-byte psk', () {
    final a = generateInvite(
        meshId: 'a' * 32, inviterPublicKey: List<int>.filled(32, 1));
    final b = generateInvite(
        meshId: 'a' * 32, inviterPublicKey: List<int>.filled(32, 1));
    expect(a.psk.length, 32);
    expect(a.psk, isNot(equals(b.psk)));
  });

  test('uri round-trips every field', () {
    final back = decodeInviteUri(encodeInviteUri(sample()));
    expect(back.meshId, 'a' * 32);
    expect(back.inviterPublicKey, List<int>.filled(32, 3));
    expect(back.psk, List<int>.filled(32, 9));
    expect(back.relayHint, 'wss://relay.example.com');
  });

  test('uri round-trips without a relay hint', () {
    final invite = PairingInvite(
      meshId: 'b' * 32,
      inviterPublicKey: List<int>.filled(32, 4),
      psk: List<int>.filled(32, 5),
    );
    expect(decodeInviteUri(encodeInviteUri(invite)).relayHint, isNull);
  });

  test('uri uses the omnifi pair scheme', () {
    expect(encodeInviteUri(sample()), startsWith('omnifi://pair?'));
  });

  test('rejects a wrong scheme', () {
    expect(() => decodeInviteUri('https://example.com/pair?m=x'),
        throwsA(isA<PairingError>()));
  });

  test('rejects a missing mesh id', () {
    expect(() => decodeInviteUri('omnifi://pair?k=AAAA&p=AAAA'),
        throwsA(isA<PairingError>()));
  });

  test('rejects a malformed mesh id', () {
    expect(
      () => decodeInviteUri('omnifi://pair?m=NOTHEX&k=AAAA&p=AAAA'),
      throwsA(isA<PairingError>()),
    );
  });

  test('rejects a wrong-length public key', () {
    final bad = encodeInviteUri(sample()).replaceAll(
        RegExp(r'k=[^&]*'), 'k=AAAA');
    expect(() => decodeInviteUri(bad), throwsA(isA<PairingError>()));
  });

  test('rejects unparseable text', () {
    expect(() => decodeInviteUri('not a uri at all %%%'),
        throwsA(isA<PairingError>()));
  });

  test('word code is 8 words from the wordlist', () {
    final words = encodeInviteWords(sample());
    expect(words.length, 8);
    for (final w in words) {
      expect(omnifiWordlist, contains(w));
    }
  });

  test('word code is deterministic for the same psk', () {
    expect(encodeInviteWords(sample()), encodeInviteWords(sample()));
  });

  test('word code differs for a different psk', () {
    final other = PairingInvite(
      meshId: 'a' * 32,
      inviterPublicKey: List<int>.filled(32, 3),
      psk: List<int>.filled(32, 10),
    );
    expect(encodeInviteWords(other), isNot(encodeInviteWords(sample())));
  });

  test('word decode resolves through the lookup callback', () {
    final invite = sample();
    final words = encodeInviteWords(invite);
    final resolved = decodeInviteWords(
      words,
      lookup: (code) {
        expect(code, words.join('-'));
        return invite;
      },
    );
    expect(resolved.meshId, invite.meshId);
  });

  test('word decode rejects a word outside the list', () {
    expect(
      () => decodeInviteWords(
        ['able', 'brisk', 'cedar', 'delta', 'eagle', 'fable', 'ghost',
          'zzzzzz'],
        lookup: (_) => sample(),
      ),
      throwsA(isA<PairingError>()),
    );
  });

  test('word decode rejects the wrong word count', () {
    expect(
      () => decodeInviteWords(['able', 'brisk'], lookup: (_) => sample()),
      throwsA(isA<PairingError>()),
    );
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/pairing/pairing_payload_test.dart`
Expected: FAIL — `PairingInvite isn't defined`.

- [ ] **Step 3: Write the implementation**

Create `packages/omnifi_core/lib/src/pairing/pairing_payload.dart`:

```dart
import 'dart:convert';
import 'dart:math';

import '../crypto/wordlist.dart';

class PairingError implements Exception {
  const PairingError(this.reason);
  final String reason;
  @override
  String toString() => 'PairingError: $reason';
}

class PairingInvite {
  PairingInvite({
    required this.meshId,
    required this.inviterPublicKey,
    required this.psk,
    this.relayHint,
  }) {
    if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(meshId)) {
      throw const PairingError('mesh id must be 32 lowercase hex characters');
    }
    if (inviterPublicKey.length != 32) {
      throw const PairingError('inviter public key must be 32 bytes');
    }
    if (psk.length != 32) {
      throw const PairingError('psk must be 32 bytes');
    }
  }

  final String meshId;
  final List<int> inviterPublicKey;
  final List<int> psk;
  final String? relayHint;
}

final Random _rng = Random.secure();

PairingInvite generateInvite({
  required String meshId,
  required List<int> inviterPublicKey,
  String? relayHint,
}) {
  return PairingInvite(
    meshId: meshId,
    inviterPublicKey: inviterPublicKey,
    psk: [for (var i = 0; i < 32; i++) _rng.nextInt(256)],
    relayHint: relayHint,
  );
}

String encodeInviteUri(PairingInvite invite) {
  final params = <String, String>{
    'm': invite.meshId,
    'k': base64UrlEncode(invite.inviterPublicKey),
    'p': base64UrlEncode(invite.psk),
    if (invite.relayHint != null) 'r': invite.relayHint!,
  };
  final query = params.entries
      .map((e) =>
          '${e.key}=${Uri.encodeQueryComponent(e.value)}')
      .join('&');
  return 'omnifi://pair?$query';
}

PairingInvite decodeInviteUri(String uri) {
  final Uri parsed;
  try {
    parsed = Uri.parse(uri);
  } on FormatException {
    throw const PairingError('invite is not a parseable URI');
  }
  if (parsed.scheme != 'omnifi' || parsed.host != 'pair') {
    throw const PairingError('invite is not an omnifi://pair URI');
  }

  final meshId = parsed.queryParameters['m'];
  final key = parsed.queryParameters['k'];
  final psk = parsed.queryParameters['p'];
  if (meshId == null || key == null || psk == null) {
    throw const PairingError('invite is missing a required parameter');
  }

  List<int> decode(String value, String label) {
    try {
      return base64Url.decode(base64Url.normalize(value));
    } on FormatException {
      throw PairingError('$label is not valid base64url');
    }
  }

  return PairingInvite(
    meshId: meshId,
    inviterPublicKey: decode(key, 'public key'),
    psk: decode(psk, 'psk'),
    relayHint: parsed.queryParameters['r'],
  );
}

/// Eight words derived from the PSK. This is a *lookup code*, not a
/// self-contained invite: 64 bits cannot carry a 32-byte PSK plus a
/// 32-byte key. The inviting device serves the full payload against it.
List<String> encodeInviteWords(PairingInvite invite) =>
    [for (var i = 0; i < 8; i++) omnifiWordlist[invite.psk[i]]];

PairingInvite decodeInviteWords(
  List<String> words, {
  required PairingInvite Function(String code) lookup,
}) {
  if (words.length != 8) {
    throw const PairingError('pairing phrase must be exactly 8 words');
  }
  for (final w in words) {
    if (!omnifiWordlist.contains(w)) {
      throw PairingError('unknown pairing word: $w');
    }
  }
  return lookup(words.join('-'));
}
```

- [ ] **Step 4: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/pairing/pairing_payload.dart';
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/pairing/pairing_payload_test.dart`
Expected: PASS — `+15: All tests passed!`

- [ ] **Step 6: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add pairing invite URI and word-phrase codecs"
```

---

## Task 16: Pairing flow with SAS confirmation

**Files:**
- Create: `packages/omnifi_core/lib/src/pairing/pairing_flow.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/pairing/pairing_flow_test.dart`

**Interfaces:**
- Consumes: `OmniFiHandshakeV1`, `StaticKeyPair`, `HandshakeError` (Task 4), `deriveSas` (Task 6), `DeviceIdentity` (Task 9), `Mesh`, `PeerRecord` (Task 10), `PairingInvite` (Task 15), `Link` (Task 11), `AeadSession` (Task 3).
- Produces:
  - `class PairingSasPending { final List<String> sas; final Future<PairingOutcome> Function(bool userConfirmed) confirm; }`
  - `class PairingOutcome { final PeerRecord peer; final AeadSession session; final String meshId; }`
  - `class PairingFlow` with:
    - `static Future<PairingSasPending> invite({required DeviceIdentity identity, required Mesh mesh, required PairingInvite invite, required Link link})`
    - `static Future<PairingSasPending> join({required DeviceIdentity identity, required PairingInvite invite, required Link link})`
  - `class PairingRejectedError implements Exception` — thrown from `confirm(false)` or on a handshake failure.

Both sides derive the SAS from the handshake master and both static public keys. The user compares the two screens. `confirm(false)` aborts and no roster change occurs.

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/pairing/pairing_flow_test.dart`:

```dart
import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

Future<DeviceIdentity> identity(String name) =>
    loadOrCreateIdentity(store: InMemorySecureStore(), displayName: name);

void main() {
  test('both sides derive the same SAS', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();

    final invite = generateInvite(
      meshId: mesh.meshId,
      inviterPublicKey: inviter.keys.publicKey,
    );

    final invitePending = PairingFlow.invite(
      identity: inviter, mesh: mesh, invite: invite, link: links.a);
    final joinPending = PairingFlow.join(
      identity: joiner, invite: invite, link: links.b);

    final a = await invitePending;
    final b = await joinPending;

    expect(a.sas.length, 5);
    expect(a.sas, b.sas);
  });

  test('confirming on both sides yields matching sessions', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();
    final invite = generateInvite(
      meshId: mesh.meshId, inviterPublicKey: inviter.keys.publicKey);

    final a = await PairingFlow.invite(
      identity: inviter, mesh: mesh, invite: invite, link: links.a);
    final b = await PairingFlow.join(
      identity: joiner, invite: invite, link: links.b);

    final outA = await a.confirm(true);
    final outB = await b.confirm(true);

    expect(outA.peer.deviceId, joiner.deviceId);
    expect(outB.peer.deviceId, inviter.deviceId);
    expect(outB.meshId, mesh.meshId);

    final sealed = await outA.session.seal([1, 2, 3]);
    expect(await outB.session.open(sealed), [1, 2, 3]);
  });

  test('the inviter adds the joiner to the roster on confirm', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();
    final invite = generateInvite(
      meshId: mesh.meshId, inviterPublicKey: inviter.keys.publicKey);

    final a = await PairingFlow.invite(
      identity: inviter, mesh: mesh, invite: invite, link: links.a);
    final b = await PairingFlow.join(
      identity: joiner, invite: invite, link: links.b);

    final outA = await a.confirm(true);
    await b.confirm(true);

    mesh.addPeer(outA.peer);
    expect(mesh.isAuthorized(joiner.deviceId, joiner.keys.publicKey), isTrue);
  });

  test('declining the SAS rejects the pairing', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();
    final invite = generateInvite(
      meshId: mesh.meshId, inviterPublicKey: inviter.keys.publicKey);

    final a = await PairingFlow.invite(
      identity: inviter, mesh: mesh, invite: invite, link: links.a);
    final b = await PairingFlow.join(
      identity: joiner, invite: invite, link: links.b);
    unawaited(b.confirm(true).catchError((Object _) => throw StateError('x')));

    expect(() => a.confirm(false), throwsA(isA<PairingRejectedError>()));
    expect(mesh.peers, isEmpty);
  });

  test('a wrong PSK produces a different SAS on each side', () async {
    final inviter = await identity('Mac');
    final joiner = await identity('PC');
    final mesh = Mesh(meshId: 'a' * 32);
    final links = FakeLink.connectedPair();

    final realInvite = generateInvite(
      meshId: mesh.meshId, inviterPublicKey: inviter.keys.publicKey);
    final wrongPskInvite = PairingInvite(
      meshId: realInvite.meshId,
      inviterPublicKey: realInvite.inviterPublicKey,
      psk: List<int>.filled(32, 0xFF),
    );

    final a = await PairingFlow.invite(
      identity: inviter, mesh: mesh, invite: realInvite, link: links.a);
    final b = await PairingFlow.join(
      identity: joiner, invite: wrongPskInvite, link: links.b);

    // This is exactly what the user is asked to catch: the two screens
    // disagree, so the pairing is a man-in-the-middle or a mistyped code.
    expect(a.sas, isNot(b.sas));
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/pairing/pairing_flow_test.dart`
Expected: FAIL — `PairingFlow isn't defined`.

- [ ] **Step 3: Write the implementation**

Create `packages/omnifi_core/lib/src/pairing/pairing_flow.dart`:

```dart
import 'dart:async';
import 'dart:typed_data';

import '../crypto/aead_session.dart';
import '../crypto/handshake.dart';
import '../crypto/sas.dart';
import '../identity/device_identity.dart';
import '../identity/mesh.dart';
import '../transport/link.dart';
import 'pairing_payload.dart';

class PairingRejectedError implements Exception {
  const PairingRejectedError(this.reason);
  final String reason;
  @override
  String toString() => 'PairingRejectedError: $reason';
}

class PairingOutcome {
  const PairingOutcome({
    required this.peer,
    required this.session,
    required this.meshId,
  });
  final PeerRecord peer;
  final AeadSession session;
  final String meshId;
}

/// A completed handshake awaiting the user's SAS comparison.
class PairingSasPending {
  const PairingSasPending({required this.sas, required this.confirm});
  final List<String> sas;
  final Future<PairingOutcome> Function(bool userConfirmed) confirm;
}

class PairingFlow {
  /// Runs the inviting side. The inviter does not yet know the joiner's
  /// static key, so the PSK from the invite carries the authentication.
  static Future<PairingSasPending> invite({
    required DeviceIdentity identity,
    required Mesh mesh,
    required PairingInvite invite,
    required Link link,
  }) =>
      _run(
        identity: identity,
        invite: invite,
        link: link,
        meshId: mesh.meshId,
        isInitiator: true,
      );

  /// Runs the joining side, using the invite scanned from the QR code.
  static Future<PairingSasPending> join({
    required DeviceIdentity identity,
    required PairingInvite invite,
    required Link link,
  }) =>
      _run(
        identity: identity,
        invite: invite,
        link: link,
        meshId: invite.meshId,
        isInitiator: false,
      );

  static Future<PairingSasPending> _run({
    required DeviceIdentity identity,
    required PairingInvite invite,
    required Link link,
    required String meshId,
    required bool isInitiator,
  }) async {
    // Neither side knows the other's static key yet — that is what pairing
    // establishes — so `expectedPeerStaticPublicKey` is null and each side
    // LEARNS the peer's key from the handshake message. Authentication comes
    // from the PSK in the QR invite (mixed into the HKDF salt) plus the SAS
    // the user compares below. A mismatched PSK changes the master secret,
    // which changes the SAS, which the user sees.
    final handshake = isInitiator
        ? OmniFiHandshakeV1.initiator(
            staticKeys: identity.keys,
            deviceId: identity.deviceId,
            psk: invite.psk,
          )
        : OmniFiHandshakeV1.responder(
            staticKeys: identity.keys,
            deviceId: identity.deviceId,
            psk: invite.psk,
          );

    final ownMessage = await handshake.start();
    final peerMessageFuture = link.inbound.first;
    await link.send(ownMessage);
    final peerMessage = await peerMessageFuture;

    final ownConfirmation = await handshake.confirmationFor(peerMessage);
    final peerConfirmationFuture = link.inbound.first;
    await link.send(ownConfirmation);
    final peerConfirmation = await peerConfirmationFuture;

    final HandshakeResult result;
    try {
      result = await handshake.complete(peerMessage, peerConfirmation);
    } on HandshakeError catch (e) {
      throw PairingRejectedError('handshake failed: ${e.reason}');
    }

    final sas = await deriveSas(
      master: result.master,
      initiatorStaticPublicKey:
          isInitiator ? identity.keys.publicKey : result.peerStaticPublicKey,
      responderStaticPublicKey:
          isInitiator ? result.peerStaticPublicKey : identity.keys.publicKey,
    );

    final peerDeviceId = _peerDeviceIdFrom(peerMessage);

    return PairingSasPending(
      sas: sas,
      confirm: (userConfirmed) async {
        if (!userConfirmed) {
          throw const PairingRejectedError(
              'user reported the authentication words did not match');
        }
        return PairingOutcome(
          peer: PeerRecord(
            deviceId: peerDeviceId,
            publicKey: result.peerStaticPublicKey,
            displayName: peerDeviceId.substring(0, 8),
            addedAtMs: DateTime.now().millisecondsSinceEpoch,
          ),
          session: result.session,
          meshId: meshId,
        );
      },
    );
  }

  static String _peerDeviceIdFrom(Uint8List peerMessage) {
    // The handshake message is CBOR {v, id, e}; reuse the same decode path
    // the handshake uses so a malformed message fails identically.
    return OmniFiHandshakeV1.deviceIdFromMessage(peerMessage);
  }
}
```

- [ ] **Step 4: Add the device-ID accessor the flow needs**

Modify `packages/omnifi_core/lib/src/crypto/handshake.dart` — add this static method inside `OmniFiHandshakeV1`, directly below `generateStaticKeys`:

```dart
  /// Extracts the sender's device ID from a handshake message.
  static String deviceIdFromMessage(List<int> message) {
    final Object? decoded;
    try {
      decoded = cbor.decode(message).toObject();
    } catch (_) {
      throw const HandshakeError('handshake message is not valid CBOR');
    }
    if (decoded is! Map) {
      throw const HandshakeError('handshake message is not a map');
    }
    final id = decoded['id'];
    if (id is! String || id.isEmpty) {
      throw const HandshakeError('handshake message has no device id');
    }
    return id;
  }
```

- [ ] **Step 5: Export the flow**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/pairing/pairing_flow.dart';
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/pairing/pairing_flow_test.dart`
Expected: PASS — `+5: All tests passed!`

- [ ] **Step 7: Run the whole suite**

Run: `cd packages/omnifi_core && dart test`
Expected: PASS.

- [ ] **Step 8: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add pairing flow with mandatory SAS confirmation"
```

---

## Task 17: Clipboard sync engine

**Files:**
- Create: `packages/omnifi_core/lib/src/sync/clipboard_watcher.dart`
- Create: `packages/omnifi_core/lib/src/sync/clipboard_sync.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/sync/clipboard_sync_test.dart`

**Interfaces:**
- Consumes: `PeerSession` (Task 13), `ClipboardPayload`, `MessageType`, `Envelope` (Task 8).
- Produces:
  - `class ClipboardContent { final String format; final Uint8List data; final bool isConcealed; }`
  - `abstract interface class ClipboardWatcher` with `Stream<ClipboardContent> get changes`, `Future<void> write(ClipboardContent content)`, `Future<void> start()`, `Future<void> stop()`
  - `class FakeClipboardWatcher implements ClipboardWatcher` — exported from the library (not test-only) so integration harnesses and the app's headless tests can use it.
  - `const int maxClipboardBytes = 1048576`
  - `String clipboardHash(String format, List<int> data)` — SHA-256 hex.
  - `class ClipboardSync` with:
    - constructor `ClipboardSync({required ClipboardWatcher watcher, required List<PeerSession> Function() peers, required int Function() clock})`
    - `Future<void> start()` / `Future<void> stop()`
    - `void setPaused(bool paused)` / `bool get isPaused`
    - `void onScreenLocked()` / `void onScreenUnlocked()`
    - `Future<void> handleIncoming(Envelope envelope)`
    - `String? get lastAppliedHash`
    - `int get skippedConcealedCount`, `int get skippedOversizedCount`

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/sync/clipboard_sync_test.dart`:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

int _now = 1753200000000;
int testClock() => _now;

ClipboardContent text(String s, {bool concealed = false}) => ClipboardContent(
      format: 'text',
      data: Uint8List.fromList(utf8.encode(s)),
      isConcealed: concealed,
    );

({PeerSession local, PeerSession remote}) linkedSessions() {
  final k1 = List<int>.filled(32, 11);
  final k2 = List<int>.filled(32, 22);
  final local = PeerSession(
    localDeviceId: 'a' * 32,
    peerDeviceId: 'b' * 32,
    crypto: AeadSession(sendKey: k1, receiveKey: k2),
    clock: testClock,
  );
  final remote = PeerSession(
    localDeviceId: 'b' * 32,
    peerDeviceId: 'a' * 32,
    crypto: AeadSession(sendKey: k2, receiveKey: k1),
    clock: testClock,
  );
  final links = FakeLink.connectedPair();
  local.attach(links.a);
  remote.attach(links.b);
  return (local: local, remote: remote);
}

void main() {
  setUp(() => _now = 1753200000000);

  test('hash is stable and format-sensitive', () {
    expect(clipboardHash('text', utf8.encode('x')),
        clipboardHash('text', utf8.encode('x')));
    expect(clipboardHash('text', utf8.encode('x')),
        isNot(clipboardHash('png', utf8.encode('x'))));
  });

  test('broadcasts a local copy to peers', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    final received = s.remote.inbound.first;
    watcher.emit(text('copied on mac'));

    final envelope = await received;
    expect(envelope.type, MessageType.clipboardUpdate);
    final payload = ClipboardPayload.fromMap(envelope.payload);
    expect(utf8.decode(payload.data), 'copied on mac');
  });

  test('applies an incoming update to the local clipboard', () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();

    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: ClipboardPayload(
        format: 'text',
        data: Uint8List.fromList(utf8.encode('from pc')),
        timestampMs: _now,
        contentHash: clipboardHash('text', utf8.encode('from pc')),
      ).toMap(),
    ));

    expect(utf8.decode(watcher.current!.data), 'from pc');
  });

  test('does not echo content it just applied', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    final incoming = text('round trip');
    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: ClipboardPayload(
        format: 'text',
        data: incoming.data,
        timestampMs: _now,
        contentHash: clipboardHash('text', incoming.data),
      ).toMap(),
    ));

    // The platform watcher now fires for our own write. Without loop
    // prevention this is where two machines ping-pong forever.
    var broadcasts = 0;
    s.remote.inbound.listen((_) => broadcasts++);
    watcher.emit(incoming);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(broadcasts, 0);
  });

  test('a genuinely new copy after an applied one still broadcasts',
      () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: ClipboardPayload(
        format: 'text',
        data: Uint8List.fromList(utf8.encode('applied')),
        timestampMs: _now,
        contentHash: clipboardHash('text', utf8.encode('applied')),
      ).toMap(),
    ));
    watcher.emit(text('applied'));

    final received = s.remote.inbound.first;
    watcher.emit(text('genuinely new'));
    final payload = ClipboardPayload.fromMap((await received).payload);
    expect(utf8.decode(payload.data), 'genuinely new');
  });

  test('skips concealed content from a password manager', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    var broadcasts = 0;
    s.remote.inbound.listen((_) => broadcasts++);
    watcher.emit(text('hunter2', concealed: true));
    await Future<void>.delayed(const Duration(milliseconds: 20));

    expect(broadcasts, 0);
    expect(sync.skippedConcealedCount, 1);
  });

  test('sends a too-large marker instead of an oversized payload', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    final received = s.remote.inbound.first;
    watcher.emit(ClipboardContent(
      format: 'text',
      data: Uint8List(maxClipboardBytes + 1),
      isConcealed: false,
    ));

    expect((await received).type, MessageType.clipboardTooLarge);
    expect(sync.skippedOversizedCount, 1);
  });

  test('pausing stops outgoing broadcasts', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();
    sync.setPaused(true);

    var broadcasts = 0;
    s.remote.inbound.listen((_) => broadcasts++);
    watcher.emit(text('while paused'));
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(broadcasts, 0);
  });

  test('screen lock pauses and unlock resumes', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    sync.onScreenLocked();
    expect(sync.isPaused, isTrue);
    sync.onScreenUnlocked();
    expect(sync.isPaused, isFalse);

    final received = s.remote.inbound.first;
    watcher.emit(text('after unlock'));
    expect(
      utf8.decode(ClipboardPayload.fromMap((await received).payload).data),
      'after unlock',
    );
  });

  test('an explicit pause survives an unlock', () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();
    sync.setPaused(true);
    sync.onScreenLocked();
    sync.onScreenUnlocked();
    expect(sync.isPaused, isTrue,
        reason: 'unlocking must not override a deliberate user pause');
  });

  test('an older incoming update loses to a newer applied one', () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();

    Envelope at(int ts, String body) => Envelope(
          version: omnifiProtocolVersion,
          type: MessageType.clipboardUpdate,
          senderDeviceId: 'b' * 32,
          messageId: 'm' * 32,
          timestampMs: ts,
          payload: ClipboardPayload(
            format: 'text',
            data: Uint8List.fromList(utf8.encode(body)),
            timestampMs: ts,
            contentHash: clipboardHash('text', utf8.encode(body)),
          ).toMap(),
        );

    await sync.handleIncoming(at(_now + 1000, 'newer'));
    await sync.handleIncoming(at(_now, 'older'));
    expect(utf8.decode(watcher.current!.data), 'newer');
  });

  test('ignores a message type it does not handle', () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();
    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.heartbeat,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: const {},
    ));
    expect(watcher.current, isNull);
  });
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/sync/clipboard_sync_test.dart`
Expected: FAIL — `ClipboardContent isn't defined`.

- [ ] **Step 3: Write the watcher interface and fake**

Create `packages/omnifi_core/lib/src/sync/clipboard_watcher.dart`:

```dart
import 'dart:async';
import 'dart:typed_data';

class ClipboardContent {
  ClipboardContent({
    required this.format,
    required this.data,
    required this.isConcealed,
  });

  /// One of the values in `supportedClipboardFormats`.
  final String format;
  final Uint8List data;

  /// True when the source marked the content as transient/secret, e.g.
  /// macOS `org.nspasteboard.ConcealedType` or the Windows
  /// `ExcludeClipboardContentFromMonitorProcessing` format.
  final bool isConcealed;
}

/// Platform clipboard access. Implementations live in the Flutter app.
abstract interface class ClipboardWatcher {
  Stream<ClipboardContent> get changes;
  Future<void> write(ClipboardContent content);
  Future<void> start();
  Future<void> stop();
}

/// Headless watcher for tests and integration harnesses.
class FakeClipboardWatcher implements ClipboardWatcher {
  final StreamController<ClipboardContent> _changes =
      StreamController<ClipboardContent>.broadcast();

  ClipboardContent? current;

  @override
  Stream<ClipboardContent> get changes => _changes.stream;

  /// Simulates the platform reporting a clipboard change.
  void emit(ClipboardContent content) {
    current = content;
    _changes.add(content);
  }

  @override
  Future<void> write(ClipboardContent content) async {
    current = content;
  }

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {
    await _changes.close();
  }
}
```

- [ ] **Step 4: Write the sync engine**

Create `packages/omnifi_core/lib/src/sync/clipboard_sync.dart`:

```dart
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../protocol/envelope.dart';
import '../protocol/messages.dart';
import '../session/peer_session.dart';
import 'clipboard_watcher.dart';

const int maxClipboardBytes = 1048576;

const String _clipboardCollapseKey = 'clipboard';

String clipboardHash(String format, List<int> data) {
  final digest = Sha256().toSync().hashSync([...utf8.encode(format), 0, ...data]);
  return digest.bytes
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
}

/// Bridges the platform clipboard to peer sessions.
class ClipboardSync {
  ClipboardSync({
    required ClipboardWatcher watcher,
    required List<PeerSession> Function() peers,
    required int Function() clock,
  })  : _watcher = watcher,
        _peers = peers,
        _clock = clock;

  final ClipboardWatcher _watcher;
  final List<PeerSession> Function() _peers;
  final int Function() _clock;

  StreamSubscription<ClipboardContent>? _sub;
  String? _lastAppliedHash;
  int _lastAppliedTimestampMs = 0;
  bool _userPaused = false;
  bool _lockPaused = false;
  int _skippedConcealedCount = 0;
  int _skippedOversizedCount = 0;

  String? get lastAppliedHash => _lastAppliedHash;
  bool get isPaused => _userPaused || _lockPaused;
  int get skippedConcealedCount => _skippedConcealedCount;
  int get skippedOversizedCount => _skippedOversizedCount;

  Future<void> start() async {
    await _watcher.start();
    _sub = _watcher.changes.listen(_onLocalChange);
  }

  Future<void> stop() async {
    await _sub?.cancel();
    await _watcher.stop();
  }

  void setPaused(bool paused) => _userPaused = paused;

  void onScreenLocked() => _lockPaused = true;

  /// Clears only the lock-induced pause. A deliberate user pause survives.
  void onScreenUnlocked() => _lockPaused = false;

  Future<void> _onLocalChange(ClipboardContent content) async {
    if (isPaused) return;

    if (content.isConcealed) {
      _skippedConcealedCount++;
      return;
    }

    final hash = clipboardHash(content.format, content.data);
    if (hash == _lastAppliedHash) {
      // Our own write echoing back through the platform watcher. Dropping
      // this is what stops two machines ping-ponging forever.
      return;
    }

    final now = _clock();

    if (content.data.length > maxClipboardBytes) {
      _skippedOversizedCount++;
      await _broadcast(MessageType.clipboardTooLarge, {
        'format': content.format,
        'bytes': content.data.length,
        'limit': maxClipboardBytes,
      });
      return;
    }

    _lastAppliedHash = hash;
    _lastAppliedTimestampMs = now;

    await _broadcast(
      MessageType.clipboardUpdate,
      ClipboardPayload(
        format: content.format,
        data: content.data,
        timestampMs: now,
        contentHash: hash,
      ).toMap(),
      collapseKey: _clipboardCollapseKey,
    );
  }

  Future<void> _broadcast(
    MessageType type,
    Map<String, Object?> payload, {
    String? collapseKey,
  }) async {
    for (final peer in _peers()) {
      if (peer.isDead) continue;
      try {
        await peer.send(type, payload, collapseKey: collapseKey);
      } on SessionRejectedError {
        // A dead session is the LinkManager's problem, not ours; skip it
        // rather than aborting delivery to healthy peers.
        continue;
      }
    }
  }

  Future<void> handleIncoming(Envelope envelope) async {
    if (envelope.type != MessageType.clipboardUpdate) return;

    final ClipboardPayload payload;
    try {
      payload = ClipboardPayload.fromMap(envelope.payload);
    } on EnvelopeError {
      return;
    }

    if (payload.timestampMs < _lastAppliedTimestampMs) {
      // Last-write-wins by wall clock. A clipboard has no history to
      // corrupt, so the loser simply loses.
      return;
    }
    if (payload.data.length > maxClipboardBytes) return;

    // Recompute rather than trusting the peer's `contentHash`. The stored hash
    // is what suppresses our own write echoing back through the platform
    // watcher; if a peer sends a hash that does not match its own payload —
    // through a bug or deliberately — the echo check never matches and the two
    // devices ping-pong forever, which is the one failure this feature exists
    // to prevent. Recomputing is self-validating and costs a single hash.
    _lastAppliedHash = clipboardHash(payload.format, payload.data);
    _lastAppliedTimestampMs = payload.timestampMs;

    await _watcher.write(ClipboardContent(
      format: payload.format,
      data: Uint8List.fromList(payload.data),
      isConcealed: false,
    ));
  }
}
```

- [ ] **Step 5: Export both**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/sync/clipboard_sync.dart';
export 'src/sync/clipboard_watcher.dart';
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/sync/clipboard_sync_test.dart`
Expected: PASS — `+13: All tests passed!`

- [ ] **Step 7: Run the whole suite**

Run: `cd packages/omnifi_core && dart test`
Expected: PASS.

- [ ] **Step 8: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add clipboard sync with loop prevention and privacy defaults"
```

---

## Task 18: Cloudflare relay Worker and Durable Object

**Files:**
- Create: `relay/package.json`
- Create: `relay/wrangler.toml`
- Create: `relay/tsconfig.json`
- Create: `relay/src/index.ts`
- Create: `relay/src/mesh_do.ts`
- Test: `relay/test/mesh_do.test.ts`

**Interfaces:**
- Consumes: nothing from the Dart packages. The relay never parses payloads.
- Produces (network contract consumed by Task 19's `RelayLink`):
  - `GET /v1/mesh/:meshId/ws?device=:deviceId` with `Upgrade: websocket` — joins the mesh.
  - Frames sent by a client are binary. The first 16 bytes are the **destination device ID** as raw bytes (32 hex chars decoded), or 16 zero bytes for broadcast. The remainder is opaque ciphertext, forwarded verbatim.
  - `GET /v1/health` → `200 {"ok":true}`.
  - Server returns HTTP `400` **before completing the upgrade** on a malformed mesh ID or device ID, and HTTP `426` on a non-upgrade request to the ws path. Once a socket exists, an oversized frame (over 1 MiB) closes it with code `1009`.

    A close code cannot be used for a malformed ID: those are detected before the WebSocket handshake completes, so no socket exists to close. Emitting one would mean accepting the upgrade purely to close it immediately — an extra round trip and a harder error for the client to surface. `1009` is a close code because by the time a frame is read, the socket is live. Task 19's `RelayLink` must therefore treat a non-101 response as a connect failure, not as a close event.

- [ ] **Step 1: Create the project files**

Create `relay/package.json`:

```json
{
  "name": "omnifi-relay",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "test": "vitest run"
  },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "^0.5.0",
    "@cloudflare/workers-types": "^4.20240909.0",
    "typescript": "^5.5.0",
    "vitest": "^2.0.0",
    "wrangler": "^3.78.0"
  }
}
```

Create `relay/wrangler.toml`:

```toml
name = "omnifi-relay"
main = "src/index.ts"
compatibility_date = "2024-09-23"

[[durable_objects.bindings]]
name = "MESH"
class_name = "MeshDurableObject"

[[migrations]]
tag = "v1"
new_classes = ["MeshDurableObject"]

[observability]
enabled = true
```

Create `relay/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "Bundler",
    "lib": ["ES2022"],
    "types": ["@cloudflare/workers-types"],
    "strict": true,
    "noEmit": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*.ts", "test/**/*.ts"]
}
```

Create `relay/vitest.config.ts`:

```ts
import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: { wrangler: { configPath: './wrangler.toml' } },
    },
  },
});
```

- [ ] **Step 2: Write the failing tests**

Create `relay/test/mesh_do.test.ts`:

```ts
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
```

- [ ] **Step 3: Install and run the tests to verify they fail**

Run: `cd relay && npm install && npm test`
Expected: FAIL — module `src/index.ts` not found or `MeshDurableObject` is not exported.

- [ ] **Step 4: Write the Durable Object**

Create `relay/src/mesh_do.ts`:

```ts
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
      return new Response('bad device id', { status: 400 });
    }
    if (request.headers.get('Upgrade') !== 'websocket') {
      return new Response('expected websocket upgrade', { status: 426 });
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
```

- [ ] **Step 5: Write the Worker entry point**

Create `relay/src/index.ts`:

```ts
export { MeshDurableObject } from './mesh_do';

interface Env {
  MESH: DurableObjectNamespace;
}

const MESH_PATH = /^\/v1\/mesh\/([0-9a-f]{32})\/ws$/;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/v1/health') {
      return Response.json({ ok: true });
    }

    const match = MESH_PATH.exec(url.pathname);
    if (!match) {
      return new Response('not found', { status: 404 });
    }

    const meshId = match[1];
    const id = env.MESH.idFromName(meshId);
    return env.MESH.get(id).fetch(request);
  },
};
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd relay && npm test`
Expected: PASS — 9 tests.

If the malformed-mesh-id test returns 404 rather than 400, note that the route regex rejects non-hex mesh IDs before the DO sees them. Change the expectation to accept either, or add an explicit `/^\/v1\/mesh\/([^/]+)\/ws$/` route that validates and returns 400. Prefer the explicit route so the client gets an actionable status.

- [ ] **Step 7: Verify it starts locally**

Run: `cd relay && npx wrangler dev --port 8787 &` then `curl -s http://localhost:8787/v1/health`
Expected: `{"ok":true}`. Stop the dev server afterwards.

- [ ] **Step 8: Commit**

```bash
cd .. && cat >> .gitignore <<'EOF'
relay/node_modules/
relay/.wrangler/
EOF
git add relay .gitignore
git commit -m "feat: add Cloudflare relay worker with blind mesh forwarding"
```

---

## Task 19: `RelayLink` — WebSocket client for the relay

**Files:**
- Create: `packages/omnifi_core/lib/src/transport/relay_link.dart`
- Modify: `packages/omnifi_core/pubspec.yaml`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/transport/relay_link_test.dart`
- Test: `packages/omnifi_core/test/integration/relay_roundtrip_test.dart`

**Interfaces:**
- Consumes: `Link`, `LinkState`, `LinkKind`, `LinkQuality`, `LinkClosedError` (Task 11); the relay network contract from Task 18.
- Produces:
  - `class RelayLink implements Link` with `static Future<RelayLink> connect({required Uri relayBase, required String meshId, required String localDeviceId, required String peerDeviceId, Duration timeout = const Duration(seconds: 10), WebSocketChannel Function(Uri)? channelFactory})`
  - `Uri relayWebSocketUri({required Uri relayBase, required String meshId, required String deviceId})`
  - `Uint8List addressFrame(String destinationDeviceId, List<int> body)` and `Uint8List stripAddress(List<int> framed)` — the 16-byte destination header from Task 18.
  - `const List<int> broadcastAddress` — 16 zero bytes.

`channelFactory` exists so unit tests can inject a fake channel without a live relay; the integration test uses the real one against `wrangler dev`.

- [ ] **Step 1: Add the dependency**

Modify `packages/omnifi_core/pubspec.yaml` — add under `dependencies:`:

```yaml
  web_socket_channel: ^3.0.0
```

Run: `cd packages/omnifi_core && dart pub get`

- [ ] **Step 2: Write the failing unit tests**

Create `packages/omnifi_core/test/transport/relay_link_test.dart`:

```dart
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

/// Minimal in-memory WebSocketChannel double.
class FakeChannel extends StreamChannelMixin implements WebSocketChannel {
  final StreamController<Object?> _incoming =
      StreamController<Object?>.broadcast();
  final List<Object?> sent = [];

  void deliver(Object? message) => _incoming.add(message);

  @override
  Stream<Object?> get stream => _incoming.stream;

  @override
  WebSocketSink get sink => _FakeSink(this);

  @override
  int? get closeCode => null;

  @override
  String? get closeReason => null;

  @override
  String? get protocol => null;

  @override
  Future<void> get ready async {}

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FakeSink implements WebSocketSink {
  _FakeSink(this._channel);
  final FakeChannel _channel;

  @override
  void add(Object? data) => _channel.sent.add(data);

  @override
  Future<void> close([int? closeCode, String? closeReason]) async {
    await _channel._incoming.close();
  }

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  test('builds the relay websocket uri', () {
    final uri = relayWebSocketUri(
      relayBase: Uri.parse('https://relay.example.com'),
      meshId: 'a' * 32,
      deviceId: '1' * 32,
    );
    expect(uri.scheme, 'wss');
    expect(uri.path, '/v1/mesh/${'a' * 32}/ws');
    expect(uri.queryParameters['device'], '1' * 32);
  });

  test('uses ws for an http base', () {
    final uri = relayWebSocketUri(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      deviceId: '1' * 32,
    );
    expect(uri.scheme, 'ws');
    expect(uri.port, 8787);
  });

  test('prefixes a 16-byte destination address', () {
    final framed = addressFrame('2' * 32, utf8.encode('body'));
    expect(framed.length, 16 + 4);
    expect(framed.sublist(0, 16), [
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
      0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
    ]);
    expect(utf8.decode(framed.sublist(16)), 'body');
  });

  test('strips the address header', () {
    final framed = addressFrame('2' * 32, utf8.encode('payload'));
    expect(utf8.decode(stripAddress(framed)), 'payload');
  });

  test('broadcast address is 16 zero bytes', () {
    expect(broadcastAddress.length, 16);
    expect(broadcastAddress.every((b) => b == 0), isTrue);
  });

  test('rejects a malformed destination device id', () {
    expect(() => addressFrame('not-hex', const []),
        throwsA(isA<ArgumentError>()));
  });

  test('rejects stripping a frame shorter than the header', () {
    expect(() => stripAddress(Uint8List(8)), throwsA(isA<ArgumentError>()));
  });

  test('connects and reports relay kind', () async {
    final fake = FakeChannel();
    final link = await RelayLink.connect(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      localDeviceId: '1' * 32,
      peerDeviceId: '2' * 32,
      channelFactory: (_) => fake,
    );
    expect(link.kind, LinkKind.relay);
    expect(link.quality.isDirect, isFalse);
    expect(link.state, LinkState.connected);
  });

  test('sends frames addressed to the peer', () async {
    final fake = FakeChannel();
    final link = await RelayLink.connect(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      localDeviceId: '1' * 32,
      peerDeviceId: '2' * 32,
      channelFactory: (_) => fake,
    );
    await link.send(utf8.encode('ciphertext'));
    final sent = fake.sent.single as Uint8List;
    expect(sent.sublist(0, 16).every((b) => b == 0x22), isTrue);
    expect(utf8.decode(sent.sublist(16)), 'ciphertext');
  });

  test('strips the header from inbound frames', () async {
    final fake = FakeChannel();
    final link = await RelayLink.connect(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      localDeviceId: '1' * 32,
      peerDeviceId: '2' * 32,
      channelFactory: (_) => fake,
    );
    final received = link.inbound.first;
    fake.deliver(addressFrame('1' * 32, utf8.encode('inbound')));
    expect(utf8.decode(await received), 'inbound');
  });

  test('ignores a text message from the relay', () async {
    final fake = FakeChannel();
    final link = await RelayLink.connect(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      localDeviceId: '1' * 32,
      peerDeviceId: '2' * 32,
      channelFactory: (_) => fake,
    );
    var frames = 0;
    link.inbound.listen((_) => frames++);
    fake.deliver('unexpected text');
    await Future<void>.delayed(const Duration(milliseconds: 10));
    expect(frames, 0);
  });

  test('sending after close throws', () async {
    final fake = FakeChannel();
    final link = await RelayLink.connect(
      relayBase: Uri.parse('http://localhost:8787'),
      meshId: 'a' * 32,
      localDeviceId: '1' * 32,
      peerDeviceId: '2' * 32,
      channelFactory: (_) => fake,
    );
    await link.close();
    expect(() => link.send(utf8.encode('x')),
        throwsA(isA<LinkClosedError>()));
  });
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/transport/relay_link_test.dart`
Expected: FAIL — `relayWebSocketUri isn't defined`.

- [ ] **Step 4: Write the implementation**

Create `packages/omnifi_core/lib/src/transport/relay_link.dart`:

```dart
import 'dart:async';
import 'dart:typed_data';

import 'package:web_socket_channel/web_socket_channel.dart';

import 'link.dart';

const int _addressBytes = 16;

const List<int> broadcastAddress = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

Uri relayWebSocketUri({
  required Uri relayBase,
  required String meshId,
  required String deviceId,
}) {
  final scheme = relayBase.scheme == 'https' ? 'wss' : 'ws';
  return relayBase.replace(
    scheme: scheme,
    path: '/v1/mesh/$meshId/ws',
    queryParameters: {'device': deviceId},
  );
}

Uint8List _deviceIdBytes(String deviceId) {
  if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(deviceId)) {
    throw ArgumentError.value(
        deviceId, 'deviceId', 'must be 32 lowercase hex characters');
  }
  final out = Uint8List(_addressBytes);
  for (var i = 0; i < _addressBytes; i++) {
    out[i] = int.parse(deviceId.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Uint8List addressFrame(String destinationDeviceId, List<int> body) {
  final header = _deviceIdBytes(destinationDeviceId);
  final out = Uint8List(_addressBytes + body.length);
  out.setRange(0, _addressBytes, header);
  out.setRange(_addressBytes, out.length, body);
  return out;
}

Uint8List stripAddress(List<int> framed) {
  if (framed.length < _addressBytes) {
    throw ArgumentError.value(
        framed.length, 'framed', 'shorter than the address header');
  }
  return Uint8List.fromList(framed.sublist(_addressBytes));
}

/// A [Link] that reaches the peer through the Cloudflare relay.
///
/// The relay sees only the 16-byte destination header and the length of
/// the opaque body it forwards.
class RelayLink implements Link {
  RelayLink._({
    required this.id,
    required WebSocketChannel channel,
    required String peerDeviceId,
  })  : _channel = channel,
        _peerDeviceId = peerDeviceId {
    _sub = _channel.stream.listen(
      _onMessage,
      onError: (Object error) {
        _setState(LinkState.failed);
      },
      onDone: () => _setState(LinkState.disconnected),
    );
  }

  static Future<RelayLink> connect({
    required Uri relayBase,
    required String meshId,
    required String localDeviceId,
    required String peerDeviceId,
    Duration timeout = const Duration(seconds: 10),
    WebSocketChannel Function(Uri)? channelFactory,
  }) async {
    final uri = relayWebSocketUri(
      relayBase: relayBase,
      meshId: meshId,
      deviceId: localDeviceId,
    );
    final channel =
        (channelFactory ?? WebSocketChannel.connect)(uri);
    await channel.ready.timeout(timeout);
    return RelayLink._(
      // Host AND port, because two relay backends can be dialed for the same
      // peer simultaneously and LinkManager keys its candidate map by id. A
      // bare 'relay:<peer>' collides across backends; host alone still
      // collides for two relays on one host at different ports, which is
      // exactly the local dev setup (localhost:8787 and localhost:8788).
      // Uri.port returns the scheme default when absent, so this stays stable.
      id: 'relay:${relayBase.host}:${relayBase.port}:$peerDeviceId',
      channel: channel,
      peerDeviceId: peerDeviceId,
    );
  }

  @override
  final String id;

  final WebSocketChannel _channel;
  final String _peerDeviceId;

  final StreamController<Uint8List> _inbound =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkState> _states =
      StreamController<LinkState>.broadcast();

  StreamSubscription<Object?>? _sub;
  LinkState _state = LinkState.connected;
  Duration? _rtt;

  @override
  LinkKind get kind => LinkKind.relay;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Stream<LinkState> get states => _states.stream;

  @override
  LinkState get state => _state;

  @override
  LinkQuality get quality => LinkQuality(kind: LinkKind.relay, rtt: _rtt);

  void recordRtt(Duration rtt) => _rtt = rtt;

  void _setState(LinkState next) {
    if (_state == next) return;
    _state = next;
    if (!_states.isClosed) _states.add(next);
  }

  void _onMessage(Object? message) {
    // The relay only ever forwards binary frames; anything else is noise.
    if (message is! List<int>) return;
    if (message.length < _addressBytes) return;
    if (_inbound.isClosed) return;
    _inbound.add(stripAddress(message));
  }

  @override
  Future<void> send(List<int> frame) async {
    if (_state != LinkState.connected) {
      throw LinkClosedError(id);
    }
    _channel.sink.add(addressFrame(_peerDeviceId, frame));
  }

  @override
  Future<void> close() async {
    _setState(LinkState.disconnected);
    await _sub?.cancel();
    await _channel.sink.close();
    if (!_inbound.isClosed) await _inbound.close();
    if (!_states.isClosed) await _states.close();
  }
}
```

- [ ] **Step 5: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/transport/relay_link.dart';
```

- [ ] **Step 6: Run the unit tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/transport/relay_link_test.dart`
Expected: PASS — `+12: All tests passed!`

- [ ] **Step 7: Write the integration test against a live local relay**

Create `packages/omnifi_core/test/integration/relay_roundtrip_test.dart`:

```dart
@Tags(['integration'])
library;

import 'dart:convert';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

/// Requires a relay at http://localhost:8787.
/// Start it with: cd relay && npx wrangler dev --port 8787
void main() {
  final base = Uri.parse('http://localhost:8787');
  const meshId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const deviceA = '11111111111111111111111111111111';
  const deviceB = '22222222222222222222222222222222';

  test('two links exchange frames through the live relay', () async {
    final a = await RelayLink.connect(
      relayBase: base,
      meshId: meshId,
      localDeviceId: deviceA,
      peerDeviceId: deviceB,
    );
    final b = await RelayLink.connect(
      relayBase: base,
      meshId: meshId,
      localDeviceId: deviceB,
      peerDeviceId: deviceA,
    );

    final received = b.inbound.first;
    await a.send(utf8.encode('through the relay'));
    expect(utf8.decode(await received), 'through the relay');

    await a.close();
    await b.close();
  });

  test('a full session survives a relay round trip', () async {
    final k1 = List<int>.filled(32, 11);
    final k2 = List<int>.filled(32, 22);
    int clock() => 1753200000000;

    final sa = PeerSession(
      localDeviceId: deviceA,
      peerDeviceId: deviceB,
      crypto: AeadSession(sendKey: k1, receiveKey: k2),
      clock: clock,
    );
    final sb = PeerSession(
      localDeviceId: deviceB,
      peerDeviceId: deviceA,
      crypto: AeadSession(sendKey: k2, receiveKey: k1),
      clock: clock,
    );

    sa.attach(await RelayLink.connect(
      relayBase: base,
      meshId: meshId,
      localDeviceId: deviceA,
      peerDeviceId: deviceB,
    ));
    sb.attach(await RelayLink.connect(
      relayBase: base,
      meshId: meshId,
      localDeviceId: deviceB,
      peerDeviceId: deviceA,
    ));

    final received = sb.inbound.first;
    await sa.send(MessageType.clipboardUpdate, {'text': 'encrypted'});
    expect((await received).payload['text'], 'encrypted');

    await sa.dispose();
    await sb.dispose();
  });
}
```

- [ ] **Step 8: Run the integration test with the relay running**

Run in one shell: `cd relay && npx wrangler dev --port 8787`
Run in another: `cd packages/omnifi_core && dart test test/integration/ --tags integration`
Expected: PASS — 2 tests. Stop the dev server afterwards.

Note: the default `dart test` run excludes these because of the `integration` tag, so the unit suite stays fast and offline.

- [ ] **Step 9: Configure the tag so plain runs skip it**

Create `packages/omnifi_core/dart_test.yaml`:

```yaml
tags:
  integration:
    skip: "requires a local relay; run with --tags integration"
```

- [ ] **Step 10: Verify the default run skips integration**

Run: `cd packages/omnifi_core && dart test`
Expected: PASS, with the integration tests reported as skipped.

- [ ] **Step 11: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add RelayLink websocket transport with relay integration tests"
```

---

## Task 20: `LanLink` — mDNS discovery and direct TCP

**Files:**
- Create: `packages/omnifi_core/lib/src/transport/lan_link.dart`
- Modify: `packages/omnifi_core/pubspec.yaml`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/transport/lan_link_test.dart`

**Interfaces:**
- Consumes: `Link` and friends (Task 11), `encodeFrame`/`FrameDecoder` (Task 7).
- Produces:
  - `const String omnifiServiceType = '_omnifi._tcp'`
  - `class LanEndpoint { final String deviceId; final InternetAddress address; final int port; }`
  - `class LanLink implements Link` with `static Future<LanLink> fromSocket(Socket socket, {required String peerDeviceId})` and `static Future<LanLink> dial(LanEndpoint endpoint, {required String peerDeviceId, Duration timeout = const Duration(seconds: 5)})`
  - `class LanListener` with `static Future<LanListener> bind({required String localDeviceId, int port = 0})`, `int get port`, `Stream<LanLink> get incoming`, `Future<void> close()`
  - `abstract interface class LanDiscovery` with `Stream<LanEndpoint> discover()` and `Future<void> advertise({required String deviceId, required int port})`, plus `class MdnsDiscovery implements LanDiscovery` and `class StaticDiscovery implements LanDiscovery` (a fixed list, used by tests and by manual "connect to this IP" configuration).

Unlike `RelayLink`, TCP is a byte stream with no message boundaries, so `LanLink` owns a `FrameDecoder` internally. Everything above `Link` still sees whole frames.

- [ ] **Step 1: Add the dependency**

Modify `packages/omnifi_core/pubspec.yaml` — add under `dependencies:`:

```yaml
  multicast_dns: ^0.3.2
```

Run: `cd packages/omnifi_core && dart pub get`

- [ ] **Step 2: Write the failing tests**

Create `packages/omnifi_core/test/transport/lan_link_test.dart`:

```dart
import 'dart:convert';
import 'dart:io';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('service type is the documented one', () {
    expect(omnifiServiceType, '_omnifi._tcp');
  });

  test('listener binds to an ephemeral port', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    expect(listener.port, greaterThan(0));
    await listener.close();
  });

  test('a dialed link exchanges frames with the accepted link', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;

    final dialed = await LanLink.dial(
      LanEndpoint(
        deviceId: '1' * 32,
        address: InternetAddress.loopbackIPv4,
        port: listener.port,
      ),
      peerDeviceId: '1' * 32,
    );
    final accepted = await acceptedFuture;

    final received = accepted.inbound.first;
    await dialed.send(utf8.encode('over the lan'));
    expect(utf8.decode(await received), 'over the lan');

    await dialed.close();
    await accepted.close();
    await listener.close();
  });

  test('reassembles a frame split across TCP writes', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;
    final socket = await Socket.connect(
        InternetAddress.loopbackIPv4, listener.port);
    final accepted = await acceptedFuture;

    final received = accepted.inbound.first;
    final frame = encodeFrame(utf8.encode('deliberately split'));
    socket.add(frame.sublist(0, 6));
    await socket.flush();
    await Future<void>.delayed(const Duration(milliseconds: 20));
    socket.add(frame.sublist(6));
    await socket.flush();

    expect(utf8.decode(await received), 'deliberately split');

    await socket.close();
    await accepted.close();
    await listener.close();
  });

  test('delivers two frames arriving in one TCP write', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;
    final socket = await Socket.connect(
        InternetAddress.loopbackIPv4, listener.port);
    final accepted = await acceptedFuture;

    final frames = <String>[];
    accepted.inbound.listen((f) => frames.add(utf8.decode(f)));
    socket.add([
      ...encodeFrame(utf8.encode('first')),
      ...encodeFrame(utf8.encode('second')),
    ]);
    await socket.flush();
    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(frames, ['first', 'second']);

    await socket.close();
    await accepted.close();
    await listener.close();
  });

  test('reports lan kind and is preferred over relay', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;
    final dialed = await LanLink.dial(
      LanEndpoint(
        deviceId: '1' * 32,
        address: InternetAddress.loopbackIPv4,
        port: listener.port,
      ),
      peerDeviceId: '1' * 32,
    );
    await acceptedFuture;

    expect(dialed.kind, LinkKind.lan);
    expect(dialed.quality.isDirect, isTrue);
    expect(
      dialed.quality.preferenceScore,
      lessThan(const LinkQuality(kind: LinkKind.relay).preferenceScore),
    );

    await dialed.close();
    await listener.close();
  });

  test('peer disconnect moves the link to disconnected', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final acceptedFuture = listener.incoming.first;
    final dialed = await LanLink.dial(
      LanEndpoint(
        deviceId: '1' * 32,
        address: InternetAddress.loopbackIPv4,
        port: listener.port,
      ),
      peerDeviceId: '1' * 32,
    );
    final accepted = await acceptedFuture;

    await dialed.close();
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(accepted.state, LinkState.disconnected);

    await accepted.close();
    await listener.close();
  });

  test('dialing a closed port fails rather than hanging', () async {
    final listener = await LanListener.bind(localDeviceId: '1' * 32);
    final port = listener.port;
    await listener.close();

    expect(
      () => LanLink.dial(
        LanEndpoint(
          deviceId: '1' * 32,
          address: InternetAddress.loopbackIPv4,
          port: port,
        ),
        peerDeviceId: '1' * 32,
        timeout: const Duration(milliseconds: 500),
      ),
      throwsA(anything),
    );
  });

  test('static discovery yields its configured endpoints', () async {
    final discovery = StaticDiscovery([
      LanEndpoint(
        deviceId: '2' * 32,
        address: InternetAddress.loopbackIPv4,
        port: 9999,
      ),
    ]);
    final found = await discovery.discover().toList();
    expect(found.single.deviceId, '2' * 32);
    expect(found.single.port, 9999);
  });
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd packages/omnifi_core && dart test test/transport/lan_link_test.dart`
Expected: FAIL — `omnifiServiceType isn't defined`.

- [ ] **Step 4: Write the implementation**

Create `packages/omnifi_core/lib/src/transport/lan_link.dart`:

```dart
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:multicast_dns/multicast_dns.dart';

import '../protocol/framing.dart';
import 'link.dart';

const String omnifiServiceType = '_omnifi._tcp';

class LanEndpoint {
  const LanEndpoint({
    required this.deviceId,
    required this.address,
    required this.port,
  });
  final String deviceId;
  final InternetAddress address;
  final int port;
}

/// A direct TCP [Link] on the local network.
///
/// TCP has no message boundaries, so this owns a [FrameDecoder]; callers
/// above the [Link] interface still see whole frames only.
class LanLink implements Link {
  LanLink._(this._socket, {required String peerDeviceId})
      : id = 'lan:$peerDeviceId' {
    _sub = _socket.listen(
      _onBytes,
      onError: (Object _) => _setState(LinkState.failed),
      onDone: () => _setState(LinkState.disconnected),
      cancelOnError: false,
    );
  }

  static Future<LanLink> fromSocket(
    Socket socket, {
    required String peerDeviceId,
  }) async =>
      LanLink._(socket, peerDeviceId: peerDeviceId);

  static Future<LanLink> dial(
    LanEndpoint endpoint, {
    required String peerDeviceId,
    Duration timeout = const Duration(seconds: 5),
  }) async {
    final socket = await Socket.connect(
      endpoint.address,
      endpoint.port,
      timeout: timeout,
    );
    socket.setOption(SocketOption.tcpNoDelay, true);
    return LanLink._(socket, peerDeviceId: peerDeviceId);
  }

  @override
  final String id;

  final Socket _socket;
  final FrameDecoder _decoder = FrameDecoder();
  final StreamController<Uint8List> _inbound =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkState> _states =
      StreamController<LinkState>.broadcast();

  StreamSubscription<Uint8List>? _sub;
  LinkState _state = LinkState.connected;
  Duration? _rtt;

  @override
  LinkKind get kind => LinkKind.lan;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Stream<LinkState> get states => _states.stream;

  @override
  LinkState get state => _state;

  @override
  LinkQuality get quality => LinkQuality(kind: LinkKind.lan, rtt: _rtt);

  void recordRtt(Duration rtt) => _rtt = rtt;

  void _setState(LinkState next) {
    if (_state == next) return;
    _state = next;
    if (!_states.isClosed) _states.add(next);
  }

  void _onBytes(Uint8List chunk) {
    try {
      for (final frame in _decoder.addChunk(chunk)) {
        if (!_inbound.isClosed) _inbound.add(frame);
      }
    } on FrameTooLargeError {
      // A peer declaring an absurd length is either broken or hostile.
      // Drop the connection rather than buffering toward an OOM.
      unawaited(close());
    }
  }

  @override
  Future<void> send(List<int> frame) async {
    if (_state != LinkState.connected) {
      throw LinkClosedError(id);
    }
    _socket.add(encodeFrame(frame));
    await _socket.flush();
  }

  @override
  Future<void> close() async {
    _setState(LinkState.disconnected);
    await _sub?.cancel();
    try {
      await _socket.close();
    } on SocketException {
      // Already gone.
    }
    _socket.destroy();
    if (!_inbound.isClosed) await _inbound.close();
    if (!_states.isClosed) await _states.close();
  }
}

/// Accepts inbound LAN connections from peers.
class LanListener {
  LanListener._(this._server, this._localDeviceId) {
    _sub = _server.listen((socket) async {
      socket.setOption(SocketOption.tcpNoDelay, true);
      // The peer's identity is established by the session handshake, not by
      // the socket, so a provisional id is fine here.
      _incoming.add(await LanLink.fromSocket(socket,
          peerDeviceId: 'pending-${socket.remotePort}'));
    });
  }

  static Future<LanListener> bind({
    required String localDeviceId,
    int port = 0,
  }) async {
    final server = await ServerSocket.bind(InternetAddress.anyIPv4, port);
    return LanListener._(server, localDeviceId);
  }

  final ServerSocket _server;
  final String _localDeviceId;
  final StreamController<LanLink> _incoming =
      StreamController<LanLink>.broadcast();
  StreamSubscription<Socket>? _sub;

  int get port => _server.port;
  String get localDeviceId => _localDeviceId;
  Stream<LanLink> get incoming => _incoming.stream;

  Future<void> close() async {
    await _sub?.cancel();
    await _server.close();
    if (!_incoming.isClosed) await _incoming.close();
  }
}

abstract interface class LanDiscovery {
  Stream<LanEndpoint> discover();
  Future<void> advertise({required String deviceId, required int port});
}

/// Fixed endpoint list. Used by tests and by manual "connect to this IP"
/// configuration on networks where multicast is blocked.
class StaticDiscovery implements LanDiscovery {
  StaticDiscovery(this.endpoints);
  final List<LanEndpoint> endpoints;

  @override
  Stream<LanEndpoint> discover() => Stream.fromIterable(endpoints);

  @override
  Future<void> advertise({
    required String deviceId,
    required int port,
  }) async {}
}

/// Bonjour/mDNS discovery of `_omnifi._tcp` peers.
class MdnsDiscovery implements LanDiscovery {
  MdnsDiscovery({MDnsClient? client}) : _client = client ?? MDnsClient();

  final MDnsClient _client;
  bool _started = false;

  @override
  Stream<LanEndpoint> discover() async* {
    if (!_started) {
      await _client.start();
      _started = true;
    }
    await for (final ptr in _client.lookup<PtrResourceRecord>(
      ResourceRecordQuery.serverPointer(omnifiServiceType),
    )) {
      await for (final srv in _client.lookup<SrvResourceRecord>(
        ResourceRecordQuery.service(ptr.domainName),
      )) {
        await for (final ip in _client.lookup<IPAddressResourceRecord>(
          ResourceRecordQuery.addressIPv4(srv.target),
        )) {
          yield LanEndpoint(
            deviceId: srv.name.split('.').first,
            address: ip.address,
            port: srv.port,
          );
        }
      }
    }
  }

  /// Advertising requires a platform responder (Bonjour on Apple, the DNS-SD
  /// service on Windows); `multicast_dns` is query-only. The Flutter app
  /// registers the service natively in Tasks 22 and 23 and calls this only
  /// to record what was advertised.
  @override
  Future<void> advertise({
    required String deviceId,
    required int port,
  }) async {
    advertisedDeviceId = deviceId;
    advertisedPort = port;
  }

  String? advertisedDeviceId;
  int? advertisedPort;
}
```

- [ ] **Step 5: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/transport/lan_link.dart';
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/transport/lan_link_test.dart`
Expected: PASS — `+9: All tests passed!`

- [ ] **Step 7: Run the whole suite**

Run: `cd packages/omnifi_core && dart test`
Expected: PASS, integration tests skipped.

- [ ] **Step 8: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add LanLink TCP transport with mDNS discovery"
```

---

## Task 21: `OmniFiEngine` — wiring the core into one object the app can drive

Before any Flutter code, the composition of identity + mesh + sessions + links + clipboard needs to exist as testable pure Dart. The app then becomes a thin shell over this.

**Files:**
- Create: `packages/omnifi_core/lib/src/engine/omnifi_engine.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/engine/omnifi_engine_test.dart`

**Interfaces:**
- Consumes: everything from Tasks 3–20.
- Produces:
  - `class EngineConfig { final List<Uri> relayBases; final String displayName; final bool lanEnabled; }` — `relayBases` is every relay backend to dial, in descending preference order. All are dialed concurrently as competing candidate links.
  - `class OmniFiEngine` with:
    - `static Future<OmniFiEngine> create({required SecureStore store, required ClipboardWatcher watcher, required EngineConfig config, int Function()? clock})`
    - `DeviceIdentity get identity`, `Mesh get mesh`
    - `Future<void> start()` / `Future<void> stop()`
    - `Stream<ConnectionStatus> get statuses`, `ConnectionStatus get status` — worst status across peers, so the tray icon reflects the weakest link rather than the best
    - `ClipboardSync get clipboard`
    - `Future<PairingSasPending> beginInvite()` / `Future<PairingSasPending> beginJoin(PairingInvite invite)`
    - `Future<void> forgetPeer(String deviceId)`
    - `Future<void> onWake()`, `void onScreenLocked()`, `void onScreenUnlocked()`
    - `List<PeerSession> get sessions`

- [ ] **Step 1: Write the failing tests**

Create `packages/omnifi_core/test/engine/omnifi_engine_test.dart`:

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

EngineConfig config({bool lan = false}) => EngineConfig(
      relayBases: [Uri.parse('http://localhost:8787')],
      displayName: 'Test Device',
      lanEnabled: lan,
    );

Future<OmniFiEngine> engine({SecureStore? store}) => OmniFiEngine.create(
      store: store ?? InMemorySecureStore(),
      watcher: FakeClipboardWatcher(),
      config: config(),
      clock: () => 1753200000000,
    );

void main() {
  test('creates an identity and a mesh on first run', () async {
    final e = await engine();
    expect(e.identity.deviceId, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(e.identity.displayName, 'Test Device');
    expect(e.mesh.meshId, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(e.mesh.peers, isEmpty);
  });

  test('reuses identity and mesh across restarts', () async {
    final store = InMemorySecureStore();
    final first = await engine(store: store);
    final second = await engine(store: store);
    expect(second.identity.deviceId, first.identity.deviceId);
    expect(second.mesh.meshId, first.mesh.meshId);
  });

  test('starts offline with no peers', () async {
    final e = await engine();
    expect(e.status, ConnectionStatus.offline);
    expect(e.sessions, isEmpty);
  });

  test('an invite carries the mesh id and this device public key',
      () async {
    final e = await engine();
    final invite = e.buildInvite();
    expect(invite.meshId, e.mesh.meshId);
    expect(invite.inviterPublicKey, e.identity.keys.publicKey);
    expect(invite.psk.length, 32);
    expect(invite.relayHint, 'http://localhost:8787');
  });

  test('forgetting a peer removes it from the roster', () async {
    final e = await engine();
    e.mesh.addPeer(PeerRecord(
      deviceId: 'b' * 32,
      publicKey: List<int>.filled(32, 5),
      displayName: 'Gone',
      addedAtMs: 1,
    ));
    await e.forgetPeer('b' * 32);
    expect(e.mesh.peer('b' * 32), isNull);
    expect(e.mesh.isAuthorized('b' * 32, List<int>.filled(32, 5)), isFalse);
  });

  test('a forgotten peer stays forgotten across a restart', () async {
    final store = InMemorySecureStore();
    final first = await engine(store: store);
    first.mesh.addPeer(PeerRecord(
      deviceId: 'b' * 32,
      publicKey: List<int>.filled(32, 5),
      displayName: 'Gone',
      addedAtMs: 1,
    ));
    await first.persist();
    await first.forgetPeer('b' * 32);

    final second = await engine(store: store);
    expect(second.mesh.peer('b' * 32), isNull);
  });

  test('status reflects the worst peer, not the best', () async {
    final e = await engine();
    e.debugSetPeerStatus('b' * 32, ConnectionStatus.connectedDirect);
    e.debugSetPeerStatus('c' * 32, ConnectionStatus.reconnecting);
    expect(e.status, ConnectionStatus.reconnecting);

    e.debugSetPeerStatus('c' * 32, ConnectionStatus.connectedRelay);
    expect(e.status, ConnectionStatus.connectedRelay);

    e.debugSetPeerStatus('b' * 32, ConnectionStatus.connectedRelay);
    e.debugSetPeerStatus('c' * 32, ConnectionStatus.connectedDirect);
    expect(e.status, ConnectionStatus.connectedRelay);
  });

  test('screen lock pauses clipboard sync', () async {
    final e = await engine();
    e.onScreenLocked();
    expect(e.clipboard.isPaused, isTrue);
    e.onScreenUnlocked();
    expect(e.clipboard.isPaused, isFalse);
  });

  test('stop is safe to call without start', () async {
    final e = await engine();
    await e.stop();
    expect(e.status, ConnectionStatus.offline);
  });

  test('clipboard changes reach a connected peer session', () async {
    final watcher = FakeClipboardWatcher();
    final e = await OmniFiEngine.create(
      store: InMemorySecureStore(),
      watcher: watcher,
      config: config(),
      clock: () => 1753200000000,
    );
    await e.start();

    final k1 = List<int>.filled(32, 11);
    final k2 = List<int>.filled(32, 22);
    final remote = PeerSession(
      localDeviceId: 'b' * 32,
      peerDeviceId: e.identity.deviceId,
      crypto: AeadSession(sendKey: k2, receiveKey: k1),
      clock: () => 1753200000000,
    );
    final local = e.debugAttachSession(
      peerDeviceId: 'b' * 32,
      crypto: AeadSession(sendKey: k1, receiveKey: k2),
    );
    final links = FakeLinkFactory.connectedPair();
    local.attach(links.a);
    remote.attach(links.b);

    final received = remote.inbound.first;
    watcher.emit(ClipboardContent(
      format: 'text',
      data: Uint8List.fromList(utf8.encode('engine wired')),
      isConcealed: false,
    ));
    final payload = ClipboardPayload.fromMap((await received).payload);
    expect(utf8.decode(payload.data), 'engine wired');
  });
}
```

- [ ] **Step 2: Promote the fake link into the library**

The engine test needs a link double, and so will the Flutter app's own tests. Move it out of `test/support/`.

Create `packages/omnifi_core/lib/src/transport/fake_link_factory.dart` containing the exact contents of `packages/omnifi_core/test/support/fake_link.dart`, with the class renamed to `FakeLinkFactory` and its `import 'package:omnifi_core/omnifi_core.dart';` replaced by:

```dart
import 'link.dart';
```

Then replace `packages/omnifi_core/test/support/fake_link.dart` with a re-export so existing tests keep compiling:

```dart
export 'package:omnifi_core/omnifi_core.dart' show FakeLinkFactory;

// Existing tests refer to `FakeLink`; keep that name working.
typedef FakeLink = FakeLinkFactory;
```

Add to `packages/omnifi_core/lib/omnifi_core.dart`:

```dart
export 'src/transport/fake_link_factory.dart';
```

- [ ] **Step 3: Run the suite to confirm the rename did not break earlier tasks**

Run: `cd packages/omnifi_core && dart test`
Expected: PASS for Tasks 1–20; the engine test still fails with `OmniFiEngine isn't defined`.

- [ ] **Step 4: Write the engine**

Create `packages/omnifi_core/lib/src/engine/omnifi_engine.dart`:

```dart
import 'dart:async';

import '../crypto/aead_session.dart';
import '../identity/device_identity.dart';
import '../identity/mesh.dart';
import '../identity/secure_store.dart';
import '../pairing/pairing_flow.dart';
import '../pairing/pairing_payload.dart';
import '../session/peer_session.dart';
import '../sync/clipboard_sync.dart';
import '../sync/clipboard_watcher.dart';
import '../transport/lan_link.dart';
import '../transport/link.dart';
import '../transport/link_manager.dart';
import '../transport/relay_link.dart';

class EngineConfig {
  const EngineConfig({
    required this.relayBases,
    required this.displayName,
    this.lanEnabled = true,
  });

  /// Every relay backend to dial, in descending order of preference.
  /// All of them are dialed concurrently and treated as competing
  /// candidate links; whichever answers first with the lowest RTT wins.
  /// There is no explicit failover logic because there does not need to
  /// be — [LinkManager] already ranks candidates, and a relay that is
  /// down simply never becomes a candidate.
  final List<Uri> relayBases;

  final String displayName;
  final bool lanEnabled;

  /// Convenience for the common single-relay case.
  Uri get primaryRelay => relayBases.first;
}

/// Composition root. Everything the UI needs hangs off this one object.
class OmniFiEngine {
  OmniFiEngine._({
    required this.identity,
    required this.mesh,
    required this.config,
    required SecureStore store,
    required ClipboardWatcher watcher,
    required int Function() clock,
  })  : _store = store,
        _clock = clock {
    clipboard = ClipboardSync(
      watcher: watcher,
      peers: () => sessions,
      clock: clock,
    );
  }

  static Future<OmniFiEngine> create({
    required SecureStore store,
    required ClipboardWatcher watcher,
    required EngineConfig config,
    int Function()? clock,
  }) async {
    final resolvedClock =
        clock ?? () => DateTime.now().millisecondsSinceEpoch;
    final identity = await loadOrCreateIdentity(
      store: store,
      displayName: config.displayName,
    );
    final mesh = await loadOrCreateMesh(store: store);
    return OmniFiEngine._(
      identity: identity,
      mesh: mesh,
      config: config,
      store: store,
      watcher: watcher,
      clock: resolvedClock,
    );
  }

  final DeviceIdentity identity;
  final Mesh mesh;
  final EngineConfig config;
  final SecureStore _store;
  final int Function() _clock;

  late final ClipboardSync clipboard;

  final Map<String, PeerSession> _sessions = {};
  final Map<String, LinkManager> _managers = {};
  final Map<String, ConnectionStatus> _peerStatuses = {};
  final StreamController<ConnectionStatus> _statuses =
      StreamController<ConnectionStatus>.broadcast();
  final List<StreamSubscription<Object?>> _subs = [];

  LanListener? _listener;
  bool _started = false;

  List<PeerSession> get sessions => _sessions.values.toList();
  Stream<ConnectionStatus> get statuses => _statuses.stream;

  /// The weakest peer's status. A tray icon that shows "connected" while one
  /// device is unreachable is worse than useless.
  ConnectionStatus get status {
    if (_peerStatuses.isEmpty) return ConnectionStatus.offline;
    const rank = {
      ConnectionStatus.offline: 0,
      ConnectionStatus.reconnecting: 1,
      ConnectionStatus.connectedRelay: 2,
      ConnectionStatus.connectedDirect: 3,
    };
    return _peerStatuses.values
        .reduce((a, b) => rank[a]! <= rank[b]! ? a : b);
  }

  PairingInvite buildInvite() => generateInvite(
        meshId: mesh.meshId,
        inviterPublicKey: identity.keys.publicKey,
        relayHint: config.primaryRelay.toString(),
      );

  Future<void> persist() => saveMesh(mesh, _store);

  Future<void> start() async {
    if (_started) return;
    _started = true;
    await clipboard.start();

    if (config.lanEnabled) {
      _listener = await LanListener.bind(localDeviceId: identity.deviceId);
    }

    for (final peer in mesh.peers) {
      await _connectPeer(peer);
    }
  }

  Future<void> _connectPeer(PeerRecord peer) async {
    // A real session requires a handshake over a link; the manager dials,
    // and the handshake runs on first connect. Sessions created here start
    // detached and become live when a link is adopted.
    final session = _sessions.putIfAbsent(
      peer.deviceId,
      () => PeerSession(
        localDeviceId: identity.deviceId,
        peerDeviceId: peer.deviceId,
        crypto: AeadSession(
          sendKey: List<int>.filled(32, 0),
          receiveKey: List<int>.filled(32, 0),
        ),
        clock: _clock,
      ),
    );

    _subs.add(session.inbound.listen(clipboard.handleIncoming));

    final manager = LinkManager(
      session: session,
      clock: _clock,
      // One dialer per configured relay backend. Two relays are two
      // candidate links, not a primary plus a failover path: LinkManager
      // already prefers LAN over any relay, and ranks relays against each
      // other by measured RTT. Adding a backend costs one list entry.
      dialers: [
        for (final relayBase in config.relayBases)
          () => RelayLink.connect(
                relayBase: relayBase,
                meshId: mesh.meshId,
                localDeviceId: identity.deviceId,
                peerDeviceId: peer.deviceId,
              ),
      ],
    );
    _managers[peer.deviceId] = manager;
    _subs.add(manager.statuses.listen((s) {
      _peerStatuses[peer.deviceId] = s;
      _statuses.add(status);
    }));
    _peerStatuses[peer.deviceId] = manager.status;
    await manager.start();
  }

  Future<PairingSasPending> beginInvite(Link link) => PairingFlow.invite(
        identity: identity,
        mesh: mesh,
        invite: buildInvite(),
        link: link,
      );

  Future<PairingSasPending> beginJoin(
    PairingInvite invite,
    Link link,
  ) =>
      PairingFlow.join(identity: identity, invite: invite, link: link);

  Future<void> forgetPeer(String deviceId) async {
    mesh.removePeer(deviceId);
    await persist();
    await _managers.remove(deviceId)?.stop();
    await _sessions.remove(deviceId)?.dispose();
    _peerStatuses.remove(deviceId);
    _statuses.add(status);
  }

  Future<void> onWake() async {
    for (final manager in _managers.values) {
      await manager.onWake();
    }
  }

  void onScreenLocked() => clipboard.onScreenLocked();
  void onScreenUnlocked() => clipboard.onScreenUnlocked();

  Future<void> stop() async {
    _started = false;
    for (final sub in _subs) {
      await sub.cancel();
    }
    _subs.clear();
    for (final manager in _managers.values) {
      await manager.stop();
    }
    _managers.clear();
    for (final session in _sessions.values) {
      await session.dispose();
    }
    _sessions.clear();
    _peerStatuses.clear();
    await _listener?.close();
    await clipboard.stop();
    _statuses.add(ConnectionStatus.offline);
  }

  // ---- Test seams. Not for production use. ----

  void debugSetPeerStatus(String deviceId, ConnectionStatus status) {
    _peerStatuses[deviceId] = status;
  }

  PeerSession debugAttachSession({
    required String peerDeviceId,
    required AeadSession crypto,
  }) {
    final session = PeerSession(
      localDeviceId: identity.deviceId,
      peerDeviceId: peerDeviceId,
      crypto: crypto,
      clock: _clock,
    );
    _sessions[peerDeviceId] = session;
    _subs.add(session.inbound.listen(clipboard.handleIncoming));
    return session;
  }
}
```

- [ ] **Step 5: Export it**

Modify `packages/omnifi_core/lib/omnifi_core.dart` — add:

```dart
export 'src/engine/omnifi_engine.dart';
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd packages/omnifi_core && dart test test/engine/omnifi_engine_test.dart`
Expected: PASS — `+10: All tests passed!`

- [ ] **Step 7: Run the whole suite**

Run: `cd packages/omnifi_core && dart test`
Expected: PASS.

- [ ] **Step 8: Analyze and commit**

```bash
cd packages/omnifi_core && dart analyze
cd ../.. && git add packages/omnifi_core
git commit -m "feat: add OmniFiEngine composition root with worst-peer status"
```

---

## Task 22: Flutter app shell with status UI and pairing screen

**Files:**
- Create: `apps/omnifi_app/pubspec.yaml`
- Create: `apps/omnifi_app/lib/main.dart`
- Create: `apps/omnifi_app/lib/app.dart`
- Create: `apps/omnifi_app/lib/engine_provider.dart`
- Create: `apps/omnifi_app/lib/ui/status_indicator.dart`
- Create: `apps/omnifi_app/lib/ui/pairing_screen.dart`
- Create: `apps/omnifi_app/lib/ui/settings_screen.dart`
- Test: `apps/omnifi_app/test/status_indicator_test.dart`
- Test: `apps/omnifi_app/test/pairing_screen_test.dart`

**Interfaces:**
- Consumes: `OmniFiEngine`, `ConnectionStatus`, `PairingSasPending`, `formatSas` from `omnifi_core`.
- Produces:
  - `class StatusIndicator extends StatelessWidget` — takes `ConnectionStatus`, renders an icon plus one of exactly four labels: `Connected (direct)`, `Connected (relay)`, `Reconnecting…`, `Offline`.
  - `class PairingScreen extends StatefulWidget` — shows the invite QR and word phrase, then the SAS confirm/deny pair of buttons.
  - `class SettingsScreen extends StatelessWidget` — pause toggle, peer list with a Forget action, relay URL field.

- [ ] **Step 1: Create the Flutter project**

Run:

```bash
mkdir -p apps && cd apps
flutter create --platforms=macos,windows,ios --org com.omnifi omnifi_app
```

- [ ] **Step 2: Wire the dependency and add QR support**

Modify `apps/omnifi_app/pubspec.yaml` — set the `dependencies:` block to:

```yaml
dependencies:
  flutter:
    sdk: flutter
  omnifi_core:
    path: ../../packages/omnifi_core
  qr_flutter: ^4.1.0
  mobile_scanner: ^5.2.3
```

Run: `cd apps/omnifi_app && flutter pub get`

- [ ] **Step 3: Write the failing widget tests**

Create `apps/omnifi_app/test/status_indicator_test.dart`:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:omnifi_app/ui/status_indicator.dart';
import 'package:omnifi_core/omnifi_core.dart';

Future<void> pump(WidgetTester tester, ConnectionStatus status) =>
    tester.pumpWidget(MaterialApp(
      home: Scaffold(body: StatusIndicator(status: status)),
    ));

void main() {
  testWidgets('shows the direct label', (tester) async {
    await pump(tester, ConnectionStatus.connectedDirect);
    expect(find.text('Connected (direct)'), findsOneWidget);
  });

  testWidgets('shows the relay label', (tester) async {
    await pump(tester, ConnectionStatus.connectedRelay);
    expect(find.text('Connected (relay)'), findsOneWidget);
  });

  testWidgets('shows the reconnecting label', (tester) async {
    await pump(tester, ConnectionStatus.reconnecting);
    expect(find.text('Reconnecting…'), findsOneWidget);
  });

  testWidgets('shows the offline label', (tester) async {
    await pump(tester, ConnectionStatus.offline);
    expect(find.text('Offline'), findsOneWidget);
  });

  testWidgets('distinguishes direct from relay visually', (tester) async {
    await pump(tester, ConnectionStatus.connectedDirect);
    final direct = tester.widget<Icon>(find.byType(Icon)).color;
    await pump(tester, ConnectionStatus.connectedRelay);
    final relay = tester.widget<Icon>(find.byType(Icon)).color;
    expect(direct, isNot(relay));
  });
}
```

Create `apps/omnifi_app/test/pairing_screen_test.dart`:

```dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:omnifi_app/ui/pairing_screen.dart';

void main() {
  testWidgets('renders the five SAS words', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: SasConfirmation(
        words: const ['able', 'brisk', 'cedar', 'delta', 'eagle'],
        onConfirm: () {},
        onReject: () {},
      ),
    ));
    expect(find.text('able brisk cedar delta eagle'), findsOneWidget);
  });

  testWidgets('confirm and reject both fire', (tester) async {
    var confirmed = false;
    var rejected = false;
    await tester.pumpWidget(MaterialApp(
      home: SasConfirmation(
        words: const ['able', 'brisk', 'cedar', 'delta', 'eagle'],
        onConfirm: () => confirmed = true,
        onReject: () => rejected = true,
      ),
    ));

    await tester.tap(find.text('They match'));
    await tester.pump();
    expect(confirmed, isTrue);

    await tester.tap(find.text("They don't match"));
    await tester.pump();
    expect(rejected, isTrue);
  });

  testWidgets('tells the user what the comparison is for', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: SasConfirmation(
        words: const ['able', 'brisk', 'cedar', 'delta', 'eagle'],
        onConfirm: () {},
        onReject: () {},
      ),
    ));
    expect(
      find.textContaining('same words'),
      findsOneWidget,
      reason: 'the user must know they are comparing two screens',
    );
  });
}
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `cd apps/omnifi_app && flutter test`
Expected: FAIL — `StatusIndicator` and `SasConfirmation` not found.

- [ ] **Step 5: Write the status indicator**

Create `apps/omnifi_app/lib/ui/status_indicator.dart`:

```dart
import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';

/// The single most important widget in the app: when OmniFi misbehaves,
/// the first question is always whether it is even connected.
class StatusIndicator extends StatelessWidget {
  const StatusIndicator({super.key, required this.status});

  final ConnectionStatus status;

  static const Map<ConnectionStatus, String> _labels = {
    ConnectionStatus.connectedDirect: 'Connected (direct)',
    ConnectionStatus.connectedRelay: 'Connected (relay)',
    ConnectionStatus.reconnecting: 'Reconnecting…',
    ConnectionStatus.offline: 'Offline',
  };

  static const Map<ConnectionStatus, IconData> _icons = {
    ConnectionStatus.connectedDirect: Icons.bolt,
    ConnectionStatus.connectedRelay: Icons.cloud_done,
    ConnectionStatus.reconnecting: Icons.sync,
    ConnectionStatus.offline: Icons.cloud_off,
  };

  static const Map<ConnectionStatus, Color> _colors = {
    ConnectionStatus.connectedDirect: Color(0xFF2E7D32),
    ConnectionStatus.connectedRelay: Color(0xFF0277BD),
    ConnectionStatus.reconnecting: Color(0xFFEF6C00),
    ConnectionStatus.offline: Color(0xFF757575),
  };

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(_icons[status], color: _colors[status], size: 18),
        const SizedBox(width: 8),
        Text(_labels[status]!),
      ],
    );
  }
}
```

- [ ] **Step 6: Write the pairing screen**

Create `apps/omnifi_app/lib/ui/pairing_screen.dart`:

```dart
import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';
import 'package:qr_flutter/qr_flutter.dart';

/// Displays the invite for another device to scan.
class InviteDisplay extends StatelessWidget {
  const InviteDisplay({super.key, required this.invite});

  final PairingInvite invite;

  @override
  Widget build(BuildContext context) {
    final uri = encodeInviteUri(invite);
    final words = encodeInviteWords(invite).join(' ');
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Text('Scan this on the device you want to add.'),
        const SizedBox(height: 16),
        QrImageView(data: uri, size: 240),
        const SizedBox(height: 16),
        const Text('No camera? Type this phrase instead:'),
        const SizedBox(height: 8),
        SelectableText(words,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 16)),
      ],
    );
  }
}

/// The mandatory confirmation step. Both devices show the same words; the
/// user comparing them is what makes the pairing resistant to an attacker
/// who observed or relayed the QR code.
class SasConfirmation extends StatelessWidget {
  const SasConfirmation({
    super.key,
    required this.words,
    required this.onConfirm,
    required this.onReject,
  });

  final List<String> words;
  final VoidCallback onConfirm;
  final VoidCallback onReject;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Check that both devices show the same words. '
                'If they differ, someone may be intercepting the pairing.',
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              SelectableText(
                formatSas(words),
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 22,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 32),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  OutlinedButton(
                    onPressed: onReject,
                    child: const Text("They don't match"),
                  ),
                  const SizedBox(width: 16),
                  FilledButton(
                    onPressed: onConfirm,
                    child: const Text('They match'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
```

- [ ] **Step 7: Run the widget tests to verify they pass**

Run: `cd apps/omnifi_app && flutter test`
Expected: PASS — 8 tests.

- [ ] **Step 8: Write the settings screen and app shell**

Create `apps/omnifi_app/lib/ui/settings_screen.dart`:

```dart
import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, required this.engine});
  final OmniFiEngine engine;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  @override
  Widget build(BuildContext context) {
    final engine = widget.engine;
    return Scaffold(
      appBar: AppBar(title: const Text('OmniFi')),
      body: ListView(
        children: [
          SwitchListTile(
            title: const Text('Pause clipboard sync'),
            value: engine.clipboard.isPaused,
            onChanged: (v) => setState(() => engine.clipboard.setPaused(v)),
          ),
          const Divider(),
          for (final peer in engine.mesh.peers)
            ListTile(
              title: Text(peer.displayName),
              subtitle: Text(peer.deviceId.substring(0, 8)),
              trailing: TextButton(
                onPressed: () async {
                  await engine.forgetPeer(peer.deviceId);
                  if (mounted) setState(() {});
                },
                child: const Text('Forget'),
              ),
            ),
        ],
      ),
    );
  }
}
```

Create `apps/omnifi_app/lib/app.dart`:

```dart
import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';

import 'ui/settings_screen.dart';
import 'ui/status_indicator.dart';

class OmniFiApp extends StatelessWidget {
  const OmniFiApp({super.key, required this.engine});
  final OmniFiEngine engine;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OmniFi',
      theme: ThemeData(useMaterial3: true),
      home: StreamBuilder<ConnectionStatus>(
        stream: engine.statuses,
        initialData: engine.status,
        builder: (context, snapshot) => Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(12),
              child: StatusIndicator(
                  status: snapshot.data ?? ConnectionStatus.offline),
            ),
            Expanded(child: SettingsScreen(engine: engine)),
          ],
        ),
      ),
    );
  }
}
```

- [ ] **Step 9: Verify the app analyzes and builds for macOS**

Run: `cd apps/omnifi_app && flutter analyze && flutter build macos --debug`
Expected: analyzer reports no issues; the build succeeds.

- [ ] **Step 10: Commit**

```bash
cd ../.. && cat >> .gitignore <<'EOF'
apps/omnifi_app/.dart_tool/
apps/omnifi_app/build/
EOF
git add apps .gitignore
git commit -m "feat: add Flutter app shell with status indicator and SAS screen"
```

---

## Task 23: macOS platform layer — Keychain, pasteboard, sleep/wake, menu bar

**Files:**
- Create: `apps/omnifi_app/lib/platform/secure_store_impl.dart`
- Create: `apps/omnifi_app/lib/platform/clipboard_watcher_impl.dart`
- Create: `apps/omnifi_app/lib/platform/power_events.dart`
- Create: `apps/omnifi_app/macos/Runner/SecureStorePlugin.swift`
- Create: `apps/omnifi_app/macos/Runner/ClipboardPlugin.swift`
- Create: `apps/omnifi_app/macos/Runner/PowerPlugin.swift`
- Modify: `apps/omnifi_app/macos/Runner/AppDelegate.swift`
- Modify: `apps/omnifi_app/macos/Runner/DebugProfile.entitlements`
- Modify: `apps/omnifi_app/macos/Runner/Release.entitlements`
- Modify: `apps/omnifi_app/lib/main.dart`
- Test: `apps/omnifi_app/test/platform/channel_contract_test.dart`

**Interfaces:**
- Consumes: `SecureStore`, `ClipboardWatcher`, `ClipboardContent` from `omnifi_core`.
- Produces:
  - `class PlatformSecureStore implements SecureStore` — method channel `com.omnifi/secure_store`, methods `read`/`write`/`delete`.
  - `class PlatformClipboardWatcher implements ClipboardWatcher` — method channel `com.omnifi/clipboard` (`write`, `start`, `stop`) and event channel `com.omnifi/clipboard/changes` emitting `{format, data, concealed}`.
  - `class PowerEvents` — event channel `com.omnifi/power` emitting `'wake'`, `'sleep'`, `'lock'`, `'unlock'`.

**Critical entitlement note:** the macOS app must have App Sandbox **disabled** and network client/server enabled. Sandbox blocks the Full Disk Access that project 2's `chat.db` reader will need, and blocks binding a LAN listener. This is also why the app can never ship through the Mac App Store — plan on direct notarized distribution.

- [ ] **Step 1: Write the Dart-side channel contract test**

Create `apps/omnifi_app/test/platform/channel_contract_test.dart`:

```dart
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:omnifi_app/platform/clipboard_watcher_impl.dart';
import 'package:omnifi_app/platform/secure_store_impl.dart';
import 'package:omnifi_core/omnifi_core.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const secureChannel = MethodChannel('com.omnifi/secure_store');
  const clipboardChannel = MethodChannel('com.omnifi/clipboard');

  final calls = <MethodCall>[];

  setUp(() {
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(secureChannel, (call) async {
      calls.add(call);
      if (call.method == 'read') return 'stored-value';
      return null;
    });
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(clipboardChannel, (call) async {
      calls.add(call);
      return null;
    });
  });

  test('secure store read passes the key through', () async {
    final store = PlatformSecureStore();
    expect(await store.read('omnifi.identity.deviceId'), 'stored-value');
    expect(calls.single.method, 'read');
    expect(calls.single.arguments, {'key': 'omnifi.identity.deviceId'});
  });

  test('secure store write passes key and value', () async {
    await PlatformSecureStore().write('k', 'v');
    expect(calls.single.method, 'write');
    expect(calls.single.arguments, {'key': 'k', 'value': 'v'});
  });

  test('secure store delete passes the key', () async {
    await PlatformSecureStore().delete('k');
    expect(calls.single.method, 'delete');
    expect(calls.single.arguments, {'key': 'k'});
  });

  test('clipboard write passes format and bytes', () async {
    await PlatformClipboardWatcher().write(ClipboardContent(
      format: 'text',
      data: Uint8List.fromList([104, 105]),
      isConcealed: false,
    ));
    expect(calls.single.method, 'write');
    final args = calls.single.arguments as Map;
    expect(args['format'], 'text');
    expect(args['data'], [104, 105]);
  });

  test('the store satisfies the core interface', () {
    expect(PlatformSecureStore(), isA<SecureStore>());
    expect(PlatformClipboardWatcher(), isA<ClipboardWatcher>());
  });
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd apps/omnifi_app && flutter test test/platform/channel_contract_test.dart`
Expected: FAIL — `PlatformSecureStore` not found.

- [ ] **Step 3: Write the Dart platform implementations**

Create `apps/omnifi_app/lib/platform/secure_store_impl.dart`:

```dart
import 'package:flutter/services.dart';
import 'package:omnifi_core/omnifi_core.dart';

/// Keychain on macOS/iOS, Credential Manager on Windows. Key material never
/// reaches a plain file through this path.
class PlatformSecureStore implements SecureStore {
  static const MethodChannel _channel =
      MethodChannel('com.omnifi/secure_store');

  @override
  Future<String?> read(String key) async =>
      _channel.invokeMethod<String>('read', {'key': key});

  @override
  Future<void> write(String key, String value) async =>
      _channel.invokeMethod<void>('write', {'key': key, 'value': value});

  @override
  Future<void> delete(String key) async =>
      _channel.invokeMethod<void>('delete', {'key': key});
}
```

Create `apps/omnifi_app/lib/platform/clipboard_watcher_impl.dart`:

```dart
import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:omnifi_core/omnifi_core.dart';

class PlatformClipboardWatcher implements ClipboardWatcher {
  static const MethodChannel _methods =
      MethodChannel('com.omnifi/clipboard');
  static const EventChannel _events =
      EventChannel('com.omnifi/clipboard/changes');

  @override
  Stream<ClipboardContent> get changes =>
      _events.receiveBroadcastStream().map((event) {
        final map = event as Map;
        return ClipboardContent(
          format: map['format'] as String,
          data: Uint8List.fromList(
              (map['data'] as List).cast<int>()),
          isConcealed: map['concealed'] as bool? ?? false,
        );
      });

  @override
  Future<void> write(ClipboardContent content) async =>
      _methods.invokeMethod<void>('write', {
        'format': content.format,
        'data': content.data,
      });

  @override
  Future<void> start() async => _methods.invokeMethod<void>('start');

  @override
  Future<void> stop() async => _methods.invokeMethod<void>('stop');
}
```

Create `apps/omnifi_app/lib/platform/power_events.dart`:

```dart
import 'package:flutter/services.dart';

/// Sleep, wake, lock and unlock notifications from the host OS.
///
/// Wake matters because sockets are suspended on sleep without notifying
/// the peer, so the app must tear down rather than wait out a timeout.
class PowerEvents {
  static const EventChannel _events = EventChannel('com.omnifi/power');

  Stream<String> get events =>
      _events.receiveBroadcastStream().map((e) => e as String);
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd apps/omnifi_app && flutter test test/platform/channel_contract_test.dart`
Expected: PASS — 5 tests.

- [ ] **Step 5: Write the macOS Keychain plugin**

Create `apps/omnifi_app/macos/Runner/SecureStorePlugin.swift`:

```swift
import FlutterMacOS
import Foundation
import Security

/// Keychain-backed secret storage. Values are stored as generic passwords
/// under the service "com.omnifi.keys".
class SecureStorePlugin: NSObject, FlutterPlugin {
  private static let service = "com.omnifi.keys"

  static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(
      name: "com.omnifi/secure_store",
      binaryMessenger: registrar.messenger)
    registrar.addMethodCallDelegate(SecureStorePlugin(), channel: channel)
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let key = args["key"] as? String else {
      result(FlutterError(code: "bad_args", message: "key required",
                          details: nil))
      return
    }

    switch call.method {
    case "read":
      result(read(key: key))
    case "write":
      guard let value = args["value"] as? String else {
        result(FlutterError(code: "bad_args", message: "value required",
                            details: nil))
        return
      }
      write(key: key, value: value)
      result(nil)
    case "delete":
      delete(key: key)
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func query(key: String) -> [String: Any] {
    return [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: SecureStorePlugin.service,
      kSecAttrAccount as String: key,
    ]
  }

  private func read(key: String) -> String? {
    var q = query(key: key)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
          let data = item as? Data else { return nil }
    return String(data: data, encoding: .utf8)
  }

  private func write(key: String, value: String) {
    delete(key: key)
    var q = query(key: key)
    q[kSecValueData as String] = value.data(using: .utf8)
    q[kSecAttrAccessible as String] =
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    SecItemAdd(q as CFDictionary, nil)
  }

  private func delete(key: String) {
    SecItemDelete(query(key: key) as CFDictionary)
  }
}
```

- [ ] **Step 6: Write the macOS pasteboard plugin**

Create `apps/omnifi_app/macos/Runner/ClipboardPlugin.swift`:

```swift
import AppKit
import FlutterMacOS
import Foundation

/// macOS has no clipboard change notification, so this polls
/// NSPasteboard.changeCount at 500ms — the standard approach.
class ClipboardPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  private var sink: FlutterEventSink?
  private var timer: Timer?
  private var lastChangeCount: Int = NSPasteboard.general.changeCount

  /// Password managers mark entries with this type; we must never sync them.
  private static let concealedType =
    NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")

  static func register(with registrar: FlutterPluginRegistrar) {
    let instance = ClipboardPlugin()
    let methods = FlutterMethodChannel(
      name: "com.omnifi/clipboard", binaryMessenger: registrar.messenger)
    registrar.addMethodCallDelegate(instance, channel: methods)
    let events = FlutterEventChannel(
      name: "com.omnifi/clipboard/changes",
      binaryMessenger: registrar.messenger)
    events.setStreamHandler(instance)
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "start":
      startPolling()
      result(nil)
    case "stop":
      timer?.invalidate()
      timer = nil
      result(nil)
    case "write":
      guard let args = call.arguments as? [String: Any],
            let format = args["format"] as? String,
            let data = args["data"] as? FlutterStandardTypedData else {
        result(FlutterError(code: "bad_args", message: nil, details: nil))
        return
      }
      write(format: format, data: data.data)
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func write(format: String, data: Data) {
    let pb = NSPasteboard.general
    pb.clearContents()
    if format == "text" {
      pb.setString(String(data: data, encoding: .utf8) ?? "",
                   forType: .string)
    } else if format == "png" {
      pb.setData(data, forType: .png)
    }
    lastChangeCount = pb.changeCount
  }

  private func startPolling() {
    timer?.invalidate()
    timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) {
      [weak self] _ in self?.poll()
    }
  }

  private func poll() {
    let pb = NSPasteboard.general
    guard pb.changeCount != lastChangeCount else { return }
    lastChangeCount = pb.changeCount
    guard let sink = sink else { return }

    let concealed = pb.types?.contains(ClipboardPlugin.concealedType)
      ?? false

    if let png = pb.data(forType: .png) {
      sink(["format": "png",
            "data": FlutterStandardTypedData(bytes: png),
            "concealed": concealed])
    } else if let text = pb.string(forType: .string) {
      sink(["format": "text",
            "data": FlutterStandardTypedData(bytes: Data(text.utf8)),
            "concealed": concealed])
    }
  }

  func onListen(withArguments arguments: Any?,
                eventSink events: @escaping FlutterEventSink)
      -> FlutterError? {
    sink = events
    return nil
  }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    sink = nil
    return nil
  }
}
```

- [ ] **Step 7: Write the macOS power plugin**

Create `apps/omnifi_app/macos/Runner/PowerPlugin.swift`:

```swift
import AppKit
import FlutterMacOS
import Foundation

class PowerPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  private var sink: FlutterEventSink?

  static func register(with registrar: FlutterPluginRegistrar) {
    let instance = PowerPlugin()
    let events = FlutterEventChannel(
      name: "com.omnifi/power", binaryMessenger: registrar.messenger)
    events.setStreamHandler(instance)
  }

  func onListen(withArguments arguments: Any?,
                eventSink events: @escaping FlutterEventSink)
      -> FlutterError? {
    sink = events
    let workspace = NSWorkspace.shared.notificationCenter
    workspace.addObserver(
      self, selector: #selector(onWake),
      name: NSWorkspace.didWakeNotification, object: nil)
    workspace.addObserver(
      self, selector: #selector(onSleep),
      name: NSWorkspace.willSleepNotification, object: nil)

    let distributed = DistributedNotificationCenter.default()
    distributed.addObserver(
      self, selector: #selector(onLock),
      name: NSNotification.Name("com.apple.screenIsLocked"), object: nil)
    distributed.addObserver(
      self, selector: #selector(onUnlock),
      name: NSNotification.Name("com.apple.screenIsUnlocked"), object: nil)
    return nil
  }

  @objc private func onWake() { sink?("wake") }
  @objc private func onSleep() { sink?("sleep") }
  @objc private func onLock() { sink?("lock") }
  @objc private func onUnlock() { sink?("unlock") }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    NSWorkspace.shared.notificationCenter.removeObserver(self)
    DistributedNotificationCenter.default().removeObserver(self)
    sink = nil
    return nil
  }
}
```

- [ ] **Step 8: Register the plugins**

Modify `apps/omnifi_app/macos/Runner/AppDelegate.swift` — add inside `applicationDidFinishLaunching`, or add the override if it is absent:

```swift
  override func applicationDidFinishLaunching(_ notification: Notification) {
    let controller = mainFlutterWindow?.contentViewController
      as! FlutterViewController
    SecureStorePlugin.register(
      with: controller.registrar(forPlugin: "SecureStorePlugin"))
    ClipboardPlugin.register(
      with: controller.registrar(forPlugin: "ClipboardPlugin"))
    PowerPlugin.register(
      with: controller.registrar(forPlugin: "PowerPlugin"))
    super.applicationDidFinishLaunching(notification)
  }
```

- [ ] **Step 9: Fix the entitlements**

Replace the contents of both `apps/omnifi_app/macos/Runner/DebugProfile.entitlements` and `apps/omnifi_app/macos/Runner/Release.entitlements` with:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.app-sandbox</key>
  <false/>
  <key>com.apple.security.network.client</key>
  <true/>
  <key>com.apple.security.network.server</key>
  <true/>
</dict>
</plist>
```

App Sandbox is off deliberately: it blocks the LAN listener, and it would block the `chat.db` access that project 2 needs. The consequence — no Mac App Store distribution — is accepted in the spec.

- [ ] **Step 10: Wire main.dart**

Create `apps/omnifi_app/lib/main.dart`:

```dart
import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';

import 'app.dart';
import 'platform/clipboard_watcher_impl.dart';
import 'platform/power_events.dart';
import 'platform/secure_store_impl.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final engine = await OmniFiEngine.create(
    store: PlatformSecureStore(),
    watcher: PlatformClipboardWatcher(),
    config: EngineConfig(
      // Cloudflare first, ARC second. Both are dialed; the faster one wins.
      // A relay that is down never becomes a candidate link, so an outage
      // on either backend is invisible to the user.
      relayBases: [
        Uri.parse(const String.fromEnvironment(
          'OMNIFI_RELAY',
          defaultValue: 'https://omnifi-relay.workers.dev',
        )),
        Uri.parse(const String.fromEnvironment(
          'OMNIFI_RELAY_FALLBACK',
          defaultValue: 'https://arc.ailuxis.com',
        )),
      ],
      displayName: 'OmniFi Device',
    ),
  );

  PowerEvents().events.listen((event) async {
    switch (event) {
      case 'wake':
        await engine.onWake();
      case 'lock':
        engine.onScreenLocked();
      case 'unlock':
        engine.onScreenUnlocked();
    }
  });

  await engine.start();
  runApp(OmniFiApp(engine: engine));
}
```

- [ ] **Step 11: Build and run on macOS**

Run: `cd apps/omnifi_app && flutter run -d macos`
Expected: the app launches and shows `Offline` (no peers yet). Copy some text and confirm no crash; the console should show no channel errors.

- [ ] **Step 12: Analyze and commit**

```bash
cd apps/omnifi_app && flutter analyze
cd ../.. && git add apps
git commit -m "feat: add macOS keychain, pasteboard and power event plugins"
```

---

## Task 24: Windows platform layer — Credential Manager, clipboard listener, tray

**Files:**
- Create: `apps/omnifi_app/windows/runner/secure_store_plugin.cpp`
- Create: `apps/omnifi_app/windows/runner/secure_store_plugin.h`
- Create: `apps/omnifi_app/windows/runner/clipboard_plugin.cpp`
- Create: `apps/omnifi_app/windows/runner/clipboard_plugin.h`
- Modify: `apps/omnifi_app/windows/runner/flutter_window.cpp`
- Modify: `apps/omnifi_app/windows/CMakeLists.txt`

**Interfaces:**
- Consumes: the same channel names as Task 23. The Dart side is already written and unchanged — that is the point of putting the interface in the core.
- Produces: native implementations of `com.omnifi/secure_store`, `com.omnifi/clipboard`, `com.omnifi/clipboard/changes`.

Windows has a real clipboard event (`AddClipboardFormatListener`), so no polling. The concealed-content format to honor is `ExcludeClipboardContentFromMonitorProcessing`.

- [ ] **Step 1: Write the Credential Manager plugin header**

Create `apps/omnifi_app/windows/runner/secure_store_plugin.h`:

```cpp
#ifndef OMNIFI_SECURE_STORE_PLUGIN_H_
#define OMNIFI_SECURE_STORE_PLUGIN_H_

#include <flutter/binary_messenger.h>

void RegisterSecureStorePlugin(flutter::BinaryMessenger* messenger);

#endif  // OMNIFI_SECURE_STORE_PLUGIN_H_
```

- [ ] **Step 2: Write the Credential Manager plugin**

Create `apps/omnifi_app/windows/runner/secure_store_plugin.cpp`:

```cpp
#include "secure_store_plugin.h"

#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>
#include <windows.h>
#include <wincred.h>

#include <memory>
#include <string>

namespace {

// Credentials are stored under "OmniFi/<key>" and protected by DPAPI,
// which ties them to the current Windows user account.
std::wstring TargetName(const std::string& key) {
  std::wstring target = L"OmniFi/";
  target.append(key.begin(), key.end());
  return target;
}

std::unique_ptr<std::string> ReadCredential(const std::string& key) {
  PCREDENTIALW cred = nullptr;
  if (!CredReadW(TargetName(key).c_str(), CRED_TYPE_GENERIC, 0, &cred)) {
    return nullptr;
  }
  auto value = std::make_unique<std::string>(
      reinterpret_cast<char*>(cred->CredentialBlob),
      cred->CredentialBlobSize);
  CredFree(cred);
  return value;
}

void WriteCredential(const std::string& key, const std::string& value) {
  std::wstring target = TargetName(key);
  CREDENTIALW cred = {};
  cred.Type = CRED_TYPE_GENERIC;
  cred.TargetName = const_cast<LPWSTR>(target.c_str());
  cred.CredentialBlobSize = static_cast<DWORD>(value.size());
  cred.CredentialBlob = reinterpret_cast<LPBYTE>(
      const_cast<char*>(value.data()));
  cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
  CredWriteW(&cred, 0);
}

void DeleteCredential(const std::string& key) {
  CredDeleteW(TargetName(key).c_str(), CRED_TYPE_GENERIC, 0);
}

}  // namespace

void RegisterSecureStorePlugin(flutter::BinaryMessenger* messenger) {
  auto channel = std::make_shared<
      flutter::MethodChannel<flutter::EncodableValue>>(
      messenger, "com.omnifi/secure_store",
      &flutter::StandardMethodCodec::GetInstance());

  channel->SetMethodCallHandler(
      [](const flutter::MethodCall<flutter::EncodableValue>& call,
         std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>
             result) {
        const auto* args =
            std::get_if<flutter::EncodableMap>(call.arguments());
        if (!args) {
          result->Error("bad_args", "expected a map");
          return;
        }
        auto key_it = args->find(flutter::EncodableValue("key"));
        if (key_it == args->end()) {
          result->Error("bad_args", "key required");
          return;
        }
        const auto key = std::get<std::string>(key_it->second);

        if (call.method_name() == "read") {
          auto value = ReadCredential(key);
          if (value) {
            result->Success(flutter::EncodableValue(*value));
          } else {
            result->Success(flutter::EncodableValue());
          }
        } else if (call.method_name() == "write") {
          auto value_it = args->find(flutter::EncodableValue("value"));
          if (value_it == args->end()) {
            result->Error("bad_args", "value required");
            return;
          }
          WriteCredential(key, std::get<std::string>(value_it->second));
          result->Success();
        } else if (call.method_name() == "delete") {
          DeleteCredential(key);
          result->Success();
        } else {
          result->NotImplemented();
        }
      });

  // Keep the channel alive for the process lifetime.
  static std::shared_ptr<
      flutter::MethodChannel<flutter::EncodableValue>> retained;
  retained = channel;
}
```

- [ ] **Step 3: Write the clipboard plugin header**

Create `apps/omnifi_app/windows/runner/clipboard_plugin.h`:

```cpp
#ifndef OMNIFI_CLIPBOARD_PLUGIN_H_
#define OMNIFI_CLIPBOARD_PLUGIN_H_

#include <flutter/binary_messenger.h>
#include <windows.h>

void RegisterClipboardPlugin(flutter::BinaryMessenger* messenger,
                             HWND window);

// Call from the window procedure for WM_CLIPBOARDUPDATE.
void OnClipboardUpdate();

#endif  // OMNIFI_CLIPBOARD_PLUGIN_H_
```

- [ ] **Step 4: Write the clipboard plugin**

Create `apps/omnifi_app/windows/runner/clipboard_plugin.cpp`:

```cpp
#include "clipboard_plugin.h"

#include <flutter/event_channel.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/method_channel.h>
#include <flutter/standard_method_codec.h>

#include <memory>
#include <string>
#include <vector>

namespace {

std::unique_ptr<flutter::EventSink<flutter::EncodableValue>> g_sink;
HWND g_window = nullptr;

// Set by password managers to opt out of clipboard history and monitors.
UINT ExcludeFormat() {
  static UINT format = RegisterClipboardFormatW(
      L"ExcludeClipboardContentFromMonitorProcessing");
  return format;
}

std::string ReadClipboardText() {
  if (!OpenClipboard(g_window)) return {};
  std::string out;
  HANDLE handle = GetClipboardData(CF_UNICODETEXT);
  if (handle) {
    auto* wide = static_cast<wchar_t*>(GlobalLock(handle));
    if (wide) {
      int size = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0,
                                     nullptr, nullptr);
      if (size > 1) {
        out.resize(size - 1);
        WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), size,
                            nullptr, nullptr);
      }
      GlobalUnlock(handle);
    }
  }
  CloseClipboard();
  return out;
}

void WriteClipboardText(const std::string& utf8) {
  int wide_size =
      MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
  if (wide_size <= 0) return;
  HGLOBAL global = GlobalAlloc(GMEM_MOVEABLE, wide_size * sizeof(wchar_t));
  if (!global) return;
  auto* dest = static_cast<wchar_t*>(GlobalLock(global));
  MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, dest, wide_size);
  GlobalUnlock(global);

  if (OpenClipboard(g_window)) {
    EmptyClipboard();
    SetClipboardData(CF_UNICODETEXT, global);
    CloseClipboard();
  } else {
    GlobalFree(global);
  }
}

}  // namespace

void OnClipboardUpdate() {
  if (!g_sink) return;

  bool concealed = IsClipboardFormatAvailable(ExcludeFormat());
  std::string text = ReadClipboardText();
  if (text.empty() && !concealed) return;

  std::vector<uint8_t> bytes(text.begin(), text.end());
  flutter::EncodableMap event = {
      {flutter::EncodableValue("format"), flutter::EncodableValue("text")},
      {flutter::EncodableValue("data"), flutter::EncodableValue(bytes)},
      {flutter::EncodableValue("concealed"),
       flutter::EncodableValue(concealed)},
  };
  g_sink->Success(flutter::EncodableValue(event));
}

void RegisterClipboardPlugin(flutter::BinaryMessenger* messenger,
                             HWND window) {
  g_window = window;
  AddClipboardFormatListener(window);

  auto methods = std::make_shared<
      flutter::MethodChannel<flutter::EncodableValue>>(
      messenger, "com.omnifi/clipboard",
      &flutter::StandardMethodCodec::GetInstance());

  methods->SetMethodCallHandler(
      [](const flutter::MethodCall<flutter::EncodableValue>& call,
         std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>>
             result) {
        if (call.method_name() == "write") {
          const auto* args =
              std::get_if<flutter::EncodableMap>(call.arguments());
          if (!args) {
            result->Error("bad_args", "expected a map");
            return;
          }
          auto data_it = args->find(flutter::EncodableValue("data"));
          if (data_it != args->end()) {
            const auto& bytes =
                std::get<std::vector<uint8_t>>(data_it->second);
            WriteClipboardText(std::string(bytes.begin(), bytes.end()));
          }
          result->Success();
        } else if (call.method_name() == "start" ||
                   call.method_name() == "stop") {
          // Windows delivers WM_CLIPBOARDUPDATE unconditionally once the
          // listener is registered, so these are no-ops.
          result->Success();
        } else {
          result->NotImplemented();
        }
      });

  auto events = std::make_shared<
      flutter::EventChannel<flutter::EncodableValue>>(
      messenger, "com.omnifi/clipboard/changes",
      &flutter::StandardMethodCodec::GetInstance());

  events->SetStreamHandler(
      std::make_unique<flutter::StreamHandlerFunctions<
          flutter::EncodableValue>>(
          [](const flutter::EncodableValue*,
             std::unique_ptr<flutter::EventSink<flutter::EncodableValue>>&&
                 sink)
              -> std::unique_ptr<
                  flutter::StreamHandlerError<flutter::EncodableValue>> {
            g_sink = std::move(sink);
            return nullptr;
          },
          [](const flutter::EncodableValue*)
              -> std::unique_ptr<
                  flutter::StreamHandlerError<flutter::EncodableValue>> {
            g_sink.reset();
            return nullptr;
          }));

  static std::shared_ptr<
      flutter::MethodChannel<flutter::EncodableValue>> retained_methods;
  static std::shared_ptr<
      flutter::EventChannel<flutter::EncodableValue>> retained_events;
  retained_methods = methods;
  retained_events = events;
}
```

- [ ] **Step 5: Register the plugins and forward the message**

Modify `apps/omnifi_app/windows/runner/flutter_window.cpp`:

Add near the top with the other includes:

```cpp
#include "clipboard_plugin.h"
#include "secure_store_plugin.h"
```

Inside `FlutterWindow::OnCreate()`, after `flutter_controller_->engine()` is available and before the `return true;`:

```cpp
  RegisterSecureStorePlugin(
      flutter_controller_->engine()->messenger());
  RegisterClipboardPlugin(
      flutter_controller_->engine()->messenger(), GetHandle());
```

Inside `FlutterWindow::MessageHandler`, add a case before the existing switch cases:

```cpp
    case WM_CLIPBOARDUPDATE:
      OnClipboardUpdate();
      return 0;
```

- [ ] **Step 6: Add the sources and the credential library to CMake**

Modify `apps/omnifi_app/windows/runner/CMakeLists.txt` — add to the `add_executable` source list:

```cmake
  "clipboard_plugin.cpp"
  "secure_store_plugin.cpp"
```

And add below it:

```cmake
target_link_libraries(${BINARY_NAME} PRIVATE Advapi32.lib Credui.lib)
```

- [ ] **Step 7: Build on Windows**

Run (on a Windows machine): `cd apps/omnifi_app && flutter build windows --debug`
Expected: the build succeeds.

If `Credui.lib` produces an unresolved symbol for `CredReadW`, link `Advapi32.lib` alone — `CredRead`/`CredWrite`/`CredDelete` live in `advapi32` on current Windows SDKs, and `Credui.lib` is only needed for the credential *dialogs* this plugin does not use.

- [ ] **Step 8: Verify the channels at runtime**

Run: `flutter run -d windows`, copy text in another app, and confirm the Dart console shows a clipboard event with `concealed: false`. Then copy from a password manager and confirm `concealed: true`.

- [ ] **Step 9: Commit**

```bash
git add apps/omnifi_app/windows
git commit -m "feat: add Windows credential store and clipboard listener plugins"
```

---

## Task 25: iOS platform layer — foreground-only sync

iOS is a second-class peer by design, per the spec. It connects when foregrounded and disconnects shortly after backgrounding. Do not attempt background sockets here; that work is explicitly deferred.

**Files:**
- Create: `apps/omnifi_app/ios/Runner/SecureStorePlugin.swift`
- Create: `apps/omnifi_app/ios/Runner/ClipboardPlugin.swift`
- Modify: `apps/omnifi_app/ios/Runner/AppDelegate.swift`
- Create: `apps/omnifi_app/lib/platform/lifecycle.dart`
- Modify: `apps/omnifi_app/lib/main.dart`
- Test: `apps/omnifi_app/test/lifecycle_test.dart`

**Interfaces:**
- Consumes: the same channels as Tasks 23 and 24.
- Produces:
  - `class LifecycleBridge` — calls `engine.start()` on resume and `engine.stop()` on pause, so the iOS app holds no socket in the background.

- [ ] **Step 1: Write the failing lifecycle test**

Create `apps/omnifi_app/test/lifecycle_test.dart`:

```dart
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:omnifi_app/platform/lifecycle.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('resume starts and pause stops', () async {
    var starts = 0;
    var stops = 0;
    final bridge = LifecycleBridge(
      onResume: () async => starts++,
      onPause: () async => stops++,
    );

    await bridge.handle(AppLifecycleState.resumed);
    expect(starts, 1);

    await bridge.handle(AppLifecycleState.paused);
    expect(stops, 1);
  });

  test('repeated resumes do not restart an already-running engine',
      () async {
    var starts = 0;
    final bridge = LifecycleBridge(
      onResume: () async => starts++,
      onPause: () async {},
    );
    await bridge.handle(AppLifecycleState.resumed);
    await bridge.handle(AppLifecycleState.resumed);
    expect(starts, 1);
  });

  test('inactive is ignored', () async {
    var starts = 0;
    var stops = 0;
    final bridge = LifecycleBridge(
      onResume: () async => starts++,
      onPause: () async => stops++,
    );
    await bridge.handle(AppLifecycleState.resumed);
    await bridge.handle(AppLifecycleState.inactive);
    expect(stops, 0, reason: 'a transient inactive must not tear down');
  });

  test('detached stops', () async {
    var stops = 0;
    final bridge = LifecycleBridge(
      onResume: () async {},
      onPause: () async => stops++,
    );
    await bridge.handle(AppLifecycleState.resumed);
    await bridge.handle(AppLifecycleState.detached);
    expect(stops, 1);
  });
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd apps/omnifi_app && flutter test test/lifecycle_test.dart`
Expected: FAIL — `LifecycleBridge` not found.

- [ ] **Step 3: Write the lifecycle bridge**

Create `apps/omnifi_app/lib/platform/lifecycle.dart`:

```dart
import 'package:flutter/widgets.dart';

/// Keeps the engine's lifetime tied to the app's foreground state.
///
/// This matters on iOS, which will not keep a socket alive in the
/// background. On desktop the app is a long-lived agent and `handle` is
/// simply never called with `paused`.
class LifecycleBridge with WidgetsBindingObserver {
  LifecycleBridge({required this.onResume, required this.onPause});

  final Future<void> Function() onResume;
  final Future<void> Function() onPause;

  bool _running = false;

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    handle(state);
  }

  Future<void> handle(AppLifecycleState state) async {
    switch (state) {
      case AppLifecycleState.resumed:
        if (_running) return;
        _running = true;
        await onResume();
      case AppLifecycleState.paused:
      case AppLifecycleState.detached:
        if (!_running) return;
        _running = false;
        await onPause();
      case AppLifecycleState.inactive:
      case AppLifecycleState.hidden:
        // Transient — a notification shade or app switcher preview. Tearing
        // down here would thrash the connection on every glance.
        break;
    }
  }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd apps/omnifi_app && flutter test test/lifecycle_test.dart`
Expected: PASS — 4 tests.

- [ ] **Step 5: Write the iOS Keychain plugin**

Create `apps/omnifi_app/ios/Runner/SecureStorePlugin.swift` with the same body as the macOS `SecureStorePlugin.swift` from Task 23, changing only the import:

```swift
import Flutter
import Foundation
import Security
```

and the registrar type in `register(with:)`:

```swift
  static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(
      name: "com.omnifi/secure_store",
      binaryMessenger: registrar.messenger())
    registrar.addMethodCallDelegate(SecureStorePlugin(), channel: channel)
  }
```

Note `registrar.messenger()` is a method on iOS and a property on macOS. The rest of the file — the `query`, `read`, `write`, `delete` helpers and `handle` — is identical.

- [ ] **Step 6: Write the iOS clipboard plugin**

Create `apps/omnifi_app/ios/Runner/ClipboardPlugin.swift`:

```swift
import Flutter
import Foundation
import UIKit

/// iOS reads the pasteboard on foreground only. iOS 16+ shows the user a
/// paste permission prompt for programmatic reads; that is accepted rather
/// than worked around.
class ClipboardPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {
  private var sink: FlutterEventSink?
  private var observer: NSObjectProtocol?

  static func register(with registrar: FlutterPluginRegistrar) {
    let instance = ClipboardPlugin()
    let methods = FlutterMethodChannel(
      name: "com.omnifi/clipboard",
      binaryMessenger: registrar.messenger())
    registrar.addMethodCallDelegate(instance, channel: methods)
    let events = FlutterEventChannel(
      name: "com.omnifi/clipboard/changes",
      binaryMessenger: registrar.messenger())
    events.setStreamHandler(instance)
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "start":
      observer = NotificationCenter.default.addObserver(
        forName: UIPasteboard.changedNotification,
        object: nil, queue: .main
      ) { [weak self] _ in self?.emitCurrent() }
      emitCurrent()
      result(nil)
    case "stop":
      if let observer = observer {
        NotificationCenter.default.removeObserver(observer)
      }
      observer = nil
      result(nil)
    case "write":
      guard let args = call.arguments as? [String: Any],
            let format = args["format"] as? String,
            let data = args["data"] as? FlutterStandardTypedData else {
        result(FlutterError(code: "bad_args", message: nil, details: nil))
        return
      }
      if format == "text" {
        UIPasteboard.general.string =
          String(data: data.data, encoding: .utf8) ?? ""
      } else if format == "png" {
        UIPasteboard.general.setData(data.data,
                                     forPasteboardType: "public.png")
      }
      result(nil)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func emitCurrent() {
    guard let sink = sink else { return }
    if UIPasteboard.general.hasImages,
       let image = UIPasteboard.general.image,
       let png = image.pngData() {
      sink(["format": "png",
            "data": FlutterStandardTypedData(bytes: png),
            "concealed": false])
    } else if let text = UIPasteboard.general.string {
      sink(["format": "text",
            "data": FlutterStandardTypedData(bytes: Data(text.utf8)),
            "concealed": false])
    }
  }

  func onListen(withArguments arguments: Any?,
                eventSink events: @escaping FlutterEventSink)
      -> FlutterError? {
    sink = events
    return nil
  }

  func onCancel(withArguments arguments: Any?) -> FlutterError? {
    sink = nil
    return nil
  }
}
```

- [ ] **Step 7: Register the iOS plugins**

Modify `apps/omnifi_app/ios/Runner/AppDelegate.swift` — inside `application(_:didFinishLaunchingWithOptions:)`, before `return super.application(...)`:

```swift
    let controller = window?.rootViewController as! FlutterViewController
    SecureStorePlugin.register(
      with: controller.registrar(forPlugin: "SecureStorePlugin")!)
    ClipboardPlugin.register(
      with: controller.registrar(forPlugin: "ClipboardPlugin")!)
```

- [ ] **Step 8: Wire the bridge into main.dart**

Modify `apps/omnifi_app/lib/main.dart` — replace the `await engine.start();` line with:

```dart
  final lifecycle = LifecycleBridge(
    onResume: engine.start,
    onPause: engine.stop,
  );
  WidgetsBinding.instance.addObserver(lifecycle);
  await lifecycle.handle(AppLifecycleState.resumed);
```

and add the import:

```dart
import 'platform/lifecycle.dart';
```

- [ ] **Step 9: Build for iOS**

Run: `cd apps/omnifi_app && flutter build ios --debug --no-codesign`
Expected: the build succeeds.

- [ ] **Step 10: Run on the simulator and confirm no background socket**

Run: `flutter run -d "iPhone 16"`, then background the app and confirm the Dart console logs the engine stopping rather than throwing socket errors.

- [ ] **Step 11: Analyze and commit**

```bash
cd apps/omnifi_app && flutter analyze
cd ../.. && git add apps
git commit -m "feat: add iOS keychain, pasteboard and foreground-only lifecycle"
```

---

## Task 26: End-to-end verification against the definition of done

This task writes no production code. It proves the spec's acceptance criteria hold on real devices and records the result.

**Files:**
- Create: `docs/superpowers/verification/2026-07-22-project-1-acceptance.md`
- Create: `scripts/verify.sh`

**Interfaces:**
- Consumes: everything.
- Produces: a signed-off acceptance record.

- [ ] **Step 1: Write the automated gate script**

Create `scripts/verify.sh`:

```bash
#!/usr/bin/env bash
# Runs every automated check for OmniFi project 1.
# The relay must be running: cd relay && npx wrangler dev --port 8787
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> omnifi_core: analyze"
(cd packages/omnifi_core && dart analyze)

echo "==> omnifi_core: unit tests"
(cd packages/omnifi_core && dart test)

echo "==> omnifi_core: integration tests (requires local relay)"
(cd packages/omnifi_core && dart test test/integration/ --tags integration)

echo "==> relay: tests"
(cd relay && npm test)

echo "==> app: analyze"
(cd apps/omnifi_app && flutter analyze)

echo "==> app: widget tests"
(cd apps/omnifi_app && flutter test)

echo "==> core must not depend on Flutter"
if grep -rqE "package:flutter|dart:ui" packages/omnifi_core/lib/; then
  echo "FAIL: omnifi_core imports Flutter" >&2
  exit 1
fi

echo "All automated checks passed."
```

Run: `chmod +x scripts/verify.sh`

- [ ] **Step 2: Run the full automated gate**

Run in one shell: `cd relay && npx wrangler dev --port 8787`
Run in another: `./scripts/verify.sh`
Expected: `All automated checks passed.`

Fix anything that fails before continuing. Do not proceed to manual verification with a red suite.

- [ ] **Step 3: Deploy the relay**

Run: `cd relay && npx wrangler deploy`
Expected: a `*.workers.dev` URL. Record it; it becomes `OMNIFI_RELAY`.

Verify: `curl -s https://<your-relay>.workers.dev/v1/health` returns `{"ok":true}`.

- [ ] **Step 4: Build the three clients against the deployed relay**

```bash
cd apps/omnifi_app
flutter build macos --dart-define=OMNIFI_RELAY=https://<your-relay>.workers.dev
flutter build windows --dart-define=OMNIFI_RELAY=https://<your-relay>.workers.dev
flutter build ios --dart-define=OMNIFI_RELAY=https://<your-relay>.workers.dev
```

- [ ] **Step 5: Run the manual acceptance matrix**

Work through each row and record PASS or FAIL with a note. These are exactly the spec's definition-of-done items.

| # | Check | How to verify |
|---|---|---|
| 1 | Three devices pair via QR | Invite from Mac, scan on iPhone, then invite from Mac and scan on PC |
| 2 | Desktop word-phrase fallback works | Pair the PC using the typed 8-word phrase instead of the QR |
| 3 | SAS is shown and matches | Confirm both screens show the same 5 words before accepting |
| 4 | SAS mismatch is refusable | Decline on one side; confirm no peer is added to either roster |
| 5 | Clipboard Mac → PC on LAN | Same Wi-Fi; copy on Mac, paste on PC; status shows `Connected (direct)` |
| 6 | Clipboard PC → Mac on LAN | Reverse of #5 |
| 7 | Clipboard via relay | Put the PC on a hotspot; status shows `Connected (relay)`; copy both ways |
| 8 | Image clipboard round-trips | Copy a screenshot on Mac, paste into an app on PC |
| 9 | Oversized content is refused visibly | Copy a >1 MiB image; confirm the peer shows the too-large state, not silence |
| 10 | No ping-pong loop | Copy once; confirm exactly one update propagates and it does not bounce |
| 11 | Survives sleep/wake | Sleep the Mac 2 minutes, wake it; clipboard sync resumes without relaunching |
| 12 | Survives network loss | Disable Wi-Fi 60s, re-enable; status returns to connected on its own |
| 13 | LAN↔relay migration is seamless | Start on relay, join the LAN; status flips to direct with no re-pairing |
| 14 | Password manager content is skipped | Copy from 1Password/Bitwarden; confirm nothing syncs |
| 15 | Screen lock pauses sync | Lock the Mac, copy on the PC; confirm nothing is applied until unlock |
| 16 | Manual pause works | Toggle pause; confirm no traffic in either direction |
| 17 | Forget removes a peer | Forget the iPhone on the Mac; confirm it can no longer sync |
| 18 | iOS foreground-only is honest | Background the iPhone; confirm the Mac shows it as not connected |
| 19 | Relay sees no plaintext | In the Cloudflare dashboard, confirm logs show sizes only, never content |

- [ ] **Step 6: Write the acceptance record**

Create `docs/superpowers/verification/2026-07-22-project-1-acceptance.md`:

```markdown
# OmniFi Project 1 — Acceptance Record

**Date:** <date of the run>
**Relay:** <deployed URL>
**Devices:** <macOS version / Windows version / iOS version>

## Automated

`./scripts/verify.sh` — PASS / FAIL
- omnifi_core unit tests: <count> passed
- omnifi_core integration tests: <count> passed
- relay tests: <count> passed
- app widget tests: <count> passed
- Flutter-free core check: PASS / FAIL

## Manual matrix

| # | Check | Result | Notes |
|---|---|---|---|
| 1 | Three devices pair via QR | | |
| ... (all 19 rows from the plan) | | | |

## Outcome

Project 1 is COMPLETE / INCOMPLETE.

Deferred, with spec references:
- iOS background sync via silent push (spec §4)
- File transfer through the clipboard (spec §5)
- Revocation ledger for offline devices (spec §3)

## Follow-ups discovered during verification

- <anything found that is not covered above>
```

- [ ] **Step 7: Commit the record**

```bash
git add docs/superpowers/verification scripts/verify.sh
git commit -m "docs: record project 1 acceptance verification"
```

---

## Plan Self-Review

**Spec coverage.** Every spec section maps to at least one task:

| Spec section | Tasks |
|---|---|
| §2 Architecture — `omnifi_core`, app, relay, `Link` interface | 1, 11, 18, 21, 22 |
| §3 Device identity, Keychain/Credential Manager | 9, 23, 24, 25 |
| §3 Mesh and roster | 10 |
| §3 Pairing flow, QR, word fallback, SAS | 6, 15, 16, 22 |
| §3 Session encryption, forward secrecy, replay | 3, 4, 5 |
| §3 Open research item R1 | 2 |
| §3 Revocation | 10, 21 |
| §4 Link racing and LAN preference | 11, 14 |
| §4 Migration above the link | 13 |
| §4 Reconnection and backoff | 14 |
| §4 Sleep/wake handling | 14, 23 |
| §4 Offline queueing and collapse | 12, 13 |
| §4 Relay Durable Object, caps | 18 |
| §4 iOS second-class peer | 25 |
| §5 Clipboard watching per platform | 17, 23, 24, 25 |
| §5 Payload, cap, too-large marker | 8, 17 |
| §5 Loop prevention | 17 |
| §5 Conflicts, last-write-wins | 17 |
| §5 Privacy defaults | 17, 23, 24 |
| §6 Error handling classes | 3, 13, 17 |
| §7 Testing strategy | every task; 5, 19, 26 specifically |
| §8 Definition of done | 26 |

**Placeholder scan.** The only intentional deferral is Task 2's decision record, which is a research deliverable with explicit acceptance criteria rather than a TODO — and Tasks 3–5 are written against a fully-specified construction so the plan executes regardless of its outcome. Task 5 contains `REPLACE_ME_VECTOR_N` constants by design; Step 2 of that task generates and pastes the real values, and the test fails until it is done.

**Type consistency check.** Names verified consistent across tasks: `AeadSession.seal`/`open`, `StaticKeyPair.publicKey`/`privateKey`, `HandshakeResult.session`/`transcript`/`master`/`peerStaticPublicKey`, `Handshake.start`/`confirmationFor`/`complete`, `LinkQuality.preferenceScore`/`isDirect`, `Link.inbound`/`states`/`state`/`quality`/`send`/`close`, `PeerSession.attach`/`send`/`inbound`/`errors`/`isDead`/`queuedFrameCount`, `Outbox.add`/`drain`/`droppedCount`, `ClipboardPayload.toMap`/`fromMap`, `Mesh.addPeer`/`removePeer`/`isAuthorized`, `ConnectionStatus` variants, and the channel names `com.omnifi/secure_store`, `com.omnifi/clipboard`, `com.omnifi/clipboard/changes`, `com.omnifi/power`.

Two consistency fixes applied inline while reviewing:
1. `Handshake` gained `confirmationFor(peerMessage)` — the original three-method interface could not produce a confirmation before ingesting the peer's message, which the Task 4 tests exercise.
2. `FakeLink` was promoted from `test/support/` into the library as `FakeLinkFactory` in Task 21, because the engine test and the app's tests both need it. The old path re-exports it so Tasks 11–20 tests keep compiling unchanged.

**Scope check.** This plan covers exactly project 1 of the four in the spec. Projects 2–4 (iMessage, audio, video) are excluded and each need their own spec → plan cycle.

---

## Task 27: ARC mesh relay route (second relay backend)

Added after the plan's first draft, when it emerged that a production Rust relay (`arc-relay`) already exists and is deployed. The decision was to run **both** backends: Cloudflare as the default, ARC as an equal-standing second candidate. `LinkManager` already races dialers and ranks by preference score, so this needs no new client failover logic — only a second entry in `EngineConfig.relayBases`.

**This task's code lives in a different repository.** ARC is at `/Volumes/Main External/Development/ARC` (a Rust workspace, `arc-relay` crate, axum + sqlx). Commit there, not in the OmniFi repo. Verify the ARC checkout is clean before starting, and do not touch `mirror/`, `ws/`, `auth/`, or any existing route.

**Files:**
- Create: `arc-relay/src/mesh/mod.rs`
- Create: `arc-relay/src/mesh/registry.rs`
- Create: `arc-relay/src/mesh/routes.rs`
- Create: `arc-relay/tests/mesh_relay.rs`
- Modify: `arc-relay/src/lib.rs` (add `pub mod mesh;`)
- Modify: `arc-relay/src/api/mod.rs` (mount the router)

**Interfaces:**
- Consumes: nothing from ARC's existing modules. Explicitly **not** `AppState`'s database pool, `auth::jwt`, `beacon_proto`, or `mirror::`.
- Produces a network contract **byte-identical to Task 18's**:
  - `GET /v1/mesh/:meshId/ws?device=:deviceId` with `Upgrade: websocket` → 101.
  - Binary frames only. First 16 bytes = destination device ID as raw bytes (32 hex chars decoded), or 16 zero bytes for broadcast. Remainder is opaque and forwarded verbatim.
  - HTTP `400` **before upgrade** on a malformed mesh ID or device ID (both must match `^[0-9a-f]{32}$`).
  - HTTP `426` on a non-upgrade request to the ws path.
  - Close `1009` on a frame over 1_048_576 bytes.
  - `GET /v1/mesh/health` → `200 {"ok":true}`. (Namespaced under `/v1/mesh` to avoid colliding with ARC's existing health route.)

### Design constraints — these are the point of the task

**The route is deliberately unauthenticated and stateless.** It must not require a JWT, must not read or write Postgres, and must not construct a `SessionMirror`. OmniFi's design has no accounts by deliberate choice; routing through ARC's authenticated path would reverse that. The mesh ID is a 128-bit random capability and is the only credential.

**It must not use `beacon_proto` envelopes.** ARC's existing fanout carries typed `ArcToClient` values. This route forwards opaque ciphertext byte-for-byte. If it ever deserializes a payload, it is wrong.

**It needs the abuse protections a Durable Object gave for free.** Unlike Cloudflare, this route sits on a single public VPS with no platform-level DDoS absorption. Enforce, in `registry.rs`:
- at most **16** concurrent sockets per mesh (reject the 17th with close `1013`),
- at most **1024** concurrent meshes process-wide (reject with HTTP `503`),
- a per-socket token bucket of **50 frames/second, burst 100** (exceeding it closes with `1008`),
- a mesh entry is dropped from the registry the moment its last socket disconnects, so an idle mesh holds no memory.

These numbers are generous for a personal mesh of 2–6 devices and cheap to enforce; their purpose is to bound a hostile or buggy client, not to shape normal traffic.

- [ ] **Step 1: Verify the ARC checkout is clean and builds**

```bash
cd "/Volumes/Main External/Development/ARC"
git status --short
cargo build -p arc-relay 2>&1 | tail -5
```

Expected: a clean working tree and a successful build. If the tree is dirty, STOP and report — do not commit alongside someone else's in-progress work.

- [ ] **Step 2: Write the failing integration test**

Create `arc-relay/tests/mesh_relay.rs`:

```rust
//! Conformance tests for the OmniFi mesh relay route.
//!
//! These mirror the Cloudflare Worker's test suite one-for-one. The two
//! backends must stay contract-identical; if you change an assertion here,
//! change it in `relay/test/mesh_do.test.ts` in the OmniFi repo too.

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

mod common;

const MESH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DEV_A: &str = "11111111111111111111111111111111";
const DEV_B: &str = "22222222222222222222222222222222";

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

fn frame(dest: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(dest);
    out.extend_from_slice(body);
    out
}

fn broadcast() -> Vec<u8> {
    vec![0u8; 16]
}

#[tokio::test]
async fn health_reports_ok() {
    let server = common::spawn_mesh_server().await;
    let body: serde_json::Value = reqwest::get(format!("{}/v1/mesh/health", server.http_base))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body, serde_json::json!({"ok": true}));
}

#[tokio::test]
async fn rejects_malformed_mesh_id() {
    let server = common::spawn_mesh_server().await;
    let res = reqwest::get(format!(
        "{}/v1/mesh/NOT-HEX/ws?device={DEV_A}",
        server.http_base
    ))
    .await
    .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn rejects_malformed_device_id() {
    let server = common::spawn_mesh_server().await;
    let res = reqwest::get(format!(
        "{}/v1/mesh/{MESH}/ws?device=nope",
        server.http_base
    ))
    .await
    .unwrap();
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn rejects_non_upgrade_request() {
    let server = common::spawn_mesh_server().await;
    let res = reqwest::get(format!(
        "{}/v1/mesh/{MESH}/ws?device={DEV_A}",
        server.http_base
    ))
    .await
    .unwrap();
    assert_eq!(res.status(), 426);
}

#[tokio::test]
async fn routes_directed_frame_to_addressed_device_only() {
    let server = common::spawn_mesh_server().await;
    let mut a = server.connect(MESH, DEV_A).await;
    let mut b = server.connect(MESH, DEV_B).await;

    a.send(Message::Binary(frame(&hex_to_bytes(DEV_B), b"ciphertext")))
        .await
        .unwrap();

    let got = b.next().await.unwrap().unwrap();
    assert_eq!(&got.into_data()[16..], b"ciphertext");
}

#[tokio::test]
async fn broadcasts_to_every_peer_except_sender() {
    let server = common::spawn_mesh_server().await;
    let mut a = server.connect(MESH, DEV_A).await;
    let mut b = server.connect(MESH, DEV_B).await;

    a.send(Message::Binary(frame(&broadcast(), b"to everyone")))
        .await
        .unwrap();

    let got = b.next().await.unwrap().unwrap();
    assert_eq!(&got.into_data()[16..], b"to everyone");
}

#[tokio::test]
async fn does_not_deliver_across_meshes() {
    let server = common::spawn_mesh_server().await;
    let mut a = server.connect(MESH, DEV_A).await;
    let mut other = server
        .connect("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DEV_B)
        .await;

    a.send(Message::Binary(frame(&broadcast(), b"mesh-local")))
        .await
        .unwrap();

    let timeout =
        tokio::time::timeout(std::time::Duration::from_millis(200), other.next()).await;
    assert!(timeout.is_err(), "frame leaked across meshes");
}

#[tokio::test]
async fn drops_frame_shorter_than_header() {
    let server = common::spawn_mesh_server().await;
    let mut a = server.connect(MESH, DEV_A).await;
    let mut b = server.connect(MESH, DEV_B).await;

    a.send(Message::Binary(vec![0u8; 8])).await.unwrap();

    let timeout = tokio::time::timeout(std::time::Duration::from_millis(200), b.next()).await;
    assert!(timeout.is_err(), "short frame was forwarded");
}

#[tokio::test]
async fn closes_on_oversized_frame() {
    let server = common::spawn_mesh_server().await;
    let mut a = server.connect(MESH, DEV_A).await;

    a.send(Message::Binary(vec![0u8; 1_048_576 + 32]))
        .await
        .unwrap();

    let closed = a.next().await;
    match closed {
        Some(Ok(Message::Close(Some(f)))) => assert_eq!(u16::from(f.code), 1009),
        other => panic!("expected close 1009, got {other:?}"),
    }
}

#[tokio::test]
async fn accepts_a_frame_exactly_at_the_cap() {
    let server = common::spawn_mesh_server().await;
    let mut a = server.connect(MESH, DEV_A).await;
    let mut b = server.connect(MESH, DEV_B).await;

    let mut body = vec![0u8; 1_048_576 - 16];
    body[0] = 42;
    a.send(Message::Binary(frame(&hex_to_bytes(DEV_B), &body)))
        .await
        .unwrap();

    let got = b.next().await.unwrap().unwrap();
    assert_eq!(got.into_data().len(), 1_048_576);
}

#[tokio::test]
async fn rejects_the_seventeenth_socket_in_one_mesh() {
    let server = common::spawn_mesh_server().await;
    let mut sockets = Vec::new();
    for i in 0..16 {
        sockets.push(server.connect(MESH, &format!("{:032x}", i)).await);
    }
    let mut overflow = server.connect(MESH, &format!("{:032x}", 99)).await;
    match overflow.next().await {
        Some(Ok(Message::Close(Some(f)))) => assert_eq!(u16::from(f.code), 1013),
        other => panic!("expected close 1013, got {other:?}"),
    }
}

#[tokio::test]
async fn mesh_is_dropped_when_its_last_socket_leaves() {
    let server = common::spawn_mesh_server().await;
    {
        let mut a = server.connect(MESH, DEV_A).await;
        a.close(None).await.unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(server.registry.mesh_count(), 0);
}
```

- [ ] **Step 3: Write the test harness**

Create `arc-relay/tests/common/mod.rs`:

```rust
//! Spawns the mesh router alone — no database, no JWT, no AppState — which
//! is itself a check that the route has no hidden dependency on either.

use arc_relay::mesh::{registry::MeshRegistry, routes::mesh_router};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

pub struct TestServer {
    pub http_base: String,
    pub ws_base: String,
    pub registry: MeshRegistry,
}

impl TestServer {
    pub async fn connect(
        &self,
        mesh: &str,
        device: &str,
    ) -> WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>> {
        let url = format!("{}/v1/mesh/{mesh}/ws?device={device}", self.ws_base);
        let (stream, _) = connect_async(url).await.expect("ws connect failed");
        stream
    }
}

pub async fn spawn_mesh_server() -> TestServer {
    let registry = MeshRegistry::new();
    let app = mesh_router(registry.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    TestServer {
        http_base: format!("http://{addr}"),
        ws_base: format!("ws://{addr}"),
        registry,
    }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

```bash
cd "/Volumes/Main External/Development/ARC"
cargo test -p arc-relay --test mesh_relay 2>&1 | tail -20
```

Expected: compilation failure — `arc_relay::mesh` does not exist.

- [ ] **Step 5: Write the registry**

Create `arc-relay/src/mesh/registry.rs` implementing:

```rust
//! In-memory mesh registry for the OmniFi relay route.
//!
//! Deliberately has no database, no auth, and no knowledge of payload
//! contents. A mesh is a set of connected sockets keyed by a 128-bit
//! random mesh ID; the ID is the only credential, and the relay cannot
//! read anything it forwards.
```

Requirements, all enforced here rather than in the route handler:
- `MeshRegistry` is `Clone` and `Arc`-backed (follow the pattern `mirror::MirrorRegistry` uses, but share no code with it).
- `pub fn new() -> Self`, `pub fn mesh_count(&self) -> usize`.
- `join(mesh_id, device_id) -> Result<MeshHandle, JoinRejection>` where `JoinRejection` distinguishes `MeshFull` (→ close 1013) from `TooManyMeshes` (→ HTTP 503).
- Each connected socket gets an `mpsc::Sender<Vec<u8>>` for outbound frames.
- `forward(mesh_id, from_device, frame)` sends the frame verbatim to the addressed device, or to every device except the sender when the first 16 bytes are zero. It must never copy or re-encode the body.
- Dropping the last `MeshHandle` in a mesh removes the mesh entry — implement `Drop` so this cannot be forgotten by a caller.
- Constants: `MAX_SOCKETS_PER_MESH = 16`, `MAX_MESHES = 1024`, `MAX_FRAME_BYTES = 1_048_576`, `RATE_LIMIT_FRAMES_PER_SEC = 50`, `RATE_LIMIT_BURST = 100`.

- [ ] **Step 6: Write the routes**

Create `arc-relay/src/mesh/routes.rs` with `pub fn mesh_router(registry: MeshRegistry) -> axum::Router` exposing `GET /v1/mesh/health` and `GET /v1/mesh/:mesh_id/ws`.

The handler must, in this order: validate the mesh ID against `^[0-9a-f]{32}$` (400 on failure), validate the `device` query parameter the same way (400), confirm the request carries a WebSocket upgrade (426 otherwise), then attempt `registry.join` (503 on `TooManyMeshes`), and only then accept the upgrade. On `MeshFull`, accept the upgrade and immediately close with 1013 — a close code is only reachable once a socket exists, which is the same reasoning that put the ID validation before the upgrade rather than after.

Create `arc-relay/src/mesh/mod.rs`:

```rust
pub mod registry;
pub mod routes;
```

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cd "/Volumes/Main External/Development/ARC"
cargo test -p arc-relay --test mesh_relay 2>&1 | tail -20
```

Expected: 13 passed.

- [ ] **Step 8: Verify the route has no hidden dependencies**

```bash
cd "/Volumes/Main External/Development/ARC"
grep -rnE "sqlx|jwt|beacon_proto|AppState|mirror::" arc-relay/src/mesh/ && echo "FAIL: mesh route touched a forbidden module" || echo "OK: mesh route is standalone"
```

Expected: `OK: mesh route is standalone`.

- [ ] **Step 9: Mount the router and confirm the whole crate still builds**

Add `pub mod mesh;` to `arc-relay/src/lib.rs`, and merge `mesh_router` into the main router in `arc-relay/src/api/mod.rs` without applying any auth middleware to it.

```bash
cargo build -p arc-relay && cargo test -p arc-relay 2>&1 | tail -15
```

Expected: the build succeeds and ARC's pre-existing test suite still passes. If any pre-existing test fails, report it — do not fix unrelated failures inside this task.

- [ ] **Step 10: Commit in the ARC repository**

```bash
cd "/Volumes/Main External/Development/ARC"
git add arc-relay/src/mesh arc-relay/tests/mesh_relay.rs arc-relay/tests/common arc-relay/src/lib.rs arc-relay/src/api/mod.rs
git commit -m "feat(mesh): add unauthenticated OmniFi mesh relay route"
```

- [ ] **Step 11: Record the deployment prerequisite**

This task does **not** deploy. Note in the report that `arc.ailuxis.com` must be redeployed (per ARC's `deploy/release.sh`) before OmniFi clients can reach the ARC backend, and that until then `EngineConfig.relayBases` should list only the Cloudflare URL.

---

## Amendment log

Changes made to this plan after its first draft, with the reason each was made.

| Date | Change | Reason |
|---|---|---|
| 2026-07-22 | Task 18's contract changed from "close 1008 on a malformed mesh or device ID" to "HTTP 400 before upgrade" | The plan's prose contradicted its own tests. A malformed ID is caught before the WebSocket upgrade completes, so no socket exists to close. Decided by the project owner. |
| 2026-07-22 | `RelayLink.id` changed from `relay:<peer>` to `relay:<host>:<peer>` | Two relay backends dialed for the same peer would collide in `LinkManager`'s candidate map, silently evicting one. |
| 2026-07-22 | `EngineConfig.relayBase` → `relayBases` (a list); engine builds one dialer per entry | Second relay backend adopted (ARC). Needs no new failover logic — `LinkManager` already ranks competing candidates. |
| 2026-07-22 | Added Task 27 (ARC mesh relay route) | A production Rust relay already exists and is deployed; running both backends gives redundancy. Decided by the project owner. |

---

## Task 28: Session establishment — handshake on first link adoption

Added after review found that `OmniFiEngine._connectPeer` builds every `PeerSession` with **all-zero AEAD keys**, with a comment deferring to a handshake that nothing in the plan ever performs. Pairing produces a real session; nothing re-establishes one when a device reconnects. Without this, Project 1's acceptance matrix cannot pass — "survives sleep/wake" and "survives network loss" both require reconnect.

**Files:**
- Create: `packages/omnifi_core/lib/src/session/session_establisher.dart`
- Modify: `packages/omnifi_core/lib/src/engine/omnifi_engine.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/session/session_establisher_test.dart`

**Interfaces:**
- Consumes: `OmniFiHandshakeV1`, `StaticKeyPair`, `HandshakeResult`, `HandshakeError` (Task 4); `DeviceIdentity` (Task 9); `PeerRecord`, `Mesh` (Task 10); `Link`, `LinkClosedError` (Task 11); `AeadSession` (Task 3); `PeerSession` (Task 13).
- Produces:
  - `class SessionEstablisher` with `static Future<AeadSession> establish({required Link link, required DeviceIdentity identity, required PeerRecord peer, Duration timeout = const Duration(seconds: 10)})`
  - `class SessionEstablishmentError implements Exception`
  - `bool isInitiatorFor(String localDeviceId, String peerDeviceId)` — deterministic role assignment.

### Design

**One handshake per session, not per link.** `PeerSession` is keyed to the device pair and survives link migration without renegotiating crypto — that is the whole point of the migration design. So the handshake runs **once**, on the first link adopted for a peer, and every later link reuses the same `AeadSession`. If a session dies (a decryption failure marks it dead and forces re-handshake), the engine discards it and establishes a fresh one on the next link.

**Role assignment is deterministic, not negotiated.** The device whose ID is lexicographically smaller is the initiator:

```dart
bool isInitiatorFor(String localDeviceId, String peerDeviceId) =>
    localDeviceId.compareTo(peerDeviceId) < 0;
```

Both sides compute the same answer from data they already hold, so there is no negotiation round and no tie to break — device IDs are 128-bit random and collisions are not a practical concern. A negotiation round here would be a second place for the protocol to diverge.

**Authentication is mutual and roster-bound.** Unlike pairing, both sides already know each other's static public key, so `expectedPeerStaticPublicKey` is the peer's key **from the roster** and `psk` is empty. That is what makes a reconnect to a known device mutually authenticated: a device presenting a different static key fails the handshake rather than being trusted on the strength of its device ID.

**The handshake runs on the raw `Link`, before any `PeerSession` exists.** It exchanges the handshake message and the confirmation using a buffered `StreamIterator` over `link.inbound`, armed before each send — the same pattern `PairingFlow` uses, and for the same reason: `inbound` is a broadcast stream, and a frame sent while no listener is attached is dropped, producing an intermittent hang rather than a clean failure.

**On failure the link is closed and not adopted.** A handshake failure means the peer is not who the roster says it is, or the link is broken. Either way the link must not become a session candidate. Close it and surface `SessionEstablishmentError`.

### Engine changes

- `_connectPeer` no longer constructs a `PeerSession` with zero keys. It creates the session lazily, after the first successful establishment.
- The dialers produce a `Link`; before offering it to `LinkManager`, the engine establishes a session if it does not yet have a live one for that peer, then attaches.
- If `session.isDead`, discard it and establish afresh on the next adopted link.
- A failed establishment must not count as a successful dial for backoff purposes.

### Tests

1. Two engines with each other in their rosters establish a session over a connected link pair, and a frame sealed by one opens on the other.
2. Role assignment is deterministic and opposite: `isInitiatorFor(a, b)` and `isInitiatorFor(b, a)` disagree, for both orderings.
3. A peer presenting a static key that does not match its roster entry fails with `SessionEstablishmentError`, and the link is closed.
4. Establishment does **not** re-run when a second link is adopted for a peer that already has a live session — assert the same `AeadSession` instance is reused and no second handshake occurs.
5. A dead session is replaced: mark a session dead, adopt a new link, and assert a fresh handshake runs and a new session is installed.
6. A link that closes mid-handshake surfaces `SessionEstablishmentError`, not a raw `LinkClosedError` or a hang.
7. Establishment respects the timeout: a peer that never responds fails within the timeout rather than hanging.

### Note on scope

This does not add key rotation, session resumption, or 0-RTT. A reconnect costs one full handshake — three X25519 operations and a round trip — which is negligible against the reconnect itself.

---

## Task 29: Pairing rendezvous

Found when the Flutter shell was built: `PairingFlow.invite` and `.join` both take a `Link`, and **nothing creates it**. Two devices that are pairing are not yet in each other's rosters, so neither the `LinkManager` dial path nor the LAN listener applies. Until this exists, pairing cannot complete end to end and nothing downstream of pairing can be tested on real hardware.

**Files:**
- Create: `packages/omnifi_core/lib/src/pairing/rendezvous.dart`
- Modify: `packages/omnifi_core/lib/src/engine/omnifi_engine.dart`
- Modify: `packages/omnifi_core/lib/omnifi_core.dart`
- Test: `packages/omnifi_core/test/pairing/rendezvous_test.dart`
- Test: extend `packages/omnifi_core/test/integration/relay_roundtrip_test.dart`

### Design — meet in a derived namespace

The relay treats a mesh ID as an opaque 32-hex routing key and creates a Durable Object per distinct value on demand. Nothing requires that value to be a *real* mesh. So the two pairing devices meet in a **rendezvous namespace derived from the pre-shared key already in the QR**:

```
rendezvousId = HKDF-SHA256(ikm: invite.psk, info: "omnifi-rendezvous-v1", len: 16) → 32 lowercase hex
```

Both sides connect to `/v1/mesh/<rendezvousId>/ws?device=<ephemeralId>` with a **fresh random ephemeral device ID** — not their real one.

Why this shape:

- **No relay change at all.** The rendezvous ID is a valid mesh ID as far as the relay is concerned.
- **No collision with live mesh traffic.** The inviter may already hold a socket to its real mesh's DO; this is a separate DO, so nothing is demultiplexed and no device ID is duplicated on one socket set.
- **Unguessable without the QR.** The namespace is derived from the PSK, so finding it requires the invite. That is not new exposure — the PSK is already the pairing secret, and the SAS is what defends against someone who *has* observed the QR.
- **Costs nothing when idle.** The DO hibernates and is discarded once both sides disconnect.

**Ephemeral device IDs matter.** Using real device IDs here would publish them to anyone who has seen the QR, before any authentication has happened. The ephemeral ID is used only to address relay frames during the exchange; the real identity is established by the handshake inside `PairingFlow`.

### Flow

1. Both sides derive `rendezvousId` from `invite.psk` and connect with their own fresh `ephemeralId`.
2. The **joiner** broadcasts a `rendezvousHello` (16 zero bytes destination) carrying its `ephemeralId`.
3. The **inviter**, waiting in invite mode, receives it and learns the joiner's `ephemeralId`.
4. Each side constructs a `RelayLink` targeted at the other's `ephemeralId`.
5. `PairingFlow.invite` / `.join` run over those links exactly as they do today — unchanged.
6. On success or failure both rendezvous links close.

**Interfaces:**
- `String rendezvousIdFor(List<int> psk)` — deterministic, both sides derive the same value.
- `class RendezvousError implements Exception`
- `class PairingRendezvous` with:
  - `static Future<Link> awaitJoiner({required PairingInvite invite, required Uri relayBase, Duration timeout = const Duration(minutes: 2)})` — inviter side.
  - `static Future<Link> connectToInviter({required PairingInvite invite, required Uri relayBase, Duration timeout = const Duration(seconds: 30)})` — joiner side.
- Engine: `beginInvite`/`beginJoin` gain rendezvous-creating variants so the UI does not have to build links itself.

### Hazards this codebase has already been bitten by

- **Arm the inbox before the first suspension.** `RelayLink.inbound` is a broadcast stream; a frame arriving with no listener attached is dropped and the symptom is an intermittent hang, not a clean failure. `SessionEstablisher` had exactly this bug latent. Subscribe *before* sending anything.
- **The inviter's timeout is long (a user is walking to another device); the joiner's is short.** Do not use one value for both.
- **A `RelayLink` whose peer never appears must fail, not hang.** Both timeouts must close the underlying socket.
- **Two joiners could hit one rendezvous.** The inviter accepts the first `rendezvousHello` and ignores the rest; a second joiner fails its timeout rather than silently pairing to nothing. The SAS still protects the accepted one.

### Tests

1. `rendezvousIdFor` is deterministic, 32 lowercase hex, and differs for different PSKs.
2. Two `PairingRendezvous` sides with the same invite find each other over a **live local relay** and produce links that carry frames both ways.
3. A full pairing completes over the rendezvous: both sides derive the **same SAS**, both confirm, both end with a roster entry for the other.
4. A joiner with the wrong PSK derives a different rendezvous ID and times out rather than pairing.
5. The inviter times out and closes its socket when no joiner appears.
6. A second joiner arriving after the first is ignored and times out; the first pairing still completes.

Tests 2–6 need a live `wrangler dev`; tag them `integration` so a plain `dart test` skips them, and state plainly in the report if the relay could not be started.

---

## Amendment log — 2026-07-24

| Change | Reason |
|---|---|
| **The iPhone is the authority, not macOS.** Relay / authority / capability-provider are now three distinct roles. | The always-on device is the phone, not a laptop that is frequently closed. See the spec amendment of the same date. |
| **iOS reframed from "second-class peer" to "the authority, request-driven."** Task 25's framing changes; its `LifecycleBridge` work does not. | iOS cannot hold a background socket without a Network Extension. But privileged operations are human-in-the-loop by nature — Face ID requires the user to be holding the phone — so the phone never needs to act unattended. |
| **macOS becomes an optional capability provider.** | It is the only device that can read `chat.db`. That makes it necessary *for iMessage*, not load-bearing for the product. |
| **The relay gains an APNs key and a mesh→token map** (a later task). | Waking a backgrounded phone requires it. Content stays encrypted; the relay gains the ability to *wake* a device, never to *read* one. Recorded as a deliberate erosion of the dumb-relay principle. |
| **Added Task 29 (pairing rendezvous).** | `PairingFlow` takes a `Link` that nothing created. Pairing could not complete end to end. |
| **Capability responses are targeted, never broadcast.** | A live 2FA code fanned out to every device would let a compromised machine harvest codes it never requested. |
| **Authenticator deferred to its own project.** | Needs Secure Enclave work, the APNs path, and a capability layer — none testable until a mesh can pair. |
