# R1 — Session Handshake Construction Decision

**Date:** 2026-07-22
**Status:** Decided

## Candidates evaluated

Method note: Dart is not installed on this machine, so `dart pub search noise` could not be
run. The survey was performed against pub.dev search (`https://pub.dev/packages?q=noise`
and `?q=noise+protocol`), individual package pages, and each candidate's linked GitHub
repository (file trees via the GitHub API, sources via `raw.githubusercontent.com`). This
substitution reaches the same data the CLI would have surfaced, plus the source needed for
criterion 4.

| Package | Version | Last publish | IK? | Vectors? | Read in full? | Verdict |
|---|---|---|---|---|---|---|
| `noise_protocol_framework` | 1.2.0 | ~Mar 2026 (repo pushed 2026-03-10) | **No** — only `KNpsk0` and `NKpsk0` handshake states ship | **No** — `test/noise_protocol_framework_test.dart` is a 1-byte empty file; the repo has no test suite at all | Yes — read `noise_protocol_framework.dart`, `symmetric_state.dart`, `cipher_state.dart`, `protocols/handshake_state_interface.dart`, `protocols/nkpsk0/handshake_state.dart`, `crypto/key_derivation.dart` (whole `lib/` is ~31 KB) | **Rejected** — fails criteria 1, 2; also DH is `elliptic`/ECDH over NIST curves, not X25519 |
| `noise_protocol` | 0.1.1 | ~2020 (6 years ago) | Documents IK among KK/XX/XXpsk3/N | Not established; README states "this early version doesn't pass acceptance tests yet" | Not read — package is **discontinued** and **Dart 3 incompatible**, so it cannot be a dependency | **Rejected** — fails criteria 2, 3, 5 (pins `cryptography ^1.0.0` + `kms ^0.4.0`, both dead) |
| `dart_libp2p` | 1.0.3 | ~Feb 2026 (5 months ago) | **No** — `lib/p2p/security/noise/` contains only `xx_pattern.dart`; libp2p's spec mandates `Noise_XX_25519_ChaChaPoly_SHA256` | Has XX unit tests, but no official Noise vector suite | Not read end-to-end — it is a full libp2p networking stack, far over the 2000-line budget, and the Noise layer is not usable standalone | **Rejected** — fails criteria 1, 2, 4; wrong dependency weight for `omnifi_core` |
| `ipfs_libp2p` / `dart_ipfs` | 0.5.6 / 1.11.7 | 2026 | No | No | No | **Rejected** — same XX-only libp2p Noise layer, wrapped in an IPFS stack |
| `noise` | 0.5.1 | ~2014 (12 years ago) | n/a | n/a | n/a | **Rejected** — gradient/simplex noise generation, not cryptography |
| `fast_noise`, `open_simplex_2`, `noise_meter`, `livekit_noise_filter`, `flutter_nnnoiseless`, `carp_audio_package`, `flutter_audio_toolkit`, `flutter_shaders_ui` | various | various | n/a | n/a | n/a | **Rejected** — name collisions: procedural noise generation or audio noise suppression |

No package named `flutter_noise` exists on pub.dev.

**Score against the five-point bar:**

| Criterion | `noise_protocol_framework` | `noise_protocol` | `dart_libp2p` |
|---|---|---|---|
| 1. Implements Noise **IK** | FAIL | claimed, unverifiable in a usable build | FAIL (XX only) |
| 2. Official Noise vectors in its own test suite | FAIL (no tests) | FAIL (self-declared) | FAIL |
| 3. Published/committed within 24 months | PASS | FAIL | PASS |
| 4. < 2000 lines and handshake state machine actually read | PASS | FAIL (not read — unusable on Dart 3) | FAIL (not read — too large) |
| 5. No unmaintained crypto shim; builds on `cryptography`/`pointycastle` | MARGINAL — uses `cryptography` for HKDF and `pointycastle`, but DH goes through `elliptic` (v0.3.x, NIST curves), not X25519 | FAIL (`cryptography ^1.0.0`, `kms ^0.4.0`) | not assessed |

Zero packages clear all five. Option (a) is rejected.

## Decision

Selected option: **(c) OmniFi Session Handshake v1**

## Rationale

Option (a) is rejected on evidence, not on preference. The only actively maintained pure-Dart
Noise package, `noise_protocol_framework`, was read end-to-end and simply does not contain an
IK pattern — its `lib/protocols/` directory holds exactly two handshake state machines,
`KNpsk0` and `NKpsk0`. Adding IK would mean writing the pattern ourselves anyway, on top of a
symmetric-state implementation with no test suite whatsoever (the single test file in the repo
is one byte long) and therefore no evidence it agrees with the official Noise vectors on even
the patterns it does ship. Its DH is also `elliptic`-based ECDH over NIST curves rather than
X25519, which is a second, independent mismatch with this project's primitives. The one
package that names IK, `noise_protocol`, is discontinued, Dart 3 incompatible, pinned to a
dead `cryptography ^1.0.0` plus an abandoned `kms` package, and its own README admits it does
not pass acceptance tests. `dart_libp2p` is XX-only by specification and would drag an entire
networking stack into `omnifi_core`.

Option (b) — porting the `snow` crate's IK pattern to Dart — was considered seriously. `snow`
is the right reference: pure Rust, actively maintained (0.10.0, updated 2025-07-19), heavily
used, and it runs the official Noise vectors. But porting IK honestly means porting
`SymmetricState` (MixKey / MixHash / MixKeyAndHash / EncryptAndHash / DecryptAndHash / Split),
the `HandshakeState` token machine, the protocol-name parser, nonce and rekey handling, and
then wiring up the full `snow`/`noise-c` vector JSON suite — the brief's 400–600 line estimate
is about right for the state machine and understates the vector plumbing. That is only worth
paying for if we need Noise *interoperability*. OmniFi's transport is closed: both endpoints
are our own clients over our own relay, and nothing on the wire needs to speak to a
third-party Noise implementation. We would be buying the cost of a hand-port without the
benefit that justifies it — and a hand-ported Noise IK is exactly as much unreviewed
hand-written crypto as option (c) is, just larger and with a more convincing name.

Therefore the construction specified in Task 4, **OmniFi Session Handshake v1**, was chosen
because no package cleared the acceptance bar. It is a triple-DH construction over X25519
(`dh_ee || dh_es || dh_se`) with the full handshake transcript and any pairing PSK bound in as
HKDF salt, directional keys split via HKDF-Expand, and an explicit `omnifi-confirm` AEAD
confirmation from each side authenticated over the transcript. Its authentication and
forward-secrecy arguments are the same ones Noise IK relies on, and it uses only primitives
from the `cryptography` package (X25519, HKDF-SHA256, ChaCha20-Poly1305) that the project
already depends on. It is fully specified in the plan and small enough to review in full.

**It is nonetheless a hand-rolled construction and it requires a security review before any
release.** That review has not happened. Nothing in this document should be read as having
performed it.

## Consequences

- **Implementation behind `Handshake` interface:** `OmniFiHandshakeV1` in
  `packages/omnifi_core/lib/src/crypto/handshake.dart`, implementing the normative
  construction from Task 4 directly on `package:cryptography` (X25519 for the three DH
  operations, HKDF-SHA256 for `master` and the `i2r`/`r2i` split, and `AeadSession` from
  Task 3 for the `omnifi-confirm` exchange and the resulting session). No third-party Noise
  dependency is added to `omnifi_core`.
- **Tests that must pass regardless of choice:** `test/crypto/handshake_test.dart`,
  `test/crypto/handshake_kat_test.dart`. These are written against the `Handshake` interface,
  not against the construction. If a vetted Noise IK package later appears, or if we decide
  to port `snow`'s IK after all, the body of `OmniFiHandshakeV1` is replaced by an adapter and
  these same tests are the acceptance gate. **The decision is reversible** — the interface and
  the test suite are the contract, and neither changes.
- **Review obligation:** OmniFi Session Handshake v1 is a hand-rolled construction and has
  **not** been security reviewed. Before any release — public beta included — the construction
  and its implementation must get a dedicated cryptographic review by a reviewer who did not
  author it, covering at minimum: transcript binding and initiator/responder ordering, the
  HKDF salt/IKM assignment, the PSK path used during pairing, key-compromise-impersonation
  and unknown-key-share resistance, confirmation-tag replay, and ephemeral key zeroisation.
  The same obligation would apply verbatim to option (b); it is not a reason to have preferred
  (b) over (c). Track this as a release blocker, not as a follow-up.
- **Known non-goal:** OmniFi Session Handshake v1 is deliberately *not* wire-compatible with
  Noise IK. It must not be described as "Noise" in user-facing or marketing material.
