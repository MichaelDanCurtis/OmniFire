# OmniFi

OmniFi: encrypted clipboard sync across macOS, Windows and iOS.

## Layout

- `packages/omnifi_core` — protocol, crypto, identity and transport core. No Flutter dependency, so it can be tested headless.
- `apps/omnifi_app` — the Flutter app shell (macOS, Windows, iOS).
- `relay/` — the Cloudflare Worker that rendezvouses two devices and relays frames between them when they can't reach each other directly.

## Verifying

Run the whole verification gate with:

```
./scripts/verify.sh
```

This runs, in order:

1. `omnifi_core`: `dart analyze` (zero issues) and `dart test`.
2. The pairing/rendezvous **integration suite**. `packages/omnifi_core/dart_test.yaml` skips these by tag for the fast inner loop, because they need a live relay — this is most of what actually discriminates the rendezvous (the latch guard, the role check, inbound buffering, retarget-on-hello, timeout-closes-socket). The script starts a local relay (`wrangler dev`) itself, polls it until it's genuinely healthy, runs `dart test --tags integration --run-skipped` against it, and stops it again on every exit path (success, failure, or interrupt). Nothing needs to be running by hand first.
3. The relay's own tests (`npm test` in `relay/`).
4. The Flutter app: `flutter analyze` and `flutter test` in `apps/omnifi_app`.
5. The structural invariant that `omnifi_core` has no dependency on `package:flutter` or `dart:ui` — that's what keeps the protocol testable without a UI.

It prints the real per-suite test counts, not just a pass/fail flag, and exits non-zero if anything fails, so it's safe to use as a pre-push hook or a CI step. Pass `--no-integration` to skip step 2 as a deliberate, visible opt-out (for example, no network available) — the script never skips it silently on its own.
