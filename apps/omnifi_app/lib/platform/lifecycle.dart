import 'package:flutter/widgets.dart';

/// Ties the engine's lifetime to the app being in the foreground.
///
/// On iOS this is the security model, not a workaround for one. The phone is
/// the device that is always with the user, holds the secrets and — later —
/// answers privileged requests behind Face ID; "it answers only while its
/// owner is present and has authenticated" is a property worth having, and
/// this is where it is enforced. iOS suspends an ordinary app within seconds
/// of backgrounding, and the three ways around that were each considered and
/// rejected: `PushKit` terminates the app unless every wake reports a CallKit
/// call, `NEAppPushProvider` is scoped to a named Wi-Fi SSID so it stops
/// existing on cellular, and `NEPacketTunnelProvider` works but turns the
/// product into a VPN. So the socket is held while the app is in front of the
/// user, and dropped cleanly the moment it is not, rather than being left for
/// the OS to sever and for the peer to discover by timeout.
///
/// On desktop the app is a long-lived agent: macOS reports `inactive` when the
/// window loses focus and `hidden` when it is minimised, and never `paused`,
/// so [handle] is simply never called with a state that stops anything.
///
/// **`inactive` and `hidden` are deliberately inert.** That is not defensive
/// padding. `ServicesBinding` synthesises the states it skipped: a real iOS
/// background delivers `inactive`, then `hidden`, then `paused` as three
/// separate observer callbacks for one gesture. Treating either of the first
/// two as a teardown would stop the engine on every glance at the app
/// switcher and on every notification banner.
class LifecycleBridge with WidgetsBindingObserver {
  LifecycleBridge({required this.onResume, required this.onPause});

  final Future<void> Function() onResume;
  final Future<void> Function() onPause;

  /// What this bridge last asked for, not what the engine reports.
  ///
  /// It has to be tracked here: without it, the synthesised state storm above
  /// and iOS's habit of re-announcing `resumed` would restart a running engine
  /// and stop a stopped one repeatedly.
  bool _running = false;

  /// Whether the bridge currently believes the engine should be running.
  /// Exposed for diagnostics; nothing in the app branches on it.
  bool get isRunning => _running;

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Dropped rather than awaited: the observer callback is synchronous, and
    // `_running` is flipped before the first suspension point inside [handle],
    // so the very next callback already sees the new intent even though the
    // engine's own start or stop is still in flight. The engine tolerates the
    // overlap by design — `stop()` clears its `_started` flag before its first
    // await and `start()` re-checks it after every one.
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
        // Transient — a notification shade, an app-switcher preview, a
        // minimised desktop window. See the class comment: these arrive on the
        // way to every real background, so acting on them would thrash the
        // connection rather than protect it.
        break;
    }
  }
}
