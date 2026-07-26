import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';

import 'app.dart';
import 'engine_provider.dart';
import 'platform/clipboard_watcher_impl.dart';
import 'platform/lifecycle.dart';
import 'platform/power_events.dart';
import 'platform/secure_store_impl.dart';

/// Where the relay lives until it is configurable at runtime.
///
/// `relay/` in this repo is the worker, and `npx wrangler dev --port 8787` is
/// how it runs locally; that is what this default points at. Anything else is
/// supplied at build time:
/// `flutter build macos --dart-define=OMNIFI_RELAY=https://...`.
const String _relay = String.fromEnvironment(
  'OMNIFI_RELAY',
  defaultValue: 'http://localhost:8787',
);

/// A second relay backend, off by default.
///
/// [EngineConfig.relayBases] is a list because each entry becomes its own
/// dialer and they compete as candidate links — a relay that is down simply
/// never becomes a candidate, so an outage on one backend is invisible. That
/// only holds for backends that *exist*: an entry pointing at a host that was
/// never deployed is a dialer whose sole behaviour is to fail, and it costs a
/// timeout per peer per backoff round. So the second slot stays empty unless
/// someone names one.
const String _relayFallback = String.fromEnvironment('OMNIFI_RELAY_FALLBACK');

/// Builds the engine this shell runs on, on the real platform adapters.
Future<OmniFiEngine> bootstrapEngine() => OmniFiEngine.create(
      // Keychain, via macOS `SecureStorePlugin`. This is what makes the device
      // identity survive a relaunch, and so what makes a pairing outlive the
      // process that made it.
      store: PlatformSecureStore(),
      // The real NSPasteboard, polled. Concealed entries (a password manager's
      // clipboard parking) are flagged at the plugin and dropped by
      // ClipboardSync before they can reach a peer.
      watcher: PlatformClipboardWatcher(),
      config: EngineConfig(
        relayBases: [
          Uri.parse(_relay),
          if (_relayFallback.isNotEmpty) Uri.parse(_relayFallback),
        ],
        displayName: 'OmniFi',
        // Null discovery means "accept, but never dial": the engine still
        // binds a LAN listener and adopts inbound connections, it just
        // contributes no LAN candidate of its own. A responder needs an mDNS
        // advertiser, which this task does not add.
        lanDiscovery: null,
      ),
    );

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final OmniFiEngine engine;
  try {
    engine = await bootstrapEngine();
  } catch (error) {
    // Deliberately not recovered from. The one failure that reaches here and
    // matters is a partial identity in the keychain, which the core refuses to
    // continue past precisely because regenerating would orphan this device
    // from every peer it has paired with. Showing the error and stopping is
    // the correct behaviour; anything that "fixed it up" would be the bug.
    runApp(_StartupFailureApp(error: error));
    return;
  }

  // The real thing, not Flutter's app-lifecycle approximation of it.
  // `didChangeAppLifecycleState` reports foreground and background; it says
  // nothing when the lid closes with the app frontmost, which is exactly the
  // case that leaves the engine holding a suspended socket that still looks
  // connected. Kept for the whole process lifetime, so no subscription handle
  // is retained.
  //
  // Guarded by platform, because `com.omnifi/power` only has a plugin behind
  // it on macOS. Subscribing on iOS would not throw — `EventChannel` reports a
  // failed `listen` through `FlutterError.reportError` rather than into the
  // stream — but it would log an error on every single launch, and a log line
  // that is always there is a log line nobody reads. iOS has no equivalent
  // signal to offer a foreground-only app anyway: sleep and wake are the
  // lifecycle transitions below, and there is no lock notification.
  if (Platform.isMacOS) {
    PowerEvents().events.listen((event) {
      switch (event) {
        case 'wake':
          // Forces every LinkManager to redial now rather than wait out a
          // backoff that started before the machine went to sleep.
          unawaited(engine.onWake());
        case 'lock':
          engine.onScreenLocked();
        case 'unlock':
          engine.onScreenUnlocked();
        case 'sleep':
          // Nothing to do: the engine has no teardown-on-sleep, and the links
          // are already suspended by the OS by the time this arrives. It is
          // 'wake' that does the work.
          break;
      }
    });
  }

  // The engine's lifetime, tied to the app being in front of the user.
  //
  // This is what makes the phone a device that answers only while its owner
  // is present, rather than a service that happens to be unreachable most of
  // the time: on `paused` the engine tears its links down itself, while there
  // is still a run loop to do it in, instead of leaving iOS to sever a socket
  // the peer then has to discover by timeout. On macOS `paused` never arrives
  // and `inactive`/`hidden` are inert, so a desktop agent runs uninterrupted.
  //
  // Held for the process lifetime; there is no symmetric `removeObserver`
  // because there is no point at which this should stop being true.
  final lifecycle = LifecycleBridge(
    onResume: engine.start,
    onPause: engine.stop,
  );
  WidgetsBinding.instance.addObserver(lifecycle);
  try {
    // Awaited, and inside the same failure posture as `bootstrapEngine`.
    // `engine.start()` does not block on any network dial — `LinkManager`
    // fires those unawaited — so the only things being waited on here are
    // `clipboard.start()` and the LAN listener's bind. The first of those is
    // a platform-channel call, which means an unregistered plugin surfaces
    // right here as `MissingPluginException` on a visible failure screen,
    // rather than as an app that launches, looks entirely healthy, and syncs
    // nothing. `EngineHost.initState` calls `start()` again a moment later;
    // that one returns immediately, because the engine's own `_started` flag
    // makes it idempotent.
    await lifecycle.handle(AppLifecycleState.resumed);
  } catch (error) {
    runApp(_StartupFailureApp(error: error));
    return;
  }

  runApp(EngineHost(
    engine: engine,
    // awaitPeerLink is left null: wiring the pairing rendezvous into the shell
    // is a separate task. The button stays visible and disabled rather than
    // being hidden.
    child: OmniFiApp(engine: engine),
  ));
}

/// Shown instead of the app when the engine cannot be built at all.
class _StartupFailureApp extends StatelessWidget {
  const _StartupFailureApp({required this.error});

  final Object error;

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'OmniFi',
        theme: ThemeData(useMaterial3: true),
        home: Scaffold(
          body: Center(
            child: Padding(
              padding: const EdgeInsets.all(32),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'OmniFi could not start',
                    style: Theme.of(context).textTheme.headlineSmall,
                  ),
                  const SizedBox(height: 16),
                  SelectableText('$error'),
                ],
              ),
            ),
          ),
        ),
      );
}
