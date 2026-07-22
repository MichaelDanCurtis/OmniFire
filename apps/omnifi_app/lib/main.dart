import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';

import 'app.dart';
import 'engine_provider.dart';

/// Where the relay lives until it is configurable. Matches the default the
/// core's own engine tests use.
final Uri _defaultRelay = Uri.parse('http://localhost:8787');

/// Builds the engine this shell runs on.
///
/// **The two platform adapters below are placeholders, and the app is not
/// usable for real syncing until they are replaced.** omnifi_core deliberately
/// declares [SecureStore] and [ClipboardWatcher] as interfaces whose
/// implementations "live in the Flutter app", and those implementations —
/// Keychain on macOS/iOS, Credential Manager on Windows, and a real pasteboard
/// watcher on each — are platform-channel work that this task does not cover.
///
/// Consequences, stated rather than discovered later:
///  * [InMemorySecureStore] means the device identity and the mesh roster are
///    regenerated on every launch. Every pairing is lost on restart, and this
///    device appears to its peers as a brand-new, unauthorized device.
///  * [FakeClipboardWatcher] never observes the system clipboard and never
///    writes to it, so nothing actually syncs. The engine, transport and
///    crypto all run; only the two ends are stubs.
Future<OmniFiEngine> bootstrapEngine() => OmniFiEngine.create(
      store: InMemorySecureStore(),
      watcher: FakeClipboardWatcher(),
      config: EngineConfig(
        // A list, not a single base: every entry becomes its own dialer and
        // they compete as candidate links. There is no `relayBase`.
        relayBases: [_defaultRelay],
        displayName: 'OmniFi',
        // Null discovery means "accept, but never dial": the engine still
        // binds a LAN listener and adopts inbound connections, it just
        // contributes no LAN candidate of its own. A real responder is
        // platform work; see EngineConfig.lanDiscovery.
        lanDiscovery: null,
      ),
    );

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final engine = await bootstrapEngine();
  runApp(EngineHost(
    engine: engine,
    // awaitPeerLink is left null: omnifi_core has no pairing rendezvous yet,
    // so there is no link to hand PairingScreen. The button stays visible and
    // disabled rather than being hidden.
    child: OmniFiApp(engine: engine),
  ));
}
