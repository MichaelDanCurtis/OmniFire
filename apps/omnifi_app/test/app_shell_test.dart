import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:omnifi_app/app.dart';
import 'package:omnifi_app/ui/settings_screen.dart';
import 'package:omnifi_core/omnifi_core.dart';

/// A real engine, not a mock. It is never `start()`ed, so nothing binds a
/// socket; this exercises the shell against the API it actually consumes.
Future<OmniFiEngine> engine() => OmniFiEngine.create(
      store: InMemorySecureStore(),
      watcher: FakeClipboardWatcher(),
      config: EngineConfig(
        relayBases: [Uri.parse('http://localhost:8787')],
        displayName: 'Test',
      ),
    );

PeerRecord peer(String id, String name) => PeerRecord(
      deviceId: id,
      publicKey: List<int>.filled(32, 7),
      displayName: name,
      addedAtMs: 1,
    );

void main() {
  testWidgets('the shell reports offline when no peer is connected',
      (tester) async {
    final e = await engine();
    await tester.pumpWidget(OmniFiApp(engine: e));
    expect(find.text('Offline'), findsOneWidget);
  });

  // The contract that matters. OmniFiEngine.status is the *worst* peer's
  // status, and a shell that surfaced the best one would show "Connected
  // (direct)" while a device sat unreachable — the exact lie the indicator
  // exists to prevent.
  //
  // One engine per test, deliberately. Pumping a second OmniFiApp into the
  // same tree does not re-read `initialData`: StreamBuilder.didUpdateWidget
  // carries its existing snapshot across a stream swap, so the assertion
  // would read the previous engine's status. Production never swaps engines
  // — main() builds exactly one — so this is a test constraint, not a defect.
  testWidgets('a relay peer downgrades a direct one', (tester) async {
    final e = await engine();
    e.debugSetPeerStatus('a' * 32, ConnectionStatus.connectedDirect);
    e.debugSetPeerStatus('b' * 32, ConnectionStatus.connectedRelay);
    await tester.pumpWidget(OmniFiApp(engine: e));
    expect(find.text('Connected (relay)'), findsOneWidget);
    expect(find.text('Connected (direct)'), findsNothing);
  });

  testWidgets('one offline peer makes the whole mesh read offline',
      (tester) async {
    final e = await engine();
    e.debugSetPeerStatus('a' * 32, ConnectionStatus.connectedDirect);
    e.debugSetPeerStatus('b' * 32, ConnectionStatus.offline);
    await tester.pumpWidget(OmniFiApp(engine: e));
    expect(find.text('Offline'), findsOneWidget);
    expect(find.text('Connected (direct)'), findsNothing);
  });

  testWidgets('the roster lists peers and Forget removes one', (tester) async {
    final e = await engine();
    e.mesh.addPeer(peer('a' * 32, 'Laptop'));
    e.mesh.addPeer(peer('b' * 32, 'Phone'));

    await tester.pumpWidget(
      MaterialApp(home: Scaffold(body: SettingsScreen(engine: e))),
    );
    expect(find.text('Laptop'), findsOneWidget);
    expect(find.text('Phone'), findsOneWidget);

    await tester.tap(find.byType(TextButton).first);
    await tester.pumpAndSettle();

    expect(find.text('Laptop'), findsNothing);
    expect(find.text('Phone'), findsOneWidget);
    expect(e.mesh.peer('a' * 32), isNull);
  });

  testWidgets('the pause toggle writes through to the engine',
      (tester) async {
    final e = await engine();
    await tester.pumpWidget(
      MaterialApp(home: Scaffold(body: SettingsScreen(engine: e))),
    );
    expect(e.clipboard.isPaused, isFalse);

    await tester.tap(find.byType(SwitchListTile));
    await tester.pumpAndSettle();

    expect(e.clipboard.isPaused, isTrue);
  });

  testWidgets('the configured relay is shown and marked primary',
      (tester) async {
    final e = await engine();
    await tester.pumpWidget(
      MaterialApp(home: Scaffold(body: SettingsScreen(engine: e))),
    );
    expect(find.text('http://localhost:8787'), findsOneWidget);
    expect(find.textContaining('Primary'), findsOneWidget);
  });

  // Pairing needs a link, and omnifi_core has no rendezvous that produces one
  // for an unpaired device. The action stays visible and disabled so the gap
  // is legible rather than invisible.
  testWidgets('Add a device is disabled without a pairing transport',
      (tester) async {
    final e = await engine();
    await tester.pumpWidget(OmniFiApp(engine: e));
    final fab = tester.widget<FloatingActionButton>(
      find.byType(FloatingActionButton),
    );
    expect(fab.onPressed, isNull);
  });
}
