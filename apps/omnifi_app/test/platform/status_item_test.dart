import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:omnifi_app/platform/status_item.dart';
import 'package:omnifi_core/omnifi_core.dart';

/// A [FakeClipboardWatcher] that remembers it was stopped, and can be made to
/// fail on the way out.
///
/// Being stopped is the only externally visible thing `OmniFiEngine.stop()`
/// does that a test can observe *at the instant* a later call arrives, which
/// is what the quit-ordering test needs. Watching `engine.statuses` instead
/// would not do: `stop()` publishes `offline` on a broadcast stream, so
/// whether that event has been delivered by the time `terminate` is invoked is
/// a microtask race, and a test resting on it would be measuring scheduling
/// rather than ordering.
class _RecordingWatcher extends FakeClipboardWatcher {
  bool stopped = false;
  bool failOnStop = false;

  @override
  Future<void> stop() async {
    stopped = true;
    if (failOnStop) throw StateError('teardown failed');
    await super.stop();
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const methods = MethodChannel('com.omnifi/status_item');
  const commands = EventChannel('com.omnifi/status_item/commands');

  late _RecordingWatcher watcher;
  late OmniFiEngine engine;
  late StatusItemBridge bridge;

  /// Every call the bridge pushed down, in order.
  final calls = <MethodCall>[];

  /// Whether the engine's clipboard had already been stopped by the time
  /// `terminate` arrived. Null until `terminate` arrives at all.
  bool? stoppedBeforeTerminate;

  /// Lets a test push a command up the way the menu does.
  MockStreamHandlerEventSink? commandSink;

  /// Completes the next time the named method is pushed down.
  final Map<String, Completer<MethodCall>> waiters = {};

  Future<MethodCall> awaiting(String method) =>
      (waiters[method] = Completer<MethodCall>())
          .future
          .timeout(const Duration(seconds: 5));

  setUp(() async {
    calls.clear();
    waiters.clear();
    stoppedBeforeTerminate = null;
    commandSink = null;

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(methods, (call) async {
      // Sampled before the call is recorded, so the assertion is about the
      // engine's state at the moment the request landed.
      if (call.method == 'terminate') {
        stoppedBeforeTerminate = watcher.stopped;
      }
      calls.add(call);
      waiters.remove(call.method)?.complete(call);
      return null;
    });

    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockStreamHandler(
      commands,
      MockStreamHandler.inline(
        onListen: (arguments, events) => commandSink = events,
        onCancel: (arguments) => commandSink = null,
      ),
    );

    watcher = _RecordingWatcher();
    engine = await OmniFiEngine.create(
      store: InMemorySecureStore(),
      watcher: watcher,
      config: EngineConfig(
        relayBases: [Uri.parse('http://localhost:8787')],
        displayName: 'Test',
      ),
    );
    bridge = StatusItemBridge(engine);
  });

  tearDown(() async {
    await bridge.dispose();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      ..setMockMethodCallHandler(methods, null)
      ..setMockStreamHandler(commands, null);
  });

  /// Pushes one status onto `engine.statuses` through the engine's own
  /// publisher rather than a stand-in stream.
  ///
  /// `forgetPeer` republishes [OmniFiEngine.status] as its last act, and
  /// forgetting a device that was never in the roster is a no-op everywhere
  /// else in it. That makes it the one lever a test has on the real stream
  /// without a socket: `debugSetPeerStatus` writes the map but publishes
  /// nothing, and swapping in a `StreamController` here would test that the
  /// bridge can listen to *a* stream rather than to the engine's.
  Future<void> publishStatus(ConnectionStatus status) async {
    engine.debugSetPeerStatus('a' * 32, status);
    await engine.forgetPeer('never-added');
    await pumpEventQueue();
  }

  void sendCommand(String command) {
    expect(commandSink, isNotNull,
        reason: 'the bridge never subscribed to the command channel');
    commandSink!.success(command);
  }

  List<MethodCall> callsTo(String method) =>
      calls.where((c) => c.method == method).toList();

  // 1 -----------------------------------------------------------------------

  test('the four statuses do not collapse onto a shared wire string', () {
    final wire = ConnectionStatus.values.map(statusItemWireName).toList();

    // The assertion that matters is the *distinctness*, not the spelling. A
    // mapping that sent `connectedRelay` down as 'connectedDirect' would still
    // "have a mapping for every state"; it would just make the menu bar claim
    // a direct link while the bytes went through a third party.
    expect(wire.toSet(), hasLength(ConnectionStatus.values.length));

    // And the spelling, because the far end is a Swift switch whose default
    // case can only fall back to something meaningless. These four strings are
    // the contract with StatusItemPlugin.swift.
    expect(wire, [
      'connectedDirect',
      'connectedRelay',
      'reconnecting',
      'offline',
    ]);
  });

  // 2 -----------------------------------------------------------------------

  test('start pushes the status and pause state the engine already has',
      () async {
    engine.clipboard.setPaused(true);
    await bridge.start();

    // Without this the item sits on whatever the Swift side defaulted to until
    // something changes — which, on a machine with no peers, is never.
    expect(callsTo('setStatus').single.arguments, {'status': 'offline'});
    expect(callsTo('setPaused').single.arguments, {'paused': true});
  });

  test('a status change pushes exactly one setStatus carrying that status',
      () async {
    await bridge.start();
    calls.clear();

    await publishStatus(ConnectionStatus.connectedRelay);

    expect(callsTo('setStatus'), hasLength(1));
    expect(callsTo('setStatus').single.arguments, {'status': 'connectedRelay'});
  });

  test('start twice does not attach a second listener', () async {
    // `start()` is called once from main() today, but the bridge outlives
    // every screen and a double subscription would not announce itself — it
    // would push every status down twice, which is invisible right up until
    // it is an icon that flickers.
    await bridge.start();
    await bridge.start();
    calls.clear();

    await publishStatus(ConnectionStatus.reconnecting);
    expect(callsTo('setStatus'), hasLength(1));
  });

  // 3 -----------------------------------------------------------------------

  test('togglePause flips the clipboard and pushes the new state back down',
      () async {
    await bridge.start();
    calls.clear();

    var pushed = awaiting('setPaused');
    sendCommand('togglePause');
    await pushed;
    expect(engine.clipboard.isPaused, isTrue);
    expect(callsTo('setPaused').last.arguments, {'paused': true});

    pushed = awaiting('setPaused');
    sendCommand('togglePause');
    await pushed;
    expect(engine.clipboard.isPaused, isFalse);
    expect(callsTo('setPaused').last.arguments, {'paused': false});
  });

  test('unchecking pause while the screen lock holds it reports still paused',
      () async {
    // The trap in a two-way toggle. `ClipboardSync.isPaused` is the OR of a
    // user pause and a lock pause, so clearing the user's half while the
    // screen is locked changes nothing observable: sync is still paused. A
    // bridge that echoed the value it *asked for* rather than the value the
    // clipboard now *reports* would clear the checkmark and tell the user
    // syncing had resumed when it had not.
    engine.onScreenLocked();
    engine.clipboard.setPaused(true);
    await bridge.start();
    calls.clear();

    final pushed = awaiting('setPaused');
    sendCommand('togglePause');
    await pushed;

    expect(engine.clipboard.isPaused, isTrue);
    expect(callsTo('setPaused').last.arguments, {'paused': true});
  });

  test('pushPaused republishes a pause the engine imposed on itself', () async {
    // Screen lock pauses the clipboard with no user action and no stream to
    // announce it. main() re-pushes after every lock and unlock; without that
    // the menu would read "syncing" straight through a locked screen.
    await bridge.start();
    calls.clear();

    engine.onScreenLocked();
    await bridge.pushPaused();
    expect(callsTo('setPaused').single.arguments, {'paused': true});

    engine.onScreenUnlocked();
    await bridge.pushPaused();
    expect(callsTo('setPaused').last.arguments, {'paused': false});
  });

  // 4 -----------------------------------------------------------------------

  test('quit stops the engine before it asks to be terminated', () async {
    await bridge.start();

    final terminated = awaiting('terminate');
    sendCommand('quit');
    await terminated;

    // The hazard exactly: terminating first leaves the last peer holding a
    // socket that looks alive until its liveness timeout expires.
    expect(stoppedBeforeTerminate, isTrue);
  });

  test('a failed teardown is not followed by a terminate', () async {
    // Losing the clean shutdown is bad; losing it silently is worse. If
    // `stop()` fails there is no clean exit left to make, and terminating
    // anyway would discard the one signal that something went wrong.
    await bridge.start();
    watcher.failOnStop = true;

    await expectLater(bridge.handleCommand('quit'), throwsStateError);
    expect(callsTo('terminate'), isEmpty);
  });

  // -------------------------------------------------------------------------

  test('openWindow shows the window and does not also hide it', () async {
    await bridge.start();
    calls.clear();

    final shown = awaiting('show');
    sendCommand('openWindow');
    await shown;
    expect(calls.map((c) => c.method), ['show']);
  });

  test('hideWindow asks for hide, not show', () async {
    await bridge.hideWindow();
    expect(calls.single.method, 'hide');
  });

  test('an unrecognised command is ignored rather than fatal', () async {
    await bridge.start();
    calls.clear();

    sendCommand('selfDestruct');
    await pumpEventQueue();
    expect(calls, isEmpty);
  });

  // 5 -----------------------------------------------------------------------

  test('a missing plugin does not take the app down with it', () async {
    // What a build without StatusItemPlugin sees: the channel exists in Dart
    // and nothing answers it. A bridge that threw out of `start()` would turn
    // an absent menu bar into a failed launch, and `quit` rides the same
    // channel — an unhandled throw there would leave the engine stopped and
    // the app still running.
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(methods, null);

    await expectLater(bridge.start(), completes);
    await expectLater(bridge.pushPaused(), completes);
    await expectLater(bridge.handleCommand('openWindow'), completes);
  });

  test('a platform error that is not a missing plugin is not swallowed',
      () async {
    // The other half of that guard. Catching every PlatformException would
    // make a status item that has stopped updating indistinguishable from one
    // that is up to date.
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(methods, (call) async {
      throw PlatformException(code: 'no_status_bar');
    });

    await expectLater(bridge.start(), throwsA(isA<PlatformException>()));
  });
}
