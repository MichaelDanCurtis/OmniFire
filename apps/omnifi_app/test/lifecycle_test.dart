import 'package:flutter/services.dart';
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

  test('repeated resumes do not restart an already-running engine', () async {
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

  // --- Beyond the brief. Each of the following guards a failure that the four
  // --- tests above pass straight through.

  test('hidden is ignored, so a minimised desktop window keeps syncing',
      () async {
    // Not a duplicate of the `inactive` case. `hidden` is what macOS reports
    // when the window is minimised or fully occluded and what iOS reports on
    // its way into the background — a bridge that treated it as a pause would
    // tear the engine down every time a desktop user hid the window, and the
    // brief's four tests would all still pass. Checked in both directions:
    // nothing stopped, and the following resume is still a no-op because the
    // engine was never stopped in the first place.
    var starts = 0;
    var stops = 0;
    final bridge = LifecycleBridge(
      onResume: () async => starts++,
      onPause: () async => stops++,
    );
    await bridge.handle(AppLifecycleState.resumed);
    await bridge.handle(AppLifecycleState.hidden);
    await bridge.handle(AppLifecycleState.resumed);
    expect(stops, 0, reason: 'hidden is not a background');
    expect(starts, 1, reason: 'nothing was stopped, so nothing restarts');
  });

  test('a resume after a pause starts again', () async {
    // The whole point of the design: the phone answers only while it is in
    // front of its owner, which is worth nothing if it never comes back.
    // `repeated resumes do not restart` passes even against a bridge that
    // latches `_running` true forever and can never restart.
    var starts = 0;
    var stops = 0;
    final bridge = LifecycleBridge(
      onResume: () async => starts++,
      onPause: () async => stops++,
    );
    await bridge.handle(AppLifecycleState.resumed);
    await bridge.handle(AppLifecycleState.paused);
    await bridge.handle(AppLifecycleState.resumed);
    expect(starts, 2);
    expect(stops, 1);
  });

  test('a pause before any resume does not stop', () async {
    // Symmetric to the repeated-resume guard and just as load-bearing: iOS
    // delivers a lifecycle event before the engine has necessarily been
    // started, and `engine.stop()` on an engine that was never started sets
    // the shutdown latch, so the next start would be running against a
    // teardown that already happened.
    var stops = 0;
    final bridge = LifecycleBridge(
      onResume: () async {},
      onPause: () async => stops++,
    );
    await bridge.handle(AppLifecycleState.paused);
    expect(stops, 0);
  });

  test('repeated pauses stop once', () async {
    var stops = 0;
    final bridge = LifecycleBridge(
      onResume: () async {},
      onPause: () async => stops++,
    );
    await bridge.handle(AppLifecycleState.resumed);
    await bridge.handle(AppLifecycleState.paused);
    await bridge.handle(AppLifecycleState.detached);
    expect(stops, 1);
  });

  test('the observer callback forwards to handle', () async {
    // Every test above calls `handle` directly, so all of them pass against a
    // bridge whose `didChangeAppLifecycleState` override is missing or empty —
    // which is a bridge that never fires at all in the running app.
    var stops = 0;
    final bridge = LifecycleBridge(
      onResume: () async {},
      onPause: () async => stops++,
    )..didChangeAppLifecycleState(AppLifecycleState.resumed);

    bridge.didChangeAppLifecycleState(AppLifecycleState.paused);
    await Future<void>.delayed(Duration.zero);
    expect(stops, 1);
  });

  test('a real platform lifecycle message drives exactly one stop', () async {
    // The real path, not a hand-called method: the platform sends a string on
    // `flutter/lifecycle`, ServicesBinding parses it, and — this is the part
    // no fake would have told us — **synthesises the intermediate states**.
    // Going resumed -> paused delivers `inactive`, then `hidden`, then
    // `paused`, in three separate observer callbacks. So the ignore-inactive
    // and ignore-hidden rules are not defensive padding; they are what stands
    // between one clean teardown and three.
    var starts = 0;
    var stops = 0;
    final seen = <AppLifecycleState>[];
    final bridge = _RecordingBridge(
      seen,
      onResume: () async => starts++,
      onPause: () async => stops++,
    );
    final binding = TestWidgetsFlutterBinding.instance;
    binding.addObserver(bridge);
    addTearDown(() => binding.removeObserver(bridge));

    Future<void> send(AppLifecycleState state) => binding.defaultBinaryMessenger
        .handlePlatformMessage(
          'flutter/lifecycle',
          const StringCodec().encodeMessage(state.toString()),
          (_) {},
        );

    await send(AppLifecycleState.resumed);
    await send(AppLifecycleState.paused);

    expect(
      seen,
      containsAllInOrder(<AppLifecycleState>[
        AppLifecycleState.resumed,
        AppLifecycleState.inactive,
        AppLifecycleState.hidden,
        AppLifecycleState.paused,
      ]),
      reason: 'the framework really does synthesise inactive and hidden',
    );
    expect(starts, 1);
    expect(stops, 1, reason: 'one background is one teardown, not three');
  });
}

/// A bridge that also records every state the framework handed it, so the
/// test can assert on what the platform path actually delivered rather than
/// on what it is assumed to deliver.
class _RecordingBridge extends LifecycleBridge {
  _RecordingBridge(this.seen, {required super.onResume, required super.onPause});

  final List<AppLifecycleState> seen;

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    seen.add(state);
    super.didChangeAppLifecycleState(state);
  }
}
