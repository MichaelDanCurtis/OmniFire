import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:omnifi_app/platform/clipboard_watcher_impl.dart';
import 'package:omnifi_app/platform/power_events.dart';
import 'package:omnifi_app/platform/secure_store_impl.dart';
import 'package:omnifi_core/omnifi_core.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const secureChannel = MethodChannel('com.omnifi/secure_store');
  const clipboardChannel = MethodChannel('com.omnifi/clipboard');
  const clipboardEvents = EventChannel('com.omnifi/clipboard/changes');
  const powerEvents = EventChannel('com.omnifi/power');

  final calls = <MethodCall>[];

  /// Set by a test that wants `read` to fail instead of returning a value.
  PlatformException? secureReadFailure;

  setUp(() {
    calls.clear();
    secureReadFailure = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(secureChannel, (call) async {
      calls.add(call);
      if (call.method == 'read') {
        final failure = secureReadFailure;
        if (failure != null) throw failure;
        return 'stored-value';
      }
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

  // --- Beyond the brief. Each of the following guards a failure mode that
  // --- compiles, analyzes and passes every test above while the app silently
  // --- does nothing at runtime.

  test('a failing keychain read surfaces rather than reading as absent',
      () async {
    // The single most expensive silent failure in this app. `read` returning
    // null is how `loadOrCreateIdentity` is told "first run"; if a real
    // keychain error were mapped to null instead of thrown, every launch
    // after a keychain fault would mint a fresh identity and the device would
    // become a stranger to every peer it had paired with.
    secureReadFailure = PlatformException(code: 'keychain', message: '-25308');
    await expectLater(
      PlatformSecureStore().read('omnifi.identity.deviceId'),
      throwsA(isA<PlatformException>()),
    );
  });

  test('clipboard start and stop use the names the plugin answers to',
      () async {
    // Nothing else checks these. A watcher whose `start` invoked some other
    // method name would leave the poller unstarted: no error, no event, and
    // an app that looks healthy and syncs nothing.
    final watcher = PlatformClipboardWatcher();
    await watcher.start();
    await watcher.stop();
    expect(calls.map((c) => c.method), ['start', 'stop']);
    expect(calls.first.arguments, isNull);
  });

  test('a clipboard event decodes through the real codec, concealed included',
      () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockStreamHandler(
      clipboardEvents,
      MockStreamHandler.inline(onListen: (arguments, events) {
        // Exactly the shape ClipboardPlugin.swift sinks: a String format, a
        // FlutterStandardTypedData payload (which the standard codec hands
        // back as Uint8List, not List<int>) and a bool.
        events.success(<Object?, Object?>{
          'format': 'text',
          'data': Uint8List.fromList([104, 105]),
          'concealed': true,
        });
        events.endOfStream();
      }),
    );

    final content = await PlatformClipboardWatcher().changes.first;
    expect(content.format, 'text');
    expect(content.data, [104, 105]);
    expect(content.isConcealed, isTrue);
  });

  test('a clipboard event without a concealed flag is treated as not concealed',
      () async {
    // The default has to be false, not true: defaulting to concealed would
    // make ClipboardSync drop every update and sync nothing at all.
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockStreamHandler(
      clipboardEvents,
      MockStreamHandler.inline(onListen: (arguments, events) {
        events.success(<Object?, Object?>{
          'format': 'text',
          'data': Uint8List.fromList([104]),
        });
        events.endOfStream();
      }),
    );

    expect((await PlatformClipboardWatcher().changes.first).isConcealed,
        isFalse);
  });

  test('power events surface the platform strings unchanged', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockStreamHandler(
      powerEvents,
      MockStreamHandler.inline(onListen: (arguments, events) {
        events.success('sleep');
        events.success('wake');
        events.endOfStream();
      }),
    );

    expect(await PowerEvents().events.toList(), ['sleep', 'wake']);
  });

  test('one clipboard watcher listens to the platform once', () async {
    // `EventChannel.receiveBroadcastStream()` sends a fresh `listen` on every
    // call, and ClipboardPlugin keeps a single sink: a second listen would
    // replace the first one's sink, so a watcher that rebuilt its stream per
    // access would silently strand whichever subscriber got there first.
    final listens = <Object?>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockStreamHandler(
      clipboardEvents,
      MockStreamHandler.inline(onListen: (arguments, events) {
        listens.add(arguments);
      }),
    );

    final watcher = PlatformClipboardWatcher();
    watcher.changes.listen((_) {});
    watcher.changes.listen((_) {});
    await null;
    await null;
    expect(listens, hasLength(1));
  });
}
