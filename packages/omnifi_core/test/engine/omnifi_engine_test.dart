import 'dart:async';
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

/// A watcher whose [write] genuinely suspends, for a duration that depends on
/// the content. Without it every write completes in the same microtask and an
/// out-of-order completion is unobservable.
class SlowWriteClipboardWatcher implements ClipboardWatcher {
  SlowWriteClipboardWatcher(this.delayFor);

  final Duration Function(ClipboardContent content) delayFor;

  final StreamController<ClipboardContent> _changes =
      StreamController<ClipboardContent>.broadcast();

  /// Every write, in the order the writes actually *completed*.
  final List<String> completedWrites = [];

  ClipboardContent? current;

  @override
  Stream<ClipboardContent> get changes => _changes.stream;

  @override
  Future<void> write(ClipboardContent content) async {
    await Future<void>.delayed(delayFor(content));
    current = content;
    completedWrites.add(utf8.decode(content.data));
  }

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {
    if (!_changes.isClosed) await _changes.close();
  }
}

Map<String, Object?> clipboardPayload(String text, int timestampMs) {
  final data = Uint8List.fromList(utf8.encode(text));
  return ClipboardPayload(
    format: 'text',
    data: data,
    timestampMs: timestampMs,
    contentHash: clipboardHash('text', data),
  ).toMap();
}

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

  test('two clipboard envelopes from one peer are applied in order', () async {
    // The first write is deliberately much slower than the second. An
    // unserialized `inbound.listen(clipboard.handleIncoming)` would let the
    // second write complete first, leaving the clipboard holding 'older'
    // while the recorded hash/timestamp say 'newer' -- after which the stale
    // content is rebroadcast as if it were new.
    final watcher = SlowWriteClipboardWatcher((c) =>
        utf8.decode(c.data) == 'older'
            ? const Duration(milliseconds: 60)
            : const Duration(milliseconds: 1));
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

    // Back-to-back: nothing waits for the first envelope to be *applied*
    // before the second one is on the wire.
    await remote.send(MessageType.clipboardUpdate,
        clipboardPayload('older', 1753200001000));
    await remote.send(MessageType.clipboardUpdate,
        clipboardPayload('newer', 1753200002000));

    await Future<void>.delayed(const Duration(milliseconds: 400));

    expect(watcher.completedWrites, ['older', 'newer']);
    expect(utf8.decode(watcher.current!.data), 'newer');
    // The recorded state must describe what the clipboard actually holds.
    expect(
      e.clipboard.lastAppliedHash,
      clipboardHash('text', watcher.current!.data),
    );
  });
}
