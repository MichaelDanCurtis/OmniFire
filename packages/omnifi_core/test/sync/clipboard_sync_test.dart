import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

import '../support/fake_link.dart';

int _now = 1753200000000;
int testClock() => _now;

ClipboardContent text(String s, {bool concealed = false}) => ClipboardContent(
      format: 'text',
      data: Uint8List.fromList(utf8.encode(s)),
      isConcealed: concealed,
    );

({PeerSession local, PeerSession remote}) linkedSessions() {
  final k1 = List<int>.filled(32, 11);
  final k2 = List<int>.filled(32, 22);
  final local = PeerSession(
    localDeviceId: 'a' * 32,
    peerDeviceId: 'b' * 32,
    crypto: AeadSession(sendKey: k1, receiveKey: k2),
    clock: testClock,
  );
  final remote = PeerSession(
    localDeviceId: 'b' * 32,
    peerDeviceId: 'a' * 32,
    crypto: AeadSession(sendKey: k2, receiveKey: k1),
    clock: testClock,
  );
  final links = FakeLink.connectedPair();
  local.attach(links.a);
  remote.attach(links.b);
  return (local: local, remote: remote);
}

void main() {
  setUp(() => _now = 1753200000000);

  test('hash is stable and format-sensitive', () {
    expect(clipboardHash('text', utf8.encode('x')),
        clipboardHash('text', utf8.encode('x')));
    expect(clipboardHash('text', utf8.encode('x')),
        isNot(clipboardHash('png', utf8.encode('x'))));
  });

  test('broadcasts a local copy to peers', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    final received = s.remote.inbound.first;
    watcher.emit(text('copied on mac'));

    final envelope = await received;
    expect(envelope.type, MessageType.clipboardUpdate);
    final payload = ClipboardPayload.fromMap(envelope.payload);
    expect(utf8.decode(payload.data), 'copied on mac');
  });

  test('applies an incoming update to the local clipboard', () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();

    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: ClipboardPayload(
        format: 'text',
        data: Uint8List.fromList(utf8.encode('from pc')),
        timestampMs: _now,
        contentHash: clipboardHash('text', utf8.encode('from pc')),
      ).toMap(),
    ));

    expect(utf8.decode(watcher.current!.data), 'from pc');
  });

  test('does not echo content it just applied', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    final incoming = text('round trip');
    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: ClipboardPayload(
        format: 'text',
        data: incoming.data,
        timestampMs: _now,
        contentHash: clipboardHash('text', incoming.data),
      ).toMap(),
    ));

    // The platform watcher now fires for our own write. Without loop
    // prevention this is where two machines ping-pong forever.
    var broadcasts = 0;
    s.remote.inbound.listen((_) => broadcasts++);
    watcher.emit(incoming);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(broadcasts, 0);
  });

  test(
      'does not echo applied content even when the peer sent a mismatched '
      'contentHash', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    final incoming = text('round trip, wrong hash');
    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: ClipboardPayload(
        format: 'text',
        data: incoming.data,
        timestampMs: _now,
        // Deliberately wrong: does not match the hash of `incoming.data`.
        // A buggy or malicious peer could send this; the receiver must not
        // trust it, since it is the mechanism that suppresses our own
        // write echoing back through the platform watcher.
        contentHash: clipboardHash('text', utf8.encode('not the real body')),
      ).toMap(),
    ));

    // The platform watcher now fires for our own write of the applied
    // content. Loop prevention must key off what was actually applied, not
    // the peer-declared hash, or this echoes straight back to the peer.
    var broadcasts = 0;
    s.remote.inbound.listen((_) => broadcasts++);
    watcher.emit(incoming);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(broadcasts, 0);
  });

  test('a genuinely new copy after an applied one still broadcasts',
      () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: ClipboardPayload(
        format: 'text',
        data: Uint8List.fromList(utf8.encode('applied')),
        timestampMs: _now,
        contentHash: clipboardHash('text', utf8.encode('applied')),
      ).toMap(),
    ));
    watcher.emit(text('applied'));

    final received = s.remote.inbound.first;
    watcher.emit(text('genuinely new'));
    final payload = ClipboardPayload.fromMap((await received).payload);
    expect(utf8.decode(payload.data), 'genuinely new');
  });

  test('skips concealed content from a password manager', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    var broadcasts = 0;
    s.remote.inbound.listen((_) => broadcasts++);
    watcher.emit(text('hunter2', concealed: true));
    await Future<void>.delayed(const Duration(milliseconds: 20));

    expect(broadcasts, 0);
    expect(sync.skippedConcealedCount, 1);
  });

  test('sends a too-large marker instead of an oversized payload', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    final received = s.remote.inbound.first;
    watcher.emit(ClipboardContent(
      format: 'text',
      data: Uint8List(maxClipboardBytes + 1),
      isConcealed: false,
    ));

    expect((await received).type, MessageType.clipboardTooLarge);
    expect(sync.skippedOversizedCount, 1);
  });

  test('pausing stops outgoing broadcasts', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();
    sync.setPaused(true);

    var broadcasts = 0;
    s.remote.inbound.listen((_) => broadcasts++);
    watcher.emit(text('while paused'));
    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(broadcasts, 0);
  });

  test('screen lock pauses and unlock resumes', () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    sync.onScreenLocked();
    expect(sync.isPaused, isTrue);
    sync.onScreenUnlocked();
    expect(sync.isPaused, isFalse);

    final received = s.remote.inbound.first;
    watcher.emit(text('after unlock'));
    expect(
      utf8.decode(ClipboardPayload.fromMap((await received).payload).data),
      'after unlock',
    );
  });

  test('an explicit pause survives an unlock', () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();
    sync.setPaused(true);
    sync.onScreenLocked();
    sync.onScreenUnlocked();
    expect(sync.isPaused, isTrue,
        reason: 'unlocking must not override a deliberate user pause');
  });

  test('an older incoming update loses to a newer applied one', () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();

    Envelope at(int ts, String body) => Envelope(
          version: omnifiProtocolVersion,
          type: MessageType.clipboardUpdate,
          senderDeviceId: 'b' * 32,
          messageId: 'm' * 32,
          timestampMs: ts,
          payload: ClipboardPayload(
            format: 'text',
            data: Uint8List.fromList(utf8.encode(body)),
            timestampMs: ts,
            contentHash: clipboardHash('text', utf8.encode(body)),
          ).toMap(),
        );

    await sync.handleIncoming(at(_now + 1000, 'newer'));
    await sync.handleIncoming(at(_now, 'older'));
    expect(utf8.decode(watcher.current!.data), 'newer');
  });

  test('ignores a message type it does not handle', () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();
    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.heartbeat,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: const {},
    ));
    expect(watcher.current, isNull);
  });

  // --- REPRO (stage 1, no source fix yet): a far-future timestamp from a
  // skewed or malicious peer must not poison `_lastAppliedTimestampMs`. ---
  test(
      'a far-future timestamp does not poison state against a later '
      'legitimate update', () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();

    const tenYearsMs = 10 * 365 * 24 * 60 * 60 * 1000;
    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now + tenYearsMs,
      payload: ClipboardPayload(
        format: 'text',
        data: Uint8List.fromList(utf8.encode('from a skewed clock')),
        timestampMs: _now + tenYearsMs,
        contentHash:
            clipboardHash('text', utf8.encode('from a skewed clock')),
      ).toMap(),
    ));

    // A subsequent legitimate update, timestamped at the real current time,
    // must still apply. Pre-fix this fails: the far-future payload above
    // sets `_lastAppliedTimestampMs` ten years ahead, so every real update
    // looks "older" and is silently dropped forever.
    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: ClipboardPayload(
        format: 'text',
        data: Uint8List.fromList(utf8.encode('legitimate update')),
        timestampMs: _now,
        contentHash: clipboardHash('text', utf8.encode('legitimate update')),
      ).toMap(),
    ));

    expect(utf8.decode(watcher.current!.data), 'legitimate update');
    expect(sync.skippedSkewedCount, 1);
  });

  test('a timestamp within tolerance of the local clock is still accepted',
      () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();

    // Comfortably inside the 5-minute tolerance -- the bound must not
    // simply reject everything.
    final withinToleranceMs = maxClockSkewMs - 1000;
    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now + withinToleranceMs,
      payload: ClipboardPayload(
        format: 'text',
        data: Uint8List.fromList(utf8.encode('slightly ahead')),
        timestampMs: _now + withinToleranceMs,
        contentHash: clipboardHash('text', utf8.encode('slightly ahead')),
      ).toMap(),
    ));

    expect(utf8.decode(watcher.current!.data), 'slightly ahead');
    expect(sync.skippedSkewedCount, 0);
  });

  // --- REPRO (stage 1, no source fix yet): the outgoing path must not
  // throw uncaught when the platform watcher reports an unsupported
  // format. ---
  test('an unsupported outgoing format is skipped, not thrown uncaught',
      () async {
    final s = linkedSessions();
    final watcher = FakeClipboardWatcher();
    final sync = ClipboardSync(
      watcher: watcher, peers: () => [s.local], clock: testClock);
    await sync.start();

    var broadcasts = 0;
    s.remote.inbound.listen((_) => broadcasts++);

    watcher.emit(ClipboardContent(
      format: 'rtf',
      data: Uint8List.fromList(utf8.encode(r'{\rtf1 hello}')),
      isConcealed: false,
    ));
    await Future<void>.delayed(const Duration(milliseconds: 20));

    expect(broadcasts, 0);
    expect(sync.skippedUnsupportedFormatCount, 1);
  });

  // --- Minor: the incoming size-cap check had no direct test (the outgoing
  // one does). This is a regression guard for code already verified correct
  // by inspection, not a reproduction of a bug. ---
  test('an oversized incoming payload is not applied', () async {
    final watcher = FakeClipboardWatcher();
    final sync =
        ClipboardSync(watcher: watcher, peers: () => [], clock: testClock);
    await sync.start();

    final oversized = Uint8List(maxClipboardBytes + 1);
    await sync.handleIncoming(Envelope(
      version: omnifiProtocolVersion,
      type: MessageType.clipboardUpdate,
      senderDeviceId: 'b' * 32,
      messageId: 'm' * 32,
      timestampMs: _now,
      payload: ClipboardPayload(
        format: 'png',
        data: oversized,
        timestampMs: _now,
        contentHash: clipboardHash('png', oversized),
      ).toMap(),
    ));

    expect(watcher.current, isNull);
  });
}
