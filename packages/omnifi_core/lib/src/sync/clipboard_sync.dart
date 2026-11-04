import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../protocol/envelope.dart';
import '../protocol/messages.dart';
import '../session/peer_session.dart';
import 'clipboard_watcher.dart';

const int maxClipboardBytes = 1048576;

/// How far ahead of the local clock an incoming payload's timestamp may be
/// before it is treated as implausible and rejected. Generous enough to
/// absorb genuine inter-device clock skew, tight enough that a poisoned
/// timestamp (buggy clock, or a malicious peer) cannot survive.
const int maxClockSkewMs = 5 * 60 * 1000;

const String _clipboardCollapseKey = 'clipboard';

String clipboardHash(String format, List<int> data) {
  final digest =
      Sha256().toSync().hashSync([...utf8.encode(format), 0, ...data]);
  return digest.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Bridges the platform clipboard to peer sessions.
class ClipboardSync {
  ClipboardSync({
    required ClipboardWatcher watcher,
    required List<PeerSession> Function() peers,
    required int Function() clock,
  })  : _watcher = watcher,
        _peers = peers,
        _clock = clock;

  final ClipboardWatcher _watcher;
  final List<PeerSession> Function() _peers;
  final int Function() _clock;

  StreamSubscription<ClipboardContent>? _sub;
  String? _lastAppliedHash;
  int _lastAppliedTimestampMs = 0;
  bool _userPaused = false;
  bool _lockPaused = false;
  int _skippedConcealedCount = 0;
  int _skippedOversizedCount = 0;
  int _skippedSkewedCount = 0;
  int _skippedUnsupportedFormatCount = 0;

  String? get lastAppliedHash => _lastAppliedHash;
  bool get isPaused => _userPaused || _lockPaused;
  int get skippedConcealedCount => _skippedConcealedCount;
  int get skippedOversizedCount => _skippedOversizedCount;
  int get skippedSkewedCount => _skippedSkewedCount;
  int get skippedUnsupportedFormatCount => _skippedUnsupportedFormatCount;

  Future<void> start() async {
    await _watcher.start();
    _sub = _watcher.changes.listen(_onLocalChange);
  }

  Future<void> stop() async {
    await _sub?.cancel();
    await _watcher.stop();
  }

  void setPaused(bool paused) => _userPaused = paused;

  void onScreenLocked() => _lockPaused = true;

  /// Clears only the lock-induced pause. A deliberate user pause survives.
  void onScreenUnlocked() => _lockPaused = false;

  Future<void> _onLocalChange(ClipboardContent content) async {
    if (isPaused) return;

    if (content.isConcealed) {
      _skippedConcealedCount++;
      return;
    }

    final hash = clipboardHash(content.format, content.data);
    if (hash == _lastAppliedHash) {
      // Our own write echoing back through the platform watcher. Dropping
      // this is what stops two machines ping-ponging forever.
      return;
    }

    final now = _clock();

    if (content.data.length > maxClipboardBytes) {
      _skippedOversizedCount++;
      await _broadcast(MessageType.clipboardTooLarge, {
        'format': content.format,
        'bytes': content.data.length,
        'limit': maxClipboardBytes,
      });
      return;
    }

    final ClipboardPayload payload;
    try {
      payload = ClipboardPayload(
        format: content.format,
        data: content.data,
        timestampMs: now,
        contentHash: hash,
      );
    } on EnvelopeError {
      // `ClipboardContent.format` documents that it must be one of
      // `supportedClipboardFormats`, but nothing enforces that upstream --
      // the platform watchers that would guarantee it are implemented
      // outside this package. Mirror the incoming path: skip gracefully
      // rather than let this throw uncaught out of the stream listener.
      _skippedUnsupportedFormatCount++;
      return;
    }

    _lastAppliedHash = hash;
    _lastAppliedTimestampMs = now;

    await _broadcast(
      MessageType.clipboardUpdate,
      payload.toMap(),
      collapseKey: _clipboardCollapseKey,
    );
  }

  Future<void> _broadcast(
    MessageType type,
    Map<String, Object?> payload, {
    String? collapseKey,
  }) async {
    for (final peer in _peers()) {
      if (peer.isDead) continue;
      try {
        await peer.send(type, payload, collapseKey: collapseKey);
      } on SessionRejectedError {
        // A dead session is the LinkManager's problem, not ours; skip it
        // rather than aborting delivery to healthy peers.
        continue;
      }
    }
  }

  Future<void> handleIncoming(Envelope envelope) async {
    if (envelope.type != MessageType.clipboardUpdate) return;

    final ClipboardPayload payload;
    try {
      payload = ClipboardPayload.fromMap(envelope.payload);
    } on EnvelopeError {
      return;
    }

    if (payload.timestampMs > _clock() + maxClockSkewMs) {
      // A timestamp implausibly far ahead of our own clock -- a skewed
      // clock, or a malicious peer -- must be rejected outright rather than
      // clamped. Accepting it (even clamped to "now") would still advance
      // `_lastAppliedTimestampMs` to a value the sender never actually
      // sent, and once that watermark is ahead of the real clock, every
      // subsequent legitimate update from any peer looks "older" and is
      // silently dropped by the check below -- incoming sync stays broken
      // until this device happens to make its own local clipboard copy.
      _skippedSkewedCount++;
      return;
    }

    if (payload.timestampMs < _lastAppliedTimestampMs) {
      // Last-write-wins by wall clock. A clipboard has no history to
      // corrupt, so the loser simply loses.
      return;
    }
    if (payload.data.length > maxClipboardBytes) return;

    // Recompute rather than trust the peer's `contentHash`. This is the
    // value the echo check compares against once the platform watcher fires
    // for our own write; if it came from the peer instead of from what we
    // actually applied, a peer that sends a hash mismatched with its own
    // data (bug, version skew, or deliberately) desyncs the check and the
    // echo is never suppressed, causing an unbounded ping-pong between the
    // two devices. Recomputing is self-validating and costs one hash of
    // content already in memory. Deliberately not also rejecting payloads
    // whose declared contentHash disagrees with their data -- that is a
    // separate integrity-strictness decision and out of scope here.
    _lastAppliedHash = clipboardHash(payload.format, payload.data);
    _lastAppliedTimestampMs = payload.timestampMs;

    await _watcher.write(ClipboardContent(
      format: payload.format,
      data: Uint8List.fromList(payload.data),
      isConcealed: false,
    ));
  }
}
