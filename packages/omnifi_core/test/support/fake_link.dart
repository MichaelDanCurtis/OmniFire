import 'dart:async';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';

/// In-memory [Link] for tests. Two fakes can be cross-wired so that a send
/// on one arrives on the other's inbound stream.
class FakeLink implements Link {
  FakeLink({
    required this.id,
    this.kind = LinkKind.lan,
    Duration? rtt = const Duration(milliseconds: 10),
  }) : _rtt = rtt;

  @override
  final String id;

  @override
  final LinkKind kind;

  final Duration? _rtt;

  final StreamController<Uint8List> _inbound =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkState> _states =
      StreamController<LinkState>.broadcast();

  final List<Uint8List> sent = [];

  FakeLink? _peer;
  LinkState _state = LinkState.connected;
  bool _failNextSend = false;
  bool _closed = false;

  /// Set when the link this one was wired to has closed. A write into a peer
  /// that has gone away is a dead socket, not a silent success.
  bool _peerClosed = false;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Stream<LinkState> get states => _states.stream;

  @override
  LinkState get state => _state;

  @override
  LinkQuality get quality => LinkQuality(kind: kind, rtt: _rtt);

  /// No-op once closed: a closed link has no state left to publish, and the
  /// underlying controller would throw.
  void setState(LinkState next) {
    if (_closed) return;
    _state = next;
    _states.add(next);
  }

  /// Makes the next [send] throw, simulating a socket that died mid-write.
  void failNextSend() => _failNextSend = true;

  /// Pushes a frame onto this link's inbound stream as though it arrived
  /// from the network. No-op once closed.
  void deliver(List<int> frame) {
    if (_closed) return;
    _inbound.add(Uint8List.fromList(frame));
  }

  /// Models a real socket write: it suspends, and the link may die while it
  /// is suspended.
  @override
  Future<void> send(List<int> frame) async {
    if (_state != LinkState.connected || _closed) {
      throw LinkClosedError(id);
    }
    if (_failNextSend) {
      _failNextSend = false;
      throw LinkClosedError(id);
    }
    await Future<void>.delayed(Duration.zero);
    if (_state != LinkState.connected || _closed || _peerClosed) {
      throw LinkClosedError(id);
    }
    sent.add(Uint8List.fromList(frame));
    _peer?.deliver(frame);
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    _state = LinkState.disconnected;
    _states.add(LinkState.disconnected);
    final peer = _peer;
    _peer = null;
    if (peer != null && identical(peer._peer, this)) {
      peer._peer = null;
      peer._peerClosed = true;
      // A closed socket is closed at both ends. The remote end sees end-of-
      // stream on its reads and goes disconnected; it does not sit connected
      // on a channel with nothing on the other side. Recursion terminates
      // because the peer's own `_peer` has already been cleared.
      await peer.close();
    }
    await _inbound.close();
    await _states.close();
  }

  static int _pairCounter = 0;

  /// Each pair gets distinct ids so that several pairs can coexist in one
  /// test without colliding in anything that keys links by [id].
  static ({FakeLink a, FakeLink b}) connectedPair({
    LinkKind kind = LinkKind.lan,
    String? idA,
    String? idB,
  }) {
    final n = ++_pairCounter;
    final a = FakeLink(id: idA ?? 'fake-a-$n', kind: kind);
    final b = FakeLink(id: idB ?? 'fake-b-$n', kind: kind);
    a._peer = b;
    b._peer = a;
    return (a: a, b: b);
  }
}
