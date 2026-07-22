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

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Stream<LinkState> get states => _states.stream;

  @override
  LinkState get state => _state;

  @override
  LinkQuality get quality => LinkQuality(kind: kind, rtt: _rtt);

  void setState(LinkState next) {
    _state = next;
    _states.add(next);
  }

  /// Makes the next [send] throw, simulating a socket that died mid-write.
  void failNextSend() => _failNextSend = true;

  /// Pushes a frame onto this link's inbound stream as though it arrived
  /// from the network.
  void deliver(List<int> frame) => _inbound.add(Uint8List.fromList(frame));

  @override
  Future<void> send(List<int> frame) async {
    if (_state != LinkState.connected) {
      throw LinkClosedError(id);
    }
    if (_failNextSend) {
      _failNextSend = false;
      throw LinkClosedError(id);
    }
    sent.add(Uint8List.fromList(frame));
    _peer?.deliver(frame);
  }

  @override
  Future<void> close() async {
    setState(LinkState.disconnected);
    await _inbound.close();
    await _states.close();
  }

  static ({FakeLink a, FakeLink b}) connectedPair({
    LinkKind kind = LinkKind.lan,
  }) {
    final a = FakeLink(id: 'fake-a', kind: kind);
    final b = FakeLink(id: 'fake-b', kind: kind);
    a._peer = b;
    b._peer = a;
    return (a: a, b: b);
  }
}
