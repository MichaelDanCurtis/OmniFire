import 'dart:typed_data';

enum LinkState { connecting, connected, disconnected, failed }

enum LinkKind { lan, relay }

class LinkClosedError implements Exception {
  const LinkClosedError(this.linkId);
  final String linkId;
  @override
  String toString() => 'LinkClosedError: link $linkId is not connected';
}

/// How desirable a link is. Lower [preferenceScore] wins.
class LinkQuality {
  const LinkQuality({required this.kind, this.rtt});

  final LinkKind kind;
  final Duration? rtt;

  bool get isDirect => kind == LinkKind.lan;

  /// LAN always outranks relay, regardless of measured latency: a relay that
  /// happens to be fast right now still costs a round trip through
  /// Cloudflare and cannot carry the media features planned for projects
  /// 3 and 4. Within a kind, a measured RTT outranks an unmeasured one.
  int get preferenceScore {
    final kindWeight = kind == LinkKind.lan ? 0 : 1000000;
    final rttWeight = rtt?.inMilliseconds ?? 999999;
    return kindWeight + rttWeight;
  }
}

/// An encrypted-transport-agnostic duplex byte channel to one peer.
///
/// Implementations: [LanLink] (Task 18), [RelayLink] (Task 17), and
/// `FakeLink` in tests. Nothing above this interface knows which is in use.
abstract interface class Link {
  String get id;
  LinkKind get kind;
  Stream<Uint8List> get inbound;
  Stream<LinkState> get states;
  LinkState get state;
  LinkQuality get quality;
  Future<void> send(List<int> frame);
  Future<void> close();
}
