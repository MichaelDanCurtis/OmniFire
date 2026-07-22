import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:multicast_dns/multicast_dns.dart';

import '../protocol/framing.dart';
import 'link.dart';

const String omnifiServiceType = '_omnifi._tcp';

class LanEndpoint {
  const LanEndpoint({
    required this.deviceId,
    required this.address,
    required this.port,
  });
  final String deviceId;
  final InternetAddress address;
  final int port;
}

/// A direct TCP [Link] on the local network.
///
/// TCP has no message boundaries, so this owns a [FrameDecoder]; callers
/// above the [Link] interface still see whole frames only.
class LanLink implements Link {
  LanLink._(this._socket, {required String peerDeviceId})
      : id = 'lan:$peerDeviceId' {
    _sub = _socket.listen(
      _onBytes,
      onError: (Object _) => _setState(LinkState.failed),
      onDone: () => _setState(LinkState.disconnected),
      cancelOnError: false,
    );
  }

  static Future<LanLink> fromSocket(
    Socket socket, {
    required String peerDeviceId,
  }) async =>
      LanLink._(socket, peerDeviceId: peerDeviceId);

  static Future<LanLink> dial(
    LanEndpoint endpoint, {
    required String peerDeviceId,
    Duration timeout = const Duration(seconds: 5),
  }) async {
    final socket = await Socket.connect(
      endpoint.address,
      endpoint.port,
      timeout: timeout,
    );
    socket.setOption(SocketOption.tcpNoDelay, true);
    return LanLink._(socket, peerDeviceId: peerDeviceId);
  }

  @override
  final String id;

  final Socket _socket;
  final FrameDecoder _decoder = FrameDecoder();
  final StreamController<Uint8List> _inbound =
      StreamController<Uint8List>.broadcast();
  final StreamController<LinkState> _states =
      StreamController<LinkState>.broadcast();

  StreamSubscription<Uint8List>? _sub;
  LinkState _state = LinkState.connected;
  Duration? _rtt;

  @override
  LinkKind get kind => LinkKind.lan;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Stream<LinkState> get states => _states.stream;

  @override
  LinkState get state => _state;

  @override
  LinkQuality get quality => LinkQuality(kind: LinkKind.lan, rtt: _rtt);

  void recordRtt(Duration rtt) => _rtt = rtt;

  void _setState(LinkState next) {
    if (_state == next) return;
    _state = next;
    if (!_states.isClosed) _states.add(next);
  }

  void _onBytes(Uint8List chunk) {
    try {
      for (final frame in _decoder.addChunk(chunk)) {
        if (!_inbound.isClosed) _inbound.add(frame);
      }
    } on FrameTooLargeError {
      // A peer declaring an absurd length is either broken or hostile.
      // Drop the connection rather than buffering toward an OOM.
      unawaited(close());
    }
  }

  @override
  Future<void> send(List<int> frame) async {
    if (_state != LinkState.connected) {
      throw LinkClosedError(id);
    }
    try {
      _socket.add(encodeFrame(frame));
      await _socket.flush();
    } on SocketException {
      // Per dart:io IOSink semantics, a write failure on a half-closed or
      // reset socket is not thrown synchronously from add() -- it surfaces
      // here, on the following flush(). Callers such as pairing_flow.dart
      // depend on LinkClosedError specifically (not a raw transport
      // exception) to tell "the link died mid-exchange" apart from a real
      // internal fault, so this must be converted rather than left to
      // propagate. The link is also terminal now: mark it failed so
      // LinkManager stops treating it as a candidate.
      _setState(LinkState.failed);
      throw LinkClosedError(id);
    }
  }

  @override
  Future<void> close() async {
    _setState(LinkState.disconnected);
    await _sub?.cancel();
    try {
      await _socket.close();
    } on SocketException {
      // Already gone.
    }
    _socket.destroy();
    if (!_inbound.isClosed) await _inbound.close();
    if (!_states.isClosed) await _states.close();
  }
}

/// Accepts inbound LAN connections from peers.
class LanListener {
  LanListener._(this._server, this._localDeviceId) {
    _sub = _server.listen((socket) async {
      socket.setOption(SocketOption.tcpNoDelay, true);
      // The peer's identity is established by the session handshake, not by
      // the socket, so a provisional id is fine here -- but it must still be
      // collision-resistant: two different peers dialing this listener
      // concurrently can independently pick the same ephemeral source port
      // (ephemeral ranges overlap across operating systems and the clients
      // do not coordinate), so the port alone is not enough. The remote
      // address is included too: two peers can share a port, but not both
      // the port and the address. LinkManager keys its candidate map
      // directly by link id with no collision check, so an id collision
      // would silently overwrite one candidate and leak its socket.
      //
      // Not covered by a test: the failure mode this defends against is two
      // peers at DIFFERENT addresses independently picking the SAME port,
      // but two live sockets a test process opens to one destination are
      // guaranteed distinct source ports by the OS -- a real-socket test
      // can only ever vary the port, never the address, so it would pass
      // identically whether or not the address were part of the id. A test
      // that claimed to cover this was removed for exactly that reason;
      // this property (address-and-port together disambiguate; either
      // alone does not) is verified by inspection instead.
      final link = await LanLink.fromSocket(
        socket,
        peerDeviceId:
            'pending-${socket.remoteAddress.address}-${socket.remotePort}',
      );
      if (_closed) {
        // Hazard this guards against: close() ran while this callback was
        // suspended at the await above. Cancelling a subscription does not
        // retract an event already dispatched into a suspended async
        // callback, so this connection can still resume after _incoming
        // was closed. Adding to a closed StreamController throws
        // StateError, and dropping the link here without closing it would
        // leak its socket -- neither caller nor any listener is coming for
        // it now, so dispose of it instead.
        //
        // This check-then-act is only correct because close() (below)
        // sets _closed synchronously, before its first await -- so any
        // accept callback resuming after close() has run is guaranteed to
        // observe it true here. That ordering is load-bearing; do not
        // reorder it.
        //
        // Load-bearing, verified by inspection rather than by a test: the
        // window is exactly one microtask wide, and dart:io drains its
        // whole accept backlog synchronously per native callback, so real
        // timing never lands in it. Forcing it deterministically would mean
        // coupling a test to how many microtasks LanLink's constructor
        // happens to schedule internally -- not a contract worth pinning a
        // test to (a prior attempt at exactly that self-deadlocked on
        // neighbouring slots and was removed).
        await link.close();
        return;
      }
      _incoming.add(link);
    });
  }

  static Future<LanListener> bind({
    required String localDeviceId,
    int port = 0,
  }) async {
    final server = await ServerSocket.bind(InternetAddress.anyIPv4, port);
    return LanListener._(server, localDeviceId);
  }

  final ServerSocket _server;
  final String _localDeviceId;
  final StreamController<LanLink> _incoming =
      StreamController<LanLink>.broadcast();
  StreamSubscription<Socket>? _sub;
  bool _closed = false;

  int get port => _server.port;
  String get localDeviceId => _localDeviceId;
  Stream<LanLink> get incoming => _incoming.stream;

  Future<void> close() async {
    // Hazard this ordering guards against: an accept callback can already
    // be suspended at the `await LanLink.fromSocket(...)` in the
    // constructor above when close() runs, and it resumes on a later
    // microtask no matter what we do to the subscription below -- so
    // without this flag, it could add a link to _incoming after this
    // method has closed it.
    //
    // Set before any await, deliberately: that resumed callback's
    // `if (_closed)` check (above) is only guaranteed to observe this flag
    // if it is set synchronously, before close() itself suspends. Moving
    // this assignment after an await would reopen the race.
    //
    // Verified by inspection rather than by a test, deliberately: the
    // window is one microtask wide and unreachable via real timing (see
    // the accept callback's comment above), so a test would have to
    // intercept LanListener's constructor-internal microtask count to
    // force it -- not a contract worth coupling a test to.
    _closed = true;
    await _sub?.cancel();
    await _server.close();
    if (!_incoming.isClosed) await _incoming.close();
  }
}

abstract interface class LanDiscovery {
  Stream<LanEndpoint> discover();
  Future<void> advertise({required String deviceId, required int port});
}

/// Fixed endpoint list. Used by tests and by manual "connect to this IP"
/// configuration on networks where multicast is blocked.
class StaticDiscovery implements LanDiscovery {
  StaticDiscovery(this.endpoints);
  final List<LanEndpoint> endpoints;

  @override
  Stream<LanEndpoint> discover() => Stream.fromIterable(endpoints);

  @override
  Future<void> advertise({
    required String deviceId,
    required int port,
  }) async {}
}

/// Bonjour/mDNS discovery of `_omnifi._tcp` peers.
class MdnsDiscovery implements LanDiscovery {
  MdnsDiscovery({MDnsClient? client}) : _client = client ?? MDnsClient();

  final MDnsClient _client;
  bool _started = false;

  @override
  Stream<LanEndpoint> discover() async* {
    if (!_started) {
      await _client.start();
      _started = true;
    }
    await for (final ptr in _client.lookup<PtrResourceRecord>(
      ResourceRecordQuery.serverPointer(omnifiServiceType),
    )) {
      await for (final srv in _client.lookup<SrvResourceRecord>(
        ResourceRecordQuery.service(ptr.domainName),
      )) {
        await for (final ip in _client.lookup<IPAddressResourceRecord>(
          ResourceRecordQuery.addressIPv4(srv.target),
        )) {
          yield LanEndpoint(
            deviceId: srv.name.split('.').first,
            address: ip.address,
            port: srv.port,
          );
        }
      }
    }
  }

  /// Advertising requires a platform responder (Bonjour on Apple, the DNS-SD
  /// service on Windows); `multicast_dns` is query-only. The Flutter app
  /// registers the service natively in Tasks 22 and 23 and calls this only
  /// to record what was advertised.
  @override
  Future<void> advertise({
    required String deviceId,
    required int port,
  }) async {
    advertisedDeviceId = deviceId;
    advertisedPort = port;
  }

  String? advertisedDeviceId;
  int? advertisedPort;
}
