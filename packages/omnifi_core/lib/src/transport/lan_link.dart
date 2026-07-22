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
    _socket.add(encodeFrame(frame));
    await _socket.flush();
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
      // the socket, so a provisional id is fine here.
      _incoming.add(await LanLink.fromSocket(socket,
          peerDeviceId: 'pending-${socket.remotePort}'));
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

  int get port => _server.port;
  String get localDeviceId => _localDeviceId;
  Stream<LanLink> get incoming => _incoming.stream;

  Future<void> close() async {
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
