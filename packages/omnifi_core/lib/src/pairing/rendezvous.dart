import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:cryptography/cryptography.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

import '../identity/device_identity.dart';
import '../transport/link.dart';
import '../transport/relay_link.dart';
import 'pairing_payload.dart';

/// Raised when two devices could not meet at the rendezvous. Ordinary, not
/// exceptional: a user who walked away, a QR that was never scanned, or a
/// second device arriving at a rendezvous that is already taken. The socket
/// this rendezvous opened has been closed by the time this is thrown.
class RendezvousError implements Exception {
  const RendezvousError(this.reason);
  final String reason;
  @override
  String toString() => 'RendezvousError: $reason';
}

/// HKDF `info` label for the rendezvous namespace. Domain-separates it from
/// every other value derived from the same pre-shared key — the session master
/// (`omnifi-session-v1`) and the SAS (`omnifi-sas-v1`) — so that publishing the
/// rendezvous id to the relay, which necessarily happens in the clear as a URL
/// path segment, reveals nothing about either.
const String _rendezvousInfo = 'omnifi-rendezvous-v1';

/// Marker for a rendezvous hello. Present in no other frame this link ever
/// carries: a handshake message is `CBOR{v, id, e, s}` with no `t` key, so a
/// hello and pairing traffic can never be mistaken for one another. That
/// matters in both directions — a hello delivered to [PairingFlow] would fail
/// its handshake decode, and a handshake message swallowed as a hello would
/// hang the pairing.
const String _helloTag = 'omnifi-rendezvous-hello-v1';

const String _roleInviter = 'inviter';
const String _roleJoiner = 'joiner';

/// 16 bytes: the relay's mesh id is 32 lowercase hex characters.
final Hkdf _rendezvousHkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 16);

final RegExp _hexDeviceId = RegExp(r'^[0-9a-f]{32}$');

/// The relay mesh id two pairing devices meet in, derived from the invite's
/// pre-shared key.
///
/// The relay treats a mesh id as an opaque 32-hex routing key and creates a
/// Durable Object per distinct value on demand, so this needs no relay change
/// at all: a derived id is a valid mesh id as far as the relay is concerned.
/// It is also a *different* DO from either device's real mesh, so an inviter
/// that already holds a socket to its own mesh has no device id appearing
/// twice in one socket set and nothing to demultiplex.
///
/// The namespace being unguessable is **not** the security property. Anyone
/// who has seen the QR can derive this and reach the rendezvous — that is
/// expected, and already true of the pre-shared key itself. The short
/// authentication string the two users compare is what defends against them.
///
/// Asynchronous because `package:cryptography`'s HKDF is, as it is everywhere
/// else in this package (`deriveSas`, `OmniFiHandshakeV1._derive`). A
/// synchronous signature would mean either a second HMAC implementation or a
/// second crypto dependency, to save one `await` in two call sites.
Future<String> rendezvousIdFor(List<int> psk) async {
  if (psk.isEmpty) {
    throw const RendezvousError(
        'the invite has an empty pre-shared key; there is no rendezvous '
        'namespace to derive from it');
  }
  final key = await _rendezvousHkdf.deriveKey(
    secretKey: SecretKey(psk),
    nonce: const [],
    info: utf8.encode(_rendezvousInfo),
  );
  final bytes = await key.extractBytes();
  final out = StringBuffer();
  for (final b in bytes) {
    out.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return out.toString();
}

typedef _Hello = ({String role, String ephemeralId});

Uint8List _encodeHello({required String role, required String ephemeralId}) =>
    Uint8List.fromList(cbor.encode(CborValue({
      't': _helloTag,
      'r': role,
      'id': ephemeralId,
    })));

/// Decodes a hello, or returns null for anything that is not one — including
/// malformed CBOR, which arrives here as ordinary traffic from anyone else who
/// scanned the QR and must never throw out of a stream callback.
_Hello? _decodeHello(List<int> frame) {
  final Object? decoded;
  try {
    decoded = cbor.decode(frame).toObject();
  } on Object {
    return null;
  }
  if (decoded is! Map) return null;
  final tag = decoded['t'];
  if (tag is! String || tag != _helloTag) return null;
  final role = decoded['r'];
  if (role is! String) return null;
  final id = decoded['id'];
  if (id is! String || !_hexDeviceId.hasMatch(id)) return null;
  // The all-zero id is the relay's *broadcast* address, and it is 32 lowercase
  // hex characters, so the pattern above admits it. Latching onto it would
  // replace "address the peer" with "fan out to the namespace" — and the very
  // next frame this side sends is its handshake message, CBOR {v, id, e, s}
  // carrying its real device id and real static public key. Anyone who has
  // seen the QR could claim it and be handed both by every device present,
  // which is precisely what the ephemeral ids exist to prevent.
  if (id == broadcastDeviceId) return null;
  return (role: role, ephemeralId: id);
}

/// Brings two devices that are in nobody's roster together over the relay, so
/// [PairingFlow] has a [Link] to run on.
///
/// Neither the [LinkManager] dial path nor the LAN listener applies before
/// pairing: both need a [PeerRecord], which is what pairing produces. This is
/// the one path that creates a link to a device this one has never met.
///
/// Both sides connect with a **fresh random ephemeral device id**, never their
/// real one. That is not cosmetic. The rendezvous is reachable by anyone who
/// has seen the QR, and the device id appears in the WebSocket URL and in
/// every frame header; using the real id would publish a stable identifier for
/// the device to that audience before a single byte has been authenticated.
/// The ephemeral id addresses relay frames for the length of the exchange and
/// nothing else — the real identities are established inside the handshake
/// [PairingFlow] runs over the link this returns.
///
/// `channelFactory` on both entry points is the same test seam
/// [RelayLink.connect] already exposes, forwarded: it lets a suite drive both
/// halves of the hello exchange — and the buffering, capping and fail-fast
/// behaviour around it — deterministically, without a relay and without the
/// timing luck a two-socket integration test depends on. Production passes
/// nothing and gets a real WebSocket.
class PairingRendezvous {
  const PairingRendezvous._();

  /// How often the joiner re-announces itself while waiting for an answer.
  ///
  /// The relay buffers nothing: a hello that arrives before the inviter has
  /// connected is fanned out to an empty Durable Object and lost. Neither side
  /// can know whether it or the other got there first, so the joiner — the
  /// side that speaks first — simply keeps saying so.
  static const Duration helloInterval = Duration(milliseconds: 500);

  /// Ceiling on the frames a rendezvous link will hold for a caller that is
  /// not listening yet, in count and in total bytes.
  ///
  /// Both are deliberately small. A pairing exchange is four frames end to
  /// end and only ever *two* can be in flight during the window this buffer
  /// exists for, and each is a CBOR handshake message of a few hundred bytes;
  /// eight frames and 256 KiB is already orders of magnitude of slack. The
  /// window itself, however, is not small: `PairingFlow._run` cancels its
  /// subscription when it returns its `PairingSasPending`, so from the moment
  /// the SAS words appear until the user taps confirm there is no listener,
  /// the socket is open, and anyone who has seen the QR can derive the
  /// namespace and broadcast into it — up to the relay's 1 MiB frame limit,
  /// with no rate limit. Unbounded retention across that window is a remote
  /// memory-exhaustion vector against a phone whose only bound is how long a
  /// human takes to read five words.
  static const int maxPendingFrames = 8;
  static const int maxPendingBytes = 256 * 1024;

  /// Ceiling on the WebSocket upgrade itself, independent of how long the
  /// caller is willing to wait for a *peer*. An inviter waits two minutes for
  /// a human to walk to another device; it should not wait two minutes to
  /// discover the relay is down.
  static const Duration _connectTimeout = Duration(seconds: 10);

  /// Waits at the rendezvous for a joiner to appear, and returns a link to it.
  ///
  /// The default timeout is long because the interaction is: the user is
  /// looking at a QR code on this screen and walking to another device.
  static Future<Link> awaitJoiner({
    required PairingInvite invite,
    required Uri relayBase,
    Duration timeout = const Duration(minutes: 2),
    void Function(RelayLink socket)? debugOnSocket,
    WebSocketChannel Function(Uri)? channelFactory,
  }) =>
      _meet(
        invite: invite,
        relayBase: relayBase,
        timeout: timeout,
        isInviter: true,
        debugOnSocket: debugOnSocket,
        channelFactory: channelFactory,
      );

  /// Announces this device at the rendezvous named by a scanned [invite], and
  /// returns a link to the inviter.
  ///
  /// The default timeout is short because the interaction is: the user has
  /// just scanned a code and is watching this device. An inviter that is not
  /// already waiting is a wrong or stale code, and saying so quickly is the
  /// useful answer.
  static Future<Link> connectToInviter({
    required PairingInvite invite,
    required Uri relayBase,
    Duration timeout = const Duration(seconds: 30),
    void Function(RelayLink socket)? debugOnSocket,
    WebSocketChannel Function(Uri)? channelFactory,
  }) =>
      _meet(
        invite: invite,
        relayBase: relayBase,
        timeout: timeout,
        isInviter: false,
        debugOnSocket: debugOnSocket,
        channelFactory: channelFactory,
      );

  static Future<Link> _meet({
    required PairingInvite invite,
    required Uri relayBase,
    required Duration timeout,
    required bool isInviter,
    void Function(RelayLink socket)? debugOnSocket,
    WebSocketChannel Function(Uri)? channelFactory,
  }) async {
    final rendezvousId = await rendezvousIdFor(invite.psk);
    final ephemeralId = randomHexId();

    final RelayLink socket;
    try {
      socket = await RelayLink.connect(
        relayBase: relayBase,
        meshId: rendezvousId,
        localDeviceId: ephemeralId,
        // No destination yet: that is what the hello exchange below settles.
        // Until then everything this side sends is broadcast to the rendezvous
        // Durable Object, which is exactly what a hello is for.
        peerDeviceId: broadcastDeviceId,
        timeout: timeout < _connectTimeout ? timeout : _connectTimeout,
        channelFactory: channelFactory,
      );
    } on Object catch (e) {
      throw RendezvousError(
          'could not open a rendezvous socket on $relayBase: $e');
    }
    debugOnSocket?.call(socket);

    // Constructed before the first suspension after `connect` returned, and it
    // subscribes to `socket.inbound` in its constructor. `RelayLink.inbound` is
    // a broadcast stream, so a frame delivered while nothing is listening is
    // discarded — the symptom being an intermittent hang with no diagnostic,
    // not a clean failure. Nothing is sent until after this line.
    final link = _RendezvousLink(
      socket: socket,
      localEphemeralId: ephemeralId,
      isInviter: isInviter,
    );
    try {
      await link.meet(timeout);
      return link;
    } on Object {
      // Both timeouts close the underlying socket. A rendezvous that gave up
      // but left its WebSocket open would leave a deaf device sitting in the
      // Durable Object for its whole idle lifetime.
      await link.closeQuietly();
      rethrow;
    }
  }
}

/// The [Link] a rendezvous hands back: the relay socket it opened, with the
/// hello exchange filtered out and the peer's frames buffered.
///
/// It is a wrapper rather than a bare [RelayLink] for one reason, and it is
/// the hazard this package has been bitten by before. The moment the peer is
/// latched, the peer may send its first handshake frame; the caller does not
/// subscribe until it calls [PairingFlow.invite] or `.join`, which is at least
/// a microtask later and in practice several. Handing back the raw broadcast
/// stream would drop anything that landed in that window. Here, one
/// subscription is armed at construction — before a single byte is sent — and
/// everything that is not a hello is queued until the caller listens.
///
/// That window is far wider than "a few microtasks", which is what makes the
/// queue's bound load-bearing rather than tidy. `PairingFlow._run` returns its
/// `PairingSasPending` from inside its `try`, so the `finally` cancels its
/// subscription at that return: from the instant the SAS words go on screen
/// until the user taps confirm there is again no listener, and the socket is
/// still open to anyone who derived the namespace from the QR. On a bare
/// [RelayLink] those frames are dropped, harmlessly; converting that drop into
/// unbounded retention would make this wrapper a remote memory-exhaustion
/// vector bounded only by human reading speed. See
/// [PairingRendezvous.maxPendingFrames].
class _RendezvousLink implements Link {
  _RendezvousLink({
    required RelayLink socket,
    required this.localEphemeralId,
    required bool isInviter,
  })  : _socket = socket,
        _ownRole = isInviter ? _roleInviter : _roleJoiner,
        _peerRole = isInviter ? _roleJoiner : _roleInviter,
        _isInviter = isInviter {
    _frames = socket.inbound.listen(_onFrame);
    _socketStates = socket.states.listen(_onSocketState);
    // A permanent handler, so that a socket dying in the window between a send
    // and the next await cannot surface as an unhandled async error in the
    // app's zone. Every real consumer awaits this future as well; this only
    // guarantees a handler exists at every instant.
    unawaited(_settled.future.catchError((Object _) {}));
  }

  final RelayLink _socket;
  final String localEphemeralId;
  final String _ownRole;
  final String _peerRole;
  final bool _isInviter;

  /// Completes when the peer has been latched, or completes with an error when
  /// the socket died first.
  final Completer<void> _settled = Completer<void>();

  late final StreamSubscription<Uint8List> _frames;
  late final StreamSubscription<LinkState> _socketStates;

  /// The peer's ephemeral device id, once one has been accepted.
  ///
  /// The only mutable state here, and the only field written on one side of a
  /// suspension and read on the other. Both are safe by construction rather
  /// than by luck: it is written in [_onFrame], which is wholly synchronous —
  /// no `await` between the null check that guards it and the assignment, so
  /// two frames arriving in the same event-loop turn cannot both latch — and
  /// [_settled] is completed in that same synchronous run, immediately after,
  /// so anything awaiting [_settled] is ordered strictly after the write.
  String? _peerEphemeralId;

  /// Frames held for a caller that has not subscribed yet, bounded by
  /// [PairingRendezvous.maxPendingFrames] and
  /// [PairingRendezvous.maxPendingBytes].
  final Queue<Uint8List> _pending = Queue<Uint8List>();
  int _pendingBytes = 0;
  bool _hasListener = false;

  /// Set once this link has failed and will carry nothing further. Held
  /// rather than emitted because the window this link exists to cover is
  /// exactly the window in which nothing is listening: an error added to a
  /// broadcast controller with no listener is discarded, same as a frame. It
  /// is handed to whoever subscribes next, and the stream is closed behind it.
  RendezvousError? _failure;

  late final StreamController<Uint8List> _inbound =
      StreamController<Uint8List>.broadcast(
    onListen: () {
      _hasListener = true;
      // Not drained inline: adding to a broadcast controller from inside its
      // own onListen callback is delivered before the subscription is fully
      // wired up.
      scheduleMicrotask(_drain);
    },
    onCancel: () => _hasListener = false,
  );

  @override
  String get id => 'rendezvous:$localEphemeralId';

  @override
  LinkKind get kind => _socket.kind;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Stream<LinkState> get states => _socket.states;

  @override
  LinkState get state => _socket.state;

  @override
  LinkQuality get quality => _socket.quality;

  @override
  Future<void> send(List<int> frame) => _socket.send(frame);

  @override
  Future<void> close() async {
    // Cancelled before the socket is torn down, so [_onSocketState] cannot
    // fire for a closure this side asked for.
    await _frames.cancel();
    await _socketStates.cancel();
    _pending.clear();
    _pendingBytes = 0;
    if (!_inbound.isClosed) await _inbound.close();
    await _socket.close();
  }

  Future<void> closeQuietly() async {
    try {
      await close();
    } on Object {
      // The rendezvous has already failed; a transport that also fails to tear
      // down cleanly must not replace that failure with an internal fault.
    }
  }

  /// Runs the hello exchange, returning once the peer is known and every frame
  /// this link sends is addressed to it.
  Future<void> meet(Duration timeout) async {
    if (_isInviter) {
      await _awaitPeer(timeout);
      // Answered only now. Before the joiner is latched the inviter has nobody
      // to address, and broadcasting its own ephemeral id unprompted would
      // hand it to every other device that scanned the QR. This send is
      // targeted at the joiner alone.
      await _sendHello();
    } else {
      await _announceUntilAnswered(timeout);
    }
  }

  Future<void> _awaitPeer(Duration timeout) async {
    try {
      await _settled.future.timeout(timeout);
    } on TimeoutException {
      throw RendezvousError(
          'no joiner appeared at the rendezvous within $timeout');
    }
  }

  Future<void> _announceUntilAnswered(Duration timeout) async {
    final elapsed = Stopwatch()..start();
    while (true) {
      await _sendHello();
      final remaining = timeout - elapsed.elapsed;
      if (remaining <= Duration.zero) break;
      final wait =
          remaining < PairingRendezvous.helloInterval
              ? remaining
              : PairingRendezvous.helloInterval;
      try {
        await _settled.future.timeout(wait);
        return;
      } on TimeoutException {
        // Nobody yet. Say it again: the relay buffers nothing, so an inviter
        // that connects late never saw the earlier announcements.
      }
    }
    throw RendezvousError(
        'no inviter answered at the rendezvous within $timeout');
  }

  Future<void> _sendHello() async {
    try {
      await _socket.send(
          _encodeHello(role: _ownRole, ephemeralId: localEphemeralId));
    } on LinkClosedError catch (e) {
      throw RendezvousError(
          'the rendezvous socket closed before a peer was found: $e');
    }
  }

  /// Synchronous from end to end, deliberately. See [_peerEphemeralId].
  void _onFrame(Uint8List frame) {
    final hello = _decodeHello(frame);
    if (hello != null) {
      // Latched already: this is a second device that scanned the same QR,
      // still broadcasting, or a duplicate announcement from the one already
      // accepted. Either way it is consumed here and never forwarded — a
      // caller that received a hello as pairing traffic would fail its
      // handshake decode. The unanswered second device fails its own timeout;
      // the SAS still protects the one that was accepted.
      if (_peerEphemeralId != null) return;
      // Roles keep two joiners from pairing with each other: a joiner's
      // announcement is broadcast, so every other joiner in the namespace
      // sees it.
      if (hello.role != _peerRole) return;
      if (hello.ephemeralId == localEphemeralId) return;
      _peerEphemeralId = hello.ephemeralId;
      // From here every frame this side sends is addressed to the peer alone,
      // not fanned out to the namespace.
      _socket.retarget(hello.ephemeralId);
      if (!_settled.isCompleted) _settled.complete();
      return;
    }
    // Pairing traffic arriving before anyone has been latched belongs to no
    // exchange this link is party to.
    if (_peerEphemeralId == null) return;
    // Already failed: the subscription is being torn down, and anything that
    // slips through in the meantime is not going anywhere.
    if (_failure != null) return;
    _pending.add(frame);
    _pendingBytes += frame.length;
    if (_pending.length > PairingRendezvous.maxPendingFrames ||
        _pendingBytes > PairingRendezvous.maxPendingBytes) {
      // Failed, not trimmed. During a pairing exchange, more than a handful
      // of frames is already anomalous — it means a bug on the peer or a
      // hostile party in the namespace — and dropping the oldest would
      // discard the frame the exchange actually needed while leaving the link
      // looking healthy, which is the worst of both. Failing costs an
      // attacker nothing they could not already get by winning the latch
      // race, and the SAS covers that.
      _fail(RendezvousError(
          'the rendezvous link was flooded while the pairing was waiting on '
          'the user: more than ${PairingRendezvous.maxPendingFrames} frames '
          'or ${PairingRendezvous.maxPendingBytes} bytes arrived with no '
          'reader'));
      return;
    }
    _drain();
  }

  /// Ends this link, keeping [error] for whoever subscribes next.
  void _fail(RendezvousError error) {
    if (_failure != null) return;
    _failure = error;
    // Dropped: the buffer holds either a bug's output or an attacker's, and
    // the frame this exchange needed cannot be told from the rest. Keeping it
    // would mean the failure itself retained what it was raised about.
    _pending.clear();
    _pendingBytes = 0;
    // Torn down now rather than left for the caller to notice: whatever is
    // sending is still connected and still sending. Not awaited — this runs
    // inside the socket's own frame callback.
    unawaited(_frames.cancel());
    unawaited(_socketStates.cancel());
    unawaited(_socket.close());
    if (!_settled.isCompleted) _settled.completeError(error);
    _drain();
  }

  void _onSocketState(LinkState state) {
    if (state == LinkState.connected) return;
    if (_settled.isCompleted) return;
    _settled.completeError(const RendezvousError(
        'the rendezvous socket closed before a peer was found'));
  }

  void _drain() {
    if (!_hasListener || _inbound.isClosed) return;
    while (_pending.isNotEmpty) {
      final frame = _pending.removeFirst();
      _pendingBytes -= frame.length;
      _inbound.add(frame);
    }
    final failure = _failure;
    if (failure == null) return;
    _inbound.addError(failure);
    unawaited(_inbound.close());
  }
}
