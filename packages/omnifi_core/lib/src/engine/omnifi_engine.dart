import 'dart:async';

import '../crypto/aead_session.dart';
import '../identity/device_identity.dart';
import '../identity/mesh.dart';
import '../identity/secure_store.dart';
import '../pairing/pairing_flow.dart';
import '../pairing/pairing_payload.dart';
import '../protocol/envelope.dart';
import '../session/peer_session.dart';
import '../session/session_establisher.dart';
import '../sync/clipboard_sync.dart';
import '../sync/clipboard_watcher.dart';
import '../transport/lan_link.dart';
import '../transport/link.dart';
import '../transport/link_manager.dart';
import '../transport/relay_link.dart';

/// Raised when no LAN link could be dialed for a peer. Ordinary, not
/// exceptional: [LinkManager] treats it as a failed dial, grows the backoff,
/// and the relay candidates carry the traffic in the meantime.
class LanDialError implements Exception {
  const LanDialError(this.reason);
  final String reason;
  @override
  String toString() => 'LanDialError: $reason';
}

class EngineConfig {
  const EngineConfig({
    required this.relayBases,
    required this.displayName,
    this.lanEnabled = true,
    this.lanDiscovery,
    this.lanPort = 0,
  });

  /// Every relay backend to dial, in descending order of preference.
  /// All of them are dialed concurrently and treated as competing
  /// candidate links; whichever answers first with the lowest RTT wins.
  /// There is no explicit failover logic because there does not need to
  /// be — [LinkManager] already ranks candidates, and a relay that is
  /// down simply never becomes a candidate.
  final List<Uri> relayBases;

  final String displayName;
  final bool lanEnabled;

  /// How LAN peers are located for dialing, and where this device's listening
  /// port is advertised.
  ///
  /// Null means "accept, but never dial": the engine still binds a listener
  /// and adopts inbound LAN connections, it just contributes no LAN candidate
  /// of its own. [StaticDiscovery] is the manual "connect to this IP" path
  /// and the one tests use; [MdnsDiscovery] is query-only until a platform
  /// responder lands (Tasks 22 and 23), so a mesh whose peers are not
  /// statically configured simply produces no LAN candidate and falls back to
  /// the relay. That is a stated limitation, not a hidden one.
  final LanDiscovery? lanDiscovery;

  /// Port for the inbound LAN listener. 0 asks the OS for an ephemeral port,
  /// which is what production wants; a fixed port is for tests and for
  /// networks where a firewall rule has to name one.
  final int lanPort;

  /// Convenience for the common single-relay case.
  Uri get primaryRelay => relayBases.first;
}

/// Composition root. Everything the UI needs hangs off this one object.
class OmniFiEngine {
  OmniFiEngine._({
    required this.identity,
    required this.mesh,
    required this.config,
    required SecureStore store,
    required ClipboardWatcher watcher,
    required int Function() clock,
  })  : _store = store,
        _clock = clock {
    clipboard = ClipboardSync(
      watcher: watcher,
      peers: () => sessions,
      clock: clock,
    );
  }

  static Future<OmniFiEngine> create({
    required SecureStore store,
    required ClipboardWatcher watcher,
    required EngineConfig config,
    int Function()? clock,
  }) async {
    final resolvedClock =
        clock ?? () => DateTime.now().millisecondsSinceEpoch;
    final identity = await loadOrCreateIdentity(
      store: store,
      displayName: config.displayName,
    );
    final mesh = await loadOrCreateMesh(store: store);
    return OmniFiEngine._(
      identity: identity,
      mesh: mesh,
      config: config,
      store: store,
      watcher: watcher,
      clock: resolvedClock,
    );
  }

  final DeviceIdentity identity;
  final Mesh mesh;
  final EngineConfig config;
  final SecureStore _store;
  final int Function() _clock;

  late final ClipboardSync clipboard;

  final Map<String, PeerSession> _sessions = {};
  final Map<String, LinkManager> _managers = {};
  final Map<String, ConnectionStatus> _peerStatuses = {};

  /// Tail of the per-peer link-adoption chain. See [_adoptLink].
  final Map<String, Future<void>> _adoptTails = {};
  final StreamController<ConnectionStatus> _statuses =
      StreamController<ConnectionStatus>.broadcast();

  /// Per-peer subscriptions, keyed so [forgetPeer] can cancel exactly the ones
  /// belonging to the peer it is removing.
  ///
  /// These used to be one flat unkeyed list, which meant a forgotten peer's
  /// listeners could not be found: the list grew without bound across
  /// pair/forget cycles, and a live status listener stayed attached to a
  /// manager the engine had already discarded, writing into [_peerStatuses]
  /// for a peer being removed. That it did no visible damage depended on
  /// microtask ordering nothing documented or tested.
  final Map<String, StreamSubscription<ConnectionStatus>> _statusSubs = {};
  final Map<String, StreamSubscription<Envelope>> _inboundSubs = {};

  /// Subscription to the LAN listener's accepted connections. Without it the
  /// listener's broadcast stream has no subscriber and every accepted socket
  /// is discarded still open.
  StreamSubscription<LanLink>? _incomingSub;

  /// Tail of the inbound-application chain. See [_applyIncoming].
  Future<void> _incomingTail = Future<void>.value();

  LanListener? _listener;
  bool _started = false;

  /// Set by [stop] and cleared by [start]. A handshake in flight when the
  /// engine is torn down completes after [stop] has already snapshotted and
  /// cleared [_sessions]; without this it would install a session nothing
  /// tracks and nothing disposes.
  bool _shutdown = false;

  List<PeerSession> get sessions => _sessions.values.toList();
  Stream<ConnectionStatus> get statuses => _statuses.stream;

  /// The weakest peer's status. A tray icon that shows "connected" while one
  /// device is unreachable is worse than useless.
  ConnectionStatus get status {
    if (_peerStatuses.isEmpty) return ConnectionStatus.offline;
    const rank = {
      ConnectionStatus.offline: 0,
      ConnectionStatus.reconnecting: 1,
      ConnectionStatus.connectedRelay: 2,
      ConnectionStatus.connectedDirect: 3,
    };
    return _peerStatuses.values
        .reduce((a, b) => rank[a]! <= rank[b]! ? a : b);
  }

  PairingInvite buildInvite() => generateInvite(
        meshId: mesh.meshId,
        inviterPublicKey: identity.keys.publicKey,
        relayHint: config.primaryRelay.toString(),
      );

  Future<void> persist() => saveMesh(mesh, _store);

  /// How long a LAN dial waits for discovery to name an endpoint for the peer
  /// before giving up. [MdnsDiscovery]'s query stream ends on its own and
  /// [StaticDiscovery]'s is finite, so this only guards a discovery that
  /// stalls.
  static const Duration _lanDiscoveryTimeout = Duration(seconds: 5);

  Future<void> start() async {
    if (_started) return;
    _started = true;
    _shutdown = false;
    await clipboard.start();
    // Re-checked after every suspension point from here on. [stop] flips
    // `_started` before its own first `await`, so a start() that carried on
    // regardless would rebuild the maps the teardown has just cleared — on
    // top of a clipboard that is already stopped — and bind a listener the
    // teardown has already decided it does not own.
    if (!_started) return;

    if (config.lanEnabled) {
      // Bound into a local, not straight into the field: [stop] captures and
      // nulls `_listener`, so a stop() landing during this bind would leave a
      // live ServerSocket assigned to an engine that believes it is stopped,
      // with nothing left to close it.
      final listener = await LanListener.bind(
        localDeviceId: identity.deviceId,
        port: config.lanPort,
      );
      if (!_started) {
        await listener.close();
        return;
      }
      _listener = listener;
      // [LanListener.incoming] is a broadcast stream: with no subscriber,
      // every accepted connection is dropped on the floor still open. This is
      // the only thing that adopts one.
      // Errors are absorbed here for the same reason [_listenInbound] absorbs
      // them: one unusable connection is a dropped connection, not an
      // unhandled async error taking down the app's zone.
      _incomingSub = listener.incoming.listen(
        (link) => unawaited(_acceptInbound(link).catchError((Object _) {})),
      );
      await config.lanDiscovery
          ?.advertise(deviceId: identity.deviceId, port: listener.port);
      if (!_started) return;
    }

    // Snapshot: `mesh.peers` already copies, but saying so here keeps the
    // guarantee local rather than borrowed from another class.
    for (final peer in mesh.peers.toList()) {
      if (!_started) return;
      await _connectPeer(peer);
    }
  }

  /// Adopts a connection the LAN listener accepted.
  ///
  /// An inbound link carries no identity of its own — [LanListener] labels it
  /// with a provisional id derived from the socket — so the peer is decided by
  /// the establisher's outcome: a roster candidate whose static key
  /// authenticates the far end is the peer, and a link that resolves to no
  /// roster member is closed rather than left open.
  ///
  /// Two limits, both stated rather than hidden.
  /// [SessionEstablisher.establish] closes the link when it fails, so at most
  /// one candidate can be tried per connection and the loop ends at the first
  /// failure; the peer redials. And a candidate whose session is already live
  /// short-circuits the establisher (one handshake per *session*, not per
  /// link), which is right for a link this device dialed but proves nothing
  /// about who opened a socket someone else did — so those candidates are
  /// only considered when the roster leaves nobody else it could have been.
  Future<void> _acceptInbound(Link link) async {
    for (final peer in _inboundCandidates()) {
      if (_shutdown || !_started) break;
      if (link.state != LinkState.connected) break;
      final manager = _managers[peer.deviceId];
      if (manager == null) continue;
      try {
        await _adoptLink(peer, link);
      } on Object {
        // Not this peer, or the link died proving it. Establishment closes
        // the link on failure, so the next iteration's state check ends the
        // loop and the far end redials.
        continue;
      }
      // Exactly the tail a dialed link gets: LinkManager ranks it against
      // this peer's relay candidates, attaches the session to whichever wins,
      // and closes it on stop().
      manager.offer(link);
      return;
    }
    await _closeQuietly(link);
  }

  /// Roster entries an inbound link could still be authenticated as. See
  /// [_acceptInbound] for why a live session disqualifies a candidate once
  /// there is more than one of them.
  List<PeerRecord> _inboundCandidates() {
    final peers = mesh.peers;
    if (peers.length <= 1) return peers.toList();
    return [
      for (final peer in peers)
        if (_sessions[peer.deviceId]?.isDead != false) peer,
    ];
  }

  /// Resolves a LAN endpoint for [peer] from discovery and dials it.
  ///
  /// Only installed as a dialer when discovery is configured, so a mesh with
  /// no static endpoints produces no LAN candidate at all rather than a
  /// dialer that exists only to fail.
  Future<Link> _dialLan(PeerRecord peer) async {
    final discovery = config.lanDiscovery;
    if (discovery == null) {
      throw const LanDialError('no LAN discovery is configured');
    }
    try {
      await for (final endpoint
          in discovery.discover().timeout(_lanDiscoveryTimeout)) {
        if (endpoint.deviceId != peer.deviceId) continue;
        return await LanLink.dial(endpoint, peerDeviceId: peer.deviceId);
      }
    } on TimeoutException {
      throw LanDialError('LAN discovery named no endpoint for '
          '${peer.deviceId} within $_lanDiscoveryTimeout');
    }
    throw LanDialError('no LAN endpoint was discovered for ${peer.deviceId}');
  }

  /// Closes best-effort: the link is being abandoned either way, and a
  /// transport that also fails to tear down cleanly must not turn "this link
  /// was rejected" into an internal fault.
  static Future<void> _closeQuietly(Link link) async {
    try {
      await link.close();
    } on Object {
      // Ignored: see above.
    }
  }

  /// Applies one inbound envelope to the clipboard, strictly after every
  /// envelope handed to this method before it.
  ///
  /// [PeerSession.inbound] is a broadcast stream and `Stream.listen` does not
  /// await an async callback, so a bare `inbound.listen(clipboard
  /// .handleIncoming)` lets two envelopes from a *single* peer overlap:
  /// [ClipboardSync.handleIncoming] records the new hash and timestamp and
  /// then awaits the platform write, and those writes can complete out of
  /// order. The clipboard would then hold older content while the recorded
  /// timestamp claims the newer one — and the stale content gets rebroadcast
  /// as though it were new.
  ///
  /// Mirrors [PeerSession]'s outbound `_serialized`: each call chains onto a
  /// `Future` tail, and the chained callback funnels both success and failure
  /// into a per-call completer so that one failing application can never
  /// latch [_incomingTail] into a permanently-rejected state that blocks
  /// every later delivery.
  Future<void> _applyIncoming(Envelope envelope) {
    final completer = Completer<void>();
    _incomingTail = _incomingTail.then((_) async {
      try {
        await clipboard.handleIncoming(envelope);
        completer.complete();
      } catch (e, st) {
        completer.completeError(e, st);
      }
    });
    return completer.future;
  }

  /// Subscribes [session]'s inbound envelopes to the serialized applier.
  ///
  /// The future is deliberately not returned to `listen` (which would ignore
  /// it anyway); errors are absorbed here so a single bad envelope surfaces
  /// as a dropped update rather than an unhandled async error.
  StreamSubscription<Envelope> _listenInbound(PeerSession session) =>
      session.inbound.listen(
        (envelope) =>
            unawaited(_applyIncoming(envelope).catchError((Object _) {})),
      );

  Future<void> _connectPeer(PeerRecord peer) async {
    // No PeerSession is created here. A session's keys come from a handshake,
    // the handshake needs a link, and the manager below is what produces
    // links, so the session is created by [_adoptLink] the first time one of
    // these dialers connects. (It used to be created here with all-zero AEAD
    // keys, deferring to a handshake nothing performed.)
    final manager = LinkManager(
      clock: _clock,
      // One dialer per configured relay backend. Two relays are two
      // candidate links, not a primary plus a failover path: LinkManager
      // already prefers LAN over any relay, and ranks relays against each
      // other by measured RTT. Adding a backend costs one list entry.
      dialers: [
        // The LAN dialer, and the only thing that makes the transport
        // LinkManager is built to *prefer* carry any traffic. Installed only
        // when discovery can actually name an endpoint; see [_dialLan].
        if (config.lanEnabled && config.lanDiscovery != null)
          () => _dialAndEstablish(peer, () => _dialLan(peer)),
        for (final relayBase in config.relayBases)
          () => _dialAndEstablish(
                peer,
                () => RelayLink.connect(
                      relayBase: relayBase,
                      meshId: mesh.meshId,
                      localDeviceId: identity.deviceId,
                      peerDeviceId: peer.deviceId,
                    ),
              ),
      ],
    );
    _managers[peer.deviceId] = manager;
    // Dropped rather than awaited: registration below must stay on this side
    // of any suspension point, and there is nothing to wait for.
    unawaited(_statusSubs.remove(peer.deviceId)?.cancel() ??
        Future<void>.value());
    _statusSubs[peer.deviceId] = manager.statuses.listen((s) {
      _peerStatuses[peer.deviceId] = s;
      _statuses.add(status);
    });
    _peerStatuses[peer.deviceId] = manager.status;
    await manager.start();
  }

  /// Dials, then establishes a session before the link is handed back to
  /// [LinkManager] to be offered as a candidate.
  ///
  /// Establishment failure propagates out of the dialer deliberately. The
  /// link never becomes a candidate — a peer that fails the handshake is not
  /// who the roster says it is — and LinkManager sees a *failed* dial, so a
  /// handshake that never succeeds grows the backoff instead of being counted
  /// as a healthy connection that simply carries nothing.
  Future<Link> _dialAndEstablish(
    PeerRecord peer,
    Future<Link> Function() dial,
  ) async {
    final link = await dial();
    await _adoptLink(peer, link);
    return link;
  }

  /// Returns the live session for [peer], establishing one over [link] first
  /// if there is not already one, and attaches it to [link].
  ///
  /// Serialized per peer. Two dialers can return links in the same turn of the
  /// event loop; without this, both would read [_sessions] before either
  /// wrote it, both would run a handshake, and the second write would strand
  /// the first session — whose peer has already discarded its half — inside
  /// whatever the manager had attached it to.
  Future<PeerSession> _adoptLink(PeerRecord peer, Link link) {
    final completer = Completer<PeerSession>();
    final tail = _adoptTails[peer.deviceId] ?? Future<void>.value();
    // Same non-latching contract as PeerSession's chains: failures land on
    // the per-call completer, never on the tail, so one failed handshake
    // cannot block every later adoption for this peer.
    _adoptTails[peer.deviceId] = tail.then((_) async {
      try {
        completer.complete(await _adoptLinkLocked(peer, link));
      } catch (e, st) {
        completer.completeError(e, st);
      }
    });
    return completer.future;
  }

  Future<PeerSession> _adoptLinkLocked(PeerRecord peer, Link link) async {
    // One handshake per *session*, not per link: a PeerSession is keyed to
    // the device pair and migrates across links without renegotiating crypto.
    // Only a dead session is replaced — a decryption failure forces a fresh
    // handshake rather than a counter resync, so its keys can never be
    // reconciled with the peer's.
    final live = _sessions[peer.deviceId];
    if (live != null && !live.isDead) {
      // Keep the manager pointing at the live session before returning: this
      // path is reached by an *inbound* link too, whose caller goes straight
      // on to LinkManager.offer(), and offer() reads `session` — which is
      // late-bound and would otherwise still be unassigned on a manager that
      // has never had a dial of its own succeed.
      _managers[peer.deviceId]?.session = live;
      return live;
    }

    final crypto = await SessionEstablisher.establish(
      link: link,
      identity: identity,
      peer: peer,
    );

    // Re-read across the suspension rather than reusing `live`: the handshake
    // is a network round trip, and forgetPeer() or stop() can have retired
    // this peer while it was in flight. Installing a session then would
    // resurrect a peer the user just removed, or leave one behind that the
    // teardown's snapshot will never dispose.
    await _requireStillConnected(peer, link);

    final stale = _sessions.remove(peer.deviceId);
    // The replaced session's inbound listener goes with it. Left attached it
    // would keep applying that session's envelopes and would never be
    // cancellable again, since nothing else holds a handle to it.
    final staleSub = _inboundSubs.remove(peer.deviceId);
    await staleSub?.cancel();
    await stale?.dispose();
    // Same check again: disposing the stale session suspends too.
    await _requireStillConnected(peer, link);

    final session = PeerSession(
      localDeviceId: identity.deviceId,
      peerDeviceId: peer.deviceId,
      crypto: crypto,
      clock: _clock,
    );
    _sessions[peer.deviceId] = session;
    _inboundSubs[peer.deviceId] = _listenInbound(session);
    // The manager may already be attached to a *different*, better-ranked
    // link, in which case its own _selectBest would not attach this fresh
    // session to anything. Point it at the link the handshake just ran over.
    _managers[peer.deviceId]?.session = session;
    session.attach(link);
    return session;
  }

  /// Throws (after closing [link]) when this engine has stopped, or when
  /// [peer] has been forgotten, since the caller last checked.
  Future<void> _requireStillConnected(PeerRecord peer, Link link) async {
    if (!_shutdown && mesh.peer(peer.deviceId) != null) return;
    await _closeQuietly(link);
    throw SessionEstablishmentError(
        'peer ${peer.deviceId} is no longer connected by this engine');
  }

  /// Runs the inviting side of a pairing over [link], using the invite whose
  /// QR the user is looking at.
  ///
  /// [invite] is a parameter, not something this method mints, and that is the
  /// whole point: [buildInvite] generates a fresh random pre-shared key on
  /// every call, and the PSK is mixed into the handshake's HKDF salt. Building
  /// a second invite here would give the two sides different master secrets
  /// and so different SAS words on every attempt — a pairing the user is
  /// trained to reject, correctly, forever. Mirrors [beginJoin], which has
  /// always taken the invite it was given.
  Future<PairingSasPending> beginInvite(
    PairingInvite invite,
    Link link,
  ) =>
      PairingFlow.invite(
        identity: identity,
        mesh: mesh,
        invite: invite,
        link: link,
      );

  Future<PairingSasPending> beginJoin(
    PairingInvite invite,
    Link link,
  ) =>
      PairingFlow.join(identity: identity, invite: invite, link: link);

  Future<void> forgetPeer(String deviceId) async {
    mesh.removePeer(deviceId);
    // Cancelled first, ahead of everything that suspends. Stopping the manager
    // below publishes ConnectionStatus.offline, and a listener still attached
    // to it writes that into _peerStatuses for the very peer being removed;
    // that this did no damage before depended entirely on the removal below
    // happening to land after the write.
    final statusSub = _statusSubs.remove(deviceId);
    final inboundSub = _inboundSubs.remove(deviceId);
    await statusSub?.cancel();
    await inboundSub?.cancel();
    await persist();
    await _managers.remove(deviceId)?.stop();
    await _sessions.remove(deviceId)?.dispose();
    // Dropped, not awaited: a handshake still in flight for this peer would
    // hold the teardown for its full timeout, and it refuses to install
    // anything anyway once the roster entry is gone.
    unawaited(_adoptTails.remove(deviceId) ?? Future<void>.value());
    _peerStatuses.remove(deviceId);
    _statuses.add(status);
  }

  Future<void> onWake() async {
    // Snapshot before the first suspension point, exactly as [stop] does and
    // for the same reason LinkManager snapshots inside its own onWake and
    // stop: forgetPeer() removes from this map and stop() clears it, and wake,
    // sleep and remove-a-device are one lifecycle, so either can land while
    // this loop is suspended inside a manager's wake. Iterating the live
    // collection across the await is a reachable ConcurrentModificationError.
    final managers = _managers.values.toList();
    for (final manager in managers) {
      await manager.onWake();
    }
  }

  void onScreenLocked() => clipboard.onScreenLocked();
  void onScreenUnlocked() => clipboard.onScreenUnlocked();

  Future<void> stop() async {
    _started = false;
    // Before the first suspension point, so a handshake already in flight
    // cannot install its session in the window this teardown is suspended in.
    _shutdown = true;
    // Snapshot and clear synchronously, before the first suspension point.
    // Iterating these collections across an `await` would let a concurrent
    // _connectPeer() (a start() still in flight, or a peer added while the
    // teardown was suspended) mutate them mid-loop, which is both a
    // ConcurrentModificationError and a way for a freshly registered manager
    // to survive the stop untracked. Same reason LinkManager.stop() snapshots.
    final subs = <StreamSubscription<Object?>>[
      ..._statusSubs.values,
      ..._inboundSubs.values,
      // Cancelled with the rest so no connection can be accepted and adopted
      // into the maps this teardown has just cleared.
      if (_incomingSub != null) _incomingSub!,
    ];
    final managers = _managers.values.toList();
    final sessions = _sessions.values.toList();
    _statusSubs.clear();
    _inboundSubs.clear();
    _incomingSub = null;
    _managers.clear();
    _sessions.clear();
    _adoptTails.clear();
    _peerStatuses.clear();
    final listener = _listener;
    _listener = null;

    for (final sub in subs) {
      await sub.cancel();
    }
    for (final manager in managers) {
      await manager.stop();
    }
    for (final session in sessions) {
      await session.dispose();
    }
    await listener?.close();
    // Anything already queued on the inbound chain still holds a reference to
    // the watcher this engine is about to stop. Draining first keeps a
    // half-applied update from racing the shutdown.
    await _incomingTail;
    await clipboard.stop();
    _statuses.add(ConnectionStatus.offline);
  }

  // ---- Test seams. Not for production use. ----

  void debugSetPeerStatus(String deviceId, ConnectionStatus status) {
    _peerStatuses[deviceId] = status;
  }

  /// The manager the engine is tracking for [deviceId], so a test can drive it
  /// directly — including after the engine has stopped tracking it.
  LinkManager? debugManagerFor(String deviceId) => _managers[deviceId];

  /// Peers this engine currently holds a manager for.
  List<String> get debugTrackedPeerIds => _managers.keys.toList();

  /// Live per-peer subscription count, so an orphaned listener is detectable.
  int get debugSubscriptionCount => _statusSubs.length + _inboundSubs.length;

  /// Port the LAN listener is bound to, or null when nothing is bound.
  int? get debugListenerPort => _listener?.port;

  /// Runs the path an accepted LAN connection takes, without a real socket.
  Future<void> debugAcceptInbound(Link link) => _acceptInbound(link);

  /// Runs the adoption path a dialer would run: establishes a session for
  /// [peer] over [link] unless a live one already exists, then attaches.
  Future<PeerSession> debugAdoptLink(PeerRecord peer, Link link) =>
      _adoptLink(peer, link);

  PeerSession debugAttachSession({
    required String peerDeviceId,
    required AeadSession crypto,
  }) {
    final session = PeerSession(
      localDeviceId: identity.deviceId,
      peerDeviceId: peerDeviceId,
      crypto: crypto,
      clock: _clock,
    );
    _sessions[peerDeviceId] = session;
    _inboundSubs[peerDeviceId] = _listenInbound(session);
    return session;
  }
}
