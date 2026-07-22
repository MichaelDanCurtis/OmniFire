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

class EngineConfig {
  const EngineConfig({
    required this.relayBases,
    required this.displayName,
    this.lanEnabled = true,
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
  final List<StreamSubscription<Object?>> _subs = [];

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

  Future<void> start() async {
    if (_started) return;
    _started = true;
    _shutdown = false;
    await clipboard.start();

    if (config.lanEnabled) {
      _listener = await LanListener.bind(localDeviceId: identity.deviceId);
    }

    for (final peer in mesh.peers) {
      await _connectPeer(peer);
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
    _subs.add(manager.statuses.listen((s) {
      _peerStatuses[peer.deviceId] = s;
      _statuses.add(status);
    }));
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
    if (live != null && !live.isDead) return live;

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
    if (_shutdown || mesh.peer(peer.deviceId) == null) {
      try {
        await link.close();
      } on Object {
        // Best effort: the link is being abandoned either way.
      }
      throw SessionEstablishmentError(
          'peer ${peer.deviceId} is no longer connected by this engine');
    }
    final stale = _sessions.remove(peer.deviceId);
    await stale?.dispose();

    final session = PeerSession(
      localDeviceId: identity.deviceId,
      peerDeviceId: peer.deviceId,
      crypto: crypto,
      clock: _clock,
    );
    _sessions[peer.deviceId] = session;
    _subs.add(_listenInbound(session));
    // The manager may already be attached to a *different*, better-ranked
    // link, in which case its own _selectBest would not attach this fresh
    // session to anything. Point it at the link the handshake just ran over.
    _managers[peer.deviceId]?.session = session;
    session.attach(link);
    return session;
  }

  Future<PairingSasPending> beginInvite(Link link) => PairingFlow.invite(
        identity: identity,
        mesh: mesh,
        invite: buildInvite(),
        link: link,
      );

  Future<PairingSasPending> beginJoin(
    PairingInvite invite,
    Link link,
  ) =>
      PairingFlow.join(identity: identity, invite: invite, link: link);

  Future<void> forgetPeer(String deviceId) async {
    mesh.removePeer(deviceId);
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
    for (final manager in _managers.values) {
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
    final subs = _subs.toList();
    final managers = _managers.values.toList();
    final sessions = _sessions.values.toList();
    _subs.clear();
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
    _subs.add(_listenInbound(session));
    return session;
  }
}
