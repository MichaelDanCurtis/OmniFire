import 'dart:async';

import '../crypto/aead_session.dart';
import '../identity/device_identity.dart';
import '../identity/mesh.dart';
import '../identity/secure_store.dart';
import '../pairing/pairing_flow.dart';
import '../pairing/pairing_payload.dart';
import '../protocol/envelope.dart';
import '../session/peer_session.dart';
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
  final StreamController<ConnectionStatus> _statuses =
      StreamController<ConnectionStatus>.broadcast();
  final List<StreamSubscription<Object?>> _subs = [];

  /// Tail of the inbound-application chain. See [_applyIncoming].
  Future<void> _incomingTail = Future<void>.value();

  LanListener? _listener;
  bool _started = false;

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
    // A real session requires a handshake over a link; the manager dials,
    // and the handshake runs on first connect. Sessions created here start
    // detached and become live when a link is adopted.
    final session = _sessions.putIfAbsent(
      peer.deviceId,
      () => PeerSession(
        localDeviceId: identity.deviceId,
        peerDeviceId: peer.deviceId,
        crypto: AeadSession(
          sendKey: List<int>.filled(32, 0),
          receiveKey: List<int>.filled(32, 0),
        ),
        clock: _clock,
      ),
    );

    _subs.add(_listenInbound(session));

    final manager = LinkManager(
      session: session,
      clock: _clock,
      // One dialer per configured relay backend. Two relays are two
      // candidate links, not a primary plus a failover path: LinkManager
      // already prefers LAN over any relay, and ranks relays against each
      // other by measured RTT. Adding a backend costs one list entry.
      dialers: [
        for (final relayBase in config.relayBases)
          () => RelayLink.connect(
                relayBase: relayBase,
                meshId: mesh.meshId,
                localDeviceId: identity.deviceId,
                peerDeviceId: peer.deviceId,
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
