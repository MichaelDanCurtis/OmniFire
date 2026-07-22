import 'dart:async';
import 'dart:math';

import '../session/peer_session.dart';
import 'link.dart';

enum ConnectionStatus {
  connectedDirect,
  connectedRelay,
  reconnecting,
  offline,
}

/// Exponential backoff with proportional jitter, capped per the spec.
class BackoffPolicy {
  BackoffPolicy({
    this.base = const Duration(seconds: 1),
    this.cap = const Duration(seconds: 30),
    this.jitter = 0.25,
    Random? random,
  }) : _random = random ?? Random();

  final Duration base;
  final Duration cap;
  final double jitter;
  final Random _random;

  Duration delayFor(int attempt) {
    final clampedAttempt = attempt.clamp(0, 30);
    final nominalMs = min(
      base.inMilliseconds * (1 << clampedAttempt),
      cap.inMilliseconds,
    );
    if (jitter <= 0) return Duration(milliseconds: nominalMs);
    final spread = nominalMs * jitter;
    final offset = (_random.nextDouble() * 2 - 1) * spread;
    final withJitter = (nominalMs + offset).round();
    return Duration(milliseconds: max(0, withJitter));
  }
}

/// Owns link selection for one peer: races candidate links, prefers the
/// best-ranked one, fails over on disconnect, and redials with backoff.
class LinkManager {
  LinkManager({
    required this.session,
    required List<Future<Link> Function()> dialers,
    required int Function() clock,
    BackoffPolicy? backoff,
    this.heartbeatInterval = const Duration(seconds: 15),
    this.livenessTimeout = const Duration(seconds: 45),
  })  : _dialers = dialers,
        _clock = clock,
        _backoff = backoff ?? BackoffPolicy();

  final PeerSession session;
  final List<Future<Link> Function()> _dialers;
  final int Function() _clock;
  final BackoffPolicy _backoff;
  final Duration heartbeatInterval;
  final Duration livenessTimeout;

  final Map<String, Link> _candidates = {};
  final Map<String, StreamSubscription<LinkState>> _stateSubs = {};
  final StreamController<ConnectionStatus> _statuses =
      StreamController<ConnectionStatus>.broadcast();

  ConnectionStatus _status = ConnectionStatus.offline;
  Link? _active;
  int? _lastAckMs;
  int _attempt = 0;
  bool _running = false;

  ConnectionStatus get status => _status;
  Stream<ConnectionStatus> get statuses => _statuses.stream;

  bool get isLive {
    final last = _lastAckMs;
    if (last == null) return false;
    return _clock() - last <= livenessTimeout.inMilliseconds;
  }

  Future<void> start() async {
    _running = true;
    await _dialAll();
  }

  Future<void> _dialAll() async {
    for (final dial in _dialers) {
      unawaited(dial().then(offer).catchError((Object _) {
        _attempt++;
      }));
    }
  }

  /// Registers a newly available link. Adopted only if it outranks the
  /// active one, so a relay appearing later never displaces a live LAN path.
  void offer(Link link) {
    _candidates[link.id] = link;
    _stateSubs[link.id]?.cancel();
    _stateSubs[link.id] = link.states.listen((s) {
      if (s == LinkState.disconnected || s == LinkState.failed) {
        _candidates.remove(link.id);
        _stateSubs.remove(link.id)?.cancel();
        if (_active?.id == link.id) {
          _active = null;
          _selectBest();
        }
      }
    });
    _selectBest();
  }

  void _selectBest() {
    final usable = _candidates.values
        .where((l) => l.state == LinkState.connected)
        .toList()
      ..sort((a, b) =>
          a.quality.preferenceScore.compareTo(b.quality.preferenceScore));

    if (usable.isEmpty) {
      _active = null;
      _setStatus(
          _running ? ConnectionStatus.reconnecting : ConnectionStatus.offline);
      return;
    }

    final best = usable.first;
    if (_active?.id != best.id) {
      _active = best;
      session.attach(best);
      _attempt = 0;
      _lastAckMs = _clock();
    }
    _setStatus(best.quality.isDirect
        ? ConnectionStatus.connectedDirect
        : ConnectionStatus.connectedRelay);
  }

  void _setStatus(ConnectionStatus next) {
    if (_status == next) return;
    _status = next;
    _statuses.add(next);
  }

  void onHeartbeatAck(int atMs) => _lastAckMs = atMs;

  /// Sleep suspends sockets without telling the peer, so on wake we tear
  /// down unconditionally instead of waiting out the liveness timeout.
  Future<void> onWake() async {
    for (final link in _candidates.values.toList()) {
      await link.close();
    }
    _candidates.clear();
    for (final sub in _stateSubs.values) {
      await sub.cancel();
    }
    _stateSubs.clear();
    _active = null;
    _lastAckMs = null;
    _setStatus(ConnectionStatus.reconnecting);
    // Unconditional: the contract for onWake is teardown *and* redial. Gating
    // the redial on _running would strand a manager that adopted links via
    // offer() without a start(), leaving the session attached to a socket the
    // sleep already killed.
    await _dialAll();
  }

  Duration nextRetryDelay() => _backoff.delayFor(_attempt);

  Future<void> stop() async {
    _running = false;
    for (final sub in _stateSubs.values) {
      await sub.cancel();
    }
    _stateSubs.clear();
    for (final link in _candidates.values.toList()) {
      await link.close();
    }
    _candidates.clear();
    _active = null;
    _setStatus(ConnectionStatus.offline);
  }
}
