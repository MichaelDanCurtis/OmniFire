import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

const int fixedClockMs = 1753200000000;

EngineConfig config({
  bool lan = false,
  String displayName = 'Test Device',
  LanDiscovery? discovery,
  int lanPort = 0,
}) =>
    EngineConfig(
      relayBases: [Uri.parse('http://localhost:8787')],
      displayName: displayName,
      lanEnabled: lan,
      lanDiscovery: discovery,
      lanPort: lanPort,
    );

Future<OmniFiEngine> engine({
  SecureStore? store,
  ClipboardWatcher? watcher,
  EngineConfig? engineConfig,
}) =>
    OmniFiEngine.create(
      store: store ?? InMemorySecureStore(),
      watcher: watcher ?? FakeClipboardWatcher(),
      config: engineConfig ?? config(),
      clock: () => fixedClockMs,
    );

/// The roster entry another device would hold for [id].
PeerRecord rosterEntryFor(DeviceIdentity id) => PeerRecord(
      deviceId: id.deviceId,
      publicKey: id.keys.publicKey,
      displayName: id.displayName,
      addedAtMs: 1,
    );

/// A roster entry for a device that does not exist, for tests that only need
/// the engine to track *a* peer.
PeerRecord placeholderPeer(String deviceId, int keyByte) => PeerRecord(
      deviceId: deviceId,
      publicKey: List<int>.filled(32, keyByte),
      displayName: deviceId.substring(0, 8),
      addedAtMs: 1,
    );

PeerSession throwawaySession(String localDeviceId, String peerDeviceId) =>
    PeerSession(
      localDeviceId: localDeviceId,
      peerDeviceId: peerDeviceId,
      crypto: AeadSession(
        sendKey: List<int>.filled(32, 1),
        receiveKey: List<int>.filled(32, 2),
      ),
      clock: () => fixedClockMs,
    );

Future<void> pumpUntil(
  bool Function() done, {
  Duration timeout = const Duration(seconds: 10),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (!done()) {
    if (DateTime.now().isAfter(deadline)) {
      throw StateError('condition was not met within $timeout');
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}

/// A watcher whose [start] blocks until [gate] is completed, so a teardown can
/// be driven into the window a suspended [OmniFiEngine.start] is sitting in.
class GatedClipboardWatcher implements ClipboardWatcher {
  final Completer<void> gate = Completer<void>();
  final StreamController<ClipboardContent> _changes =
      StreamController<ClipboardContent>.broadcast();

  @override
  Stream<ClipboardContent> get changes => _changes.stream;

  @override
  Future<void> write(ClipboardContent content) async {}

  @override
  Future<void> start() => gate.future;

  @override
  Future<void> stop() async {
    if (!_changes.isClosed) await _changes.close();
  }
}

/// A [LanDiscovery] that runs a callback at two points [start] cannot
/// otherwise be interrupted at.
///
/// [advertise] is called, and its body runs, strictly before [start] awaits
/// it; [discover] is evaluated synchronously inside `LinkManager.start()`,
/// which [start] calls from inside its per-peer loop. A hook that calls
/// `stop()` from either therefore lands `_started = false` in exactly the
/// window the guard after it exists for -- without counting microtasks.
class HookedDiscovery implements LanDiscovery {
  HookedDiscovery({this.onAdvertise, this.onDiscover});

  final void Function()? onAdvertise;
  final void Function()? onDiscover;
  bool discovered = false;

  @override
  Stream<LanEndpoint> discover() {
    if (!discovered) {
      discovered = true;
      onDiscover?.call();
    }
    return const Stream<LanEndpoint>.empty();
  }

  @override
  Future<void> advertise({
    required String deviceId,
    required int port,
  }) async {
    onAdvertise?.call();
  }
}

/// Wraps a [Link] so [close] suspends until released. Everything else
/// delegates, so a manager tearing this down stalls exactly where a real
/// socket close would.
class GatedCloseLink implements Link {
  GatedCloseLink(this.inner);
  final Link inner;
  final Completer<void> _gate = Completer<void>();

  void release() {
    if (!_gate.isCompleted) _gate.complete();
  }

  @override
  String get id => inner.id;
  @override
  LinkKind get kind => inner.kind;
  @override
  Stream<Uint8List> get inbound => inner.inbound;
  @override
  Stream<LinkState> get states => inner.states;
  @override
  LinkState get state => inner.state;
  @override
  LinkQuality get quality => inner.quality;
  @override
  Future<void> send(List<int> frame) => inner.send(frame);

  @override
  Future<void> close() async {
    await _gate.future;
    await inner.close();
  }
}

/// A watcher whose [write] genuinely suspends, for a duration that depends on
/// the content. Without it every write completes in the same microtask and an
/// out-of-order completion is unobservable.
class SlowWriteClipboardWatcher implements ClipboardWatcher {
  SlowWriteClipboardWatcher(this.delayFor);

  final Duration Function(ClipboardContent content) delayFor;

  final StreamController<ClipboardContent> _changes =
      StreamController<ClipboardContent>.broadcast();

  /// Every write, in the order the writes actually *completed*.
  final List<String> completedWrites = [];

  ClipboardContent? current;

  @override
  Stream<ClipboardContent> get changes => _changes.stream;

  @override
  Future<void> write(ClipboardContent content) async {
    await Future<void>.delayed(delayFor(content));
    current = content;
    completedWrites.add(utf8.decode(content.data));
  }

  @override
  Future<void> start() async {}

  @override
  Future<void> stop() async {
    if (!_changes.isClosed) await _changes.close();
  }
}

Map<String, Object?> clipboardPayload(String text, int timestampMs) {
  final data = Uint8List.fromList(utf8.encode(text));
  return ClipboardPayload(
    format: 'text',
    data: data,
    timestampMs: timestampMs,
    contentHash: clipboardHash('text', data),
  ).toMap();
}

void main() {
  test('creates an identity and a mesh on first run', () async {
    final e = await engine();
    expect(e.identity.deviceId, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(e.identity.displayName, 'Test Device');
    expect(e.mesh.meshId, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(e.mesh.peers, isEmpty);
  });

  test('reuses identity and mesh across restarts', () async {
    final store = InMemorySecureStore();
    final first = await engine(store: store);
    final second = await engine(store: store);
    expect(second.identity.deviceId, first.identity.deviceId);
    expect(second.mesh.meshId, first.mesh.meshId);
  });

  test('starts offline with no peers', () async {
    final e = await engine();
    expect(e.status, ConnectionStatus.offline);
    expect(e.sessions, isEmpty);
  });

  test('an invite carries the mesh id and this device public key',
      () async {
    final e = await engine();
    final invite = e.buildInvite();
    expect(invite.meshId, e.mesh.meshId);
    expect(invite.inviterPublicKey, e.identity.keys.publicKey);
    expect(invite.psk.length, 32);
    expect(invite.relayHint, 'http://localhost:8787');
  });

  test('both sides of a pairing derive the same authentication words',
      () async {
    // The invite is built ONCE, by the inviter, and the same object is what
    // the QR carries to the joiner. beginInvite() minting its own would put a
    // different random PSK into the HKDF salt on the inviting side, giving
    // the two devices different master secrets and different SAS words on
    // every single attempt -- a pairing the user is trained to reject.
    final inviter = await engine();
    final joiner = await engine();
    final invite = inviter.buildInvite();
    final links = FakeLinkFactory.connectedPair();

    // Concurrent, as they are in reality: neither side waits for the other.
    final invitePending = inviter.beginInvite(invite, links.a);
    final joinPending = joiner.beginJoin(invite, links.b);
    final inviterSide = await invitePending;
    final joinerSide = await joinPending;

    expect(inviterSide.sas, joinerSide.sas);
    expect(inviterSide.sas, isNotEmpty);

    // And the pairing completes, on both sides, into matching roster entries.
    final inviterOutcome = await inviterSide.confirm(true);
    final joinerOutcome = await joinerSide.confirm(true);
    expect(inviterOutcome.peer.deviceId, joiner.identity.deviceId);
    expect(joinerOutcome.peer.deviceId, inviter.identity.deviceId);
    expect(inviterOutcome.meshId, inviter.mesh.meshId);
    expect(joinerOutcome.meshId, inviter.mesh.meshId);
  });

  test('the rendezvous pairing entry points surface an unreachable relay',
      () async {
    // Wiring, not protocol: the two-device case is covered against the live
    // relay in test/integration. What this pins down is that the engine's
    // rendezvous entry points reach the rendezvous at all, and that a relay
    // that is not there fails as a RendezvousError rather than as a raw
    // socket error the UI has no idea what to do with -- or, worse, than
    // hanging for the two-minute inviter timeout.
    final e = await engine(
      engineConfig: EngineConfig(
        // Nothing listens here.
        relayBases: [Uri(scheme: 'http', host: 'localhost', port: 1)],
        displayName: 'Test Device',
        lanEnabled: false,
      ),
    );
    final invite = e.buildInvite();
    const brief = Duration(milliseconds: 500);

    await expectLater(
      e.beginInviteAtRendezvous(invite, timeout: brief),
      throwsA(isA<RendezvousError>()),
    );
    await expectLater(
      e.beginJoinAtRendezvous(invite, timeout: brief),
      throwsA(isA<RendezvousError>()),
    );
  });

  group('the engine owns the rendezvous link it created', () {
    // These drive `pairOverRendezvous` directly, which is what both
    // `beginInviteAtRendezvous` and `beginJoinAtRendezvous` are: `meet` and
    // `run` injected, so the ownership rules can be exercised without a
    // relay. The two-device protocol itself is covered against the live
    // relay in test/integration.

    test('a successful pairing closes the link once confirm resolves',
        () async {
      final inviter = await engine();
      final joiner = await engine();
      final invite = inviter.buildInvite();
      final links = FakeLinkFactory.connectedPair();

      final invitePending = inviter.pairOverRendezvous(
        meet: () async => links.a,
        run: (link) => inviter.beginInvite(invite, link),
        timeout: const Duration(seconds: 10),
      );
      final joinPending = joiner.beginJoin(invite, links.b);
      final inviterSide = await invitePending;
      final joinerSide = await joinPending;
      expect(inviterSide.sas, joinerSide.sas);

      // The joiner goes first only because closing one end of a fake pair
      // closes both; nothing about the fix depends on the order.
      await joinerSide.confirm(true);
      final outcome = await inviterSide.confirm(true);
      expect(outcome.peer.deviceId, joiner.identity.deviceId);

      expect(links.a.state, isNot(LinkState.connected),
          reason: 'PairingSasPending exposes only sas and confirm, so the '
              'caller has no handle to close this with. A link left open '
              'here is one WebSocket leaked into the rendezvous Durable '
              'Object per successful pairing, for its whole idle lifetime');
    });

    test('a pairing that fails key confirmation also closes the link',
        () async {
      // The other outcome of confirm(true). PairingFlow closes the link on
      // confirm(false) and on nothing else, so this path leaks exactly as the
      // success path does.
      final inviter = await engine();
      final joiner = await engine();
      final invite = inviter.buildInvite();
      // One bit off, as a mistyped or relayed code would be: the two sides
      // derive different masters, so neither key confirmation can verify.
      final tampered = PairingInvite(
        meshId: invite.meshId,
        inviterPublicKey: invite.inviterPublicKey,
        psk: [...invite.psk.take(31), invite.psk[31] ^ 1],
      );
      final links = FakeLinkFactory.connectedPair();

      final invitePending = inviter.pairOverRendezvous(
        meet: () async => links.a,
        run: (link) => inviter.beginInvite(invite, link),
        timeout: const Duration(seconds: 10),
      );
      final joinPending = joiner.beginJoin(tampered, links.b);
      final inviterSide = await invitePending;
      final joinerSide = await joinPending;
      expect(inviterSide.sas, isNot(joinerSide.sas),
          reason: 'a wrong psk is exactly what the SAS is there to show');

      await expectLater(
          inviterSide.confirm(true), throwsA(isA<PairingRejectedError>()));
      expect(links.a.state, isNot(LinkState.connected));
    });

    test('a flow that fails to start closes the link', () async {
      final e = await engine();
      final link = FakeLinkFactory(id: 'rendezvous:never-used');
      await expectLater(
        e.pairOverRendezvous(
          meet: () async => link,
          run: (_) async => throw StateError('the flow could not start'),
          timeout: const Duration(seconds: 10),
        ),
        throwsA(isA<StateError>()),
      );
      expect(link.state, isNot(LinkState.connected),
          reason: 'a pairing that never reached the SAS has no caller left '
              'to close its socket');
    });

    test('a peer that dies after the latch fails the pairing instead of '
        'hanging', () async {
      // A link whose peer latched and then went away. It is deliberately not
      // closed: that is what a RelayLink looks like when the remote process
      // dies. RelayLink closes its inbound stream only in its own close(), so
      // no end-of-stream ever arrives, PairingFlow's link-closed branch is
      // unreachable, and PairingFlow has no timeout of its own. The ordinary
      // route to this is a joiner whose socket dies in the instant after the
      // inviter latched it.
      final e = await engine();
      final invite = e.buildInvite();
      final link = FakeLinkFactory(id: 'rendezvous:dead-peer');
      final elapsed = Stopwatch()..start();

      await expectLater(
        e.pairOverRendezvous(
          meet: () async => link,
          run: (l) => e.beginInvite(invite, l),
          timeout: const Duration(milliseconds: 200),
        ),
        throwsA(isA<PairingRejectedError>()),
        reason: 'a bare TimeoutException here is a transport detail the UI '
            'has no case for; this is the same event as any other peer that '
            'stopped answering',
      ).timeout(const Duration(seconds: 30));
      elapsed.stop();

      // The floor, not the 200ms, is what governs — see minExchangeTimeout.
      expect(elapsed.elapsed, lessThan(OmniFiEngine.minExchangeTimeout * 3),
          reason: 'without a deadline that survives the latch this never '
              'returns at all');
      expect(link.state, isNot(LinkState.connected));
    });
  });

  test('forgetting a peer removes it from the roster', () async {
    final e = await engine();
    e.mesh.addPeer(PeerRecord(
      deviceId: 'b' * 32,
      publicKey: List<int>.filled(32, 5),
      displayName: 'Gone',
      addedAtMs: 1,
    ));
    await e.forgetPeer('b' * 32);
    expect(e.mesh.peer('b' * 32), isNull);
    expect(e.mesh.isAuthorized('b' * 32, List<int>.filled(32, 5)), isFalse);
  });

  test('a forgotten peer stays forgotten across a restart', () async {
    final store = InMemorySecureStore();
    final first = await engine(store: store);
    first.mesh.addPeer(PeerRecord(
      deviceId: 'b' * 32,
      publicKey: List<int>.filled(32, 5),
      displayName: 'Gone',
      addedAtMs: 1,
    ));
    await first.persist();
    await first.forgetPeer('b' * 32);

    final second = await engine(store: store);
    expect(second.mesh.peer('b' * 32), isNull);
  });

  test('status reflects the worst peer, not the best', () async {
    final e = await engine();
    e.debugSetPeerStatus('b' * 32, ConnectionStatus.connectedDirect);
    e.debugSetPeerStatus('c' * 32, ConnectionStatus.reconnecting);
    expect(e.status, ConnectionStatus.reconnecting);

    e.debugSetPeerStatus('c' * 32, ConnectionStatus.connectedRelay);
    expect(e.status, ConnectionStatus.connectedRelay);

    e.debugSetPeerStatus('b' * 32, ConnectionStatus.connectedRelay);
    e.debugSetPeerStatus('c' * 32, ConnectionStatus.connectedDirect);
    expect(e.status, ConnectionStatus.connectedRelay);
  });

  test('screen lock pauses clipboard sync', () async {
    final e = await engine();
    e.onScreenLocked();
    expect(e.clipboard.isPaused, isTrue);
    e.onScreenUnlocked();
    expect(e.clipboard.isPaused, isFalse);
  });

  test('stop is safe to call without start', () async {
    final e = await engine();
    await e.stop();
    expect(e.status, ConnectionStatus.offline);
  });

  test('clipboard changes reach a connected peer session', () async {
    final watcher = FakeClipboardWatcher();
    final e = await OmniFiEngine.create(
      store: InMemorySecureStore(),
      watcher: watcher,
      config: config(),
      clock: () => 1753200000000,
    );
    await e.start();

    final k1 = List<int>.filled(32, 11);
    final k2 = List<int>.filled(32, 22);
    final remote = PeerSession(
      localDeviceId: 'b' * 32,
      peerDeviceId: e.identity.deviceId,
      crypto: AeadSession(sendKey: k2, receiveKey: k1),
      clock: () => 1753200000000,
    );
    final local = e.debugAttachSession(
      peerDeviceId: 'b' * 32,
      crypto: AeadSession(sendKey: k1, receiveKey: k2),
    );
    final links = FakeLinkFactory.connectedPair();
    local.attach(links.a);
    remote.attach(links.b);

    final received = remote.inbound.first;
    watcher.emit(ClipboardContent(
      format: 'text',
      data: Uint8List.fromList(utf8.encode('engine wired')),
      isConcealed: false,
    ));
    final payload = ClipboardPayload.fromMap((await received).payload);
    expect(utf8.decode(payload.data), 'engine wired');
  });

  test('two clipboard envelopes from one peer are applied in order', () async {
    // The first write is deliberately much slower than the second. An
    // unserialized `inbound.listen(clipboard.handleIncoming)` would let the
    // second write complete first, leaving the clipboard holding 'older'
    // while the recorded hash/timestamp say 'newer' -- after which the stale
    // content is rebroadcast as if it were new.
    final watcher = SlowWriteClipboardWatcher((c) =>
        utf8.decode(c.data) == 'older'
            ? const Duration(milliseconds: 60)
            : const Duration(milliseconds: 1));
    final e = await OmniFiEngine.create(
      store: InMemorySecureStore(),
      watcher: watcher,
      config: config(),
      clock: () => 1753200000000,
    );
    await e.start();

    final k1 = List<int>.filled(32, 11);
    final k2 = List<int>.filled(32, 22);
    final remote = PeerSession(
      localDeviceId: 'b' * 32,
      peerDeviceId: e.identity.deviceId,
      crypto: AeadSession(sendKey: k2, receiveKey: k1),
      clock: () => 1753200000000,
    );
    final local = e.debugAttachSession(
      peerDeviceId: 'b' * 32,
      crypto: AeadSession(sendKey: k1, receiveKey: k2),
    );
    final links = FakeLinkFactory.connectedPair();
    local.attach(links.a);
    remote.attach(links.b);

    // Back-to-back: nothing waits for the first envelope to be *applied*
    // before the second one is on the wire.
    await remote.send(MessageType.clipboardUpdate,
        clipboardPayload('older', 1753200001000));
    await remote.send(MessageType.clipboardUpdate,
        clipboardPayload('newer', 1753200002000));

    await Future<void>.delayed(const Duration(milliseconds: 400));

    expect(watcher.completedWrites, ['older', 'newer']);
    expect(utf8.decode(watcher.current!.data), 'newer');
    // The recorded state must describe what the clipboard actually holds.
    expect(
      e.clipboard.lastAppliedHash,
      clipboardHash('text', watcher.current!.data),
    );
  });

  // ---- Fix 3: onWake must not iterate a live collection across an await ----

  test('waking survives a peer being forgotten mid-loop', () async {
    final e = await engine();
    const b = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const c = 'cccccccccccccccccccccccccccccccc';
    e.mesh.addPeer(placeholderPeer(b, 5));
    e.mesh.addPeer(placeholderPeer(c, 6));
    await e.start();

    // Give the first manager a link whose close() stalls, so the engine's
    // wake loop is genuinely suspended between its two managers.
    final managerB = e.debugManagerFor(b)!;
    managerB.session = throwawaySession(e.identity.deviceId, b);
    final stalled =
        GatedCloseLink(FakeLinkFactory(id: 'stalled-lan', kind: LinkKind.lan));
    managerB.offer(stalled);

    final waking = e.onWake();
    // Removes the second manager from the map the wake loop is walking.
    await e.forgetPeer(c);
    stalled.release();

    // Without a snapshot this is a ConcurrentModificationError.
    await waking;
    expect(e.debugTrackedPeerIds, [b]);
    await e.stop();
  });

  // ---- Fix 4: start() must not outlive a stop() that lands mid-flight ----

  test('a stop landing while start is suspended leaves nothing running or '
      'bound', () async {
    // A port nobody holds, so "still bound afterwards" is decidable.
    final probe = await ServerSocket.bind(InternetAddress.anyIPv4, 0);
    final port = probe.port;
    await probe.close();

    final watcher = GatedClipboardWatcher();
    final e = await engine(
      watcher: watcher,
      engineConfig: config(lan: true, lanPort: port),
    );
    e.mesh.addPeer(placeholderPeer('b' * 32, 5));

    final starting = e.start();
    await Future<void>.delayed(Duration.zero);
    await e.stop();
    // start() resumes into an engine that has already torn itself down.
    watcher.gate.complete();
    await starting;

    expect(e.debugTrackedPeerIds, isEmpty);
    expect(e.debugListenerPort, isNull);
    expect(e.sessions, isEmpty);
    expect(e.debugSubscriptionCount, 0);
    // A ServerSocket bound after the teardown would still own this port.
    final rebind = await ServerSocket.bind(InternetAddress.anyIPv4, port);
    await rebind.close();
  });

  test('a stop landing inside the LAN bind closes the too-late listener',
      () async {
    // The test above resumes at the FIRST re-check, so nothing is ever bound
    // and the bind guard is not what it proves. This one resumes after the
    // bind has succeeded: the guard is the only thing standing between a
    // stopped engine and a live ServerSocket nothing owns.
    final probe = await ServerSocket.bind(InternetAddress.anyIPv4, 0);
    final port = probe.port;
    await probe.close();

    final e = await engine(engineConfig: config(lan: true, lanPort: port));
    e.mesh.addPeer(placeholderPeer('b' * 32, 5));

    final bound = Completer<LanListener>();
    final release = Completer<void>();
    e.debugBindListener = ({required String localDeviceId, int port = 0}) async {
      final listener =
          await LanListener.bind(localDeviceId: localDeviceId, port: port);
      bound.complete(listener);
      await release.future;
      return listener;
    };

    final starting = e.start();
    final listener = await bound.future;
    expect(listener.port, port);

    // Bound for real, and now handed to an engine that has already torn
    // itself down.
    final stopping = e.stop();
    release.complete();
    await starting;
    await stopping;

    expect(e.debugListenerPort, isNull);
    expect(e.debugTrackedPeerIds, isEmpty);
    expect(e.debugSubscriptionCount, 0);
    // A listener the guard failed to close would still own this port.
    final rebind = await ServerSocket.bind(InternetAddress.anyIPv4, port);
    await rebind.close();
  });

  test('a stop landing during the LAN advertise connects no peers', () async {
    late OmniFiEngine e;
    Future<void>? stopping;
    final discovery =
        HookedDiscovery(onAdvertise: () => stopping = e.stop());
    e = await engine(engineConfig: config(lan: true, discovery: discovery));
    e.mesh.addPeer(placeholderPeer('b' * 32, 5));

    await e.start();
    await stopping;

    // The teardown ran with the maps empty. A peer connected after it would
    // hold a manager and a status subscription nothing will ever stop.
    expect(e.debugTrackedPeerIds, isEmpty);
    expect(e.debugSubscriptionCount, 0);
    expect(e.debugListenerPort, isNull);
  });

  test('a stop landing between two peers connects no further peers', () async {
    late OmniFiEngine e;
    Future<void>? stopping;
    // Fires from inside the FIRST peer's dial, so the stop lands while the
    // per-peer loop is suspended in _connectPeer and the second iteration is
    // still to come.
    final discovery = HookedDiscovery(onDiscover: () => stopping = e.stop());
    e = await engine(engineConfig: config(lan: true, discovery: discovery));
    e.mesh.addPeer(placeholderPeer('b' * 32, 5));
    e.mesh.addPeer(placeholderPeer('c' * 32, 6));

    await e.start();
    await stopping;

    expect(discovery.discovered, isTrue);
    expect(e.debugTrackedPeerIds, isEmpty);
    expect(e.debugSubscriptionCount, 0);
  });

  // ---- Fix 5: forgetPeer must cancel that peer's subscriptions ----

  test("a forgotten peer's manager can no longer write into the status map",
      () async {
    final e = await engine();
    const b = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    e.mesh.addPeer(placeholderPeer(b, 5));
    await e.start();
    expect(e.debugSubscriptionCount, 1);

    final manager = e.debugManagerFor(b)!;
    manager.session = throwawaySession(e.identity.deviceId, b);

    await e.forgetPeer(b);
    expect(e.debugSubscriptionCount, 0);
    expect(e.status, ConnectionStatus.offline);

    // The manager is discarded but still alive. A status change on it must
    // not reach _peerStatuses for a peer that has been removed.
    manager.offer(FakeLinkFactory(id: 'orphan-lan', kind: LinkKind.lan));
    await Future<void>.delayed(Duration.zero);
    expect(e.status, ConnectionStatus.offline);
    await e.stop();
  });

  test('per-peer subscriptions do not accumulate across pair/forget cycles',
      () async {
    final e = await engine();
    for (var i = 0; i < 3; i++) {
      final id = String.fromCharCode(0x61 + i) * 32;
      e.mesh.addPeer(placeholderPeer(id, 5 + i));
      await e.start();
      expect(e.debugSubscriptionCount, 1);
      await e.forgetPeer(id);
      expect(e.debugSubscriptionCount, 0);
      await e.stop();
    }
  });

  // ---- Fix 2: the LAN transport is actually wired ----

  test('an inbound link is adopted as the roster peer that authenticates',
      () async {
    final e = await engine();
    final peerIdentity = await loadOrCreateIdentity(
      store: InMemorySecureStore(),
      displayName: 'Peer',
    );
    e.mesh.addPeer(rosterEntryFor(peerIdentity));
    await e.start();

    final links = FakeLinkFactory.connectedPair();
    // The far end runs exactly the handshake a real peer runs on reconnect.
    final peerSide = SessionEstablisher.establish(
      link: links.b,
      identity: peerIdentity,
      peer: rosterEntryFor(e.identity),
    );
    await e.debugAcceptInbound(links.a);
    await peerSide;

    expect(e.sessions.single.peerDeviceId, peerIdentity.deviceId);
    // And the link went on to the manager, as a dialed one would.
    expect(
      e.debugManagerFor(peerIdentity.deviceId)!.candidates,
      contains(links.a.id),
    );
    expect(links.a.state, LinkState.connected);
    await e.stop();
  });

  test('an inbound link is refused for a peer whose session is already live',
      () async {
    // An inbound socket carries no identity of its own, and a peer whose
    // session is already live short-circuits the establisher -- so adopting
    // one runs NO handshake at all. Because LAN outranks every relay, the
    // adopted socket becomes the active link and the session migrates onto
    // it: anyone who can reach the listener port black-holes the peer's
    // traffic and, with one junk frame, kills the session.
    final e = await engine();
    final peerIdentity = await loadOrCreateIdentity(
      store: InMemorySecureStore(),
      displayName: 'Peer',
    );
    e.mesh.addPeer(rosterEntryFor(peerIdentity));
    await e.start();

    // The state a reconnected peer leaves behind: a live session carried by
    // a relay link.
    final session = e.debugAttachSession(
      peerDeviceId: peerIdentity.deviceId,
      crypto: AeadSession(
        sendKey: List<int>.filled(32, 11),
        receiveKey: List<int>.filled(32, 22),
      ),
    );
    final manager = e.debugManagerFor(peerIdentity.deviceId)!;
    manager.session = session;
    final relay = FakeLinkFactory(id: 'relay-live', kind: LinkKind.relay);
    manager.offer(relay);
    expect(session.link?.id, 'relay-live');

    // The attacker: a LAN socket with nobody on the far end. Nothing on it
    // ever authenticates, because nothing on this path can.
    final attack = FakeLinkFactory.connectedPair(
      idA: 'attacker',
      idB: 'attacker-far',
    );
    await e.debugAcceptInbound(attack.a);

    expect(session.link?.id, 'relay-live');
    expect(manager.candidates.keys, ['relay-live']);
    expect(attack.a.state, LinkState.disconnected);
    expect(attack.a.sent, isEmpty);
    await e.stop();
  });

  test('an inbound link that resolves to no roster member is closed',
      () async {
    final e = await engine();
    await e.start();

    final links = FakeLinkFactory.connectedPair();
    await e.debugAcceptInbound(links.a);

    expect(links.a.state, LinkState.disconnected);
    expect(e.sessions, isEmpty);
    await e.stop();
  });

  test('an accepted LAN connection is not left open on the floor', () async {
    // Nothing subscribes to LanListener.incoming unless the engine does, and
    // it is a broadcast stream: an unsubscribed listener accepts sockets and
    // discards them still open, one leaked file descriptor per connection.
    final e = await engine(engineConfig: config(lan: true));
    await e.start();
    expect(e.debugListenerPort, isNotNull);

    final socket = await Socket.connect(
      InternetAddress.loopbackIPv4,
      e.debugListenerPort!,
    );
    // The roster is empty, so this resolves to nobody and must be closed.
    await expectLater(
      socket
          .listen(null)
          .asFuture<void>()
          .timeout(const Duration(seconds: 5)),
      completes,
    );
    await socket.close();
    await e.stop();
  });

  test('a discovered LAN peer becomes a direct connection that carries the '
      'clipboard', () async {
    final watcherA = FakeClipboardWatcher();
    final watcherB = FakeClipboardWatcher();
    final discovery = StaticDiscovery([]);

    final a = await engine(
      watcher: watcherA,
      engineConfig:
          config(lan: true, displayName: 'A', discovery: discovery),
    );
    final b = await engine(
      watcher: watcherB,
      engineConfig: config(lan: true, displayName: 'B'),
    );

    // Rostered both ways before either starts: a manager has to exist for a
    // peer before an inbound link can be adopted for it.
    a.mesh.addPeer(rosterEntryFor(b.identity));
    b.mesh.addPeer(rosterEntryFor(a.identity));

    await b.start();
    discovery.endpoints.add(LanEndpoint(
      deviceId: b.identity.deviceId,
      address: InternetAddress.loopbackIPv4,
      port: b.debugListenerPort!,
    ));
    await a.start();

    await pumpUntil(() => a.sessions.isNotEmpty && b.sessions.isNotEmpty);
    expect(a.sessions.single.peerDeviceId, b.identity.deviceId);
    expect(b.sessions.single.peerDeviceId, a.identity.deviceId);
    expect(a.status, ConnectionStatus.connectedDirect);
    expect(b.status, ConnectionStatus.connectedDirect);

    // And the link carries traffic, which is the whole point of preferring it.
    watcherA.emit(ClipboardContent(
      format: 'text',
      data: Uint8List.fromList(utf8.encode('over the lan')),
      isConcealed: false,
    ));
    await pumpUntil(() =>
        watcherB.current != null &&
        utf8.decode(watcherB.current!.data) == 'over the lan');

    await a.stop();
    await b.stop();
  });
}
