import 'dart:async';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:omnifi_core/omnifi_core.dart';
import 'package:stream_channel/stream_channel.dart';
import 'package:test/test.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

/// Minimal in-memory [WebSocketChannel], the same shape as the one in
/// test/transport/relay_link_test.dart. Kept local so this file can be read
/// on its own, and because these tests care about `sent` in a way that one
/// does not.
class _FakeChannel extends StreamChannelMixin<Object?>
    implements WebSocketChannel {
  final StreamController<Object?> _incoming =
      StreamController<Object?>.broadcast();
  final List<Object?> sent = [];
  int? _closeCode;
  bool sinkClosed = false;

  /// Pushes a frame at this socket exactly as the relay would.
  void deliver(Object? message) => _incoming.add(message);

  /// Simulates the relay closing the socket with [code].
  Future<void> deliverClose(int? code) async {
    _closeCode = code;
    await _incoming.close();
  }

  @override
  Stream<Object?> get stream => _incoming.stream;

  @override
  WebSocketSink get sink => _FakeSink(this);

  @override
  int? get closeCode => _closeCode;

  @override
  String? get closeReason => null;

  @override
  String? get protocol => null;

  @override
  Future<void> get ready async {}

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FakeSink implements WebSocketSink {
  _FakeSink(this._channel);
  final _FakeChannel _channel;

  @override
  void add(Object? data) => _channel.sent.add(data);

  @override
  Future<void> close([int? closeCode, String? closeReason]) async {
    _channel.sinkClosed = true;
    if (!_channel._incoming.isClosed) await _channel._incoming.close();
  }

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

final Uri _relay = Uri.parse('http://localhost:8787');

PairingInvite _invite() => generateInvite(
      meshId: randomHexId(),
      inviterPublicKey: List<int>.filled(32, 3),
    );

/// A rendezvous hello, encoded here rather than borrowed from the library so
/// that the wire format these tests depend on is pinned by the test too.
Uint8List _hello({required String role, required String id}) =>
    Uint8List.fromList(cbor.encode(CborValue({
      't': 'omnifi-rendezvous-hello-v1',
      'r': role,
      'id': id,
    })));

/// Starts an inviting rendezvous on [channel] and returns its pending link,
/// but only once that link has subscribed to the socket.
///
/// The wait matters: the socket's inbound stream is a broadcast stream, so a
/// frame delivered before the subscription exists is discarded and the test
/// would hang for reasons that have nothing to do with what it is checking.
/// `debugOnSocket` fires synchronously immediately before `_RendezvousLink`
/// is constructed, and the constructor subscribes with no suspension in
/// between, so by the time this completer's continuation runs the link is
/// listening.
Future<Future<Link>> _startInviter(
  _FakeChannel channel, {
  Duration timeout = const Duration(seconds: 20),
}) async {
  final armed = Completer<void>();
  final link = PairingRendezvous.awaitJoiner(
    invite: _invite(),
    relayBase: _relay,
    timeout: timeout,
    channelFactory: (_) => channel,
    debugOnSocket: (_) => armed.complete(),
  );
  // A rendezvous that fails before it opens a socket never reaches
  // debugOnSocket; surface that as an error here rather than as a hang. This
  // also keeps `link` from ever being an unhandled async error.
  unawaited(link.then((_) {}, onError: (Object e) {
    if (!armed.isCompleted) armed.completeError(e);
  }));
  await armed.future;
  return link;
}

/// Latches a joiner onto an inviting rendezvous and returns the link, the
/// joiner's ephemeral id, and the socket underneath.
Future<({Link link, String joinerId, _FakeChannel channel})> _latched() async {
  final channel = _FakeChannel();
  final pending = await _startInviter(channel);
  final joinerId = randomHexId();
  channel.deliver(
      addressFrame(broadcastDeviceId, _hello(role: 'joiner', id: joinerId)));
  final link = await pending;
  return (link: link, joinerId: joinerId, channel: channel);
}

/// Everything [link] hands to a subscriber that arrives late, frames and
/// errors together, in order.
Future<List<Object>> _observe(Link link) async {
  final observed = <Object>[];
  final sub = link.inbound.listen(observed.add, onError: observed.add);
  await pumpEventQueue();
  await sub.cancel();
  return observed;
}

void main() {
  group('the inbound buffer is bounded', () {
    // The window this buffer covers is not "a few microtasks between meet()
    // returning and PairingFlow subscribing". PairingFlow._run returns its
    // PairingSasPending from inside its try, so the finally cancels its
    // subscription at that return: from the instant the SAS words appear
    // until the user taps confirm there is no listener, the socket is open,
    // and anyone who scanned the QR can derive the namespace and broadcast
    // into it at up to the relay's 1 MiB per frame with no rate limit.

    test('a flood past the frame cap fails the link instead of growing',
        () async {
      final f = await _latched();
      const flood = PairingRendezvous.maxPendingFrames + 4;
      for (var i = 0; i < flood; i++) {
        f.channel.deliver(addressFrame(f.joinerId, Uint8List(32)));
      }
      await pumpEventQueue();

      final observed = await _observe(f.link);
      expect(observed.whereType<RendezvousError>(), isNotEmpty,
          reason: 'an unbounded buffer just keeps every frame and looks '
              'healthy while it does it');
      expect(observed.whereType<Uint8List>(), isEmpty,
          reason: 'the buffer must not have grown past the cap: an unbounded '
              'one hands over the entire flood the moment anyone listens');
      expect(f.link.state, isNot(LinkState.connected),
          reason: 'the socket doing the flooding is still connected and still '
              'sending; failing the link has to tear it down');
    });

    test('a flood past the byte cap fails the link even under the frame cap',
        () async {
      // Four frames is well inside the frame cap, so only the byte cap can
      // catch this. It is the half that matters most: the relay's limit is
      // 1 MiB per frame, so a handful of frames is all an attacker needs.
      final f = await _latched();
      final big = Uint8List(96 * 1024);
      expect(4, lessThan(PairingRendezvous.maxPendingFrames));
      expect(4 * big.length, greaterThan(PairingRendezvous.maxPendingBytes));
      for (var i = 0; i < 4; i++) {
        f.channel.deliver(addressFrame(f.joinerId, big));
      }
      await pumpEventQueue();

      final observed = await _observe(f.link);
      expect(observed.whereType<RendezvousError>(), isNotEmpty);
      expect(f.link.state, isNot(LinkState.connected));
    });

    test('everything up to the cap is still held for a late subscriber',
        () async {
      // The other half of the bound, and the reason this buffer exists at
      // all. A cap set too low, or a fix that dropped frames instead of
      // holding them, would lose the handshake message the exchange needs.
      final f = await _latched();
      for (var i = 0; i < PairingRendezvous.maxPendingFrames; i++) {
        f.channel.deliver(addressFrame(f.joinerId, Uint8List.fromList([i])));
      }
      await pumpEventQueue();

      final observed = await _observe(f.link);
      expect(observed.whereType<Uint8List>(),
          hasLength(PairingRendezvous.maxPendingFrames));
      expect(observed.whereType<RendezvousError>(), isEmpty);
      expect(f.link.state, LinkState.connected);
    });
  });

  group('hello validation', () {
    test('a hello claiming the all-zero broadcast id is refused', () async {
      // broadcastDeviceId is 32 lowercase hex characters, so it satisfies the
      // only check the id ever got. Latching onto it points the link at the
      // header the relay fans out to *every* socket in the Durable Object,
      // and the next frame this side sends is its handshake message: CBOR
      // {v, id, e, s} carrying its real device id and real static public key.
      final channel = _FakeChannel();
      final pending =
          await _startInviter(channel, timeout: const Duration(seconds: 1));
      channel.deliver(addressFrame(broadcastDeviceId,
          _hello(role: 'joiner', id: broadcastDeviceId)));

      await expectLater(pending, throwsA(isA<RendezvousError>()),
          reason: 'a rendezvous that accepted this would return a link '
              'addressed to the whole namespace');
      expect(channel.sent, isEmpty,
          reason: 'the inviter answers only once it has latched a joiner, so '
              'anything sent here is its ephemeral id going to every QR '
              'holder present');
    });

    test('a hello with a non-hex ephemeral id is refused before retarget sees '
        'it', () async {
      // Reverting the hex check is not cosmetic. RelayLink.retarget throws
      // ArgumentError for a malformed id, and _onFrame is a Stream.listen
      // callback: the throw becomes an unhandled async error, _settled is
      // never completed, and the rendezvous hangs to its timeout. Both
      // outcomes end in a RendezvousError, so only the zone tells them apart.
      final zoneErrors = <Object>[];
      Object? thrown;
      await (runZonedGuarded(() async {
            final channel = _FakeChannel();
            final pending = await _startInviter(channel,
                timeout: const Duration(milliseconds: 400));
            channel.deliver(addressFrame(
                broadcastDeviceId, _hello(role: 'joiner', id: 'z' * 32)));
            try {
              await pending;
            } on Object catch (e) {
              thrown = e;
            }
          }, (e, _) => zoneErrors.add(e)) ??
          Future<void>.value());

      expect(thrown, isA<RendezvousError>());
      expect(zoneErrors, isEmpty,
          reason: 'a malformed id must be dropped by _decodeHello, not '
              'handed to retarget from inside a stream callback');
    });
  });

  group('socket failures during the rendezvous', () {
    test('a send onto a dead socket fails as a RendezvousError, not a raw '
        'LinkClosedError', () async {
      // The joiner's first action is to announce itself. Closing the socket
      // synchronously in debugOnSocket — before _RendezvousLink is even
      // constructed, so it never observes the state change — puts that very
      // first send onto a socket that is already gone.
      final channel = _FakeChannel();
      await expectLater(
        PairingRendezvous.connectToInviter(
          invite: _invite(),
          relayBase: _relay,
          timeout: const Duration(seconds: 5),
          channelFactory: (_) => channel,
          debugOnSocket: (socket) => unawaited(socket.close()),
        ),
        throwsA(isA<RendezvousError>()),
        reason: 'a transport error reaching the UI as LinkClosedError reads '
            'as an internal fault rather than "the rendezvous went away"',
      );
    });

    test('a socket that dies while waiting fails fast, not at the timeout',
        () async {
      // The inviter's timeout is two minutes because it is waiting for a
      // human to walk to another device. Waiting that long to report that the
      // relay hung up is the difference between a diagnostic and a hang.
      final channel = _FakeChannel();
      final pending =
          await _startInviter(channel, timeout: const Duration(seconds: 20));
      final elapsed = Stopwatch()..start();
      await channel.deliverClose(1009);

      await expectLater(pending, throwsA(isA<RendezvousError>()))
          .timeout(const Duration(seconds: 5));
      elapsed.stop();
      expect(elapsed.elapsed, lessThan(const Duration(seconds: 5)),
          reason: 'without the fail-fast this sits until the 20s timeout');
    });
  });
}
