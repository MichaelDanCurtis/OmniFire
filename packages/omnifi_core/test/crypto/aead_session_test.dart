import 'dart:convert';
import 'dart:typed_data';

import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

/// Two sessions facing each other: A's send key is B's receive key.
({AeadSession a, AeadSession b}) pair() {
  final k1 = List<int>.filled(32, 1);
  final k2 = List<int>.filled(32, 2);
  return (
    a: AeadSession(sendKey: k1, receiveKey: k2),
    b: AeadSession(sendKey: k2, receiveKey: k1),
  );
}

void main() {
  test('round-trips a message', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('hello'));
    final opened = await p.b.open(sealed);
    expect(utf8.decode(opened), 'hello');
  });

  test('counter increments per sealed message', () async {
    final p = pair();
    expect(p.a.sendCounter, 0);
    await p.a.seal(utf8.encode('one'));
    expect(p.a.sendCounter, 1);
    await p.a.seal(utf8.encode('two'));
    expect(p.a.sendCounter, 2);
  });

  test('rejects a replayed frame', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('once'));
    await p.b.open(sealed);
    expect(() => p.b.open(sealed), throwsA(isA<ReplayError>()));
  });

  test('rejects an out-of-order lower counter', () async {
    final p = pair();
    final first = await p.a.seal(utf8.encode('1'));
    final second = await p.a.seal(utf8.encode('2'));
    await p.b.open(second);
    expect(() => p.b.open(first), throwsA(isA<ReplayError>()));
  });

  test('accepts a forward gap in counters', () async {
    final p = pair();
    await p.a.seal(utf8.encode('dropped'));
    final second = await p.a.seal(utf8.encode('arrived'));
    final opened = await p.b.open(second);
    expect(utf8.decode(opened), 'arrived');
    expect(p.b.lastAcceptedReceiveCounter, 1);
  });

  test('rejects a tampered mac', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('intact'));
    sealed[sealed.length - 1] ^= 0xFF;
    expect(() => p.b.open(sealed), throwsA(isA<DecryptionError>()));
  });

  test('rejects a tampered ciphertext', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('intact'));
    sealed[AeadSession.counterBytes] ^= 0xFF;
    expect(() => p.b.open(sealed), throwsA(isA<DecryptionError>()));
  });

  test('rejects a mismatched aad', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('bound'), aad: [1, 2, 3]);
    expect(() => p.b.open(sealed, aad: [9, 9, 9]),
        throwsA(isA<DecryptionError>()));
  });

  test('rejects a frame shorter than the header plus mac', () async {
    final p = pair();
    expect(() => p.b.open(Uint8List(10)), throwsA(isA<DecryptionError>()));
  });

  test('concurrent seals never reuse a counter', () async {
    final p = pair();
    final frames = await Future.wait([
      p.a.seal(utf8.encode('a')),
      p.a.seal(utf8.encode('b')),
    ]);
    final c0 = counterOf(frames[0]);
    final c1 = counterOf(frames[1]);
    expect(c0, isNot(c1), reason: 'concurrent seals reused a nonce');
    expect({c0, c1}, {0, 1});
    expect(p.a.sendCounter, 2);
  });

  test('concurrent opens of the same frame accept it exactly once', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('once only'));

    final outcomes = await Future.wait([
      p.b.open(sealed).then<Object?>((v) => v, onError: (Object e) => e),
      p.b.open(sealed).then<Object?>((v) => v, onError: (Object e) => e),
    ]);

    final accepted = outcomes.whereType<Uint8List>().toList();
    final replays = outcomes.whereType<ReplayError>().toList();
    expect(accepted, hasLength(1),
        reason: 'a replayed frame was accepted more than once');
    expect(replays, hasLength(1));
    expect(utf8.decode(accepted.single), 'once only');
    expect(p.b.lastAcceptedReceiveCounter, 0);
  });

  test('a failed decryption does not advance the accepted counter', () async {
    final p = pair();
    await p.a.seal(utf8.encode('zero'));
    final one = await p.a.seal(utf8.encode('one'));

    final tampered = Uint8List.fromList(one);
    tampered[AeadSession.counterBytes] ^= 0xFF;
    await expectLater(p.b.open(tampered), throwsA(isA<DecryptionError>()));
    expect(p.b.lastAcceptedReceiveCounter, -1);

    final opened = await p.b.open(one);
    expect(utf8.decode(opened), 'one');
    expect(p.b.lastAcceptedReceiveCounter, 1);
  });
}

/// Reads the 8-byte big-endian counter header from a sealed frame.
int counterOf(Uint8List sealed) =>
    ByteData.view(sealed.buffer, sealed.offsetInBytes).getUint64(0);
