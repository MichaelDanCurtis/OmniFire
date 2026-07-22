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

  test('rejects a tampered ciphertext', () async {
    final p = pair();
    final sealed = await p.a.seal(utf8.encode('intact'));
    sealed[sealed.length - 1] ^= 0xFF;
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
}
