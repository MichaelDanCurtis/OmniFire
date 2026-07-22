import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

PairingInvite sample() => PairingInvite(
      meshId: 'a' * 32,
      inviterPublicKey: List<int>.filled(32, 3),
      psk: List<int>.filled(32, 9),
      relayHint: 'wss://relay.example.com',
    );

void main() {
  test('generates an invite with a fresh 32-byte psk', () {
    final a = generateInvite(
        meshId: 'a' * 32, inviterPublicKey: List<int>.filled(32, 1));
    final b = generateInvite(
        meshId: 'a' * 32, inviterPublicKey: List<int>.filled(32, 1));
    expect(a.psk.length, 32);
    expect(a.psk, isNot(equals(b.psk)));
  });

  test('uri round-trips every field', () {
    final back = decodeInviteUri(encodeInviteUri(sample()));
    expect(back.meshId, 'a' * 32);
    expect(back.inviterPublicKey, List<int>.filled(32, 3));
    expect(back.psk, List<int>.filled(32, 9));
    expect(back.relayHint, 'wss://relay.example.com');
  });

  test('uri round-trips without a relay hint', () {
    final invite = PairingInvite(
      meshId: 'b' * 32,
      inviterPublicKey: List<int>.filled(32, 4),
      psk: List<int>.filled(32, 5),
    );
    expect(decodeInviteUri(encodeInviteUri(invite)).relayHint, isNull);
  });

  test('uri uses the omnifi pair scheme', () {
    expect(encodeInviteUri(sample()), startsWith('omnifi://pair?'));
  });

  test('rejects a wrong scheme', () {
    expect(() => decodeInviteUri('https://example.com/pair?m=x'),
        throwsA(isA<PairingError>()));
  });

  test('rejects a missing mesh id', () {
    expect(() => decodeInviteUri('omnifi://pair?k=AAAA&p=AAAA'),
        throwsA(isA<PairingError>()));
  });

  test('rejects a malformed mesh id', () {
    expect(
      () => decodeInviteUri('omnifi://pair?m=NOTHEX&k=AAAA&p=AAAA'),
      throwsA(isA<PairingError>()),
    );
  });

  test('rejects a wrong-length public key', () {
    final bad = encodeInviteUri(sample()).replaceAll(
        RegExp(r'k=[^&]*'), 'k=AAAA');
    expect(() => decodeInviteUri(bad), throwsA(isA<PairingError>()));
  });

  test('rejects unparseable text', () {
    expect(() => decodeInviteUri('not a uri at all %%%'),
        throwsA(isA<PairingError>()));
  });

  test('word code is 8 words from the wordlist', () {
    final words = encodeInviteWords(sample());
    expect(words.length, 8);
    for (final w in words) {
      expect(omnifiWordlist, contains(w));
    }
  });

  test('word code is deterministic for the same psk', () {
    expect(encodeInviteWords(sample()), encodeInviteWords(sample()));
  });

  test('word code differs for a different psk', () {
    final other = PairingInvite(
      meshId: 'a' * 32,
      inviterPublicKey: List<int>.filled(32, 3),
      psk: List<int>.filled(32, 10),
    );
    expect(encodeInviteWords(other), isNot(encodeInviteWords(sample())));
  });

  test('word decode resolves through the lookup callback', () {
    final invite = sample();
    final words = encodeInviteWords(invite);
    final resolved = decodeInviteWords(
      words,
      lookup: (code) {
        expect(code, words.join('-'));
        return invite;
      },
    );
    expect(resolved.meshId, invite.meshId);
  });

  test('word decode rejects a word outside the list', () {
    expect(
      () => decodeInviteWords(
        ['able', 'brisk', 'cedar', 'delta', 'eagle', 'fable', 'ghost',
          'zzzzzz'],
        lookup: (_) => sample(),
      ),
      throwsA(isA<PairingError>()),
    );
  });

  test('word decode rejects the wrong word count', () {
    expect(
      () => decodeInviteWords(['able', 'brisk'], lookup: (_) => sample()),
      throwsA(isA<PairingError>()),
    );
  });
}
