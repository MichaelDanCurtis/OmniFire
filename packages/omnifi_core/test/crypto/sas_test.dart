import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('wordlist has exactly 256 unique words', () {
    expect(omnifiWordlist.length, 256);
    expect(omnifiWordlist.toSet().length, 256);
  });

  test('wordlist entries are lowercase and 3-7 letters', () {
    for (final w in omnifiWordlist) {
      expect(w, matches(RegExp(r'^[a-z]{3,7}$')), reason: 'bad word: $w');
    }
  });

  test('derives the requested number of words', () async {
    final sas = await deriveSas(
      master: List<int>.filled(32, 3),
      initiatorStaticPublicKey: List<int>.filled(32, 1),
      responderStaticPublicKey: List<int>.filled(32, 2),
    );
    expect(sas.length, 5);
    for (final w in sas) {
      expect(omnifiWordlist, contains(w));
    }
  });

  test('is deterministic for the same inputs', () async {
    Future<List<String>> go() => deriveSas(
          master: List<int>.filled(32, 3),
          initiatorStaticPublicKey: List<int>.filled(32, 1),
          responderStaticPublicKey: List<int>.filled(32, 2),
        );
    expect(await go(), await go());
  });

  test('differs when the master secret differs', () async {
    final a = await deriveSas(
      master: List<int>.filled(32, 3),
      initiatorStaticPublicKey: List<int>.filled(32, 1),
      responderStaticPublicKey: List<int>.filled(32, 2),
    );
    final b = await deriveSas(
      master: List<int>.filled(32, 4),
      initiatorStaticPublicKey: List<int>.filled(32, 1),
      responderStaticPublicKey: List<int>.filled(32, 2),
    );
    expect(a, isNot(equals(b)));
  });

  test('differs when a static key differs (MITM detection)', () async {
    final honest = await deriveSas(
      master: List<int>.filled(32, 3),
      initiatorStaticPublicKey: List<int>.filled(32, 1),
      responderStaticPublicKey: List<int>.filled(32, 2),
    );
    final mitm = await deriveSas(
      master: List<int>.filled(32, 3),
      initiatorStaticPublicKey: List<int>.filled(32, 1),
      responderStaticPublicKey: List<int>.filled(32, 9),
    );
    expect(honest, isNot(equals(mitm)));
  });

  test('formats as space-separated words', () {
    expect(formatSas(['able', 'brisk', 'cedar']), 'able brisk cedar');
  });
}
