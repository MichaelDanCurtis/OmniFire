import 'dart:convert';

import 'package:cryptography/cryptography.dart';

import 'wordlist.dart';

final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

/// Derives a human-verifiable short authentication string.
///
/// Bound to both static public keys so that a man-in-the-middle, who
/// necessarily presents a different key to each side, produces a
/// different SAS on each screen.
Future<List<String>> deriveSas({
  required List<int> master,
  required List<int> initiatorStaticPublicKey,
  required List<int> responderStaticPublicKey,
  int words = 5,
}) async {
  if (words < 1 || words > 32) {
    throw ArgumentError.value(words, 'words', 'must be between 1 and 32');
  }
  final key = await _hkdf.deriveKey(
    secretKey: SecretKey(master),
    nonce: [...initiatorStaticPublicKey, ...responderStaticPublicKey],
    info: utf8.encode('omnifi-sas-v1'),
  );
  final bytes = await key.extractBytes();
  return [for (var i = 0; i < words; i++) omnifiWordlist[bytes[i]]];
}

String formatSas(List<String> words) => words.join(' ');
