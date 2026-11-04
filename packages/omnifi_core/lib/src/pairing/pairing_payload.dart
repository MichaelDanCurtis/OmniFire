import 'dart:convert';
import 'dart:math';

import '../crypto/wordlist.dart';

class PairingError implements Exception {
  const PairingError(this.reason);
  final String reason;
  @override
  String toString() => 'PairingError: $reason';
}

class PairingInvite {
  PairingInvite({
    required this.meshId,
    required this.inviterPublicKey,
    required this.psk,
    this.relayHint,
  }) {
    if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(meshId)) {
      throw const PairingError('mesh id must be 32 lowercase hex characters');
    }
    if (inviterPublicKey.length != 32) {
      throw const PairingError('inviter public key must be 32 bytes');
    }
    if (psk.length != 32) {
      throw const PairingError('psk must be 32 bytes');
    }
    final hint = relayHint;
    if (hint != null) {
      if (hint.length > 256) {
        throw const PairingError('relay hint must be at most 256 characters');
      }
      final Uri hintUri;
      try {
        hintUri = Uri.parse(hint);
      } on FormatException {
        throw const PairingError('relay hint is not a parseable URI');
      }
      if (!hintUri.isAbsolute) {
        throw const PairingError('relay hint must be an absolute URI');
      }
      const allowedSchemes = {'http', 'https', 'ws', 'wss'};
      if (!allowedSchemes.contains(hintUri.scheme)) {
        throw const PairingError(
            'relay hint scheme must be one of http, https, ws, wss');
      }
      if (hintUri.host.isEmpty) {
        throw const PairingError('relay hint must have a non-empty host');
      }
    }
  }

  final String meshId;
  final List<int> inviterPublicKey;
  final List<int> psk;
  final String? relayHint;
}

final Random _rng = Random.secure();

PairingInvite generateInvite({
  required String meshId,
  required List<int> inviterPublicKey,
  String? relayHint,
}) {
  return PairingInvite(
    meshId: meshId,
    inviterPublicKey: inviterPublicKey,
    psk: [for (var i = 0; i < 32; i++) _rng.nextInt(256)],
    relayHint: relayHint,
  );
}

String encodeInviteUri(PairingInvite invite) {
  final params = <String, String>{
    'm': invite.meshId,
    'k': base64UrlEncode(invite.inviterPublicKey),
    'p': base64UrlEncode(invite.psk),
    if (invite.relayHint != null) 'r': invite.relayHint!,
  };
  final query = params.entries
      .map((e) =>
          '${e.key}=${Uri.encodeQueryComponent(e.value)}')
      .join('&');
  return 'omnifi://pair?$query';
}

PairingInvite decodeInviteUri(String uri) {
  final Uri parsed;
  try {
    parsed = Uri.parse(uri);
  } on FormatException {
    throw const PairingError('invite is not a parseable URI');
  }
  if (parsed.scheme != 'omnifi' || parsed.host != 'pair') {
    throw const PairingError('invite is not an omnifi://pair URI');
  }

  // Uri.parse does not validate percent-encoding: it is checked lazily the
  // first time queryParameters is read, and that single read eagerly
  // decodes every value in the query -- not just the one being accessed.
  // A malformed escape anywhere in the query (most easily reached via the
  // unconstrained relay-hint field) must not escape as a raw
  // FormatException, so the access is guarded here.
  final Map<String, String> queryParameters;
  try {
    queryParameters = parsed.queryParameters;
  } on FormatException {
    throw const PairingError('invite query could not be decoded');
  }

  final meshId = queryParameters['m'];
  final key = queryParameters['k'];
  final psk = queryParameters['p'];
  if (meshId == null || key == null || psk == null) {
    throw const PairingError('invite is missing a required parameter');
  }

  List<int> decode(String value, String label) {
    try {
      return base64Url.decode(base64Url.normalize(value));
    } on FormatException {
      throw PairingError('$label is not valid base64url');
    }
  }

  return PairingInvite(
    meshId: meshId,
    inviterPublicKey: decode(key, 'public key'),
    psk: decode(psk, 'psk'),
    // Read from the guarded local, not `parsed.queryParameters` again. A second
    // access is inert only because `Uri.queryParameters` is pure and
    // deterministic, so it would rethrow what the guard above already caught —
    // safety by accident, which a refactor could remove without warning.
    relayHint: queryParameters['r'],
  );
}

/// Eight words derived from the PSK. This is a *lookup code*, not a
/// self-contained invite: 64 bits cannot carry a 32-byte PSK plus a
/// 32-byte key. The inviting device serves the full payload against it.
List<String> encodeInviteWords(PairingInvite invite) =>
    [for (var i = 0; i < 8; i++) omnifiWordlist[invite.psk[i]]];

PairingInvite decodeInviteWords(
  List<String> words, {
  required PairingInvite Function(String code) lookup,
}) {
  if (words.length != 8) {
    throw const PairingError('pairing phrase must be exactly 8 words');
  }
  for (final w in words) {
    if (!omnifiWordlist.contains(w)) {
      throw PairingError('unknown pairing word: $w');
    }
  }
  return lookup(words.join('-'));
}
