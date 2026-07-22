import 'dart:convert';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:cryptography/cryptography.dart';

import '../version.dart';
import 'aead_session.dart';

class HandshakeError implements Exception {
  const HandshakeError(this.reason);
  final String reason;
  @override
  String toString() => 'HandshakeError: $reason';
}

class StaticKeyPair {
  const StaticKeyPair({required this.publicKey, required this.privateKey});
  final List<int> publicKey;
  final List<int> privateKey;
}

class HandshakeResult {
  const HandshakeResult({
    required this.session,
    required this.transcript,
    required this.master,
    required this.peerStaticPublicKey,
  });
  final AeadSession session;
  final List<int> transcript;
  final List<int> master;

  /// The peer's static public key as *learned from the peer's handshake
  /// message*, not an echo of a constructor argument. When
  /// [OmniFiHandshakeV1.expectedPeerStaticPublicKey] was supplied it has been
  /// checked against this value.
  final List<int> peerStaticPublicKey;
}

/// A peer handshake message, after structural validation.
typedef _PeerMessage = ({
  int version,
  String id,
  List<int> ephemeralPublicKey,
  List<int> staticPublicKey,
});

typedef _Derived = ({
  List<int> master,
  List<int> send,
  List<int> receive,
  List<int> sendConfirm,
  List<int> receiveConfirm,
  List<int> transcript,
  List<int> peerStaticPublicKey,
});

abstract interface class Handshake {
  Future<Uint8List> start();
  Future<Uint8List> confirmationFor(List<int> peerMessage);
  Future<HandshakeResult> complete(
      List<int> peerMessage, List<int> peerConfirmation);
}

/// OmniFi Session Handshake v1. See the plan's Task 4 for the normative
/// construction. Reviewed under R1; amended after review.
///
/// Wire message: `CBOR{v, id, e, s}` where `e` is the 32-byte ephemeral public
/// key and `s` is the 32-byte static public key of the sender. All three
/// Diffie-Hellman values are computed against the static key *learned* from the
/// peer's message; [expectedPeerStaticPublicKey], when supplied, is compared
/// against that learned key and a mismatch aborts the handshake. That
/// comparison is what makes a session to an already-paired device mutually
/// authenticated. During pairing the expectation is absent and authentication
/// rests on the pre-shared key mixed into the HKDF salt plus an out-of-band
/// short-authentication-string comparison.
///
/// A `Handshake` instance is single-use: [start] throws if called twice.
class OmniFiHandshakeV1 implements Handshake {
  OmniFiHandshakeV1._({
    required this.staticKeys,
    required this.deviceId,
    required this.isInitiator,
    required this.expectedPeerStaticPublicKey,
    required this.psk,
  }) {
    // A Handshake with neither an expected peer static key nor a pre-shared
    // key authenticates nobody: it neither checks the peer against a known
    // identity (the post-pairing case) nor mixes in a shared secret (the
    // pairing case). That combination is never legitimate, so refuse it here
    // rather than silently producing a working-but-unauthenticated session.
    if (expectedPeerStaticPublicKey == null && psk.isEmpty) {
      throw const HandshakeError(
          'no authentication mechanism configured: expectedPeerStaticPublicKey '
          'is null and psk is empty; supply a known peer static key '
          '(post-pairing) or a non-empty psk (pairing), not neither');
    }
  }

  factory OmniFiHandshakeV1.initiator({
    required StaticKeyPair staticKeys,
    required String deviceId,
    required List<int>? expectedPeerStaticPublicKey,
    List<int> psk = const [],
  }) =>
      OmniFiHandshakeV1._(
        staticKeys: staticKeys,
        deviceId: deviceId,
        isInitiator: true,
        expectedPeerStaticPublicKey: expectedPeerStaticPublicKey,
        psk: psk,
      );

  factory OmniFiHandshakeV1.responder({
    required StaticKeyPair staticKeys,
    required String deviceId,
    required List<int>? expectedPeerStaticPublicKey,
    List<int> psk = const [],
  }) =>
      OmniFiHandshakeV1._(
        staticKeys: staticKeys,
        deviceId: deviceId,
        isInitiator: false,
        expectedPeerStaticPublicKey: expectedPeerStaticPublicKey,
        psk: psk,
      );

  static final _x25519 = X25519();
  static final _hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  static const _confirmPlaintext = 'omnifi-confirm';
  static const _keyBytes = 32;

  final StaticKeyPair staticKeys;
  final String deviceId;
  final bool isInitiator;

  /// The peer's static public key as already known from the roster, or null
  /// during pairing when it is not yet known.
  final List<int>? expectedPeerStaticPublicKey;
  final List<int> psk;

  /// Set synchronously by [start] so that a second call — including a
  /// concurrent one that has not yet reached its first suspension point —
  /// fails instead of minting a second ephemeral key.
  bool _started = false;

  SimpleKeyPair? _ephemeral;
  Uint8List? _ownMessage;

  /// Memoised [_derive] output, together with the exact peer message it was
  /// computed from. Deriving is three X25519 operations; `confirmationFor` and
  /// `complete` would otherwise each pay for them.
  _Derived? _derived;
  Uint8List? _derivedFrom;

  static Future<StaticKeyPair> generateStaticKeys() async {
    final kp = await _x25519.newKeyPair();
    return StaticKeyPair(
      publicKey: (await kp.extractPublicKey()).bytes,
      privateKey: await kp.extractPrivateKeyBytes(),
    );
  }

  /// Extracts the sender's device ID from a handshake message.
  static String deviceIdFromMessage(List<int> message) {
    final Object? decoded;
    try {
      decoded = cbor.decode(message).toObject();
    } catch (_) {
      throw const HandshakeError('handshake message is not valid CBOR');
    }
    if (decoded is! Map) {
      throw const HandshakeError('handshake message is not a map');
    }
    final id = decoded['id'];
    if (id is! String || id.isEmpty) {
      throw const HandshakeError('handshake message has no device id');
    }
    return id;
  }

  @override
  Future<Uint8List> start() async {
    if (_started) {
      throw const HandshakeError(
          'start() may only be called once; a Handshake is single-use');
    }
    _started = true;

    final kp = await _x25519.newKeyPair();
    final ePub = (await kp.extractPublicKey()).bytes;
    final message = Uint8List.fromList(cbor.encode(CborValue({
      'v': omnifiProtocolVersion,
      'id': deviceId,
      'e': CborBytes(ePub),
      's': CborBytes(staticKeys.publicKey),
    })));

    // Both fields are published together, with no suspension point between
    // the assignments and the return of the local. Nothing observes a
    // half-initialised instance and the returned bytes are never re-read from
    // a field that another task could have overwritten.
    _ephemeral = kp;
    _ownMessage = message;
    return message;
  }

  List<int> _transcript(List<int> ownMessage, List<int> peerMessage) =>
      isInitiator
          ? [...ownMessage, ...peerMessage]
          : [...peerMessage, ...ownMessage];

  static _PeerMessage _decodePeerMessage(List<int> peerMessage) {
    final Object? decoded;
    try {
      decoded = cbor.decode(peerMessage).toObject();
    } catch (_) {
      throw const HandshakeError('peer message is not valid CBOR');
    }
    if (decoded is! Map) {
      throw const HandshakeError('peer message is not a map');
    }

    final v = decoded['v'];
    if (v is! int || v != omnifiProtocolVersion) {
      throw HandshakeError(
          'peer protocol version $v is not $omnifiProtocolVersion');
    }

    final id = decoded['id'];
    if (id is! String || id.isEmpty) {
      throw const HandshakeError('peer device id is missing or not a string');
    }

    final e = decoded['e'];
    if (e is! List<int> || e.length != _keyBytes) {
      throw const HandshakeError('peer ephemeral key is malformed');
    }

    final s = decoded['s'];
    if (s is! List<int> || s.length != _keyBytes) {
      throw const HandshakeError('peer static key is malformed');
    }

    return (
      version: v,
      id: id,
      ephemeralPublicKey: e,
      staticPublicKey: s,
    );
  }

  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  Future<List<int>> _dh(List<int> privateKey, List<int> publicKey) async {
    final kp = await _x25519.newKeyPairFromSeed(privateKey);
    final shared = await _x25519.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: SimplePublicKey(publicKey, type: KeyPairType.x25519),
    );
    return shared.extractBytes();
  }

  Future<_Derived> _derive(List<int> peerMessage) async {
    // Read every piece of instance state into a local exactly once, before the
    // first suspension point. Re-reading a field after an await could pair an
    // ephemeral key with a transcript built from a different message.
    final ephemeral = _ephemeral;
    final ownMessage = _ownMessage;
    if (ephemeral == null || ownMessage == null) {
      throw const HandshakeError('start() must be called first');
    }

    final cached = _derived;
    final cachedFrom = _derivedFrom;
    final peer = Uint8List.fromList(peerMessage);
    if (cached != null && cachedFrom != null) {
      if (!_constantTimeEquals(cachedFrom, peer)) {
        throw const HandshakeError(
            'this Handshake was already derived against a different peer '
            'message; one Handshake serves exactly one peer exchange');
      }
      return cached;
    }

    final decoded = _decodePeerMessage(peer);
    final peerStatic = decoded.staticPublicKey;
    final expected = expectedPeerStaticPublicKey;
    if (expected != null && !_constantTimeEquals(expected, peerStatic)) {
      throw const HandshakeError(
          'peer static public key does not match the expected static key '
          'for this device');
    }

    final ePriv = await ephemeral.extractPrivateKeyBytes();
    final peerEPub = decoded.ephemeralPublicKey;
    final transcript = _transcript(ownMessage, peer);

    final dhEe = await _dh(ePriv, peerEPub);
    final List<int> dhEs;
    final List<int> dhSe;
    if (isInitiator) {
      dhEs = await _dh(ePriv, peerStatic);
      dhSe = await _dh(staticKeys.privateKey, peerEPub);
    } else {
      dhEs = await _dh(staticKeys.privateKey, peerEPub);
      dhSe = await _dh(ePriv, peerStatic);
    }

    final master = await _hkdf.deriveKey(
      secretKey: SecretKey([...dhEe, ...dhEs, ...dhSe]),
      nonce: [...transcript, ...psk],
      info: utf8.encode('omnifi-session-v1'),
    );
    final masterBytes = await master.extractBytes();

    // `package:cryptography`'s Hkdf.deriveKey is full HKDF Extract-then-Expand
    // (RFC 5869), not the bare HKDF-Expand the design doc's normative text
    // describes — passing `nonce: const []` selects an empty salt for
    // Extract, it does not skip Extract. This is deliberate and does not
    // weaken anything: domain separation between the four keys derived here
    // comes entirely from the four distinct `info` labels, and an empty salt
    // is a valid HKDF salt (RFC 5869 treats a missing salt as a zero string).
    // Do not "fix" this to a literal HKDF-Expand-only call — that would
    // change every derived key and break interop with anything that already
    // speaks this wire format.
    Future<List<int>> expand(String label) async {
      final k = await _hkdf.deriveKey(
        secretKey: SecretKey(masterBytes),
        nonce: const [],
        info: utf8.encode(label),
      );
      return k.extractBytes();
    }

    // Four keys, not two. The confirmation is sealed at counter 0, and the
    // AeadSession returned by complete() also starts its send counter at 0.
    // Sharing a key between them would reuse an (key, nonce) pair under
    // ChaCha20-Poly1305: because the confirmation plaintext is the public
    // constant `omnifi-confirm`, an observer recovers the counter-0 keystream
    // and strips the first 14 bytes off the first data frame, and the
    // RFC 8439 Poly1305 one-time key (block counter 0, same nonce) leaks with
    // it, permitting forgery. Differing AAD does not help: neither the
    // keystream nor the Poly1305 key depends on AAD. Separate confirmation
    // keys make the collision impossible.
    final i2r = await expand('i2r');
    final r2i = await expand('r2i');
    final i2rConfirm = await expand('i2r-confirm');
    final r2iConfirm = await expand('r2i-confirm');

    final result = (
      master: masterBytes,
      send: isInitiator ? i2r : r2i,
      receive: isInitiator ? r2i : i2r,
      sendConfirm: isInitiator ? i2rConfirm : r2iConfirm,
      receiveConfirm: isInitiator ? r2iConfirm : i2rConfirm,
      transcript: transcript,
      peerStaticPublicKey: peerStatic,
    );
    _derived = result;
    _derivedFrom = peer;
    return result;
  }

  /// The short-authentication-string inputs — the master secret and the
  /// peer's static public key *as learned from* [peerMessage] — available
  /// before the peer's key confirmation has been verified.
  ///
  /// Pairing needs this. When the pre-shared key is wrong — a mistyped code,
  /// or a man-in-the-middle who relayed a different invite — the two sides
  /// derive different masters, so the key confirmation *cannot* verify. The
  /// honest failure mode there is two screens showing different words, which
  /// is exactly what the user is asked to catch; failing with an opaque
  /// exception before the words are ever shown would hide the attack rather
  /// than surface it.
  ///
  /// No key material and no session is returned here: [complete] remains the
  /// only way to obtain a key-confirmed [AeadSession], and a caller that
  /// wants to send data must still call it and honour its failure.
  Future<({List<int> master, List<int> peerStaticPublicKey})> sasInputsFor(
      List<int> peerMessage) async {
    final d = await _derive(peerMessage);
    return (master: d.master, peerStaticPublicKey: d.peerStaticPublicKey);
  }

  @override
  Future<Uint8List> confirmationFor(List<int> peerMessage) async {
    final d = await _derive(peerMessage);
    // Confirmation keys only. This session object never seals a data frame.
    final confirmSession = AeadSession(
        sendKey: d.sendConfirm, receiveKey: d.receiveConfirm);
    return confirmSession.seal(utf8.encode(_confirmPlaintext),
        aad: d.transcript);
  }

  @override
  Future<HandshakeResult> complete(
      List<int> peerMessage, List<int> peerConfirmation) async {
    final d = await _derive(peerMessage);
    final verifier = AeadSession(
        sendKey: d.sendConfirm, receiveKey: d.receiveConfirm);
    try {
      final opened = await verifier.open(peerConfirmation, aad: d.transcript);
      if (utf8.decode(opened) != _confirmPlaintext) {
        throw const HandshakeError('peer confirmation payload mismatch');
      }
    } on DecryptionError {
      throw const HandshakeError('peer confirmation failed to authenticate');
    }

    return HandshakeResult(
      // Data keys only, on a session that has never been used to seal or open
      // a confirmation, so its counters genuinely start at zero.
      session: AeadSession(sendKey: d.send, receiveKey: d.receive),
      transcript: d.transcript,
      master: d.master,
      peerStaticPublicKey: d.peerStaticPublicKey,
    );
  }
}
