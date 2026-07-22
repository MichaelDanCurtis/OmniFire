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
  final List<int> peerStaticPublicKey;
}

abstract interface class Handshake {
  Future<Uint8List> start();
  Future<Uint8List> confirmationFor(List<int> peerMessage);
  Future<HandshakeResult> complete(
      List<int> peerMessage, List<int> peerConfirmation);
}

/// OmniFi Session Handshake v1. See the plan's Task 4 for the normative
/// construction. Reviewed under R1.
class OmniFiHandshakeV1 implements Handshake {
  OmniFiHandshakeV1._({
    required this.staticKeys,
    required this.deviceId,
    required this.isInitiator,
    required this.peerStaticPublicKey,
    required this.psk,
  });

  factory OmniFiHandshakeV1.initiator({
    required StaticKeyPair staticKeys,
    required String deviceId,
    required List<int> peerStaticPublicKey,
    List<int> psk = const [],
  }) =>
      OmniFiHandshakeV1._(
        staticKeys: staticKeys,
        deviceId: deviceId,
        isInitiator: true,
        peerStaticPublicKey: peerStaticPublicKey,
        psk: psk,
      );

  factory OmniFiHandshakeV1.responder({
    required StaticKeyPair staticKeys,
    required String deviceId,
    required List<int> peerStaticPublicKey,
    List<int> psk = const [],
  }) =>
      OmniFiHandshakeV1._(
        staticKeys: staticKeys,
        deviceId: deviceId,
        isInitiator: false,
        peerStaticPublicKey: peerStaticPublicKey,
        psk: psk,
      );

  static final _x25519 = X25519();
  static final _hkdf =
      Hkdf(hmac: Hmac.sha256(), outputLength: 32);

  static const _confirmPlaintext = 'omnifi-confirm';

  final StaticKeyPair staticKeys;
  final String deviceId;
  final bool isInitiator;
  final List<int> peerStaticPublicKey;
  final List<int> psk;

  SimpleKeyPair? _ephemeral;
  Uint8List? _ownMessage;

  static Future<StaticKeyPair> generateStaticKeys() async {
    final kp = await _x25519.newKeyPair();
    return StaticKeyPair(
      publicKey: (await kp.extractPublicKey()).bytes,
      privateKey: await kp.extractPrivateKeyBytes(),
    );
  }

  @override
  Future<Uint8List> start() async {
    final kp = await _x25519.newKeyPair();
    _ephemeral = kp;
    final ePub = (await kp.extractPublicKey()).bytes;
    final message = cbor.encode(CborValue({
      'v': omnifiProtocolVersion,
      'id': deviceId,
      'e': CborBytes(ePub),
    }));
    _ownMessage = Uint8List.fromList(message);
    return _ownMessage!;
  }

  List<int> _transcript(List<int> peerMessage) {
    final own = _ownMessage;
    if (own == null) {
      throw const HandshakeError('start() must be called before completing');
    }
    return isInitiator ? [...own, ...peerMessage] : [...peerMessage, ...own];
  }

  static List<int> _peerEphemeral(List<int> peerMessage) {
    final Object? decoded;
    try {
      decoded = cbor.decode(peerMessage).toObject();
    } catch (_) {
      throw const HandshakeError('peer message is not valid CBOR');
    }
    if (decoded is! Map) {
      throw const HandshakeError('peer message is not a map');
    }
    final e = decoded['e'];
    if (e is! List<int> || e.length != 32) {
      throw const HandshakeError('peer ephemeral key is malformed');
    }
    return e;
  }

  Future<List<int>> _dh(List<int> privateKey, List<int> publicKey) async {
    final kp = await _x25519.newKeyPairFromSeed(privateKey);
    final shared = await _x25519.sharedSecretKey(
      keyPair: kp,
      remotePublicKey: SimplePublicKey(publicKey, type: KeyPairType.x25519),
    );
    return shared.extractBytes();
  }

  Future<({List<int> master, List<int> send, List<int> receive,
          List<int> transcript})>
      _derive(List<int> peerMessage) async {
    final ephemeral = _ephemeral;
    if (ephemeral == null) {
      throw const HandshakeError('start() must be called first');
    }
    final ePriv = await ephemeral.extractPrivateKeyBytes();
    final peerEPub = _peerEphemeral(peerMessage);
    final transcript = _transcript(peerMessage);

    final dhEe = await _dh(ePriv, peerEPub);
    final List<int> dhEs;
    final List<int> dhSe;
    if (isInitiator) {
      dhEs = await _dh(ePriv, peerStaticPublicKey);
      dhSe = await _dh(staticKeys.privateKey, peerEPub);
    } else {
      dhEs = await _dh(staticKeys.privateKey, peerEPub);
      dhSe = await _dh(ePriv, peerStaticPublicKey);
    }

    final master = await _hkdf.deriveKey(
      secretKey: SecretKey([...dhEe, ...dhEs, ...dhSe]),
      nonce: [...transcript, ...psk],
      info: utf8.encode('omnifi-session-v1'),
    );
    final masterBytes = await master.extractBytes();

    Future<List<int>> expand(String label) async {
      final k = await _hkdf.deriveKey(
        secretKey: SecretKey(masterBytes),
        nonce: const [],
        info: utf8.encode(label),
      );
      return k.extractBytes();
    }

    final i2r = await expand('i2r');
    final r2i = await expand('r2i');

    return (
      master: masterBytes,
      send: isInitiator ? i2r : r2i,
      receive: isInitiator ? r2i : i2r,
      transcript: transcript,
    );
  }

  @override
  Future<Uint8List> confirmationFor(List<int> peerMessage) async {
    final d = await _derive(peerMessage);
    final confirmSession =
        AeadSession(sendKey: d.send, receiveKey: d.receive);
    return confirmSession.seal(utf8.encode(_confirmPlaintext),
        aad: d.transcript);
  }

  @override
  Future<HandshakeResult> complete(
      List<int> peerMessage, List<int> peerConfirmation) async {
    final d = await _derive(peerMessage);
    final verifier =
        AeadSession(sendKey: d.send, receiveKey: d.receive);
    try {
      final opened =
          await verifier.open(peerConfirmation, aad: d.transcript);
      if (utf8.decode(opened) != _confirmPlaintext) {
        throw const HandshakeError('peer confirmation payload mismatch');
      }
    } on DecryptionError {
      throw const HandshakeError('peer confirmation failed to authenticate');
    }

    return HandshakeResult(
      session: AeadSession(sendKey: d.send, receiveKey: d.receive),
      transcript: d.transcript,
      master: d.master,
      peerStaticPublicKey: peerStaticPublicKey,
    );
  }
}
