import 'dart:async';
import 'dart:typed_data';

import '../crypto/aead_session.dart';
import '../crypto/handshake.dart';
import '../crypto/sas.dart';
import '../identity/device_identity.dart';
import '../identity/mesh.dart';
import '../transport/link.dart';
import 'pairing_payload.dart';

class PairingRejectedError implements Exception {
  const PairingRejectedError(this.reason);
  final String reason;
  @override
  String toString() => 'PairingRejectedError: $reason';
}

class PairingOutcome {
  const PairingOutcome({
    required this.peer,
    required this.session,
    required this.meshId,
  });
  final PeerRecord peer;
  final AeadSession session;
  final String meshId;
}

/// A completed handshake awaiting the user's SAS comparison.
class PairingSasPending {
  const PairingSasPending({required this.sas, required this.confirm});
  final List<String> sas;
  final Future<PairingOutcome> Function(bool userConfirmed) confirm;
}

class PairingFlow {
  /// Runs the inviting side. The inviter does not yet know the joiner's
  /// static key, so the PSK from the invite carries the authentication.
  static Future<PairingSasPending> invite({
    required DeviceIdentity identity,
    required Mesh mesh,
    required PairingInvite invite,
    required Link link,
  }) =>
      _run(
        identity: identity,
        invite: invite,
        link: link,
        meshId: mesh.meshId,
        isInitiator: true,
      );

  /// Runs the joining side, using the invite scanned from the QR code.
  static Future<PairingSasPending> join({
    required DeviceIdentity identity,
    required PairingInvite invite,
    required Link link,
  }) =>
      _run(
        identity: identity,
        invite: invite,
        link: link,
        meshId: invite.meshId,
        isInitiator: false,
      );

  static Future<PairingSasPending> _run({
    required DeviceIdentity identity,
    required PairingInvite invite,
    required Link link,
    required String meshId,
    required bool isInitiator,
  }) async {
    // Neither side knows the other's static key yet — that is what pairing
    // establishes — so `expectedPeerStaticPublicKey` is null and each side
    // LEARNS the peer's key from the handshake message. Authentication comes
    // from the PSK in the QR invite (mixed into the HKDF salt) plus the SAS
    // the user compares below. A mismatched PSK changes the master secret,
    // which changes the SAS, which the user sees.
    final handshake = isInitiator
        ? OmniFiHandshakeV1.initiator(
            staticKeys: identity.keys,
            deviceId: identity.deviceId,
            expectedPeerStaticPublicKey: null,
            psk: invite.psk,
          )
        : OmniFiHandshakeV1.responder(
            staticKeys: identity.keys,
            deviceId: identity.deviceId,
            expectedPeerStaticPublicKey: null,
            psk: invite.psk,
          );

    // One subscription for the whole exchange. Re-listening to `link.inbound`
    // between the two receives would drop any frame the peer sent while we
    // were not listening: it is a broadcast stream, so an event with no
    // current listener is simply discarded, and both sides run the same
    // symmetric crypto and so send at nearly the same moment. A
    // StreamIterator listens once and buffers while it is between reads.
    final inbox = StreamIterator<Uint8List>(link.inbound);
    try {
      final ownMessage = await handshake.start();
      // Started before the send so the peer's reply cannot outrun the listen.
      final peerMessageArrived = inbox.moveNext();
      await link.send(ownMessage);
      if (!await peerMessageArrived) {
        throw const PairingRejectedError(
            'the link closed before the peer sent its handshake message');
      }
      final peerMessage = inbox.current;

      // The SAS is derived from the master *before* the peer's key
      // confirmation is verified, and deliberately so. A wrong PSK gives the
      // two sides different masters, so the confirmation can never verify;
      // aborting there would deny the user the one signal — two screens of
      // different words — that tells them a code was mistyped or a
      // man-in-the-middle is relaying the pairing. The confirmation failure
      // is not swallowed: it is carried to `confirm` below, so no session and
      // no roster entry can be produced from an unconfirmed handshake.
      final sasInputs = await handshake.sasInputsFor(peerMessage);
      final peerStaticPublicKey = sasInputs.peerStaticPublicKey;

      // Canonical ROLE order, not "mine first": the SAS is a function of the
      // ordered pair of static keys, so the two devices would show different
      // words for an honest pairing if each put its own key first.
      final sas = await deriveSas(
        master: sasInputs.master,
        initiatorStaticPublicKey:
            isInitiator ? identity.keys.publicKey : peerStaticPublicKey,
        responderStaticPublicKey:
            isInitiator ? peerStaticPublicKey : identity.keys.publicKey,
      );

      final ownConfirmation = await handshake.confirmationFor(peerMessage);
      final peerConfirmationArrived = inbox.moveNext();
      await link.send(ownConfirmation);
      if (!await peerConfirmationArrived) {
        throw const PairingRejectedError(
            'the link closed before the peer sent its key confirmation');
      }
      final peerConfirmation = inbox.current;

      HandshakeResult? result;
      String? confirmationFailure;
      try {
        result = await handshake.complete(peerMessage, peerConfirmation);
      } on HandshakeError catch (e) {
        confirmationFailure = e.reason;
      }

      final peerDeviceId = _peerDeviceIdFrom(peerMessage);

      return PairingSasPending(
        sas: sas,
        confirm: (userConfirmed) async {
          if (!userConfirmed) {
            throw const PairingRejectedError(
                'user reported the authentication words did not match');
          }
          final completed = result;
          if (completed == null) {
            throw PairingRejectedError(
                'handshake failed: ${confirmationFailure ?? 'unknown'}');
          }
          return PairingOutcome(
            peer: PeerRecord(
              deviceId: peerDeviceId,
              publicKey: completed.peerStaticPublicKey,
              displayName: peerDeviceId.substring(0, 8),
              addedAtMs: DateTime.now().millisecondsSinceEpoch,
            ),
            session: completed.session,
            meshId: meshId,
          );
        },
      );
    } finally {
      await inbox.cancel();
    }
  }

  static String _peerDeviceIdFrom(Uint8List peerMessage) {
    // The handshake message is CBOR {v, id, e}; reuse the same decode path
    // the handshake uses so a malformed message fails identically.
    return OmniFiHandshakeV1.deviceIdFromMessage(peerMessage);
  }
}
