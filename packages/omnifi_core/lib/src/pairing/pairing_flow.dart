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
            'the peer aborted the pairing: the link closed before it sent '
            'its handshake message');
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
            'the peer aborted the pairing: the link closed before it sent '
            'its key confirmation');
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
            // Declining tears down the channel. On a direct link between the
            // two honest parties, or against an attacker relaying a single
            // channel, this closes the pairing outright: there is nothing
            // left for the other side to confirm against. It does NOT
            // generalize to a real man-in-the-middle running two separate
            // channels (this device <-> attacker <-> peer): closing our
            // A<->M leg cannot close the attacker's M<->B leg, and the
            // attacker is free to withhold whatever signal it likes from B
            // regardless of what we do here. Nor can it help at all once the
            // peer has already run `confirm(true)` to completion -- that
            // side is done, and revoking it would need a revocation frame,
            // which the no-new-wire-frame constraint for this exchange
            // deliberately forbids. This is still the right and only thing
            // this layer can do: it needs no wire message -- and
            // deliberately uses none, since a decline frame sent on this
            // raw, pre-session link would be unauthenticated and so
            // forgeable by the very attacker it is meant to stop. A closed
            // link cannot be forged, only withheld, and withholding it is
            // what an attacker already has to work with.
            //
            // Closing is best-effort: a decline must be reported as a
            // decline even if the transport fails to close cleanly, so a
            // thrown LinkClosedError (or anything else) from close() here
            // must not escape in place of PairingRejectedError.
            try {
              await link.close();
            } on Object {
              // Ignored: see above.
            }
            throw const PairingRejectedError(
                'user reported the authentication words did not match');
          }
          if (link.state != LinkState.connected) {
            // The peer went away between the handshake and this confirmation.
            // Most likely it was the peer's user who declined; either way the
            // channel this pairing was negotiated over no longer exists, so
            // there is nothing to confirm.
            throw const PairingRejectedError(
                'the peer aborted the pairing: the link closed before this '
                'side confirmed');
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
    } on LinkClosedError catch (e) {
      // A send that lands on a link the peer has just torn down is the same
      // event as a read that ends: the pairing was abandoned. Surfacing the
      // transport error raw would make callers, and the UI above them, treat
      // an ordinary decline as an internal fault.
      throw PairingRejectedError('the pairing link closed mid-exchange: $e');
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
