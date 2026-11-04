import 'dart:async';
import 'dart:typed_data';

import '../crypto/aead_session.dart';
import '../crypto/handshake.dart';
import '../identity/device_identity.dart';
import '../identity/mesh.dart';
import '../transport/link.dart';

/// Raised when a session could not be established over a link. The link has
/// been closed by the time this is thrown: a peer that fails the handshake is
/// not who the roster says it is, or the link is broken, and either way the
/// link must not go on to become a session candidate.
class SessionEstablishmentError implements Exception {
  const SessionEstablishmentError(this.reason);
  final String reason;
  @override
  String toString() => 'SessionEstablishmentError: $reason';
}

/// Which side of a device pair opens the handshake.
///
/// Deterministic, never negotiated: the lexicographically smaller device id
/// initiates. Both sides compute the same answer from ids they already hold,
/// so there is no extra round trip and no tie to break — device ids are
/// 128-bit random, and a negotiation round would be one more place for two
/// implementations to disagree.
bool isInitiatorFor(String localDeviceId, String peerDeviceId) =>
    localDeviceId.compareTo(peerDeviceId) < 0;

/// Runs the OmniFi session handshake over a raw [Link], before any
/// [PeerSession] exists, and yields the [AeadSession] a session is built on.
///
/// This is the reconnect counterpart to pairing. Pairing establishes *who* a
/// peer is; this re-establishes an encrypted channel to a peer already known.
/// The difference is where authentication comes from: pairing has no expected
/// static key and leans on the invite's pre-shared key plus the user's SAS
/// comparison, while here both sides already hold each other's static key, so
/// the expectation is the peer's key **from the roster** and the pre-shared
/// key is empty. A device presenting a different static key fails the
/// handshake instead of being trusted on the strength of a device id.
///
/// Establishment runs **once per session, not once per link**. A [PeerSession]
/// is keyed to the device pair and migrates between links without
/// renegotiating crypto, so the caller establishes on the first link adopted
/// for a peer and reuses the result for every later link. Only a session that
/// has died — a decryption failure forces a fresh handshake rather than a
/// counter resync — is replaced.
class SessionEstablisher {
  const SessionEstablisher._();

  static Future<AeadSession> establish({
    required Link link,
    required DeviceIdentity identity,
    required PeerRecord peer,
    Duration timeout = const Duration(seconds: 10),
  }) async {
    try {
      return await _run(link: link, identity: identity, peer: peer)
          .timeout(timeout);
    } on SessionEstablishmentError {
      await _closeQuietly(link);
      rethrow;
    } on TimeoutException {
      // Closing is also what unblocks the abandoned _run: its buffered read
      // ends, it throws, and `Future.timeout` — which keeps an error handler
      // registered on the source future — absorbs that failure rather than
      // letting it surface as an unhandled async error.
      await _closeQuietly(link);
      throw SessionEstablishmentError(
          'the peer did not complete the handshake within $timeout');
    } on Object catch (e) {
      await _closeQuietly(link);
      throw SessionEstablishmentError('session establishment failed: $e');
    }
  }

  static Future<AeadSession> _run({
    required Link link,
    required DeviceIdentity identity,
    required PeerRecord peer,
  }) async {
    final isInitiator = isInitiatorFor(identity.deviceId, peer.deviceId);
    // `expectedPeerStaticPublicKey` is the roster's key, and the pre-shared
    // key is empty. Passing null here would compile and would silently drop
    // mutual authentication, leaving a reconnect trusting whatever static key
    // the far end chose to present.
    final handshake = isInitiator
        ? OmniFiHandshakeV1.initiator(
            staticKeys: identity.keys,
            deviceId: identity.deviceId,
            expectedPeerStaticPublicKey: peer.publicKey,
            psk: const [],
          )
        : OmniFiHandshakeV1.responder(
            staticKeys: identity.keys,
            deviceId: identity.deviceId,
            expectedPeerStaticPublicKey: peer.publicKey,
            psk: const [],
          );

    // One subscription for the whole exchange, armed before each send.
    // `link.inbound` is a broadcast stream: an event delivered while nothing
    // is listening is discarded, and because both sides run the same
    // symmetric crypto they send at nearly the same moment. Re-listening
    // between reads would drop the peer's frame and hang until the timeout
    // instead of failing cleanly. A StreamIterator listens once and buffers
    // while it is between reads. Same reason PairingFlow does this.
    final inbox = StreamIterator<Uint8List>(link.inbound);
    try {
      // Armed before the *first* suspension, not just before the first send:
      // a StreamIterator does not subscribe until moveNext() is called, so
      // arming it after `handshake.start()` leaves nothing listening across
      // that await. It is safe today only because X25519 key generation
      // resolves on the microtask queue; a platform-channel-backed provider
      // such as cryptography_flutter suspends for real, the peer's first
      // frame is dropped, and the exchange hangs to the timeout with no
      // diagnostic.
      final peerMessageArrived = inbox.moveNext();
      final ownMessage = await handshake.start();
      await link.send(ownMessage);
      if (!await peerMessageArrived) {
        throw const SessionEstablishmentError(
            'the link closed before the peer sent its handshake message');
      }
      final peerMessage = inbox.current;

      // Role assignment was computed from the roster's device id. A peer that
      // presents a different id computed the opposite role from the one we
      // did, so the transcript halves would be ordered differently on the two
      // sides and nothing would verify; refuse it here, where the reason is
      // legible, rather than as an opaque confirmation failure. The static
      // key check below is what actually authenticates.
      final claimedId = OmniFiHandshakeV1.deviceIdFromMessage(peerMessage);
      if (claimedId != peer.deviceId) {
        throw SessionEstablishmentError(
            'peer identified itself as $claimedId on a link dialed for '
            '${peer.deviceId}');
      }

      // Derives, and with it checks the presented static key against the
      // roster's. It throws before returning any bytes, so nothing is sent to
      // a peer that has already failed authentication.
      final ownConfirmation = await handshake.confirmationFor(peerMessage);
      final peerConfirmationArrived = inbox.moveNext();
      await link.send(ownConfirmation);
      if (!await peerConfirmationArrived) {
        throw const SessionEstablishmentError(
            'the link closed before the peer sent its key confirmation');
      }
      final peerConfirmation = inbox.current;

      final result = await handshake.complete(peerMessage, peerConfirmation);
      return result.session;
    } on HandshakeError catch (e) {
      throw SessionEstablishmentError('handshake failed: ${e.reason}');
    } on LinkClosedError catch (e) {
      // A send onto a link the peer has just torn down is the same event as a
      // read that ends. Surfacing the transport error raw would make callers
      // treat an ordinary reconnect race as an internal fault.
      throw SessionEstablishmentError('the link closed mid-handshake: $e');
    } finally {
      await inbox.cancel();
    }
  }

  /// Closes best-effort: a failed establishment must be reported as a failed
  /// establishment even if the transport also fails to tear down cleanly.
  static Future<void> _closeQuietly(Link link) async {
    try {
      await link.close();
    } on Object {
      // Ignored: see above.
    }
  }
}
