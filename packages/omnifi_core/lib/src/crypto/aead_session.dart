import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Thrown when a frame's counter does not strictly advance.
class ReplayError implements Exception {
  const ReplayError(this.counter, this.lastAccepted);
  final int counter;
  final int lastAccepted;
  @override
  String toString() =>
      'ReplayError: counter $counter did not advance past $lastAccepted';
}

/// Thrown when a frame fails authentication or is structurally invalid.
class DecryptionError implements Exception {
  const DecryptionError(this.reason);
  final String reason;
  @override
  String toString() => 'DecryptionError: $reason';
}

/// One direction-pair of an established session.
///
/// Sealed layout: [8-byte BE counter][ciphertext][16-byte MAC].
/// The nonce is the counter, left-padded with four zero bytes to 12.
class AeadSession {
  AeadSession({required List<int> sendKey, required List<int> receiveKey})
      : _sendKey = SecretKey(List<int>.unmodifiable(sendKey)),
        _receiveKey = SecretKey(List<int>.unmodifiable(receiveKey)) {
    if (sendKey.length != 32 || receiveKey.length != 32) {
      throw ArgumentError('session keys must be 32 bytes');
    }
  }

  static const int counterBytes = 8;
  static const int macBytes = 16;
  static const int _nonceBytes = 12;

  final _algorithm = Chacha20.poly1305Aead();
  final SecretKey _sendKey;
  final SecretKey _receiveKey;

  int _sendCounter = 0;
  int _lastAcceptedReceiveCounter = -1;

  int get sendCounter => _sendCounter;
  int get lastAcceptedReceiveCounter => _lastAcceptedReceiveCounter;

  static Uint8List _nonceFor(int counter) {
    final nonce = Uint8List(_nonceBytes);
    ByteData.view(nonce.buffer).setUint64(_nonceBytes - counterBytes, counter);
    return nonce;
  }

  Future<Uint8List> seal(List<int> plaintext,
      {List<int> aad = const []}) async {
    // Reserve the counter synchronously, before the first suspension point.
    // Reading it and incrementing after the await would let two concurrent
    // seals encrypt under an identical nonce, which is fatal for
    // ChaCha20-Poly1305. `_sendCounter++` contains no await, so on a
    // single-threaded isolate the reservation is atomic w.r.t. the event loop.
    final counter = _sendCounter++;
    final box = await _algorithm.encrypt(
      plaintext,
      secretKey: _sendKey,
      nonce: _nonceFor(counter),
      aad: aad,
    );

    final out = Uint8List(counterBytes + box.cipherText.length + macBytes);
    ByteData.view(out.buffer).setUint64(0, counter);
    out.setRange(counterBytes, counterBytes + box.cipherText.length,
        box.cipherText);
    out.setRange(counterBytes + box.cipherText.length, out.length,
        box.mac.bytes);
    return out;
  }

  Future<Uint8List> open(List<int> sealed,
      {List<int> aad = const []}) async {
    if (sealed.length < counterBytes + macBytes) {
      throw const DecryptionError('frame shorter than header plus mac');
    }
    final bytes = Uint8List.fromList(sealed);
    final counter = ByteData.view(bytes.buffer, bytes.offsetInBytes)
        .getUint64(0);

    // Cheap fast path: reject an obvious replay before paying for decryption.
    if (counter <= _lastAcceptedReceiveCounter) {
      throw ReplayError(counter, _lastAcceptedReceiveCounter);
    }

    final cipherText =
        bytes.sublist(counterBytes, bytes.length - macBytes);
    final mac = Mac(bytes.sublist(bytes.length - macBytes));

    final List<int> plaintext;
    try {
      plaintext = await _algorithm.decrypt(
        SecretBox(cipherText, nonce: _nonceFor(counter), mac: mac),
        secretKey: _receiveKey,
        aad: aad,
      );
    } on SecretBoxAuthenticationError {
      throw const DecryptionError('authentication failed');
    }

    // Re-check after the suspension: a concurrent open() of the same frame
    // may have committed while we were awaiting decryption. Committing only
    // after successful authentication is what stops an unauthenticated
    // attacker from advancing the window, so the guard has to be repeated
    // here rather than moved earlier.
    if (counter <= _lastAcceptedReceiveCounter) {
      throw ReplayError(counter, _lastAcceptedReceiveCounter);
    }

    _lastAcceptedReceiveCounter = counter;
    return Uint8List.fromList(plaintext);
  }
}
