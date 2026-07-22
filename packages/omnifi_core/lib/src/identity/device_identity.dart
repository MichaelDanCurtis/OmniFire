import 'dart:convert';
import 'dart:math';

import '../crypto/handshake.dart';
import 'secure_store.dart';

class IdentityError implements Exception {
  const IdentityError(this.reason);
  final String reason;
  @override
  String toString() => 'IdentityError: $reason';
}

const _kDeviceId = 'omnifi.identity.deviceId';
const _kPrivateKey = 'omnifi.identity.privateKey';
const _kPublicKey = 'omnifi.identity.publicKey';
const _kDisplayName = 'omnifi.identity.displayName';

final Random _rng = Random.secure();

/// Lowercase hex identifier, 32 characters for the default 16 bytes.
String randomHexId([int bytes = 16]) {
  final buf = StringBuffer();
  for (var i = 0; i < bytes; i++) {
    buf.write(_rng.nextInt(256).toRadixString(16).padLeft(2, '0'));
  }
  return buf.toString();
}

class DeviceIdentity {
  const DeviceIdentity({
    required this.deviceId,
    required this.displayName,
    required this.keys,
  });

  final String deviceId;
  final String displayName;
  final StaticKeyPair keys;
}

/// Loads the device's long-term identity, creating it on first run.
///
/// Idempotent: the device ID and keypair are generated exactly once and
/// reused forever after. Only the display name is refreshed on reload.
Future<DeviceIdentity> loadOrCreateIdentity({
  required SecureStore store,
  required String displayName,
}) async {
  final existingId = await store.read(_kDeviceId);
  final existingPriv = await store.read(_kPrivateKey);
  final existingPub = await store.read(_kPublicKey);

  if (existingId != null && existingPriv != null && existingPub != null) {
    final List<int> priv;
    final List<int> pub;
    try {
      priv = base64Decode(existingPriv);
      pub = base64Decode(existingPub);
    } on FormatException {
      throw const IdentityError('stored key material is not valid base64');
    }
    if (priv.length != 32 || pub.length != 32) {
      throw const IdentityError('stored key material has the wrong length');
    }
    await store.write(_kDisplayName, displayName);
    return DeviceIdentity(
      deviceId: existingId,
      displayName: displayName,
      keys: StaticKeyPair(publicKey: pub, privateKey: priv),
    );
  }

  final keys = await OmniFiHandshakeV1.generateStaticKeys();
  final deviceId = randomHexId();
  await store.write(_kDeviceId, deviceId);
  await store.write(_kPrivateKey, base64Encode(keys.privateKey));
  await store.write(_kPublicKey, base64Encode(keys.publicKey));
  await store.write(_kDisplayName, displayName);

  return DeviceIdentity(
    deviceId: deviceId,
    displayName: displayName,
    keys: keys,
  );
}
