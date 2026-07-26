import 'package:flutter/services.dart';
import 'package:omnifi_core/omnifi_core.dart';

/// Keychain on macOS/iOS, Credential Manager on Windows. Key material never
/// reaches a plain file through this path.
///
/// Every method is a thin pass-through **and deliberately catches nothing**.
/// `null` from [read] is the signal `loadOrCreateIdentity` reads as "this
/// device has no identity yet, mint one", so a keychain fault that were
/// mapped to `null` would not degrade gracefully — it would silently generate
/// a new device ID and keypair, orphaning this device from every peer it has
/// already paired with. The native side is written to the same rule: only
/// `errSecItemNotFound` becomes `null`, every other `OSStatus` becomes a
/// `PlatformException`.
class PlatformSecureStore implements SecureStore {
  static const MethodChannel _channel =
      MethodChannel('com.omnifi/secure_store');

  @override
  Future<String?> read(String key) =>
      _channel.invokeMethod<String>('read', {'key': key});

  @override
  Future<void> write(String key, String value) =>
      _channel.invokeMethod<void>('write', {'key': key, 'value': value});

  @override
  Future<void> delete(String key) =>
      _channel.invokeMethod<void>('delete', {'key': key});
}
