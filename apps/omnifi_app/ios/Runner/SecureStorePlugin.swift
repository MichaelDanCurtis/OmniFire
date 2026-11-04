import Flutter
import Foundation
import Security

/// Keychain-backed secret storage. Values are stored as generic passwords
/// under the service "com.omnifi.keys".
///
/// This is the iOS twin of `macos/Runner/SecureStorePlugin.swift`. Two
/// differences, both real:
///
///  * `registrar.messenger` is a **property** on macOS and a **method** on
///    iOS. Getting that wrong does not fail to compile in an obvious place; it
///    fails to register, and every channel call then answers
///    `MissingPluginException` at runtime.
///  * `kSecAttrAccessible` is honoured here. On macOS this plugin lands in the
///    file-based keychain, which ignores it; iOS is the data-protection
///    keychain, so `AfterFirstUnlockThisDeviceOnly` genuinely does keep the
///    device private key out of iCloud Keychain and out of encrypted backups,
///    and genuinely does make it unreadable before the first unlock after a
///    reboot. That last part matters for the authority role this device is
///    taking on: the secrets are not reachable on a phone that has not been
///    unlocked since it was powered on.
///
/// **Every failure is reported, and none is swallowed.** `read` returning
/// `nil` is not "something went wrong", it is the specific statement "this
/// device has no such entry" — which is what `loadOrCreateIdentity` reads as
/// "first run, mint a new identity". Mapping a locked keychain, a missing
/// entitlement or a corrupt entry to `nil` would therefore not degrade
/// gracefully: it would silently regenerate this device's ID and keypair and
/// orphan it from every peer it had already paired with. So only
/// `errSecItemNotFound` becomes `nil`; every other `OSStatus` becomes a
/// `FlutterError`, and the Dart side lets it throw.
///
/// The same reasoning applies to `write`: an unchecked `SecItemAdd` that
/// failed would leave the process running on an identity that was never
/// persisted, and the next launch would mint another one.
class SecureStorePlugin: NSObject, FlutterPlugin {
  private static let service = "com.omnifi.keys"

  static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(
      name: "com.omnifi/secure_store",
      binaryMessenger: registrar.messenger())
    registrar.addMethodCallDelegate(SecureStorePlugin(), channel: channel)
  }

  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let key = args["key"] as? String else {
      result(FlutterError(code: "bad_args", message: "key required",
                          details: nil))
      return
    }

    switch call.method {
    case "read":
      do {
        result(try read(key: key))
      } catch {
        result(Self.error(error, "reading \(key)"))
      }
    case "write":
      guard let value = args["value"] as? String else {
        result(FlutterError(code: "bad_args", message: "value required",
                            details: nil))
        return
      }
      do {
        try write(key: key, value: value)
        result(nil)
      } catch {
        result(Self.error(error, "writing \(key)"))
      }
    case "delete":
      do {
        try delete(key: key)
        result(nil)
      } catch {
        result(Self.error(error, "deleting \(key)"))
      }
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  /// A non-success, non-"absent" `OSStatus`.
  private struct KeychainError: Error {
    let status: OSStatus
  }

  private static func error(_ error: Error, _ what: String) -> FlutterError {
    let status = (error as? KeychainError)?.status ?? errSecInternalError
    let explanation =
      SecCopyErrorMessageString(status, nil) as String? ?? "unknown"
    return FlutterError(
      code: "keychain",
      message: "keychain failed while \(what): OSStatus \(status) "
        + "(\(explanation))",
      details: Int(status))
  }

  private func query(key: String) -> [String: Any] {
    return [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: SecureStorePlugin.service,
      kSecAttrAccount as String: key,
    ]
  }

  private func read(key: String) throws -> String? {
    var q = query(key: key)
    q[kSecReturnData as String] = true
    q[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let status = SecItemCopyMatching(q as CFDictionary, &item)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess else { throw KeychainError(status: status) }
    // Present but unreadable is a fault, not an absence. Returning nil here
    // would put us straight back on the regenerate-the-identity path.
    guard let data = item as? Data,
          let value = String(data: data, encoding: .utf8) else {
      throw KeychainError(status: errSecDecode)
    }
    return value
  }

  private func write(key: String, value: String) throws {
    try delete(key: key)
    var q = query(key: key)
    q[kSecValueData as String] = Data(value.utf8)
    // Unlike macOS, this is load-bearing here: the iOS data-protection
    // keychain honours it. "ThisDeviceOnly" keeps the entry out of iCloud
    // Keychain and out of encrypted backups, and "AfterFirstUnlock" makes it
    // unreadable until the user has unlocked the phone at least once since
    // boot. It is deliberately not `WhenUnlocked`: this app is foreground-only
    // by design, but the engine's own teardown runs as the app is being
    // suspended, and that path must still be able to reach the identity.
    q[kSecAttrAccessible as String] =
      kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let status = SecItemAdd(q as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainError(status: status) }
  }

  private func delete(key: String) throws {
    let status = SecItemDelete(query(key: key) as CFDictionary)
    // Deleting what is not there is the intended end state, not a failure.
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw KeychainError(status: status)
    }
  }
}
