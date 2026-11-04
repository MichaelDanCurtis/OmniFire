/// Platform-backed secret storage. Implementations live in the Flutter app
/// (Keychain on macOS/iOS, Credential Manager on Windows). The core never
/// touches a file directly.
abstract interface class SecureStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

/// Non-persistent store for tests and integration harnesses.
class InMemorySecureStore implements SecureStore {
  final Map<String, String> _values = {};

  @override
  Future<String?> read(String key) async => _values[key];

  @override
  Future<void> write(String key, String value) async {
    _values[key] = value;
  }

  @override
  Future<void> delete(String key) async {
    _values.remove(key);
  }
}
