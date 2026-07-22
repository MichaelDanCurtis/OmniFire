import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

void main() {
  test('random hex id is 32 lowercase hex characters', () {
    final id = randomHexId();
    expect(id, matches(RegExp(r'^[0-9a-f]{32}$')));
  });

  test('random hex ids do not collide across many draws', () {
    final ids = {for (var i = 0; i < 1000; i++) randomHexId()};
    expect(ids.length, 1000);
  });

  test('creates an identity on first load', () async {
    final store = InMemorySecureStore();
    final id = await loadOrCreateIdentity(
        store: store, displayName: 'Mac Studio');
    expect(id.deviceId, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(id.displayName, 'Mac Studio');
    expect(id.keys.publicKey.length, 32);
    expect(id.keys.privateKey.length, 32);
  });

  test('returns the identical identity on a second load', () async {
    final store = InMemorySecureStore();
    final first = await loadOrCreateIdentity(
        store: store, displayName: 'Mac Studio');
    final second = await loadOrCreateIdentity(
        store: store, displayName: 'Ignored On Reload');
    expect(second.deviceId, first.deviceId);
    expect(second.keys.publicKey, first.keys.publicKey);
    expect(second.keys.privateKey, first.keys.privateKey);
  });

  test('display name is updated on reload but identity is not', () async {
    final store = InMemorySecureStore();
    final first =
        await loadOrCreateIdentity(store: store, displayName: 'Old Name');
    final second =
        await loadOrCreateIdentity(store: store, displayName: 'New Name');
    expect(second.displayName, 'New Name');
    expect(second.deviceId, first.deviceId);
  });

  test('two stores produce two distinct identities', () async {
    final a = await loadOrCreateIdentity(
        store: InMemorySecureStore(), displayName: 'A');
    final b = await loadOrCreateIdentity(
        store: InMemorySecureStore(), displayName: 'B');
    expect(a.deviceId, isNot(b.deviceId));
    expect(a.keys.publicKey, isNot(b.keys.publicKey));
  });

  test('a corrupt stored key is rejected rather than silently replaced',
      () async {
    final store = InMemorySecureStore();
    await loadOrCreateIdentity(store: store, displayName: 'A');
    await store.write('omnifi.identity.privateKey', 'not-base64-!!!');
    expect(
      () => loadOrCreateIdentity(store: store, displayName: 'A'),
      throwsA(isA<IdentityError>()),
    );
  });

  test(
      'device ID present, private key missing throws IdentityError instead '
      'of regenerating', () async {
    final store = InMemorySecureStore();
    await loadOrCreateIdentity(store: store, displayName: 'A');
    await store.delete('omnifi.identity.privateKey');
    expect(
      () => loadOrCreateIdentity(store: store, displayName: 'A'),
      throwsA(isA<IdentityError>().having(
        (e) => e.toString(),
        'message',
        contains('incomplete'),
      )),
    );
  });

  test(
      'device ID present, public key missing throws IdentityError instead '
      'of regenerating', () async {
    final store = InMemorySecureStore();
    await loadOrCreateIdentity(store: store, displayName: 'A');
    await store.delete('omnifi.identity.publicKey');
    expect(
      () => loadOrCreateIdentity(store: store, displayName: 'A'),
      throwsA(isA<IdentityError>().having(
        (e) => e.toString(),
        'message',
        contains('incomplete'),
      )),
    );
  });

  test(
      'private and public keys present, device ID missing throws '
      'IdentityError instead of regenerating', () async {
    final store = InMemorySecureStore();
    await loadOrCreateIdentity(store: store, displayName: 'A');
    await store.delete('omnifi.identity.deviceId');
    expect(
      () => loadOrCreateIdentity(store: store, displayName: 'A'),
      throwsA(isA<IdentityError>().having(
        (e) => e.toString(),
        'message',
        contains('incomplete'),
      )),
    );
  });
}
