import 'package:omnifi_core/omnifi_core.dart';
import 'package:test/test.dart';

PeerRecord peer(String id, {int keyFill = 7, String name = 'Peer'}) =>
    PeerRecord(
      deviceId: id,
      publicKey: List<int>.filled(32, keyFill),
      displayName: name,
      addedAtMs: 1753200000000,
    );

void main() {
  test('creates a mesh with a 32-char hex id', () async {
    final mesh = await loadOrCreateMesh(store: InMemorySecureStore());
    expect(mesh.meshId, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(mesh.peers, isEmpty);
  });

  test('reloads the same mesh id', () async {
    final store = InMemorySecureStore();
    final first = await loadOrCreateMesh(store: store);
    final second = await loadOrCreateMesh(store: store);
    expect(second.meshId, first.meshId);
  });

  test('adds and looks up a peer', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32, name: 'Windows PC'));
    expect(mesh.peers.length, 1);
    expect(mesh.peer('b' * 32)?.displayName, 'Windows PC');
  });

  test('adding the same device id replaces rather than duplicates', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32, name: 'Old'));
    mesh.addPeer(peer('b' * 32, name: 'New'));
    expect(mesh.peers.length, 1);
    expect(mesh.peer('b' * 32)?.displayName, 'New');
  });

  test('removes a peer and reports whether it existed', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32));
    expect(mesh.removePeer('b' * 32), isTrue);
    expect(mesh.removePeer('b' * 32), isFalse);
    expect(mesh.peers, isEmpty);
  });

  test('authorizes a known device with a matching key', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32, keyFill: 7));
    expect(mesh.isAuthorized('b' * 32, List<int>.filled(32, 7)), isTrue);
  });

  test('refuses a known device id with a different key', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32, keyFill: 7));
    expect(mesh.isAuthorized('b' * 32, List<int>.filled(32, 8)), isFalse);
  });

  test('refuses an unknown device id', () {
    final mesh = Mesh(meshId: 'a' * 32);
    expect(mesh.isAuthorized('c' * 32, List<int>.filled(32, 7)), isFalse);
  });

  test('refuses a revoked device even with its original key', () {
    final mesh = Mesh(meshId: 'a' * 32);
    mesh.addPeer(peer('b' * 32, keyFill: 7));
    mesh.removePeer('b' * 32);
    expect(mesh.isAuthorized('b' * 32, List<int>.filled(32, 7)), isFalse);
  });

  test('survives a save and reload with peers intact', () async {
    final store = InMemorySecureStore();
    final mesh = await loadOrCreateMesh(store: store);
    mesh.addPeer(peer('b' * 32, name: 'iPhone'));
    await saveMesh(mesh, store);

    final reloaded = await loadOrCreateMesh(store: store);
    expect(reloaded.meshId, mesh.meshId);
    expect(reloaded.peers.length, 1);
    expect(reloaded.peer('b' * 32)?.displayName, 'iPhone');
    expect(reloaded.isAuthorized('b' * 32, List<int>.filled(32, 7)), isTrue);
  });

  test('rejects a peer record with a wrong-length key', () {
    expect(
      () => PeerRecord(
        deviceId: 'b' * 32,
        publicKey: List<int>.filled(16, 1),
        displayName: 'Bad',
        addedAtMs: 1,
      ),
      throwsA(isA<ArgumentError>()),
    );
  });

  test('fresh store still creates a new mesh normally', () async {
    final store = InMemorySecureStore();
    final mesh = await loadOrCreateMesh(store: store);
    expect(mesh.meshId, matches(RegExp(r'^[0-9a-f]{32}$')));
    expect(mesh.peers, isEmpty);
  });

  test(
      'throws MeshError when mesh id is stored but roster is missing '
      '(partial state)', () async {
    final store = InMemorySecureStore();
    final mesh = await loadOrCreateMesh(store: store);
    mesh.addPeer(peer('b' * 32, name: 'iPhone'));
    await saveMesh(mesh, store);

    // Simulate a partial write / storage eviction: the mesh id survives but
    // the roster entry is gone.
    await store.delete('omnifi.mesh.roster');

    expect(
      () => loadOrCreateMesh(store: store),
      throwsA(
        isA<MeshError>().having(
          (e) => e.reason,
          'reason',
          contains('roster'),
        ),
      ),
    );
  });

  test('fromMap throws ArgumentError when a peers entry is not a map', () {
    expect(
      () => Mesh.fromMap({
        'meshId': 'a' * 32,
        'peers': ['not a map'],
      }),
      throwsA(isA<ArgumentError>()),
    );
  });

  test('PeerRecord.fromMap throws ArgumentError on invalid base64 publicKey',
      () {
    expect(
      () => PeerRecord.fromMap({
        'deviceId': 'b' * 32,
        'publicKey': 'not-valid-base64!!',
        'displayName': 'Bad',
        'addedAtMs': 1,
      }),
      throwsA(isA<ArgumentError>()),
    );
  });

  test(
      'throws MeshError when roster is stored but mesh id is missing '
      '(partial state)', () async {
    final store = InMemorySecureStore();
    final mesh = await loadOrCreateMesh(store: store);
    mesh.addPeer(peer('b' * 32, name: 'iPhone'));
    await saveMesh(mesh, store);

    // Simulate a partial write / storage eviction: the roster survives but
    // the mesh id entry is gone.
    await store.delete('omnifi.mesh.id');

    expect(
      () => loadOrCreateMesh(store: store),
      throwsA(
        isA<MeshError>().having(
          (e) => e.reason,
          'reason',
          contains('incomplete'),
        ),
      ),
    );
  });

  test(
      'the roster survives the refusal when mesh id is missing '
      '(no destructive overwrite)', () async {
    final store = InMemorySecureStore();
    final mesh = await loadOrCreateMesh(store: store);
    mesh.addPeer(peer('b' * 32, name: 'iPhone'));
    await saveMesh(mesh, store);

    await store.delete('omnifi.mesh.id');

    await expectLater(
      () => loadOrCreateMesh(store: store),
      throwsA(isA<MeshError>()),
    );

    final rosterAfter = await store.read('omnifi.mesh.roster');
    expect(rosterAfter, isNotNull);
    expect(rosterAfter, contains('iPhone'));
    expect(rosterAfter, contains('b' * 32));
  });
}
