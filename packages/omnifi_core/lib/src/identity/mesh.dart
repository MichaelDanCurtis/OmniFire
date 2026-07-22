import 'dart:convert';

import 'device_identity.dart';
import 'secure_store.dart';

class MeshError implements Exception {
  const MeshError(this.reason);
  final String reason;
  @override
  String toString() => 'MeshError: $reason';
}

const _kMeshId = 'omnifi.mesh.id';
const _kRoster = 'omnifi.mesh.roster';

class PeerRecord {
  PeerRecord({
    required this.deviceId,
    required this.publicKey,
    required this.displayName,
    required this.addedAtMs,
  }) {
    if (publicKey.length != 32) {
      throw ArgumentError.value(
          publicKey.length, 'publicKey', 'must be 32 bytes');
    }
  }

  final String deviceId;
  final List<int> publicKey;
  final String displayName;
  final int addedAtMs;

  Map<String, Object?> toMap() => {
        'deviceId': deviceId,
        'publicKey': base64Encode(publicKey),
        'displayName': displayName,
        'addedAtMs': addedAtMs,
      };

  static PeerRecord fromMap(Map<String, Object?> map) {
    final deviceId = map['deviceId'];
    final publicKey = map['publicKey'];
    final displayName = map['displayName'];
    final addedAtMs = map['addedAtMs'];
    if (deviceId is! String ||
        publicKey is! String ||
        displayName is! String ||
        addedAtMs is! int) {
      throw ArgumentError('malformed peer record');
    }
    final List<int> decodedKey;
    try {
      decodedKey = base64Decode(publicKey);
    } on FormatException {
      throw ArgumentError('malformed peer record: publicKey is not valid '
          'base64');
    }
    return PeerRecord(
      deviceId: deviceId,
      publicKey: decodedKey,
      displayName: displayName,
      addedAtMs: addedAtMs,
    );
  }
}

Map<String, Object?> _asStringKeyedMap(Object? value) {
  if (value is! Map) {
    throw ArgumentError('malformed mesh: peers entry is not a map');
  }
  return value.map((k, v) => MapEntry(k.toString(), v));
}

class Mesh {
  Mesh({required this.meshId, List<PeerRecord> peers = const []})
      : _peers = {for (final p in peers) p.deviceId: p};

  final String meshId;
  final Map<String, PeerRecord> _peers;

  List<PeerRecord> get peers => List.unmodifiable(_peers.values);

  void addPeer(PeerRecord peer) => _peers[peer.deviceId] = peer;

  bool removePeer(String deviceId) => _peers.remove(deviceId) != null;

  PeerRecord? peer(String deviceId) => _peers[deviceId];

  /// A peer is authorized only when its device ID is in the roster AND the
  /// presented public key matches the stored one byte for byte. Matching on
  /// device ID alone would let an attacker reuse a revoked ID with a new key.
  bool isAuthorized(String deviceId, List<int> publicKey) {
    final record = _peers[deviceId];
    if (record == null) return false;
    if (record.publicKey.length != publicKey.length) return false;
    var diff = 0;
    for (var i = 0; i < publicKey.length; i++) {
      diff |= record.publicKey[i] ^ publicKey[i];
    }
    return diff == 0;
  }

  Map<String, Object?> toMap() => {
        'meshId': meshId,
        'peers': [for (final p in _peers.values) p.toMap()],
      };

  static Mesh fromMap(Map<String, Object?> map) {
    final meshId = map['meshId'];
    final peers = map['peers'];
    if (meshId is! String || peers is! List) {
      throw ArgumentError('malformed mesh');
    }
    return Mesh(
      meshId: meshId,
      peers: [
        for (final p in peers)
          PeerRecord.fromMap(_asStringKeyedMap(p)),
      ],
    );
  }
}

Future<Mesh> loadOrCreateMesh({required SecureStore store}) async {
  final existingId = await store.read(_kMeshId);
  if (existingId == null) {
    final mesh = Mesh(meshId: randomHexId());
    await saveMesh(mesh, store);
    return mesh;
  }
  final roster = await store.read(_kRoster);
  if (roster == null) {
    throw const MeshError(
      'stored mesh id is present but the roster (omnifi.mesh.roster) is '
      'missing. Continuing with an empty roster is refused, since that '
      'would silently deauthorize every previously-paired device. To '
      'recover, restore the missing roster entry from a backup if '
      'possible; otherwise delete all of the omnifi.mesh.* keys to '
      'deliberately start a new mesh.',
    );
  }
  final decoded = jsonDecode(roster);
  if (decoded is! Map) {
    throw ArgumentError('stored roster is malformed');
  }
  return Mesh.fromMap(decoded.map((k, v) => MapEntry(k.toString(), v)));
}

Future<void> saveMesh(Mesh mesh, SecureStore store) async {
  await store.write(_kMeshId, mesh.meshId);
  await store.write(_kRoster, jsonEncode(mesh.toMap()));
}
