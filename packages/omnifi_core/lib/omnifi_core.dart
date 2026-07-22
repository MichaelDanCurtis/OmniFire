/// OmniFi core: identity, crypto, protocol, transport. Flutter-free by design.
library omnifi_core;

export 'src/version.dart';
export 'src/identity/device_identity.dart';
export 'src/identity/secure_store.dart';
export 'src/identity/mesh.dart';
export 'src/crypto/aead_session.dart';
export 'src/crypto/handshake.dart';
export 'src/crypto/sas.dart';
export 'src/crypto/wordlist.dart';
export 'src/protocol/framing.dart';
export 'src/protocol/envelope.dart';
export 'src/protocol/messages.dart';
export 'src/transport/link.dart';
export 'src/transport/relay_link.dart';
export 'src/transport/lan_link.dart';
export 'src/transport/outbox.dart';
export 'src/transport/link_manager.dart';
export 'src/session/peer_session.dart';
export 'src/pairing/pairing_payload.dart';
export 'src/pairing/pairing_flow.dart';
export 'src/sync/clipboard_sync.dart';
export 'src/sync/clipboard_watcher.dart';
