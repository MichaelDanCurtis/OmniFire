import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';

/// Pause toggle, roster with a Forget action, and the configured relays.
///
/// Stateful, unlike the brief's interface sketch, because the pause flag and
/// the roster both live in the engine and are read synchronously: nothing
/// publishes a change stream for either, so this screen has to re-read them
/// after it asks the engine to change one. That is a `setState` on a widget
/// that owns no state of its own, which is exactly what [StatefulWidget] is
/// for. The alternative — a stream on the engine — is core work, not UI work.
class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, required this.engine});
  final OmniFiEngine engine;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  /// Device ids are 32 lowercase hex characters, so a fixed `substring(0, 8)`
  /// is safe today. Guarded anyway: a short id would otherwise turn a peer
  /// list into a RangeError, and the roster is loaded from persisted JSON.
  static String _shortId(String deviceId) =>
      deviceId.length <= 8 ? deviceId : deviceId.substring(0, 8);

  Future<void> _forget(PeerRecord peer) async {
    await widget.engine.forgetPeer(peer.deviceId);
    if (!mounted) return;
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    final engine = widget.engine;
    final peers = engine.mesh.peers;
    return ListView(
      children: [
        SwitchListTile(
          title: const Text('Pause clipboard sync'),
          subtitle: const Text(
              'Nothing is captured or sent while this is on.'),
          value: engine.clipboard.isPaused,
          onChanged: (v) => setState(() => engine.clipboard.setPaused(v)),
        ),
        const Divider(),
        const ListTile(
          dense: true,
          title: Text('Paired devices'),
        ),
        if (peers.isEmpty)
          const ListTile(
            title: Text('No devices paired yet.'),
          ),
        for (final peer in peers)
          ListTile(
            title: Text(peer.displayName),
            subtitle: Text(_shortId(peer.deviceId)),
            trailing: TextButton(
              onPressed: () => _forget(peer),
              child: const Text('Forget'),
            ),
          ),
        const Divider(),
        const ListTile(
          dense: true,
          title: Text('Relays'),
        ),
        // Read-only, and not because it was easier. [EngineConfig] is
        // immutable and its relay list is consumed once per peer, when
        // [OmniFiEngine] builds that peer's dialers — there is no setter to
        // write an edited URL into and no path that would pick one up. An
        // editable field here would be a text box that silently discards what
        // the user types. Making it writable is engine work: a config change
        // has to rebuild every peer's LinkManager.
        for (final relay in engine.config.relayBases)
          ListTile(
            dense: true,
            title: SelectableText(relay.toString()),
            subtitle: Text(
              relay == engine.config.primaryRelay
                  ? 'Primary — this URL goes into new pairing invites.'
                  : 'Additional candidate.',
            ),
          ),
      ],
    );
  }
}
