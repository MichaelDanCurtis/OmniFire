import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';

import 'ui/pairing_screen.dart';
import 'ui/settings_screen.dart';
import 'ui/status_indicator.dart';

class OmniFiApp extends StatelessWidget {
  const OmniFiApp({super.key, required this.engine, this.awaitPeerLink});

  final OmniFiEngine engine;

  /// Supplies the transport a pairing handshake runs over. Null until the
  /// core grows a pairing rendezvous — see [PairingScreen.awaitPeerLink] —
  /// in which case "Add a device" is shown disabled rather than hidden, so
  /// the missing capability is visible instead of merely absent.
  final Future<Link> Function()? awaitPeerLink;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OmniFi',
      theme: ThemeData(useMaterial3: true),
      home: Scaffold(
        appBar: AppBar(
          title: const Text('OmniFi'),
          actions: [
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: Center(
                child: StreamBuilder<ConnectionStatus>(
                  stream: engine.statuses,
                  initialData: engine.status,
                  builder: (context, snapshot) => StatusIndicator(
                    // The engine publishes the *worst* peer's status, so this
                    // is a floor across the mesh, not a summary of the best
                    // link. Falling back to offline when the stream has not
                    // yet produced anything errs the same way.
                    status: snapshot.data ?? ConnectionStatus.offline,
                  ),
                ),
              ),
            ),
          ],
        ),
        body: SettingsScreen(engine: engine),
        floatingActionButton: Builder(
          builder: (context) {
            final linkSource = awaitPeerLink;
            final button = FloatingActionButton.extended(
              onPressed: linkSource == null
                  ? null
                  : () => Navigator.of(context).push(
                        MaterialPageRoute<void>(
                          builder: (_) => PairingScreen(
                            engine: engine,
                            awaitPeerLink: linkSource,
                          ),
                        ),
                      ),
              icon: const Icon(Icons.add),
              label: const Text('Add a device'),
            );
            if (linkSource != null) return button;
            return Tooltip(
              message: 'Pairing needs a transport that can accept a '
                  'connection from an unpaired device. That is not wired up '
                  'yet.',
              child: button,
            );
          },
        ),
      ),
    );
  }
}
