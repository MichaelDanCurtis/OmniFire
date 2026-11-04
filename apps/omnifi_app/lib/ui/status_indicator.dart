import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';

/// How one [ConnectionStatus] is presented. Grouped into a single record so
/// the switch below has to answer every question about a state at once, and
/// so no state can acquire a label without also acquiring a glyph and colour.
class _Presentation {
  const _Presentation({
    required this.label,
    required this.icon,
    required this.color,
    required this.semantics,
  });

  final String label;
  final IconData icon;
  final Color color;

  /// Spoken description. The label alone reads as a fragment out of context,
  /// and a screen-reader user gets no benefit at all from the colour.
  final String semantics;
}

/// The single most important widget in the app: when OmniFi misbehaves, the
/// first question is always whether it is even connected.
///
/// The status it renders is the *worst* peer's, not the best — see
/// [OmniFiEngine.status]. A tray icon reading "connected" while one device is
/// unreachable is worse than useless, so a mesh with one offline peer reads
/// `Offline` here even when every other peer is fine.
class StatusIndicator extends StatelessWidget {
  const StatusIndicator({super.key, required this.status});

  final ConnectionStatus status;

  /// Written as an exhaustive switch rather than a lookup map so that adding a
  /// fifth [ConnectionStatus] is a compile error here instead of a null
  /// dereference in front of the user. There are exactly four states and the
  /// UI is required to name all four.
  static _Presentation _presentationFor(ConnectionStatus status) =>
      switch (status) {
        // Direct and relay must be distinguishable at a glance, not just by
        // reading: relay means the bytes are transiting a third-party server
        // (encrypted, but transiting it), and that is a thing a user is
        // entitled to notice without parsing a parenthetical. Hence a
        // different glyph *and* a different colour — colour alone excludes
        // anyone who cannot separate green from blue.
        ConnectionStatus.connectedDirect => const _Presentation(
            label: 'Connected (direct)',
            icon: Icons.bolt,
            color: Color(0xFF2E7D32),
            semantics: 'Connected directly to every paired device.',
          ),
        ConnectionStatus.connectedRelay => const _Presentation(
            label: 'Connected (relay)',
            icon: Icons.cloud_done,
            color: Color(0xFF0277BD),
            semantics: 'Connected through the relay server. Traffic is still '
                'end-to-end encrypted.',
          ),
        ConnectionStatus.reconnecting => const _Presentation(
            label: 'Reconnecting…',
            icon: Icons.sync,
            color: Color(0xFFEF6C00),
            semantics: 'Reconnecting to a paired device.',
          ),
        ConnectionStatus.offline => const _Presentation(
            label: 'Offline',
            icon: Icons.cloud_off,
            color: Color(0xFF757575),
            semantics: 'Offline. Nothing is syncing.',
          ),
      };

  @override
  Widget build(BuildContext context) {
    final presentation = _presentationFor(status);
    return Semantics(
      liveRegion: true,
      label: presentation.semantics,
      // The Row below already renders the label as text; excluding the
      // children stops a screen reader announcing "Offline" twice.
      excludeSemantics: true,
      child: Tooltip(
        message: presentation.semantics,
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(presentation.icon, color: presentation.color, size: 18),
            const SizedBox(width: 8),
            Text(presentation.label),
          ],
        ),
      ),
    );
  }
}
