import 'dart:async';

import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';
import 'package:qr_flutter/qr_flutter.dart';

/// Displays the invite for another device to scan.
class InviteDisplay extends StatelessWidget {
  const InviteDisplay({super.key, required this.invite});

  final PairingInvite invite;

  @override
  Widget build(BuildContext context) {
    final uri = encodeInviteUri(invite);
    final words = encodeInviteWords(invite).join(' ');
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Text('Scan this on the device you want to add.'),
        const SizedBox(height: 16),
        // The white background and padding are not decoration. QrImageView
        // draws black modules on a transparent ground by default, which under
        // a dark theme is black-on-near-black: unreadable to a scanner, and
        // unreadable in a way the developer running a light theme never sees.
        Container(
          color: Colors.white,
          padding: const EdgeInsets.all(12),
          child: QrImageView(data: uri, size: 240),
        ),
        const SizedBox(height: 16),
        // Deliberately NOT offered as "type this phrase instead". These eight
        // words are derived from the first eight PSK bytes, and omnifi_core
        // documents them as a *lookup code*: 64 bits cannot carry a 32-byte
        // PSK plus a 32-byte key, so manual entry requires the inviting device
        // to serve the full payload against the code. Nothing serves it yet,
        // so a "type this instead" affordance would be a dead end. What the
        // code can honestly do today is let both users check by voice that
        // they are looking at the same invite.
        const Text('Pairing code:'),
        const SizedBox(height: 8),
        SelectableText(words,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 16)),
        const SizedBox(height: 8),
        Text(
          'Read this aloud to check the other device scanned this invite '
          'and not another one.',
          textAlign: TextAlign.center,
          style: Theme.of(context).textTheme.bodySmall,
        ),
      ],
    );
  }
}

/// The mandatory confirmation step. Both devices show the same words; the
/// user comparing them is what makes the pairing resistant to an attacker
/// who observed or relayed the QR code.
///
/// [onReject] is not a cancel button. Declining closes the pairing link, so
/// the peer cannot complete either — see [PairingSasPending.confirm]. The copy
/// says so, because a user who believes "no" merely dismisses a dialog will
/// press "yes" to make the dialog go away.
class SasConfirmation extends StatelessWidget {
  const SasConfirmation({
    super.key,
    required this.words,
    required this.onConfirm,
    required this.onReject,
  });

  final List<String> words;
  final VoidCallback onConfirm;
  final VoidCallback onReject;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Check that both devices show the same words. '
                'If they differ, someone may be intercepting the pairing.',
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 24),
              SelectableText(
                formatSas(words),
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 22,
                  fontWeight: FontWeight.bold,
                ),
              ),
              const SizedBox(height: 32),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  OutlinedButton(
                    onPressed: onReject,
                    child: const Text("They don't match"),
                  ),
                  const SizedBox(width: 16),
                  FilledButton(
                    onPressed: onConfirm,
                    child: const Text('They match'),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              Text(
                'Declining ends the pairing on both devices.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

enum _Stage { showingInvite, waitingForPeer, confirming, paired, failed }

/// Drives one pairing from the inviting side: show the invite, run the
/// handshake over a link, put the SAS in front of the user, and record the
/// peer only if they confirm.
///
/// Thin by construction. Every stateful decision belongs to omnifi_core; this
/// widget holds a stage enum, the invite it is displaying, and whatever the
/// engine handed back.
class PairingScreen extends StatefulWidget {
  const PairingScreen({
    super.key,
    required this.engine,
    required this.awaitPeerLink,
  });

  final OmniFiEngine engine;

  /// Produces the transport the pairing handshake runs over.
  ///
  /// Injected rather than taken from the engine because omnifi_core has no
  /// pairing rendezvous: [OmniFiEngine.beginInvite] requires a [Link] the
  /// caller already holds, and nothing in the core yet accepts an inbound
  /// connection from a device that is not already on the roster
  /// ([OmniFiEngine] closes any inbound link that resolves to no roster
  /// member). Wiring a real rendezvous is transport work, not UI work, so the
  /// seam is here rather than a half-protocol implemented in Flutter.
  final Future<Link> Function() awaitPeerLink;

  @override
  State<PairingScreen> createState() => _PairingScreenState();
}

class _PairingScreenState extends State<PairingScreen> {
  /// Built exactly once, in [initState].
  ///
  /// [OmniFiEngine.buildInvite] mints a fresh random PSK on every call, and
  /// the PSK is mixed into the handshake's HKDF salt. Rebuilding it in
  /// `build()` would not merely churn the QR image: the invite the joiner
  /// scanned and the invite this side later hands to `beginInvite` would carry
  /// different PSKs, so the two devices would derive different master secrets
  /// and show different SAS words on every attempt — a pairing the user is
  /// trained to reject, correctly, forever.
  late final PairingInvite _invite;

  _Stage _stage = _Stage.showingInvite;
  PairingSasPending? _pending;
  String? _failure;

  @override
  void initState() {
    super.initState();
    _invite = widget.engine.buildInvite();
    unawaited(_run());
  }

  Future<void> _run() async {
    setState(() => _stage = _Stage.waitingForPeer);
    try {
      final link = await widget.awaitPeerLink();
      // The invite displayed is the invite passed in. See [_invite].
      final pending = await widget.engine.beginInvite(_invite, link);
      if (!mounted) return;
      setState(() {
        _pending = pending;
        _stage = _Stage.confirming;
      });
    } on Object catch (e) {
      if (!mounted) return;
      setState(() {
        _failure = '$e';
        _stage = _Stage.failed;
      });
    }
  }

  Future<void> _answer(bool matched) async {
    final pending = _pending;
    if (pending == null) return;
    // Cleared first so a double tap cannot run the confirmation twice.
    setState(() => _pending = null);
    try {
      final outcome = await pending.confirm(matched);
      // The roster write is the app's job: PairingFlow returns a PeerRecord
      // but deliberately does not touch the mesh, so an unconfirmed or
      // declined pairing can leave nothing behind.
      widget.engine.mesh.addPeer(outcome.peer);
      await widget.engine.persist();
      if (!mounted) return;
      setState(() => _stage = _Stage.paired);
    } on Object catch (e) {
      if (!mounted) return;
      setState(() {
        _failure = '$e';
        _stage = _Stage.failed;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final pending = _pending;
    if (_stage == _Stage.confirming && pending != null) {
      return SasConfirmation(
        words: pending.sas,
        onConfirm: () => unawaited(_answer(true)),
        onReject: () => unawaited(_answer(false)),
      );
    }

    return Scaffold(
      appBar: AppBar(title: const Text('Add a device')),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: switch (_stage) {
            _Stage.showingInvite ||
            _Stage.waitingForPeer =>
              Column(mainAxisSize: MainAxisSize.min, children: [
                InviteDisplay(invite: _invite),
                const SizedBox(height: 24),
                const CircularProgressIndicator(),
                const SizedBox(height: 12),
                const Text('Waiting for the other device…'),
              ]),
            // Unreachable in practice — handled above — but a stage enum with
            // a silent hole is how a blank screen ships.
            _Stage.confirming => const CircularProgressIndicator(),
            _Stage.paired => const Text('Device paired.'),
            _Stage.failed => Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Text('Pairing did not complete.'),
                  const SizedBox(height: 8),
                  Text(
                    _failure ?? 'Unknown reason.',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ),
          },
        ),
      ),
    );
  }
}
