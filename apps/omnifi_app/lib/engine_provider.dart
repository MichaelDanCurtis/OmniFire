import 'dart:async';

import 'package:flutter/material.dart';
import 'package:omnifi_core/omnifi_core.dart';

/// Makes the running [OmniFiEngine] reachable from anywhere in the tree.
class EngineScope extends InheritedWidget {
  const EngineScope({
    super.key,
    required this.engine,
    required super.child,
  });

  final OmniFiEngine engine;

  static OmniFiEngine of(BuildContext context) {
    final scope = context.dependOnInheritedWidgetOfExactType<EngineScope>();
    assert(scope != null, 'No EngineScope above this widget.');
    return scope!.engine;
  }

  /// The engine identity never changes for the life of a host, so no
  /// dependent ever needs rebuilding on account of this widget.
  @override
  bool updateShouldNotify(EngineScope oldWidget) =>
      !identical(engine, oldWidget.engine);
}

/// Owns the engine's lifecycle and bridges the platform's app-lifecycle
/// events into it.
///
/// This is the one piece of genuine wiring the UI layer has to do: the engine
/// exposes [OmniFiEngine.onWake], [OmniFiEngine.onScreenLocked] and
/// [OmniFiEngine.onScreenUnlocked] and nothing outside Flutter can call them.
/// Everything else here is start, stop, and get out of the way.
class EngineHost extends StatefulWidget {
  const EngineHost({super.key, required this.engine, required this.child});

  final OmniFiEngine engine;
  final Widget child;

  @override
  State<EngineHost> createState() => _EngineHostState();
}

class _EngineHostState extends State<EngineHost> with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    unawaited(widget.engine.start());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    // Dropped rather than awaited: dispose cannot be async, and the engine's
    // teardown is idempotent. The process is usually going away regardless.
    unawaited(widget.engine.stop());
    super.dispose();
  }

  /// An approximation, and flagged as one.
  ///
  /// Flutter reports app lifecycle, not screen lock. A locked screen shows up
  /// as `hidden`/`paused` on iOS and as `inactive` on macOS, but so does the
  /// user switching apps — which is not a reason to stop capturing the
  /// clipboard. Treating only the backgrounded states as a lock keeps the
  /// clipboard running during an ordinary app switch and pauses it when the
  /// machine is put away. A true lock signal needs a platform channel
  /// (`NSDistributedNotificationCenter` on macOS, `WTSRegisterSessionNotification`
  /// on Windows) and is platform work, not UI work.
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    final engine = widget.engine;
    switch (state) {
      case AppLifecycleState.resumed:
        engine.onScreenUnlocked();
        // Links do not survive a sleep. onWake forces every manager to
        // redial rather than wait out a backoff that started before the lid
        // closed.
        unawaited(engine.onWake());
      case AppLifecycleState.paused:
      case AppLifecycleState.hidden:
        engine.onScreenLocked();
      case AppLifecycleState.inactive:
      case AppLifecycleState.detached:
        break;
    }
  }

  @override
  Widget build(BuildContext context) =>
      EngineScope(engine: widget.engine, child: widget.child);
}
