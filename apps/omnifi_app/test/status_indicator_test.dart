import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:omnifi_app/ui/status_indicator.dart';
import 'package:omnifi_core/omnifi_core.dart';

Future<void> pump(WidgetTester tester, ConnectionStatus status) =>
    tester.pumpWidget(MaterialApp(
      home: Scaffold(body: StatusIndicator(status: status)),
    ));

void main() {
  testWidgets('shows the direct label', (tester) async {
    await pump(tester, ConnectionStatus.connectedDirect);
    expect(find.text('Connected (direct)'), findsOneWidget);
  });

  testWidgets('shows the relay label', (tester) async {
    await pump(tester, ConnectionStatus.connectedRelay);
    expect(find.text('Connected (relay)'), findsOneWidget);
  });

  testWidgets('shows the reconnecting label', (tester) async {
    await pump(tester, ConnectionStatus.reconnecting);
    expect(find.text('Reconnecting…'), findsOneWidget);
  });

  testWidgets('shows the offline label', (tester) async {
    await pump(tester, ConnectionStatus.offline);
    expect(find.text('Offline'), findsOneWidget);
  });

  testWidgets('distinguishes direct from relay visually', (tester) async {
    await pump(tester, ConnectionStatus.connectedDirect);
    final direct = tester.widget<Icon>(find.byType(Icon)).color;
    await pump(tester, ConnectionStatus.connectedRelay);
    final relay = tester.widget<Icon>(find.byType(Icon)).color;
    expect(direct, isNot(relay));
  });

  // The colour check above passes even if both states share one glyph, and a
  // user who cannot distinguish those two colours would then have no signal at
  // all that their traffic is going through a third party.
  testWidgets('distinguishes direct from relay by glyph as well as colour',
      (tester) async {
    await pump(tester, ConnectionStatus.connectedDirect);
    final direct = tester.widget<Icon>(find.byType(Icon)).icon;
    await pump(tester, ConnectionStatus.connectedRelay);
    final relay = tester.widget<Icon>(find.byType(Icon)).icon;
    expect(direct, isNot(relay));
  });

  testWidgets('every status is rendered by exactly one label', (tester) async {
    const labels = {
      'Connected (direct)',
      'Connected (relay)',
      'Reconnecting…',
      'Offline',
    };
    for (final status in ConnectionStatus.values) {
      await pump(tester, status);
      final shown = tester.widget<Text>(find.byType(Text)).data;
      expect(labels, contains(shown), reason: '$status rendered "$shown"');
    }
  });
}
