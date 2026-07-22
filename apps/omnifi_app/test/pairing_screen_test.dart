import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:omnifi_app/ui/pairing_screen.dart';

void main() {
  testWidgets('renders the five SAS words', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: SasConfirmation(
        words: const ['able', 'brisk', 'cedar', 'delta', 'eagle'],
        onConfirm: () {},
        onReject: () {},
      ),
    ));
    expect(find.text('able brisk cedar delta eagle'), findsOneWidget);
  });

  testWidgets('confirm and reject both fire', (tester) async {
    var confirmed = false;
    var rejected = false;
    await tester.pumpWidget(MaterialApp(
      home: SasConfirmation(
        words: const ['able', 'brisk', 'cedar', 'delta', 'eagle'],
        onConfirm: () => confirmed = true,
        onReject: () => rejected = true,
      ),
    ));

    await tester.tap(find.text('They match'));
    await tester.pump();
    expect(confirmed, isTrue);

    await tester.tap(find.text("They don't match"));
    await tester.pump();
    expect(rejected, isTrue);
  });

  testWidgets('tells the user what the comparison is for', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: SasConfirmation(
        words: const ['able', 'brisk', 'cedar', 'delta', 'eagle'],
        onConfirm: () {},
        onReject: () {},
      ),
    ));
    expect(
      find.textContaining('same words'),
      findsOneWidget,
      reason: 'the user must know they are comparing two screens',
    );
  });

  // Declining is the whole man-in-the-middle defence: it tears the pairing
  // link down so the peer cannot complete. A decline the user cannot reach
  // without first reading past the confirm button is a decline that will not
  // be used, so it must be present and enabled on first paint.
  testWidgets('the decline button is enabled, not decorative', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: SasConfirmation(
        words: const ['able', 'brisk', 'cedar', 'delta', 'eagle'],
        onConfirm: () {},
        onReject: () {},
      ),
    ));
    // byWidgetPredicate, not byType: byType matches the exact runtime type, so
    // byType(ButtonStyleButton) finds nothing for an OutlinedButton subclass.
    final reject = tester.widget<ButtonStyleButton>(
      find.ancestor(
        of: find.text("They don't match"),
        matching: find.byWidgetPredicate((w) => w is ButtonStyleButton),
      ),
    );
    expect(reject.enabled, isTrue);
  });

  testWidgets('warns that a mismatch means interception', (tester) async {
    await tester.pumpWidget(MaterialApp(
      home: SasConfirmation(
        words: const ['able', 'brisk', 'cedar', 'delta', 'eagle'],
        onConfirm: () {},
        onReject: () {},
      ),
    ));
    expect(find.textContaining('intercept'), findsOneWidget);
  });
}
