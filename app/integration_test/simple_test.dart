import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'package:onepass/main.dart';
import 'package:onepass/src/rust/api/engine.dart';
import 'package:onepass/src/rust/api/simple.dart';
import 'package:onepass/src/rust/frb_generated.dart';

/// On-device smoke test: verifies Flutter can call into the Rust engine
/// through the FFI bridge (native library actually loads and answers).
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  testWidgets('Flutter calls into the Rust engine over FFI',
      (tester) async {
    // Direct FFI round-trips.
    expect(engineVersion(), isNotEmpty);
    expect(greet(name: 'OnePass'), 'Hello, OnePass!');

    // End-to-end through the widget tree.
    await tester.pumpWidget(const OnePassApp());
    await tester.pumpAndSettle();
    expect(find.textContaining('Engine v'), findsOneWidget);
    expect(find.textContaining('Hello, OnePass!'), findsOneWidget);
  });
}
