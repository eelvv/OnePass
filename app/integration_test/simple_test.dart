import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'package:onepass/src/rust/api/engine.dart';
import 'package:onepass/src/rust/api/simple.dart';
import 'package:onepass/src/rust/api/dto.dart';
import 'package:onepass/src/rust/api/vault.dart';
import 'package:onepass/src/rust/frb_generated.dart';

/// On-device smoke test: verifies Flutter can call into the Rust engine
/// through the FFI bridge (native library actually loads and answers).
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());

  testWidgets('Flutter calls into the Rust engine over FFI', (tester) async {
    // Direct FFI round-trips.
    expect(engineVersion(), isNotEmpty);
    expect(greet(name: 'OnePass'), 'Hello, OnePass!');
    expect(isUnlocked(), isFalse);

    // Password generation through the policy API.
    final pw = generatePassword(
      len: 20,
      policy: PasswordPolicyDto(
        upper: true,
        lower: true,
        digits: true,
        symbols: true,
        excludeAmbiguous: true,
        requireEachSet: true,
      ),
    );
    expect(pw.length, 20);
  });
}
