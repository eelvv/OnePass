import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:onepass/main.dart';

void main() {
  testWidgets('smoke view renders values handed over from the bridge',
      (tester) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: BridgeSmokeView(
          engineVersion: '0.1.1',
          greeting: 'Hello, OnePass!',
        ),
      ),
    );

    expect(find.text('Engine v0.1.1'), findsOneWidget);
    expect(find.text('Hello, OnePass!'), findsOneWidget);
    expect(find.text('Phase 0 build: Flutter → FFI → Rust engine'),
        findsOneWidget);
  });
}
