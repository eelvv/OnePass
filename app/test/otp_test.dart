import 'package:flutter_test/flutter_test.dart';

import 'package:onepass/state/providers.dart';

void main() {
  group('otpRemaining', () {
    test('wraps inside the period window', () {
      final epoch =
          DateTime.parse('1970-01-01T00:00:59Z').millisecondsSinceEpoch ~/ 1000;
      expect(otpRemaining(30, epoch), 1);
      expect(otpRemaining(30, epoch - 1), 2);
    });

    test('handles the window boundary', () {
      final epoch =
          DateTime.parse('1970-01-01T01:00:00Z').millisecondsSinceEpoch ~/ 1000;
      expect(otpRemaining(30, epoch), 30);
    });
  });
}
