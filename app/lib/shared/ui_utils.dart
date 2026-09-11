import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../l10n/app_localizations.dart';

/// Copies to the clipboard and schedules a clear after [timeout] when the
/// content is unchanged (Android 10+ cannot read the clipboard in
/// background, so the clear only works while the app is foregrounded).
Future<void> copyWithAutoClear(
  BuildContext context,
  String label,
  String value, {
  Duration timeout = const Duration(seconds: 60),
}) async {
  await Clipboard.setData(ClipboardData(text: value));
  if (context.mounted) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(label)));
  }
  unawaited(Future.delayed(timeout, () async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (data?.text == value) {
      await Clipboard.setData(const ClipboardData(text: ''));
    }
  }));
}

/// Seconds until the current TOTP window ends (for countdown rings).
/// Returns 0 for a non-positive period (e.g. HOTP entries have none) instead
/// of throwing a modulo-by-zero error.
int otpRemaining(int period, int epochSecs) =>
    period <= 0 ? 0 : period - (epochSecs % period);

/// Formats .NET-epoch seconds as a short local date (best effort).
String formatDotnetDate(BuildContext context, int dotnetSecs) {
  if (dotnetSecs == 0) return '—';
  const dotNetOffset = 62135596800;
  final dt = DateTime.fromMillisecondsSinceEpoch(
    (dotnetSecs - dotNetOffset) * 1000,
  );
  return MaterialLocalizations.of(context).formatShortDate(dt);
}

/// Root navigator key: lock flows pop all pushed routes before swapping
/// the home to the lock screen (keeps the navigation stack consistent).
final appNavigatorKey = GlobalKey<NavigatorState>();

extension L10nX on BuildContext {
  AppLocalizations get l10n => AppLocalizations.of(this)!;
}
