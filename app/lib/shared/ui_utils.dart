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
int otpRemaining(int period, int epochSecs) =>
    period - (epochSecs % period);

/// Formats .NET-epoch seconds as a short local date (best effort).
String formatDotnetDate(BuildContext context, int dotnetSecs) {
  if (dotnetSecs == 0) return '—';
  const dotNetOffset = 62135596800;
  final dt = DateTime.fromMillisecondsSinceEpoch(
    (dotnetSecs - dotNetOffset) * 1000,
  );
  return MaterialLocalizations.of(context).formatShortDate(dt);
}

extension L10nX on BuildContext {
  AppLocalizations get l10n => AppLocalizations.of(this)!;
}
