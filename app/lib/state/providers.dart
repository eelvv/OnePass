import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../l10n/app_localizations.dart';
import '../src/rust/api/engine.dart';
import '../src/rust/api/dto.dart';
import '../src/rust/api/vault.dart' as bridge;

/// ---------------------------------------------------------------------------
/// Settings

enum ThemeModeSetting { system, light, dark }

enum LocaleSetting { system, zh, en }

class AppSettings {
  const AppSettings({
    this.themeMode = ThemeModeSetting.system,
    this.locale = LocaleSetting.system,
    this.seedIndex = 0,
    this.lockOnBackground = true,
  });

  final ThemeModeSetting themeMode;
  final LocaleSetting locale;
  final int seedIndex;
  final bool lockOnBackground;

  AppSettings copyWith({
    ThemeModeSetting? themeMode,
    LocaleSetting? locale,
    int? seedIndex,
    bool? lockOnBackground,
  }) =>
      AppSettings(
        themeMode: themeMode ?? this.themeMode,
        locale: locale ?? this.locale,
        seedIndex: seedIndex ?? this.seedIndex,
        lockOnBackground: lockOnBackground ?? this.lockOnBackground,
      );
}

/// Loads settings synchronously via a pre-fetched SharedPreferences instance.
final sharedPreferencesProvider =
    Provider<SharedPreferences>((ref) => throw UnimplementedError());

final settingsProvider =
    NotifierProvider<SettingsController, AppSettings>(SettingsController.new);

class SettingsController extends Notifier<AppSettings> {
  late SharedPreferences _prefs;

  @override
  AppSettings build() {
    _prefs = ref.watch(sharedPreferencesProvider);
    return AppSettings(
      themeMode: ThemeModeSetting
          .values[_prefs.getInt('themeMode') ?? 0],
      locale: LocaleSetting.values[_prefs.getInt('locale') ?? 0],
      seedIndex: _prefs.getInt('seedIndex') ?? 0,
      lockOnBackground: _prefs.getBool('lockOnBackground') ?? true,
    );
  }

  Future<void> update(AppSettings next) async {
    state = next;
    await _prefs.setInt('themeMode', next.themeMode.index);
    await _prefs.setInt('locale', next.locale.index);
    await _prefs.setInt('seedIndex', next.seedIndex);
    await _prefs.setBool('lockOnBackground', next.lockOnBackground);
  }
}

/// ---------------------------------------------------------------------------
/// Lock state + entries

/// True while no vault session is open (initial state = locked).
final lockedProvider = NotifierProvider<LockedController, bool>(
  LockedController.new,
);

class LockedController extends Notifier<bool> {
  @override
  bool build() => true;

  void setLocked(bool value) => state = value;
}

/// The in-memory entry list mirror; refreshed after every mutation.
final entriesProvider =
    NotifierProvider<EntriesController, AsyncValue<List<EntryDto>>>(
  EntriesController.new,
);

class EntriesController extends Notifier<AsyncValue<List<EntryDto>>> {
  @override
  AsyncValue<List<EntryDto>> build() => const AsyncValue.data([]);

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    try {
      state = AsyncValue.data(await bridge.listEntries());
    } catch (e, st) {
      state = AsyncValue.error(e, st);
    }
  }

  void apply(List<EntryDto> entries) => state = AsyncValue.data(entries);
}

/// Currently selected entry uuid (drives the desktop detail pane).
final selectedEntryProvider =
    NotifierProvider<SelectedEntryController, String?>(
  SelectedEntryController.new,
);

class SelectedEntryController extends Notifier<String?> {
  @override
  String? build() => null;

  void select(String? uuid) => state = uuid;
}

/// Vault file path (app documents dir + onepass.kdbx), resolved once.
final vaultPathProvider = FutureProvider<String>((ref) async {
  final dir = await getApplicationDocumentsDirectory();
  return '${dir.path}/onepass.kdbx';
});

/// Engine version for the about tile.
final engineVersionProvider = FutureProvider<String>(
  (ref) async => engineVersion(),
);

/// ---------------------------------------------------------------------------
/// Helpers

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
