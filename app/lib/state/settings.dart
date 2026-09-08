import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Appearance + security preferences, persisted via SharedPreferences.
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

/// Overridden in main() with a pre-fetched SharedPreferences instance so
/// settings are available synchronously at first frame.
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
      // Clamp guards against stale indices after enum changes.
      themeMode: ThemeModeSetting
          .values[(_prefs.getInt('themeMode') ?? 0)
          .clamp(0, ThemeModeSetting.values.length - 1)],
      locale: LocaleSetting
          .values[(_prefs.getInt('locale') ?? 0)
          .clamp(0, LocaleSetting.values.length - 1)],
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
