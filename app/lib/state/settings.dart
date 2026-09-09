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
    this.lockGraceSecs = 60,
    this.biometricEnabled = false,
    this.flagSecure = false,
  });

  final ThemeModeSetting themeMode;
  final LocaleSetting locale;
  final int seedIndex;
  final bool lockOnBackground;

  /// Grace period (seconds) before locking after the app is backgrounded.
  /// 0 = lock immediately.
  final int lockGraceSecs;

  /// Biometric unlock enabled (master password stored in secure storage).
  final bool biometricEnabled;

  /// FLAG_SECURE: prevent screenshots / app-switcher preview.
  final bool flagSecure;

  AppSettings copyWith({
    ThemeModeSetting? themeMode,
    LocaleSetting? locale,
    int? seedIndex,
    bool? lockOnBackground,
    int? lockGraceSecs,
    bool? biometricEnabled,
    bool? flagSecure,
  }) =>
      AppSettings(
        themeMode: themeMode ?? this.themeMode,
        locale: locale ?? this.locale,
        seedIndex: seedIndex ?? this.seedIndex,
        lockOnBackground: lockOnBackground ?? this.lockOnBackground,
        lockGraceSecs: lockGraceSecs ?? this.lockGraceSecs,
        biometricEnabled: biometricEnabled ?? this.biometricEnabled,
        flagSecure: flagSecure ?? this.flagSecure,
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
      lockGraceSecs:
          (_prefs.getInt('lockGraceSecs') ?? 60).clamp(0, 300),
      biometricEnabled: _prefs.getBool('biometricEnabled') ?? false,
      flagSecure: _prefs.getBool('flagSecure') ?? false,
    );
  }

  Future<void> update(AppSettings next) async {
    state = next;
    await _prefs.setInt('themeMode', next.themeMode.index);
    await _prefs.setInt('locale', next.locale.index);
    await _prefs.setInt('seedIndex', next.seedIndex);
    await _prefs.setBool('lockOnBackground', next.lockOnBackground);
    await _prefs.setInt('lockGraceSecs', next.lockGraceSecs);
    await _prefs.setBool('biometricEnabled', next.biometricEnabled);
    await _prefs.setBool('flagSecure', next.flagSecure);
  }
}
