import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'l10n/app_localizations.dart';
import 'src/rust/api/vault.dart' as bridge;
import 'src/rust/frb_generated.dart';
import 'features/lock/lock_screen.dart';
import 'features/vault/vault_screen.dart';
import 'state/providers.dart';
import 'theme/app_theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Bootstrap the Rust core: loads librust_lib_onepass.so into the process.
  // All engine logic lives in Rust; Dart only calls across the FFI boundary.
  await RustLib.init();
  final prefs = await SharedPreferences.getInstance();
  runApp(ProviderScope(
    overrides: [sharedPreferencesProvider.overrideWithValue(prefs)],
    child: const OnePassApp(),
  ));
}

class OnePassApp extends ConsumerStatefulWidget {
  const OnePassApp({super.key});

  @override
  ConsumerState<OnePassApp> createState() => _OnePassAppState();
}

class _OnePassAppState extends ConsumerState<OnePassApp>
    with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    super.didChangeAppLifecycleState(state);
    // Auto-lock: drop the Rust session (password zeroized) when the app is
    // backgrounded, if the user has not disabled it.
    if (state == AppLifecycleState.paused &&
        ref.read(settingsProvider).lockOnBackground &&
        !ref.read(lockedProvider)) {
      bridge.lockVault();
      ref.read(lockedProvider.notifier).setLocked(true);
    }
  }

  @override
  Widget build(BuildContext context) {
    final settings = ref.watch(settingsProvider);
    final locked = ref.watch(lockedProvider);

    final seed = accentPresets[settings.seedIndex % accentPresets.length].seed;
    final themeMode = switch (settings.themeMode) {
      ThemeModeSetting.system => ThemeMode.system,
      ThemeModeSetting.light => ThemeMode.light,
      ThemeModeSetting.dark => ThemeMode.dark,
    };
    final locale = switch (settings.locale) {
      LocaleSetting.system => null,
      LocaleSetting.zh => const Locale('zh'),
      LocaleSetting.en => const Locale('en'),
    };

    return MaterialApp(
      title: 'OnePass',
      locale: locale,
      supportedLocales: AppLocalizations.supportedLocales,
      localizationsDelegates: const [
        AppLocalizations.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      theme: buildOnePassTheme(seed, Brightness.light),
      darkTheme: buildOnePassTheme(seed, Brightness.dark),
      themeMode: themeMode,
      home: AnimatedSwitcher(
        duration: const Duration(milliseconds: 200),
        child: locked
            ? LockScreen(
                key: const ValueKey('lock'),
                onUnlocked: () {},
              )
            : const VaultScreen(key: ValueKey('vault')),
      ),
    );
  }
}
