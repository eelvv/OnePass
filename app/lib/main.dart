import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'dart:async';
import 'dart:ui';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'l10n/app_localizations.dart';
import 'shared/logger.dart';
import 'src/rust/api/vault.dart' as bridge;
import 'src/rust/frb_generated.dart';
import 'features/lock/lock_screen.dart';
import 'features/vault/vault_screen.dart';
import 'state/providers.dart';
import 'theme/app_theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // File logging first, then global error hooks - both feed diagnostics.
  await Logger.init();
  FlutterError.onError = (details) {
    Logger.e('flutter error', details.exception, details.stack);
    FlutterError.presentError(details);
  };
  PlatformDispatcher.instance.onError = (e, st) {
    Logger.e('uncaught platform error', e, st);
    return true;
  };
  // Bootstrap the Rust core: loads librust_lib_onepass.so into the process.
  // All engine logic lives in Rust; Dart only calls across the FFI boundary.
  await RustLib.init();
  final prefs = await SharedPreferences.getInstance();
  // Apply FLAG_SECURE before the first frame when enabled (the Android
  // side also re-applies it at engine start from the same preference).
  if (prefs.getBool('flagSecure') ?? false) {
    await const MethodChannel('onepass/security')
        .invokeMethod('setFlagSecure', {'enabled': true});
  }
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
  DateTime? _pausedAt;

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
  Future<void> didChangeAppLifecycleState(AppLifecycleState state) async {
    super.didChangeAppLifecycleState(state);
    // Auto-lock with a configurable grace period. Dart timers are
    // unreliable while backgrounded, so the check re-runs on resume:
    // - lockGraceSecs == 0 locks immediately on pause
    // - otherwise the elapsed background time is compared on resume
    final grace = ref.read(settingsProvider).lockGraceSecs;
    final alreadyLocked = ref.read(lockedProvider);
    if (!ref.read(settingsProvider).lockOnBackground || alreadyLocked) {
      return;
    }
    if (state == AppLifecycleState.paused) {
      if (grace <= 0) {
        Logger.i('auto-lock on background (immediate)');
        await bridge.lockVault();
        ref.read(lockedProvider.notifier).setLocked(true);
      } else {
        _pausedAt = DateTime.now();
      }
    } else if (state == AppLifecycleState.resumed && _pausedAt != null) {
      final gone = DateTime.now().difference(_pausedAt!).inSeconds;
      _pausedAt = null;
      if (gone >= grace) {
        Logger.i('auto-lock: background grace of $grace s exceeded ($gone s)');
        await bridge.lockVault();
        ref.read(lockedProvider.notifier).setLocked(true);
      }
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
