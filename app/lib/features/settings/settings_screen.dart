import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter/services.dart';
import 'package:share_plus/share_plus.dart';

import '../../shared/biometric.dart';
import '../../shared/errors.dart';
import '../../shared/logger.dart';
import '../../src/rust/api/vault.dart' as bridge;
import '../../state/providers.dart';
import '../../theme/app_theme.dart';

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  final _newPassword = TextEditingController();
  bool _busy = false;

  @override
  void dispose() {
    _newPassword.dispose();
    super.dispose();
  }

  Future<void> _changePassword() async {
    final l10n = context.l10n;
    final messenger = ScaffoldMessenger.of(context);
    final value = _newPassword.text;
    if (value.isEmpty) return;
    setState(() => _busy = true);
    String? error;
    try {
      await bridge.changeMasterPassword(newPassword: value.codeUnits);
      await bridge.saveSession();
      _newPassword.clear();
    } catch (e) {
      error = e.toString();
    }
    if (!mounted) return;
    setState(() => _busy = false);
    if (error != null) {
      Logger.e('change master password failed', error);
      messenger.showSnackBar(
        SnackBar(content: Text(friendlyError(l10n, error))),
      );
    } else {
      messenger.showSnackBar(
        SnackBar(content: Text(l10n.passwordChanged)),
      );
    }
  }

  Future<void> _toggleBiometric(bool want) async {
    final l10n = context.l10n;
    final messenger = ScaffoldMessenger.of(context);
    final controller = ref.read(settingsProvider.notifier);
    final settings = ref.read(settingsProvider);

    if (!want) {
      // Disabling: confirm with biometrics, then forget the stored password.
      final ok = await BiometricService.authenticate(l10n.biometricReason);
      if (ok) {
        await BiometricService.forget();
        await controller.update(settings.copyWith(biometricEnabled: false));
        Logger.i('biometric unlock disabled');
      }
      return;
    }

    if (!await BiometricService.canAuthenticate()) {
      messenger.showSnackBar(SnackBar(content: Text(l10n.biometricNotAvailable)));
      return;
    }
    if (!await BiometricService.authenticate(l10n.biometricReason)) return;
    if (!mounted) return;

    final pwController = TextEditingController();
    final password = await showDialog<String>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(l10n.biometricUnlock),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(l10n.enableBiometricPrompt),
            const SizedBox(height: 12),
            TextField(
              controller: pwController,
              obscureText: true,
              autofocus: true,
              decoration: InputDecoration(labelText: l10n.masterPassword),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(dialogContext, pwController.text),
            child: Text(l10n.save),
          ),
        ],
      ),
    );
    pwController.dispose();
    if (password == null || password.isEmpty || !mounted) return;

    final path = await ref.read(vaultPathProvider.future);
    final valid = await bridge.checkVaultPassword(
      path: path,
      password: password.codeUnits,
    );
    if (!valid) {
      messenger.showSnackBar(SnackBar(content: Text(l10n.wrongPassword)));
      return;
    }
    await BiometricService.storePassword(password);
    await controller.update(settings.copyWith(biometricEnabled: true));
    Logger.i('biometric unlock enabled');
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final settings = ref.watch(settingsProvider);
    final controller = ref.read(settingsProvider.notifier);
    final engine = ref.watch(engineVersionProvider);

    return Scaffold(
      appBar: AppBar(title: Text(l10n.settings)),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560),
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              _SectionHeader(l10n.appearance),
              Card(
                child: Column(
                  children: [
                    ListTile(
                      leading: const Icon(Icons.brightness_6_outlined),
                      title: Text(l10n.themeMode),
                    ),
                    RadioGroup<ThemeModeSetting>(
                      groupValue: settings.themeMode,
                      onChanged: (v) =>
                          controller.update(settings.copyWith(themeMode: v)),
                      child: Column(
                        children: [
                          RadioListTile<ThemeModeSetting>(
                            title: Text(l10n.themeSystem),
                            value: ThemeModeSetting.system,
                          ),
                          RadioListTile<ThemeModeSetting>(
                            title: Text(l10n.themeLight),
                            value: ThemeModeSetting.light,
                          ),
                          RadioListTile<ThemeModeSetting>(
                            title: Text(l10n.themeDark),
                            value: ThemeModeSetting.dark,
                          ),
                        ],
                      ),
                    ),
                    const Divider(height: 1),
                    Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(l10n.accentColor,
                              style: Theme.of(context).textTheme.labelLarge),
                          const SizedBox(height: 8),
                          Wrap(
                            spacing: 12,
                            children: [
                              for (var i = 0; i < accentPresets.length; i++)
                                _SeedDot(
                                  preset: accentPresets[i],
                                  selected: settings.seedIndex == i,
                                  onTap: () => controller.update(
                                      settings.copyWith(seedIndex: i)),
                                ),
                            ],
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              _SectionHeader(l10n.language),
              Card(
                child: Column(
                  children: [
                    RadioGroup<LocaleSetting>(
                      groupValue: settings.locale,
                      onChanged: (v) =>
                          controller.update(settings.copyWith(locale: v)),
                      child: Column(
                        children: [
                          RadioListTile<LocaleSetting>(
                            title: Text(l10n.langSystem),
                            value: LocaleSetting.system,
                          ),
                          RadioListTile<LocaleSetting>(
                            title: const Text('中文'),
                            value: LocaleSetting.zh,
                          ),
                          RadioListTile<LocaleSetting>(
                            title: const Text('English'),
                            value: LocaleSetting.en,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              _SectionHeader(l10n.security),
              Card(
                child: Column(
                  children: [
                    SwitchListTile(
                      secondary: const Icon(Icons.lock_clock_outlined),
                      title: Text(l10n.lockOnBackground),
                      value: settings.lockOnBackground,
                      onChanged: (v) => controller
                          .update(settings.copyWith(lockOnBackground: v)),
                    ),
                    if (settings.lockOnBackground)
                      ListTile(
                        leading: const Icon(Icons.timer_outlined),
                        title: Text(l10n.lockGrace),
                        trailing: DropdownButton<int>(
                          value: settings.lockGraceSecs,
                          underline: const SizedBox.shrink(),
                          items: const [
                            DropdownMenuItem(value: 0, child: Text('0s')),
                            DropdownMenuItem(value: 30, child: Text('30s')),
                            DropdownMenuItem(value: 60, child: Text('1m')),
                            DropdownMenuItem(value: 300, child: Text('5m')),
                          ],
                          onChanged: (v) => controller.update(
                              settings.copyWith(lockGraceSecs: v ?? 60)),
                        ),
                      ),
                    SwitchListTile(
                      secondary: const Icon(Icons.fingerprint),
                      title: Text(l10n.biometricUnlock),
                      value: settings.biometricEnabled,
                      onChanged: (want) => _toggleBiometric(want),
                    ),
                    SwitchListTile(
                      secondary: const Icon(Icons.visibility_off_outlined),
                      title: Text(l10n.flagSecure),
                      value: settings.flagSecure,
                      onChanged: (v) async {
                        await controller
                            .update(settings.copyWith(flagSecure: v));
                        await const MethodChannel('onepass/security')
                            .invokeMethod('setFlagSecure', {'enabled': v});
                        Logger.i('flagSecure=$v');
                      },
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 8),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(l10n.changeMasterPassword,
                          style: Theme.of(context).textTheme.titleMedium),
                      const SizedBox(height: 4),
                      Text(l10n.changePasswordHint,
                          style: Theme.of(context).textTheme.bodySmall),
                      const SizedBox(height: 12),
                      TextFormField(
                        controller: _newPassword,
                        obscureText: true,
                        autofillHints: const [AutofillHints.newPassword],
                        decoration:
                            InputDecoration(labelText: l10n.masterPassword),
                      ),
                      const SizedBox(height: 12),
                      FilledButton.tonal(
                        onPressed: _busy ? null : _changePassword,
                        child: Text(l10n.changeMasterPassword),
                      ),
                    ],
                  ),
                ),
              ),
              _SectionHeader(l10n.logs),
              Card(
                child: Column(
                  children: [
                    ListTile(
                      leading: const Icon(Icons.description_outlined),
                      title: Text(l10n.logFile),
                      subtitle: FutureBuilder<String>(
                        future: logFilePath(),
                        builder: (context, snapshot) =>
                            Text(snapshot.data ?? '…'),
                      ),
                    ),
                    ListTile(
                      leading: const Icon(Icons.share_outlined),
                      title: Text(l10n.shareLogs),
                      onTap: () async {
                        final path = await logFilePath();
                        await SharePlus.instance.share(
                          ShareParams(files: [XFile(path)]),
                        );
                      },
                    ),
                    ListTile(
                      leading: const Icon(Icons.delete_sweep_outlined),
                      title: Text(l10n.clearLogs),
                      onTap: () async {
                        final messenger = ScaffoldMessenger.of(context);
                        await Logger.clear();
                        messenger.showSnackBar(
                          SnackBar(content: Text(l10n.logsCleared)),
                        );
                      },
                    ),
                  ],
                ),
              ),
              _SectionHeader(l10n.about),
              Card(
                child: ListTile(
                  leading: const Icon(Icons.shield_outlined),
                  title: Text(l10n.appTitle),
                  subtitle: engine.when(
                    data: (v) => Text('${l10n.engineVersion}: v$v'),
                    loading: () => const SizedBox.shrink(),
                    error: (e, _) => Text('$e'),
                  ),
                ),
              ),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  const _SectionHeader(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(4, 16, 4, 8),
      child: Text(
        text,
        style: Theme.of(context)
            .textTheme
            .titleSmall
            ?.copyWith(color: Theme.of(context).colorScheme.primary),
      ),
    );
  }
}

class _SeedDot extends StatelessWidget {
  const _SeedDot({
    required this.preset,
    required this.selected,
    required this.onTap,
  });

  final AccentPreset preset;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      customBorder: const CircleBorder(),
      child: Tooltip(
        message: preset.name,
        child: Container(
          width: 40,
          height: 40,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: preset.seed,
            border: selected
                ? Border.all(
                    width: 3,
                    color: Theme.of(context).colorScheme.onSurface,
                  )
                : null,
          ),
          child: selected
              ? const Icon(Icons.check, color: Colors.white, size: 20)
              : null,
        ),
      ),
    );
  }
}
