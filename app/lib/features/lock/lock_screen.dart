import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../l10n/app_localizations.dart';
import '../../shared/errors.dart';
import '../../shared/biometric.dart';
import '../../shared/logger.dart';
import '../../src/rust/api/vault.dart' as bridge;
import '../../state/providers.dart';

/// Unlock (existing vault) / create (new vault) screen. Rendered while the
/// session is locked; the mode follows whether the vault file exists.
class LockScreen extends ConsumerStatefulWidget {
  const LockScreen({super.key, required this.onUnlocked});

  final VoidCallback onUnlocked;

  @override
  ConsumerState<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends ConsumerState<LockScreen> {
  final _formKey = GlobalKey<FormState>();
  final _nameController = TextEditingController();
  final _passwordController = TextEditingController();
  final _confirmController = TextEditingController();
  bool _createMode = false;
  bool _modeResolved = false;
  bool _busy = false;
  bool _biometricReady = false;

  @override
  void initState() {
    super.initState();
    _resolveMode();
  }

  @override
  void dispose() {
    _nameController.dispose();
    _passwordController.dispose();
    _confirmController.dispose();
    super.dispose();
  }

  Future<void> _resolveMode() async {
    final path = await ref.read(vaultPathProvider.future);
    final exists = await File(path).exists();
    final settings = ref.read(settingsProvider);
    final canBiometric =
        settings.biometricEnabled && await BiometricService.canAuthenticate();
    if (mounted) {
      setState(() {
        _createMode = !exists;
        _biometricReady = !exists && canBiometric;
        _modeResolved = true;
      });
    }
  }

  /// Biometric unlock: authenticate, read the stored master password and
  /// open the vault with it.
  Future<void> _biometricUnlock() async {
    final l10n = context.l10n;
    final messenger = ScaffoldMessenger.of(context);
    final ok = await BiometricService.authenticate(l10n.biometricReason);
    if (!ok) return;
    final password = await BiometricService.readPassword();
    if (password == null || !mounted) return;

    final path = await ref.read(vaultPathProvider.future);
    String? error;
    try {
      final entries = await bridge.openVault(
        path: path,
        password: password.codeUnits,
      );
      ref.read(entriesProvider.notifier).apply(entries);
      Logger.i('biometric unlock ok (${entries.length} entries)');
    } catch (e, st) {
      Logger.e('biometric unlock failed', e, st);
      error = friendlyError(l10n, e);
      // Stored password no longer matches (vault re-imported?): drop it.
      await BiometricService.forget();
      if (mounted) {
        ref.read(settingsProvider.notifier).update(
              ref.read(settingsProvider).copyWith(biometricEnabled: false),
            );
      }
    }
    if (!mounted) return;
    if (error != null) {
      messenger
        ..hideCurrentSnackBar()
        ..showSnackBar(SnackBar(content: Text(error)));
      if (mounted) setState(() => _biometricReady = false);
      return;
    }
    ref.read(lockedProvider.notifier).setLocked(false);
    widget.onUnlocked();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() => _busy = true);
    final l10n = context.l10n;
    final messenger = ScaffoldMessenger.of(context);
    final path = await ref.read(vaultPathProvider.future);
    final password = _passwordController.text;

    String? error;
    try {
      if (_createMode) {
        Logger.i('creating vault');
        await bridge.createVault(
          path: path,
          name: _nameController.text.trim().isEmpty
              ? l10n.vaultNameHint
              : _nameController.text.trim(),
          password: password.codeUnits,
        );
        Logger.i('vault created');
      } else {
        Logger.i('unlock attempt');
        final entries = await bridge.openVault(
          path: path,
          password: password.codeUnits,
        );
        ref.read(entriesProvider.notifier).apply(entries);
        Logger.i('unlocked (${entries.length} entries)');
      }
      await bridge.saveSession();
      // Never keep the master password in a text controller.
      _passwordController.clear();
      _confirmController.clear();
    } catch (e, st) {
      Logger.e('unlock/create failed', e, st);
      error = friendlyError(l10n, e);
    }

    if (!mounted) return;
    setState(() => _busy = false);
    if (error != null) {
      messenger
        ..hideCurrentSnackBar()
        ..showSnackBar(SnackBar(content: Text(error)));
      return;
    }
    await ref.read(entriesProvider.notifier).refresh();
    ref.read(lockedProvider.notifier).setLocked(false);
    widget.onUnlocked();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 400),
              child: Card(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: !_modeResolved
                      ? const SizedBox(
                          height: 140,
                          child: Center(child: CircularProgressIndicator()),
                        )
                      : _buildForm(context, l10n),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildForm(BuildContext context, AppLocalizations l10n) {
    return Form(
      key: _formKey,
      autovalidateMode: AutovalidateMode.onUserInteraction,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Icon(Icons.shield_outlined,
              size: 56, color: Theme.of(context).colorScheme.primary),
          const SizedBox(height: 12),
          Text(
            _createMode ? l10n.createVault : l10n.appTitle,
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 4),
          Text(
            _createMode ? l10n.createVaultPrompt : l10n.unlockPrompt,
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const SizedBox(height: 24),
          if (_createMode) ...[
            TextFormField(
              controller: _nameController,
              decoration: InputDecoration(
                labelText: l10n.vaultName,
                hintText: l10n.vaultNameHint,
              ),
            ),
            const SizedBox(height: 16),
          ],
          TextFormField(
            controller: _passwordController,
            obscureText: true,
            autofillHints: _createMode
                ? const [AutofillHints.newPassword]
                : const [AutofillHints.password],
            decoration: InputDecoration(labelText: l10n.masterPassword),
            validator: (v) =>
                (v == null || v.isEmpty) ? l10n.requiredField : null,
            onFieldSubmitted: (_) => _busy ? null : _submit(),
          ),
          if (_createMode) ...[
            const SizedBox(height: 16),
            TextFormField(
              controller: _confirmController,
              obscureText: true,
              autofillHints: const [AutofillHints.newPassword],
              decoration: InputDecoration(labelText: l10n.confirmPassword),
              validator: (v) =>
                  v != _passwordController.text ? l10n.passwordsDontMatch : null,
            ),
          ],
          const SizedBox(height: 24),
          FilledButton(
            onPressed: _busy ? null : _submit,
            child: _busy
                ? const SizedBox(
                    height: 18,
                    width: 18,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : Text(_createMode ? l10n.createVault : l10n.unlock),
          ),
          if (_biometricReady && !_createMode) ...[
            const SizedBox(height: 12),
            OutlinedButton.icon(
              onPressed: _busy ? null : _biometricUnlock,
              icon: const Icon(Icons.fingerprint),
              label: Text(l10n.unlockWithBiometric),
            ),
          ],
        ],
      ),
    );
  }
}
