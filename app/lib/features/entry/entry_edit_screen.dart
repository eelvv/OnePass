import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../shared/errors.dart';
import '../../shared/logger.dart';
import '../../src/rust/api/dto.dart';
import '../../src/rust/api/error.dart';
import '../../src/rust/api/vault.dart' as bridge;
import '../../state/providers.dart';

const otpKinds = ['totp', 'hotp', 'steam', 'motp', 'yandex'];
const otpAlgorithms = ['SHA1', 'SHA256', 'SHA512'];

/// Opens the entry editor: a centered dialog on wide screens, a full page on
/// phones. [existingUuid] null = create. Returns the entry uuid on save.
/// [initialType2fa] preselects the 2FA tab; [initialSecretOrUri] prefills the
/// secret/URI field (used by the QR scanner flow).
Future<String?> openEntryEditor(
  BuildContext context,
  WidgetRef ref, {
  String? existingUuid,
  bool initialType2fa = false,
  String? initialSecretOrUri,
}) async {
  final wide = MediaQuery.widthOf(context) >= 720;
  final saved = wide
      ? await showDialog<String>(
          context: context,
          builder: (context) => Dialog(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 560, maxHeight: 720),
              child: EntryEditor(
                existingUuid: existingUuid,
                initialType2fa: initialType2fa,
                initialSecretOrUri: initialSecretOrUri,
              ),
            ),
          ),
        )
      : await Navigator.push<String>(
          context,
          MaterialPageRoute<String>(
            builder: (_) => Scaffold(
              body: SafeArea(
                child: EntryEditor(
                  existingUuid: existingUuid,
                  initialType2fa: initialType2fa,
                  initialSecretOrUri: initialSecretOrUri,
                ),
              ),
            ),
          ),
        );
  if (saved != null) {
    ref.read(selectedEntryProvider.notifier).select(saved);
    await ref.read(entriesProvider.notifier).refresh();
    await bridge.saveSession();
  }
  return saved;
}

/// Unified add/edit form for password and 2FA entries (mirrors the CLI form).
class EntryEditor extends ConsumerStatefulWidget {
  const EntryEditor({
    super.key,
    this.existingUuid,
    this.initialType2fa = false,
    this.initialSecretOrUri,
  });

  final String? existingUuid;
  final bool initialType2fa;
  final String? initialSecretOrUri;

  @override
  ConsumerState<EntryEditor> createState() => _EntryEditorState();
}

class _EntryEditorState extends ConsumerState<EntryEditor> {
  final _formKey = GlobalKey<FormState>();
  final _title = TextEditingController();
  final _username = TextEditingController();
  final _password = TextEditingController();
  final _url = TextEditingController();
  final _notes = TextEditingController();
  final _issuer = TextEditingController();
  final _account = TextEditingController();
  final _secret = TextEditingController();
  final _digits = TextEditingController(text: '6');
  final _period = TextEditingController(text: '30');
  final _counter = TextEditingController(text: '0');
  final _pin = TextEditingController();
  late bool _is2fa = widget.initialType2fa;
  String _kind = 'totp';
  String _algorithm = 'SHA1';
  bool _busy = false;
  bool _loaded = false;
  Object? _loadError;
  String? _existingUuid;

  @override
  void initState() {
    super.initState();
    _existingUuid = widget.existingUuid;
    if (widget.initialSecretOrUri != null) {
      _secret.text = widget.initialSecretOrUri!;
      _prefillFromUri(widget.initialSecretOrUri!);
    }
    if (_existingUuid != null) _load();
  }

  @override
  void dispose() {
    for (final c in [
      _title, _username, _password, _url, _notes,
      _issuer, _account, _secret, _digits, _period, _counter, _pin,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  /// QR flow: parse the scanned otpauth URI and prefill the 2FA fields.
  Future<void> _prefillFromUri(String uri) async {
    try {
      final info = bridge.parseOtpauthUri(uri: uri);
      if (!mounted) return;
      setState(() {
        _is2fa = true;
        _issuer.text = info.issuer;
        _account.text = info.account;
        _kind = info.kind;
        _algorithm = info.algorithm;
        _digits.text = '${info.digits}';
        _period.text = '${info.period}';
        _counter.text = '${info.counter}';
      });
    } catch (e, st) {
      // Keep the raw URI in the secret field; validation happens on save.
      Logger.e('otpauth prefill failed', e, st);
    }
  }

  Future<void> _load() async {
    final uuid = _existingUuid!;
    try {
      final detail = await bridge.entryDetail(uuidHex: uuid);
      final otp = await bridge.otpInfo(uuidHex: uuid);

      String password = '';
      String? otpUri;
      for (final f in detail.fields) {
        if (f.key == 'Password' && f.protected) {
          password = await bridge.revealField(uuidHex: uuid, key: f.key);
        }
        if (f.key == 'otp' && f.protected) {
          otpUri = await bridge.revealField(uuidHex: uuid, key: f.key);
        }
      }

      if (!mounted) return;
      setState(() {
        _is2fa = otp != null;
        for (final f in detail.fields) {
          switch (f.key) {
            case 'Title':
              _title.text = f.value;
            case 'UserName':
              _username.text = f.value;
            case 'Password':
              _password.text = password;
            case 'URL':
              _url.text = f.value;
            case 'Notes':
              _notes.text = f.value;
          }
        }
        if (otp != null) {
          _issuer.text = otp.issuer;
          _account.text = otp.account;
          _kind = otp.kind;
          _algorithm = otp.algorithm;
          _digits.text = '${otp.digits}';
          _period.text = '${otp.period}';
          _counter.text = '${otp.counter}';
          // The PIN survives through the otpauth URI prefilled in _secret;
          // the PIN field stays empty unless the user re-enters one.
          _pin.clear();
        }
        if (otpUri != null) _secret.text = otpUri;
        _loaded = true;
        _loadError = null;
      });
    } catch (e, st) {
      Logger.e('entry editor load failed', e, st);
      if (mounted) {
        setState(() {
          _loadError = e;
          _loaded = false;
        });
      }
    }
  }

  Future<void> _generatePassword() async {
    final policy = PasswordPolicyDto(
      upper: true,
      lower: true,
      digits: true,
      symbols: true,
      excludeAmbiguous: true,
      requireEachSet: false,
    );
    final pw = bridge.generatePassword(len: 20, policy: policy);
    if (mounted) setState(() => _password.text = pw);
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() => _busy = true);
    final l10n = context.l10n;
    final messenger = ScaffoldMessenger.of(context);
    try {
      if (_is2fa) {
        final input = OtpEntryInput(
          issuer: _issuer.text.trim(),
          account: _account.text.trim(),
          secretOrUri: _secret.text.trim(),
          kind: _kind,
          algorithm: _algorithm,
          digits: int.tryParse(_digits.text.trim()) ?? 6,
          period: BigInt.from(int.tryParse(_period.text.trim()) ?? 30),
          counter: BigInt.from(int.tryParse(_counter.text.trim()) ?? 0),
          pin: _pin.text,
        );
        if (_existingUuid == null) {
          _existingUuid = await bridge.addOtpEntry(input: input);
        } else {
          await bridge.updateOtpEntry(uuidHex: _existingUuid!, input: input);
        }
      } else {
        final input = PasswordEntryInput(
          title: _title.text.trim(),
          username: _username.text.trim(),
          password: _password.text,
          url: _url.text.trim(),
          notes: _notes.text,
        );
        if (_existingUuid == null) {
          _existingUuid = await bridge.addPasswordEntry(input: input);
        } else {
          await bridge.updatePasswordEntry(
            uuidHex: _existingUuid!,
            input: input,
          );
        }
      }
      if (!mounted) return;
      Logger.i('entry saved ($_existingUuid)');
      Navigator.of(context).pop(_existingUuid);
    } catch (e, st) {
      Logger.e('entry save failed', e, st);
      if (e is BridgeError && e.kind == ErrorKind.sessionState) {
        // Session dropped (e.g. auto-lock race): surface the lock screen
        // instead of leaving the editor in a dead state.
        if (mounted) {
          ref.read(lockedProvider.notifier).setLocked(true);
        }
      } else if (mounted) {
        messenger
          ..hideCurrentSnackBar()
          ..showSnackBar(SnackBar(content: Text(friendlyError(l10n, e))));
      }
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Header row with the close affordance - kept visible in EVERY state
  /// (loading / load-error / form) so the screen can always be exited.
  Widget _header(BuildContext context) {
    final l10n = context.l10n;
    return Row(
      children: [
        Expanded(
          child: Text(
            _existingUuid == null ? l10n.addEntry : l10n.editEntry,
            style: Theme.of(context).textTheme.titleLarge,
          ),
        ),
        IconButton(
          icon: const Icon(Icons.close),
          onPressed: () => Navigator.of(context).pop(false),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    if (_existingUuid != null && !_loaded) {
      // Loading AND load-failure states keep the close affordance so the
      // screen can always be exited.
      return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.all(20),
            child: _header(context),
          ),
          if (_loadError == null)
            const Expanded(
              child: Center(child: CircularProgressIndicator()),
            )
          else ...[
            Expanded(
              child: Center(
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Text(
                    friendlyError(l10n, _loadError!),
                    textAlign: TextAlign.center,
                  ),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(16),
              child: FilledButton.tonal(
                onPressed: _load,
                child: Text(l10n.retry),
              ),
            ),
          ],
        ],
      );
    }

    return Form(
      key: _formKey,
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _header(context),
            const SizedBox(height: 12),
            SegmentedButton<bool>(
              segments: [
                ButtonSegment(value: false, label: Text(l10n.typePassword)),
                ButtonSegment(value: true, label: Text(l10n.type2fa)),
              ],
              selected: {_is2fa},
              onSelectionChanged: (s) => setState(() => _is2fa = s.first),
            ),
            const SizedBox(height: 16),
            if (!_is2fa) ...[
              TextFormField(
                controller: _title,
                decoration: InputDecoration(labelText: l10n.fieldTitle),
                validator: (v) =>
                    (v == null || v.trim().isEmpty) ? l10n.requiredField : null,
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _username,
                decoration: InputDecoration(labelText: l10n.fieldUsername),
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _password,
                obscureText: true,
                decoration: InputDecoration(
                  labelText: l10n.fieldPassword,
                  suffixIcon: IconButton(
                    tooltip: l10n.generate,
                    icon: const Icon(Icons.casino_outlined),
                    onPressed: _generatePassword,
                  ),
                ),
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _url,
                decoration: InputDecoration(labelText: l10n.fieldUrl),
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _notes,
                maxLines: 3,
                decoration: InputDecoration(labelText: l10n.fieldNotes),
              ),
            ] else ...[
              TextFormField(
                controller: _issuer,
                decoration: InputDecoration(labelText: l10n.fieldIssuer),
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _account,
                decoration: InputDecoration(labelText: l10n.fieldAccount),
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _secret,
                minLines: 1,
                maxLines: 3,
                decoration: InputDecoration(
                  labelText: l10n.fieldSecret,
                  helperText:
                      _existingUuid == null ? null : l10n.keepSecretHint,
                ),
                validator: (v) =>
                    (v == null || v.trim().isEmpty) && _existingUuid == null
                        ? l10n.requiredField
                        : null,
              ),
              const SizedBox(height: 12),
              DropdownButtonFormField<String>(
                initialValue: _kind,
                decoration: InputDecoration(labelText: l10n.fieldKind),
                items: otpKinds
                    .map((k) => DropdownMenuItem(value: k, child: Text(k)))
                    .toList(),
                onChanged: (v) => setState(() => _kind = v ?? 'totp'),
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: DropdownButtonFormField<String>(
                      initialValue: _algorithm,
                      decoration:
                          InputDecoration(labelText: l10n.fieldAlgorithm),
                      items: otpAlgorithms
                          .map((a) =>
                              DropdownMenuItem(value: a, child: Text(a)))
                          .toList(),
                      onChanged: (v) =>
                          setState(() => _algorithm = v ?? 'SHA1'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: TextFormField(
                      controller: _digits,
                      keyboardType: TextInputType.number,
                      decoration: InputDecoration(labelText: l10n.fieldDigits),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: TextFormField(
                      controller: _period,
                      keyboardType: TextInputType.number,
                      decoration: InputDecoration(labelText: l10n.fieldPeriod),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: TextFormField(
                      controller: _counter,
                      keyboardType: TextInputType.number,
                      decoration:
                          InputDecoration(labelText: l10n.fieldCounter),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: TextFormField(
                      controller: _pin,
                      obscureText: true,
                      decoration: InputDecoration(labelText: l10n.fieldPin),
                    ),
                  ),
                ],
              ),
            ],
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: _busy ? null : _submit,
              icon: _busy
                  ? const SizedBox(
                      height: 16,
                      width: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Icon(Icons.save_outlined),
              label: Text(l10n.save),
            ),
          ],
        ),
      ),
    );
  }
}
