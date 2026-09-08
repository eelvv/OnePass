import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../src/rust/api/dto.dart';
import '../../src/rust/api/vault.dart' as bridge;
import '../../state/providers.dart';

const otpKinds = ['totp', 'hotp', 'steam', 'motp', 'yandex'];
const otpAlgorithms = ['SHA1', 'SHA256', 'SHA512'];

/// Opens the entry editor: a centered dialog on wide screens, a full page on
/// phones. [existingUuid] null = create.
Future<void> openEntryEditor(
  BuildContext context,
  WidgetRef ref, {
  String? existingUuid,
}) async {
  final wide = MediaQuery.widthOf(context) >= 720;
  final saved = wide
      ? await showDialog<bool>(
          context: context,
          builder: (context) => Dialog(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 560, maxHeight: 720),
              child: EntryEditor(existingUuid: existingUuid),
            ),
          ),
        )
      : await Navigator.push<bool>(
          context,
          MaterialPageRoute<bool>(
            builder: (_) => Scaffold(
              body: SafeArea(
                child: EntryEditor(existingUuid: existingUuid),
              ),
            ),
          ),
        );
  if (saved == true) {
    await ref.read(entriesProvider.notifier).refresh();
    await bridge.saveSession();
  }
}

/// Unified add/edit form for password and 2FA entries (mirrors the CLI form).
class EntryEditor extends ConsumerStatefulWidget {
  const EntryEditor({super.key, this.existingUuid});

  final String? existingUuid;

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
  bool _is2fa = false;
  String _kind = 'totp';
  String _algorithm = 'SHA1';
  bool _busy = false;
  bool _loaded = false;
  String? _existingUuid;

  @override
  void initState() {
    super.initState();
    _existingUuid = widget.existingUuid;
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

  Future<void> _load() async {
    final uuid = _existingUuid!;
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
        _pin.text = otp.hasPin ? '' : '';
      }
      if (otpUri != null) _secret.text = otpUri;
      _loaded = true;
    });
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
      Navigator.of(context).pop(true);
    } catch (e) {
      messenger
        ..hideCurrentSnackBar()
        ..showSnackBar(SnackBar(content: Text(e.toString())));
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    if (_existingUuid != null && !_loaded) {
      return const Center(child: CircularProgressIndicator());
    }

    return Form(
      key: _formKey,
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
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
            ),
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
