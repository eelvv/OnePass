import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../src/rust/api/dto.dart';
import '../../src/rust/api/vault.dart' as bridge;
import '../../state/providers.dart';
import 'entry_edit_screen.dart';

const revealAutoHide = Duration(seconds: 15);

/// Entry detail: an inline pane on wide screens, a pushed page on phones.
/// Protected values are fetched on demand and auto-hide after 15 seconds.
class DetailPane extends ConsumerStatefulWidget {
  const DetailPane({super.key});

  @override
  ConsumerState<DetailPane> createState() => _DetailPaneState();
}

class _DetailPaneState extends ConsumerState<DetailPane> {
  EntryDetail? _detail;
  OtpInfoDto? _otpInfo;
  String? _otpCode;
  int _otpRemaining = 0;
  Timer? _otpTicker;
  final Map<String, String> _revealed = {};
  Timer? _revealTimer;
  bool _loading = false;
  Object? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _otpTicker?.cancel();
    _revealTimer?.cancel();
    super.dispose();
  }

  Future<void> _load() async {
    final uuid = ref.read(selectedEntryProvider);
    if (uuid == null) return;
    setState(() {
      _loading = true;
      _error = null;
      _revealed.clear();
      _otpCode = null;
    });
    _otpTicker?.cancel();
    try {
      final detail = await bridge.entryDetail(uuidHex: uuid);
      final info = await bridge.otpInfo(uuidHex: uuid);
      if (!mounted) return;
      setState(() {
        _detail = detail;
        _otpInfo = info;
        _loading = false;
      });
      if (info != null) _startTicker(info);
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e;
          _loading = false;
        });
      }
    }
  }

  void _startTicker(OtpInfoDto info) {
    _otpTicker?.cancel();
    void tick() {
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final code = bridge.otpCode(
        uuidHex: ref.read(selectedEntryProvider) ?? '',
        timeSecs: BigInt.from(now),
      );
      if (mounted) {
        setState(() {
          _otpCode = code;
          _otpRemaining = otpRemaining(info.period.toInt(), now);
        });
      }
    }

    tick();
    _otpTicker = Timer.periodic(const Duration(seconds: 1), (_) => tick());
  }

  /// Fetches a protected value and starts the 15s auto-hide window.
  Future<void> _reveal(String key) async {
    final uuid = ref.read(selectedEntryProvider);
    if (uuid == null) return;
    try {
      final value = await bridge.revealField(uuidHex: uuid, key: key);
      if (!mounted) return;
      setState(() => _revealed[key] = value);
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.toString())),
        );
      }
    }
    _revealTimer?.cancel();
    _revealTimer = Timer(revealAutoHide, () {
      if (mounted) setState(() => _revealed.remove(key));
    });
  }

  void _hide(String key) => setState(() => _revealed.remove(key));

  Future<void> _delete() async {
    final uuid = ref.read(selectedEntryProvider);
    if (uuid == null) return;
    final l10n = context.l10n;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.deleteEntryConfirm),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(l10n.delete),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await bridge.deleteEntries(uuidHexes: [uuid]);
    ref.read(selectedEntryProvider.notifier).select(null);
    if (mounted && Navigator.of(context).canPop()) Navigator.pop(context);
    await ref.read(entriesProvider.notifier).refresh();
    await bridge.saveSession();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final uuid = ref.watch(selectedEntryProvider);

    // Reload whenever the selection changes (desktop pane stays mounted).
    ref.listen<String?>(selectedEntryProvider, (previous, next) {
      if (previous != next) _load();
    });

    if (uuid == null) {
      return _Placeholder(text: l10n.selectToDelete);
    }
    if (_loading && _detail == null) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: Text('${l10n.errorLoading}: $_error'),
            ),
            FilledButton.tonal(
              onPressed: _load,
              child: Text(l10n.retry),
            ),
          ],
        ),
      );
    }
    final detail = _detail;
    if (detail == null) return const SizedBox.shrink();

    final title =
        detail.fields.where((f) => f.key == 'Title').map((f) => f.value).firstOrNull ??
            l10n.appTitle;

    return Scaffold(
      appBar: AppBar(
        title: Text(title),
        actions: [
          IconButton(
            tooltip: l10n.editEntry,
            icon: const Icon(Icons.edit_outlined),
            onPressed: () => openEntryEditor(context, ref, existingUuid: uuid),
          ),
          IconButton(
            tooltip: l10n.delete,
            icon: const Icon(Icons.delete_outline),
            onPressed: _delete,
          ),
        ],
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640),
          child: ListView(
            padding: const EdgeInsets.all(16),
            children: [
              if (_otpInfo != null) ...[
                _OtpCard(
                  info: _otpInfo!,
                  code: _otpCode,
                  remaining: _otpRemaining,
                ),
                const SizedBox(height: 16),
              ],
              ...detail.fields.map(
                (f) => _FieldTile(
                  field: f,
                  revealedValue: _revealed[f.key],
                  onReveal: () => _reveal(f.key),
                  onHide: () => _hide(f.key),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _FieldTile extends StatelessWidget {
  const _FieldTile({
    required this.field,
    required this.revealedValue,
    required this.onReveal,
    required this.onHide,
  });

  final FieldDto field;
  final String? revealedValue;
  final VoidCallback onReveal;
  final VoidCallback onHide;

  bool get _isCopyable =>
      field.key == 'Password' || field.key == 'URL' || field.key == 'UserName';

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final revealed = field.protected && revealedValue != null;
    final value = field.protected
        ? (revealed ? revealedValue! : '••••••••')
        : (field.value.isEmpty ? '—' : field.value);

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: ListTile(
        title: Text(
          field.key,
          style: Theme.of(context)
              .textTheme
              .labelMedium
              ?.copyWith(color: Theme.of(context).colorScheme.primary),
        ),
        subtitle: SelectableText(
          value,
          style: field.protected && !revealed
              ? const TextStyle(letterSpacing: 2)
              : null,
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (field.protected)
              IconButton(
                tooltip: revealed ? l10n.lock : l10n.unlock,
                icon: Icon(revealed
                    ? Icons.visibility_off_outlined
                    : Icons.visibility_outlined),
                onPressed: revealed ? onHide : onReveal,
              ),
            if (_isCopyable && (!field.protected || revealed))
              IconButton(
                tooltip: l10n.copied,
                icon: const Icon(Icons.copy_outlined),
                onPressed: () => copyWithAutoClear(
                  context,
                  l10n.copied,
                  field.protected ? revealedValue! : field.value,
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _OtpCard extends StatelessWidget {
  const _OtpCard({
    required this.info,
    required this.code,
    required this.remaining,
  });

  final OtpInfoDto info;
  final String? code;
  final int remaining;

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final scheme = Theme.of(context).colorScheme;
    final period = info.period.toInt();
    final progress = period <= 0 ? 0.0 : remaining / period;

    return Card(
      margin: EdgeInsets.zero,
      color: scheme.surfaceContainerHighest,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.phonelink_lock_outlined,
                    size: 18, color: scheme.tertiary),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    [info.issuer, info.account]
                        .where((s) => s.isNotEmpty)
                        .join(' · '),
                    style: Theme.of(context).textTheme.labelLarge,
                  ),
                ),
                Text(
                  '${info.kind.toUpperCase()} · ${info.digits}d/${period}s',
                  style: Theme.of(context).textTheme.labelSmall,
                ),
              ],
            ),
            const SizedBox(height: 8),
            Row(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Expanded(
                  child: Text(
                    code ?? '••••••',
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                          fontFamily: 'monospace',
                          letterSpacing: 4,
                        ),
                  ),
                ),
                IconButton(
                  tooltip: l10n.otpCopied,
                  icon: const Icon(Icons.copy_all_outlined),
                  onPressed: code == null
                      ? null
                      : () => copyWithAutoClear(context, l10n.otpCopied, code!),
                ),
              ],
            ),
            const SizedBox(height: 8),
            LinearProgressIndicator(value: progress.clamp(0, 1)),
          ],
        ),
      ),
    );
  }
}

class _Placeholder extends StatelessWidget {
  const _Placeholder({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.touch_app_outlined,
              size: 48, color: Theme.of(context).colorScheme.outline),
          const SizedBox(height: 12),
          Text(text, style: Theme.of(context).textTheme.bodyMedium),
        ],
      ),
    );
  }
}
