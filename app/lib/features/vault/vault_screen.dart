import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:share_plus/share_plus.dart';

import '../../src/rust/api/dto.dart';
import '../../src/rust/api/vault.dart' as bridge;
import '../../state/providers.dart';
import '../entry/entry_detail_pane.dart';
import '../entry/entry_edit_screen.dart';
import '../settings/settings_screen.dart';

/// Entry list + (on wide screens) the detail pane. Master-detail adapts to
/// width: below 720dp the detail opens as a pushed page, above it as an
/// inline pane — the classic desktop password-manager layout.
class VaultScreen extends ConsumerStatefulWidget {
  const VaultScreen({super.key});

  @override
  ConsumerState<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends ConsumerState<VaultScreen> {
  static const wideBreakpoint = 720.0;

  final _searchController = TextEditingController();
  String _query = '';
  final Set<String> _selected = {};

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(entriesProvider.notifier).refresh();
    });
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _afterMutation() async {
    await ref.read(entriesProvider.notifier).refresh();
    await bridge.saveSession();
  }

  Future<void> _lock() async {
    await bridge.lockVault();
    ref.read(lockedProvider.notifier).setLocked(true);
    ref.read(selectedEntryProvider.notifier).select(null);
  }

  void _toggleSelect(String uuid) {
    setState(() {
      if (!_selected.remove(uuid)) _selected.add(uuid);
    });
  }

  Future<void> _deleteSelected() async {
    final l10n = context.l10n;
    final count = _selected.length;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.deleteSelected),
        content: Text(l10n.deleteConfirm(count)),
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
    if (confirmed != true) return;
    final removed = await bridge.deleteEntries(uuidHexes: _selected.toList());
    if (!mounted) return;
    setState(() => _selected.clear());
    if (removed > BigInt.zero) {
      ref.read(selectedEntryProvider.notifier).select(null);
      await _afterMutation();
    }
  }

  Future<void> _importFile() async {
    final l10n = context.l10n;
    final result = await FilePicker.platform.pickFiles(
      type: FileType.any,
      withData: true,
    );
    final bytes = result?.files.single.bytes;
    if (bytes == null) return;
    try {
      final imported = await bridge.importFromBytes(bytes: bytes);
      await _afterMutation();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(l10n.imported(imported.length))),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('${l10n.importFailed}: $e')),
        );
      }
    }
  }

  Future<void> _importUriText() async {
    final l10n = context.l10n;
    final controller = TextEditingController();
    final text = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.importPickUriText),
        content: TextField(
          controller: controller,
          maxLines: 6,
          decoration: InputDecoration(hintText: l10n.importUriHint),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(l10n.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text),
            child: Text(l10n.save),
          ),
        ],
      ),
    );
    if (text == null || text.trim().isEmpty) return;
    try {
      final imported = await bridge.importFromOtpauthText(text: text);
      await _afterMutation();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(l10n.imported(imported.length))),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('${l10n.importFailed}: $e')),
        );
      }
    }
  }

  Future<void> _exportOtpauth() async {
    final l10n = context.l10n;
    final text = await bridge.exportOtpauthText();
    await Share.share(text, subject: 'OnePass otpauth');
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.exportShared)),
      );
    }
  }

  Future<void> _exportAegis() async {
    final l10n = context.l10n;
    final bytes = await bridge.exportAegis();
    final tmp = '${Directory.systemTemp.path}/onepass-aegis-'
        '${DateTime.now().millisecondsSinceEpoch}.json';
    await File(tmp).writeAsBytes(bytes);
    await Share.shareXFiles(
      [XFile(tmp, mimeType: 'application/json')],
      subject: 'OnePass Aegis export',
    );
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(l10n.exportShared)),
      );
    }
  }

  void _showIoSheet() {
    final l10n = context.l10n;
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.upload_file),
              title: Text(l10n.importPickFile),
              onTap: () {
                Navigator.pop(context);
                _importFile();
              },
            ),
            ListTile(
              leading: const Icon(Icons.content_paste),
              title: Text(l10n.importPickUriText),
              onTap: () {
                Navigator.pop(context);
                _importUriText();
              },
            ),
            ListTile(
              leading: const Icon(Icons.verified_user_outlined),
              title: Text(l10n.exportOtpauth),
              onTap: () {
                Navigator.pop(context);
                _exportOtpauth();
              },
            ),
            ListTile(
              leading: const Icon(Icons.data_object),
              title: Text(l10n.exportAegis),
              onTap: () {
                Navigator.pop(context);
                _exportAegis();
              },
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    final entriesAsync = ref.watch(entriesProvider);
    final wide = MediaQuery.widthOf(context) >= wideBreakpoint;

    final actions = _selected.isEmpty
        ? [
            IconButton(
              tooltip: l10n.lock,
              icon: const Icon(Icons.lock_outline),
              onPressed: _lock,
            ),
            IconButton(
              tooltip: l10n.settings,
              icon: const Icon(Icons.settings_outlined),
              onPressed: () => Navigator.push(
                context,
                MaterialPageRoute<void>(
                  builder: (_) => const SettingsScreen(),
                ),
              ),
            ),
            PopupMenuButton<String>(
              onSelected: (v) {
                if (v == 'io') _showIoSheet();
              },
              itemBuilder: (context) => [
                PopupMenuItem(value: 'io', child: Text(l10n.importAction)),
              ],
            ),
          ]
        : [
            IconButton(
              icon: const Icon(Icons.delete_outline),
              tooltip: l10n.deleteSelected,
              onPressed: _deleteSelected,
            ),
            IconButton(
              icon: const Icon(Icons.close),
              onPressed: () => setState(() => _selected.clear()),
            ),
          ];

    Widget listBody = Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
          child: TextField(
            controller: _searchController,
            decoration: InputDecoration(
              prefixIcon: const Icon(Icons.search),
              hintText: l10n.searchEntries,
            ),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),
        Expanded(
          child: entriesAsync.when(
            loading: () => const Center(child: CircularProgressIndicator()),
            error: (e, _) => Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Padding(
                    padding: const EdgeInsets.all(16),
                    child: Text('${l10n.errorLoading}: $e'),
                  ),
                  FilledButton.tonal(
                    onPressed: () =>
                        ref.read(entriesProvider.notifier).refresh(),
                    child: Text(l10n.retry),
                  ),
                ],
              ),
            ),
            data: (entries) {
              final query = _query.trim().toLowerCase();
              final filtered = query.isEmpty
                  ? entries
                  : entries
                      .where((e) =>
                          e.title.toLowerCase().contains(query) ||
                          e.username.toLowerCase().contains(query))
                      .toList();
              if (filtered.isEmpty) {
                return _EmptyState(hasEntries: entries.isNotEmpty);
              }
              return ListView.separated(
                itemCount: filtered.length,
                separatorBuilder: (_, _) => const Divider(height: 1),
                itemBuilder: (context, index) {
                  final entry = filtered[index];
                  return _EntryTile(
                    entry: entry,
                    selected: _selected.contains(entry.uuid),
                    isCurrent: ref.watch(selectedEntryProvider) == entry.uuid,
                    onLongPress: () => _toggleSelect(entry.uuid),
                    onTap: () {
                      ref.read(selectedEntryProvider.notifier).select(
                            entry.uuid,
                          );
                      if (!wide) {
                        Navigator.push(
                          context,
                          MaterialPageRoute<void>(
                            builder: (_) => const DetailPane(),
                          ),
                        );
                      }
                    },
                  );
                },
              );
            },
          ),
        ),
      ],
    );

    final appBar = AppBar(
      title: _selected.isEmpty ? Text(l10n.appTitle) : Text('${_selected.length}'),
      actions: actions,
    );

    if (!wide) {
      return Scaffold(
        appBar: appBar,
        body: listBody,
        floatingActionButton: FloatingActionButton(
          heroTag: 'add-entry',
          onPressed: () => openEntryEditor(context, ref),
          tooltip: l10n.addEntry,
          child: const Icon(Icons.add),
        ),
      );
    }

    // Desktop / tablet: list + inline detail pane.
    return Scaffold(
      appBar: appBar,
      body: Row(
        children: [
          SizedBox(width: 380, child: listBody),
          const VerticalDivider(width: 1),
          const Expanded(child: DetailPane()),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        heroTag: 'add-entry-wide',
        onPressed: () => openEntryEditor(context, ref),
        tooltip: l10n.addEntry,
        child: const Icon(Icons.add),
      ),
    );
  }
}

class _EntryTile extends StatelessWidget {
  const _EntryTile({
    required this.entry,
    required this.selected,
    required this.isCurrent,
    required this.onLongPress,
    required this.onTap,
  });

  final EntryDto entry;
  final bool selected;
  final bool isCurrent;
  final VoidCallback onLongPress;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final wide = MediaQuery.widthOf(context) >= 720;

    return ListTile(
      leading: Icon(
        entry.hasOtp ? Icons.phonelink_lock_outlined : Icons.key_outlined,
        color: scheme.primary,
      ),
      title: Text(
        entry.title.isEmpty ? '—' : entry.title,
        style: TextStyle(
          fontWeight: isCurrent && wide ? FontWeight.bold : null,
          color: selected ? scheme.primary : null,
        ),
      ),
      subtitle: Text(
        entry.username.isEmpty ? entry.url : entry.username,
        maxLines: 1,
        overflow: TextOverflow.ellipsis,
      ),
      trailing: entry.hasOtp
          ? Icon(Icons.timelapse, size: 18, color: scheme.tertiary)
          : null,
      selected: selected || (isCurrent && wide),
      onLongPress: onLongPress,
      onTap: onTap,
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.hasEntries});

  final bool hasEntries;

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.shield_moon_outlined,
              size: 56, color: Theme.of(context).colorScheme.outline),
          const SizedBox(height: 12),
          Text(
            hasEntries ? l10n.noSearchResults : l10n.noEntries,
            style: Theme.of(context).textTheme.titleMedium,
          ),
          if (!hasEntries) ...[
            const SizedBox(height: 4),
            Text(l10n.noEntriesHint, style: Theme.of(context).textTheme.bodySmall),
          ],
        ],
      ),
    );
  }
}
