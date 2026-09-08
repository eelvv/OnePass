import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:path_provider/path_provider.dart';

import '../shared/logger.dart';
import '../src/rust/api/dto.dart';
import '../src/rust/api/engine.dart';
import '../src/rust/api/vault.dart' as bridge;

/// True while no vault session is open (initial state = locked).
final lockedProvider = NotifierProvider<LockedController, bool>(
  LockedController.new,
);

class LockedController extends Notifier<bool> {
  @override
  bool build() => true;

  void setLocked(bool value) => state = value;
}

/// The in-memory entry list mirror; refreshed after every mutation.
final entriesProvider =
    NotifierProvider<EntriesController, AsyncValue<List<EntryDto>>>(
  EntriesController.new,
);

class EntriesController extends Notifier<AsyncValue<List<EntryDto>>> {
  @override
  AsyncValue<List<EntryDto>> build() => const AsyncValue.data([]);

  Future<void> refresh() async {
    state = const AsyncValue.loading();
    try {
      state = AsyncValue.data(await bridge.listEntries());
    } catch (e, st) {
      Logger.e('listEntries failed', e, st);
      state = AsyncValue.error(e, st);
    }
  }

  void apply(List<EntryDto> entries) => state = AsyncValue.data(entries);
}

/// Currently selected entry uuid (drives the desktop detail pane).
final selectedEntryProvider =
    NotifierProvider<SelectedEntryController, String?>(
  SelectedEntryController.new,
);

class SelectedEntryController extends Notifier<String?> {
  @override
  String? build() => null;

  void select(String? uuid) => state = uuid;
}

/// Vault file path (app documents dir + onepass.kdbx), resolved once.
final vaultPathProvider = FutureProvider<String>((ref) async {
  final dir = await getApplicationDocumentsDirectory();
  return '${dir.path}/onepass.kdbx';
});

/// Engine version for the about tile.
final engineVersionProvider = FutureProvider<String>(
  (ref) async => engineVersion(),
);
