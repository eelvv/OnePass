import 'dart:io';

import 'package:path_provider/path_provider.dart';

/// Append-only file logger: `<app support>/logs/onepass.log` (rotated at 1 MB).
/// Secrets (master password, entry secrets, OTP codes) are never logged.
class Logger {
  Logger._();

  /// Absolute path of the active log file (null before init).
  static String? path;

  static File? _file;
  static final List<String> _pending = [];
  static Future<void>? _tail;

  /// Resolves the log file and rotates if oversized. Returns the log path.
  static Future<String> init() async {
    final dir = await getApplicationSupportDirectory();
    final logs = Directory('${dir.path}/logs');
    await logs.create(recursive: true);
    final f = File('${logs.path}/onepass.log');
    try {
      if (await f.exists() && await f.length() > 1024 * 1024) {
        final old = File('${logs.path}/onepass.1.log');
        if (await old.exists()) await old.delete();
        await f.rename(old.path);
      }
    } catch (_) {
      // Rotation is best-effort; never block startup on it.
    }
    _file = f;
    path = f.path;
    _log('I', 'session start');
    return f.path;
  }

  static void i(String message) => _log('I', message);
  static void w(String message) => _log('W', message);
  static void e(String message, [Object? error, StackTrace? stack]) =>
      _log('E', '$message ${error ?? ''} ${stack ?? ''}');

  static void _log(String level, String message) {
    _pending.add('${DateTime.now().toIso8601String()} [$level] $message');
    _tail = (_tail ?? Future<void>.value()).then((_) async {
      final file = _file;
      final batch = _pending.join('\n');
      _pending.clear();
      if (file == null || batch.isEmpty) return;
      await file.writeAsString('$batch\n', mode: FileMode.append);
    });
  }

  static Future<void> clear() async {
    final file = _file;
    if (file != null && await file.exists()) {
      await file.writeAsString('', mode: FileMode.write);
      i('logs cleared');
    }
  }
}
/// Convenience for UI tiles that need the path without touching internals.
Future<String> logFilePath() async {
  final existing = Logger.path;
  if (existing != null) return existing;
  return Logger.init();
}
