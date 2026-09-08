import '../l10n/app_localizations.dart';
import '../src/rust/api/error.dart';

/// Maps a bridge error to a short, localized, user-facing message.
/// Internal debug strings never reach the UI - they go to the log instead.
String friendlyError(AppLocalizations l10n, Object error) {
  if (error is BridgeError) {
    switch (error.kind) {
      case ErrorKind.wrongPassword:
        return l10n.wrongPassword;
      case ErrorKind.format:
        return l10n.errorFileFormat;
      case ErrorKind.io:
        return l10n.errorIo;
      case ErrorKind.invalidParameter:
        return l10n.errorInvalidInput;
      case ErrorKind.sessionState:
      case ErrorKind.other:
        return l10n.errorGeneric;
    }
  }
  return l10n.errorGeneric;
}
