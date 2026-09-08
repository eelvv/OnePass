/// Barrel file: import this single module for all app-wide state and
/// shared UI helpers.
library;

export '../shared/ui_utils.dart'
    show L10nX, copyWithAutoClear, formatDotnetDate, otpRemaining;
export 'settings.dart';
export 'vault.dart';
