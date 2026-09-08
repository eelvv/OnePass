// ignore: unused_import
import 'package:intl/intl.dart' as intl;

import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get appTitle => 'OnePass';

  @override
  String get unlock => 'Unlock';

  @override
  String get unlockPrompt => 'Enter your master password';

  @override
  String get createVault => 'Create vault';

  @override
  String get createVaultPrompt => 'Set a vault name and master password';

  @override
  String get vaultName => 'Vault name';

  @override
  String get masterPassword => 'Master password';

  @override
  String get confirmPassword => 'Confirm password';

  @override
  String get passwordsDontMatch => 'Passwords do not match';

  @override
  String get vaultNameHint => 'My vault';

  @override
  String get wrongPassword => 'Wrong password';

  @override
  String get searchEntries => 'Search entries';

  @override
  String get noEntries => 'No entries yet';

  @override
  String get noEntriesHint => 'Tap + to add your first password or 2FA item';

  @override
  String get noSearchResults => 'No matches';

  @override
  String get lock => 'Lock';

  @override
  String get settings => 'Settings';

  @override
  String get addEntry => 'Add entry';

  @override
  String get editEntry => 'Edit entry';

  @override
  String get delete => 'Delete';

  @override
  String get deleteSelected => 'Delete selected';

  @override
  String deleteConfirm(int count) {
    return 'Delete $count selected entries?';
  }

  @override
  String get deleteEntryConfirm => 'Delete this entry?';

  @override
  String get cancel => 'Cancel';

  @override
  String get save => 'Save';

  @override
  String get saved => 'Saved';

  @override
  String get copied => 'Copied';

  @override
  String get importAction => 'Import…';

  @override
  String get exportAction => 'Export…';

  @override
  String get importPickFile => 'Pick a file (Aegis JSON / Google migration)';

  @override
  String get importPickUriText => 'Paste otpauth:// URIs';

  @override
  String get importUriHint => 'One otpauth:// URI per line';

  @override
  String imported(int count) {
    return 'Imported $count entries';
  }

  @override
  String get importFailed => 'Import failed';

  @override
  String get exportOtpauth => '2FA as otpauth:// URIs';

  @override
  String get exportAegis => '2FA as Aegis JSON';

  @override
  String get exportShared => 'Export shared / copied';

  @override
  String get entryType => 'Type';

  @override
  String get typePassword => 'Password';

  @override
  String get type2fa => '2FA';

  @override
  String get fieldTitle => 'Title';

  @override
  String get fieldUsername => 'Username';

  @override
  String get fieldPassword => 'Password';

  @override
  String get fieldUrl => 'URL';

  @override
  String get fieldNotes => 'Notes';

  @override
  String get fieldIssuer => 'Issuer';

  @override
  String get fieldAccount => 'Account';

  @override
  String get fieldSecret => 'Secret or otpauth:// URI';

  @override
  String get fieldKind => 'Kind';

  @override
  String get fieldAlgorithm => 'Algorithm';

  @override
  String get fieldDigits => 'Digits';

  @override
  String get fieldPeriod => 'Period (s)';

  @override
  String get fieldCounter => 'Counter';

  @override
  String get fieldPin => 'PIN';

  @override
  String get generate => 'Generate';

  @override
  String get keepSecretHint => 'Leave empty to keep the current secret';

  @override
  String get requiredField => 'Required';

  @override
  String get appearance => 'Appearance';

  @override
  String get themeMode => 'Theme';

  @override
  String get themeSystem => 'Follow system';

  @override
  String get themeLight => 'Light';

  @override
  String get themeDark => 'Dark';

  @override
  String get accentColor => 'Accent color';

  @override
  String get language => 'Language';

  @override
  String get langSystem => 'Follow system';

  @override
  String get security => 'Security';

  @override
  String get lockOnBackground => 'Lock when app goes to background';

  @override
  String get changeMasterPassword => 'Change master password';

  @override
  String get changePasswordHint => 'Applies and saves immediately';

  @override
  String get passwordChanged => 'Master password changed';

  @override
  String get about => 'About';

  @override
  String get engineVersion => 'Engine version';

  @override
  String get locked => 'Locked';

  @override
  String get selectToDelete => 'Long-press an entry to multi-select';

  @override
  String get errorLoading => 'Failed to load';

  @override
  String get retry => 'Retry';

  @override
  String get otpCopied => 'One-time code copied';

  @override
  String get errorGeneric => 'Operation failed';

  @override
  String get errorFileFormat =>
      'This file is not a valid vault, or it is corrupted';

  @override
  String get errorIo => 'File read/write failed';

  @override
  String get errorInvalidInput => 'Invalid input';

  @override
  String get importKdbx => 'Import vault (.kdbx)';

  @override
  String get exportKdbx => 'Export vault (.kdbx) copy';

  @override
  String get vaultImported => 'Vault imported';

  @override
  String get vaultPasswordPrompt => 'Password of the vault to import';

  @override
  String get logs => 'Logs';

  @override
  String get logFile => 'Log file';

  @override
  String get shareLogs => 'Share logs';

  @override
  String get clearLogs => 'Clear logs';

  @override
  String get logsCleared => 'Logs cleared';
}
