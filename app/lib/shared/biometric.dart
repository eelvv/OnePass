import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

/// Biometric unlock service.
///
/// Enable flow: user authenticates once with biometrics, then re-enters the
/// master password; the password is stored in Keystore-backed secure storage.
/// Unlock flow: authenticate with biometrics, read the stored password, and
/// open the vault with it. Disabling forgets the stored password.
///
/// Note: on Android the storage key survives biometric re-enrollment (no
/// crypto-object invalidation) - acceptable for v1, revisit with
/// `enforceBiometrics` if stronger binding is needed.
class BiometricService {
  BiometricService._();

  static const _storage = FlutterSecureStorage();
  static const _key = 'onepass.biometricMasterPassword';
  static final _auth = LocalAuthentication();

  /// Whether the device supports biometric authentication.
  static Future<bool> canAuthenticate() async {
    try {
      final supported = await _auth.isDeviceSupported();
      final canCheck = await _auth.canCheckBiometrics;
      return supported && canCheck;
    } on PlatformException {
      return false;
    }
  }

  /// Shows the biometric prompt. Returns true on success.
  static Future<bool> authenticate(String localizedReason) async {
    try {
      return await _auth.authenticate(
        localizedReason: localizedReason,
        biometricOnly: true,
        persistAcrossBackgrounding: true,
      );
    } on PlatformException {
      return false;
    }
  }

  static Future<void> storePassword(String password) =>
      _storage.write(key: _key, value: password);

  static Future<String?> readPassword() => _storage.read(key: _key);

  static Future<void> forget() => _storage.delete(key: _key);
}
