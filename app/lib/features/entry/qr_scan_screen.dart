import 'package:flutter/material.dart';
import 'package:flutter_zxing/flutter_zxing.dart';

import '../../shared/ui_utils.dart';

/// Full-screen QR scanner for 2FA onboarding (Aegis-style flow): scans an
/// `otpauth://` QR code and pops with the raw URI, which is then parsed and
/// prefilled into the entry editor. Uses zxing-cpp via flutter_zxing
/// (lightweight, no ML model in the APK).
class QrScanScreen extends StatefulWidget {
  const QrScanScreen({super.key});

  @override
  State<QrScanScreen> createState() => _QrScanScreenState();
}

class _QrScanScreenState extends State<QrScanScreen> {
  bool _handled = false;

  void _onScan(Code code) {
    if (_handled) return;
    final raw = (code.text ?? '').trimLeft();
    if (raw.startsWith('otpauth://')) {
      _handled = true;
      Navigator.of(context).pop(raw);
    }
    // Non-otpauth QR codes are ignored; the camera keeps scanning.
  }

  @override
  Widget build(BuildContext context) {
    final l10n = context.l10n;
    return Scaffold(
      appBar: AppBar(title: Text(l10n.scanQr)),
      body: Stack(
        children: [
          ReaderWidget(
            codeFormat: Format.qrCode,
            tryHarder: true,
            onScan: _onScan,
          ),
          // Framing hint.
          Align(
            alignment: Alignment.bottomCenter,
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                decoration: BoxDecoration(
                  color: Colors.black54,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Text(
                  l10n.scanHint,
                  style: const TextStyle(color: Colors.white),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
