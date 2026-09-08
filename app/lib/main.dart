import 'package:flutter/material.dart';

import 'src/rust/api/engine.dart';
import 'src/rust/api/simple.dart';
import 'src/rust/frb_generated.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Bootstrap the Rust core: loads librust_lib_onepass.so into the process.
  // All engine logic lives in Rust; Dart only calls across the FFI boundary
  // (lib/src/rust is generated marshalling glue, not engine code).
  await RustLib.init();
  runApp(const OnePassApp());
}

/// Phase 0 scaffolding: proves the Rust bridge end-to-end on device.
/// Replaced by the real app shell in later phases.
class OnePassApp extends StatelessWidget {
  const OnePassApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OnePass',
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF3D5AFE)),
      ),
      darkTheme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF3D5AFE),
          brightness: Brightness.dark,
        ),
      ),
      home: const BridgeSmokeScreen(),
    );
  }
}

/// Fetches data across the FFI boundary and hands plain values to the view.
class BridgeSmokeScreen extends StatelessWidget {
  const BridgeSmokeScreen({super.key});

  @override
  Widget build(BuildContext context) {
    // Both are synchronous FFI calls executed by the Rust engine.
    return BridgeSmokeView(
      engineVersion: engineVersion(),
      greeting: greet(name: 'OnePass'),
    );
  }
}

/// Pure Flutter view (no bridge dependency) — host-testable.
class BridgeSmokeView extends StatelessWidget {
  const BridgeSmokeView({
    super.key,
    required this.engineVersion,
    required this.greeting,
  });

  final String engineVersion;
  final String greeting;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('OnePass')),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.shield_outlined, size: 64),
            const SizedBox(height: 16),
            Text('Engine v$engineVersion',
                style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(greeting, style: Theme.of(context).textTheme.bodyMedium),
            const SizedBox(height: 24),
            Text(
              'Phase 0 build: Flutter → FFI → Rust engine',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}
