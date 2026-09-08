import 'package:flutter/material.dart';

/// Accent color presets selectable in Settings (design system: trust blue as
/// the default, per the OnePass design tokens).
class AccentPreset {
  const AccentPreset(this.name, this.seed);
  final String name;
  final Color seed;
}

const accentPresets = <AccentPreset>[
  AccentPreset('Trust Blue', Color(0xFF1E3A8A)),
  AccentPreset('Indigo', Color(0xFF4F46E5)),
  AccentPreset('Teal', Color(0xFF0F766E)),
  AccentPreset('Violet', Color(0xFF7C3AED)),
  AccentPreset('Graphite', Color(0xFF334155)),
];

ThemeData buildOnePassTheme(Color seed, Brightness brightness) {
  final scheme = ColorScheme.fromSeed(seedColor: seed, brightness: brightness);
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    visualDensity: VisualDensity.standard,
    inputDecorationTheme: InputDecorationTheme(
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
      isDense: true,
    ),
    cardTheme: CardThemeData(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: scheme.outlineVariant.withValues(alpha: 0.5)),
      ),
    ),
    snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating),
  );
}
