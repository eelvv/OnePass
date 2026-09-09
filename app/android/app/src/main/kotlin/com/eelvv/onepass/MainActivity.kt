package com.eelvv.onepass

import android.app.Activity
import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * FlutterFragmentActivity is required by local_auth (biometric prompt).
 *
 * FLAG_SECURE (screenshot prevention) is applied at engine start from the
 * persisted preference, so a cold start is covered before Dart runs; the
 * Dart side also toggles it live through the security channel.
 */
class MainActivity : FlutterFragmentActivity() {
    private val prefs by lazy {
        getSharedPreferences("FlutterSharedPreferences", Activity.MODE_PRIVATE)
    }

    private fun applyFlagSecure(enabled: Boolean) {
        if (enabled) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        applyFlagSecure(prefs.getBoolean("flutter.flagSecure", false))
        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            "onepass/security",
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "setFlagSecure" -> {
                    val enabled = call.argument<Boolean>("enabled") ?: false
                    prefs.edit().putBoolean("flutter.flagSecure", enabled).apply()
                    applyFlagSecure(enabled)
                    result.success(true)
                }
                else -> result.notImplemented()
            }
        }
    }
}
