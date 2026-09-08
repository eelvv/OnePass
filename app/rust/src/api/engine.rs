//! Engine information exposed to the Flutter app.

/// Semantic version of the bundled OnePass engine (`onepass-engine` crate).
#[flutter_rust_bridge::frb(sync)]
pub fn engine_version() -> String {
    onepass_engine::VERSION.to_string()
}
