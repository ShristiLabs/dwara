//! Environment profiles (DW-110): dev/staging/prod config overlays.
//!
//! A [`ProfileOverlay`] carries a base config plus per-profile config
//! patches (each patch is a partial [`Gateway`](crate::config::Gateway)
//! serialized as YAML). [`apply_profile`] merges the selected profile's
//! patch onto the base config: the patch's collections (listeners,
//! routes, upstreams, etc.) REPLACE the base's (not append -- a profile
//! is a full topology overlay, not a delta), and the patch's scalar
//! fields override the base's when set.
//!
//! The profile is selected via the `DWARA_PROFILE` env var (one of
//! `dev`, `staging`, `prod`; case-insensitive). When unset, no overlay
//! is applied (the base config is used as-is).
//!
//! The config schema type ([`ProfileOverlay`]) lives in
//! [`crate::config`] (always present, so configs round-trip without
//! the `api_lifecycle` feature). This module re-exports it as the
//! runtime-facing alias the overlay applier consumes.

use serde_json::Value;

pub use crate::config::LifecycleProfilesConfig as ProfileOverlay;

/// The environment profile enum (dev/staging/prod).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnvProfile {
    Dev,
    Staging,
    Prod,
}

impl EnvProfile {
    /// The config key for this profile (matches the `profiles` map
    /// keys: `dev`, `staging`, `prod`).
    pub fn key(self) -> &'static str {
        match self {
            EnvProfile::Dev => "dev",
            EnvProfile::Staging => "staging",
            EnvProfile::Prod => "prod",
        }
    }

    /// Parse a profile from the `DWARA_PROFILE` env var value
    /// (case-insensitive). Returns `None` when the value is empty or
    /// not a recognized profile name.
    pub fn from_env_var(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "" => None,
            "dev" => Some(EnvProfile::Dev),
            "staging" => Some(EnvProfile::Staging),
            "prod" => Some(EnvProfile::Prod),
            _ => None,
        }
    }
}

/// The result of applying a profile overlay: the merged config as a
/// YAML string, plus the profile that was selected (or `None` when no
/// profile was selected).
#[derive(Debug, Clone, PartialEq)]
pub struct AppliedProfile {
    pub config_yaml: String,
    pub profile: Option<EnvProfile>,
}

/// Apply the selected profile's patch onto the base config.
///
/// The profile is read from the `DWARA_PROFILE` env var. When unset,
/// the base config is returned unchanged. When set to a recognized
/// profile (`dev`/`staging`/`prod`, case-insensitive) AND that profile
/// has a patch in the overlay, the patch is merged onto the base. When
/// set to a recognized profile with NO patch, the base is returned
/// unchanged (the profile is selected but defines no overrides -- a
/// no-op overlay). When set to an unrecognized value, the base is
/// returned unchanged (an unknown profile is a no-op, not an error --
/// the operator may have a typo, but the gateway still starts on the
/// base config).
///
/// The merge is a shallow JSON merge: the base and patch are each
/// parsed into JSON values, the patch's top-level keys overwrite the
/// base's, and the result is serialized back to YAML. Collection
/// fields (listeners, routes, upstreams, etc.) in the patch REPLACE
/// the base's collections (not append) -- a profile is a full topology
/// overlay.
pub fn apply_profile(overlay: &ProfileOverlay) -> Result<AppliedProfile, String> {
    let profile = std::env::var("DWARA_PROFILE")
        .ok()
        .and_then(|v| EnvProfile::from_env_var(&v));
    let Some(profile) = profile else {
        return Ok(AppliedProfile {
            config_yaml: overlay.base_config.clone(),
            profile: None,
        });
    };
    let Some(patch_yaml) = overlay.profile_overrides.get(profile.key()) else {
        return Ok(AppliedProfile {
            config_yaml: overlay.base_config.clone(),
            profile: Some(profile),
        });
    };
    let merged = merge_yaml(&overlay.base_config, patch_yaml)?;
    Ok(AppliedProfile {
        config_yaml: merged,
        profile: Some(profile),
    })
}

/// Merge a patch YAML onto a base YAML: shallow top-level key merge
/// (patch keys overwrite base keys; keys only in the base are
/// preserved). Returns the merged config as a YAML string.
fn merge_yaml(base_yaml: &str, patch_yaml: &str) -> Result<String, String> {
    let base: Value =
        serde_yaml_ng::from_str(base_yaml).map_err(|e| format!("base config parse failed: {e}"))?;
    let patch: Value = serde_yaml_ng::from_str(patch_yaml)
        .map_err(|e| format!("profile patch parse failed: {e}"))?;
    let merged = merge_json(&base, &patch);
    // Serialize back through serde_json -> serde_yaml_ng to get stable
    // YAML output (serde_yaml_ng's own serializer on a serde_json::Value
    // round-trips cleanly).
    serde_yaml_ng::to_string(&merged).map_err(|e| format!("merged serialize failed: {e}"))
}

/// Shallow JSON merge: patch's top-level keys overwrite base's; keys
/// only in the base are preserved. Non-object bases or patches are
/// returned as the patch (the patch wins outright when either side is
/// not an object).
fn merge_json(base: &Value, patch: &Value) -> Value {
    match (base, patch) {
        (Value::Object(base_map), Value::Object(patch_map)) => {
            let mut out = base_map.clone();
            for (k, v) in patch_map {
                out.insert(k.clone(), v.clone());
            }
            Value::Object(out)
        }
        _ => patch.clone(),
    }
}
