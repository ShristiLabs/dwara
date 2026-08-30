//! Enterprise licensing gate (DW-032).
//!
//! The edition boundary as a runtime value: a [`LicenseGate`] holds an
//! optional verified license and answers the two questions every
//! enterprise feature asks before it engages — "are we in enterprise
//! mode?" ([`LicenseGate::is_enterprise`]) and "does this license grant
//! feature X?" ([`LicenseGate::has_feature`]). OSS builds (the default,
//! no `ent` cargo feature) compile a stub gate that is always
//! [`LicenseGate::none`]: every enterprise feature is inert by
//! construction, and no `licensing-core` dependency is pulled in.
//!
//! # Verification model
//!
//! When the `ent` feature is compiled in, `LicenseGate::from_file`
//! reads a license file, verifies its Ed25519 signature against the
//! product's public key, and checks expiry. The public key is NEVER
//! user-configurable in the YAML (an operator must not be able to
//! substitute their own key to forge a license): it comes from the
//! `DWARA_LICENSE_PUBLIC_KEY` environment variable or, when unset, the
//! compiled-in development key (local/CI only — production MUST set the
//! env var). The product ID is pinned to `"dwara"` so a license issued
//! for another ShristiLabs product cannot be replayed here.
//!
//! # Grace period
//!
//! A license that has passed its `expires_at` timestamp is not
//! immediately fatal. For a configurable grace window (default 7 days,
//! 0..=30) after expiry, enterprise features keep working and a warning
//! is logged — the operator has a buffer to renew. After the grace
//! window the gate degrades to OSS: [`LicenseGate::is_enterprise`]
//! returns false and every enterprise feature falls back to its OSS
//! behavior. This is the done-when: "Invalid/expired license degrades to
//! OSS feature set gracefully."
//!
//! # Startup vs reload
//!
//! The gate is built once at startup (dwara-bin) and rebuilt on every
//! config reload that carries a `license` block. A signature-invalid
//! license REFUSES to start (exit 1) at cold start; on reload, a
//! signature-invalid license keeps the running generation serving (the
//! same atomic-not-publish rollback as every other reload failure). A
//! missing license file refuses to start at cold start and keeps serving
//! on reload.
//!
//! # Feature claim flags
//!
//! The license's `features` vector carries claim strings. The gate
//! checks them by exact string match. The current enterprise features
//! and their claim strings:
//!
//! - `redis_rate_limiter` — DW-031 (not yet implemented; the gate
//!   provides the check, the feature will call it).
//! - `config_convergence` — DW-054 (not yet implemented; same).
//!
//! Future enterprise features add their claim string here and call
//! [`LicenseGate::has_feature`] at their config-validation site.

#[cfg(feature = "ent")]
use std::path::Path;

/// Default grace period (days) after a license expires before the gate
/// degrades to OSS. Configurable via `gateway.license.grace_period_days`
/// (0..=30); 0 means no grace (immediate degradation on expiry). The
/// canonical value lives in [`crate::config::limits`] (the lowest domain)
/// so both this module and `snapshot::validate` read the same number
/// without an upward import; this re-export is the convenience path for
/// gate consumers.
pub const DEFAULT_GRACE_PERIOD_DAYS: u32 = crate::config::limits::DEFAULT_LICENSE_GRACE_PERIOD_DAYS;

/// Maximum configurable grace period (days). Re-exported from
/// [`crate::config::limits`] for the same reason as
/// [`DEFAULT_GRACE_PERIOD_DAYS`].
pub const MAX_GRACE_PERIOD_DAYS: u32 = crate::config::limits::MAX_LICENSE_GRACE_PERIOD_DAYS;

/// The product ID this gateway verifies licenses for. Pinned so a
/// license issued for another ShristiLabs product cannot be replayed
/// against dwara even in the unlikely event of key reuse.
pub const PRODUCT_ID: &str = "dwara";

/// The environment variable holding the base64-encoded Ed25519 public
/// key for license verification. When unset, the compiled-in development
/// key is used (local/CI only; production MUST set this).
pub const PUBLIC_KEY_ENV_VAR: &str = "DWARA_LICENSE_PUBLIC_KEY";

/// License claim string for the Redis rate-limiter backend (DW-031).
pub const FEATURE_REDIS_RATE_LIMITER: &str = "redis_rate_limiter";

/// License claim string for config convergence (DW-054).
pub const FEATURE_CONFIG_CONVERGENCE: &str = "config_convergence";

/// The runtime status of the license gate, mirrored by the
/// `dwara_license_status` metric (0..=3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseStatus {
    /// No license configured (OSS mode). Metric value 0.
    NoLicense,
    /// A valid, unexpired license is loaded. Metric value 1.
    Valid,
    /// The license is expired but within the grace period; enterprise
    /// features still work. Metric value 2.
    ExpiredWithinGrace,
    /// The license is expired past the grace period; the gate has
    /// degraded to OSS. Metric value 3.
    ExpiredPastGrace,
}

impl LicenseStatus {
    /// The numeric value exported as the `dwara_license_status` gauge.
    pub fn as_metric(self) -> i64 {
        match self {
            LicenseStatus::NoLicense => 0,
            LicenseStatus::Valid => 1,
            LicenseStatus::ExpiredWithinGrace => 2,
            LicenseStatus::ExpiredPastGrace => 3,
        }
    }
}

/// Error produced while loading or verifying a license.
#[derive(Debug)]
pub enum LicenseLoadError {
    /// The license file could not be read (not found, permission
    /// denied, ...). At startup this is fatal (exit 1).
    NotFound(String),
    /// The license signature is invalid (tampered, wrong key, or
    /// malformed). At startup this is fatal (exit 1).
    InvalidSignature,
    /// The license file could not be parsed as JSON / the claims
    /// shape was wrong.
    Parse(String),
    /// The license is for a different product (the `product_id` claim
    /// does not match [`PRODUCT_ID`]).
    ProductMismatch { expected: String, actual: String },
    /// The license is for a different instance (replay prevention).
    InstanceMismatch { expected: String, actual: String },
    /// The public key could not be loaded (env var set but invalid).
    KeyError(String),
    /// An I/O error other than not-found.
    Io(String),
}

impl std::fmt::Display for LicenseLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseLoadError::NotFound(p) => {
                write!(f, "license file not found: {p}")
            }
            LicenseLoadError::InvalidSignature => write!(f, "license signature invalid"),
            LicenseLoadError::Parse(m) => write!(f, "license file parse error: {m}"),
            LicenseLoadError::ProductMismatch { expected, actual } => write!(
                f,
                "license product mismatch: expected {expected}, got {actual}"
            ),
            LicenseLoadError::InstanceMismatch { expected, actual } => write!(
                f,
                "license instance ID mismatch: expected {expected}, got {actual}"
            ),
            LicenseLoadError::KeyError(m) => write!(f, "license key error: {m}"),
            LicenseLoadError::Io(m) => write!(f, "license IO error: {m}"),
        }
    }
}

impl std::error::Error for LicenseLoadError {}

/// The enterprise licensing gate.
///
/// In OSS builds (no `ent` feature) this is a zero-sized stub: every
/// method returns the OSS answer and no `licensing-core` types appear.
/// In `ent` builds it holds an optional verified license plus the grace
/// window and the current status.
#[derive(Debug, Clone)]
pub struct LicenseGate {
    /// The verified license, if any. `None` in OSS builds or when no
    /// license is configured / the license has degraded past grace.
    #[cfg(feature = "ent")]
    license: Option<licensing_core::License>,
    /// Grace period in days (0..=30). Carried so reload can re-evaluate
    /// expiry against the current clock without re-reading config.
    grace_period_days: u32,
    /// The current status (drives the metric and the is_enterprise
    /// answer when a license is expired past grace).
    status: LicenseStatus,
}

impl Default for LicenseGate {
    fn default() -> Self {
        Self::none()
    }
}

impl LicenseGate {
    /// No license: OSS mode. All enterprise features are inert. This is
    /// the only constructor available in OSS builds.
    pub fn none() -> Self {
        LicenseGate {
            #[cfg(feature = "ent")]
            license: None,
            grace_period_days: DEFAULT_GRACE_PERIOD_DAYS,
            status: LicenseStatus::NoLicense,
        }
    }

    /// The configured grace period (days).
    pub fn grace_period_days(&self) -> u32 {
        self.grace_period_days
    }

    /// The current license status (mirrors the `dwara_license_status`
    /// metric).
    pub fn status(&self) -> LicenseStatus {
        self.status
    }

    /// True if a valid license is loaded AND enterprise features should
    /// be active. A license expired within the grace period still
    /// returns true; a license expired past grace (or no license at all)
    /// returns false.
    pub fn is_enterprise(&self) -> bool {
        match self.status {
            LicenseStatus::Valid | LicenseStatus::ExpiredWithinGrace => true,
            LicenseStatus::NoLicense | LicenseStatus::ExpiredPastGrace => false,
        }
    }

    /// True if the loaded license grants the named feature claim. Returns
    /// false when there is no license, when the license has degraded past
    /// grace, or when the feature is not in the license's `features`
    /// list.
    pub fn has_feature(&self, feature: &str) -> bool {
        if !self.is_enterprise() {
            return false;
        }
        #[cfg(feature = "ent")]
        {
            self.license
                .as_ref()
                .map(|l| l.has_feature(feature))
                .unwrap_or(false)
        }
        #[cfg(not(feature = "ent"))]
        {
            // Unreachable: is_enterprise() is always false without ent.
            let _ = feature;
            false
        }
    }

    /// True if the license has passed its `expires_at` timestamp (whether
    /// or not it is still within the grace period). Returns false when
    /// there is no license.
    pub fn is_expired(&self) -> bool {
        match self.status {
            LicenseStatus::ExpiredWithinGrace | LicenseStatus::ExpiredPastGrace => true,
            LicenseStatus::Valid | LicenseStatus::NoLicense => false,
        }
    }

    /// The customer name from the license claims, if a license is
    /// loaded. Used for the startup log line.
    #[cfg(feature = "ent")]
    pub fn customer(&self) -> Option<&str> {
        self.license.as_ref().map(|l| l.claims.customer.as_str())
    }

    /// The plan name from the license claims, if a license is loaded.
    #[cfg(feature = "ent")]
    pub fn plan(&self) -> Option<&str> {
        self.license.as_ref().map(|l| l.claims.plan.as_str())
    }

    /// The feature claim list from the license, if loaded. Used for the
    /// startup log line.
    #[cfg(feature = "ent")]
    pub fn features(&self) -> Vec<String> {
        self.license
            .as_ref()
            .map(|l| l.claims.features.clone())
            .unwrap_or_default()
    }

    /// The license's expiry timestamp (RFC 3339), if loaded. Used for
    /// the grace-period warning log line.
    #[cfg(feature = "ent")]
    pub fn expires_at(&self) -> Option<String> {
        self.license
            .as_ref()
            .map(|l| l.claims.expires_at.to_rfc3339())
    }

    /// Verify and load a license file (ent feature only). Reads the
    /// public key from [`PUBLIC_KEY_ENV_VAR`] (falling back to the
    /// compiled-in development key when unset), pins the product ID to
    /// [`PRODUCT_ID`], verifies the Ed25519 signature, and evaluates
    /// expiry against the grace window.
    ///
    /// Returns:
    /// - `Ok(gate)` with status [`LicenseStatus::Valid`] if the license
    ///   is unexpired.
    /// - `Ok(gate)` with status [`LicenseStatus::ExpiredWithinGrace`]
    ///   if expired but within `grace_period_days` of `expires_at`.
    /// - `Ok(gate)` with status [`LicenseStatus::ExpiredPastGrace`] if
    ///   expired past the grace window (the gate is inert; the caller
    ///   logs the degradation).
    /// - `Err(InvalidSignature)` if the signature does not verify.
    /// - `Err(NotFound)` if the file is missing.
    /// - `Err(Parse)` if the file is not a valid license JSON.
    /// - `Err(ProductMismatch)` / `Err(InstanceMismatch)` for claim
    ///   mismatches.
    ///
    /// Note: the underlying `licensing-core` verifier treats expiry as
    /// an error. This gate catches the `Expired` error and re-classifies
    /// it against the grace window, so an expired-but-within-grace
    /// license loads successfully (the whole point of the grace period).
    #[cfg(feature = "ent")]
    pub fn from_file(path: &Path, grace_period_days: u32) -> Result<Self, LicenseLoadError> {
        let verifier = licensing_core::LicenseVerifier::from_env_var(PUBLIC_KEY_ENV_VAR)
            .map_err(|e| LicenseLoadError::KeyError(e.to_string()))?
            .with_expected_product_id(PRODUCT_ID);

        let license = match verifier.verify(path) {
            Ok(lic) => lic,
            Err(licensing_core::LicenseError::NotFound(p)) => {
                return Err(LicenseLoadError::NotFound(p));
            }
            Err(licensing_core::LicenseError::InvalidSignature) => {
                return Err(LicenseLoadError::InvalidSignature);
            }
            Err(licensing_core::LicenseError::Parse(m)) => {
                return Err(LicenseLoadError::Parse(m));
            }
            Err(licensing_core::LicenseError::ProductMismatch { expected, actual }) => {
                return Err(LicenseLoadError::ProductMismatch { expected, actual });
            }
            Err(licensing_core::LicenseError::InstanceMismatch { expected, actual }) => {
                return Err(LicenseLoadError::InstanceMismatch { expected, actual });
            }
            Err(licensing_core::LicenseError::Io(e)) => {
                return Err(LicenseLoadError::Io(e.to_string()));
            }
            Err(licensing_core::LicenseError::Expired { expires_at }) => {
                // Re-classify against the grace window. The license
                // signature was valid; only expiry failed. We still
                // need the claims to answer feature/customer queries
                // during the grace window, so re-parse the file for
                // the claims (the signature was already verified).
                let claims = read_claims(path)?;
                let now = chrono::Utc::now();
                let grace_end = expires_at + chrono::Duration::days(grace_period_days as i64);
                let status = if now <= grace_end {
                    LicenseStatus::ExpiredWithinGrace
                } else {
                    LicenseStatus::ExpiredPastGrace
                };
                // Only keep the license for feature checks if within
                // grace; past grace the gate is inert (OSS).
                let license = if status == LicenseStatus::ExpiredWithinGrace {
                    Some(licensing_core::License {
                        claims,
                        verified_at: now,
                    })
                } else {
                    None
                };
                return Ok(LicenseGate {
                    license,
                    grace_period_days,
                    status,
                });
            }
            Err(e) => {
                // Canonical/KeyError/Base64: treat as a load failure.
                return Err(LicenseLoadError::Parse(e.to_string()));
            }
        };

        Ok(LicenseGate {
            license: Some(license),
            grace_period_days,
            status: LicenseStatus::Valid,
        })
    }

    /// Build a gate from an already-verified in-memory license file
    /// (ent feature only). Used by tests: the caller signs a license
    /// with the dev signer, then this method verifies it and evaluates
    /// the grace window. Equivalent to [`Self::from_file`] but takes an
    /// in-memory [`licensing_core::LicenseFile`] instead of a path.
    #[cfg(feature = "ent")]
    pub fn from_file_claims(
        file: &licensing_core::LicenseFile,
        grace_period_days: u32,
    ) -> Result<Self, LicenseLoadError> {
        let verifier = licensing_core::LicenseVerifier::from_env_var(PUBLIC_KEY_ENV_VAR)
            .map_err(|e| LicenseLoadError::KeyError(e.to_string()))?
            .with_expected_product_id(PRODUCT_ID);

        match verifier.verify_claims(file) {
            Ok(lic) => Ok(LicenseGate {
                license: Some(lic),
                grace_period_days,
                status: LicenseStatus::Valid,
            }),
            Err(licensing_core::LicenseError::Expired { expires_at }) => {
                let now = chrono::Utc::now();
                let grace_end = expires_at + chrono::Duration::days(grace_period_days as i64);
                let status = if now <= grace_end {
                    LicenseStatus::ExpiredWithinGrace
                } else {
                    LicenseStatus::ExpiredPastGrace
                };
                let license = if status == LicenseStatus::ExpiredWithinGrace {
                    Some(licensing_core::License {
                        claims: file.claims.clone(),
                        verified_at: now,
                    })
                } else {
                    None
                };
                Ok(LicenseGate {
                    license,
                    grace_period_days,
                    status,
                })
            }
            Err(licensing_core::LicenseError::InvalidSignature) => {
                Err(LicenseLoadError::InvalidSignature)
            }
            Err(licensing_core::LicenseError::ProductMismatch { expected, actual }) => {
                Err(LicenseLoadError::ProductMismatch { expected, actual })
            }
            Err(licensing_core::LicenseError::InstanceMismatch { expected, actual }) => {
                Err(LicenseLoadError::InstanceMismatch { expected, actual })
            }
            Err(e) => Err(LicenseLoadError::Parse(e.to_string())),
        }
    }
}

/// Read just the claims from a license file (the signature was already
/// verified by the time we get here; we only need the claims to answer
/// feature queries during the grace window).
#[cfg(feature = "ent")]
fn read_claims(path: &Path) -> Result<licensing_core::LicenseClaims, LicenseLoadError> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            LicenseLoadError::NotFound(path.display().to_string())
        } else {
            LicenseLoadError::Io(e.to_string())
        }
    })?;
    let file: licensing_core::LicenseFile =
        serde_json::from_str(&contents).map_err(|e| LicenseLoadError::Parse(e.to_string()))?;
    Ok(file.claims)
}

#[cfg(test)]
mod tests {
    // White-box unit tests of the grace-period classification logic live
    // here (not in tests/) because they exercise the private status
    // transitions that the public from_file API only reaches through the
    // licensing-core verifier. The end-to-end license load/verify/feature
    // tests are in tests/licensing.rs (ent-feature-gated).

    use super::*;

    #[test]
    fn none_gate_is_oss() {
        let gate = LicenseGate::none();
        assert!(!gate.is_enterprise());
        assert!(!gate.is_expired());
        assert!(!gate.has_feature("redis_rate_limiter"));
        assert_eq!(gate.status(), LicenseStatus::NoLicense);
        assert_eq!(gate.status().as_metric(), 0);
    }

    #[test]
    fn status_metric_values() {
        assert_eq!(LicenseStatus::NoLicense.as_metric(), 0);
        assert_eq!(LicenseStatus::Valid.as_metric(), 1);
        assert_eq!(LicenseStatus::ExpiredWithinGrace.as_metric(), 2);
        assert_eq!(LicenseStatus::ExpiredPastGrace.as_metric(), 3);
    }

    #[test]
    fn is_enterprise_matrix() {
        assert!(LicenseGate::with_status(LicenseStatus::Valid).is_enterprise());
        assert!(LicenseGate::with_status(LicenseStatus::ExpiredWithinGrace).is_enterprise());
        assert!(!LicenseGate::with_status(LicenseStatus::NoLicense).is_enterprise());
        assert!(!LicenseGate::with_status(LicenseStatus::ExpiredPastGrace).is_enterprise());
    }

    #[test]
    fn is_expired_matrix() {
        assert!(!LicenseGate::with_status(LicenseStatus::Valid).is_expired());
        assert!(LicenseGate::with_status(LicenseStatus::ExpiredWithinGrace).is_expired());
        assert!(LicenseGate::with_status(LicenseStatus::ExpiredPastGrace).is_expired());
        assert!(!LicenseGate::with_status(LicenseStatus::NoLicense).is_expired());
    }

    /// Test helper: build a gate with a given status (ent builds carry
    /// no license for the past-grace / no-license cases; the valid /
    /// within-grace cases still answer is_enterprise correctly without
    /// a license because the status drives the answer, not the license
    /// field — has_feature is the only method that consults the license,
    /// and it returns false when the license is None).
    impl LicenseGate {
        #[cfg(test)]
        fn with_status(status: LicenseStatus) -> Self {
            LicenseGate {
                #[cfg(feature = "ent")]
                license: None,
                grace_period_days: DEFAULT_GRACE_PERIOD_DAYS,
                status,
            }
        }
    }
}
