//! API lifecycle management (DW-110).
//!
//! Three concerns that span the lifetime of an API surface the gateway
//! fronts, all hand-rolled over existing substrates (no new
//! dependencies):
//!
//! - [`portal`] -- the developer portal: a read-only static HTML page
//!   auto-generated from the configured OpenAPI spec sources. It
//!   aggregates the existing OpenAPI specs (file paths or upstream
//!   `/openapi.json` endpoints) into a single listing of the APIs, their
//!   versions, and links to the specs. The portal is served at a
//!   configured reserved path (before route resolution, like
//!   `/healthz`).
//! - [`profiles`] -- environment profiles: dev/staging/prod config
//!   overlays. A `ProfileOverlay` carries a base config plus per-profile
//!   config patches; [`profiles::apply_profile`] merges the selected
//!   profile's patch onto the base. The profile is selected via the
//!   `DWARA_PROFILE` env var.
//! - [`journey`] -- the API journey recorder: records the request flow
//!   through the gateway (route match, authn, authz, transforms,
//!   upstream pick, response) as a JSON document, stored via the
//!   existing analytics raw table. A `Journey` is a vec of `JourneyStep`
//!   (phase, duration, result, detail) keyed by request id.
//!
//! ## Feature gate
//!
//! The `api_lifecycle` cargo feature must be enabled. Without it, the
//! module is not compiled and the top-level `lifecycle` config block is
//! accepted but inert (validation warns, mirroring the `a2a`/`graphql`
//! pattern).
//!
//! ## Dependency direction
//!
//! `lifecycle` depends on `config` (the config schema), `observability`
//! (metrics), and `analytics` (the raw table the journey recorder
//! stores into). It never imports `dataplane` -- the dataplane calls
//! into the journey recorder and the portal renderer, never the
//! reverse (the same direction the `ai` domain holds).

pub mod journey;
pub mod portal;
pub mod profiles;

pub use journey::{
    journey_dimension, Journey, JourneyConfig, JourneyRecorder, JourneyStep, JourneyStepResult,
};
pub use portal::{DevPortal, DevPortalConfig, DevPortalSpec, DevPortalSpecSource, LoadedSpec};
pub use profiles::{apply_profile, AppliedProfile, EnvProfile, ProfileOverlay};
