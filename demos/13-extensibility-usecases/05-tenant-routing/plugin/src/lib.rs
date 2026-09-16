//! tenant-router: decode the tenant, tag the request, rewrite the path.
//!
//! The tenant-aware-routing recipe (docs-site "Extension use cases and
//! recipes"): tenant identity arrives in a form static route match
//! criteria cannot express -- here a deliberately simple header
//! grammar, `x-org-domain: acme.com` -> tenant label `acme` (the
//! first DNS label). A signed-cookie or JWT-claim grammar would slot
//! in at the same place.
//!
//! At `request_headers` (after route resolution, before authn) the
//! plugin:
//!
//! 1. derives the tenant from the header (missing/unknown -> the
//!    `public` default),
//! 2. stamps `x-tenant` on the REQUEST (what downstream matching,
//!    logging, and the upstream see),
//! 3. rewrites `/portal/<rest>` -> `/tenant/<tenant>/<rest>` -- the
//!    path prefix IS the routing decision: per-tenant backends (or,
//!    in this demo, per-tenant mock endpoints) key off it. The
//!    gateway applies the rewrite to the FORWARDED request (the final
//!    say for the upstream target; route matching and the policy
//!    phases evaluated the original `/portal/...` target).
//!
//! At `response_headers` it stamps `x-tenant` on the RESPONSE so the
//! client can observe (and cache) the verdict. The two phases share
//! one per-request plugin instance, so the stashed tenant survives
//! from request to response.

use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};

const ORG_HEADER: &str = "x-org-domain";
const TENANT_HEADER: &str = "x-tenant";
const PORTAL_PREFIX: &str = "/portal/";
const TENANT_PREFIX: &str = "/tenant/";
const DEFAULT_TENANT: &str = "public";

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(TenantRoot) });
}

struct TenantRoot;

impl Context for TenantRoot {}

impl RootContext for TenantRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(TenantFilter { tenant: None }))
    }
}

/// The per-request filter. `tenant` is decoded at request_headers and
/// reused at response_headers (same instance).
struct TenantFilter {
    tenant: Option<String>,
}

/// The header grammar: the first DNS label of the org domain.
/// Missing or unparsable -> the safe default tenant.
fn tenant_from_org(value: Option<&str>) -> String {
    match value
        .filter(|v| !v.is_empty())
        .and_then(|v| v.split('.').next())
        .filter(|label| !label.is_empty())
    {
        Some(label) => label.to_string(),
        None => DEFAULT_TENANT.to_string(),
    }
}

impl Context for TenantFilter {}

impl HttpContext for TenantFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        let tenant = tenant_from_org(self.get_http_request_header(ORG_HEADER).as_deref());
        self.set_http_request_header(TENANT_HEADER, Some(&tenant));

        let path = self.get_http_request_header(":path").unwrap_or_default();
        if let Some(rest) = path.strip_prefix(PORTAL_PREFIX) {
            let rewritten = format!("{TENANT_PREFIX}{tenant}/{rest}");
            // Rewrite at the edge: the gateway applies the changed
            // :path to the FORWARDED request (the final say for the
            // upstream target, after route resolution with no route
            // re-match; see the "Header conventions" note in
            // crates/dwara-core/src/dataplane/plugin_dispatch.rs).
            self.set_http_request_header(":path", Some(&rewritten));
            let _ = proxy_wasm::hostcalls::log(
                LogLevel::Info,
                &format!("tenant={tenant} {path} -> {rewritten}"),
            );
        }
        self.tenant = Some(tenant);
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        if let Some(tenant) = &self.tenant {
            self.add_http_response_header(TENANT_HEADER, tenant);
        }
        Action::Continue
    }
}
