//! entitlement-guard: per-request external decision with a TTL cache.
//!
//! The per-request-decision recipe (docs-site "Extension use cases and
//! recipes", use case 7): the verdict genuinely must be computed per
//! request by an external service -- here a mock entitlement service,
//! standing in for experiment bucketing, fraud scores, or per-user
//! quotas. The plugin asks it over `proxy_http_call` at
//! `request_headers` (after route resolution, before authn) and
//! applies the verdict as request headers the upstream (and the
//! access log) can see:
//!
//! - `x-user` on the inbound request names the principal;
//! - `x-entitlement: allow|deny` is the applied verdict;
//! - `x-entitlement-source: service|cache` says whether THIS request
//!   hit the decision service or the in-plugin cache.
//!
//! ## The pause/resume contract
//!
//! `dispatch_http_call` registers the exchange and the phase returns
//! `Action::Pause`; the host performs the HTTP exchange, then delivers
//! `proxy_on_http_call_response(token, ...)`, where the plugin reads
//! the response (`x-verdict` header, MapType 6) and resumes Continue.
//! A callout that cannot complete (timeout, refused) never reaches
//! the callback: the gateway fails the route closed (500
//! `plugin_failed`) -- the documented deviation from Envoy's empty
//! callback, and the reason this plugin sizes its timeout (400 ms)
//! deliberately.
//!
//! ## The TTL cache
//!
//! `proxy_get/set_shared_data` is VM-scoped (one map shared by every
//! per-request instance of this module), so a `<verdict>|<expiry>`
//! entry cached on one request is visible to the next. Fresh entries
//! (expiry in the future) answer without a callout -- the recipe's
//! latency and availability lever. The TTL is deliberately short (2s)
//! so the demo can show both sides of the window.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};

/// The decision service's base URI (the demo's mock on 18262).
const DECISION_URI: &str = "http://127.0.0.1:18262";
/// Callout timeout: the fail-closed budget for one decision.
const CALLOUT_TIMEOUT: Duration = Duration::from_millis(400);
/// Cache entry lifetime.
const CACHE_TTL_MS: u128 = 2_000;
/// Shared-data key prefix for cached verdicts.
const CACHE_KEY_PREFIX: &str = "ent:";

#[no_mangle]
pub fn _start() {
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(EntitlementRoot) });
}

struct EntitlementRoot;

impl Context for EntitlementRoot {}

impl RootContext for EntitlementRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(EntitlementFilter {
            user: String::new(),
        }))
    }
}

/// The per-request filter. `user` is captured at request_headers and
/// reused in the callout callback (one instance per request).
struct EntitlementFilter {
    user: String,
}

/// Milliseconds since the Unix epoch (the shared-data expiry clock).
fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

impl Context for EntitlementFilter {
    /// The delivered callout response: read the verdict header, apply
    /// it, cache it, and resume (returning Continue from this callback
    /// resumes the paused phase -- the SDK expresses the decision
    /// through the hostcalls made here, not a return value).
    fn on_http_call_response(
        &mut self,
        _token_id: u32,
        _num_headers: usize,
        _body_size: usize,
        _num_trailers: usize,
    ) {
        let verdict = self
            .get_http_call_response_header("x-verdict")
            .filter(|v| v == "allow" || v == "deny")
            .unwrap_or_else(|| "deny".to_string());
        // Cache the verdict behind the next request (VM-scoped shared
        // data: every instance of this module sees the entry) -- even
        // the deny, so a banned user does not hammer the service.
        let entry = format!("{verdict}|{}", now_ms() + CACHE_TTL_MS);
        let _ = self.set_shared_data(
            &format!("{CACHE_KEY_PREFIX}{}", self.user),
            Some(entry.as_bytes()),
            None,
        );
        let _ = proxy_wasm::hostcalls::log(
            LogLevel::Info,
            &format!("user={} verdict={} (service)", self.user, verdict),
        );
        if verdict == "deny" {
            // A deny is decided at the edge: short-circuit (the
            // upstream is never dialed).
            self.send_http_response(
                403,
                vec![("x-entitlement-source", "service")],
                Some(b"entitlement denied"),
            );
            return;
        }
        self.set_http_request_header("x-entitlement", Some(&verdict));
        self.set_http_request_header("x-entitlement-source", Some("service"));
    }
}

impl HttpContext for EntitlementFilter {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        self.user = self
            .get_http_request_header("x-user")
            .filter(|u| !u.is_empty())
            .unwrap_or_else(|| "anonymous".to_string());

        // Cache hit: a fresh entry answers without a callout.
        let (cached, _cas) =
            self.get_shared_data(&format!("{CACHE_KEY_PREFIX}{}", self.user));
        if let Some(entry) = cached.and_then(|bytes| String::from_utf8(bytes).ok()) {
            if let Some((verdict, expiry)) = entry.split_once('|') {
                if let Ok(expiry_ms) = expiry.parse::<u128>() {
                    if expiry_ms > now_ms() {
                        let _ = proxy_wasm::hostcalls::log(
                            LogLevel::Info,
                            &format!("user={} verdict={} (cache)", self.user, verdict),
                        );
                        if verdict == "deny" {
                            self.send_http_response(
                                403,
                                vec![("x-entitlement-source", "cache")],
                                Some(b"entitlement denied"),
                            );
                            return Action::Continue;
                        }
                        self.set_http_request_header("x-entitlement", Some(verdict));
                        self.set_http_request_header("x-entitlement-source", Some("cache"));
                        return Action::Continue;
                    }
                }
            }
        }

        // Cache miss: dispatch the decision callout and pause. The
        // gateway performs the exchange and delivers
        // proxy_on_http_call_response (see the Context impl above). A
        // dispatch that cannot even register (BadArgument) answers
        // 503 from the plugin -- never a silent pass-through.
        match self.dispatch_http_call(
            DECISION_URI,
            vec![
                (":method", "GET"),
                (":path", &format!("/decide?user={}", self.user)),
                (":authority", "127.0.0.1:18262"),
            ],
            None,
            vec![],
            CALLOUT_TIMEOUT,
        ) {
            Ok(_token) => Action::Pause,
            Err(status) => {
                let _ = proxy_wasm::hostcalls::log(
                    LogLevel::Error,
                    &format!("dispatch_http_call failed: {status:?}"),
                );
                self.send_http_response(
                    503,
                    vec![("x-entitlement-source", "unavailable")],
                    Some(b"entitlement decision unavailable"),
                );
                Action::Continue
            }
        }
    }
}
