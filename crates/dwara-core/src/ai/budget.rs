//! AI token budgets (DW-078): tokens/min and cost/day per consumer or
//! per policy-shared team.
//!
//! A budget is a LIMIT OF TOTALS, not a rate: it caps how many
//! provider-reported tokens (or how much priced cost) one budget
//! holder may consume inside a window. It composes with — never
//! replaces — the request-count limiter (DW-017) and the request
//! quotas (DW-033): those count REQUESTS, this counts TOKENS.
//!
//! # Check-then-spend (the locked no-estimation decision)
//!
//! The gateway never estimates a request's cost before the provider
//! answers, so enforcement is two-phase:
//!
//! 1. **Pre-check** (before any provider contact): a holder whose
//!    window is ALREADY exhausted is rejected with 429
//!    `ai_budget_exceeded` and a `Retry-After` to the window boundary.
//! 2. **Spend** (after usage is known): the provider-REPORTED usage is
//!    added to the window — non-streaming from the translated
//!    response, streaming from the accumulated DW-077 usage events.
//!
//! The contract is therefore: reject when the window is exhausted,
//! spend what the provider reports. Overrun within one request is
//! bounded by that one request's usage — a holder at the limit can
//! always complete one more request, and the next pre-check rejects.
//!
//! # Mid-stream cutoff
//!
//! While a stream is being forwarded, the provider's usage report is
//! spent as it GROWS — each reported token exactly once — and checked
//! against the window after every batch. When a dialect reports usage
//! EARLY (Anthropic carries input tokens in `message_start`), a
//! crossing is detected mid-stream: forwarding stops, the client
//! receives the documented `ai_budget_exceeded` SSE event and the
//! terminator, and the provider body is dropped AT ONCE — the upstream
//! cancel propagates immediately, so even a stalled client cannot keep
//! the provider generating. Dialects that
//! only report usage at the END (OpenAI without include_usage would
//! be one; the gateway forces include_usage, whose chunk is terminal)
//! cannot cut off mid-stream: their usage is spent at stream end and
//! enforced by the next pre-check. Documented, honest boundary.
//!
//! # Windows and keys
//!
//! `tokens_per_min` is a fixed 60-second window aligned to the epoch
//! minute (deterministic in tests; `Retry-After` counts to the next
//! boundary). `cost_per_day_micros` is a UTC calendar day — the same
//! window shape as the DW-033 quotas. Cost is integer MICRO-USD (no
//! floating-point money). The budget KEY is the consumer name
//! (`scope: consumer`) or, for a shared team budget, the POLICY name
//! (`scope: policy`) — every consumer attaching that policy spends
//! from one ledger entry.
//!
//! # Pricing seam (DW-079)
//!
//! Cost enforcement is wired end to end but reads prices through
//! [`cost_micros`], which returns 0 until the pricing tables land in
//! DW-079 — enforced-but-inert, the honest seam.
//!
//! # Lifetime
//!
//! The ledger (windows) lives on the dataplane and SURVIVES config
//! reloads (a reload must not reset a 60-second window or a daily
//! spend); only the limits resolve per generation. A reload PRUNES the
//! keys the new generation can no longer derive (a removed or renamed
//! holder's windows) — carried-forward state is bounded by the config,
//! not the deployment's history. Unbudgeted consumers (no policy with
//! a `token_budget` binds them) are unlimited — fail-open, the DW-017
//! default posture. An ANONYMOUS request (a route without
//! `auth_required`) cannot bind a consumer-scoped budget — the walk
//! falls through to the next candidate, so a less-specific
//! policy-scoped (team) budget still binds rather than silently
//! unlimiting the request.

use crate::ai::types::Usage;
use crate::config::{TokenBudget, TokenBudgetScope};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Seconds in a minute (the token window's whole length).
const SECS_PER_MIN: u64 = 60;
/// Seconds in a day (the cost window's whole length, UTC-aligned).
const SECS_PER_DAY: u64 = 86_400;

/// One ledger window's spent totals (reset when the window rolls).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Spent {
    tokens: u64,
    cost_micros: u64,
}

/// Which window a ledger entry tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum WindowKind {
    Minute,
    Day,
}

/// The shared spend ledger: one entry per (budget key, window kind).
/// A single mutex guards the map — AI request rates are orders of
/// magnitude below the GCRA path's sharding needs, and the critical
/// section is two integer adds (the DW-033 store pays an fsync per
/// request; this pays none).
#[derive(Debug, Default)]
pub struct BudgetLedger {
    windows: Mutex<HashMap<(String, WindowKind), (u64, Spent)>>,
}

impl BudgetLedger {
    /// The current spend of one window (0 when untouched).
    fn spent(&self, key: &str, kind: WindowKind, window_index: u64) -> Spent {
        let windows = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        windows
            .get(&(key.to_string(), kind))
            .filter(|(idx, _)| *idx == window_index)
            .map(|(_, s)| *s)
            .unwrap_or_default()
    }

    /// Add `tokens` to a window (rolling it forward if the window
    /// advanced). Returns the NEW total and whether it crossed
    /// `limit` (the spend is recorded either way — honest accounting).
    fn spend_tokens(
        &self,
        key: &str,
        window_index: u64,
        tokens: u64,
        limit: Option<u64>,
    ) -> (u64, bool) {
        let mut windows = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        let entry = windows
            .entry((key.to_string(), WindowKind::Minute))
            .or_insert((window_index, Spent::default()));
        if entry.0 != window_index {
            *entry = (window_index, Spent::default());
        }
        entry.1.tokens = entry.1.tokens.saturating_add(tokens);
        let crossed = limit.is_some_and(|l| entry.1.tokens > l);
        (entry.1.tokens, crossed)
    }

    /// Add `cost_micros` to the day window (same roll semantics).
    fn spend_cost(&self, key: &str, window_index: u64, cost_micros: u64) {
        let mut windows = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        let entry = windows
            .entry((key.to_string(), WindowKind::Day))
            .or_insert((window_index, Spent::default()));
        if entry.0 != window_index {
            *entry = (window_index, Spent::default());
        }
        entry.1.cost_micros = entry.1.cost_micros.saturating_add(cost_micros);
    }

    /// Drop every key not in `keep` (reload pruning): keys the new
    /// generation can no longer resolve must not accumulate forever.
    /// An in-flight request still holding a guard over a pruned key
    /// re-creates its entry on its next spend — orphaned, and pruned
    /// again by the following reload.
    fn retain(&self, keep: &HashSet<String>) {
        let mut windows = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        windows.retain(|(key, _), _| keep.contains(key));
    }
}

/// The per-generation budget rules plus the reload-surviving ledger.
#[derive(Debug, Default)]
pub struct AiBudgetEngine {
    /// Policy name -> its token budget (config-declared).
    budgets: HashMap<String, TokenBudget>,
    /// Per-consumer token budgets (DW-113): consumer name -> its
    /// direct token budget. Checked FIRST in resolve (before the
    /// policy chain) as the most-specific budget. A consumer with no
    /// entry here falls through to the policy chain.
    consumer_budgets: HashMap<String, TokenBudget>,
    /// Shared spend ledger — carried across generations.
    ledger: Arc<BudgetLedger>,
    /// Whether the anonymous-fall-through warning already fired this
    /// generation (once per compile, not per request).
    warned_anonymous: AtomicBool,
}

impl AiBudgetEngine {
    /// Compile from the gateway config; the ledger starts empty.
    pub fn compile(gateway: &crate::config::Gateway) -> Self {
        Self::compile_with_ledger(gateway, Arc::new(BudgetLedger::default()))
    }

    /// Compile with a PREVIOUS generation's ledger (reload: rules
    /// change, spend survives — except for holders the new generation
    /// can no longer derive, whose keys are pruned so carried state
    /// stays config-bounded).
    pub fn compile_with_ledger(
        gateway: &crate::config::Gateway,
        ledger: Arc<BudgetLedger>,
    ) -> Self {
        let budgets = gateway
            .policies
            .iter()
            .filter_map(|p| p.token_budget.as_ref().map(|b| (p.name.clone(), *b)))
            .collect();
        // DW-113: per-consumer token budgets. A consumer with a
        // `token_budget` set gets its own budget, checked before the
        // policy chain (the most-specific budget).
        let consumer_budgets = gateway
            .consumers
            .iter()
            .filter_map(|c| c.token_budget.map(|b| (c.name.clone(), b)))
            .collect();
        ledger.retain(&derivable_keys(gateway, &budgets, &consumer_budgets));
        AiBudgetEngine {
            budgets,
            consumer_budgets,
            ledger,
            warned_anonymous: AtomicBool::new(false),
        }
    }

    /// Whether any policy or consumer declares a budget (cheap
    /// dataplane skip).
    pub fn is_empty(&self) -> bool {
        self.budgets.is_empty() && self.consumer_budgets.is_empty()
    }

    /// The shared ledger (carried into the next generation).
    pub fn ledger(&self) -> Arc<BudgetLedger> {
        Arc::clone(&self.ledger)
    }

    /// Resolve the binding budget for one request: the FIRST policy
    /// carrying a `token_budget` in the frozen precedence chain
    /// consumer > route > service > listener > global (a budget is a
    /// limit-of-totals, so the most specific level governs — unlike
    /// AND-composed rate rules). The ledger key is the consumer name
    /// or, for a team budget (`scope: policy`), the policy name.
    ///
    /// An ANONYMOUS request has no per-consumer window, so a
    /// consumer-scoped budget CANNOT bind it: that candidate is
    /// skipped and the walk CONTINUES — aborting here would silently
    /// unlimit the request even when a less-specific policy-scoped
    /// (team) budget later in the chain should govern it.
    pub fn resolve(
        &self,
        consumer: Option<&str>,
        consumer_policies: &[String],
        route_policies: &[String],
        service_policies: &[String],
        listener_policies: &[String],
        global_policies: &[String],
    ) -> Option<BudgetGuard> {
        // DW-113: per-consumer token budget — the MOST specific
        // budget, checked before the policy chain. A consumer with a
        // direct `token_budget` binds it (consumer-scoped by
        // definition); an anonymous caller cannot bind one (no
        // consumer name).
        if let Some(consumer_name) = consumer {
            if let Some(budget) = self.consumer_budgets.get(consumer_name) {
                return Some(BudgetGuard {
                    ledger: Arc::clone(&self.ledger),
                    key: consumer_name.to_string(),
                    tokens_per_min: budget.tokens_per_min,
                    cost_per_day_micros: budget.cost_per_day_micros,
                    scope: TokenBudgetScope::Consumer,
                });
            }
        }
        let levels = [
            consumer_policies,
            route_policies,
            service_policies,
            listener_policies,
            global_policies,
        ];
        for level in levels {
            for name in level {
                if let Some(budget) = self.budgets.get(name) {
                    let key = match budget.scope {
                        TokenBudgetScope::Consumer => match consumer {
                            Some(c) => c.to_string(),
                            None => {
                                // Once per generation: reachable only
                                // when an anonymous caller hit a route
                                // whose budget chain starts with a
                                // consumer-scoped policy — a config
                                // smell worth naming, not a rejection.
                                if !self.warned_anonymous.swap(true, Ordering::Relaxed) {
                                    tracing::warn!(
                                        code = "ai_budget_anonymous_skipped",
                                        policy = %name,
                                        "anonymous request cannot bind a \
                                         consumer-scoped token budget; \
                                         continuing to the next candidate"
                                    );
                                }
                                continue;
                            }
                        },
                        TokenBudgetScope::Policy => name.clone(),
                    };
                    return Some(BudgetGuard {
                        ledger: Arc::clone(&self.ledger),
                        key,
                        tokens_per_min: budget.tokens_per_min,
                        cost_per_day_micros: budget.cost_per_day_micros,
                        scope: budget.scope,
                    });
                }
            }
        }
        None
    }
}

/// The ledger keys the generation's config can still resolve: every
/// budgeted policy name (team scope, keyed by the policy), plus — for
/// consumer-scoped budgets — the consumers that can bind them (direct
/// attachers, and every consumer when the policy is attached at a
/// level any authenticated consumer can hit:
/// route/service/listener/global), plus the per-consumer direct
/// budgets (DW-113, keyed by the consumer name).
fn derivable_keys(
    gateway: &crate::config::Gateway,
    budgets: &HashMap<String, TokenBudget>,
    consumer_budgets: &HashMap<String, TokenBudget>,
) -> HashSet<String> {
    let mut keep: HashSet<String> = HashSet::new();
    // DW-113: per-consumer direct budgets are always derivable while
    // the consumer carries the budget.
    for name in consumer_budgets.keys() {
        keep.insert(name.clone());
    }
    for (name, budget) in budgets {
        match budget.scope {
            TokenBudgetScope::Policy => {
                keep.insert(name.clone());
            }
            TokenBudgetScope::Consumer => {
                for c in &gateway.consumers {
                    if c.policies.iter().any(|p| p == name) {
                        keep.insert(c.name.clone());
                    }
                }
                if attached_beyond_consumer(gateway, name) {
                    keep.extend(gateway.consumers.iter().map(|c| c.name.clone()));
                }
            }
        }
    }
    keep
}

/// Whether the policy is attached at any level ANY authenticated
/// consumer can bind (route, service, listener, global) — not only by
/// direct consumer attachment.
fn attached_beyond_consumer(gateway: &crate::config::Gateway, policy: &str) -> bool {
    let at = |names: &[String]| names.iter().any(|p| p == policy);
    gateway.routes.iter().any(|r| at(&r.policies))
        || gateway.services.iter().any(|s| at(&s.policies))
        || gateway.listeners.iter().any(|l| at(&l.policies))
        || at(&gateway.global_policies)
}

/// The resolved budget for one request: a live guard over the ledger.
pub struct BudgetGuard {
    ledger: Arc<BudgetLedger>,
    key: String,
    tokens_per_min: Option<u64>,
    cost_per_day_micros: Option<u64>,
    /// The budget's scope (DW-079): when `Policy`, the `key` IS the
    /// team name (the policy name) — exposed so the spend recorder
    /// can attribute the request to the team.
    scope: TokenBudgetScope,
}

/// Which budget window denied (the `kind` label of
/// `dwara_ai_budget_denied_total`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetKind {
    /// The tokens/min window.
    Tokens,
    /// The cost/day window.
    Cost,
}

impl BudgetKind {
    /// The metric label value (`tokens` | `cost`).
    pub fn as_str(self) -> &'static str {
        match self {
            BudgetKind::Tokens => "tokens",
            BudgetKind::Cost => "cost",
        }
    }
}

/// The pre-check verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetVerdict {
    /// The holder has budget remaining in every configured window.
    Allowed,
    /// A window is exhausted: retry after this many seconds. `kind` is
    /// the window that set the Retry-After (the later wall when both
    /// are exhausted) so the denial metric attributes correctly.
    Denied {
        kind: BudgetKind,
        retry_after_s: u64,
    },
}

impl BudgetGuard {
    /// The minute-window index containing `now_s`.
    fn minute_index(now_s: u64) -> u64 {
        now_s / SECS_PER_MIN
    }

    /// The UTC-day window index containing `now_s`.
    fn day_index(now_s: u64) -> u64 {
        now_s / SECS_PER_DAY
    }

    /// Pre-check BEFORE any provider contact: rejected when either
    /// window is already exhausted (both windows are checked
    /// independently — the done-when requirement). `Retry-After` is
    /// the time to the denying window's boundary (the later wall when
    /// both are exhausted), and the verdict's kind is the window that
    /// set it.
    pub fn check(&self, now_s: u64) -> BudgetVerdict {
        let mut denial: Option<(BudgetKind, u64)> = None;
        if let Some(limit) = self.tokens_per_min {
            let spent = self
                .ledger
                .spent(&self.key, WindowKind::Minute, Self::minute_index(now_s))
                .tokens;
            if spent >= limit {
                let wait = SECS_PER_MIN - (now_s % SECS_PER_MIN);
                denial = later_wall(denial, BudgetKind::Tokens, wait);
            }
        }
        if let Some(limit) = self.cost_per_day_micros {
            let spent = self
                .ledger
                .spent(&self.key, WindowKind::Day, Self::day_index(now_s))
                .cost_micros;
            if spent >= limit {
                let wait = SECS_PER_DAY - (now_s % SECS_PER_DAY);
                denial = later_wall(denial, BudgetKind::Cost, wait);
            }
        }
        match denial {
            Some((kind, retry_after_s)) => BudgetVerdict::Denied {
                kind,
                retry_after_s,
            },
            None => BudgetVerdict::Allowed,
        }
    }

    /// Record the provider-reported usage after the call. Returns
    /// whether THIS spend crossed the token window (the mid-stream
    /// cutoff signal; the spend is recorded either way).
    pub fn spend(&self, now_s: u64, usage: Usage, cost_micros: u64) -> bool {
        let tokens = usage.total_tokens.unwrap_or_else(|| {
            usage
                .prompt_tokens
                .unwrap_or(0)
                .saturating_add(usage.completion_tokens.unwrap_or(0))
        });
        let (_, crossed) = self.ledger.spend_tokens(
            &self.key,
            Self::minute_index(now_s),
            tokens,
            self.tokens_per_min,
        );
        if cost_micros > 0 {
            self.ledger
                .spend_cost(&self.key, Self::day_index(now_s), cost_micros);
        }
        crossed
    }

    /// The SSE event frame for a mid-stream budget cutoff (the
    /// documented over-budget event; DW-077's terminator follows).
    pub fn cutoff_frame(rid: &str) -> String {
        let body = crate::ai::openai_compat::error_body(
            "the token budget for this window is exhausted; the stream was cut off",
            "rate_limit_error",
            Some("ai_budget_exceeded"),
            rid,
        );
        format!("data: {}\n\n", body)
    }

    /// The team key for spend attribution (DW-079): the policy name
    /// when the budget is `scope: policy` (a shared team budget), or
    /// an empty string when the budget is consumer-scoped or no
    /// budget binds the request.
    pub fn team_key(&self) -> &str {
        match self.scope {
            TokenBudgetScope::Policy => &self.key,
            TokenBudgetScope::Consumer => "",
        }
    }
}

/// Keep the LATER wall when both windows deny: the Retry-After and
/// its kind belong to the window that actually binds (a tie keeps the
/// first — either window denies either way).
fn later_wall(
    cur: Option<(BudgetKind, u64)>,
    kind: BudgetKind,
    wait: u64,
) -> Option<(BudgetKind, u64)> {
    match cur {
        Some((_, prev)) if prev >= wait => cur,
        _ => Some((kind, wait)),
    }
}

/// The DW-079 pricing seam: micro-USD for one provider-model call
/// with this usage. Reads prices through a DEFAULT (empty) pricing
/// table, so this free function always returns 0 — it exists for
/// test/backward-compat call sites that do not have a dataplane
/// handle. The live path uses the dataplane's compiled
/// [`PricingTable`](crate::ai::cost::PricingTable) (stored on the
/// DataPlane as an ArcSwap, refreshed per generation).
pub fn cost_micros(provider_model: &str, usage: Usage) -> u64 {
    crate::ai::cost::PricingTable::default().cost_micros(provider_model, usage)
}

/// Resolve a consumer's attached policies from the config (by name).
pub fn consumer_policies_of<'a>(
    gateway: &'a crate::config::Gateway,
    consumer: &str,
) -> &'a [String] {
    gateway
        .consumers
        .iter()
        .find(|c| c.name == consumer)
        .map(|c| c.policies.as_slice())
        .unwrap_or(&[])
}

/// The route's service's policy list (empty when the service is
/// missing — validation rejects that elsewhere).
pub fn service_policies_of<'a>(gateway: &'a crate::config::Gateway, service: &str) -> &'a [String] {
    gateway
        .services
        .iter()
        .find(|s| s.name == service)
        .map(|s| s.policies.as_slice())
        .unwrap_or(&[])
}

/// The listener's policy list (by name).
pub fn listener_policies_of<'a>(
    gateway: &'a crate::config::Gateway,
    listener: &str,
) -> &'a [String] {
    gateway
        .listeners
        .iter()
        .find(|l| l.name == listener)
        .map(|l| l.policies.as_slice())
        .unwrap_or(&[])
}

// White-box suite: stays in src/ because it inspects private
// BudgetLedger/resolve internals (window indexing, reload pruning,
// scope fall-through) that the e2e tests in tests/ai_budget.rs can
// only observe indirectly.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Gateway, Policy, TokenBudget, TokenBudgetScope};

    fn gateway_with(budget: TokenBudget, attach_to_consumer: bool) -> Gateway {
        // The empty document parses to the all-defaults gateway.
        let mut g = crate::config::parse_gateway("").expect("empty gateway parses");
        g.policies = vec![Policy {
            name: "ai-budget".into(),
            rate_limit: None,
            rate_limits: vec![],
            timeouts: None,
            dry_run: false,
            token_budget: Some(budget),
            anomaly: None,
            adaptive: None,
        }];
        g.consumers = vec![crate::config::Consumer {
            name: "acme".into(),
            credentials: vec![],
            policies: if attach_to_consumer {
                vec!["ai-budget".into()]
            } else {
                vec![]
            },
            consumer_type: crate::config::ConsumerType::User,
            tool_allowlist: vec![],
            token_budget: None,
            priority: None,
            quotas: None,
            groups: vec![],
            authorization: None,
            ai_logging: None,
        }];
        g
    }

    // White-box: the window arithmetic and check-then-spend contract
    // are private behavior; the gateway-level enforcement (429 shape,
    // mid-stream cutoff) is covered by tests/ai_budget.rs.

    #[test]
    fn pre_check_rejects_only_when_spent_reaches_the_limit() {
        let g = gateway_with(
            TokenBudget {
                tokens_per_min: Some(100),
                cost_per_day_micros: None,
                scope: TokenBudgetScope::Consumer,
            },
            true,
        );
        let engine = AiBudgetEngine::compile(&g);
        let guard = engine
            .resolve(Some("acme"), &["ai-budget".into()], &[], &[], &[], &[])
            .expect("consumer budget binds");

        let now = 1_000_000;
        assert_eq!(guard.check(now), BudgetVerdict::Allowed);
        // One request spends exactly the window: still allowed DURING
        // (the pre-check passed), the NEXT pre-check denies.
        assert!(!guard.spend(
            now,
            Usage {
                prompt_tokens: Some(100),
                completion_tokens: None,
                total_tokens: None
            },
            0
        ));
        match guard.check(now) {
            BudgetVerdict::Denied {
                kind,
                retry_after_s,
            } => {
                assert_eq!(kind, BudgetKind::Tokens);
                assert!(retry_after_s > 0 && retry_after_s <= 60)
            }
            v => panic!("expected denial, got {v:?}"),
        }
        // The next minute window is fresh.
        assert_eq!(guard.check(now + 60), BudgetVerdict::Allowed);
    }

    #[test]
    fn windows_roll_and_keys_are_separate() {
        let g = gateway_with(
            TokenBudget {
                tokens_per_min: Some(10),
                cost_per_day_micros: None,
                scope: TokenBudgetScope::Consumer,
            },
            true,
        );
        let engine = AiBudgetEngine::compile(&g);
        let a = engine
            .resolve(Some("acme"), &["ai-budget".into()], &[], &[], &[], &[])
            .unwrap();
        let now = 500;
        a.spend(
            now,
            Usage {
                prompt_tokens: None,
                completion_tokens: Some(10),
                total_tokens: None,
            },
            0,
        );
        assert_eq!(
            a.check(now),
            BudgetVerdict::Denied {
                kind: BudgetKind::Tokens,
                retry_after_s: 60 - (now % 60)
            }
        );
        // Another consumer (same policy) has its OWN window.
        let b = engine
            .resolve(Some("other"), &["ai-budget".into()], &[], &[], &[], &[])
            .unwrap();
        assert_eq!(b.check(now), BudgetVerdict::Allowed);
        // A team-scoped budget shares by policy name.
        let g2 = gateway_with(
            TokenBudget {
                tokens_per_min: Some(10),
                cost_per_day_micros: None,
                scope: TokenBudgetScope::Policy,
            },
            true,
        );
        let engine2 = AiBudgetEngine::compile_with_ledger(&g2, engine.ledger());
        let t1 = engine2
            .resolve(Some("acme"), &["ai-budget".into()], &[], &[], &[], &[])
            .unwrap();
        let t2 = engine2
            .resolve(Some("other"), &["ai-budget".into()], &[], &[], &[], &[])
            .unwrap();
        t1.spend(
            now,
            Usage {
                prompt_tokens: Some(10),
                completion_tokens: None,
                total_tokens: None,
            },
            0,
        );
        assert_eq!(
            t2.check(now),
            BudgetVerdict::Denied {
                kind: BudgetKind::Tokens,
                retry_after_s: 60 - (now % 60)
            }
        );
    }

    #[test]
    fn cost_window_is_independent_of_tokens() {
        let g = gateway_with(
            TokenBudget {
                tokens_per_min: Some(10),
                cost_per_day_micros: Some(1_000),
                scope: TokenBudgetScope::Consumer,
            },
            true,
        );
        let engine = AiBudgetEngine::compile(&g);
        let guard = engine
            .resolve(Some("acme"), &["ai-budget".into()], &[], &[], &[], &[])
            .unwrap();
        let now = 10_000_000; // mid-day
                              // Exhaust TOKENS only.
        guard.spend(
            now,
            Usage {
                prompt_tokens: Some(10),
                completion_tokens: None,
                total_tokens: None,
            },
            0,
        );
        assert_eq!(
            guard.check(now),
            BudgetVerdict::Denied {
                kind: BudgetKind::Tokens,
                retry_after_s: 60 - (now % 60)
            }
        );
        // ...but the same holder in the NEXT minute is still denied on
        // tokens only until the minute rolls; with tokens fresh, cost
        // alone governs: spend cost to the cap via the seam-shaped
        // call path (cost>0 spends).
        guard.spend(now + 60, Usage::default(), 1_000);
        match guard.check(now + 60) {
            BudgetVerdict::Denied {
                kind,
                retry_after_s,
            } => {
                // The COST wall: hours-scale retry, not 60s, attributed
                // to the cost window (the denial metric's kind).
                assert_eq!(kind, BudgetKind::Cost);
                assert!(retry_after_s > 3600, "cost-day retry {retry_after_s}");
            }
            v => panic!("expected cost denial, got {v:?}"),
        }
    }

    #[test]
    fn precedence_takes_the_most_specific_binding() {
        let mut g = gateway_with(
            TokenBudget {
                tokens_per_min: Some(5),
                cost_per_day_micros: None,
                scope: TokenBudgetScope::Consumer,
            },
            true,
        );
        g.policies.push(Policy {
            name: "route-budget".into(),
            rate_limit: None,
            rate_limits: vec![],
            timeouts: None,
            dry_run: false,
            token_budget: Some(TokenBudget {
                tokens_per_min: Some(999),
                cost_per_day_micros: None,
                scope: TokenBudgetScope::Consumer,
            }),
            anomaly: None,
            adaptive: None,
        });
        let engine = AiBudgetEngine::compile(&g);
        // Consumer-level (5) wins over route-level (999).
        let guard = engine
            .resolve(
                Some("acme"),
                &["ai-budget".into()],
                &["route-budget".into()],
                &[],
                &[],
                &[],
            )
            .unwrap();
        let now = 77_777;
        guard.spend(
            now,
            Usage {
                prompt_tokens: Some(5),
                completion_tokens: None,
                total_tokens: None,
            },
            0,
        );
        assert_eq!(
            guard.check(now),
            BudgetVerdict::Denied {
                kind: BudgetKind::Tokens,
                retry_after_s: 60 - (now % 60)
            }
        );
    }

    #[test]
    fn anonymous_caller_skips_consumer_scope_and_binds_less_specific() {
        // Mixed scopes in one chain: a consumer-scoped budget first
        // (route level), a policy-scoped (team) one after (global).
        let mut g = gateway_with(
            TokenBudget {
                tokens_per_min: Some(1_000_000),
                cost_per_day_micros: None,
                scope: TokenBudgetScope::Consumer,
            },
            false,
        );
        g.policies.push(Policy {
            name: "team-budget".into(),
            rate_limit: None,
            rate_limits: vec![],
            timeouts: None,
            dry_run: false,
            token_budget: Some(TokenBudget {
                tokens_per_min: Some(10),
                cost_per_day_micros: None,
                scope: TokenBudgetScope::Policy,
            }),
            anomaly: None,
            adaptive: None,
        });
        let engine = AiBudgetEngine::compile(&g);
        // Anonymous: the consumer-scoped candidate cannot bind, the
        // walk CONTINUES, and the team budget governs (an early None
        // here would silently unlimit anonymous traffic).
        let guard = engine
            .resolve(
                None,
                &[],
                &["ai-budget".into()],
                &[],
                &[],
                &["team-budget".into()],
            )
            .expect("the policy-scoped budget binds an anonymous caller");
        guard.spend(
            5_000,
            Usage {
                prompt_tokens: Some(10),
                ..Usage::default()
            },
            0,
        );
        // The bound guard spends under the team key ("team-budget")
        // and denies at its 10-token window — proving the walk fell
        // through to the policy-scoped budget.
        assert_eq!(
            guard.check(5_000),
            BudgetVerdict::Denied {
                kind: BudgetKind::Tokens,
                retry_after_s: 60 - (5_000 % 60)
            }
        );
    }

    #[test]
    fn reload_prunes_ledger_keys_the_new_generation_cannot_derive() {
        let budget = TokenBudget {
            tokens_per_min: Some(10),
            cost_per_day_micros: None,
            scope: TokenBudgetScope::Consumer,
        };
        let attached = gateway_with(budget, true);
        let engine = AiBudgetEngine::compile(&attached);
        let ledger = engine.ledger();
        engine
            .resolve(Some("acme"), &["ai-budget".into()], &[], &[], &[], &[])
            .expect("consumer budget binds")
            .spend(
                960,
                Usage {
                    prompt_tokens: Some(10),
                    ..Usage::default()
                },
                0,
            );
        let minute = 960 / SECS_PER_MIN;

        // Reload with the holder intact: the spend carries over.
        AiBudgetEngine::compile_with_ledger(&attached, Arc::clone(&ledger));
        assert_eq!(ledger.spent("acme", WindowKind::Minute, minute).tokens, 10);

        // Reload with the attachment removed: "acme" is no longer a
        // derivable key, so its windows are pruned (a removed or
        // renamed holder must not be carried forward forever).
        let detached = gateway_with(budget, false);
        AiBudgetEngine::compile_with_ledger(&detached, Arc::clone(&ledger));
        assert_eq!(
            ledger.spent("acme", WindowKind::Minute, minute),
            Spent::default()
        );

        // A team-scoped budget's key stays derivable while the budget
        // exists, so it survives the same reload.
        let team = gateway_with(
            TokenBudget {
                tokens_per_min: Some(10),
                cost_per_day_micros: None,
                scope: TokenBudgetScope::Policy,
            },
            true,
        );
        let engine = AiBudgetEngine::compile(&team);
        let ledger = engine.ledger();
        engine
            .resolve(Some("acme"), &["ai-budget".into()], &[], &[], &[], &[])
            .unwrap()
            .spend(
                960,
                Usage {
                    prompt_tokens: Some(10),
                    ..Usage::default()
                },
                0,
            );
        AiBudgetEngine::compile_with_ledger(&team, Arc::clone(&ledger));
        assert_eq!(
            ledger.spent("ai-budget", WindowKind::Minute, minute).tokens,
            10
        );
    }

    #[test]
    fn unbudgeted_consumers_resolve_no_guard() {
        let g = gateway_with(
            TokenBudget {
                tokens_per_min: Some(10),
                cost_per_day_micros: None,
                scope: TokenBudgetScope::Consumer,
            },
            false, // policy exists but is NOT attached to the consumer
        );
        let engine = AiBudgetEngine::compile(&g);
        assert!(engine
            .resolve(Some("acme"), &[], &[], &[], &[], &[])
            .is_none());
        assert!(engine
            .resolve(Some("anon"), &[], &[], &[], &[], &[])
            .is_none());
    }
}
