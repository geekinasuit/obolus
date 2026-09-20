//! Deciding what a request costs.
//!
//! Before this module the price of a request was fixed at boot: whatever `maxAmountRequired` each
//! armed payment option carried, forever, for every request. Running as a business needs the price
//! *determined* per call and pluggable — the vision names cost-in/margin-out, flat, promotional,
//! and free rates.
//!
//! This is the seam. A [`PriceDeterminer`] is handed one advertised payment requirement at a time
//! and returns the atomic amount to quote for it. Two properties are load-bearing:
//!
//! * **A determiner prices the amount and nothing else.** It sees the requirement it is pricing but
//!   does not choose it: scheme, network, asset, and pay-to are copied through untouched by the
//!   caller (see [`crate::gateway`]). So a determiner cannot add, drop, or alter an advertised
//!   network — the arming guard remains the sole authority over which networks are offered, exactly
//!   as before. The seam widens *pricing*, not the attack surface.
//! * **Every price it can return is payable.** `quote` returns a [`u128`], not a string, and a
//!   `u128` is by definition a non-negative integer in atomic units — the same thing
//!   [`crate::x402::validate_atomic_amount`] checks a configured amount is. A determiner therefore
//!   cannot compute a quote no conforming client could pay; there is no revalidation step to forget.
//!
//! The default determiner, [`StaticPrice`], reproduces the pre-seam gateway exactly. The concrete
//! rate structures the vision names are built on top of this trait; [`FlatPrice`] is the first.

use crate::backends::Backend;
use crate::x402::PaymentRequirements;

/// What a single quote is about: the model the request named (or `None`), the backend it routed to,
/// and the advertised payment requirement being priced.
///
/// The determiner is called once per advertised requirement, so `requirement` is the *one* option
/// being priced — a determiner prices each `(scheme, network)` independently and never sees the set
/// as a whole. `model` and `backend` are what a per-model or per-backend policy keys on; the
/// default rate ignores both.
pub struct PriceContext<'a> {
    /// The `model` field of the request, if it named one. `None` for a request a catch-all backend
    /// took without a model (the single-backend case).
    pub model: Option<&'a str>,
    /// The backend this request routed to. Carries the operator's per-backend metadata a policy may
    /// price on (`id`, `kind`, `models`, `precedence`).
    pub backend: &'a Backend,
    /// The advertised option being priced. Its `maxAmountRequired` is the current quote; every other
    /// field is copied through unchanged and must not influence anything but the amount.
    pub requirement: &'a PaymentRequirements,
}

/// Decides the price of one advertised payment requirement, in atomic units.
///
/// Returning a `u128` — not a string — is deliberate: every value it can produce is a valid atomic
/// amount, so a determiner cannot quote a price no client can pay, and it prices *only* the amount.
/// Scheme, network, asset, and pay-to come from the [`PriceContext::requirement`] it is handed and
/// are copied through by the caller untouched, so the arming guard stays the sole authority over
/// which networks are advertised.
///
/// Implementations MUST be total. A `quote` runs on the paying request path — a panic there is a
/// 500 charged to no one, on a path that previously could not fail. Return a price; never unwrap a
/// fallible computation into the hot path.
pub trait PriceDeterminer: Send + Sync {
    fn quote(&self, ctx: PriceContext<'_>) -> u128;
}

/// The behaviour-preserving default: quote each requirement at its own configured amount.
///
/// This is the identity policy — the price was, and remains, whatever the armed requirement
/// carried. A gateway built without an explicit determiner uses this, so wiring the seam in changes
/// no quote until an operator configures a different rate.
pub struct StaticPrice;

impl PriceDeterminer for StaticPrice {
    fn quote(&self, ctx: PriceContext<'_>) -> u128 {
        // On the configuration path the amount is validated as a `u128` before it is armed
        // (`validate_atomic_amount`), so that parse cannot fail for a requirement that arrived
        // through config. This guard covers every *other* constructor — a test, or a future caller
        // building `PaymentRequirements` directly — and fails *closed*: an unparseable amount
        // quotes the maximum, which no client can pay, rather than zero, which would give the work
        // away.
        ctx.requirement.max_amount_required.parse().unwrap_or(u128::MAX)
    }
}

/// One flat rate for everything: every advertised requirement is quoted the same amount, regardless
/// of model, backend, or network.
///
/// The flat-rate seller's policy — a single price to use the gateway, whichever chain the client
/// pays on. Because it quotes the same number on every network, it deliberately flattens any
/// per-network differences the armed set carried; that is the policy, not an oversight.
pub struct FlatPrice {
    amount: u128,
}

impl FlatPrice {
    /// A flat rate of `amount` atomic units per request.
    pub fn new(amount: u128) -> Self {
        Self { amount }
    }
}

impl PriceDeterminer for FlatPrice {
    fn quote(&self, _ctx: PriceContext<'_>) -> u128 {
        self.amount
    }
}

/// Basis points per whole: 10000 bps = 100%. The denominator [`CostPlus`] marks a cost up by.
const BPS_PER_WHOLE: u128 = 10_000;

/// Cost-in, margin-out: quote a declared upstream cost plus a margin in basis points.
///
/// The "run it for money" rate. An operator states what the request costs them upstream and the
/// margin they take, and every request is quoted `cost + cost * margin_bps / 10000`. Basis points,
/// not a percentage or a float: integer arithmetic with sub-percent precision (`250` bps = 2.5%),
/// so a margin is exact and there is no float in the money path. `0` bps quotes the cost exactly —
/// a legitimate break-even rate the operator states on purpose.
///
/// Gateway-wide by construction here: one declared cost, so — like [`FlatPrice`] — the quote is the
/// same on every advertised option. It is a distinct type rather than a pre-computed `FlatPrice`
/// because it holds `cost` and `margin_bps` as live inputs: a later slice makes `cost` vary by the
/// routed backend (`ctx.backend`), at which point `quote` genuinely depends on the context it is
/// handed. The config door refuses a declared cost of zero, so a positive cost with any margin
/// quotes a positive, payable amount — this rate never reaches the zero-amount case.
pub struct CostPlus {
    cost: u128,
    margin_bps: u32,
}

impl CostPlus {
    /// A cost-plus rate: `cost` atomic units marked up by `margin_bps` basis points. `cost` is the
    /// operator's declared upstream cost; the config door (see [`crate::config::select_pricing`])
    /// rejects a zero cost before one reaches here.
    pub fn new(cost: u128, margin_bps: u32) -> Self {
        Self { cost, margin_bps }
    }
}

impl PriceDeterminer for CostPlus {
    fn quote(&self, _ctx: PriceContext<'_>) -> u128 {
        // Saturating throughout, so `quote` is total on any input the config door admits (it must
        // never panic on the paying path). The base cost is kept exact and only the *markup* can
        // saturate: an absurd cost×margin that would overflow `u128` yields a quote near the
        // maximum, which no client can pay — fail-closed, the same direction as `StaticPrice`'s
        // unparseable guard, never a giveaway.
        let markup = self.cost.saturating_mul(self.margin_bps as u128) / BPS_PER_WHOLE;
        self.cost.saturating_add(markup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::{FakeUpstream, Upstream};
    use crate::x402::{PaymentRequirements, SCHEME_EXACT};
    use std::sync::Arc;

    fn backend() -> Backend {
        let upstream: Arc<dyn Upstream> = Arc::new(FakeUpstream::streaming());
        Backend::for_test("test-backend", vec!["a-model"], None, upstream)
    }

    /// A payment requirement quoting `amount`, otherwise a synthetic-but-well-formed option.
    fn requirement(amount: &str) -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: "test-net".to_string(),
            max_amount_required: amount.to_string(),
            resource: "http://localhost/v1/chat/completions".to_string(),
            description: String::new(),
            mime_type: String::new(),
            pay_to: "0xTEST-PAY-TO".to_string(),
            max_timeout_seconds: 60,
            asset: "0xTEST-ASSET".to_string(),
            extra: None,
        }
    }

    fn ctx<'a>(backend: &'a Backend, requirement: &'a PaymentRequirements) -> PriceContext<'a> {
        PriceContext { model: Some("a-model"), backend, requirement }
    }

    #[test]
    fn static_price_quotes_the_requirements_own_amount() {
        let backend = backend();
        // Two requirements at different amounts, as an armed set with per-network prices has.
        let cheap = requirement("1000");
        let dear = requirement("2000");
        assert_eq!(StaticPrice.quote(ctx(&backend, &cheap)), 1000);
        assert_eq!(StaticPrice.quote(ctx(&backend, &dear)), 2000);
    }

    #[test]
    fn static_price_fails_closed_on_an_unparseable_amount() {
        // A requirement built directly, bypassing the config path's validation — exactly the
        // constructor the fail-closed guard exists for. It must quote the unpayable maximum, never
        // zero: a bug must not serve for free.
        let backend = backend();
        let bad = requirement("not-a-number");
        assert_eq!(StaticPrice.quote(ctx(&backend, &bad)), u128::MAX);
    }

    #[test]
    fn flat_price_quotes_its_rate_regardless_of_the_requirements_amount() {
        let backend = backend();
        let flat = FlatPrice::new(500);
        // Same rate whatever the requirement's own amount was — that is the point of a flat rate.
        assert_eq!(flat.quote(ctx(&backend, &requirement("1000"))), 500);
        assert_eq!(flat.quote(ctx(&backend, &requirement("2000"))), 500);
    }

    #[test]
    fn cost_plus_marks_the_cost_up_by_the_margin() {
        let backend = backend();
        // 1000 cost + 2500 bps (25%) margin = 1250, whatever the requirement's own amount was.
        let rate = CostPlus::new(1000, 2500);
        assert_eq!(rate.quote(ctx(&backend, &requirement("1"))), 1250);
        assert_eq!(rate.quote(ctx(&backend, &requirement("999999"))), 1250);
    }

    #[test]
    fn cost_plus_with_zero_margin_quotes_the_cost_exactly() {
        // Break-even is a legitimate rate: charge the upstream cost and take nothing on top.
        let backend = backend();
        assert_eq!(CostPlus::new(1000, 0).quote(ctx(&backend, &requirement("1"))), 1000);
    }

    #[test]
    fn cost_plus_keeps_sub_percent_margin_precision() {
        // 250 bps = 2.5%, which an integer-percentage margin could not express. 1000 + 25 = 1025.
        let backend = backend();
        assert_eq!(CostPlus::new(1000, 250).quote(ctx(&backend, &requirement("1"))), 1025);
    }

    #[test]
    fn cost_plus_fails_closed_on_an_overflowing_markup() {
        // A cost and margin whose product overflows u128 must not wrap to a tiny quote and sell the
        // work off cheap. Saturating arithmetic yields a quote near the maximum — unpayable — the
        // same fail-closed direction as StaticPrice's unparseable guard.
        let backend = backend();
        let rate = CostPlus::new(u128::MAX, u32::MAX);
        assert_eq!(rate.quote(ctx(&backend, &requirement("1"))), u128::MAX);
    }
}
