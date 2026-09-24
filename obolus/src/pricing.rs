//! Deciding what a request costs.
//!
//! Before this module the price of a request was fixed at boot: whatever `amount` each
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
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// price on — `id`, `kind`, `models`, `precedence`, and the declared `cost` the cost-plus rate
    /// marks up.
    pub backend: &'a Backend,
    /// The advertised option being priced. Its `amount` is the current quote; every other
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
        ctx.requirement.amount.parse().unwrap_or(u128::MAX)
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

/// Cost-in, margin-out: quote the routed backend's declared upstream cost plus a margin in basis
/// points.
///
/// The "run it for money" rate. Each backend declares what a request to it costs the operator
/// upstream — `OBOLUS_UPSTREAM_COST` on the single-backend path, a per-entry `cost` in the backends
/// file otherwise — and this rate marks that cost up by a gateway-wide margin, quoting
/// `cost + cost * margin_bps / 10000`. Basis points, not a percentage or a float: the margin is an
/// exact integer with sub-percent precision (`250` bps = 2.5%) and there is no float in the money
/// path. The *markup* is in whole atomic units and floored, so a markup that works out to less than
/// one atomic unit (a tiny cost, or a tiny margin) rounds down to zero: the quote is only ever
/// rounded toward the payer, and by less than one atomic unit. `0` bps quotes the cost exactly — a
/// legitimate break-even rate the operator states on purpose.
///
/// The cost is read per request from [`PriceContext::backend`], so two requests routed to backends
/// with different costs are quoted differently through the one determiner; the margin is shared.
/// The config door refuses to start under this rate unless *every* backend declares a cost (see
/// [`crate::config::require_backend_costs`]) and refuses a declared cost of zero, so on the paying
/// path the backend's cost is present and positive — the fail-closed branch below is unreachable in
/// a configured gateway.
pub struct CostPlus {
    margin_bps: u32,
}

impl CostPlus {
    /// A cost-plus rate marking each backend's declared cost up by `margin_bps` basis points. The
    /// cost is read per request from the routed backend; the config door
    /// ([`crate::config::require_backend_costs`]) guarantees one is present before this runs.
    pub fn new(margin_bps: u32) -> Self {
        Self { margin_bps }
    }
}

impl PriceDeterminer for CostPlus {
    fn quote(&self, ctx: PriceContext<'_>) -> u128 {
        // The routed backend's declared cost. `None` is unreachable on the paying path — the config
        // door refuses cost-plus unless every backend has a cost — so it fails *closed*: quote the
        // unpayable maximum rather than give the work away, the same direction as `StaticPrice`'s
        // unparseable guard.
        let cost = ctx.backend.cost.unwrap_or(u128::MAX);
        // Saturating throughout, so `quote` is total. The base cost is kept exact and only the
        // *markup* can saturate: an absurd cost×margin that would overflow `u128` yields a quote
        // near the maximum, which no client can pay — fail-closed, never a giveaway.
        let markup = cost.saturating_mul(self.margin_bps as u128) / BPS_PER_WHOLE;
        cost.saturating_add(markup)
    }
}

/// A time-bounded promotional discount layered over a base rate.
///
/// A promotion is a percentage off for a while: during the `[start, end)` window (Unix seconds,
/// `start` inclusive, `end` exclusive) the quote is the base rate's quote marked *down* by
/// `discount_bps` basis points; outside the window the base rate applies unchanged.
///
/// It discounts a *percentage*, deliberately, not a fixed atomic amount. A percentage is
/// asset-agnostic, so the same promo is correct across payment options whose assets have different
/// decimals — where one fixed atomic number would mean two different real prices — and it composes
/// over any base rate. So `promotional` is a *modifier*, not a rate of its own: `OBOLUS_PRICING`
/// still selects the base (`static` or `cost-plus`) and the promo wraps whatever that produced.
///
/// The discounted quote is `base * (10000 - discount_bps) / 10000`, floored to whole atomic units —
/// the same direction as the [`CostPlus`] markup floor, rounding toward the payer by under one unit.
/// The config door refuses `discount_bps >= 10000` ([`crate::config`]): 100% off is a free rate,
/// which drives verify/settle differently and is tracked separately. But the floor alone can still
/// reach zero on a *payable* base — a deep (sub-100%) discount on a small amount — so `quote` clamps
/// a floored-to-zero result back to one atomic unit whenever the base was payable: a promotion never
/// quotes zero of its own accord, and never slips into the free rate's settle path by rounding. A
/// base that was already zero stays zero. The arithmetic saturates throughout, so `quote` is total
/// even for a `discount_bps >= 10000` that reached this determiner past the config door.
pub struct Promotional {
    discount_bps: u32,
    start: u64,
    end: u64,
    /// The rate the discount is taken off — the determiner `OBOLUS_PRICING` selected.
    base: Arc<dyn PriceDeterminer>,
    /// Reads the current Unix time in seconds, per quote. Injected so tests can pin "now" and probe
    /// the window boundary exactly; production reads the wall clock. Kept off [`PriceContext`] so the
    /// seam signature — and every other determiner — is untouched by promotional's need for a clock.
    now: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl Promotional {
    /// A promotion of `discount_bps` basis points off `base`, active during `[start, end)` (Unix
    /// seconds). Reads the wall clock per quote. The config door guarantees `discount_bps < 10000`
    /// and `start < end` before this is constructed.
    pub fn new(discount_bps: u32, start: u64, end: u64, base: Arc<dyn PriceDeterminer>) -> Self {
        Self {
            discount_bps,
            start,
            end,
            base,
            // Before the epoch is impossible for a real clock; if it somehow reads so, `0` sorts
            // before any sane window start, so the base rate applies — a clock fault never invents a
            // discount.
            now: Box::new(|| {
                SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
            }),
        }
    }
}

impl PriceDeterminer for Promotional {
    fn quote(&self, ctx: PriceContext<'_>) -> u128 {
        // The base rate prices first; the promo only ever marks its result down. Computed before the
        // window check so a per-backend or per-model base still sees every field it keys on.
        let base = self.base.quote(ctx);
        let now = (self.now)();
        if self.start <= now && now < self.end {
            // `discount_bps < 10000` on the configured path, so `kept` is in [1, 10000] and the
            // discounted quote never exceeds `base`. `saturating_sub` keeps `quote` total for a
            // caller that bypassed the config door: a `discount_bps >= 10000` there yields `kept` 0
            // rather than an underflow panic on the paying path.
            let kept = BPS_PER_WHOLE.saturating_sub(self.discount_bps as u128);
            let discounted = base.saturating_mul(kept) / BPS_PER_WHOLE;
            // A promotion never turns a *payable* request free. The floor above reaches zero for a
            // deep discount on a small base — `1000 * 5 / 10000 = 0` at 99.95% off, and 99.95% is a
            // discount the config door admits (it refuses only `>= 100%`) — and for a
            // `discount_bps >= 10000` that reached this determiner past the door. Zero is the *free*
            // rate's amount, and free drives a settle path this rate deliberately does not exercise
            // (#67); a promo sliding into it by rounding would cross that boundary silently and
            // unpriced. So a base that was payable but floored to zero quotes one atomic unit — the
            // fail-toward-charging direction, matching the `u128::MAX` sentinels elsewhere in this
            // file. A base already zero stays zero: that is the base rate's decision, not the promo's.
            if base > 0 && discounted == 0 {
                1
            } else {
                discounted
            }
        } else {
            base
        }
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
            amount: amount.to_string(),
            asset: "0xTEST-ASSET".to_string(),
            pay_to: "0xTEST-PAY-TO".to_string(),
            max_timeout_seconds: 60,
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
    fn cost_plus_marks_the_backends_cost_up_by_the_margin() {
        // Cost 1000 (from the backend) + 2500 bps (25%) margin = 1250, whatever the requirement's
        // own amount was.
        let backend = backend().with_cost(1000);
        let rate = CostPlus::new(2500);
        assert_eq!(rate.quote(ctx(&backend, &requirement("1"))), 1250);
        assert_eq!(rate.quote(ctx(&backend, &requirement("999999"))), 1250);
    }

    #[test]
    fn cost_plus_prices_each_backend_from_its_own_cost() {
        // The point of per-backend cost: one determiner, one margin, but the quote follows the
        // routed backend's declared cost.
        let cheap = backend().with_cost(1000);
        let dear = backend().with_cost(2000);
        let rate = CostPlus::new(2500);
        assert_eq!(rate.quote(ctx(&cheap, &requirement("1"))), 1250);
        assert_eq!(rate.quote(ctx(&dear, &requirement("1"))), 2500);
    }

    #[test]
    fn cost_plus_with_zero_margin_quotes_the_cost_exactly() {
        // Break-even is a legitimate rate: charge the upstream cost and take nothing on top.
        let backend = backend().with_cost(1000);
        assert_eq!(CostPlus::new(0).quote(ctx(&backend, &requirement("1"))), 1000);
    }

    #[test]
    fn cost_plus_keeps_sub_percent_margin_precision() {
        // 250 bps = 2.5%, which an integer-percentage margin could not express. 1000 + 25 = 1025.
        let backend = backend().with_cost(1000);
        assert_eq!(CostPlus::new(250).quote(ctx(&backend, &requirement("1"))), 1025);
    }

    #[test]
    fn cost_plus_floors_a_sub_unit_markup_to_zero() {
        // The markup is whole atomic units, so when `cost * margin_bps < 10000` the exact markup is
        // less than one unit and floors to zero — the quote is the bare cost. This rounds toward the
        // payer (never overcharges) and loses under one atomic unit of margin; it is why the doc
        // says the margin is exact but the markup is floored, not that every quote is exact.
        // 3 * 2500 / 10000 = 0.
        let backend = backend().with_cost(3);
        assert_eq!(CostPlus::new(2500).quote(ctx(&backend, &requirement("1"))), 3);
    }

    #[test]
    fn cost_plus_fails_closed_on_an_overflowing_markup() {
        // A cost and margin whose product overflows u128 must not wrap to a tiny quote and sell the
        // work off cheap. Saturating arithmetic yields a quote near the maximum — unpayable — the
        // same fail-closed direction as StaticPrice's unparseable guard.
        let backend = backend().with_cost(u128::MAX);
        let rate = CostPlus::new(u32::MAX);
        assert_eq!(rate.quote(ctx(&backend, &requirement("1"))), u128::MAX);
    }

    #[test]
    fn cost_plus_fails_closed_on_a_costless_backend() {
        // Unreachable in a configured gateway — the config door refuses cost-plus unless every
        // backend has a cost — but if a costless backend ever reached the seam, the quote must be
        // the unpayable maximum, never zero (which would give the work away).
        let backend = backend(); // no cost declared
        assert_eq!(CostPlus::new(2500).quote(ctx(&backend, &requirement("1"))), u128::MAX);
    }

    /// A promotion whose clock is pinned to `now`, so a test can place "now" exactly relative to the
    /// window. Sets the private `now` field directly (a child module reaches its parent's privates),
    /// which is why the production struct needs no test-only constructor.
    fn promo_at(
        now: u64,
        discount_bps: u32,
        start: u64,
        end: u64,
        base: Arc<dyn PriceDeterminer>,
    ) -> Promotional {
        Promotional { discount_bps, start, end, base, now: Box::new(move || now) }
    }

    fn flat(amount: u128) -> Arc<dyn PriceDeterminer> {
        Arc::new(FlatPrice::new(amount))
    }

    #[test]
    fn promotional_discounts_the_base_inside_the_window() {
        // 25% off a flat 1000 → 750, with now (150) inside [100, 200).
        let backend = backend();
        let promo = promo_at(150, 2500, 100, 200, flat(1000));
        assert_eq!(promo.quote(ctx(&backend, &requirement("1"))), 750);
    }

    #[test]
    fn promotional_window_start_is_inclusive_and_end_is_exclusive() {
        // The boundary semantics `[start, end)` promises: at start the discount is on, at end it is
        // off. Charging the discounted price for one extra second past `end`, or withholding it at
        // the first instant of the promo, would both be wrong.
        let backend = backend();
        let at_start = promo_at(100, 2500, 100, 200, flat(1000));
        let at_end = promo_at(200, 2500, 100, 200, flat(1000));
        assert_eq!(at_start.quote(ctx(&backend, &requirement("1"))), 750);
        assert_eq!(at_end.quote(ctx(&backend, &requirement("1"))), 1000);
    }

    #[test]
    fn promotional_leaves_the_base_untouched_outside_the_window() {
        // Before the window opens and after it closes, the base rate is quoted with no discount.
        let backend = backend();
        let before = promo_at(99, 2500, 100, 200, flat(1000));
        let after = promo_at(250, 2500, 100, 200, flat(1000));
        assert_eq!(before.quote(ctx(&backend, &requirement("1"))), 1000);
        assert_eq!(after.quote(ctx(&backend, &requirement("1"))), 1000);
    }

    #[test]
    fn promotional_composes_over_cost_plus() {
        // The promo discounts whatever the base produced, not the requirement's own amount: cost-plus
        // quotes 1250 (cost 1000 + 25% margin), then 20% off inside the window → 1000. This is the
        // point of a percentage modifier — it layers over the money rate, which a fixed promo amount
        // could not do across assets.
        let backend = backend().with_cost(1000);
        let inside = promo_at(150, 2000, 100, 200, Arc::new(CostPlus::new(2500)));
        let outside = promo_at(250, 2000, 100, 200, Arc::new(CostPlus::new(2500)));
        assert_eq!(inside.quote(ctx(&backend, &requirement("1"))), 1000);
        assert_eq!(outside.quote(ctx(&backend, &requirement("1"))), 1250);
    }

    #[test]
    fn promotional_floors_a_sub_unit_discount_toward_the_payer() {
        // base 3, 25% off = 2.25, floored to 2 — the same rounding direction as the cost-plus markup
        // floor: the payer gets the lower whole unit, never overcharged, losing under one unit.
        let backend = backend();
        let promo = promo_at(150, 2500, 100, 200, flat(3));
        assert_eq!(promo.quote(ctx(&backend, &requirement("1"))), 2);
    }

    #[test]
    fn promotional_never_floors_a_payable_base_to_zero() {
        // A deep but sub-100% discount on a small base: 99.95% off (9995 bps, which the config door
        // admits — it refuses only >= 10000) of 1000 is `1000 * 5 / 10000 = 0` by the raw floor. A
        // promotion must not quote zero and slide into the free rate's settle path, so the payable
        // base floors to one atomic unit, not zero.
        let backend = backend();
        let promo = promo_at(150, 9995, 100, 200, flat(1000));
        assert_eq!(promo.quote(ctx(&backend, &requirement("1"))), 1);
    }

    #[test]
    fn promotional_leaves_an_already_free_base_at_zero() {
        // The clamp lifts only a base that *was* payable. A base that already quotes zero is the
        // base rate's own decision (a free static amount, say) and passes through untouched — the
        // promo does not invent a charge where the base made none.
        let backend = backend();
        let promo = promo_at(150, 2500, 100, 200, flat(0));
        assert_eq!(promo.quote(ctx(&backend, &requirement("1"))), 0);
    }

    #[test]
    fn promotional_bypassing_the_config_door_fails_toward_charging_not_free() {
        // The config door refuses `discount_bps >= 10000`, but the determiner must stay total and
        // fail-closed if one reaches it anyway (a future unvalidated caller). 100%-off of a payable
        // base yields `kept == 0` → a raw zero, clamped to one atomic unit: the fail-toward-charging
        // direction, never a silent giveaway.
        let backend = backend();
        let promo = promo_at(150, 10_000, 100, 200, flat(1000));
        assert_eq!(promo.quote(ctx(&backend, &requirement("1"))), 1);
    }

    #[test]
    fn promotional_new_reads_the_wall_clock() {
        // `new` (not the pinned-clock helper) must consult the real clock. A window that ended in
        // 1970 never covers now, so the base stands; a window open until u64::MAX always covers now,
        // so the discount applies. Together they prove the production clock is wired, without pinning
        // it — the one test that exercises the `SystemTime` path.
        let backend = backend();
        let ended = Promotional::new(2500, 0, 1, flat(1000));
        let open = Promotional::new(2500, 0, u64::MAX, flat(1000));
        assert_eq!(ended.quote(ctx(&backend, &requirement("1"))), 1000);
        assert_eq!(open.quote(ctx(&backend, &requirement("1"))), 750);
    }
}
