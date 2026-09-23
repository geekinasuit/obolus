//! Turning a multi-chain gateway configuration into the payment options a gateway advertises.
//!
//! A [`crate::gateway::Gateway`] can advertise several ways to pay at once — one per
//! `(scheme, network)`, e.g. Base and Solana. This module parses the operator-facing
//! `OBOLUS_ACCEPTS` form — a JSON array of per-chain entries — into [`PaymentRequirements`],
//! folding in the gateway-wide fields and validating each amount.
//!
//! What it deliberately does **not** do is check `(scheme, network)` uniqueness. That invariant
//! belongs to [`Gateway::new`](crate::gateway::Gateway::new), the type that later hands one of these
//! requirements to `settle`: enforcing it there makes a wrong-asset settlement impossible by
//! construction, not merely improbable if a config path remembers to de-duplicate.

use serde::Deserialize;

use crate::backends::Backends;
use crate::x402::{validate_atomic_amount, PaymentRequirements, SCHEME_EXACT};

/// One per-chain entry in `OBOLUS_ACCEPTS`: network / asset / pay-to / price. The gateway-wide
/// fields come from [`SharedOffer`].
///
/// `deny_unknown_fields` on purpose: a typo (`payto`, `amount`) must fail loudly at startup rather
/// than be silently dropped, leaving a challenge with a defaulted-away field that no client can pay
/// or that sends money nowhere.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptEntry {
    network: String,
    asset: String,
    pay_to: String,
    max_amount_required: String,
}

/// The gateway-wide fields folded onto every advertised option — the parts that do not vary by
/// chain.
#[derive(Debug, Clone)]
pub struct SharedOffer {
    pub resource: String,
    pub description: String,
    pub max_timeout_seconds: u64,
}

/// Why an `OBOLUS_ACCEPTS` value could not be turned into payment options.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ConfigError {
    /// Not a JSON array of the expected shape — bad JSON, wrong type, or an unknown/missing field.
    #[error(
        "OBOLUS_ACCEPTS must be a JSON array of \
         {{\"network\",\"asset\",\"payTo\",\"maxAmountRequired\"}} objects: {0}"
    )]
    Malformed(String),

    /// A syntactically valid but empty array. A gateway that advertises nothing can never be paid.
    #[error(
        "OBOLUS_ACCEPTS is an empty array: a gateway must advertise at least one payment option \
         (unset it to use the single-chain OBOLUS_NETWORK / OBOLUS_ASSET / OBOLUS_PAY_TO / \
         OBOLUS_PRICE variables instead)"
    )]
    Empty,

    /// An entry's `maxAmountRequired` is not a non-negative integer in atomic units. Names the
    /// offending network so an operator can find the bad entry.
    #[error("OBOLUS_ACCEPTS entry for network {network:?}: maxAmountRequired {detail}")]
    BadAmount { network: String, detail: String },

    /// An entry's `network` is empty. It is the match key, so the gateway starts cleanly and 402s
    /// every request forever — the same failure [`Empty`](ConfigError::Empty) guards against,
    /// arriving through a different door.
    #[error("OBOLUS_ACCEPTS entry has an empty network; network is the match key and must be set")]
    EmptyNetwork,

    /// An entry's `asset` or `pay_to` is present but empty — a *missing* one is already rejected, so
    /// this is the `""` case, advertising an option that sends money nowhere. Names the entry's
    /// network so an operator can find it.
    #[error("OBOLUS_ACCEPTS entry for network {network:?}: {field} must not be empty")]
    EmptyField { network: String, field: EntryField },
}

impl ConfigError {
    /// Name an [`EntryDefect`] as an `OBOLUS_ACCEPTS` problem, tagging it with the entry's network
    /// so an operator can find it in a multi-entry array. The single-chain arm of `main` maps the
    /// same defects onto the variable names *it* reads; see [`validated_option`].
    fn in_accepts_entry(network: String, defect: EntryDefect) -> Self {
        match defect {
            EntryDefect::EmptyNetwork => ConfigError::EmptyNetwork,
            EntryDefect::EmptyField { field } => ConfigError::EmptyField { network, field },
            EntryDefect::BadAmount(detail) => ConfigError::BadAmount { network, detail },
        }
    }
}

/// Which of an option's fields is empty.
///
/// A closed set, so the compiler makes every consumer say something true about each member. A
/// `&'static str` is the same shape with exhaustiveness switched off: `main`'s `single_chain_defect`
/// discriminates on the value behind a `{ .. }` catch-all, so a third empty-able field added to
/// [`validated_option`] would compile clean and tell an operator to go and clear a variable that was
/// fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryField {
    /// The token a client pays in.
    Asset,
    /// The address that receives payment.
    PayTo,
}

impl std::fmt::Display for EntryField {
    /// The `OBOLUS_ACCEPTS` JSON key, not the Rust field name — an operator has to find this in
    /// their own array.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            EntryField::Asset => "asset",
            EntryField::PayTo => "payTo",
        })
    }
}

/// Why one payment option is unusable, named without reference to *how* it was configured.
///
/// The same four fields reach [`PaymentRequirements`] by two doors — an `OBOLUS_ACCEPTS` entry and
/// `main`'s single-chain arm — and the defects are identical at both. What differs is only the name
/// an operator must go and fix: `OBOLUS_ACCEPTS entry for network "…"` on one path,
/// `OBOLUS_PAY_TO` on the other. So the *checking* lives once, here, and each caller supplies its own
/// naming; a check added at one call site instead leaves the other door open.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum EntryDefect {
    /// `network` is absent or whitespace-only. It is the gateway's match key, so an empty one can
    /// never match a real payment envelope: the gateway would start cleanly and 402 every request
    /// forever.
    #[error("network is the match key and must be set")]
    EmptyNetwork,

    /// `asset` or `pay_to` is present but empty — an option that says where money comes from and
    /// goes to, and names neither.
    #[error("{field} must not be empty")]
    EmptyField { field: EntryField },

    /// The amount is not a non-negative integer in atomic units — not a different price, but one no
    /// client can pay. Carries [`validate_atomic_amount`]'s own detail verbatim so both callers can
    /// keep the wording they had.
    #[error("{0}")]
    BadAmount(String),
}

/// Build one advertised payment option, applying the validation **both** configuration forms owe.
///
/// This is the single per-option seam: every field an operator can set arrives here, from either
/// door, before it can become something a client pays against. So CAIP-2 canonicalisation (#14)
/// belongs here, not in [`parse_accepts`] — landing it there would canonicalise the multi-chain path
/// and leave the default single-chain one raw.
///
/// Trimming is deliberately *not* done: what the guard checks must be byte-identical to what is
/// advertised, and silently trimming here would make `" eip155:84532 "` boot while the near-miss
/// diagnosis that exists to explain it never fires. Emptiness is judged on the trimmed value because
/// a whitespace-only id is not a value.
pub fn validated_option(
    network: String,
    asset: String,
    pay_to: String,
    max_amount_required: &str,
    shared: &SharedOffer,
) -> Result<PaymentRequirements, EntryDefect> {
    if network.trim().is_empty() {
        return Err(EntryDefect::EmptyNetwork);
    }
    if asset.trim().is_empty() {
        return Err(EntryDefect::EmptyField { field: EntryField::Asset });
    }
    if pay_to.trim().is_empty() {
        return Err(EntryDefect::EmptyField { field: EntryField::PayTo });
    }
    let amount = validate_atomic_amount(max_amount_required).map_err(EntryDefect::BadAmount)?;
    Ok(PaymentRequirements {
        scheme: SCHEME_EXACT.to_string(),
        network,
        max_amount_required: amount,
        resource: shared.resource.clone(),
        description: shared.description.clone(),
        mime_type: "application/json".to_string(),
        pay_to,
        max_timeout_seconds: shared.max_timeout_seconds,
        asset,
        extra: None,
    })
}

/// Parse an `OBOLUS_ACCEPTS` JSON array into the payment options a gateway advertises, folding in
/// the `shared` fields and validating each entry via [`validated_option`]. See the module docs on
/// why `(scheme, network)` uniqueness is *not* checked here.
pub fn parse_accepts(
    raw: &str,
    shared: &SharedOffer,
) -> Result<Vec<PaymentRequirements>, ConfigError> {
    let entries: Vec<AcceptEntry> =
        serde_json::from_str(raw).map_err(|e| ConfigError::Malformed(e.to_string()))?;
    if entries.is_empty() {
        return Err(ConfigError::Empty);
    }
    entries
        .into_iter()
        .map(|entry| {
            // Kept for the error message only: `validated_option` consumes the field, and naming
            // the offending entry is what lets an operator find it in a multi-entry array.
            let named = entry.network.clone();
            validated_option(
                entry.network,
                entry.asset,
                entry.pay_to,
                &entry.max_amount_required,
                shared,
            )
            .map_err(|defect| ConfigError::in_accepts_entry(named, defect))
        })
        .collect()
}

/// The single-chain payment variables that `OBOLUS_ACCEPTS` supersedes. When `OBOLUS_ACCEPTS` is set
/// these are inert, so an operator who sets both has almost certainly configured a network they
/// believe is live but is not — exactly the surprise a payment gateway must not ship silently.
pub const SINGLE_CHAIN_VARS: [&str; 4] =
    ["OBOLUS_NETWORK", "OBOLUS_ASSET", "OBOLUS_PAY_TO", "OBOLUS_PRICE"];

/// Which of the [`SINGLE_CHAIN_VARS`] are present, given a presence probe. Taking the probe as an
/// argument keeps this testable without mutating process-global environment state; `main` passes
/// `|k| std::env::var(k).is_ok()`. A non-empty result means both configuration forms were set, and
/// the caller should refuse to start rather than silently ignore the inert one.
pub fn superseded_single_chain_vars<F: Fn(&str) -> bool>(is_set: F) -> Vec<&'static str> {
    SINGLE_CHAIN_VARS.into_iter().filter(|&k| is_set(k)).collect()
}

/// Selects the pricing rate. Unset (or `static`) keeps today's behaviour — each option quoted at
/// its own armed amount; `cost-plus` selects [`crate::pricing::CostPlus`].
pub const PRICING_VAR: &str = "OBOLUS_PRICING";
/// Cost-plus's declared upstream cost, atomic units. Required when `OBOLUS_PRICING=cost-plus`.
pub const UPSTREAM_COST_VAR: &str = "OBOLUS_UPSTREAM_COST";
/// Cost-plus's margin, in basis points (10000 = 100%). Required when `OBOLUS_PRICING=cost-plus`.
pub const MARGIN_BPS_VAR: &str = "OBOLUS_MARGIN_BPS";

/// A promotional discount off the selected rate, in basis points (2500 = 25% off). Set together
/// with [`PROMO_START_VAR`] and [`PROMO_END_VAR`] — all three or none.
pub const PROMO_DISCOUNT_BPS_VAR: &str = "OBOLUS_PROMO_DISCOUNT_BPS";
/// When the promotional window opens, Unix seconds (inclusive). See [`PROMO_DISCOUNT_BPS_VAR`].
pub const PROMO_START_VAR: &str = "OBOLUS_PROMO_START";
/// When the promotional window closes, Unix seconds (exclusive). See [`PROMO_DISCOUNT_BPS_VAR`].
pub const PROMO_END_VAR: &str = "OBOLUS_PROMO_END";

/// The pricing rate an operator selected, ready for `main` to build a determiner from. A plain data
/// value, not a determiner: the determiner types live in [`crate::pricing`], and keeping the config
/// door's output free of them lets this parse and its refusals be unit-tested without wiring a
/// gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PricingChoice {
    /// The behaviour-preserving default: [`crate::pricing::StaticPrice`], each option at its own
    /// armed amount.
    Static,
    /// Cost-plus ([`crate::pricing::CostPlus`]): each backend's declared cost marked up by a
    /// gateway-wide `margin_bps` basis points. The cost lives on the backend, not here — so this
    /// carries only the margin, and `upstream_cost`: the single-backend path's `OBOLUS_UPSTREAM_COST`
    /// value, which `main` attaches to the sole backend (`None` when a backends file declares the
    /// cost per entry instead). Every backend having a cost is enforced by [`require_backend_costs`].
    CostPlus { margin_bps: u32, upstream_cost: Option<u128> },
}

/// Why a pricing configuration could not be turned into a [`PricingChoice`]. Each is a boot refusal:
/// a gateway that priced wrongly — or advertised an amount it would not charge — is worse than one
/// that will not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PricingConfigError {
    /// `OBOLUS_PRICING` names something that is not a rate — a typo, or an unexpanded `${VAR}` that
    /// arrived empty. Refused rather than guessed, so a mistyped rate never silently falls back to a
    /// price the operator did not choose.
    #[error(
        "OBOLUS_PRICING {value:?} is not a known rate. Set it to \"static\" (the default — each \
         advertised option keeps its own configured amount) or \"cost-plus\", or unset it."
    )]
    UnknownRate { value: String },

    /// `cost-plus` is selected but its margin is absent. Cost-plus infers no margin, so a missing
    /// one is a refusal, not a default. (The cost is not required here — it may be declared per
    /// backend in `OBOLUS_BACKENDS_FILE` instead of via `OBOLUS_UPSTREAM_COST`; that every backend
    /// has one is checked by [`require_backend_costs`], not here.)
    #[error("OBOLUS_PRICING is \"cost-plus\" but {var} is not set: {detail}")]
    MissingParam { var: &'static str, detail: &'static str },

    /// The declared cost is not a non-negative integer in atomic units — the same shape
    /// [`validate_atomic_amount`] rejects for an advertised amount, applied to the cost cost-plus
    /// marks up.
    #[error(
        "OBOLUS_UPSTREAM_COST {value:?} is not a non-negative integer in atomic units \
         (no decimals, sign, separators, or exponent)."
    )]
    BadCost { value: String },

    /// The declared cost is zero. A zero cost is not a cost to mark up (any margin on zero is still
    /// zero), and a zero quote would reach the settle-a-zero-amount path this rate deliberately does
    /// not cover. Serving requests free is a distinct rate, not cost-plus.
    #[error(
        "OBOLUS_UPSTREAM_COST is 0: a zero upstream cost is not a cost to mark up (any margin on \
         zero is still zero). Set the upstream cost cost-plus should mark up; serving free is a \
         separate rate, not cost-plus."
    )]
    ZeroCost,

    /// The margin is not a whole number of basis points.
    #[error(
        "OBOLUS_MARGIN_BPS {value:?} is not a whole number of basis points \
         (10000 = 100%, 2500 = 25%, 250 = 2.5%)."
    )]
    BadMargin { value: String },

    /// `cost-plus` is selected alongside the multi-chain `OBOLUS_ACCEPTS`. A declared cost is in
    /// atomic units of one asset; the several networks `OBOLUS_ACCEPTS` advertises carry different
    /// assets and decimals, so a cost is ambiguous across them. Per-*backend* cost is supported;
    /// per-*network* (cross-asset) cost is later work — it needs a reference cost unit plus a
    /// per-network conversion — so this combination is deliberately refused.
    #[error(
        "OBOLUS_PRICING is \"cost-plus\" and OBOLUS_ACCEPTS is set. A cost-plus cost is in atomic \
         units of a single asset, and the several networks OBOLUS_ACCEPTS advertises carry \
         different assets and decimals, so one cost is ambiguous across them — multi-chain \
         cost-plus pricing is not supported yet. Unset OBOLUS_ACCEPTS to price a single chain with \
         cost-plus, or unset OBOLUS_PRICING to advertise each entry's own amount."
    )]
    CostPlusMultiChain,

    /// `cost-plus` is selected alongside an explicitly configured `OBOLUS_PRICE`. Under cost-plus
    /// the amount comes from the cost and margin, so `OBOLUS_PRICE` would sit inert — the
    /// silently-ignored-payment-config surprise the `OBOLUS_ACCEPTS` supersession also guards.
    #[error(
        "OBOLUS_PRICING is \"cost-plus\", which sets every amount from a declared cost and \
         OBOLUS_MARGIN_BPS, but OBOLUS_PRICE is also set and would be silently ignored. Remove \
         OBOLUS_PRICE, or unset OBOLUS_PRICING to charge that amount instead."
    )]
    InertPrice,

    /// Cost-plus's parameters are set, but `cost-plus` is not selected — so they would sit inert. The
    /// `OBOLUS_TOKEN_ISSUER`-without-a-key shape: configuration that cannot take effect refuses
    /// rather than being dropped.
    #[error(
        "{vars} configure cost-plus pricing, but OBOLUS_PRICING is not \"cost-plus\", so they would \
         be silently ignored. Set OBOLUS_PRICING=cost-plus to use them, or unset them."
    )]
    OrphanedParams { vars: String },

    /// `cost-plus` is selected but one or more backends declare no cost. The rate marks up each
    /// backend's own declared cost; a backend without one cannot be priced, and guessing a cost is
    /// the fail-open the boot refusals exist to prevent. Names the backends so the operator knows
    /// which to fix. A cross-source refusal (the registry plus the rate), so it lives in
    /// [`require_backend_costs`], not [`select_pricing`].
    #[error(
        "OBOLUS_PRICING is \"cost-plus\" but these backends declare no cost: {ids}. Cost-plus marks \
         up each backend's declared cost, so every backend needs one — set OBOLUS_UPSTREAM_COST for \
         the single-backend setup, or a per-entry \"cost\" in OBOLUS_BACKENDS_FILE."
    )]
    MissingBackendCost { ids: String },

    /// A backend declares a `cost`, but `cost-plus` is not selected — so the cost would sit inert,
    /// the same silently-ignored-config surprise `OrphanedParams` guards for `OBOLUS_UPSTREAM_COST`.
    /// Names the backends so the operator knows which entries to fix.
    #[error(
        "these backends declare a cost: {ids}, but OBOLUS_PRICING is not \"cost-plus\", so the cost \
         would be silently ignored. Set OBOLUS_PRICING=cost-plus to use it, or remove the cost."
    )]
    InertBackendCost { ids: String },
}

/// Turn the pricing environment into a [`PricingChoice`], or refuse.
///
/// `get` returns a variable's value if it is set (`main` passes `|k| std::env::var(k).ok()`).
/// Taking it as an argument keeps every refusal testable without mutating process-global
/// environment state, exactly as [`superseded_single_chain_vars`] does for the supersession check.
///
/// Presence, not just value, is load-bearing here. `OBOLUS_PRICE` has a default (`"1000"`), so the
/// inert-amount refusal keys on whether it was *explicitly set* — an operator who never set it must
/// not be refused on a default they do not know exists. And `OBOLUS_ACCEPTS` / `OBOLUS_PRICE` are
/// mutually exclusive by the time `main` calls this (the requirements block above refuses both at
/// once), so at most one inert-amount refusal can fire in the running binary; checking both keeps
/// this function correct in isolation.
pub fn select_pricing<F: Fn(&str) -> Option<String>>(
    get: F,
) -> Result<PricingChoice, PricingConfigError> {
    // The orphaned-parameter refusal, shared by the unset and explicit-`static` paths: cost-plus's
    // parameters set without cost-plus selected would sit inert.
    let static_or_orphan = |get: &F| -> Result<PricingChoice, PricingConfigError> {
        let orphaned: Vec<&str> = [UPSTREAM_COST_VAR, MARGIN_BPS_VAR]
            .into_iter()
            .filter(|&k| get(k).is_some())
            .collect();
        if orphaned.is_empty() {
            Ok(PricingChoice::Static)
        } else {
            Err(PricingConfigError::OrphanedParams { vars: orphaned.join(", ") })
        }
    };

    match get(PRICING_VAR) {
        None => static_or_orphan(&get),
        Some(raw) => match raw.trim() {
            "static" => static_or_orphan(&get),
            "cost-plus" => {
                // Combination refusals before parameter parsing: a wrong pairing is a more
                // fundamental misconfiguration than a malformed parameter, and naming it first is
                // what an operator has to fix first.
                if get("OBOLUS_ACCEPTS").is_some() {
                    return Err(PricingConfigError::CostPlusMultiChain);
                }
                if get("OBOLUS_PRICE").is_some() {
                    return Err(PricingConfigError::InertPrice);
                }
                // The single-backend cost. Optional here: with a backends file the cost is declared
                // per entry instead (and OBOLUS_UPSTREAM_COST is refused alongside the file, in
                // `main`), so its absence is not a refusal — a backend that ends up with no cost is
                // caught by `require_backend_costs`, which names it. When present it is validated the
                // way the single-backend amount is: a direct `u128` parse, the value kept because
                // the cost is computed with, not advertised verbatim. Zero is a valid atomic amount
                // yet refused; see `ZeroCost`.
                let upstream_cost = match get(UPSTREAM_COST_VAR) {
                    None => None,
                    Some(raw) => match raw.parse::<u128>() {
                        Ok(0) => return Err(PricingConfigError::ZeroCost),
                        Ok(cost) => Some(cost),
                        Err(_) => return Err(PricingConfigError::BadCost { value: raw }),
                    },
                };
                let margin_bps = match get(MARGIN_BPS_VAR) {
                    None => {
                        return Err(PricingConfigError::MissingParam {
                            var: MARGIN_BPS_VAR,
                            detail: "the margin to add, in basis points (10000 = 100%)",
                        })
                    }
                    Some(raw) => match raw.parse::<u32>() {
                        Ok(bps) => bps,
                        Err(_) => return Err(PricingConfigError::BadMargin { value: raw }),
                    },
                };
                Ok(PricingChoice::CostPlus { margin_bps, upstream_cost })
            }
            _ => Err(PricingConfigError::UnknownRate { value: raw }),
        },
    }
}

/// The cross-source coverage check: does the selected rate agree with what the backends declare?
///
/// [`select_pricing`] sees only the environment; [`crate::backends::load_backends`] sees only the
/// backends file. Whether *every* backend has the cost cost-plus needs — or whether a backend
/// declares a cost no selected rate would read — is a fact about both at once, so it is checked
/// here, once `main` has both in hand and before it prints the banner or arms the gateway.
///
/// Two symmetric refusals, both instances of the same rule the boot path holds throughout:
/// configuration that cannot take effect refuses rather than being silently dropped.
/// - cost-plus with a costless backend → [`PricingConfigError::MissingBackendCost`]: the rate marks
///   up each backend's own cost, and guessing one for the backend that lacks it is the fail-open
///   these refusals exist to prevent.
/// - a backend cost with any non-cost-plus rate → [`PricingConfigError::InertBackendCost`]: the cost
///   would sit unread, the `OrphanedParams` surprise arriving through the backends file.
///
/// Each refusal names the offending backends by id so an operator can find the entries to fix.
pub fn require_backend_costs(
    backends: &Backends,
    pricing: PricingChoice,
) -> Result<(), PricingConfigError> {
    let named = |select: fn(&crate::backends::Backend) -> bool| -> String {
        backends
            .backends()
            .iter()
            .filter(|b| select(b))
            .map(|b| b.id.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match pricing {
        PricingChoice::CostPlus { .. } => {
            let missing = named(|b| b.cost.is_none());
            if missing.is_empty() {
                Ok(())
            } else {
                Err(PricingConfigError::MissingBackendCost { ids: missing })
            }
        }
        PricingChoice::Static => {
            let inert = named(|b| b.cost.is_some());
            if inert.is_empty() {
                Ok(())
            } else {
                Err(PricingConfigError::InertBackendCost { ids: inert })
            }
        }
    }
}

/// A promotional discount an operator configured, ready for `main` to wrap the base determiner with.
/// A plain data value like [`PricingChoice`]: the [`crate::pricing::Promotional`] determiner is
/// built from it in `main`, so this parse and its refusals are unit-testable without a gateway.
///
/// A promotion is a *modifier* on whichever rate [`PricingChoice`] selected, not a rate of its own —
/// it discounts a percentage off that rate during a window — so it is parsed separately here and
/// carries no `PricingChoice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromoConfig {
    /// Basis points off the base rate during the window (2500 = 25% off). Always in `1..10000`: a
    /// zero discount and a 100%-or-more discount are both refused (see [`PromoConfigError`]).
    pub discount_bps: u32,
    /// When the window opens, Unix seconds, inclusive.
    pub start: u64,
    /// When the window closes, Unix seconds, exclusive. Always strictly after `start` and after the
    /// boot instant.
    pub end: u64,
}

/// Why a promotional configuration could not be turned into a [`PromoConfig`]. Each is a boot
/// refusal, the same posture the pricing door holds: a gateway that advertised a promotional window
/// it would not honour — or one that discounts nothing, or everything — is worse than one that will
/// not start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PromoConfigError {
    /// Some of the three promo variables are set and some are not. A promotion needs all three (a
    /// discount and both window bounds); a partial set cannot describe one, and dropping the partial
    /// config silently is the surprise the pricing door's `OrphanedParams` also guards against.
    #[error(
        "a promotional discount needs all of OBOLUS_PROMO_DISCOUNT_BPS, OBOLUS_PROMO_START and \
         OBOLUS_PROMO_END; set: {present}; missing: {missing}. Set all three to run a promotion, or \
         unset the rest."
    )]
    Incomplete { present: String, missing: String },

    /// The discount is not a whole number of basis points.
    #[error(
        "OBOLUS_PROMO_DISCOUNT_BPS {value:?} is not a whole number of basis points \
         (2500 = 25% off, 250 = 2.5% off)."
    )]
    BadDiscount { value: String },

    /// The discount is zero. A promotion that discounts nothing quotes exactly the base rate, so it
    /// advertises a promotional window that changes no price — inert config, refused rather than
    /// dropped, the same rule as `OBOLUS_UPSTREAM_COST=0`.
    #[error(
        "OBOLUS_PROMO_DISCOUNT_BPS is 0: a promotion that discounts nothing is the base rate. Set \
         the basis points to discount (2500 = 25% off), or unset the promotional variables."
    )]
    ZeroDiscount,

    /// The discount is 100% or more. That makes the request free, and a free rate settles a
    /// zero-value authorization differently from a paid one; it is configured separately, not as a
    /// promotion, so this door only admits a discount that still leaves an amount to pay.
    #[error(
        "OBOLUS_PROMO_DISCOUNT_BPS is {value}: 10000 bps is 100% off, which makes the request free. \
         A free rate settles differently and is configured separately, not as a promotion. Set a \
         discount below 10000."
    )]
    DiscountTooLarge { value: u32 },

    /// A window bound is not a non-negative integer of Unix seconds.
    #[error("{var} {value:?} is not a Unix timestamp in whole seconds.")]
    BadTimestamp { var: &'static str, value: String },

    /// The window is empty or inverted: `start` is not strictly before `end`. A window that never
    /// opens cannot be a promotion.
    #[error(
        "OBOLUS_PROMO_START ({start}) is not before OBOLUS_PROMO_END ({end}): a promotional window \
         must open before it closes."
    )]
    EmptyWindow { start: u64, end: u64 },

    /// The window closed before boot. Its discount could never apply, yet the banner would advertise
    /// a promotion — the advertise-what-you-won't-charge trap the arming banner also refuses. A
    /// window still open, or one entirely in the future, is fine; only an already-closed one refuses.
    #[error(
        "OBOLUS_PROMO_END ({end}) is at or before now ({now}, Unix seconds): the promotional window \
         has already closed, so its discount could never apply. Set a window that has not ended, or \
         unset the promotional variables."
    )]
    AlreadyEnded { end: u64, now: u64 },
}

/// Turn the promotional environment into an optional [`PromoConfig`], or refuse.
///
/// `get` reads a variable's value as [`select_pricing`] does. `now_unix` is the boot instant in Unix
/// seconds, passed in rather than read here so every refusal — including the already-closed-window
/// one — is deterministically testable; `main` reads the wall clock once and passes it.
///
/// Returns `Ok(None)` when no promotional variable is set — the common case, no promotion. All three
/// set and valid returns `Ok(Some(_))`; anything between is a refusal.
pub fn select_promo<F: Fn(&str) -> Option<String>>(
    get: F,
    now_unix: u64,
) -> Result<Option<PromoConfig>, PromoConfigError> {
    let vars = [PROMO_DISCOUNT_BPS_VAR, PROMO_START_VAR, PROMO_END_VAR];
    let present: Vec<&str> = vars.into_iter().filter(|&k| get(k).is_some()).collect();
    if present.is_empty() {
        return Ok(None);
    }
    if present.len() < vars.len() {
        let missing: Vec<&str> = vars.into_iter().filter(|&k| get(k).is_none()).collect();
        return Err(PromoConfigError::Incomplete {
            present: present.join(", "),
            missing: missing.join(", "),
        });
    }

    // All three present. Parse without trimming, as the cost and margin parses do: a value with
    // stray whitespace is a malformed value, refused, not silently accepted.
    let discount_raw = get(PROMO_DISCOUNT_BPS_VAR).expect("present checked above");
    let discount_bps = match discount_raw.parse::<u32>() {
        Ok(bps) => bps,
        Err(_) => return Err(PromoConfigError::BadDiscount { value: discount_raw }),
    };
    if discount_bps == 0 {
        return Err(PromoConfigError::ZeroDiscount);
    }
    if discount_bps >= 10_000 {
        return Err(PromoConfigError::DiscountTooLarge { value: discount_bps });
    }

    let parse_ts = |var: &'static str| -> Result<u64, PromoConfigError> {
        let raw = get(var).expect("present checked above");
        raw.parse::<u64>().map_err(|_| PromoConfigError::BadTimestamp { var, value: raw })
    };
    let start = parse_ts(PROMO_START_VAR)?;
    let end = parse_ts(PROMO_END_VAR)?;
    if start >= end {
        return Err(PromoConfigError::EmptyWindow { start, end });
    }
    if end <= now_unix {
        return Err(PromoConfigError::AlreadyEnded { end, now: now_unix });
    }
    Ok(Some(PromoConfig { discount_bps, start, end }))
}

/// Where request telemetry goes: `stdout` (the default) or `off`. See `docs/telemetry.md`.
pub const TELEMETRY_VAR: &str = "OBOLUS_TELEMETRY";

/// The telemetry sink an operator selected. Plain data, like [`PricingChoice`], so the door's
/// refusals are testable without starting a writer thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryChoice {
    /// One JSON line per request on stdout ([`crate::telemetry::LineSink`]).
    Stdout,
    /// No telemetry ([`crate::telemetry::NoTelemetry`]).
    Off,
}

/// Why the telemetry selection was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TelemetryConfigError {
    #[error("OBOLUS_TELEMETRY={value:?} is not a telemetry sink; use \"stdout\" or \"off\"")]
    Unknown { value: String },
}

/// Select the telemetry sink. Unset is `stdout`: an operator running this for money should see
/// revenue against cost without having to ask for it. An unrecognised value is refused rather than
/// read as either default — a typo of `off` must not leave telemetry on, nor one of `stdout` turn it
/// off.
pub fn select_telemetry<F: Fn(&str) -> Option<String>>(
    get: F,
) -> Result<TelemetryChoice, TelemetryConfigError> {
    match get(TELEMETRY_VAR) {
        None => Ok(TelemetryChoice::Stdout),
        Some(raw) => match raw.trim() {
            "stdout" => Ok(TelemetryChoice::Stdout),
            "off" => Ok(TelemetryChoice::Off),
            _ => Err(TelemetryConfigError::Unknown { value: raw }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn telemetry_env(value: Option<&str>) -> impl Fn(&str) -> Option<String> + '_ {
        move |key| (key == TELEMETRY_VAR).then(|| value.map(str::to_string)).flatten()
    }

    #[test]
    fn unset_telemetry_is_stdout() {
        assert_eq!(select_telemetry(telemetry_env(None)), Ok(TelemetryChoice::Stdout));
    }

    #[test]
    fn telemetry_can_be_selected_or_switched_off() {
        assert_eq!(select_telemetry(telemetry_env(Some("stdout"))), Ok(TelemetryChoice::Stdout));
        assert_eq!(select_telemetry(telemetry_env(Some("off"))), Ok(TelemetryChoice::Off));
    }

    #[test]
    fn an_unknown_telemetry_value_is_refused_naming_it() {
        let err = select_telemetry(telemetry_env(Some("of"))).unwrap_err();
        assert_eq!(err, TelemetryConfigError::Unknown { value: "of".to_string() });
        assert!(err.to_string().contains("\"of\""), "{err}");
    }

    fn shared() -> SharedOffer {
        SharedOffer {
            resource: "http://127.0.0.1:8403/v1/chat/completions".to_string(),
            description: "One inference request".to_string(),
            max_timeout_seconds: 60,
        }
    }

    #[test]
    fn parses_a_multi_chain_array_folding_in_the_shared_fields() {
        let raw = r#"[
            {"network":"test-net-a","asset":"0xAAA","payTo":"0xPAYA","maxAmountRequired":"1000"},
            {"network":"test-net-b","asset":"0xBBB","payTo":"0xPAYB","maxAmountRequired":"2000"}
        ]"#;
        let options = parse_accepts(raw, &shared()).unwrap();
        assert_eq!(options.len(), 2);

        assert_eq!(options[0].network, "test-net-a");
        assert_eq!(options[0].asset, "0xAAA");
        assert_eq!(options[0].pay_to, "0xPAYA");
        assert_eq!(options[0].max_amount_required, "1000");
        assert_eq!(options[1].network, "test-net-b");
        assert_eq!(options[1].max_amount_required, "2000");

        // The shared, non-per-chain fields are folded onto every option.
        for o in &options {
            assert_eq!(o.scheme, SCHEME_EXACT);
            assert_eq!(o.resource, shared().resource);
            assert_eq!(o.description, "One inference request");
            assert_eq!(o.mime_type, "application/json");
            assert_eq!(o.max_timeout_seconds, 60);
        }
    }

    #[test]
    fn an_empty_array_is_rejected() {
        assert_eq!(parse_accepts("[]", &shared()), Err(ConfigError::Empty));
    }

    #[test]
    fn a_bad_amount_is_rejected_and_names_the_offending_network() {
        // Reusing validate_atomic_amount means a float / sign / separator is caught here, at config
        // time, and the error points at WHICH entry so an operator can find it in a long array.
        let raw =
            r#"[{"network":"test-net-a","asset":"0xAAA","payTo":"0xPAYA","maxAmountRequired":"1.5"}]"#;
        let err = parse_accepts(raw, &shared()).unwrap_err();
        assert!(matches!(err, ConfigError::BadAmount { .. }), "got {err:?}");
        assert!(err.to_string().contains("test-net-a"), "must name the entry, got: {err}");
    }

    #[test]
    fn an_unknown_field_is_rejected_not_silently_dropped() {
        // deny_unknown_fields: a typo'd key ("payto") must fail, not vanish — otherwise the entry
        // would build a challenge with an empty/defaulted pay-to and quietly send money nowhere.
        let raw = r#"[{"network":"n","asset":"a","payto":"0xTYPO","maxAmountRequired":"1"}]"#;
        let err = parse_accepts(raw, &shared()).unwrap_err();
        assert!(matches!(err, ConfigError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn a_missing_field_is_rejected() {
        let raw = r#"[{"network":"n","asset":"a","maxAmountRequired":"1"}]"#; // no payTo
        let err = parse_accepts(raw, &shared()).unwrap_err();
        assert!(matches!(err, ConfigError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn a_json_object_that_is_not_an_array_is_rejected() {
        let err = parse_accepts(r#"{"network":"n"}"#, &shared()).unwrap_err();
        assert!(matches!(err, ConfigError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn an_empty_network_is_rejected() {
        // network is the match key: an empty one yields a gateway that starts fine and 402s every
        // request forever. Whitespace-only is the same trap, so it is rejected too.
        for bad in [
            r#"[{"network":"","asset":"0xAAA","payTo":"0xPAYA","maxAmountRequired":"1000"}]"#,
            r#"[{"network":"   ","asset":"0xAAA","payTo":"0xPAYA","maxAmountRequired":"1000"}]"#,
        ] {
            let err = parse_accepts(bad, &shared()).unwrap_err();
            assert!(matches!(err, ConfigError::EmptyNetwork), "got {err:?} for {bad}");
        }
    }

    #[test]
    fn an_empty_asset_or_pay_to_is_rejected_naming_the_field_and_network() {
        // Both are required, so a *missing* one is already Malformed; this is the present-but-""
        // case — an option that would advertise sending money nowhere. Caught at startup, named.
        let empty_asset =
            r#"[{"network":"test-net-a","asset":"","payTo":"0xPAYA","maxAmountRequired":"1000"}]"#;
        let err = parse_accepts(empty_asset, &shared()).unwrap_err();
        assert!(
            matches!(&err, ConfigError::EmptyField { field: EntryField::Asset, network } if network == "test-net-a"),
            "got {err:?}",
        );
        // The rendered text as well as the variant: `EntryField`'s `Display` is what puts the JSON
        // key into this message, and a wrong impl would leave the variant assertion above green
        // while telling the operator to fix a field name that is not in their array.
        assert!(err.to_string().contains("asset must not be empty"), "got {err}");

        let empty_pay_to =
            r#"[{"network":"test-net-a","asset":"0xAAA","payTo":"  ","maxAmountRequired":"1000"}]"#;
        let err = parse_accepts(empty_pay_to, &shared()).unwrap_err();
        assert!(
            matches!(&err, ConfigError::EmptyField { field: EntryField::PayTo, .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains("payTo must not be empty"), "got {err}");
    }

    #[test]
    fn superseded_vars_reports_exactly_the_ones_set() {
        // The pay-to and price are also set alongside OBOLUS_ACCEPTS; both must be named so the
        // operator sees which supposedly-live config is actually inert.
        let present =
            superseded_single_chain_vars(|k| k == "OBOLUS_PAY_TO" || k == "OBOLUS_PRICE");
        assert_eq!(present, vec!["OBOLUS_PAY_TO", "OBOLUS_PRICE"]);
    }

    #[test]
    fn no_superseded_vars_when_none_are_set() {
        assert!(superseded_single_chain_vars(|_| false).is_empty());
    }

    /// A `get` closure over a fixed set of `(var, value)` pairs — the presence/value probe
    /// `select_pricing` takes, without touching process-global environment state.
    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn unset_pricing_is_static() {
        assert_eq!(select_pricing(env(&[])), Ok(PricingChoice::Static));
    }

    #[test]
    fn explicit_static_is_static() {
        assert_eq!(select_pricing(env(&[("OBOLUS_PRICING", "static")])), Ok(PricingChoice::Static));
    }

    #[test]
    fn cost_plus_reads_its_margin_and_the_single_backend_cost() {
        // The single-backend path: OBOLUS_UPSTREAM_COST is present and becomes the sole backend's
        // cost (`main` attaches it), carried out of here as `upstream_cost`.
        let choice = select_pricing(env(&[
            ("OBOLUS_PRICING", "cost-plus"),
            ("OBOLUS_UPSTREAM_COST", "1000"),
            ("OBOLUS_MARGIN_BPS", "2500"),
        ]));
        assert_eq!(
            choice,
            Ok(PricingChoice::CostPlus { margin_bps: 2500, upstream_cost: Some(1000) })
        );
    }

    #[test]
    fn cost_plus_without_an_upstream_cost_defers_the_cost_to_the_backends() {
        // The backends-file path: no OBOLUS_UPSTREAM_COST, because each backend declares its own
        // cost. Not a refusal here — `require_backend_costs` is what insists every backend has one.
        let choice = select_pricing(env(&[
            ("OBOLUS_PRICING", "cost-plus"),
            ("OBOLUS_MARGIN_BPS", "2500"),
        ]));
        assert_eq!(
            choice,
            Ok(PricingChoice::CostPlus { margin_bps: 2500, upstream_cost: None })
        );
    }

    #[test]
    fn cost_plus_allows_a_zero_margin() {
        // Break-even is legitimate — a zero margin is a stated choice, not a missing value.
        let choice = select_pricing(env(&[
            ("OBOLUS_PRICING", "cost-plus"),
            ("OBOLUS_UPSTREAM_COST", "1000"),
            ("OBOLUS_MARGIN_BPS", "0"),
        ]));
        assert_eq!(
            choice,
            Ok(PricingChoice::CostPlus { margin_bps: 0, upstream_cost: Some(1000) })
        );
    }

    #[test]
    fn an_unknown_rate_is_rejected_naming_the_value() {
        // A typo (or an unexpanded ${VAR} arriving empty) must refuse, never fall back to a price
        // the operator did not choose.
        for bad in ["cost_plus", "flat", ""] {
            let err = select_pricing(env(&[("OBOLUS_PRICING", bad)])).unwrap_err();
            assert!(
                matches!(&err, PricingConfigError::UnknownRate { value } if value == bad),
                "got {err:?} for {bad:?}",
            );
        }
    }

    #[test]
    fn cost_plus_without_a_margin_is_rejected() {
        let err = select_pricing(env(&[
            ("OBOLUS_PRICING", "cost-plus"),
            ("OBOLUS_UPSTREAM_COST", "1000"),
        ]))
        .unwrap_err();
        assert!(
            matches!(err, PricingConfigError::MissingParam { var: MARGIN_BPS_VAR, .. }),
            "got {err:?}",
        );
    }

    #[test]
    fn a_bad_cost_is_rejected() {
        // The same shape validate_atomic_amount rejects for an advertised amount: floats, signs,
        // separators, and non-numbers are none of them a cost.
        for bad in ["1.5", "-5", "1_000", "1e3", "lots"] {
            let err = select_pricing(env(&[
                ("OBOLUS_PRICING", "cost-plus"),
                ("OBOLUS_UPSTREAM_COST", bad),
                ("OBOLUS_MARGIN_BPS", "2500"),
            ]))
            .unwrap_err();
            assert!(
                matches!(&err, PricingConfigError::BadCost { value } if value == bad),
                "got {err:?} for {bad:?}",
            );
        }
    }

    #[test]
    fn a_zero_cost_is_rejected() {
        // Admissible as an atomic amount, but refused here: nothing to mark up, and the zero-quote
        // settle path is out of this rate's scope.
        let err = select_pricing(env(&[
            ("OBOLUS_PRICING", "cost-plus"),
            ("OBOLUS_UPSTREAM_COST", "0"),
            ("OBOLUS_MARGIN_BPS", "2500"),
        ]))
        .unwrap_err();
        assert_eq!(err, PricingConfigError::ZeroCost);
    }

    #[test]
    fn a_bad_margin_is_rejected() {
        for bad in ["2.5", "-1", "25%", "lots"] {
            let err = select_pricing(env(&[
                ("OBOLUS_PRICING", "cost-plus"),
                ("OBOLUS_UPSTREAM_COST", "1000"),
                ("OBOLUS_MARGIN_BPS", bad),
            ]))
            .unwrap_err();
            assert!(
                matches!(&err, PricingConfigError::BadMargin { value } if value == bad),
                "got {err:?} for {bad:?}",
            );
        }
    }

    #[test]
    fn cost_plus_alongside_obolus_accepts_is_rejected() {
        // Multi-chain cost-plus is deliberately unsupported: one atomic cost is ambiguous across
        // networks with different assets. The combination refuses before any amount is advertised.
        let err = select_pricing(env(&[
            ("OBOLUS_PRICING", "cost-plus"),
            ("OBOLUS_ACCEPTS", "[]"),
            ("OBOLUS_UPSTREAM_COST", "1000"),
            ("OBOLUS_MARGIN_BPS", "2500"),
        ]))
        .unwrap_err();
        assert_eq!(err, PricingConfigError::CostPlusMultiChain);
    }

    #[test]
    fn cost_plus_alongside_an_explicit_price_is_rejected() {
        // OBOLUS_PRICE would sit inert under cost-plus — the silently-ignored-payment-config
        // surprise the OBOLUS_ACCEPTS supersession also guards. Keyed on explicit presence, so an
        // operator who never set OBOLUS_PRICE (and gets its "1000" default) is not refused.
        let err = select_pricing(env(&[
            ("OBOLUS_PRICING", "cost-plus"),
            ("OBOLUS_PRICE", "1000"),
            ("OBOLUS_UPSTREAM_COST", "1000"),
            ("OBOLUS_MARGIN_BPS", "2500"),
        ]))
        .unwrap_err();
        assert_eq!(err, PricingConfigError::InertPrice);
    }

    #[test]
    fn cost_plus_params_without_selecting_cost_plus_are_rejected() {
        // Inert config that looks configured — refused on both the unset and explicit-`static`
        // paths, naming exactly the parameters that would be ignored.
        for pricing in [None, Some("static")] {
            let mut pairs = vec![("OBOLUS_UPSTREAM_COST", "1000"), ("OBOLUS_MARGIN_BPS", "2500")];
            if let Some(p) = pricing {
                pairs.push(("OBOLUS_PRICING", p));
            }
            let err = select_pricing(env(&pairs)).unwrap_err();
            assert!(
                matches!(&err, PricingConfigError::OrphanedParams { vars }
                    if vars.contains("OBOLUS_UPSTREAM_COST") && vars.contains("OBOLUS_MARGIN_BPS")),
                "got {err:?} for OBOLUS_PRICING={pricing:?}",
            );
        }
    }

    // --- require_backend_costs: the cross-source coverage check ---

    use crate::backends::Backend;
    use crate::upstream::{FakeUpstream, Upstream};
    use std::sync::Arc;

    /// A test backend with the given id, model alias, and optional declared cost. The upstream is a
    /// fake; this check never touches it.
    fn backend_costing(id: &str, cost: Option<u128>) -> Backend {
        let upstream: Arc<dyn Upstream> = Arc::new(FakeUpstream::streaming());
        let b = Backend::for_test(id, vec![id], None, upstream);
        match cost {
            Some(c) => b.with_cost(c),
            None => b,
        }
    }

    #[test]
    fn cost_plus_accepts_backends_that_all_declare_a_cost() {
        let backends =
            Backends::from_parts(vec![backend_costing("a", Some(1000)), backend_costing("b", Some(2000))]);
        let pricing = PricingChoice::CostPlus { margin_bps: 2500, upstream_cost: None };
        assert_eq!(require_backend_costs(&backends, pricing), Ok(()));
    }

    #[test]
    fn cost_plus_rejects_a_costless_backend_naming_it() {
        // The rate marks up each backend's own cost; one without a cost cannot be priced, and
        // guessing one is the fail-open these boot refusals prevent. The refusal names the entry.
        let backends =
            Backends::from_parts(vec![backend_costing("has-cost", Some(1000)), backend_costing("no-cost", None)]);
        let pricing = PricingChoice::CostPlus { margin_bps: 2500, upstream_cost: None };
        let err = require_backend_costs(&backends, pricing).unwrap_err();
        assert!(
            matches!(&err, PricingConfigError::MissingBackendCost { ids } if ids == "no-cost"),
            "got {err:?}",
        );
    }

    #[test]
    fn static_accepts_backends_that_declare_no_cost() {
        let backends =
            Backends::from_parts(vec![backend_costing("a", None), backend_costing("b", None)]);
        assert_eq!(require_backend_costs(&backends, PricingChoice::Static), Ok(()));
    }

    #[test]
    fn static_rejects_a_backend_cost_naming_it() {
        // A cost with a non-cost-plus rate would sit unread — the OrphanedParams surprise arriving
        // through the backends file rather than the environment. Named so the operator finds it.
        let backends =
            Backends::from_parts(vec![backend_costing("plain", None), backend_costing("priced", Some(1000))]);
        let err = require_backend_costs(&backends, PricingChoice::Static).unwrap_err();
        assert!(
            matches!(&err, PricingConfigError::InertBackendCost { ids } if ids == "priced"),
            "got {err:?}",
        );
    }

    // The boot instant these promo tests place windows relative to. Fixed, so every refusal —
    // including the already-closed-window one — is deterministic.
    const NOW: u64 = 1_000;

    #[test]
    fn no_promo_vars_is_no_promotion() {
        assert_eq!(select_promo(env(&[]), NOW), Ok(None));
    }

    #[test]
    fn all_three_promo_vars_parse_to_a_config() {
        // A window entirely in the future (a scheduled promo): valid, boots.
        let got = select_promo(
            env(&[
                ("OBOLUS_PROMO_DISCOUNT_BPS", "2500"),
                ("OBOLUS_PROMO_START", "2000"),
                ("OBOLUS_PROMO_END", "3000"),
            ]),
            NOW,
        );
        assert_eq!(got, Ok(Some(PromoConfig { discount_bps: 2500, start: 2000, end: 3000 })));
    }

    #[test]
    fn a_currently_open_window_is_accepted() {
        // now (1000) sits inside [500, 1500): a promo live at boot.
        let got = select_promo(
            env(&[
                ("OBOLUS_PROMO_DISCOUNT_BPS", "2500"),
                ("OBOLUS_PROMO_START", "500"),
                ("OBOLUS_PROMO_END", "1500"),
            ]),
            NOW,
        );
        assert_eq!(got, Ok(Some(PromoConfig { discount_bps: 2500, start: 500, end: 1500 })));
    }

    #[test]
    fn a_partial_promo_config_is_refused_naming_what_is_missing() {
        // Only the discount, no window — cannot describe a promotion, must not be silently dropped.
        let err =
            select_promo(env(&[("OBOLUS_PROMO_DISCOUNT_BPS", "2500")]), NOW).unwrap_err();
        assert!(
            matches!(&err, PromoConfigError::Incomplete { present, missing }
                if present == "OBOLUS_PROMO_DISCOUNT_BPS"
                    && missing == "OBOLUS_PROMO_START, OBOLUS_PROMO_END"),
            "got {err:?}",
        );
    }

    #[test]
    fn a_bad_discount_is_refused() {
        for bad in ["2.5", "-1", "25%", "", "lots"] {
            let err = select_promo(
                env(&[
                    ("OBOLUS_PROMO_DISCOUNT_BPS", bad),
                    ("OBOLUS_PROMO_START", "2000"),
                    ("OBOLUS_PROMO_END", "3000"),
                ]),
                NOW,
            )
            .unwrap_err();
            assert!(
                matches!(&err, PromoConfigError::BadDiscount { value } if value == bad),
                "got {err:?} for {bad:?}",
            );
        }
    }

    #[test]
    fn a_zero_discount_is_refused() {
        // A promo that discounts nothing is the base rate — inert config, refused like a zero cost.
        let err = select_promo(
            env(&[
                ("OBOLUS_PROMO_DISCOUNT_BPS", "0"),
                ("OBOLUS_PROMO_START", "2000"),
                ("OBOLUS_PROMO_END", "3000"),
            ]),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, PromoConfigError::ZeroDiscount);
    }

    #[test]
    fn a_hundred_percent_or_more_discount_is_refused() {
        // 10000 bps = 100% off = free, a separate rate; anything larger too.
        for bad in ["10000", "10001", "50000"] {
            let n: u32 = bad.parse().unwrap();
            let err = select_promo(
                env(&[
                    ("OBOLUS_PROMO_DISCOUNT_BPS", bad),
                    ("OBOLUS_PROMO_START", "2000"),
                    ("OBOLUS_PROMO_END", "3000"),
                ]),
                NOW,
            )
            .unwrap_err();
            assert!(
                matches!(err, PromoConfigError::DiscountTooLarge { value } if value == n),
                "got {err:?} for {bad}",
            );
        }
    }

    #[test]
    fn a_bad_window_bound_is_refused_naming_the_variable() {
        let start_err = select_promo(
            env(&[
                ("OBOLUS_PROMO_DISCOUNT_BPS", "2500"),
                ("OBOLUS_PROMO_START", "not-a-time"),
                ("OBOLUS_PROMO_END", "3000"),
            ]),
            NOW,
        )
        .unwrap_err();
        assert!(
            matches!(&start_err, PromoConfigError::BadTimestamp { var, value }
                if *var == PROMO_START_VAR && value == "not-a-time"),
            "got {start_err:?}",
        );
        let end_err = select_promo(
            env(&[
                ("OBOLUS_PROMO_DISCOUNT_BPS", "2500"),
                ("OBOLUS_PROMO_START", "2000"),
                ("OBOLUS_PROMO_END", "nope"),
            ]),
            NOW,
        )
        .unwrap_err();
        assert!(
            matches!(&end_err, PromoConfigError::BadTimestamp { var, value }
                if *var == PROMO_END_VAR && value == "nope"),
            "got {end_err:?}",
        );
    }

    #[test]
    fn an_empty_or_inverted_window_is_refused() {
        // start == end (empty) and start > end (inverted) both fail: a window that never opens.
        for (start, end) in [("3000", "3000"), ("3000", "2000")] {
            let err = select_promo(
                env(&[
                    ("OBOLUS_PROMO_DISCOUNT_BPS", "2500"),
                    ("OBOLUS_PROMO_START", start),
                    ("OBOLUS_PROMO_END", end),
                ]),
                NOW,
            )
            .unwrap_err();
            assert!(
                matches!(err, PromoConfigError::EmptyWindow { .. }),
                "got {err:?} for [{start}, {end})",
            );
        }
    }

    #[test]
    fn a_window_that_closed_before_boot_is_refused() {
        // end at or before now (1000): the discount could never apply, yet the banner would
        // advertise it. Both the exact boundary (end == now) and a past end refuse.
        for end in ["1000", "500"] {
            let err = select_promo(
                env(&[
                    ("OBOLUS_PROMO_DISCOUNT_BPS", "2500"),
                    ("OBOLUS_PROMO_START", "100"),
                    ("OBOLUS_PROMO_END", end),
                ]),
                NOW,
            )
            .unwrap_err();
            assert!(
                matches!(err, PromoConfigError::AlreadyEnded { .. }),
                "got {err:?} for end {end}",
            );
        }
    }
}
