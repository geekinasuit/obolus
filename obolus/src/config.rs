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

/// The pricing rate an operator selected, ready for `main` to build a determiner from. A plain data
/// value, not a determiner: the determiner types live in [`crate::pricing`], and keeping the config
/// door's output free of them lets this parse and its refusals be unit-tested without wiring a
/// gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PricingChoice {
    /// The behaviour-preserving default: [`crate::pricing::StaticPrice`], each option at its own
    /// armed amount.
    Static,
    /// Cost-plus: a gateway-wide declared upstream `cost` marked up by `margin_bps` basis points
    /// ([`crate::pricing::CostPlus`]).
    CostPlus { cost: u128, margin_bps: u32 },
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

    /// `cost-plus` is selected but one of its parameters is absent. Cost-plus infers no money value,
    /// so a missing cost or margin is a refusal, not a default.
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

    /// `cost-plus` is selected alongside the multi-chain `OBOLUS_ACCEPTS`. Cost-plus is gateway-wide
    /// — one declared cost — and a single atomic cost is ambiguous across networks that carry
    /// different assets and decimals, so the combination is deliberately not supported in this
    /// slice. (A per-network or per-backend cost is later work.)
    #[error(
        "OBOLUS_PRICING is \"cost-plus\" and OBOLUS_ACCEPTS is set. Cost-plus is gateway-wide (one \
         declared cost), and a single atomic cost is ambiguous across the several networks \
         OBOLUS_ACCEPTS advertises, which carry different assets and decimals — so multi-chain \
         cost-plus pricing is not supported yet. Unset OBOLUS_ACCEPTS to price a single chain with \
         cost-plus, or unset OBOLUS_PRICING to advertise each entry's own amount."
    )]
    CostPlusMultiChain,

    /// `cost-plus` is selected alongside an explicitly configured `OBOLUS_PRICE`. Under cost-plus
    /// the amount comes from the cost and margin, so `OBOLUS_PRICE` would sit inert — the
    /// silently-ignored-payment-config surprise the `OBOLUS_ACCEPTS` supersession also guards.
    #[error(
        "OBOLUS_PRICING is \"cost-plus\", which sets every amount from OBOLUS_UPSTREAM_COST and \
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
                let cost = match get(UPSTREAM_COST_VAR) {
                    None => {
                        return Err(PricingConfigError::MissingParam {
                            var: UPSTREAM_COST_VAR,
                            detail: "the upstream cost each request is marked up from, in atomic \
                                     units",
                        })
                    }
                    // A direct `u128` parse, which is exactly what `validate_atomic_amount` does —
                    // but the cost is computed *with*, not advertised verbatim, so we keep the value,
                    // not the wire string. Zero is admissible as an atomic amount yet refused here;
                    // see `ZeroCost`.
                    Some(raw) => match raw.parse::<u128>() {
                        Ok(0) => return Err(PricingConfigError::ZeroCost),
                        Ok(cost) => cost,
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
                Ok(PricingChoice::CostPlus { cost, margin_bps })
            }
            _ => Err(PricingConfigError::UnknownRate { value: raw }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn cost_plus_reads_its_cost_and_margin() {
        let choice = select_pricing(env(&[
            ("OBOLUS_PRICING", "cost-plus"),
            ("OBOLUS_UPSTREAM_COST", "1000"),
            ("OBOLUS_MARGIN_BPS", "2500"),
        ]));
        assert_eq!(choice, Ok(PricingChoice::CostPlus { cost: 1000, margin_bps: 2500 }));
    }

    #[test]
    fn cost_plus_allows_a_zero_margin() {
        // Break-even is legitimate — a zero margin is a stated choice, not a missing value.
        let choice = select_pricing(env(&[
            ("OBOLUS_PRICING", "cost-plus"),
            ("OBOLUS_UPSTREAM_COST", "1000"),
            ("OBOLUS_MARGIN_BPS", "0"),
        ]));
        assert_eq!(choice, Ok(PricingChoice::CostPlus { cost: 1000, margin_bps: 0 }));
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
    fn cost_plus_without_a_cost_is_rejected() {
        let err = select_pricing(env(&[
            ("OBOLUS_PRICING", "cost-plus"),
            ("OBOLUS_MARGIN_BPS", "2500"),
        ]))
        .unwrap_err();
        assert!(
            matches!(err, PricingConfigError::MissingParam { var: UPSTREAM_COST_VAR, .. }),
            "got {err:?}",
        );
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
}
