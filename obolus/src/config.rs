//! Turning a multi-chain gateway configuration into the payment options a gateway advertises.
//!
//! A [`crate::gateway::Gateway`] can advertise several ways to pay at once — one per
//! `(scheme, network)`, e.g. Base and Solana (OBOL-003). This module parses the operator-facing
//! `OBOLUS_ACCEPTS` form — a JSON array of per-chain entries — into [`PaymentRequirements`],
//! folding in the gateway-wide fields and validating each amount.
//!
//! What it deliberately does **not** do is check `(scheme, network)` uniqueness. That invariant
//! belongs to [`Gateway::new`](crate::gateway::Gateway::new), the type that later hands one of these
//! requirements to `settle`: enforcing it there makes a wrong-asset settlement impossible by
//! construction, not merely improbable if a config path remembers to de-duplicate.

use serde::Deserialize;

use crate::x402::{validate_atomic_amount, PaymentRequirements, SCHEME_EXACT};

/// One per-chain entry in `OBOLUS_ACCEPTS`: only the fields a chain actually changes. The
/// gateway-wide fields (scheme, resource, description, mime type, timeout) are shared across every
/// option and come from [`SharedOffer`], so an entry names just network / asset / pay-to / price.
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

    /// An entry's `network` is empty. `network` is the match key, so an empty one yields a gateway
    /// that can never match a real payment — an un-payable route that starts cleanly and 402s every
    /// request forever, the same failure [`Empty`](ConfigError::Empty) guards against arriving
    /// through a different door.
    #[error("OBOLUS_ACCEPTS entry has an empty network; network is the match key and must be set")]
    EmptyNetwork,

    /// An entry's `asset` or `pay_to` is empty. A *missing* one is already rejected (both are
    /// required, no serde default), so this is the present-but-`""` case: it would advertise an
    /// option that "sends money nowhere" — the exact failure `deny_unknown_fields` prevents for a
    /// dropped field, caught here at startup rather than left for the facilitator to reject at settle
    /// time. Names the entry's network so an operator can find it.
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
/// A closed set on purpose, so that every consumer of [`EntryDefect`] is made by the compiler to say
/// something true about each member. A `&'static str` here is the same shape with exhaustiveness
/// silently switched off, and it is where the two consumers drift: `main`'s `single_chain_defect`
/// would discriminate on the string *value* with a `{ .. }` catch-all naming `OBOLUS_PAY_TO`, so a
/// third empty-able field added to [`validated_option`] — `OBOLUS_RESOURCE` is operator-settable and
/// unvalidated today, and OBOL-005 will be editing that function — compiles clean and tells an
/// operator to go and clear a variable that was fine.
///
/// That is the dead end this whole layer exists to close (a refusal whose named cause is visibly
/// false leaves `OBOLUS_ALLOW_MAINNET` as the only actionable-looking thing in the message), only
/// worse: confidently wrong about a specific variable rather than merely generic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryField {
    /// The token a client pays in.
    Asset,
    /// The address that receives payment.
    PayTo,
}

impl std::fmt::Display for EntryField {
    /// The `OBOLUS_ACCEPTS` JSON key — which is what both error texts printed when this was a
    /// string literal, so the rendered messages are byte-identical across the change and the
    /// `config` tests that pin them keep their meaning.
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
/// naming. With the checks in [`parse_accepts`] alone, `OBOLUS_PAY_TO=` advertised a challenge that
/// sends money nowhere while the identical `OBOLUS_ACCEPTS` entry was rejected, and an empty
/// `OBOLUS_NETWORK` reached the arming guard to be diagnosed as an x402 short name.
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
/// door, before it can become something a client pays against. Two consequences worth stating:
///
/// - A validation added here covers both paths by construction. One added at a call site does not,
///   and the divergence is silent.
/// - [OBOL-005]'s CAIP-2 canonicalisation belongs **here**, not in [`parse_accepts`], which is one of
///   two sites — landing it there would canonicalise the multi-chain path and leave the default
///   single-chain one raw.
///
/// Trimming is deliberately *not* done: what the guard checks must be byte-identical to what is
/// advertised, and silently trimming here would make `" eip155:84532 "` boot while the near-miss
/// diagnosis that exists to explain it never fires. Emptiness is judged on the trimmed value
/// because a whitespace-only id is not a value; canonicalising a real one is OBOL-005's decision to
/// make, in one place, on purpose.
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
    // asset and pay_to name where money comes from and goes to; a present-but-empty one advertises
    // an option that sends money nowhere. Fail closed at startup, uniformly with network, rather
    // than advertise it and rely on the facilitator to reject at settle time.
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

/// Which of the [`SINGLE_CHAIN_VARS`] are present, given a presence probe. `main` passes
/// `|k| std::env::var(k).is_ok()`; taking the probe as an argument keeps this pure and testable
/// without mutating process-global environment state (which would race other tests). A non-empty
/// result means `OBOLUS_ACCEPTS` and the single-chain vars were both set — the caller should refuse
/// to start rather than silently ignore the latter.
pub fn superseded_single_chain_vars<F: Fn(&str) -> bool>(is_set: F) -> Vec<&'static str> {
    SINGLE_CHAIN_VARS.into_iter().filter(|&k| is_set(k)).collect()
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
}
