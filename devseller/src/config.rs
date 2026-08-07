//! What this development seller should do about a payment — two knobs, not one.
//!
//! # Why two
//!
//! Verification and settlement fail independently in the real world, and the interesting cases for
//! a client author live in the gap between them: a payment that verifies and *then* fails to settle
//! is what decides whether the client retries, whether it re-signs, and whether it double-pays when
//! it does — and the client reaching that case has already spent a nonce, as far as it knows.
//! A single `Outcome` enum cannot express it — the moment `Reject` and `FailAfterSettlement` are
//! variants of the same type, choosing one forecloses the other, and "verified, then settlement
//! timed out" becomes unreachable.
//!
//! So [`VerifyMode`] and [`SettleMode`] are separate fields, set by separate variables, and every
//! combination of the two is legal.

use std::fmt;

/// What `verify` should do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyMode {
    /// Really check the signature offline, and the terms against what was advertised. The default,
    /// and the reason this binary exists rather than a fake: a counterparty that says yes to
    /// anything cannot tell a client its signing is correct.
    Verify,
    /// Accept without inspecting anything — for exercising the happy path of a client that is not
    /// yet signing correctly, or at all.
    Accept,
    /// Reject every payment with this reason, whatever it says.
    Reject(String),
}

/// What `settle` should do once `verify` has passed.
///
/// The gateway serves the upstream response on `success: true` and nothing else, so these variants
/// split two ways and the split is the point. [`Succeed`] and [`EmptyReceipt`] hand the client its
/// answer plus an `X-PAYMENT-RESPONSE` receipt, and ask whether it reads any of that receipt beyond
/// the one field. The rest withhold the work and answer 402 or 502, which is the harder case: the
/// client has signed an authorization and sent it, a nonce is spent as far as it knows, and it now
/// has to decide whether to retry, whether to re-sign, and which of those two statuses means it may.
///
/// [`Succeed`]: SettleMode::Succeed
/// [`EmptyReceipt`]: SettleMode::EmptyReceipt
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleMode {
    /// A no-op success carrying a synthetic transaction id. The default.
    Succeed,
    /// `Ok`, carrying `success: false`. A receipt reporting its own failure is a refusal, so the
    /// client gets a 402 reading `settlement did not complete` — a reason the gateway supplies
    /// rather than one this binary chooses, which is all that separates it from [`Rejected`] on the
    /// wire. Worth having anyway: a real facilitator can refuse either way, and a client that
    /// handles only the error shape will meet this one.
    ///
    /// [`Rejected`]: SettleMode::Rejected
    Unsuccessful,
    /// Settlement was unreachable: our problem, not the payer's, and a 502 to the client.
    Unavailable(String),
    /// Settlement was refused: the payer's problem, and distinct from unreachable because the
    /// client's next move differs — this is a 402 carrying the reason, not a 502.
    Rejected(String),
    /// `Ok`, `success: true`, and every identifying field empty — a receipt that says a payment
    /// happened while naming no transaction to check it against. The work *is* served, so this is
    /// the variant that asks whether the client checks any more of the receipt than `success`.
    EmptyReceipt,
    /// Block for this long before answering, so a client's own settlement deadline fires first.
    Timeout(u64),
}

/// The full development-seller configuration, assembled from the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevConfig {
    pub verify: VerifyMode,
    pub settle: SettleMode,
}

/// A configuration value that cannot mean what it says. Rendered by `main` as a startup refusal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{variable}: {detail}")]
pub struct ConfigError {
    pub variable: &'static str,
    pub detail: String,
}

impl ConfigError {
    fn new(variable: &'static str, detail: impl fmt::Display) -> Self {
        Self { variable, detail: detail.to_string() }
    }
}

pub const VERIFY_VAR: &str = "OBOLUS_DEV_VERIFY";
pub const REJECT_REASON_VAR: &str = "OBOLUS_DEV_REJECT_REASON";
pub const SETTLE_VAR: &str = "OBOLUS_DEV_SETTLE";
pub const SETTLE_REASON_VAR: &str = "OBOLUS_DEV_SETTLE_REASON";
pub const SETTLE_DELAY_VAR: &str = "OBOLUS_DEV_SETTLE_DELAY_SECS";
pub const TOKEN_NAME_VAR: &str = "OBOLUS_DEV_TOKEN_NAME";
pub const TOKEN_VERSION_VAR: &str = "OBOLUS_DEV_TOKEN_VERSION";

const VERIFY_CHOICES: &str = "verify (default), accept, reject";
const SETTLE_CHOICES: &str =
    "succeed (default), unsuccessful, unavailable, rejected, empty-receipt, timeout";

/// Build the configuration from a lookup function.
///
/// `lookup` is passed in rather than reading the process environment directly so this stays pure
/// and testable — the same reason `check_arming` takes `armed` as an argument rather than reading
/// `OBOLUS_ALLOW_MAINNET` itself.
pub fn from_env(
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<DevConfig, ConfigError> {
    Ok(DevConfig { verify: verify_mode(&lookup)?, settle: settle_mode(&lookup)? })
}

fn verify_mode(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<VerifyMode, ConfigError> {
    // Set-but-empty is a refusal rather than a fallback to the default, matching every other
    // variable this repository reads: an empty value means something arrived carrying nothing (an
    // unexpanded `${VAR}`, an `EnvironmentFile` line ending in `=`), and silently taking the
    // default hides the fact that the operator's chosen mode never reached the process.
    let raw = match lookup(VERIFY_VAR) {
        None => return Ok(VerifyMode::Verify),
        Some(raw) if raw.trim().is_empty() => {
            return Err(ConfigError::new(
                VERIFY_VAR,
                format!(
                    "set but empty. Unset it to take the default, or name one of: {VERIFY_CHOICES}"
                ),
            ))
        }
        Some(raw) => raw,
    };

    match raw.trim() {
        "verify" => Ok(VerifyMode::Verify),
        "accept" => Ok(VerifyMode::Accept),
        "reject" => Ok(VerifyMode::Reject(
            lookup(REJECT_REASON_VAR)
                .filter(|reason| !reason.trim().is_empty())
                .unwrap_or_else(|| "rejected by the development seller".to_string()),
        )),
        other => Err(ConfigError::new(
            VERIFY_VAR,
            format!("{other:?} is not a verification mode. Choose one of: {VERIFY_CHOICES}"),
        )),
    }
}

fn settle_mode(
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<SettleMode, ConfigError> {
    let reason = |default: &str| {
        lookup(SETTLE_REASON_VAR)
            .filter(|r| !r.trim().is_empty())
            .unwrap_or_else(|| default.to_string())
    };

    let raw = match lookup(SETTLE_VAR) {
        None => return Ok(SettleMode::Succeed),
        Some(raw) if raw.trim().is_empty() => {
            return Err(ConfigError::new(
                SETTLE_VAR,
                format!(
                    "set but empty. Unset it to take the default, or name one of: {SETTLE_CHOICES}"
                ),
            ))
        }
        Some(raw) => raw,
    };

    match raw.trim() {
        "succeed" => Ok(SettleMode::Succeed),
        "unsuccessful" => Ok(SettleMode::Unsuccessful),
        "unavailable" => Ok(SettleMode::Unavailable(reason("settlement is unreachable"))),
        "rejected" => Ok(SettleMode::Rejected(reason("settlement was refused"))),
        "empty-receipt" => Ok(SettleMode::EmptyReceipt),
        "timeout" => {
            let secs = match lookup(SETTLE_DELAY_VAR) {
                None => 120,
                Some(raw) => raw.trim().parse::<u64>().map_err(|e| {
                    ConfigError::new(
                        SETTLE_DELAY_VAR,
                        format!("must be a whole number of seconds: {e}"),
                    )
                })?,
            };
            if secs == 0 {
                return Err(ConfigError::new(
                    SETTLE_DELAY_VAR,
                    "must be greater than 0: a 0-second delay returns immediately, which is \
                     `succeed` with a misleading name rather than a timeout.",
                ));
            }
            Ok(SettleMode::Timeout(secs))
        }
        other => Err(ConfigError::new(
            SETTLE_VAR,
            format!("{other:?} is not a settlement outcome. Choose one of: {SETTLE_CHOICES}"),
        )),
    }
}

/// One line naming both knobs, for the startup banner.
impl fmt::Display for DevConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verify = match &self.verify {
            VerifyMode::Verify => "verify (signature and terms checked offline)".to_string(),
            VerifyMode::Accept => "accept (payments are NOT inspected)".to_string(),
            VerifyMode::Reject(reason) => format!("reject ({reason})"),
        };
        let settle = match &self.settle {
            SettleMode::Succeed => "succeed".to_string(),
            SettleMode::Unsuccessful => "unsuccessful (receipt says success: false)".to_string(),
            SettleMode::Unavailable(reason) => format!("unavailable ({reason})"),
            SettleMode::Rejected(reason) => format!("rejected ({reason})"),
            SettleMode::EmptyReceipt => "empty-receipt (success: true, nothing identified)".to_string(),
            SettleMode::Timeout(secs) => format!("timeout (blocks {secs}s)"),
        };
        write!(f, "verify={verify} settle={settle}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |key: &str| map.get(key).cloned()
    }

    #[test]
    fn the_default_is_real_verification_and_plain_success() {
        // The default must be the strict one. A development seller that accepts anything unless
        // told otherwise is a fake with extra steps, and a client author who never sets a variable
        // would get exactly the counterparty this binary exists to replace.
        let config = from_env(env(&[])).expect("an empty environment is a valid configuration");

        assert_eq!(config.verify, VerifyMode::Verify);
        assert_eq!(config.settle, SettleMode::Succeed);
    }

    /// The property the two-knob split exists for: verification passing and settlement failing is
    /// reachable, which is impossible if the two share one enum.
    #[test]
    fn verification_and_settlement_outcomes_are_independent() {
        let config = from_env(env(&[(VERIFY_VAR, "verify"), (SETTLE_VAR, "unavailable")]))
            .expect("verify + failing settlement is a legal combination");

        assert_eq!(config.verify, VerifyMode::Verify);
        assert!(matches!(config.settle, SettleMode::Unavailable(_)));

        // ...and in the other direction too, so this is not satisfied by one lucky pairing.
        let config = from_env(env(&[(VERIFY_VAR, "accept"), (SETTLE_VAR, "unsuccessful")]))
            .expect("accept + unsuccessful settlement is a legal combination");
        assert_eq!(config.verify, VerifyMode::Accept);
        assert_eq!(config.settle, SettleMode::Unsuccessful);
    }

    #[test]
    fn every_settlement_outcome_is_selectable_by_name() {
        // A table rather than one representative: a parser that fell through to the default on an
        // unrecognised name would pass a single-variant test and silently ignore five of six.
        for (name, expected) in [
            ("succeed", SettleMode::Succeed),
            ("unsuccessful", SettleMode::Unsuccessful),
            ("empty-receipt", SettleMode::EmptyReceipt),
        ] {
            let config = from_env(env(&[(SETTLE_VAR, name)])).expect("a named outcome parses");
            assert_eq!(config.settle, expected, "{name} did not select its own outcome");
        }
        assert!(matches!(
            from_env(env(&[(SETTLE_VAR, "unavailable")])).unwrap().settle,
            SettleMode::Unavailable(_)
        ));
        assert!(matches!(
            from_env(env(&[(SETTLE_VAR, "rejected")])).unwrap().settle,
            SettleMode::Rejected(_)
        ));
        assert_eq!(
            from_env(env(&[(SETTLE_VAR, "timeout")])).unwrap().settle,
            SettleMode::Timeout(120)
        );
    }

    #[test]
    fn an_unknown_mode_is_refused_and_the_choices_are_named() {
        // Falling through to the default would be the dangerous direction: an operator who typed
        // `OBOLUS_DEV_VERIFY=strict` would get `Verify` and never learn their value was ignored —
        // and one who typed `OBOLUS_DEV_SETTLE=fail` would get `succeed`, which is the outcome they
        // were specifically trying to avoid.
        let error = from_env(env(&[(SETTLE_VAR, "fail")])).expect_err("`fail` is not an outcome");
        assert_eq!(error.variable, SETTLE_VAR);
        assert!(error.detail.contains("unavailable"), "the message must name the choices: {error}");

        let error = from_env(env(&[(VERIFY_VAR, "strict")])).expect_err("`strict` is not a mode");
        assert_eq!(error.variable, VERIFY_VAR);
        assert!(error.detail.contains("accept"), "the message must name the choices: {error}");
    }

    #[test]
    fn a_set_but_empty_mode_is_refused_rather_than_defaulted() {
        for variable in [VERIFY_VAR, SETTLE_VAR] {
            let error =
                from_env(env(&[(variable, "")])).expect_err("set-but-empty is a configuration error");
            assert_eq!(error.variable, variable);
            assert!(error.detail.contains("set but empty"), "got: {error}");
        }
    }

    #[test]
    fn a_zero_timeout_is_refused_because_it_is_not_a_timeout() {
        let error = from_env(env(&[(SETTLE_VAR, "timeout"), (SETTLE_DELAY_VAR, "0")]))
            .expect_err("a 0-second timeout returns immediately");
        assert_eq!(error.variable, SETTLE_DELAY_VAR);
    }

    #[test]
    fn a_junk_timeout_is_refused_rather_than_silently_defaulted() {
        let error = from_env(env(&[(SETTLE_VAR, "timeout"), (SETTLE_DELAY_VAR, "soon")]))
            .expect_err("`soon` is not a number of seconds");
        assert_eq!(error.variable, SETTLE_DELAY_VAR);
    }

    #[test]
    fn reject_and_settlement_reasons_are_configurable_and_default_to_something_legible() {
        let config = from_env(env(&[(VERIFY_VAR, "reject"), (REJECT_REASON_VAR, "insufficient funds")]))
            .expect("a configured reason parses");
        assert_eq!(config.verify, VerifyMode::Reject("insufficient funds".to_string()));

        // Unset, and set-but-empty, both fall back — a reason is cosmetic, so an empty one is not
        // worth refusing to start over, unlike a mode that changes behaviour.
        for pairs in [vec![(VERIFY_VAR, "reject")], vec![(VERIFY_VAR, "reject"), (REJECT_REASON_VAR, "")]] {
            let config = from_env(env(&pairs)).expect("reject with no reason parses");
            assert_eq!(
                config.verify,
                VerifyMode::Reject("rejected by the development seller".to_string())
            );
        }
    }

    #[test]
    fn the_banner_line_names_both_knobs() {
        // The operator's only view of what this instance will do. A line that named one knob would
        // leave the other's setting invisible, which is how someone spends an afternoon debugging a
        // client against a seller that was rejecting everything on purpose.
        let line = from_env(env(&[(VERIFY_VAR, "accept"), (SETTLE_VAR, "unsuccessful")]))
            .unwrap()
            .to_string();

        assert!(line.contains("accept"), "got: {line}");
        assert!(line.contains("unsuccessful"), "got: {line}");
    }
}
