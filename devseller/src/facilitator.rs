//! A facilitator that judges payments in-process, so a client can be tested against a
//! counterparty that fails on command.
//!
//! # How this differs from `FakeFacilitator`
//!
//! The library's fake is `#[cfg(test)]`-only and does not inspect the payment at all — it drives
//! the gateway's control flow and nothing else. Its own documentation says why it can never be
//! more than that: we author both sides, so "my fake accepted my payment" is worth nothing as
//! evidence.
//!
//! That argument still holds here, and it is why [`VerifyMode::Verify`] is not built out of our
//! own beliefs about EIP-712. The verification path is pinned to the specification's own published
//! signature — see `verify`'s known-answer tests — so what this facilitator enforces is a
//! third-party vector's idea of correct, not ours. A client that satisfies it has satisfied
//! something we did not get to define.
//!
//! What it still is not: a settlement oracle. Nothing here touches a chain, so `settle` moves no
//! money whatever it returns. That is the reason startup refuses any network it cannot prove is
//! testnet — a gateway advertising a real chain while settling nothing is a gateway that serves
//! inference for free to anyone who can reach it.

use std::time::Duration;

use obolus::facilitator::{Facilitator, FacilitatorError};
use obolus::x402::{PaymentPayload, PaymentRequirements, SettlementReceipt};

use crate::config::{SettleMode, VerifyMode};
use crate::verify::{
    check_terms, check_window, domain_for, parse_exact_payload, TokenDomain, VerifyError,
};

/// The synthetic transaction id a successful settlement reports.
///
/// Obviously not a real hash: a plausible-looking one in a development seller's receipt is the
/// kind of value that ends up pasted into a block explorer, or worse, into a bug report as
/// evidence a payment settled.
const SYNTHETIC_TRANSACTION: &str = "0xDEV-SELLER-NOTHING-SETTLED-NOT-A-REAL-TRANSACTION";

/// The payer a receipt names when nothing was verified — [`VerifyMode::Accept`] never learns who
/// the payer is, and inventing an address would put a fabricated identity in a receipt.
const UNKNOWN_PAYER: &str = "0xDEV-SELLER-PAYER-NOT-VERIFIED";

pub struct DevFacilitator {
    verify: VerifyMode,
    settle: SettleMode,
    token: TokenDomain,
    /// Injected so the window check is testable without waiting for wall-clock time to pass.
    now: fn() -> u64,
}

impl DevFacilitator {
    pub fn new(verify: VerifyMode, settle: SettleMode, token: TokenDomain) -> Self {
        Self { verify, settle, token, now: unix_now }
    }

    #[cfg(test)]
    fn with_clock(mut self, now: fn() -> u64) -> Self {
        self.now = now;
        self
    }

    /// The offline verification path, factored out of the trait method so it is reachable from
    /// tests without an async runtime.
    fn judge(
        &self,
        payment: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<(), VerifyError> {
        let payload = parse_exact_payload(&payment.payload)?;
        // Terms before signature, deliberately. Both are rejections either way, but a client
        // paying the wrong price gets told the price rather than "your signature does not
        // recover" — which is what a domain mismatch also says, and the two are not confusable
        // when only one of them can be true at a time.
        check_terms(payment, &payload, requirements)?;
        check_window(&payload.authorization, (self.now)())?;
        crate::verify::verify_signature(&payload, &domain_for(requirements, &self.token)?)
    }

    fn receipt(&self, network: &str, payer: String, success: bool) -> SettlementReceipt {
        SettlementReceipt {
            success,
            transaction: Some(SYNTHETIC_TRANSACTION.to_string()),
            network: network.to_string(),
            payer: Some(payer),
        }
    }

    /// Who this payment says it is from, for the receipt.
    ///
    /// Only under [`VerifyMode::Verify`] is there a payer worth naming. The `from` field is a claim
    /// the caller writes, and only a recovered signature ties it to anyone; under
    /// [`VerifyMode::Accept`] nothing checked it, so copying it into a receipt that reports
    /// `success: true` would launder an unverified string into something that reads as established.
    /// The parse would succeed there — the payload is well-formed, it is merely unexamined — so
    /// this has to be refused by mode rather than by whether the bytes decode.
    fn payer_of(&self, payment: &PaymentPayload) -> String {
        if self.verify != VerifyMode::Verify {
            return UNKNOWN_PAYER.to_string();
        }
        parse_exact_payload(&payment.payload)
            .map(|payload| crate::verify::render_address(&payload.authorization.from))
            .unwrap_or_else(|_| UNKNOWN_PAYER.to_string())
    }
}

impl Facilitator for DevFacilitator {
    async fn verify(
        &self,
        payment: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<(), FacilitatorError> {
        match &self.verify {
            VerifyMode::Accept => Ok(()),
            VerifyMode::Reject(reason) => Err(FacilitatorError::Rejected(reason.clone())),
            // Every verification failure is `Rejected`, never `Unavailable`: nothing in this path
            // depends on a service that could be down, so a failure here is always something about
            // the payment. Reporting one as `Unavailable` would tell the client to retry an
            // unchanged payment that will be refused identically forever.
            VerifyMode::Verify => {
                self.judge(payment, requirements).map_err(|e| FacilitatorError::Rejected(e.to_string()))
            }
        }
    }

    async fn settle(
        &self,
        payment: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<SettlementReceipt, FacilitatorError> {
        match &self.settle {
            SettleMode::Succeed => {
                Ok(self.receipt(&requirements.network, self.payer_of(payment), true))
            }
            SettleMode::Unsuccessful => {
                Ok(self.receipt(&requirements.network, self.payer_of(payment), false))
            }
            // `None`, not an empty string: both optional fields are `skip_serializing_if`, so they
            // are absent from the encoded receipt entirely rather than present and blank. A client
            // that reads `transaction` without checking finds a missing key — a settlement
            // reported as successful that the payer has no way to look up.
            SettleMode::EmptyReceipt => Ok(SettlementReceipt {
                success: true,
                transaction: None,
                network: String::new(),
                payer: None,
            }),
            SettleMode::Unavailable(reason) => Err(FacilitatorError::Unavailable(reason.clone())),
            SettleMode::Rejected(reason) => Err(FacilitatorError::Rejected(reason.clone())),
            SettleMode::Timeout(secs) => {
                // Block rather than return an error: the case a client author needs to exercise is
                // their *own* deadline firing, which never happens if the seller answers promptly
                // with a failure.
                tokio::time::sleep(Duration::from_secs(*secs)).await;
                Err(FacilitatorError::Unavailable(format!(
                    "settlement timed out after {secs}s (development seller, deliberately)"
                )))
            }
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The published vector's own values — the same file `verify`'s KAT reads, so a payment built
    /// here is one the specification says is correctly signed.
    const KAT: &str = include_str!("../../eip3009/fixtures/x402-authorization.json");

    /// Inside the published authorization's validity window, so the clock check passes and the
    /// signature check is what these tests are actually measuring.
    const WITHIN_WINDOW: u64 = 1_740_672_100;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(KAT).expect("the fixture is valid JSON")
    }

    fn payment() -> PaymentPayload {
        let doc = fixture();
        let a = &doc["authorization"];
        PaymentPayload {
            x402_version: 1,
            scheme: "exact".to_string(),
            network: "eip155:84532".to_string(),
            payload: json!({
                "signature": doc["signature"],
                "authorization": {
                    "from": a["from"],
                    "to": a["to"],
                    "value": a["value"],
                    "validAfter": a["valid_after"],
                    "validBefore": a["valid_before"],
                    "nonce": a["nonce"],
                }
            }),
        }
    }

    /// Requirements that the published payment actually satisfies: the fixture's own payee, its
    /// amount, and the token contract it was signed against.
    fn requirements() -> PaymentRequirements {
        let doc = fixture();
        PaymentRequirements {
            scheme: "exact".to_string(),
            network: "eip155:84532".to_string(),
            max_amount_required: "10000".to_string(),
            resource: "http://127.0.0.1:8404/v1/chat/completions".to_string(),
            description: "One inference request".to_string(),
            mime_type: "application/json".to_string(),
            pay_to: doc["authorization"]["to"].as_str().unwrap().to_string(),
            max_timeout_seconds: 60,
            asset: doc["domain"]["verifying_contract"].as_str().unwrap().to_string(),
            extra: None,
        }
    }

    fn verifying() -> DevFacilitator {
        DevFacilitator::new(VerifyMode::Verify, SettleMode::Succeed, TokenDomain::default())
            .with_clock(|| WITHIN_WINDOW)
    }

    #[test]
    fn the_published_payment_is_accepted_under_real_verification() {
        // The in-distribution case, and on its own it proves little — which is what every test
        // below is for. It is here so the negatives cannot pass by rejecting everything.
        verifying().judge(&payment(), &requirements()).expect("the specification's own payment");
    }

    /// The out-of-distribution half of the definition of done: a payment that differs from the
    /// advertised terms must be rejected under `verify`. Each perturbation is one field, so a
    /// rejection names which check fired rather than proving only that *something* was wrong.
    #[test]
    fn a_payment_that_does_not_match_the_advertisement_is_rejected() {
        let facilitator = verifying();
        let payment = payment();

        // Paying somebody else, with an otherwise perfect signature.
        let mut wrong_payee = requirements();
        wrong_payee.pay_to = "0x00000000000000000000000000000000000000bb".to_string();
        assert!(
            matches!(
                facilitator.judge(&payment, &wrong_payee),
                Err(VerifyError::WrongPayee { .. })
            ),
            "an authorization paying another address must not satisfy this resource"
        );

        // Underpaying: the authorization is for 10000, the resource now asks 10001.
        let mut too_expensive = requirements();
        too_expensive.max_amount_required = "10001".to_string();
        assert!(matches!(
            facilitator.judge(&payment, &too_expensive),
            Err(VerifyError::Underpaid { got: 10000, want: 10001 })
        ));

        // A different network in the advertisement than the payment names.
        let mut other_network = requirements();
        other_network.network = "eip155:11155111".to_string();
        assert!(matches!(
            facilitator.judge(&payment, &other_network),
            Err(VerifyError::NetworkMismatch { .. })
        ));

        // A different token contract: the asset IS the EIP-712 verifyingContract, so this fails
        // as a signature that does not recover rather than as a field comparison.
        let mut other_asset = requirements();
        other_asset.asset = "0x0000000000000000000000000000000000000001".to_string();
        assert!(matches!(
            facilitator.judge(&payment, &other_asset),
            Err(VerifyError::NotRecovered { .. })
        ));
    }

    #[test]
    fn a_malformed_payload_is_rejected_rather_than_panicking() {
        let facilitator = verifying();
        for payload in [
            json!({}),
            json!({"signature": "0xdeadbeef"}),
            json!({"signature": "0xdeadbeef", "authorization": {}}),
            json!({"signature": "not-hex", "authorization": {"from": "0x00"}}),
        ] {
            let payment = PaymentPayload {
                x402_version: 1,
                scheme: "exact".to_string(),
                network: "eip155:84532".to_string(),
                payload,
            };
            assert!(facilitator.judge(&payment, &requirements()).is_err());
        }
    }

    #[test]
    fn an_expired_authorization_is_rejected() {
        // The published vector's window closed in February 2025, so a present-day clock rejects
        // it — which is the correct behaviour and the reason the KAT injects a clock.
        let facilitator = DevFacilitator::new(
            VerifyMode::Verify,
            SettleMode::Succeed,
            TokenDomain::default(),
        )
        .with_clock(|| 1_800_000_000);

        assert!(matches!(
            facilitator.judge(&payment(), &requirements()),
            Err(VerifyError::Expired { .. })
        ));
    }

    #[test]
    fn a_misconfigured_token_domain_rejects_and_says_so() {
        // The failure mode this binary is most likely to hand someone: `name` and `version` are
        // configuration (#13), and a wrong one makes every correct signature fail to recover.
        // The rejection has to be traceable to the domain or the client author debugs their signer
        // for an afternoon.
        let facilitator = DevFacilitator::new(
            VerifyMode::Verify,
            SettleMode::Succeed,
            TokenDomain { name: "USD Coin".to_string(), version: "2".to_string() },
        )
        .with_clock(|| WITHIN_WINDOW);

        let message = facilitator
            .judge(&payment(), &requirements())
            .expect_err("a wrong domain name must reject")
            .to_string();

        assert!(message.contains("USD Coin"), "the rejection must name the domain: {message}");
        assert!(
            message.contains("OBOLUS_DEV_TOKEN_NAME"),
            "the rejection must name the variable to fix: {message}"
        );
    }

    #[tokio::test]
    async fn accept_mode_does_not_inspect_the_payment() {
        // The whole point of the mode: a client that is not signing correctly yet still reaches
        // the upstream. Fed a payload that `verify` mode rejects outright.
        let facilitator =
            DevFacilitator::new(VerifyMode::Accept, SettleMode::Succeed, TokenDomain::default());
        let garbage = PaymentPayload {
            x402_version: 1,
            scheme: "exact".to_string(),
            network: "eip155:84532".to_string(),
            payload: json!({"authorization": "not even an object"}),
        };

        assert!(Facilitator::verify(&facilitator, &garbage, &requirements()).await.is_ok());
    }

    #[tokio::test]
    async fn reject_mode_refuses_a_payment_that_is_actually_valid() {
        // Discriminating: fed the *published* payment, which `verify` mode accepts. A `reject`
        // that only ever saw bad payments would be indistinguishable from working verification.
        let facilitator = DevFacilitator::new(
            VerifyMode::Reject("insufficient funds".to_string()),
            SettleMode::Succeed,
            TokenDomain::default(),
        );

        assert_eq!(
            Facilitator::verify(&facilitator, &payment(), &requirements()).await,
            Err(FacilitatorError::Rejected("insufficient funds".to_string()))
        );
    }

    #[tokio::test]
    async fn settlement_outcomes_are_reachable_after_a_passing_verification() {
        // The pairing the two-knob split exists for. Each of these runs with `VerifyMode::Verify`
        // and the *valid* published payment, so verification genuinely passed and the settlement
        // outcome is the only thing under test.
        let payment = payment();
        let requirements = requirements();

        let succeeding = verifying();
        let receipt = Facilitator::settle(&succeeding, &payment, &requirements)
            .await
            .expect("succeed settles");
        assert!(receipt.success);
        // The payer is read off the *verified* authorization, not invented.
        assert_eq!(receipt.payer.as_deref(), Some("0x857b06519e91e3a54538791bdbb0e22373e36b66"));

        let unsuccessful = DevFacilitator::new(
            VerifyMode::Verify,
            SettleMode::Unsuccessful,
            TokenDomain::default(),
        )
        .with_clock(|| WITHIN_WINDOW);
        assert!(Facilitator::verify(&unsuccessful, &payment, &requirements).await.is_ok());
        let receipt = Facilitator::settle(&unsuccessful, &payment, &requirements)
            .await
            .expect("an unsuccessful receipt is still an Ok");
        assert!(!receipt.success, "the receipt must say the payment did not succeed");

        let unavailable = DevFacilitator::new(
            VerifyMode::Verify,
            SettleMode::Unavailable("chain is down".to_string()),
            TokenDomain::default(),
        )
        .with_clock(|| WITHIN_WINDOW);
        assert!(Facilitator::verify(&unavailable, &payment, &requirements).await.is_ok());
        assert_eq!(
            Facilitator::settle(&unavailable, &payment, &requirements).await,
            Err(FacilitatorError::Unavailable("chain is down".to_string()))
        );

        let empty = DevFacilitator::new(
            VerifyMode::Verify,
            SettleMode::EmptyReceipt,
            TokenDomain::default(),
        )
        .with_clock(|| WITHIN_WINDOW);
        let receipt =
            Facilitator::settle(&empty, &payment, &requirements).await.expect("empty-receipt is Ok");
        // Reported successful with no transaction at all — and because the field is
        // `skip_serializing_if`, absent from the encoded receipt rather than blank.
        assert!(receipt.success);
        assert_eq!(receipt.transaction, None);
        assert_eq!(receipt.payer, None);
    }

    /// Which settle modes hand the client its answer, and which withhold it.
    ///
    /// The split is not local to this file, which is what makes it worth pinning here. The gateway
    /// attaches the receipt and serves the upstream body on `success: true` and on nothing else —
    /// `obolus` holds that half, that an unsuccessful receipt buys nothing and a failed settlement
    /// does not serve the answer. So a mode's side of the split is decided entirely by what `settle`
    /// returns, and this is the half that lives in this crate.
    ///
    /// `Unsuccessful` is why the list is the list: it is the only value here that returns `Ok` and
    /// still withholds the work, so without it "settlement returned `Ok`" and "the client is served"
    /// agree on every remaining case. `EmptyReceipt` does the same job for the receipt's other
    /// fields, being served with no transaction and no payer.
    ///
    /// The match is exhaustive on purpose. A seventh variant cannot be added without an arm here,
    /// and writing that arm is where the decision about which side it belongs on has to be made.
    #[tokio::test]
    async fn only_a_receipt_reporting_success_serves_the_work() {
        let payment = payment();
        let requirements = requirements();

        for mode in [
            SettleMode::Succeed,
            SettleMode::Unsuccessful,
            SettleMode::Unavailable("no route to the chain".to_string()),
            SettleMode::Rejected("nonce already used".to_string()),
            SettleMode::EmptyReceipt,
            // Zero seconds: the delay exists for a client's own deadline to fire against, and
            // waiting out a real one here would buy nothing this assertion can see.
            SettleMode::Timeout(0),
        ] {
            let serves_the_work = match &mode {
                SettleMode::Succeed | SettleMode::EmptyReceipt => true,
                SettleMode::Unsuccessful
                | SettleMode::Unavailable(_)
                | SettleMode::Rejected(_)
                | SettleMode::Timeout(_) => false,
            };

            let facilitator =
                DevFacilitator::new(VerifyMode::Verify, mode.clone(), TokenDomain::default())
                    .with_clock(|| WITHIN_WINDOW);
            let outcome = Facilitator::settle(&facilitator, &payment, &requirements).await;

            assert_eq!(
                matches!(&outcome, Ok(receipt) if receipt.success),
                serves_the_work,
                "{mode:?} is on the wrong side of the split; settle returned {outcome:?}"
            );
        }
    }

    /// Under `accept`, the receipt names no payer.
    ///
    /// `from` is a string the caller writes, and only a recovered signature ties it to anyone.
    /// `accept` recovers nothing, so copying it into a receipt that reports `success: true` hands a
    /// client author an address that reads as established and is not — the precise confusion this
    /// binary exists to spare them.
    ///
    /// Note the shape this has to have: the payload below is the published, **well-formed** one, so
    /// a fallback keyed on whether the bytes parse would still name the caller's claim here. Only
    /// the mode separates the two cases, which is why the check is on the mode.
    #[tokio::test]
    async fn an_accepted_payment_names_no_payer_in_its_receipt() {
        let payment = payment();
        let requirements = requirements();

        let accepting =
            DevFacilitator::new(VerifyMode::Accept, SettleMode::Succeed, TokenDomain::default())
                .with_clock(|| WITHIN_WINDOW);
        let receipt = Facilitator::settle(&accepting, &payment, &requirements)
            .await
            .expect("accept-mode settlement succeeds");
        assert_eq!(
            receipt.payer.as_deref(),
            Some(UNKNOWN_PAYER),
            "an unverified `from` must not be reported as the payer"
        );

        // The discriminating half. Without it this passes on a binary whose receipts never name a
        // payer at all, which is a different bug and not the one under test.
        let receipt = Facilitator::settle(&verifying(), &payment, &requirements)
            .await
            .expect("verified settlement succeeds");
        assert_eq!(receipt.payer.as_deref(), Some("0x857b06519e91e3a54538791bdbb0e22373e36b66"));
    }

    /// The payer placeholder must not look like an address either.
    ///
    /// Every other test asserts `payer == UNKNOWN_PAYER`, which is satisfied by whatever the
    /// constant happens to hold — including a plausible address, the one value a receipt naming an
    /// *unverified* payer must never contain. This pins the shape rather than the name, matching
    /// what the sibling test below does for the transaction id.
    #[test]
    fn the_unverified_payer_placeholder_never_looks_like_an_address() {
        assert!(!UNKNOWN_PAYER.starts_with("0x0"), "a placeholder payer must not read as an address");
        assert!(UNKNOWN_PAYER.contains("NOT-VERIFIED"));
        assert!(
            !UNKNOWN_PAYER[2..].chars().all(|c| c.is_ascii_hexdigit()),
            "a placeholder payer must not be parseable as a real address"
        );
    }

    #[test]
    fn a_successful_receipt_never_carries_a_plausible_transaction_hash() {
        // A development seller settles nothing. A receipt that *looks* like a real settlement is
        // the value that ends up in a block explorer, or in a bug report as evidence money moved.
        assert!(!SYNTHETIC_TRANSACTION.starts_with("0x0"));
        assert!(SYNTHETIC_TRANSACTION.contains("NOT-A-REAL-TRANSACTION"));
        assert!(
            !SYNTHETIC_TRANSACTION[2..].chars().all(|c| c.is_ascii_hexdigit()),
            "a receipt's transaction id must not be parseable as a real hash"
        );
    }
}
