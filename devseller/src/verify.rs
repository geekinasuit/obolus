//! Offline verification of an x402 `exact`/EVM payment — the work a real facilitator does on
//! `/verify`, performed in-process so a client can be tested without one.
//!
//! # Three checks, deliberately separate
//!
//! [`verify_signature`] is pure cryptography: does this signature, over this authorization, under
//! this domain, recover to the party that claims to have authorized it? [`check_terms`] asks
//! whether the payment is for what was advertised. [`check_window`] asks whether it is being
//! presented inside its validity window.
//!
//! They are separate because only the first is testable against a published vector. The x402
//! specification's worked example was signed in February 2025, so any check against a wall clock
//! rejects it — a combined `verify` could not be pointed at the one piece of evidence in this
//! repository that comes from outside our own authorship. Splitting them keeps
//! [`verify_signature`] under the known-answer test in [`kat_tests`] and leaves the policy checks,
//! which are ours, plainly labelled as ours.
//!
//! # Where the EIP-712 domain comes from
//!
//! Verifying an EIP-3009 authorization means recomputing
//! `keccak256(0x19 || 0x01 || domainSeparator || structHash)`, and the separator comes from the
//! token contract's EIP-712 domain: `name`, `version`, `chainId`, `verifyingContract`. Two of the
//! four are already in the payment requirements — `verifyingContract` *is* the advertised asset,
//! and `chainId` is the CAIP-2 network's reference. The other two are properties of the token
//! contract that nothing in an x402 challenge carries, and the specification does not say where to
//! get them (OBOL-019). So they are configuration here, and every rejection renders the domain it
//! used: a misconfigured `name` produces a signature that does not recover, and "bad signature"
//! with no domain printed is precisely the dead end this crate exists to help someone out of.

use eip3009::{decode_hex_array, Authorization, Eip712Domain};
use obolus::x402::{PaymentPayload, PaymentRequirements};
use serde_json::Value;

/// The `name` and `version` halves of the token contract's EIP-712 domain — the two fields no
/// x402 challenge carries and this gateway therefore has to be told.
///
/// Defaults to the Base Sepolia USDC values, which is what the specification's own example was
/// signed under, so a client following the spec's worked example verifies out of the box.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenDomain {
    pub name: String,
    pub version: String,
}

impl Default for TokenDomain {
    fn default() -> Self {
        Self { name: "USDC".to_string(), version: "2".to_string() }
    }
}

/// A decoded `exact`-scheme EVM payload: the authorization and the signature over it.
#[derive(Debug, Clone, PartialEq)]
pub struct ExactPayload {
    pub authorization: Authorization,
    pub signature: Vec<u8>,
}

// Not `Clone`: two variants carry an `eip3009::Eip3009Error`, which isn't. Nothing needs to clone a
// refusal — it is produced once and rendered once.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum VerifyError {
    #[error("payload.{field} is missing")]
    Missing { field: &'static str },

    /// A uint256 arrived as a JSON number rather than a decimal string.
    ///
    /// Its own variant rather than a generic type error because the remedy is not obvious from
    /// "expected a string": JSON numbers are IEEE-754 doubles in most parsers, so a `uint256`
    /// above 2^53 silently loses precision on the way in. x402 carries these as strings for that
    /// reason, and a client that sends numbers will be rejected by a real facilitator too.
    #[error(
        "payload.{field} is a JSON number; x402 carries uint256 values as decimal strings \
         because a number large enough to matter does not survive a JSON parser intact"
    )]
    NumericUint { field: &'static str },

    #[error("payload.{field} is not a decimal uint256: {value:?}")]
    BadUint { field: &'static str, value: String },

    #[error("payload.{field} is not valid hex of the expected length: {source}")]
    BadHex { field: &'static str, source: eip3009::Eip3009Error },

    /// The advertised asset could not be read as a 20-byte contract address, so no EIP-712 domain
    /// can be built and nothing can be verified against it.
    #[error(
        "cannot verify against advertised asset {asset:?}: it is not a 20-byte contract address, \
         and the asset IS the EIP-712 verifyingContract, so there is no domain to check a \
         signature under"
    )]
    UnusableAsset { asset: String },

    /// The advertised `payTo` could not be read as a 20-byte recipient address, so no correct client
    /// can build an authorization naming it as the destination.
    ///
    /// Distinct from [`VerifyError::UnusableAsset`], which it would be tempting to reuse: that one
    /// explains itself by saying the asset *is* the `verifyingContract`, which is false of `payTo`
    /// and sends a reader looking at their domain configuration for a fault that is not there.
    #[error(
        "cannot use advertised payTo {pay_to:?}: it is not a 20-byte recipient address, so an \
         EIP-3009 authorization has no destination to name and this resource cannot be paid"
    )]
    UnusablePayTo { pay_to: String },

    /// The advertised network is not `eip155:<chain-id>`, so it names no EVM chain id.
    #[error(
        "cannot verify against advertised network {network:?}: offline EIP-3009 verification needs \
         an EVM chain id for the EIP-712 domain, which only a CAIP-2 \"eip155:<chain-id>\" \
         identifier carries"
    )]
    UnusableNetwork { network: String },

    #[error("payment names scheme {got:?}; this resource is advertised as {want:?}")]
    SchemeMismatch { got: String, want: String },

    #[error("payment names network {got:?}; this resource is advertised on {want:?}")]
    NetworkMismatch { got: String, want: String },

    /// The authorization pays somebody else. The one rejection that matters most to a seller.
    #[error("authorization pays {got}; this resource is advertised as payable to {want}")]
    WrongPayee { got: String, want: String },

    #[error("authorization is for {got} atomic units; this resource costs {want}")]
    Underpaid { got: u128, want: u128 },

    /// Renders the domain, deliberately. Without it this says only "bad signature", and the
    /// likeliest cause is a `name`/`version` mismatch the payer cannot see from the outside.
    #[error(
        "signature does not recover to the authorizing party.\n  authorization.from: {expected}\n  \
         recovered:          {recovered}\n  verified under EIP-712 domain: {domain}\n  If the \
         payer signed correctly, the domain above is wrong — name and version are properties of \
         the token contract that no x402 challenge carries (OBOL-019). Set OBOLUS_DEV_TOKEN_NAME \
         and OBOLUS_DEV_TOKEN_VERSION to match the contract the payer signed against."
    )]
    NotRecovered { expected: String, recovered: String, domain: String },

    #[error("signature is unusable: {source}. Verified under EIP-712 domain: {domain}")]
    UnusableSignature { source: eip3009::Eip3009Error, domain: String },

    /// The window has not opened. Both boundaries are exclusive, so `now == valid_after` lands here
    /// too, and the message has to account for it — otherwise it prints the same number twice and
    /// reads as a bug in this seller rather than as a payment presented one second early.
    #[error(
        "authorization is not valid until after {valid_after} (now {now}). The boundary itself is \
         outside the window: EIP-3009 requires validAfter < block.timestamp, strictly."
    )]
    NotYetValid { valid_after: u64, now: u64 },

    /// The window has closed, with the same boundary caveat as [`VerifyError::NotYetValid`].
    #[error(
        "authorization expired at {valid_before} (now {now}). The boundary itself is outside the \
         window: EIP-3009 requires block.timestamp < validBefore, strictly."
    )]
    Expired { valid_before: u64, now: u64 },
}

/// Decode the `payload` object of an `exact`-scheme EVM payment.
///
/// Every uint256 is parsed **fallibly** from its decimal string. `as u128` would be the shorter
/// spelling and is the one bug this whole file must not have: a truncated amount produces a
/// signature that verifies over a number nobody authorized.
pub fn parse_exact_payload(payload: &Value) -> Result<ExactPayload, VerifyError> {
    let auth = payload.get("authorization").ok_or(VerifyError::Missing { field: "authorization" })?;

    Ok(ExactPayload {
        authorization: Authorization {
            from: address_field(auth, "from")?,
            to: address_field(auth, "to")?,
            value: uint_field(auth, "value")?,
            valid_after: window_field(auth, "validAfter")?,
            valid_before: window_field(auth, "validBefore")?,
            nonce: hex_field(auth, "nonce")?,
        },
        signature: hex_string(payload, "signature")
            .and_then(|s| eip3009::decode_hex(s).map_err(|e| VerifyError::BadHex {
                field: "signature",
                source: e,
            }))?,
    })
}

/// Build the EIP-712 domain to verify under, from what was advertised plus the two configured
/// token fields.
pub fn domain_for(
    requirements: &PaymentRequirements,
    token: &TokenDomain,
) -> Result<Eip712Domain, VerifyError> {
    Ok(Eip712Domain {
        name: token.name.clone(),
        version: token.version.clone(),
        chain_id: chain_id_of(&requirements.network)?,
        verifying_contract: decode_hex_array::<20>(&requirements.asset)
            .map_err(|_| VerifyError::UnusableAsset { asset: requirements.asset.clone() })?,
    })
}

/// A validity-window timestamp, narrowed to the `u64` an [`Authorization`] carries.
///
/// Fallible rather than `as`, which would silently turn an absurd `validBefore` into a plausible
/// one — and this is the single field pair whose entire job is to be compared against a clock, so a
/// value that quietly changes on the way in defeats the comparison rather than failing it. Nothing
/// legitimate is anywhere near the boundary: `u64` seconds reaches well past any date that will ever
/// be written into an authorization.
fn window_field(object: &Value, field: &'static str) -> Result<u64, VerifyError> {
    let raw = uint_field(object, field)?;
    u64::try_from(raw).map_err(|_| VerifyError::BadUint { field, value: raw.to_string() })
}

/// The advertised recipient, as the 20 bytes an authorization has to name.
///
/// Separate from [`domain_for`] because it is checkable in **every** verification mode. The domain
/// only matters when this binary inspects signatures, but `payTo` is what a *client* must put in the
/// authorization it signs — so an unreadable one makes the challenge unpayable whether or not
/// anything here would have looked at the result.
pub fn pay_to_of(requirements: &PaymentRequirements) -> Result<[u8; 20], VerifyError> {
    decode_hex_array::<20>(&requirements.pay_to)
        .map_err(|_| VerifyError::UnusablePayTo { pay_to: requirements.pay_to.clone() })
}

/// The EVM chain id a CAIP-2 network identifier names.
///
/// Deliberately narrow: only `eip155:<decimal>` yields a chain id. Anything else — an x402 short
/// name, a Solana identifier, Obolus's own placeholder — names no EVM chain, and guessing one
/// would produce a domain that silently fails every signature.
pub fn chain_id_of(network: &str) -> Result<u64, VerifyError> {
    network
        .strip_prefix("eip155:")
        .and_then(|reference| reference.parse::<u64>().ok())
        .ok_or_else(|| VerifyError::UnusableNetwork { network: network.to_string() })
}

/// Does `signature` over this authorization, under this domain, recover to `authorization.from`?
///
/// The one function here held to a published vector — see [`kat_tests`]. Nothing about the
/// gateway's policy enters into it.
pub fn verify_signature(
    payload: &ExactPayload,
    domain: &Eip712Domain,
) -> Result<(), VerifyError> {
    let recovered = eip3009::recover_address(
        &payload.authorization.transfer_digest(domain),
        &payload.signature,
    )
    .map_err(|e| VerifyError::UnusableSignature { source: e, domain: render_domain(domain) })?;

    if recovered != payload.authorization.from {
        return Err(VerifyError::NotRecovered {
            expected: render_address(&payload.authorization.from),
            recovered: render_address(&recovered),
            domain: render_domain(domain),
        });
    }
    Ok(())
}

/// Is this payment for what was advertised — same scheme, same network, our address, enough money?
///
/// The **asset** is checked by [`verify_signature`], not here: the asset address is the EIP-712
/// `verifyingContract`, so a payment authorizing a different token is signed under a different
/// domain and fails to recover. That is a stronger check than a field comparison, because the
/// payer cannot restate the asset in a way that disagrees with what they signed.
pub fn check_terms(
    payment: &PaymentPayload,
    payload: &ExactPayload,
    requirements: &PaymentRequirements,
) -> Result<(), VerifyError> {
    if payment.scheme != requirements.scheme {
        return Err(VerifyError::SchemeMismatch {
            got: payment.scheme.clone(),
            want: requirements.scheme.clone(),
        });
    }
    if payment.network != requirements.network {
        return Err(VerifyError::NetworkMismatch {
            got: payment.network.clone(),
            want: requirements.network.clone(),
        });
    }

    let pay_to = pay_to_of(requirements)?;
    if payload.authorization.to != pay_to {
        return Err(VerifyError::WrongPayee {
            got: render_address(&payload.authorization.to),
            want: render_address(&pay_to),
        });
    }

    // `>=`, not `==`: `maxAmountRequired` is the price this resource asks, and a payer who
    // authorized more than that has still paid for it. Underpayment is the direction that costs
    // the seller, and it is the direction this rejects.
    let price: u128 = requirements.max_amount_required.parse().map_err(|_| VerifyError::BadUint {
        field: "maxAmountRequired",
        value: requirements.max_amount_required.clone(),
    })?;
    if payload.authorization.value < price {
        return Err(VerifyError::Underpaid { got: payload.authorization.value, want: price });
    }
    Ok(())
}

/// Is the authorization inside its validity window at `now` (seconds since the Unix epoch)?
///
/// Separate from the two checks above because it is the only one that depends on a clock, and a
/// clock is what makes the specification's own worked example unverifiable — it was signed in
/// February 2025. Callers that want to replay a published vector skip this.
///
/// Both boundaries are **exclusive**, matching what the EIP-3009 contract itself enforces
/// (`validAfter < block.timestamp < validBefore`). The `validAfter` edge is the one worth being
/// deliberate about: accepting `now == validAfter` would pass a payment here that the chain would
/// refuse, and a development seller that is more permissive than the contract tells a client author
/// their authorization is good one second before it is.
pub fn check_window(authorization: &Authorization, now: u64) -> Result<(), VerifyError> {
    if now <= authorization.valid_after {
        return Err(VerifyError::NotYetValid { valid_after: authorization.valid_after, now });
    }
    if now >= authorization.valid_before {
        return Err(VerifyError::Expired { valid_before: authorization.valid_before, now });
    }
    Ok(())
}

/// `0x`-prefixed lowercase hex. No EIP-55 checksum casing: these strings appear in rejection
/// messages beside an address the payer supplied, and one-cased comparison is what a reader can do
/// by eye.
pub fn render_address(address: &[u8; 20]) -> String {
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for byte in address {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The domain a verification ran under, in one line — the thing a rejection has to name if the
/// payer is to have any way of finding a `name`/`version` mismatch.
pub fn render_domain(domain: &Eip712Domain) -> String {
    format!(
        "name={:?} version={:?} chainId={} verifyingContract={}",
        domain.name,
        domain.version,
        domain.chain_id,
        render_address(&domain.verifying_contract)
    )
}

fn hex_string<'a>(object: &'a Value, field: &'static str) -> Result<&'a str, VerifyError> {
    object.get(field).and_then(Value::as_str).ok_or(VerifyError::Missing { field })
}

fn address_field(object: &Value, field: &'static str) -> Result<[u8; 20], VerifyError> {
    hex_field(object, field)
}

fn hex_field<const N: usize>(object: &Value, field: &'static str) -> Result<[u8; N], VerifyError> {
    let raw = hex_string(object, field)?;
    decode_hex_array::<N>(raw).map_err(|e| VerifyError::BadHex { field, source: e })
}

/// A uint256 carried as a decimal string, parsed fallibly into `u128`.
///
/// `u128` rather than a full 256-bit type because every value x402 puts through this path — a USDC
/// amount, a Unix timestamp — is far inside it, and the parse *rejects* anything that is not
/// rather than wrapping. A true uint256 overflow lands in [`VerifyError::BadUint`], which is a
/// refusal to verify; it never becomes a smaller number that then gets signed for.
fn uint_field(object: &Value, field: &'static str) -> Result<u128, VerifyError> {
    match object.get(field) {
        None => Err(VerifyError::Missing { field }),
        Some(Value::Number(_)) => Err(VerifyError::NumericUint { field }),
        Some(value) => {
            let raw = value.as_str().ok_or(VerifyError::Missing { field })?;
            raw.parse::<u128>()
                .map_err(|_| VerifyError::BadUint { field, value: raw.to_string() })
        }
    }
}

/// The published known-answer vector, and the negatives that stop it passing for the wrong reason.
///
/// # Why this file carries the KAT and not just `eip3009`
///
/// `eip3009`'s own `kat` module already checks that `verify_transfer` recovers the published
/// signer. What it cannot check is the path *this* binary takes to get there: the wire payload is
/// camelCase JSON with every uint256 as a decimal string, and every one of those decodes is code
/// in this file. A transposed `validAfter`/`validBefore`, or an `as u128` truncation of `value`,
/// changes the struct hash and so changes the digest — and would be invisible to a test that
/// built an `Authorization` by hand.
///
/// So these tests feed the published vector through [`parse_exact_payload`] in the shape a client
/// actually sends, and only then verify. The oracle is the specification's own signature; nothing
/// here was produced by us.
#[cfg(test)]
mod kat_tests {
    use super::*;

    /// The vector, loaded from the same file `eip3009`'s KAT reads — one copy, so the two cannot
    /// drift into testing different bytes.
    const X402_AUTHORIZATION: &str =
        include_str!("../../eip3009/fixtures/x402-authorization.json");

    fn fixture() -> Value {
        serde_json::from_str(X402_AUTHORIZATION).expect("the fixture is valid JSON")
    }

    /// The fixture stores the authorization in its own snake_case shape. Re-emit it as the
    /// camelCase wire payload a client puts in the `X-PAYMENT` header, which is what this module
    /// parses — anything else would test a decoder nobody uses.
    fn wire_payload(doc: &Value) -> Value {
        let a = &doc["authorization"];
        serde_json::json!({
            "signature": doc["signature"],
            "authorization": {
                "from": a["from"],
                "to": a["to"],
                "value": a["value"],
                "validAfter": a["valid_after"],
                "validBefore": a["valid_before"],
                "nonce": a["nonce"],
            }
        })
    }

    fn fixture_domain(doc: &Value) -> Eip712Domain {
        let d = &doc["domain"];
        Eip712Domain {
            name: d["name"].as_str().expect("domain.name").to_string(),
            version: d["version"].as_str().expect("domain.version").to_string(),
            chain_id: d["chain_id"].as_u64().expect("domain.chain_id"),
            verifying_contract: decode_hex_array::<20>(
                d["verifying_contract"].as_str().expect("domain.verifying_contract"),
            )
            .expect("the fixture's verifying contract is a 20-byte address"),
        }
    }

    #[test]
    fn the_published_x402_payload_verifies_through_this_decoder() {
        let doc = fixture();
        let payload = parse_exact_payload(&wire_payload(&doc)).expect("decode the wire payload");

        verify_signature(&payload, &fixture_domain(&doc))
            .expect("the specification's own signature must verify");
    }

    #[test]
    fn the_decoder_recovers_every_authorization_field_from_the_wire_shape() {
        // The signature check above would catch a wrong field, but only as "does not recover" —
        // which is the same symptom as a wrong domain, a wrong signature, or a bug in secp256k1.
        // These assertions say which.
        let doc = fixture();
        let payload = parse_exact_payload(&wire_payload(&doc)).expect("decode the wire payload");
        let a = &payload.authorization;

        assert_eq!(render_address(&a.from), doc["authorization"]["from"].as_str().unwrap().to_lowercase());
        assert_eq!(render_address(&a.to), doc["authorization"]["to"].as_str().unwrap().to_lowercase());
        assert_eq!(a.value, 10_000);
        assert_eq!(a.valid_after, 1_740_672_089);
        assert_eq!(a.valid_before, 1_740_672_154);
    }

    /// A positive KAT alone is nearly worthless: it passes identically if `verify_signature`
    /// ignored the domain, or ignored any one field of it. Perturb each of the four in turn and
    /// require a rejection every time.
    #[test]
    fn every_domain_field_is_load_bearing() {
        let doc = fixture();
        let payload = parse_exact_payload(&wire_payload(&doc)).expect("decode the wire payload");
        let base = fixture_domain(&doc);

        let mut wrong_name = base.clone();
        wrong_name.name = "USD Coin".to_string();

        let mut wrong_version = base.clone();
        wrong_version.version = "1".to_string();

        // Base mainnet — the near-miss most likely to happen by accident.
        let mut wrong_chain = base.clone();
        wrong_chain.chain_id = 8453;

        let mut wrong_contract = base.clone();
        wrong_contract.verifying_contract[19] ^= 0x01;

        for (field, domain) in [
            ("name", wrong_name),
            ("version", wrong_version),
            ("chainId", wrong_chain),
            ("verifyingContract", wrong_contract),
        ] {
            assert!(
                verify_signature(&payload, &domain).is_err(),
                "perturbing the domain's {field} must break verification, or the signature is \
                 not actually being checked against it"
            );
        }
    }

    /// The rejection has to name the domain it used, because a `name`/`version` mismatch is
    /// invisible from the payer's side and is the likeliest cause of a failure here (OBOL-019).
    #[test]
    fn a_failed_recovery_names_the_domain_it_verified_under() {
        let doc = fixture();
        let payload = parse_exact_payload(&wire_payload(&doc)).expect("decode the wire payload");
        let mut domain = fixture_domain(&doc);
        domain.name = "USD Coin".to_string();

        let message = verify_signature(&payload, &domain).expect_err("a wrong name must fail").to_string();

        assert!(message.contains("USD Coin"), "the message must name the domain used; got:\n{message}");
        assert!(message.contains("84532"), "the message must name the chain id used; got:\n{message}");
    }

    /// A tampered signature must fail. Without this, a `verify_signature` that returned `Ok`
    /// unconditionally would pass every assertion above except the domain perturbations.
    #[test]
    fn a_tampered_signature_does_not_verify() {
        let doc = fixture();
        let mut payload = parse_exact_payload(&wire_payload(&doc)).expect("decode the wire payload");
        payload.signature[10] ^= 0x01;

        assert!(verify_signature(&payload, &fixture_domain(&doc)).is_err());
    }

    /// The published vector's window closed in February 2025 — which is exactly why the clock
    /// check is not part of `verify_signature`. Pinned so nobody folds it back in and quietly
    /// makes the one third-party vector in this repository unusable.
    #[test]
    fn the_published_vector_is_outside_its_validity_window_today() {
        let doc = fixture();
        let payload = parse_exact_payload(&wire_payload(&doc)).expect("decode the wire payload");

        assert!(
            check_window(&payload.authorization, 1_800_000_000).is_err(),
            "the published vector is long expired; a combined verify would reject the KAT"
        );
        // ...and the window check is not vacuous: inside the window it passes.
        assert!(check_window(&payload.authorization, 1_740_672_100).is_ok());
    }

    /// Both boundaries are exclusive, matching what the EIP-3009 contract enforces:
    /// `validAfter < block.timestamp < validBefore`.
    ///
    /// The `validAfter` edge is the one worth pinning. An inclusive comparison there accepts a
    /// payment one second before the chain would, and a development seller more permissive than the
    /// contract tells a client author their authorization is good while it is not yet — the failure
    /// this binary exists to make impossible to hit by accident.
    #[test]
    fn the_validity_window_excludes_both_of_its_boundaries() {
        let doc = fixture();
        let payload = parse_exact_payload(&wire_payload(&doc)).expect("decode the wire payload");
        let authorization = &payload.authorization;
        let after = authorization.valid_after;
        let before = authorization.valid_before;

        assert!(check_window(authorization, after + 1).is_ok(), "one second later is inside");
        assert!(check_window(authorization, before - 1).is_ok(), "one second earlier is inside");

        // On the text and not just on `is_err`. At either boundary the message quotes the same
        // number in both of its slots, which reads as a seller bug to the one client author most
        // likely to hit it — the one who set `validAfter` to the instant they signed. What keeps it
        // legible is the sentence saying the boundary is excluded, so that is what is asserted.
        let at_start = check_window(authorization, after).expect_err("validAfter itself is outside");
        assert!(at_start.to_string().contains("The boundary itself is outside"), "{at_start}");

        let at_end = check_window(authorization, before).expect_err("validBefore itself is outside");
        assert!(at_end.to_string().contains("The boundary itself is outside"), "{at_end}");
    }
}

#[cfg(test)]
mod decode_tests {
    use super::*;

    fn payload_with(authorization: Value) -> Value {
        serde_json::json!({
            "signature": "0x00",
            "authorization": authorization,
        })
    }

    /// The bug this module must not have. A `value` above `u128::MAX` is refused outright rather
    /// than wrapping into a smaller number the payer never authorized.
    #[test]
    fn an_out_of_range_amount_is_refused_not_truncated() {
        // 2^128, one past what `u128` holds — reachable in a real uint256 field.
        let payload = payload_with(serde_json::json!({
            "from": "0x00000000000000000000000000000000000000aa",
            "to": "0x00000000000000000000000000000000000000bb",
            "value": "340282366920938463463374607431768211456",
            "validAfter": "0",
            "validBefore": "1",
            "nonce": "0x0000000000000000000000000000000000000000000000000000000000000001",
        }));

        assert_eq!(
            parse_exact_payload(&payload),
            Err(VerifyError::BadUint {
                field: "value",
                value: "340282366920938463463374607431768211456".to_string(),
            })
        );
    }

    /// A validity timestamp past `u64` is refused rather than narrowed.
    ///
    /// Truncation runs the dangerous way here: 2^64 narrows to 0, which reads as "valid since the
    /// epoch" — an absurd value quietly becoming a permissive one, in the one field pair whose whole
    /// purpose is to be compared against a clock.
    #[test]
    fn an_out_of_range_validity_timestamp_is_refused_not_truncated() {
        // 2^64, one past what the `u64` in an `Authorization` holds.
        let payload = payload_with(serde_json::json!({
            "from": "0x00000000000000000000000000000000000000aa",
            "to": "0x00000000000000000000000000000000000000bb",
            "value": "1",
            "validAfter": "18446744073709551616",
            "validBefore": "18446744073709551617",
            "nonce": "0x0000000000000000000000000000000000000000000000000000000000000001",
        }));

        assert_eq!(
            parse_exact_payload(&payload),
            Err(VerifyError::BadUint {
                field: "validAfter",
                value: "18446744073709551616".to_string(),
            })
        );
    }

    /// The same refusal for `validBefore` — which the case above cannot cover.
    ///
    /// Struct-literal fields evaluate in order, so a payload with *both* out of range short-circuits
    /// on `validAfter` and never reaches the second field at all. That leaves a narrowing cast on
    /// `validBefore` free to survive the whole suite. Here `validAfter` is in range, so the check
    /// under test is the only one that can fire.
    #[test]
    fn an_out_of_range_expiry_is_refused_not_truncated() {
        let payload = payload_with(serde_json::json!({
            "from": "0x00000000000000000000000000000000000000aa",
            "to": "0x00000000000000000000000000000000000000bb",
            "value": "1",
            "validAfter": "0",
            "validBefore": "18446744073709551616",
            "nonce": "0x0000000000000000000000000000000000000000000000000000000000000001",
        }));

        assert_eq!(
            parse_exact_payload(&payload),
            Err(VerifyError::BadUint {
                field: "validBefore",
                value: "18446744073709551616".to_string(),
            })
        );
    }

    #[test]
    fn a_numeric_uint_is_rejected_with_the_reason_it_cannot_be_one() {
        let payload = payload_with(serde_json::json!({
            "from": "0x00000000000000000000000000000000000000aa",
            "to": "0x00000000000000000000000000000000000000bb",
            "value": 10000,
            "validAfter": "0",
            "validBefore": "1",
            "nonce": "0x0000000000000000000000000000000000000000000000000000000000000001",
        }));

        let message = parse_exact_payload(&payload).expect_err("a JSON number is not a uint256").to_string();
        assert!(message.contains("decimal strings"), "got:\n{message}");
    }

    #[test]
    fn only_an_eip155_network_yields_a_chain_id() {
        assert_eq!(chain_id_of("eip155:84532"), Ok(84532));
        // Every one of these is a network Obolus can legitimately be advertising, and none names
        // an EVM chain — so offline verification must refuse rather than guess a domain.
        for network in ["base-sepolia", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", "test-network-not-a-real-caip2", "eip155:", "eip155:0x1"] {
            assert!(
                chain_id_of(network).is_err(),
                "{network:?} names no EVM chain id and must not produce one"
            );
        }
    }
}
