//! x402 protocol edges: the challenge Obolus issues, and the codec for the three x402 headers —
//! `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE` and `PAYMENT-RESPONSE`.
//!
//! Obolus speaks x402 **v2**, and only v2. The wire types and the header codec live in [`v2`] and are
//! re-exported here, so the rest of the crate names them without naming a version. v1 is gone rather
//! than kept beside it: as obolus shipped it, it paired v2's CAIP-2 network ids with v1's envelope,
//! and nothing on either side of the protocol accepted that (#71). Supporting real v1 clients is
//! #73.
//!
//! # Phase A boundary: the payment payload is OPAQUE
//!
//! Nothing in this module parses an EIP-3009 authorization, hashes an EIP-712 struct, or
//! touches a signature. We decode the *envelope* (version, and the option the client accepted) and
//! hand the rest to a [`crate::facilitator::Facilitator`] that verifies and settles it, forwarded as
//! received. That is what lets Phase A ship with no cryptography of our own. Phase B adds a
//! self-settling facilitator behind the same seam — this module does not change.
//!
//! # Why `network` and `scheme` are plain strings
//!
//! The x402 network identifiers are still moving, so they are *configuration*, not types.
//! Modelling them as enums would turn "a network we haven't heard of" into a decode failure
//! at the edge, when it should be a clean mismatch the gateway reports. There are
//! deliberately no baked-in network constants here; the tests use obviously-synthetic
//! fixtures, and the real identifiers arrive as configuration, checked by the arming guard.

pub mod v2;

pub use v2::{
    decode_payment, decode_payment_required, decode_receipt, encode_payment,
    encode_payment_required, encode_receipt, PaymentPayload, PaymentRequired, PaymentRequirements,
    ResourceInfo, SettlementReceipt, HEADER_PAYMENT_REQUIRED, HEADER_PAYMENT_RESPONSE,
    HEADER_PAYMENT_SIGNATURE, X402_VERSION,
};

use base64::engine::general_purpose::{
    GeneralPurpose, STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// The engine we EMIT with: standard alphabet, padded. Decoding is deliberately more
/// permissive — see [`decode_base64`].
const BASE64: GeneralPurpose = STANDARD;

/// The payment scheme Phase A issues: pay exactly this amount to this address.
pub const SCHEME_EXACT: &str = "exact";

/// Why an x402 header could not be decoded.
///
/// Deliberately distinct variants: "you sent me garbage" and "you sent me a protocol version
/// I don't speak" are different conversations to have with a client.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CodecError {
    #[error("{header} is not valid base64: {detail}")]
    Base64 { header: &'static str, detail: String },
    #[error("{header} did not decode to valid JSON: {detail}")]
    Json { header: &'static str, detail: String },
    #[error("unsupported x402 version {found}; this gateway speaks {expected}")]
    UnsupportedVersion { found: u8, expected: u8 },
}

fn encode<T: Serialize>(value: &T) -> String {
    // Serializing our own owned types cannot fail: no non-string map keys, no NaN, no
    // custom Serialize impl that can error.
    BASE64.encode(serde_json::to_vec(value).expect("obolus types are always serializable"))
}

/// Decode a header value under any base64 alphabet a client might plausibly have used.
///
/// We emit standard-padded, but accept url-safe and unpadded on the way in. Which variant a
/// client's x402 library emits is not something we can pin from here, and rejecting a perfectly
/// good payment over an alphabet choice would surface to the payer as *"your payment is invalid"* —
/// an interop break wearing a payment rejection's clothes.
///
/// Being liberal here is safe precisely because this layer is pure transport: we never hash,
/// sign, or compare the *encoded* form, so there is no canonicalisation to attack. Each
/// variant either yields the same bytes or fails to decode. The strictness that matters lives
/// downstream, in the facilitator that judges the authorization itself.
fn decode_base64(raw: &str) -> Option<Vec<u8>> {
    STANDARD
        .decode(raw)
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
        .or_else(|_| URL_SAFE.decode(raw))
        .or_else(|_| URL_SAFE_NO_PAD.decode(raw))
        .ok()
}

fn decode<T: for<'de> Deserialize<'de>>(header: &'static str, raw: &str) -> Result<T, CodecError> {
    let bytes = decode_base64(raw.trim()).ok_or_else(|| CodecError::Base64 {
        header,
        detail: "not valid base64 under any accepted alphabet (standard or url-safe, padded or not)"
            .to_string(),
    })?;
    serde_json::from_slice(&bytes).map_err(|e| CodecError::Json { header, detail: e.to_string() })
}

/// Check that an `amount` string is a non-negative integer in atomic units, returning it unchanged
/// if so.
///
/// The amount is carried over the wire as a decimal string (never a float — see
/// [`PaymentRequirements`]), which means a value that is *not* a plain integer — `1.5`, `1,000`,
/// `1e3`, `-5`, or empty — is not a smaller or larger price, it is one no conforming client can
/// pay. Left unchecked at startup, that mistake surfaces only at A3 as "every payment is
/// refused", far from its cause. We validate by parsing as [`u128`] (wide enough for any token's
/// atomic units) but keep the original string, because the wire form is authoritative and
/// reformatting it could itself change it.
pub fn validate_atomic_amount(raw: &str) -> Result<String, String> {
    match raw.parse::<u128>() {
        Ok(_) => Ok(raw.to_string()),
        Err(_) => Err(format!(
            "{raw:?} is not a non-negative integer amount in atomic units \
             (no decimals, sign, separators, or exponent)"
        )),
    }
}

/// The transport rules every header shares — whitespace, the base64 alphabets, and the
/// garbage-in cases — exercised through the payment header, the one a client writes. The
/// per-header shapes are [`v2`]'s tests.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Obviously-synthetic fixtures. These are NOT real network identifiers or addresses —
    /// the real ones are configuration, and inventing plausible-looking ones in tests is how
    /// a guess gets promoted to a fact.
    const FIXTURE_NETWORK: &str = "test-network-not-a-real-caip2";
    const FIXTURE_PAY_TO: &str = "0xTEST-PAY-TO-ADDRESS-NOT-REAL";
    const FIXTURE_ASSET: &str = "0xTEST-ASSET-ADDRESS-NOT-REAL";

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: FIXTURE_NETWORK.to_string(),
            amount: "1000".to_string(),
            asset: FIXTURE_ASSET.to_string(),
            pay_to: FIXTURE_PAY_TO.to_string(),
            max_timeout_seconds: 60,
            extra: None,
        }
    }

    fn payment(authorization: &str) -> PaymentPayload {
        let payload = json!({ "authorization": authorization });
        PaymentPayload::new(None, requirements(), payload.as_object().unwrap().clone())
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        // Header values pick up incidental whitespace in transit; that is not a protocol error.
        let sent = payment("opaque-to-phase-a");
        let padded = format!("  {}\n", encode_payment(&sent));
        assert_eq!(decode_payment(&padded).unwrap(), sent);
    }

    #[test]
    fn accepts_url_safe_and_unpadded_alphabets() {
        // Chosen so the two alphabets actually diverge (bytes landing on indices 62/63, where
        // standard emits `+` `/` and url-safe emits `-` `_`). Asserted below rather than assumed —
        // a fixture that happened to encode identically would make every case below vacuous.
        let sent = payment("???>>>???>>>??>>");
        let json = serde_json::to_vec(&sent).unwrap();
        let standard = STANDARD.encode(&json);
        let url_safe = URL_SAFE.encode(&json);
        assert_ne!(standard, url_safe, "fixture must exercise the +/ vs -_ divergence");

        for encoded in [
            standard,
            url_safe,
            STANDARD_NO_PAD.encode(&json),
            URL_SAFE_NO_PAD.encode(&json),
        ] {
            assert_eq!(decode_payment(&encoded).unwrap(), sent, "failed to decode {encoded}");
        }
    }

    #[test]
    fn rejects_non_base64() {
        let err = decode_payment("not!valid!base64!").unwrap_err();
        assert!(
            matches!(err, CodecError::Base64 { header: HEADER_PAYMENT_SIGNATURE, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_base64_that_is_not_json() {
        let err = decode_payment(&BASE64.encode(b"plain text, not json")).unwrap_err();
        assert!(
            matches!(err, CodecError::Json { header: HEADER_PAYMENT_SIGNATURE, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_json_that_is_not_a_payment_envelope() {
        let err = decode_payment(&BASE64.encode(br#"{"unrelated":true}"#)).unwrap_err();
        assert!(matches!(err, CodecError::Json { .. }), "got {err:?}");
    }

    #[test]
    fn a_challenge_offers_every_option_in_order() {
        // `accepts` is a menu: the first entry is preferred, the client may pay any.
        let a = requirements();
        let mut b = requirements();
        b.network = "test-network-b-not-a-real-caip2".to_string();
        let resource =
            ResourceInfo { url: "http://127.0.0.1/x".to_string(), description: None, mime_type: None };
        let challenge = PaymentRequired::offering_all(resource, vec![a.clone(), b.clone()]);
        assert_eq!(challenge.accepts, vec![a, b], "both options present, in order");
        assert!(challenge.error.is_none());
    }

    #[test]
    fn valid_atomic_amounts_pass_through_verbatim() {
        for good in ["0", "1", "1000", "340282366920938463463374607431768211455"] {
            assert_eq!(validate_atomic_amount(good).unwrap(), good);
        }
    }

    #[test]
    fn amounts_that_no_client_could_pay_are_rejected_at_the_source() {
        // Each of these starts a server today and fails only at A3 as "nobody can pay". The
        // point of the check is to move that failure to startup, where the cause is legible.
        for bad in ["", "1.5", "1,000", "1e3", "-5", "0x10", " 10", "10 ", "1_000"] {
            assert!(validate_atomic_amount(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
