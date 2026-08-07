//! x402 protocol edges: the HTTP 402 challenge Obolus issues, and the `X-PAYMENT` /
//! `X-PAYMENT-RESPONSE` header codec.
//!
//! # Phase A boundary: the payment payload is OPAQUE
//!
//! Nothing in this module parses an EIP-3009 authorization, hashes an EIP-712 struct, or
//! touches a signature. We decode the *envelope* (version / scheme / network) and hand the
//! inner `payload` to a [`crate::facilitator::Facilitator`] that verifies and settles it.
//! That is what lets Phase A ship with no cryptography of our own. Phase B adds a
//! self-settling facilitator behind the same seam — this module does not change.
//!
//! # Why `network` and `scheme` are plain strings
//!
//! The x402 network identifiers are still moving, so they are *configuration*, not types.
//! Modelling them as enums would turn "a network we haven't heard of" into a decode failure
//! at the edge, when it should be a clean mismatch the gateway reports. There are
//! deliberately no baked-in network constants here; the tests use obviously-synthetic
//! fixtures, and the real identifiers arrive as config at A3 from the facilitator's own
//! advertised list rather than being guessed here.

use base64::engine::general_purpose::{
    GeneralPurpose, STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// The engine we EMIT with: standard alphabet, padded. Decoding is deliberately more
/// permissive — see [`decode_base64`].
const BASE64: GeneralPurpose = STANDARD;

/// The x402 protocol version this gateway speaks.
///
/// Pinned deliberately: an unrecognised version is rejected rather than best-effort parsed.
/// Guessing at a future envelope shape in payment code is how you accept something you did
/// not understand.
pub const X402_VERSION: u8 = 1;

/// The payment scheme Phase A issues: pay exactly this amount to this address.
pub const SCHEME_EXACT: &str = "exact";

/// The header a client sends its payment in.
pub const HEADER_PAYMENT: &str = "X-PAYMENT";

/// The header Obolus answers with once settlement succeeds.
pub const HEADER_PAYMENT_RESPONSE: &str = "X-PAYMENT-RESPONSE";

/// One way to pay for a resource: which chain, which token, how much, to whom.
///
/// Amounts are strings in the asset's atomic units, never floats — a payment amount that
/// round-trips through an f64 is a payment amount you can lose money on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    /// Atomic units of `asset`, as a decimal string.
    pub max_amount_required: String,
    /// The resource being paid for (a URL).
    pub resource: String,
    pub description: String,
    pub mime_type: String,
    /// The address that receives payment.
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    /// The asset contract/mint address on `network`.
    pub asset: String,
    /// Scheme-specific extras, passed through untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// The body of a 402 response: here is what I accept, pick one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u8,
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PaymentRequired {
    /// A challenge offering every listed way to pay, at the pinned protocol version.
    ///
    /// Order is preserved: the first entry is the gateway's preferred option, but `accepts` is a
    /// menu and the client may pick any of them. This is how one gateway advertises several chains
    /// (e.g. Base *and* Solana) in a single 402 — the client chooses which to pay (OBOL-003).
    pub fn offering_all(accepts: Vec<PaymentRequirements>) -> Self {
        Self { x402_version: X402_VERSION, accepts, error: None }
    }

    /// A challenge offering a single way to pay. Shorthand for [`offering_all`](Self::offering_all)
    /// with one option.
    pub fn offering(requirements: PaymentRequirements) -> Self {
        Self::offering_all(vec![requirements])
    }

    /// The same challenge, annotated with why the previous attempt did not satisfy it.
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }
}

/// A decoded `X-PAYMENT` envelope.
///
/// `payload` is intentionally an opaque [`serde_json::Value`] — see the module docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u8,
    pub scheme: String,
    pub network: String,
    pub payload: serde_json::Value,
}

/// What we put in `X-PAYMENT-RESPONSE` after settling.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReceipt {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

/// Why an `X-PAYMENT` header could not be turned into a [`PaymentPayload`].
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

/// Encode a payment envelope for the `X-PAYMENT` header.
pub fn encode_payment(payload: &PaymentPayload) -> String {
    encode(payload)
}

/// Decode an `X-PAYMENT` header value, rejecting protocol versions we do not speak.
pub fn decode_payment(raw: &str) -> Result<PaymentPayload, CodecError> {
    let payload: PaymentPayload = decode(HEADER_PAYMENT, raw)?;
    if payload.x402_version != X402_VERSION {
        return Err(CodecError::UnsupportedVersion {
            found: payload.x402_version,
            expected: X402_VERSION,
        });
    }
    Ok(payload)
}

/// Encode a settlement receipt for the `X-PAYMENT-RESPONSE` header.
pub fn encode_receipt(receipt: &SettlementReceipt) -> String {
    encode(receipt)
}

/// Decode an `X-PAYMENT-RESPONSE` header value. Provided for clients and for our own
/// round-trip tests; the gateway itself only ever encodes.
pub fn decode_receipt(raw: &str) -> Result<SettlementReceipt, CodecError> {
    decode(HEADER_PAYMENT_RESPONSE, raw)
}

/// Check that a `maxAmountRequired` string is a non-negative integer in atomic units, returning
/// it unchanged if so.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Obviously-synthetic fixtures. These are NOT real network identifiers or addresses —
    /// the real ones are configuration, and inventing plausible-looking ones in tests is how
    /// a guess gets promoted to a fact.
    const FIXTURE_NETWORK: &str = "test-network-not-a-real-caip2";
    const FIXTURE_PAY_TO: &str = "0xTEST-PAY-TO-ADDRESS-NOT-REAL";
    const FIXTURE_ASSET: &str = "0xTEST-ASSET-ADDRESS-NOT-REAL";

    /// Produced OUTSIDE this codebase (`base64 -i golden-payment.json` on the exact JSON in
    /// [`golden_json`]) so it is an independent oracle. A round-trip test alone would happily
    /// pass with a wrong alphabet or wrong padding, because it would decode its own mistake.
    const GOLDEN_B64: &str = "eyJ4NDAyVmVyc2lvbiI6MSwic2NoZW1lIjoiZXhhY3QiLCJuZXR3b3JrIjoidGVzdC1uZXR3b3JrLW5vdC1hLXJlYWwtY2FpcDIiLCJwYXlsb2FkIjp7ImF1dGhvcml6YXRpb24iOiJvcGFxdWUtdG8tcGhhc2UtYSJ9fQ==";

    fn golden_json() -> &'static str {
        r#"{"x402Version":1,"scheme":"exact","network":"test-network-not-a-real-caip2","payload":{"authorization":"opaque-to-phase-a"}}"#
    }

    fn golden_payload() -> PaymentPayload {
        PaymentPayload {
            x402_version: X402_VERSION,
            scheme: SCHEME_EXACT.to_string(),
            network: FIXTURE_NETWORK.to_string(),
            payload: serde_json::json!({ "authorization": "opaque-to-phase-a" }),
        }
    }

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: FIXTURE_NETWORK.to_string(),
            max_amount_required: "1000".to_string(),
            resource: "http://localhost:8402/v1/chat/completions".to_string(),
            description: "One inference request".to_string(),
            mime_type: "application/json".to_string(),
            pay_to: FIXTURE_PAY_TO.to_string(),
            max_timeout_seconds: 60,
            asset: FIXTURE_ASSET.to_string(),
            extra: None,
        }
    }

    #[test]
    fn decodes_the_independently_produced_golden_vector() {
        let decoded = decode_payment(GOLDEN_B64).expect("golden vector must decode");
        assert_eq!(decoded, golden_payload());
    }

    #[test]
    fn encodes_to_the_independently_produced_golden_vector() {
        // Pins our serialization too: field names, field ORDER, and no stray whitespace.
        // If serde ever renames or reorders a field, this fails loudly rather than silently
        // emitting an envelope a facilitator would reject.
        assert_eq!(encode_payment(&golden_payload()), GOLDEN_B64);
    }

    #[test]
    fn golden_vector_decodes_to_the_documented_json() {
        // Guards the comment above GOLDEN_B64: the constant really is that JSON, so a future
        // reader can regenerate it the same way.
        let bytes = BASE64.decode(GOLDEN_B64).expect("golden vector is base64");
        assert_eq!(String::from_utf8(bytes).expect("golden vector is utf-8"), golden_json());
    }

    #[test]
    fn payment_envelope_round_trips() {
        let payload = golden_payload();
        assert_eq!(decode_payment(&encode_payment(&payload)).unwrap(), payload);
    }

    #[test]
    fn receipt_round_trips() {
        let receipt = SettlementReceipt {
            success: true,
            transaction: Some("0xTEST-TX-HASH-NOT-REAL".to_string()),
            network: FIXTURE_NETWORK.to_string(),
            payer: Some("0xTEST-PAYER-NOT-REAL".to_string()),
        };
        assert_eq!(decode_receipt(&encode_receipt(&receipt)).unwrap(), receipt);
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        // Header values pick up incidental whitespace in transit; that is not a protocol error.
        let padded = format!("  {GOLDEN_B64}\n");
        assert_eq!(decode_payment(&padded).unwrap(), golden_payload());
    }

    #[test]
    fn accepts_url_safe_and_unpadded_alphabets() {
        let payload = PaymentPayload {
            x402_version: X402_VERSION,
            scheme: SCHEME_EXACT.to_string(),
            network: FIXTURE_NETWORK.to_string(),
            // Chosen so the two alphabets actually diverge (bytes landing on indices 62/63,
            // where standard emits `+` `/` and url-safe emits `-` `_`). Asserted below rather
            // than assumed — a fixture that happened to encode identically would make every
            // case below vacuous.
            payload: serde_json::json!({ "authorization": "???>>>???>>>??>>" }),
        };
        let json = serde_json::to_vec(&payload).unwrap();
        let standard = STANDARD.encode(&json);
        let url_safe = URL_SAFE.encode(&json);
        assert_ne!(standard, url_safe, "fixture must exercise the +/ vs -_ divergence");

        for encoded in [
            standard,
            url_safe,
            STANDARD_NO_PAD.encode(&json),
            URL_SAFE_NO_PAD.encode(&json),
        ] {
            assert_eq!(decode_payment(&encoded).unwrap(), payload, "failed to decode {encoded}");
        }
    }

    #[test]
    fn rejects_non_base64() {
        let err = decode_payment("not!valid!base64!").unwrap_err();
        assert!(matches!(err, CodecError::Base64 { header: HEADER_PAYMENT, .. }), "got {err:?}");
    }

    #[test]
    fn rejects_base64_that_is_not_json() {
        let err = decode_payment(&BASE64.encode(b"plain text, not json")).unwrap_err();
        assert!(matches!(err, CodecError::Json { header: HEADER_PAYMENT, .. }), "got {err:?}");
    }

    #[test]
    fn rejects_json_that_is_not_a_payment_envelope() {
        let err = decode_payment(&BASE64.encode(br#"{"unrelated":true}"#)).unwrap_err();
        assert!(matches!(err, CodecError::Json { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_an_unsupported_protocol_version() {
        let mut future = golden_payload();
        future.x402_version = X402_VERSION + 1;
        let err = decode_payment(&encode_payment(&future)).unwrap_err();
        assert_eq!(
            err,
            CodecError::UnsupportedVersion { found: X402_VERSION + 1, expected: X402_VERSION }
        );
    }

    #[test]
    fn challenge_serializes_with_the_protocol_field_names() {
        // The wire names are camelCase while the Rust fields are snake_case, so a dropped
        // `rename_all` would produce a challenge no client understands — and every one of our
        // own round-trip tests would still pass. Assert on the JSON itself.
        let json = serde_json::to_value(PaymentRequired::offering(requirements())).unwrap();
        assert_eq!(json["x402Version"], serde_json::json!(X402_VERSION));
        let accepts = &json["accepts"][0];
        assert_eq!(accepts["maxAmountRequired"], serde_json::json!("1000"));
        assert_eq!(accepts["payTo"], serde_json::json!(FIXTURE_PAY_TO));
        assert_eq!(accepts["mimeType"], serde_json::json!("application/json"));
        assert_eq!(accepts["maxTimeoutSeconds"], serde_json::json!(60));
    }

    #[test]
    fn absent_optional_fields_are_omitted_not_null() {
        let json = serde_json::to_value(PaymentRequired::offering(requirements())).unwrap();
        assert!(json.get("error").is_none(), "no error key when there is no error");
        assert!(json["accepts"][0].get("extra").is_none(), "no extra key when there is no extra");
    }

    #[test]
    fn with_error_annotates_the_challenge() {
        let challenge = PaymentRequired::offering(requirements()).with_error("payment expired");
        assert_eq!(challenge.error.as_deref(), Some("payment expired"));
        assert_eq!(challenge.accepts.len(), 1, "annotating must not disturb the offer");
    }

    #[test]
    fn offering_all_advertises_every_option() {
        let a = requirements();
        let mut b = requirements();
        b.network = "test-network-b-not-a-real-caip2".to_string();
        let challenge = PaymentRequired::offering_all(vec![a.clone(), b.clone()]);
        assert_eq!(challenge.accepts, vec![a, b], "both options present, in order");
        assert!(challenge.error.is_none());
    }

    #[test]
    fn offering_is_offering_all_with_a_single_option() {
        // The single-option constructor is exactly the one-element list form, so the two paths
        // cannot drift apart.
        let r = requirements();
        assert_eq!(PaymentRequired::offering(r.clone()), PaymentRequired::offering_all(vec![r]));
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
