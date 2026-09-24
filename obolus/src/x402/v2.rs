//! x402 **v2** wire types and the `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE`
//! header codec — the only version obolus speaks. The parent module re-exports all of it.
//!
//! # What v2 changes, and why obolus needs it
//!
//! v1 as obolus shipped it never interoperated with anything (#71): it advertised CAIP-2 networks,
//! which are v2's naming, inside a v1 envelope. v2 is the version that pairs CAIP-2 with its
//! envelope, and the one the live facilitators and the current reference client speak. On the wire:
//!
//! - the challenge travels in a base64 `PAYMENT-REQUIRED` **header**. The reference client reads
//!   only the header; a v2 challenge in a response body alone is an error to it.
//! - the price is `amount` (v1: `maxAmountRequired`), and the resource's `url`, `description` and
//!   `mimeType` move out of each option into one [`ResourceInfo`].
//! - the client's payment echoes the option it chose, whole, as `accepted`. v1 carried only its
//!   scheme and network, which is all v1's gateway could ever match a payment on.
//!
//! # The payment is still opaque — and forwarded as received
//!
//! As in v1, nothing here parses an authorization or touches a signature. [`PaymentPayload`] keeps
//! the client's envelope exactly as decoded and serializes back to it, so what a facilitator judges
//! is what the client sent — including the fields obolus does not model (`resource`, `extensions`,
//! an unknown `extra` key) — rather than obolus's re-typed approximation of it. The only thing
//! typed out of it is `accepted`, which is envelope, not payload.
//!
//! Sources, read 2026-09-23: the core spec
//! <https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md>, the HTTP
//! transport <https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/http.md> (its
//! header examples are this module's known-answer vectors — see the tests), and the reference
//! implementation `@x402/core` 2.27.0.

use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};

use super::CodecError;

/// The x402 protocol version this module speaks.
///
/// Pinned, as in v1: a payment naming any other version is refused with that version in the error,
/// not parsed on the chance that its shape happens to fit.
pub const X402_VERSION: u8 = 2;

/// The header a 402 carries its challenge in: a base64 [`PaymentRequired`].
pub const HEADER_PAYMENT_REQUIRED: &str = "PAYMENT-REQUIRED";

/// The header a client sends its payment in: a base64 [`PaymentPayload`].
pub const HEADER_PAYMENT_SIGNATURE: &str = "PAYMENT-SIGNATURE";

/// The header a settled response carries its receipt in: a base64 [`SettlementReceipt`].
pub const HEADER_PAYMENT_RESPONSE: &str = "PAYMENT-RESPONSE";

/// What is being paid for — stated once per challenge, where v1 repeated it on every option.
///
/// The spec also defines optional `serviceName`, `tags` and `iconUrl` for discovery. Obolus
/// advertises none of them, so they are not modelled; a client's own `resource` is never re-typed
/// through this struct, so nothing a client sends is lost to that omission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// One way to pay: which chain, which token, how much, to whom.
///
/// Field order is the spec's, and it is load-bearing: it is the order these serialize in, which is
/// what lets the encode tests reproduce the spec's own base64 byte for byte. Amounts stay decimal
/// strings in atomic units, never floats, exactly as in v1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    /// A CAIP-2 network id (`eip155:84532`) — v2's naming, and the form the arming guard admits.
    pub network: String,
    /// Atomic units of `asset`, as a decimal string.
    pub amount: String,
    /// The asset contract/mint address on `network`.
    pub asset: String,
    /// The address that receives payment.
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    /// Scheme-specific extras, passed through untouched. For EVM `exact` this is where the token's
    /// EIP-712 domain (`name`, `version`) travels, which a client needs in order to sign at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

impl PaymentRequirements {
    /// Is `payment` a payment for exactly this option?
    ///
    /// The same test the reference server applies (`paymentRequirementsMatchAccepted` in
    /// `@x402/core` 2.27.0): everything in the client's `accepted` except `extra` must equal this
    /// option — scheme, network, amount, asset, pay-to and timeout, and no field besides — and every
    /// key this option puts in `extra` must appear in the client's with an equal value. The client
    /// may add `extra` keys of its own (a scheme uses that to echo, say, which transfer method it
    /// chose); it may not drop or change one of ours.
    ///
    /// Compared against the `accepted` the client actually sent, not against its typed
    /// [`PaymentPayload::accepted`]: re-typing drops unknown fields, and a field obolus does not
    /// know is precisely one this option does not contain.
    ///
    /// One step of the reference is not ported: it first removes the scheme's `dynamicExtraFields`
    /// — `extra` keys the client is allowed to fill in differently — from both sides. `@x402/evm`
    /// 2.27.0 declares none for `exact`, so EVM `exact` matches exactly as the reference does. A
    /// scheme that declares some would have its payments refused here until obolus learns its list.
    pub fn is_accepted_by(&self, payment: &PaymentPayload) -> bool {
        let Some(accepted) = payment.received.get("accepted").and_then(Value::as_object) else {
            return false;
        };
        let offered = serde_json::to_value(self).expect("obolus types are always serializable");
        let Value::Object(mut offered) = offered else {
            unreachable!("PaymentRequirements serializes to a JSON object")
        };
        let offered_extra = offered.remove("extra");
        let mut accepted = accepted.clone();
        let accepted_extra = accepted.remove("extra");
        if offered != accepted {
            return false;
        }
        match offered_extra {
            None => true,
            Some(offered_extra) => {
                contains_subset(&offered_extra, accepted_extra.as_ref().unwrap_or(&Value::Null))
            }
        }
    }
}

/// Does `actual` contain everything in `expected`? Objects compare key by key, recursively, with
/// extra keys in `actual` allowed; anything else must be equal. `objectContainsSubset` in the
/// reference, as `paymentRequirementsMatchAccepted` calls it.
fn contains_subset(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => expected
            .iter()
            .all(|(key, value)| actual.get(key).is_some_and(|found| contains_subset(value, found))),
        (Value::Object(_), _) => false,
        _ => expected == actual,
    }
}

/// A 402's challenge: what is being paid for, and every way to pay for it.
///
/// Field order is the spec's, for the same reason as on [`PaymentRequirements`]. The spec's
/// optional `extensions` is not modelled: obolus advertises none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
}

impl PaymentRequired {
    /// A challenge for `resource` offering every listed way to pay, at the pinned version. Order is
    /// preserved: the first option is the preferred one, but the client may pay with any.
    pub fn offering_all(resource: ResourceInfo, accepts: Vec<PaymentRequirements>) -> Self {
        Self { x402_version: X402_VERSION, error: None, resource, accepts }
    }

    /// The same challenge, annotated with why the previous attempt did not satisfy it.
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }
}

/// A client's payment: the option it chose, and a scheme-specific payload obolus never opens.
///
/// Holds the envelope exactly as decoded (see the module docs), and serializes back to it — so
/// handing this to a facilitator forwards what the client sent. [`accepted`](Self::accepted) is a
/// typed, read-only view of the chosen option; matching an option goes through
/// [`PaymentRequirements::is_accepted_by`], which reads the received form instead. Neither field
/// is public, so the typed view cannot be edited into disagreement with what is forwarded.
///
/// "As decoded" is JSON-exact, not byte-exact: key order and whitespace are not kept, and nothing
/// downstream of a JSON parser can tell the difference.
///
/// Forwarding everything includes a client's `extensions`, although obolus advertises none; they
/// reach the facilitator unexamined until refusing unadvertised ones lands (#72).
#[derive(Debug, Clone, PartialEq)]
pub struct PaymentPayload {
    accepted: PaymentRequirements,
    received: Value,
}

impl PaymentPayload {
    /// A payment built on the client side — for tests and other clients; the gateway only ever
    /// decodes one. `payload` is the scheme's data (for EVM `exact`, `signature` and
    /// `authorization`): an object by type, because [`decode_payment`] refuses anything else, and a
    /// payment that could be built but not received would test nothing real.
    pub fn new(
        resource: Option<ResourceInfo>,
        accepted: PaymentRequirements,
        payload: Map<String, Value>,
    ) -> Self {
        let mut received = serde_json::json!({
            "x402Version": X402_VERSION,
            "accepted": accepted,
            "payload": payload,
        });
        if let Some(resource) = resource {
            received["resource"] = serde_json::to_value(resource).expect("always serializable");
        }
        Self { accepted, received }
    }

    /// The option the client says it paid for, typed — for reading (its network, its amount). Whether
    /// it is one this gateway offered is [`PaymentRequirements::is_accepted_by`]'s question.
    pub fn accepted(&self) -> &PaymentRequirements {
        &self.accepted
    }

    /// The scheme-specific payload — for EVM `exact`, the signature and the authorization.
    pub fn payload(&self) -> &Value {
        &self.received["payload"]
    }

    /// The whole envelope, as the client sent it.
    pub fn as_received(&self) -> &Value {
        &self.received
    }
}

impl Serialize for PaymentPayload {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.received.serialize(serializer)
    }
}

/// The receipt a settled response carries: did it settle, and where.
///
/// `transaction` is always present, as the spec requires — the empty string when nothing was
/// broadcast. Field order is the spec's example order, so the spec's receipts re-encode to its own
/// base64 byte for byte.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettlementReceipt {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    pub transaction: String,
    /// CAIP-2, like every network in v2.
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// What actually settled, in atomic units, where the scheme can differ from the price.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
}

/// The version a decoded envelope names, checked before anything else is parsed.
///
/// Checked first so that a v1 client — whose envelope has no `accepted` — is told "unsupported
/// version 1", which says what is actually wrong, rather than "missing field `accepted`".
fn check_version(header: &'static str, envelope: &Value) -> Result<(), CodecError> {
    let found = envelope.get("x402Version").and_then(Value::as_u64).ok_or_else(|| CodecError::Json {
        header,
        detail: "no integer x402Version field".to_string(),
    })?;
    let found = u8::try_from(found).map_err(|_| CodecError::Json {
        header,
        detail: format!("x402Version {found} is not a protocol version"),
    })?;
    if found != X402_VERSION {
        return Err(CodecError::UnsupportedVersion { found, expected: X402_VERSION });
    }
    Ok(())
}

/// Encode a challenge for the `PAYMENT-REQUIRED` header.
pub fn encode_payment_required(challenge: &PaymentRequired) -> String {
    super::encode(challenge)
}

/// Decode a `PAYMENT-REQUIRED` header value, refusing versions other than v2. Client-side, and for
/// our own tests: the gateway only ever encodes a challenge.
pub fn decode_payment_required(raw: &str) -> Result<PaymentRequired, CodecError> {
    let envelope: Value = super::decode(HEADER_PAYMENT_REQUIRED, raw)?;
    check_version(HEADER_PAYMENT_REQUIRED, &envelope)?;
    serde_json::from_value(envelope)
        .map_err(|e| CodecError::Json { header: HEADER_PAYMENT_REQUIRED, detail: e.to_string() })
}

/// Encode a payment for the `PAYMENT-SIGNATURE` header — the envelope as held, so a decoded payment
/// re-encodes to what the client sent.
pub fn encode_payment(payment: &PaymentPayload) -> String {
    super::encode(payment)
}

/// Decode a `PAYMENT-SIGNATURE` header value.
///
/// Refuses a version other than v2 (named as such, and checked before anything else), an envelope
/// with no `accepted` option, and one whose `payload` is not an object. The last is checked explicitly
/// because serde would otherwise read a *missing* `payload` as JSON `null` and let it through.
pub fn decode_payment(raw: &str) -> Result<PaymentPayload, CodecError> {
    let received: Value = super::decode(HEADER_PAYMENT_SIGNATURE, raw)?;
    check_version(HEADER_PAYMENT_SIGNATURE, &received)?;
    let json_error = |detail: String| CodecError::Json { header: HEADER_PAYMENT_SIGNATURE, detail };
    let accepted = received
        .get("accepted")
        .ok_or_else(|| json_error("no accepted payment option".to_string()))?;
    let accepted: PaymentRequirements =
        serde_json::from_value(accepted.clone()).map_err(|e| json_error(format!("accepted: {e}")))?;
    if !received.get("payload").is_some_and(Value::is_object) {
        return Err(json_error("payload must be a JSON object".to_string()));
    }
    Ok(PaymentPayload { accepted, received })
}

/// Encode a settlement receipt for the `PAYMENT-RESPONSE` header.
pub fn encode_receipt(receipt: &SettlementReceipt) -> String {
    super::encode(receipt)
}

/// Decode a `PAYMENT-RESPONSE` header value. For clients and our own tests; the gateway only ever
/// encodes.
pub fn decode_receipt(raw: &str) -> Result<SettlementReceipt, CodecError> {
    super::decode(HEADER_PAYMENT_RESPONSE, raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use serde_json::json;

    /// The x402 v2 HTTP transport spec, verbatim, pinned at x402-foundation/x402 commit
    /// `b6d5bffd73f56b72c37f888c743224dab63e35ff` (the last change to `specs/transports-v2/http.md`
    /// as of 2026-09-23; Apache-2.0).
    ///
    /// Its header examples are this module's known-answer vectors: base64 blobs, each followed by
    /// the JSON the spec says it decodes to. Written by x402, not by us — so a codec that agrees with
    /// them agrees with something we did not author, which a round trip through our own encoder
    /// never proves. Replacing the snapshot is a reviewed change, never a re-baseline to make a
    /// failing test pass.
    const HTTP_TRANSPORT_SNAPSHOT: &str =
        include_str!("../../tests/fixtures/x402-http-transport-v2.md");

    /// The `nth` example (0-based) of `header` in the snapshot: the base64 on its `HEADER: …` line,
    /// and the JSON the spec prints as its decoding — the first ```` ```json ```` block after it.
    ///
    /// Found by the header constants themselves, so a misspelt constant fails here as "no example".
    fn spec_example(header: &str, nth: usize) -> (String, Value) {
        let prefix = format!("{header}: ");
        let lines: Vec<&str> = HTTP_TRANSPORT_SNAPSHOT.lines().collect();
        let at = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.starts_with(&prefix))
            .map(|(i, _)| i)
            .nth(nth)
            .unwrap_or_else(|| panic!("the snapshot has no example #{nth} of {header}"));
        let blob = lines[at][prefix.len()..].trim().to_string();
        let open = (at..lines.len())
            .find(|&i| lines[i].trim() == "```json")
            .unwrap_or_else(|| panic!("no printed decoding follows {header} example #{nth}"));
        let close = (open + 1..lines.len())
            .find(|&i| lines[i].trim() == "```")
            .expect("the printed decoding's code block is closed");
        let printed = lines[open + 1..close].join("\n");
        let printed = serde_json::from_str(&printed)
            .unwrap_or_else(|e| panic!("{header} example #{nth}'s printed decoding is not JSON: {e}"));
        (blob, printed)
    }

    /// Every header example in the snapshot, by header and position.
    const SPEC_EXAMPLES: [(&str, usize); 4] = [
        (HEADER_PAYMENT_REQUIRED, 0),
        (HEADER_PAYMENT_SIGNATURE, 0),
        (HEADER_PAYMENT_RESPONSE, 0), // success
        (HEADER_PAYMENT_RESPONSE, 1), // failure
    ];

    #[test]
    fn the_spec_examples_decode_to_the_json_the_spec_prints() {
        // Guards the oracle before anything leans on it: spec examples go stale, and a blob that
        // no longer matches its printed decoding would make every test below vouch for the wrong
        // thing.
        for (header, nth) in SPEC_EXAMPLES {
            let (blob, printed) = spec_example(header, nth);
            let bytes = super::super::decode_base64(&blob)
                .unwrap_or_else(|| panic!("{header} example #{nth} is not base64"));
            let decoded: Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("{header} example #{nth} is not JSON: {e}"));
            assert_eq!(decoded, printed, "{header} example #{nth}");
        }
    }

    #[test]
    fn decodes_the_spec_challenge() {
        let (blob, _) = spec_example(HEADER_PAYMENT_REQUIRED, 0);
        let challenge = decode_payment_required(&blob).expect("the spec's challenge decodes");
        assert_eq!(challenge.x402_version, 2);
        assert_eq!(challenge.error.as_deref(), Some("PAYMENT-SIGNATURE header is required"));
        assert_eq!(challenge.resource.url, "https://api.example.com/premium-data");
        assert_eq!(challenge.resource.mime_type.as_deref(), Some("application/json"));
        let [option] = challenge.accepts.as_slice() else { panic!("one option") };
        assert_eq!(option.scheme, "exact");
        assert_eq!(option.network, "eip155:84532");
        assert_eq!(option.amount, "10000");
        assert_eq!(option.asset, "0x036CbD53842c5426634e7929541eC2318f3dCF7e");
        assert_eq!(option.pay_to, "0x209693Bc6afc0C5328bA36FaF03C514EF312287C");
        assert_eq!(option.max_timeout_seconds, 60);
        assert_eq!(option.extra, Some(json!({ "name": "USDC", "version": "2" })));
    }

    #[test]
    fn encodes_the_spec_challenge_byte_for_byte() {
        // Pins field names, field order, omitted optionals and the base64 alphabet at once, against
        // bytes x402 produced. The gateway emits this header on every 402, so it is the encoding
        // that most needs an outside oracle.
        let (blob, _) = spec_example(HEADER_PAYMENT_REQUIRED, 0);
        let challenge = decode_payment_required(&blob).unwrap();
        assert_eq!(encode_payment_required(&challenge), blob);
    }

    #[test]
    fn decodes_the_spec_payment() {
        let (blob, printed) = spec_example(HEADER_PAYMENT_SIGNATURE, 0);
        let payment = decode_payment(&blob).expect("the spec's payment decodes");
        assert_eq!(payment.accepted().network, "eip155:84532");
        assert_eq!(payment.accepted().amount, "10000");
        assert_eq!(
            payment.payload()["authorization"]["from"],
            json!("0x857b06519E91e3A54538791bDbb0E22373e36b66")
        );
        // Held as received: `resource`, which nothing here models, is still there.
        assert_eq!(payment.as_received(), &printed);
    }

    #[test]
    fn a_decoded_payment_serializes_back_to_what_was_received() {
        // What a facilitator is handed. Built from the spec's payment plus the fields obolus does
        // not model, so dropping any of them on the way through would show.
        let (_, mut sent) = spec_example(HEADER_PAYMENT_SIGNATURE, 0);
        sent["extensions"] = json!({ "some-extension": { "info": { "k": "v" } } });
        sent["accepted"]["extra"]["assetTransferMethod"] = json!("eip3009");
        let payment = decode_payment(&super::super::BASE64.encode(sent.to_string())).unwrap();
        assert_eq!(serde_json::to_value(&payment).unwrap(), sent);
        assert_eq!(decode_payment(&encode_payment(&payment)).unwrap(), payment);
    }

    #[test]
    fn encodes_the_spec_receipts_byte_for_byte() {
        // Both examples: the success receipt, and the failure receipt whose `transaction` is the
        // empty string — present, not omitted, as the spec requires.
        for nth in [0, 1] {
            let (blob, _) = spec_example(HEADER_PAYMENT_RESPONSE, nth);
            let receipt = decode_receipt(&blob).expect("the spec's receipt decodes");
            assert_eq!(encode_receipt(&receipt), blob, "receipt example #{nth}");
        }
        let (blob, _) = spec_example(HEADER_PAYMENT_RESPONSE, 1);
        let failure = decode_receipt(&blob).unwrap();
        assert!(!failure.success);
        assert_eq!(failure.error_reason.as_deref(), Some("insufficient_funds"));
        assert_eq!(failure.transaction, "");
    }

    /// A real x402 v1 payment envelope, produced outside this codebase (`base64 -i` on
    /// `{"x402Version":1,"scheme":"exact","network":"test-network-not-a-real-caip2","payload":{"authorization":"opaque-to-phase-a"}}`)
    /// when obolus still spoke v1 — so it is v1's shape as a v1 codec wrote it, not our guess at it.
    const V1_PAYMENT_B64: &str = "eyJ4NDAyVmVyc2lvbiI6MSwic2NoZW1lIjoiZXhhY3QiLCJuZXR3b3JrIjoidGVzdC1uZXR3b3JrLW5vdC1hLXJlYWwtY2FpcDIiLCJwYXlsb2FkIjp7ImF1dGhvcml6YXRpb24iOiJvcGFxdWUtdG8tcGhhc2UtYSJ9fQ==";

    #[test]
    fn a_v1_payment_is_refused_as_version_1() {
        // A v1 envelope is refused by its version, not as malformed. This is the codec only: a v1
        // client sends `X-PAYMENT`, which the gateway does not read at all, so over HTTP it is
        // simply re-challenged (#73).
        let err = decode_payment(V1_PAYMENT_B64).unwrap_err();
        assert_eq!(err, CodecError::UnsupportedVersion { found: 1, expected: 2 });
        let bytes = super::super::decode_base64(V1_PAYMENT_B64).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap()["x402Version"], json!(1));
    }

    fn encoded(value: Value) -> String {
        super::super::BASE64.encode(value.to_string())
    }

    fn spec_payment() -> Value {
        spec_example(HEADER_PAYMENT_SIGNATURE, 0).1
    }

    #[test]
    fn a_payment_without_a_usable_version_is_malformed() {
        for version in [json!(null), json!("2"), json!(2.5), json!(-2), json!(258)] {
            let mut payment = spec_payment();
            payment["x402Version"] = version.clone();
            let err = decode_payment(&encoded(payment)).unwrap_err();
            assert!(matches!(err, CodecError::Json { .. }), "x402Version {version}: {err:?}");
        }
        let mut payment = spec_payment();
        payment.as_object_mut().unwrap().remove("x402Version");
        assert!(matches!(decode_payment(&encoded(payment)).unwrap_err(), CodecError::Json { .. }));
    }

    #[test]
    fn a_future_version_is_refused_by_number() {
        let mut payment = spec_payment();
        payment["x402Version"] = json!(3);
        let err = decode_payment(&encoded(payment)).unwrap_err();
        assert_eq!(err, CodecError::UnsupportedVersion { found: 3, expected: 2 });
    }

    #[test]
    fn a_payment_must_name_the_option_it_accepted() {
        let mut payment = spec_payment();
        payment.as_object_mut().unwrap().remove("accepted");
        assert!(matches!(decode_payment(&encoded(payment)).unwrap_err(), CodecError::Json { .. }));

        let mut payment = spec_payment();
        payment["accepted"].as_object_mut().unwrap().remove("amount");
        assert!(matches!(decode_payment(&encoded(payment)).unwrap_err(), CodecError::Json { .. }));
    }

    #[test]
    fn a_payment_whose_payload_is_missing_or_not_an_object_is_malformed() {
        // Missing is the case that matters: serde reads an absent `Value` field as `null`.
        let mut payment = spec_payment();
        payment.as_object_mut().unwrap().remove("payload");
        assert!(matches!(decode_payment(&encoded(payment)).unwrap_err(), CodecError::Json { .. }));
        for payload in [json!(null), json!("0xsig"), json!([1, 2])] {
            let mut payment = spec_payment();
            payment["payload"] = payload.clone();
            let err = decode_payment(&encoded(payment)).unwrap_err();
            assert!(matches!(err, CodecError::Json { .. }), "payload {payload}: {err:?}");
        }
    }

    #[test]
    fn a_challenge_of_another_version_is_refused() {
        let (_, mut challenge) = spec_example(HEADER_PAYMENT_REQUIRED, 0);
        challenge["x402Version"] = json!(1);
        let err = decode_payment_required(&encoded(challenge)).unwrap_err();
        assert_eq!(err, CodecError::UnsupportedVersion { found: 1, expected: 2 });
    }

    /// The spec's advertised option — the one its payment example accepted.
    fn offered() -> PaymentRequirements {
        let (blob, _) = spec_example(HEADER_PAYMENT_REQUIRED, 0);
        decode_payment_required(&blob).unwrap().accepts.remove(0)
    }

    /// The spec's payment, with `edit` applied to its `accepted`.
    fn paying(edit: impl FnOnce(&mut Value)) -> PaymentPayload {
        let mut payment = spec_payment();
        edit(&mut payment["accepted"]);
        decode_payment(&encoded(payment)).expect("still a well-formed payment")
    }

    #[test]
    fn the_spec_payment_is_accepted_by_the_spec_option() {
        assert!(offered().is_accepted_by(&paying(|_| {})));
    }

    #[test]
    fn a_payment_differing_in_any_core_field_is_not_for_this_option() {
        for (field, other) in [
            ("scheme", json!("upto")),
            ("network", json!("eip155:8453")),
            ("amount", json!("9999")),
            ("asset", json!("0x0000000000000000000000000000000000000001")),
            ("payTo", json!("0x0000000000000000000000000000000000000002")),
            ("maxTimeoutSeconds", json!(61)),
        ] {
            let payment = paying(|accepted| accepted[field] = other.clone());
            assert!(!offered().is_accepted_by(&payment), "{field} = {other} must not match");
        }
    }

    #[test]
    fn a_field_the_option_does_not_have_is_a_mismatch() {
        // Invisible to a typed comparison, which would drop the field before comparing.
        let payment = paying(|accepted| accepted["surprise"] = json!(true));
        assert!(!offered().is_accepted_by(&payment));
    }

    #[test]
    fn the_client_may_add_extra_keys_but_not_drop_or_change_ours() {
        let added = paying(|accepted| accepted["extra"]["assetTransferMethod"] = json!("eip3009"));
        assert!(offered().is_accepted_by(&added), "an added extra key is allowed");

        let dropped = paying(|accepted| {
            accepted["extra"].as_object_mut().unwrap().remove("version");
        });
        assert!(!offered().is_accepted_by(&dropped), "a dropped extra key is not");

        let changed = paying(|accepted| accepted["extra"]["name"] = json!("USD Coin"));
        assert!(!offered().is_accepted_by(&changed), "a changed extra value is not");

        let gone = paying(|accepted| {
            accepted.as_object_mut().unwrap().remove("extra");
        });
        assert!(!offered().is_accepted_by(&gone), "an option with extra needs the client's extra");
    }

    #[test]
    fn an_option_without_extra_accepts_any_client_extra() {
        let mut bare = offered();
        bare.extra = None;
        assert!(bare.is_accepted_by(&paying(|_| {})));
        assert!(bare.is_accepted_by(&paying(|accepted| {
            accepted.as_object_mut().unwrap().remove("extra");
        })));
    }

    #[test]
    fn extra_subsets_compare_nested_objects_key_by_key() {
        let mut nested = offered();
        nested.extra = Some(json!({ "name": "USDC", "domain": { "chainId": 84532 } }));
        let wider = paying(|accepted| {
            accepted["extra"] =
                json!({ "name": "USDC", "domain": { "chainId": 84532, "salt": "0x01" } });
        });
        assert!(nested.is_accepted_by(&wider));
        let different = paying(|accepted| {
            accepted["extra"] = json!({ "name": "USDC", "domain": { "chainId": 1 } });
        });
        assert!(!nested.is_accepted_by(&different));
        let flattened = paying(|accepted| {
            accepted["extra"] = json!({ "name": "USDC", "domain": "84532" });
        });
        assert!(!nested.is_accepted_by(&flattened));
    }

    #[test]
    fn a_client_built_payment_round_trips_and_matches_its_option() {
        let option = offered();
        let resource = ResourceInfo {
            url: "https://api.example.com/premium-data".to_string(),
            description: None,
            mime_type: None,
        };
        let payload = json!({ "signature": "0x00" }).as_object().unwrap().clone();
        let payment = PaymentPayload::new(Some(resource), option.clone(), payload);
        assert_eq!(payment.as_received()["x402Version"], json!(2));
        assert_eq!(payment.as_received()["resource"]["url"], json!("https://api.example.com/premium-data"));
        let decoded = decode_payment(&encode_payment(&payment)).unwrap();
        assert_eq!(decoded, payment);
        assert!(option.is_accepted_by(&decoded));
    }

    #[test]
    fn absent_optionals_are_omitted_not_null() {
        let mut option = offered();
        option.extra = None;
        let challenge = PaymentRequired::offering_all(
            ResourceInfo { url: "http://127.0.0.1/x".to_string(), description: None, mime_type: None },
            vec![option],
        );
        let json = serde_json::to_value(&challenge).unwrap();
        assert!(json.get("error").is_none());
        assert!(json["resource"].get("description").is_none());
        assert!(json["resource"].get("mimeType").is_none());
        assert!(json["accepts"][0].get("extra").is_none());
        assert_eq!(json["x402Version"], json!(2));
        assert_eq!(challenge.with_error("expired").error.as_deref(), Some("expired"));
    }
}
