//! The settlement seam — the one interface Phase A and Phase B share.
//!
//! Phase A ships [`FakeFacilitator`] (hermetic, per-PR CI) and, at A3, a delegating
//! implementation that forwards `verify` / `settle` to a third-party facilitator over HTTP
//! (exercised only by the post-merge cron e2e). Phase B adds a self-settling implementation
//! that verifies the authorization and submits on-chain itself. The gateway above this trait
//! is identical across all three — that is the entire point of the seam.

use std::future::Future;
// Used only by the test-only fakes below and the test module; gated so the `obolus` binary,
// compiled without `cfg(test)`, carries neither the imports nor the fakes that need them.
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{header::CONTENT_TYPE, Request, StatusCode};
use http_body_util::Full;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};

use crate::x402::{PaymentPayload, PaymentRequirements, SettlementReceipt};

/// Why a facilitator did not complete a payment.
///
/// The split is load-bearing, not cosmetic: [`Rejected`](FacilitatorError::Rejected) is the
/// client's problem and earns another 402, while
/// [`Unavailable`](FacilitatorError::Unavailable) is *our* problem and must not be dressed up
/// as "your payment was bad". Collapsing the two would teach clients to retry payments that
/// were never actually evaluated.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum FacilitatorError {
    /// Well-formed but not acceptable: bad signature, insufficient funds, expired
    /// authorization, wrong recipient.
    #[error("payment rejected: {0}")]
    Rejected(String),
    /// We could not reach or understand the facilitator.
    #[error("facilitator unavailable: {0}")]
    Unavailable(String),
}

/// Verify a payment authorization, then collect on it.
pub trait Facilitator: Send + Sync + 'static {
    /// Is this payment good? Must not move funds.
    fn verify(
        &self,
        payment: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> impl Future<Output = Result<(), FacilitatorError>> + Send;

    /// Collect the payment, returning the receipt we hand back in `X-PAYMENT-RESPONSE`.
    fn settle(
        &self,
        payment: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> impl Future<Output = Result<SettlementReceipt, FacilitatorError>> + Send;
}

/// What a [`FakeFacilitator`] should pretend happened.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub enum FakeOutcome {
    /// Verify and settle both succeed.
    Accept,
    /// Verify rejects with this reason.
    Reject(String),
    /// Verify fails as an infrastructure problem.
    Unavailable(String),
    /// Verify succeeds but settlement is then unreachable — the awkward middle case that
    /// decides whether we charge for work we already started.
    AcceptThenFailSettlement(String),
    /// Verify succeeds but settlement is *refused* — a payment that looked good and then was
    /// not. Distinct from [`AcceptThenFailSettlement`](FakeOutcome::AcceptThenFailSettlement)
    /// because the client's next move differs: refused is theirs to fix, unreachable is ours.
    AcceptThenRejectSettlement(String),
    /// Verify succeeds and settlement returns `Ok` — carrying `success: false`. The shape that
    /// catches a gateway which trusts the `Result` and never reads the receipt.
    AcceptThenUnsuccessfulReceipt,
}

/// An in-process facilitator for hermetic tests and local development.
///
/// # This is a fast-iteration device, never a gate
///
/// We author both the client signer and this verifier. "My fake accepted my payment" is
/// therefore worth nothing as evidence — a shared misunderstanding of the EIP-712 domain
/// separator or the `transferWithAuthorization` struct hash makes both sides agree with each
/// other while a real facilitator still rejects. It is an in-distribution pass.
///
/// The load-bearing checks live elsewhere, and deliberately outside our own authorship: the
/// published EIP-3009 / EIP-712 known-answer vector (offline, hermetic) and the post-merge
/// cron settle against a third-party facilitator. Nothing in this file may ever become the
/// thing that decides whether the signer is correct.
///
/// Note that it does not inspect `payment` at all — it *cannot*, because Phase A keeps the
/// payload opaque. It exists to drive the gateway's control flow, not to judge payments.
///
/// Gated to `cfg(test)`: the `obolus` binary compiles the library without `cfg(test)`, so this
/// accept-anything facilitator is physically absent from it (#17) — no configuration path
/// can select it, because it does not exist to select. The compiler is the enforcement.
#[cfg(test)]
pub struct FakeFacilitator {
    outcome: FakeOutcome,
    transaction: String,
    calls: FakeCalls,
}

/// An observation handle on a [`FakeFacilitator`], still readable after the facilitator has
/// been moved into a gateway.
///
/// This exists because "we did not charge" is not observable from the response: a gateway that
/// settled eagerly and *then* hit an upstream error would return the same status and the same
/// absent receipt header as one that correctly never charged. Asserting on the response alone
/// would pass either way, so the no-charge tests assert on this instead.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct FakeCalls {
    verifies: Arc<AtomicUsize>,
    settles: Arc<AtomicUsize>,
    /// The requirement handed to each `verify` / `settle` call, in order. Counts alone cannot
    /// answer the money-critical multi-chain question — *which* advertised option did we settle
    /// against? — because a gateway that settled against the wrong option returns the same status
    /// and receipt as one that settled against the right one. The requirement is the only thing
    /// that distinguishes right-asset from wrong-asset settlement, and (like the no-charge case)
    /// it is invisible in the response, so it is recorded here.
    verified: Arc<std::sync::Mutex<Vec<PaymentRequirements>>>,
    settled: Arc<std::sync::Mutex<Vec<PaymentRequirements>>>,
}

#[cfg(test)]
impl FakeCalls {
    /// How many times `verify` was called.
    pub fn verifies(&self) -> usize {
        self.verifies.load(Ordering::SeqCst)
    }

    /// How many times `settle` was called — i.e. how many times we tried to take money.
    pub fn settles(&self) -> usize {
        self.settles.load(Ordering::SeqCst)
    }

    /// The requirements handed to `verify`, in call order.
    pub fn verified_requirements(&self) -> Vec<PaymentRequirements> {
        self.verified.lock().unwrap().clone()
    }

    /// The requirements handed to `settle`, in call order — i.e. *what* we tried to charge for.
    pub fn settled_requirements(&self) -> Vec<PaymentRequirements> {
        self.settled.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl FakeFacilitator {
    pub fn new(outcome: FakeOutcome) -> Self {
        Self {
            outcome,
            transaction: "0xTEST-TX-HASH-NOT-A-REAL-TRANSACTION".to_string(),
            calls: FakeCalls::default(),
        }
    }

    /// A handle for asserting what this facilitator was asked to do.
    pub fn calls(&self) -> FakeCalls {
        self.calls.clone()
    }

    pub fn accepting() -> Self {
        Self::new(FakeOutcome::Accept)
    }

    pub fn rejecting(reason: impl Into<String>) -> Self {
        Self::new(FakeOutcome::Reject(reason.into()))
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::new(FakeOutcome::Unavailable(reason.into()))
    }

    pub fn failing_settlement(reason: impl Into<String>) -> Self {
        Self::new(FakeOutcome::AcceptThenFailSettlement(reason.into()))
    }

    pub fn rejecting_settlement(reason: impl Into<String>) -> Self {
        Self::new(FakeOutcome::AcceptThenRejectSettlement(reason.into()))
    }

    pub fn returning_unsuccessful_receipt() -> Self {
        Self::new(FakeOutcome::AcceptThenUnsuccessfulReceipt)
    }
}

#[cfg(test)]
impl Facilitator for FakeFacilitator {
    async fn verify(
        &self,
        _payment: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<(), FacilitatorError> {
        self.calls.verifies.fetch_add(1, Ordering::SeqCst);
        self.calls.verified.lock().unwrap().push(requirements.clone());
        match &self.outcome {
            FakeOutcome::Accept
            | FakeOutcome::AcceptThenFailSettlement(_)
            | FakeOutcome::AcceptThenRejectSettlement(_)
            | FakeOutcome::AcceptThenUnsuccessfulReceipt => Ok(()),
            FakeOutcome::Reject(reason) => Err(FacilitatorError::Rejected(reason.clone())),
            FakeOutcome::Unavailable(reason) => Err(FacilitatorError::Unavailable(reason.clone())),
        }
    }

    async fn settle(
        &self,
        payment: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<SettlementReceipt, FacilitatorError> {
        self.calls.settles.fetch_add(1, Ordering::SeqCst);
        self.calls.settled.lock().unwrap().push(requirements.clone());
        match &self.outcome {
            FakeOutcome::Accept => Ok(SettlementReceipt {
                success: true,
                transaction: Some(self.transaction.clone()),
                network: payment.network.clone(),
                payer: None,
            }),
            FakeOutcome::AcceptThenFailSettlement(reason) => {
                Err(FacilitatorError::Unavailable(reason.clone()))
            }
            FakeOutcome::AcceptThenRejectSettlement(reason) => {
                Err(FacilitatorError::Rejected(reason.clone()))
            }
            FakeOutcome::AcceptThenUnsuccessfulReceipt => Ok(SettlementReceipt {
                success: false,
                transaction: None,
                network: payment.network.clone(),
                payer: None,
            }),
            FakeOutcome::Reject(reason) => Err(FacilitatorError::Rejected(reason.clone())),
            FakeOutcome::Unavailable(reason) => Err(FacilitatorError::Unavailable(reason.clone())),
        }
    }
}

/// Facilitator responses are small JSON documents; cap what we read so a misbehaving endpoint
/// cannot make us buffer without bound. Generous next to a real verify/settle response.
const MAX_FACILITATOR_RESPONSE_BYTES: usize = 64 * 1024;

/// How long we wait for one facilitator call before treating it as unavailable. Settlement can
/// legitimately block while the facilitator waits for an on-chain receipt, so this is generous.
const DEFAULT_FACILITATOR_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest facilitator-supplied reason we echo verbatim into a client-facing 402. A real
/// closed-enum reason (`insufficient_funds`, …) is far shorter; anything longer is treated as
/// untrustworthy and replaced with the generic, so a hostile or MITM'd facilitator on the
/// (currently un-TLS'd) channel cannot reflect bulk content into our response body.
const MAX_REJECT_REASON_LEN: usize = 128;

/// Why a [`DelegatedFacilitator`] could not be constructed. Both variants are base-URL problems
/// caught at construction, where the cause is legible, rather than surfaced later as a connect-time
/// "facilitator unavailable" once the URL has reached config.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum DelegatedFacilitatorError {
    /// The base URL is `https://`, but Phase A has no TLS client wired. TLS enters at the connector
    /// when the live rail is built; until then this type speaks plain HTTP only (a loopback in
    /// tests, a local facilitator otherwise).
    #[error(
        "facilitator base URL {0:?} uses https, but Obolus Phase A has no TLS client wired yet; \
         use an http:// endpoint until the live rail adds TLS"
    )]
    TlsNotWired(String),

    /// The base URL is not an `http://` endpoint (a schemeless or other-scheme base). We build
    /// request URLs by string concatenation and speak only plain HTTP, so an explicit `http://`
    /// base is required.
    #[error("facilitator base URL {0:?} is not an http:// endpoint")]
    NotAnHttpBase(String),
}

/// The body both `/verify` and `/settle` take; this wrapper only adds the top-level `x402Version`.
///
/// The legacy facilitator *type* omits `x402Version` at this level, but every reference
/// implementation puts it on the wire — so we send it, trusting the wire over the stale type.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FacilitatorRequest<'a> {
    x402_version: u8,
    payment_payload: &'a PaymentPayload,
    payment_requirements: &'a PaymentRequirements,
}

/// The `/verify` response. Every field is optional on the wire: only `isValid` is load-bearing,
/// and a response missing even that is an ambiguity we report as unavailable, never a rejection.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyResponse {
    #[serde(default)]
    is_valid: Option<bool>,
    #[serde(default)]
    invalid_reason: Option<String>,
}

/// The `/settle` response. `success` is the *sole* authority on whether funds moved: a reverted
/// on-chain settlement comes back with a real `transaction` hash *and* `success: false`, so we
/// must never infer settlement from a transaction being present. `transaction` / `network` are
/// plain strings, not enums — the live facilitator returns network identifiers a closed enum would
/// fail to parse.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettleResponse {
    #[serde(default)]
    success: Option<bool>,
    #[serde(default)]
    error_reason: Option<String>,
    #[serde(default)]
    payer: Option<String>,
    #[serde(default)]
    transaction: Option<String>,
    #[serde(default)]
    network: Option<String>,
}

/// A [`Facilitator`] that delegates `verify` and `settle` to a third-party x402 facilitator over
/// HTTP.
///
/// Phase A carries no cryptography: the inner authorization stays opaque (see [`crate::x402`]), and
/// this type only frames the `{x402Version, paymentPayload, paymentRequirements}` envelope, POSTs
/// it, and maps the facilitator's verdict onto the [`FacilitatorError`] split. Two rules do the
/// load-bearing work:
///
/// * **The response body is parsed before its HTTP status is trusted.** A conforming facilitator
///   returns a full `{"success":false,"errorReason":…}` document even on `HTTP 400`; a client that
///   bailed on the status first would discard the reason and could retry a settlement that had
///   already broadcast.
/// * **Only an explicit, parsed refusal becomes [`Rejected`](FacilitatorError::Rejected).** A
///   timeout, a dropped connection, an unreadable body, or a body carrying no verdict is
///   [`Unavailable`](FacilitatorError::Unavailable) — a payment we never managed to evaluate must
///   not reach the client as "your payment was bad".
///
/// It speaks plain HTTP only; see [`DelegatedFacilitatorError::TlsNotWired`].
#[derive(Debug)]
pub struct DelegatedFacilitator {
    verify_url: String,
    settle_url: String,
    client: Client<HttpConnector, Full<Bytes>>,
    timeout: Duration,
}

impl DelegatedFacilitator {
    /// Build a client for the facilitator rooted at `base_url` — which carries a path
    /// (e.g. `http://host:8402/facilitator`), so `/verify` and `/settle` are appended to it, not to
    /// the origin. A trailing slash is trimmed so a hand-entered `…/facilitator/` does not become
    /// `…/facilitator//verify`.
    ///
    /// Rejects an `https://` base — see [`DelegatedFacilitatorError::TlsNotWired`].
    pub fn new(base_url: impl Into<String>) -> Result<Self, DelegatedFacilitatorError> {
        let base = base_url.into();
        let base = base.trim_end_matches('/');
        // Allowlist the scheme case-insensitively. A case-sensitive `https://` denylist would wave
        // through `HTTPS://…` and schemeless bases, defeating the guard.
        let lowered = base.to_ascii_lowercase();
        if lowered.starts_with("https://") {
            return Err(DelegatedFacilitatorError::TlsNotWired(base.to_string()));
        }
        if !lowered.starts_with("http://") {
            return Err(DelegatedFacilitatorError::NotAnHttpBase(base.to_string()));
        }
        Ok(Self {
            verify_url: format!("{base}/verify"),
            settle_url: format!("{base}/settle"),
            // A pooled connection that fails the instant we hand it a request would, by default, be
            // silently retried — re-sending POST /settle and risking a double settlement. Disable
            // the retry so the failure surfaces as `Unavailable` instead (see #31).
            client: Client::builder(TokioExecutor::new())
                .retry_canceled_requests(false)
                .build_http::<Full<Bytes>>(),
            timeout: DEFAULT_FACILITATOR_TIMEOUT,
        })
    }

    /// Override the per-call timeout. Tests use it to exercise the timeout path without waiting the
    /// default; the live rail may also tune it.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// POST the shared envelope to `url` and return the response status and body, reading the body
    /// regardless of status. Every failure to *complete* the round-trip — encode, connect, time
    /// out, read — is [`Unavailable`](FacilitatorError::Unavailable): we could not evaluate the
    /// payment, so it is our problem. Its detail is safe to keep here (the gateway logs it and
    /// shows the client a generic message) but must never leak into a
    /// [`Rejected`](FacilitatorError::Rejected) reason.
    async fn round_trip(
        &self,
        url: &str,
        endpoint: &str,
        payment: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<(StatusCode, Bytes), FacilitatorError> {
        let envelope = FacilitatorRequest {
            x402_version: payment.x402_version,
            payment_payload: payment,
            payment_requirements: requirements,
        };
        let body = serde_json::to_vec(&envelope).map_err(|e| {
            FacilitatorError::Unavailable(format!(
                "could not encode facilitator /{endpoint} request: {e}"
            ))
        })?;
        let request = Request::post(url)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| {
                FacilitatorError::Unavailable(format!(
                    "could not build facilitator /{endpoint} request: {e}"
                ))
            })?;

        // One deadline over the WHOLE round-trip — the request AND the body read. Wrapping only
        // `client.request` would bound the wait for the response *head* but leave the body read
        // unbounded, so a facilitator that sends headers and then stalls the body would wedge a
        // settle forever (an indeterminate "may have charged" hang, and a trivial DoS lever over the
        // deliberately-plaintext channel). The 64KB cap does not help — an untimed slow dribble
        // stays under it.
        let round_trip = async {
            let response = self.client.request(request).await.map_err(|e| {
                FacilitatorError::Unavailable(format!(
                    "could not reach facilitator /{endpoint}: {e}"
                ))
            })?;
            let (parts, incoming) = response.into_parts();
            let status = parts.status;
            let bytes = axum::body::to_bytes(Body::new(incoming), MAX_FACILITATOR_RESPONSE_BYTES)
                .await
                .map_err(|e| {
                    FacilitatorError::Unavailable(format!(
                        "could not read facilitator /{endpoint} response (status {status}): {e}"
                    ))
                })?;
            Ok::<(StatusCode, Bytes), FacilitatorError>((status, bytes))
        };
        match tokio::time::timeout(self.timeout, round_trip).await {
            Err(_elapsed) => Err(FacilitatorError::Unavailable(format!(
                "facilitator /{endpoint} did not complete within {:?}",
                self.timeout
            ))),
            Ok(result) => result,
        }
    }
}

impl Facilitator for DelegatedFacilitator {
    async fn verify(
        &self,
        payment: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<(), FacilitatorError> {
        let (status, bytes) =
            self.round_trip(&self.verify_url, "verify", payment, requirements).await?;
        // Only a 2xx or 4xx is an authoritative verdict: the facilitator evaluated the payment
        // (accepted it, or refused it for a client-side reason). A 5xx — or a 1xx/3xx — means it
        // failed before reaching a verdict, so we do not read a verdict out of its body: trusting one
        // would let a 5xx `isValid:true` wave a payment through (free inference) and a 5xx
        // `isValid:false` blame the client for the facilitator's outage.
        if !status.is_success() && !status.is_client_error() {
            return Err(FacilitatorError::Unavailable(format!(
                "facilitator /verify returned non-verdict status {status}"
            )));
        }
        let parsed: VerifyResponse = serde_json::from_slice(&bytes).map_err(|e| {
            FacilitatorError::Unavailable(format!(
                "facilitator /verify returned an unparseable body (status {status}): {e}"
            ))
        })?;
        match parsed.is_valid {
            Some(true) => Ok(()),
            // A parsed "no" on a verdict-bearing status: the client's authorization is bad. Surface
            // the facilitator's own reason (bounded by `reject_reason` — an unvalidated string, not a
            // guaranteed closed enum); never our status/URL/body detail.
            Some(false) => Err(FacilitatorError::Rejected(reject_reason(
                parsed.invalid_reason.as_deref(),
                "payment verification failed",
            ))),
            // Parsed, but no verdict. Not a rejection: a payment we could not evaluate must not come
            // back as 402, or the client re-signs an authorization that was fine all along.
            None => Err(FacilitatorError::Unavailable(format!(
                "facilitator /verify body carried no isValid field (status {status})"
            ))),
        }
    }

    async fn settle(
        &self,
        payment: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<SettlementReceipt, FacilitatorError> {
        let (status, bytes) =
            self.round_trip(&self.settle_url, "settle", payment, requirements).await?;
        // As in verify: only a 2xx or 4xx carries an authoritative verdict. A 5xx (or 1xx/3xx) is a
        // facilitator failure, not a settlement outcome — a `success` field on that path is noise. A
        // 5xx `success:true` must NOT build a receipt (we would serve a paid answer for a settlement
        // that never happened); a 5xx `success:false` is our outage, not the client's 402. Only the
        // status is logged — the untrusted body is left for A3 structured logging to capture safely.
        if !status.is_success() && !status.is_client_error() {
            return Err(FacilitatorError::Unavailable(format!(
                "facilitator /settle returned non-verdict status {status}"
            )));
        }
        let parsed: SettleResponse = serde_json::from_slice(&bytes).map_err(|e| {
            FacilitatorError::Unavailable(format!(
                "facilitator /settle returned an unparseable body (status {status}): {e}"
            ))
        })?;
        match parsed.success {
            // `success` is the sole authority — build the receipt ourselves rather than deserialize
            // the domain type, normalizing "" to absent and filling the network from the payment
            // when the facilitator omits it.
            Some(true) => Ok(SettlementReceipt {
                success: true,
                transaction: non_empty(parsed.transaction),
                network: non_empty(parsed.network).unwrap_or_else(|| payment.network.clone()),
                payer: non_empty(parsed.payer),
            }),
            // A definite non-settlement: a pre-broadcast refusal (`transaction: ""`) or an on-chain
            // revert (a real hash, but reverted — no funds moved). Either way the payer was not
            // charged, so it is the client's 402 to retry, carrying the facilitator's own reason
            // (bounded by `reject_reason`).
            //
            // KNOWN GAP — `errorReason == "duplicate_settlement"` means this authorization already
            // settled on a prior call, so money *did* move; neither 402 nor 502 is right for it. Its
            // real handling is the A3 payment-keyed idempotency cache short-circuiting it to the
            // cached receipt, and the fail-open-vs-terminal policy is Christian's call (#17).
            // Until that lands it folds into this default; it is deliberately not special-cased.
            Some(false) => Err(FacilitatorError::Rejected(reject_reason(
                parsed.error_reason.as_deref(),
                "settlement did not complete",
            ))),
            // Parsed, but no verdict — we cannot tell whether funds moved, so it is our problem, not
            // a rejection the client should retry as a fresh payment.
            None => Err(FacilitatorError::Unavailable(format!(
                "facilitator /settle body carried no success field (status {status})"
            ))),
        }
    }
}

/// Normalize an optional wire string, treating `""` as absent — the facilitator uses the empty
/// string, not omission, for "no payer" and "no transaction broadcast".
fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|s| !s.is_empty())
}

/// The reason handed back on a rejection, echoed to the unauthenticated caller in the 402 body.
/// The facilitator's reason is unvalidated, so we surface it only when present and within
/// [`MAX_REJECT_REASON_LEN`], otherwise a fixed generic. Never includes our transport detail
/// (status/URL/body) — that lives only in [`Unavailable`](FacilitatorError::Unavailable).
fn reject_reason(reason: Option<&str>, fallback: &str) -> String {
    match reason {
        Some(reason) if !reason.is_empty() && reason.len() <= MAX_REJECT_REASON_LEN => {
            reason.to_string()
        }
        _ => fallback.to_string(),
    }
}

#[cfg(test)]
mod delegated_tests {
    use super::*;

    use std::sync::Mutex;

    use axum::extract::State;
    use axum::response::Response;
    use axum::routing::post;
    use axum::Router;
    use futures_util::StreamExt;
    use serde_json::{json, Value};
    use tokio::net::TcpListener;

    use crate::x402::{SCHEME_EXACT, X402_VERSION};

    // Obviously-synthetic fixtures — never real identifiers.
    const FIXTURE_NETWORK: &str = "test-network-not-a-real-caip2";
    const FIXTURE_PAY_TO: &str = "0xTEST-PAY-TO-ADDRESS-NOT-REAL";
    const FIXTURE_ASSET: &str = "0xTEST-ASSET-ADDRESS-NOT-REAL";

    fn payment() -> PaymentPayload {
        PaymentPayload {
            x402_version: X402_VERSION,
            scheme: SCHEME_EXACT.to_string(),
            network: FIXTURE_NETWORK.to_string(),
            payload: json!({ "authorization": "opaque-to-phase-a" }),
        }
    }

    fn requirements() -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: FIXTURE_NETWORK.to_string(),
            max_amount_required: "1000".to_string(),
            resource: "http://127.0.0.1:8402/v1/chat/completions".to_string(),
            description: "One inference request".to_string(),
            mime_type: "application/json".to_string(),
            pay_to: FIXTURE_PAY_TO.to_string(),
            max_timeout_seconds: 60,
            asset: FIXTURE_ASSET.to_string(),
            extra: None,
        }
    }

    // Byte-exact response fixtures, field names and example values copied verbatim from the x402 v1
    // spec §7.1/§7.2 (whitespace normalized). They are an out-of-distribution oracle for our wire
    // types: rename a field and these stop mapping. Threaded through the real HTTP path below as the
    // mock's canned bodies rather than parsed in isolation.
    // https://github.com/coinbase/x402/blob/main/specs/x402-specification-v1.md
    const SPEC_VERIFY_SUCCESS: &str =
        r#"{"isValid":true,"payer":"0x857b06519E91e3A54538791bDbb0E22373e36b66"}"#;
    const SPEC_VERIFY_ERROR: &str = r#"{"isValid":false,"invalidReason":"insufficient_funds","payer":"0x857b06519E91e3A54538791bDbb0E22373e36b66"}"#;
    const SPEC_SETTLE_SUCCESS: &str = r#"{"success":true,"payer":"0x857b06519E91e3A54538791bDbb0E22373e36b66","transaction":"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef","network":"base-sepolia"}"#;
    const SPEC_SETTLE_ERROR: &str = r#"{"success":false,"errorReason":"insufficient_funds","payer":"0x857b06519E91e3A54538791bDbb0E22373e36b66","transaction":"","network":"base-sepolia"}"#;

    /// One canned facilitator response: a status, a body, and an optional delay so a test can make
    /// the endpoint hang past the client's timeout.
    struct Canned {
        status: StatusCode,
        body: String,
        delay: Option<Duration>,
    }

    impl Canned {
        fn ok(body: &str) -> Self {
            Self { status: StatusCode::OK, body: body.to_string(), delay: None }
        }
        fn status(status: StatusCode, body: &str) -> Self {
            Self { status, body: body.to_string(), delay: None }
        }
        fn hanging(delay: Duration) -> Self {
            Self { status: StatusCode::OK, body: String::new(), delay: Some(delay) }
        }
    }

    #[derive(Clone)]
    struct MockState {
        verify: Arc<Canned>,
        settle: Arc<Canned>,
        captured: Arc<Mutex<Vec<(&'static str, Value)>>>,
    }

    async fn verify_handler(State(state): State<MockState>, body: Bytes) -> (StatusCode, String) {
        state.captured.lock().unwrap().push(("verify", serde_json::from_slice(&body).unwrap_or(Value::Null)));
        reply(&state.verify).await
    }

    async fn settle_handler(State(state): State<MockState>, body: Bytes) -> (StatusCode, String) {
        state.captured.lock().unwrap().push(("settle", serde_json::from_slice(&body).unwrap_or(Value::Null)));
        reply(&state.settle).await
    }

    async fn reply(canned: &Canned) -> (StatusCode, String) {
        if let Some(delay) = canned.delay {
            tokio::time::sleep(delay).await;
        }
        (canned.status, canned.body.clone())
    }

    /// Serve a mock facilitator under a `/facilitator` path prefix — the real base carries a path,
    /// so this exercises `{base}/verify` rather than an origin-rooted `/verify`. Returns the base
    /// URL (including the path) and the capture log.
    async fn serve(
        verify: Canned,
        settle: Canned,
    ) -> (String, Arc<Mutex<Vec<(&'static str, Value)>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            verify: Arc::new(verify),
            settle: Arc::new(settle),
            captured: captured.clone(),
        };
        let app = Router::new()
            .route("/facilitator/verify", post(verify_handler))
            .route("/facilitator/settle", post(settle_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}/facilitator"), captured)
    }

    /// The canned response for the endpoint a test does not exercise. Deliberately not a valid
    /// verify *or* settle verdict, and served as a 500, so a misroute (settle reaching the verify
    /// URL or vice versa) surfaces as an obvious "wrong endpoint" rather than a plausible-looking
    /// ambiguous-body failure.
    fn unused() -> Canned {
        Canned::status(
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"unused":"endpoint not exercised by this test"}"#,
        )
    }

    // --- construction ------------------------------------------------------------------------

    #[test]
    fn new_rejects_an_https_base_because_no_tls_is_wired() {
        let err = DelegatedFacilitator::new("https://x402.org/facilitator").unwrap_err();
        assert!(matches!(err, DelegatedFacilitatorError::TlsNotWired(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn new_tolerates_a_trailing_slash_on_the_base() {
        // If `new` stopped trimming, the URL would be `…/facilitator//verify`, which the mock's
        // route would not match — so this plain accept would fail instead of passing.
        let (base, _captured) = serve(Canned::ok(SPEC_VERIFY_SUCCESS), unused()).await;
        let facilitator = DelegatedFacilitator::new(format!("{base}/")).unwrap();
        assert_eq!(facilitator.verify(&payment(), &requirements()).await, Ok(()));
    }

    // --- verify ------------------------------------------------------------------------------

    #[tokio::test]
    async fn verify_accepts_and_sends_the_shared_envelope() {
        let (base, captured) = serve(Canned::ok(SPEC_VERIFY_SUCCESS), unused()).await;
        let facilitator = DelegatedFacilitator::new(base).unwrap();

        assert_eq!(facilitator.verify(&payment(), &requirements()).await, Ok(()));

        // The request the facilitator received is the {x402Version, paymentPayload,
        // paymentRequirements} envelope, camelCased end to end.
        let log = captured.lock().unwrap();
        assert_eq!(log.len(), 1);
        let (endpoint, body) = &log[0];
        assert_eq!(*endpoint, "verify");
        assert_eq!(body["x402Version"], json!(X402_VERSION));
        assert_eq!(body["paymentPayload"]["scheme"], json!("exact"));
        assert_eq!(body["paymentPayload"]["network"], json!(FIXTURE_NETWORK));
        assert_eq!(body["paymentPayload"]["payload"]["authorization"], json!("opaque-to-phase-a"));
        assert_eq!(body["paymentRequirements"]["payTo"], json!(FIXTURE_PAY_TO));
        assert_eq!(body["paymentRequirements"]["maxAmountRequired"], json!("1000"));
        assert_eq!(body["paymentRequirements"]["maxTimeoutSeconds"], json!(60));
    }

    #[tokio::test]
    async fn verify_rejects_on_is_valid_false_with_the_facilitators_reason() {
        let (base, _c) = serve(Canned::ok(SPEC_VERIFY_ERROR), unused()).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .verify(&payment(), &requirements())
            .await
            .unwrap_err();
        assert_eq!(err, FacilitatorError::Rejected("insufficient_funds".to_string()));
    }

    #[tokio::test]
    async fn verify_parses_the_body_before_trusting_the_status() {
        // Discriminating pair with verify_without_a_verdict_is_unavailable_not_rejected (a 200 whose
        // body carries no verdict → Unavailable): here a 400 whose body DOES carry a verdict must map
        // to Rejected. A status-first client (Unavailable on any non-2xx, before reading the body)
        // would instead turn this into Unavailable and fail the assertion below. The two together pin
        // that the verdict comes from the parsed body, not the HTTP status.
        let (base, _c) =
            serve(Canned::status(StatusCode::BAD_REQUEST, SPEC_VERIFY_ERROR), unused()).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .verify(&payment(), &requirements())
            .await
            .unwrap_err();
        assert_eq!(err, FacilitatorError::Rejected("insufficient_funds".to_string()));
    }

    #[tokio::test]
    async fn verify_without_a_verdict_is_unavailable_not_rejected() {
        let (base, _c) = serve(Canned::ok(r#"{"payer":"0x0"}"#), unused()).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .verify(&payment(), &requirements())
            .await
            .unwrap_err();
        assert!(matches!(err, FacilitatorError::Unavailable(_)), "got {err:?}");
    }

    // --- settle ------------------------------------------------------------------------------

    #[tokio::test]
    async fn settle_succeeds_and_builds_the_receipt_from_the_wire() {
        let (base, captured) = serve(unused(), Canned::ok(SPEC_SETTLE_SUCCESS)).await;
        let receipt = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap();
        assert_eq!(
            receipt,
            SettlementReceipt {
                success: true,
                transaction: Some(
                    "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string()
                ),
                network: "base-sepolia".to_string(),
                payer: Some("0x857b06519E91e3A54538791bDbb0E22373e36b66".to_string()),
            }
        );
        assert_eq!(captured.lock().unwrap().len(), 1, "settle was called exactly once");
    }

    #[tokio::test]
    async fn settle_normalizes_empty_payer_and_fills_missing_network_from_the_payment() {
        let body = r#"{"success":true,"transaction":"0xabc","payer":"","network":""}"#;
        let (base, _c) = serve(unused(), Canned::ok(body)).await;
        let receipt = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap();
        assert_eq!(receipt.payer, None, "an empty payer is absent, not \"\"");
        assert_eq!(receipt.network, FIXTURE_NETWORK, "empty network falls back to the payment's");
        assert_eq!(receipt.transaction.as_deref(), Some("0xabc"));
    }

    #[tokio::test]
    async fn settle_rejects_on_success_false_with_the_facilitators_reason() {
        let (base, _c) = serve(unused(), Canned::ok(SPEC_SETTLE_ERROR)).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap_err();
        assert_eq!(err, FacilitatorError::Rejected("insufficient_funds".to_string()));
    }

    #[tokio::test]
    async fn a_reverted_settlement_is_rejected_not_treated_as_settled() {
        // The dangerous shape: success:false but a real, non-empty transaction hash (an on-chain
        // revert). `success` is the sole authority, so this must be a rejection — a client keying on
        // the transaction's presence would wrongly believe it settled.
        let body = r#"{"success":false,"errorReason":"invalid_transaction_state","transaction":"0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef","network":"base-sepolia"}"#;
        let (base, _c) = serve(unused(), Canned::ok(body)).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap_err();
        assert_eq!(err, FacilitatorError::Rejected("invalid_transaction_state".to_string()));
    }

    #[tokio::test]
    async fn settle_parses_the_body_before_trusting_the_status() {
        // Discriminating twin of verify_parses_the_body_before_trusting_the_status: a 400 carrying a
        // structured settle verdict must be Rejected, not Unavailable. Paired with the no-verdict /
        // unparseable-body settle tests (Unavailable even at 200), this pins that we key on the parsed
        // `success`, not the HTTP status.
        let (base, _c) =
            serve(unused(), Canned::status(StatusCode::BAD_REQUEST, SPEC_SETTLE_ERROR)).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap_err();
        assert_eq!(err, FacilitatorError::Rejected("insufficient_funds".to_string()));
    }

    #[tokio::test]
    async fn settle_duplicate_settlement_folds_into_rejected_for_now() {
        // Pins the CURRENT behavior and its comment: `duplicate_settlement` is not special-cased in
        // Phase A — its real handling (serve the cached receipt) is the A3 idempotency cache, and
        // the fail-open-vs-terminal policy is Christian's call (#17).
        let body = r#"{"success":false,"errorReason":"duplicate_settlement","transaction":"","network":"base-sepolia"}"#;
        let (base, _c) = serve(unused(), Canned::ok(body)).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap_err();
        assert_eq!(err, FacilitatorError::Rejected("duplicate_settlement".to_string()));
    }

    #[tokio::test]
    async fn settle_without_a_verdict_is_unavailable() {
        // A body that parses but carries no `success` field: we cannot tell whether funds moved, so
        // it is our problem (502), never a 402 the client retries as a fresh payment.
        let (base, _c) = serve(unused(), Canned::ok(r#"{"network":"base-sepolia"}"#)).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap_err();
        assert!(matches!(err, FacilitatorError::Unavailable(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn settle_with_an_unparseable_body_is_unavailable() {
        let (base, _c) = serve(unused(), Canned::ok("this is not json")).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap_err();
        assert!(matches!(err, FacilitatorError::Unavailable(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn settle_that_times_out_is_unavailable() {
        // The mock holds the response past the client's timeout; a timed-out settle is ambiguous
        // (funds may have moved), so it is unavailable, never a rejection.
        let (base, _c) = serve(unused(), Canned::hanging(Duration::from_secs(10))).await;
        let facilitator =
            DelegatedFacilitator::new(base).unwrap().with_timeout(Duration::from_millis(50));
        let err = facilitator.settle(&payment(), &requirements()).await.unwrap_err();
        assert!(matches!(err, FacilitatorError::Unavailable(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn an_unreachable_facilitator_is_unavailable() {
        // Bind then drop to hand back a port that now refuses connections.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = listener.local_addr().unwrap();
        drop(listener);
        let facilitator = DelegatedFacilitator::new(format!("http://{dead}/facilitator")).unwrap();
        let err = facilitator.settle(&payment(), &requirements()).await.unwrap_err();
        assert!(matches!(err, FacilitatorError::Unavailable(_)), "got {err:?}");
    }

    // --- status-class authority (only 2xx/4xx are verdicts; 5xx is a facilitator failure) --------

    #[tokio::test]
    async fn a_5xx_success_body_is_not_a_settlement() {
        // The money-critical case: a facilitator internal error (500) whose body nonetheless claims
        // `success:true` with a transaction hash. A status-blind client builds a receipt and the
        // gateway serves a paid answer for a settlement that never authoritatively happened. A 5xx is
        // not a verdict, so this must be Unavailable, never a receipt.
        let body = r#"{"success":true,"transaction":"0xabc","network":"base-sepolia"}"#;
        let (base, _c) =
            serve(unused(), Canned::status(StatusCode::INTERNAL_SERVER_ERROR, body)).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap_err();
        assert!(matches!(err, FacilitatorError::Unavailable(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_5xx_error_body_is_unavailable_not_a_client_rejection() {
        // A 502 with `success:false`: the facilitator failed, it did not rule the payment bad. A
        // status-blind client returns Rejected — a 402 telling the client to mint a fresh
        // authorization for *our* outage. It must be Unavailable.
        let (base, _c) =
            serve(unused(), Canned::status(StatusCode::BAD_GATEWAY, SPEC_SETTLE_ERROR)).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap_err();
        assert!(matches!(err, FacilitatorError::Unavailable(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_5xx_verify_verdict_is_unavailable_not_trusted() {
        // The verify-side free-inference guard: a 500 claiming `isValid:true` must not authorize the
        // request. Not a verdict → Unavailable.
        let (base, _c) = serve(
            Canned::status(StatusCode::INTERNAL_SERVER_ERROR, r#"{"isValid":true}"#),
            unused(),
        )
        .await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .verify(&payment(), &requirements())
            .await
            .unwrap_err();
        assert!(matches!(err, FacilitatorError::Unavailable(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn settle_that_stalls_after_the_head_is_unavailable() {
        // The deadline must cover the WHOLE round-trip, not just the response head. This mock flushes
        // the head plus a first chunk, then withholds the tail forever (a Notify that never fires).
        // `settle` buffers the body (to_bytes), so a timeout wrapping only `client.request` would
        // return the head promptly and then hang on the withheld tail with no deadline — an
        // indeterminate may-have-charged wedge. With the deadline over the whole round-trip it gives
        // up and reports Unavailable. The outer 5s guard turns a regression (an unbounded hang) into a
        // clean failure rather than hanging the suite.
        let never = Arc::new(tokio::sync::Notify::new());
        let never_for_server = never.clone();
        let app = Router::new().route(
            "/facilitator/settle",
            post(move || {
                let never = never_for_server.clone();
                async move {
                    let head = futures_util::stream::once(async {
                        Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"{\"succ"))
                    });
                    let withheld = futures_util::stream::once(async move {
                        never.notified().await; // never fires
                        Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"ess\":true}"))
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from_stream(head.chain(withheld)))
                        .unwrap()
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let facilitator = DelegatedFacilitator::new(format!("http://{addr}/facilitator"))
            .unwrap()
            .with_timeout(Duration::from_millis(200));
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            facilitator.settle(&payment(), &requirements()),
        )
        .await
        .expect("settle must give up at its own deadline, not hang on the withheld body")
        .unwrap_err();
        assert!(matches!(err, FacilitatorError::Unavailable(_)), "got {err:?}");
    }

    // --- construction guards ---------------------------------------------------------------------

    #[tokio::test]
    async fn new_rejects_an_uppercase_https_base() {
        // The scheme allowlist is case-insensitive: HTTPS in any case is still TLS we have not wired.
        let err =
            DelegatedFacilitator::new("HTTPS://facilitator.example/facilitator").unwrap_err();
        assert!(matches!(err, DelegatedFacilitatorError::TlsNotWired(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn new_rejects_a_schemeless_base() {
        // A schemeless base would silently produce a bad request URL; caught at construction.
        let err = DelegatedFacilitator::new("facilitator.example/facilitator").unwrap_err();
        assert!(matches!(err, DelegatedFacilitatorError::NotAnHttpBase(_)), "got {err:?}");
    }

    // --- client-facing reason hygiene ------------------------------------------------------------

    #[tokio::test]
    async fn a_bulk_rejection_reason_is_replaced_with_the_generic() {
        // reject_reason echoes the facilitator's reason into the client-facing 402, but the wire type
        // is an unvalidated String on a no-TLS channel. An over-long reason (200 chars) is treated as
        // untrustworthy and replaced with the fixed generic, so a hostile/MITM'd facilitator cannot
        // reflect bulk content into our response body. A short reason is still surfaced (see
        // settle_rejects_on_success_false_with_the_facilitators_reason).
        let huge = "x".repeat(200);
        let body = format!(
            r#"{{"success":false,"errorReason":"{huge}","transaction":"","network":"base-sepolia"}}"#
        );
        let (base, _c) = serve(unused(), Canned::ok(&body)).await;
        let err = DelegatedFacilitator::new(base)
            .unwrap()
            .settle(&payment(), &requirements())
            .await
            .unwrap_err();
        assert_eq!(err, FacilitatorError::Rejected("settlement did not complete".to_string()));
    }
}
