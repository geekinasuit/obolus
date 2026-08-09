//! The toll booth itself: issue a 402, take payment, grant passage.
//!
//! # When we charge, and why the order is what it is
//!
//! `verify` → start upstream → `settle` → stream the body.
//!
//! Two constraints pull against each other. `X-PAYMENT-RESPONSE` is a *header*, so settlement
//! has to finish before the first byte of the body goes out — we cannot stream an answer and
//! then charge for it. But settling before we know the upstream will answer at all would
//! charge for work that never happened, and Obolus has no refund path.
//!
//! Splitting the upstream response into a head and a streaming body resolves it: we hold the
//! payment until the upstream has committed to a successful response, charge at that moment,
//! and only then emit headers and stream.
//!
//! ## Exactly how far "costs the client nothing" goes
//!
//! It covers everything up to and including the response head: an upstream that cannot be
//! reached, or that answers with an error status, is never charged for. It does **not** cover
//! a failure *after* the head.
//!
//! That limit is not incidental, it is structural, and it bites hardest on precisely the
//! upstream we are targeting. A token-streaming backend sends `200 OK` before it has generated
//! anything, so committing at head-time proves only that the request was *accepted* — not that
//! it will be *answered*. For a buffered (`stream: false`) upstream the head is much closer to
//! a real promise. A mid-stream death after settlement therefore leaves the client paid-up with
//! a partial answer, and no header remains to say so, because the receipt already went out.
//!
//! Closing that gap needs something this layer does not have: a refund path, an escrow, or
//! settlement in trailers. All three are Phase-B-or-later conversations that depend on
//! facilitator semantics we have not met yet. Until then the bound is pinned by a test rather
//! than left to be rediscovered — see `a_midstream_failure_after_settlement_is_a_known_gap`.
//!
//! # What a client failure looks like
//!
//! Anything the client can fix by paying properly gets another 402 carrying the challenge
//! *and* an `error` explaining the previous attempt. Anything that is our fault or the
//! facilitator's gets a 502. A payment that was never actually evaluated must never come back
//! looking like a rejected one.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::access::{bearer_token, TokenPath};
use crate::facilitator::{Facilitator, FacilitatorError};
use crate::upstream::{Upstream, UpstreamResponse};
use crate::x402::{self, PaymentPayload, PaymentRequired, PaymentRequirements, SettlementReceipt};

/// Why a [`Gateway`] could not be built from a set of payment options.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GatewayError {
    /// No options at all. A gateway that accepts nothing can never be paid — it would 402 every
    /// request forever — so it is refused at construction rather than served as a dead route.
    #[error("a gateway must accept at least one payment option, but none were configured")]
    NoPaymentOptions,

    /// Two options share a `(scheme, network)`. The `X-PAYMENT` envelope exposes only
    /// `(scheme, network)` — the asset lives *inside* the opaque payload Phase A never parses — so
    /// two options on the same pair cannot be told apart when a payment arrives: the second would be
    /// unreachable, and, worse, we could hand the facilitator the wrong asset to settle against.
    /// Multi-chain therefore means *distinct networks*, not several assets on one network.
    #[error(
        "duplicate payment option: two entries share (scheme, network) = ({scheme}, {network}); \
         a payment envelope carries only (scheme, network), so they cannot be distinguished at \
         settle time — advertise at most one entry per exact (scheme, network). Network strings are \
         compared verbatim, not case- or whitespace-normalized (a CAIP-2 reference such as Solana's \
         base58 genesis hash is case-sensitive), so canonicalize your ids before configuring them"
    )]
    DuplicateOption { scheme: String, network: String },
}

/// A payment-gated route in front of one upstream service.
///
/// It can advertise several ways to pay at once — one entry per `(scheme, network)`, e.g. Base and
/// Solana — and settles each request against whichever advertised option the client actually paid
/// (OBOL-003).
pub struct Gateway<F: Facilitator, U: Upstream> {
    facilitator: F,
    upstream: U,
    /// Non-empty and unique by `(scheme, network)` — enforced by [`Gateway::new`].
    requirements: Vec<PaymentRequirements>,
}

impl<F: Facilitator, U: Upstream> Gateway<F, U> {
    /// Build a gateway advertising `requirements`. Fails if the list is empty, or if two entries
    /// share a `(scheme, network)` — see [`GatewayError`].
    ///
    /// The uniqueness invariant is enforced *here*, at the type that later hands one of these
    /// requirements to `settle`, rather than only at the config boundary — so a wrong-asset
    /// settlement is impossible by construction, including for a future caller that builds a
    /// `Gateway` directly.
    ///
    /// **That guarantee does not extend to arming, and the asymmetry is deliberate — read it before
    /// relying on the paragraph above.** This constructor does *not* check that the advertised
    /// networks are testnet. That guard is [`arming::check_arming`](crate::arming::check_arming)
    /// (OBOL-004), and it is applied by the `obolus` binary at startup, not here. So a caller
    /// constructing a `Gateway` directly — the A3 real-facilitator integration tests, a second
    /// binary, an external crate — gets the uniqueness invariant and **not** the arming one, and
    /// must run `check_arming` itself or it will advertise whatever it was handed. Whether that
    /// should be closed structurally is OBOL-008.
    pub fn new(
        facilitator: F,
        upstream: U,
        requirements: Vec<PaymentRequirements>,
    ) -> Result<Self, GatewayError> {
        if requirements.is_empty() {
            return Err(GatewayError::NoPaymentOptions);
        }
        for (i, a) in requirements.iter().enumerate() {
            for b in &requirements[i + 1..] {
                if a.scheme == b.scheme && a.network == b.network {
                    return Err(GatewayError::DuplicateOption {
                        scheme: a.scheme.clone(),
                        network: a.network.clone(),
                    });
                }
            }
        }
        Ok(Self { facilitator, upstream, requirements })
    }

    /// The advertised option whose `(scheme, network)` this payment matches, if any.
    ///
    /// Unique by construction, so the first match is the only match. Matching on `(scheme, network)`
    /// and nothing more is not a shortcut — it is the most the opaque envelope lets us see (the
    /// asset is inside the payload we do not parse), which is exactly why `new` forbids two options
    /// from sharing the pair.
    fn accepted_for(&self, payment: &PaymentPayload) -> Option<&PaymentRequirements> {
        self.requirements
            .iter()
            .find(|r| r.scheme == payment.scheme && r.network == payment.network)
    }

    /// A 402 carrying *every* option we accept, optionally with why the last attempt did not qualify.
    fn challenge(&self, error: Option<String>) -> Response {
        let mut challenge = PaymentRequired::offering_all(self.requirements.clone());
        if let Some(error) = error {
            challenge = challenge.with_error(error);
        }
        (StatusCode::PAYMENT_REQUIRED, Json(challenge)).into_response()
    }
}

/// Our fault or the facilitator's — never dressed up as the client's.
///
/// `detail` can name internal infrastructure — at A3 the facilitator or Ollama URL, a host, a
/// connection string. That belongs in our logs, not in a response body any unauthenticated
/// caller can read back. The client is told only that the gateway (not their payment) failed;
/// the specifics stay server-side.
fn upstream_failure(detail: String) -> Response {
    eprintln!("obolus: upstream/settlement failure: {detail}");
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({ "error": "upstream or settlement unavailable" })),
    )
        .into_response()
}

async fn health() -> &'static str {
    "ok"
}

/// The paying path. Not an axum handler — [`completion`] is the route, and reaches this when the
/// caller presented no token we honour.
async fn paid_completion<F: Facilitator, U: Upstream>(
    gateway: Arc<Gateway<F, U>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(raw) = headers.get(x402::HEADER_PAYMENT) else {
        return gateway.challenge(None);
    };
    let Ok(raw) = raw.to_str() else {
        return gateway
            .challenge(Some(format!("{} must be ASCII base64", x402::HEADER_PAYMENT)));
    };

    let payment = match x402::decode_payment(raw) {
        Ok(payment) => payment,
        Err(err) => return gateway.challenge(Some(err.to_string())),
    };

    // Our own policy check, not the facilitator's: which advertised option did the client pay? None
    // → they picked an offer we did not make, so re-challenge with everything we DO accept. This is
    // the only place the paid option is chosen, and the *matched* `requirements` — not "the"
    // requirements — is what we verify and settle against.
    let Some(requirements) = gateway.accepted_for(&payment) else {
        return gateway.challenge(Some(format!(
            "payment offers {}/{}, which is not one of the payment options this resource accepts",
            payment.scheme, payment.network,
        )));
    };

    match gateway.facilitator.verify(&payment, requirements).await {
        Ok(()) => {}
        Err(FacilitatorError::Rejected(reason)) => return gateway.challenge(Some(reason)),
        Err(err @ FacilitatorError::Unavailable(_)) => return upstream_failure(err.to_string()),
    }

    // Payment is good. Commit the upstream BEFORE charging.
    let response = match gateway.upstream.forward(body).await {
        Ok(response) => response,
        Err(err) => return upstream_failure(err.to_string()),
    };
    if !response.status.is_success() {
        // The upstream refused: charge nothing, and hand its answer back the same way every other
        // response here is built. Constructing it as `(status, body)` instead drops the upstream's
        // content type, so an identical `503 {"error":..}` reaches a paying client untyped and a
        // token-holder as `application/json` — a divergence between the paid and unpaid paths on
        // the very axis this module exists to close.
        return proxy_response(response, None);
    }

    let receipt = match gateway.facilitator.settle(&payment, requirements).await {
        Ok(receipt) if receipt.success => receipt,
        // A receipt that reports its own failure is a refusal, not a success. Serving the
        // response on the strength of `Ok(_)` alone would give the work away for free.
        Ok(_) => return gateway.challenge(Some("settlement did not complete".to_string())),
        // The same split as verify. Returning 502 for a payment the facilitator actually
        // evaluated and refused would be both a lie and the more dangerous lie: 502 reads as
        // transient, so clients retry it harder than they retry a 402.
        Err(FacilitatorError::Rejected(reason)) => return gateway.challenge(Some(reason)),
        Err(err @ FacilitatorError::Unavailable(_)) => return upstream_failure(err.to_string()),
    };

    proxy_response(response, Some(&receipt))
}

/// Turn an upstream response into the client's, attaching a receipt only if the client paid.
///
/// Both access paths build their response here. Two separately-maintained copies would drift, and
/// the one that drifts unnoticed is the one nobody is being charged for.
fn proxy_response(response: UpstreamResponse, receipt: Option<&SettlementReceipt>) -> Response {
    let mut proxied = Response::builder().status(response.status);
    if let Some(content_type) = &response.content_type {
        // Parse rather than hand the builder a `&str`: `Response::builder().header(..)` defers a
        // bad value to `.body()`, which would turn this into a 502 — *after* we charged, over a
        // header the client does not need. The status is already set and the receipt is guarded
        // below the same way, so a content type that is not header-safe just gets dropped.
        match HeaderValue::from_str(content_type) {
            Ok(value) => proxied = proxied.header(axum::http::header::CONTENT_TYPE, value),
            Err(_) => {}
        }
    }
    if let Some(receipt) = receipt {
        match HeaderValue::from_str(&x402::encode_receipt(receipt)) {
            Ok(value) => proxied = proxied.header(x402::HEADER_PAYMENT_RESPONSE, value),
            // Unreachable: the receipt is base64, which is always header-safe. But the client
            // paid, so serve the response rather than failing over a header we could not attach.
            Err(_) => {}
        }
    }
    proxied.body(response.body).unwrap_or_else(|err| upstream_failure(err.to_string()))
}

/// The two ways through the gate, bound together in front of the toll booth.
///
/// [`Gateway`] deliberately does not appear in this decision: it runs the 402 handshake and must
/// never learn who the caller is.
pub struct Access<F: Facilitator, U: Upstream> {
    /// `None` switches the token path off entirely and every request pays — which is what an
    /// instance with no verifying key configured does, and is the behaviour to fall back to.
    token: Option<TokenPath>,
    gateway: Arc<Gateway<F, U>>,
}

impl<F: Facilitator, U: Upstream> Access<F, U> {
    pub fn new(gateway: Gateway<F, U>, token: Option<TokenPath>) -> Self {
        Self { token, gateway: Arc::new(gateway) }
    }

    /// How the token path this instance will actually route describes itself, or `None` when it has
    /// none.
    ///
    /// Exists so `main`'s startup banner can be keyed on the routed value instead of on the
    /// configuration that was *meant* to produce it. `main` is compiled by no test target, so the
    /// only checkable form of "the verifier reached the router" is a line the binary prints that it
    /// could not have printed otherwise — see `tests/server_arming.rs`.
    pub fn token_path(&self) -> Option<&str> {
        self.token.as_ref().map(TokenPath::description)
    }
}

/// Serve a caller we recognise; charge one we do not.
async fn completion<F: Facilitator, U: Upstream>(
    State(access): State<Arc<Access<F, U>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let (Some(path), Some(token)) = (&access.token, bearer_token(&headers)) {
        match path.verify(token) {
            Ok(()) => {
                let response = match access.gateway.upstream.forward(body).await {
                    Ok(response) => response,
                    Err(err) => return upstream_failure(err.to_string()),
                };
                return proxy_response(response, None);
            }
            // Every failure lands here, including a verifier that could not evaluate the token at
            // all, and every one of them continues to the paying path. The response then says
            // nothing about the token: naming why it failed would hand an attacker a probing
            // oracle against a gateway whose other path is anonymous by design.
            Err(err) => eprintln!("obolus: bearer token not honoured: {err}"),
        }
    }
    paid_completion(access.gateway.clone(), headers, body).await
}

/// Wire an access surface into an OpenAI-compatible route plus an ungated health check.
///
/// Takes the constructed [`Access`] rather than its parts so that whatever `main` printed about the
/// token path was read off the same value that lands here.
pub fn router<F: Facilitator, U: Upstream>(access: Access<F, U>) -> Router {
    Router::new()
        // Ungated on purpose: liveness is not a paid service, and a health check that needs a
        // wallet is a health check nothing can call.
        .route("/health", get(health))
        .route("/v1/chat/completions", post(completion::<F, U>))
        .with_state(Arc::new(access))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::FakeTokenVerifier;
    use crate::facilitator::{FakeCalls, FakeFacilitator};
    use crate::upstream::{FakeUpstream, UpstreamCalls};
    use crate::x402::{PaymentPayload, SettlementReceipt, SCHEME_EXACT, X402_VERSION};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    /// Obviously-synthetic fixtures — not real networks, addresses, or transactions.
    const FIXTURE_NETWORK: &str = "test-network-not-a-real-caip2";
    const FIXTURE_PAY_TO: &str = "0xTEST-PAY-TO-ADDRESS-NOT-REAL";
    const FIXTURE_ASSET: &str = "0xTEST-ASSET-ADDRESS-NOT-REAL";

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

    fn payment() -> PaymentPayload {
        PaymentPayload {
            x402_version: X402_VERSION,
            scheme: SCHEME_EXACT.to_string(),
            network: FIXTURE_NETWORK.to_string(),
            payload: serde_json::json!({ "authorization": "opaque-to-phase-a" }),
        }
    }

    /// The wired router plus a handle on what the facilitator was actually asked to do.
    ///
    /// Needed because "we did not charge" is invisible in the response: a gateway that settled
    /// eagerly and then hit an upstream error returns the same status and the same missing
    /// receipt header as one that correctly never charged.
    fn app_with(facilitator: FakeFacilitator, upstream: FakeUpstream) -> (Router, FakeCalls) {
        let calls = facilitator.calls();
        let gateway = Gateway::new(facilitator, upstream, vec![requirements()]).unwrap();
        (router(Access::new(gateway, None)), calls)
    }

    fn app(facilitator: FakeFacilitator, upstream: FakeUpstream) -> Router {
        app_with(facilitator, upstream).0
    }

    /// The same wiring with the token path switched on, plus handles on both seams.
    ///
    /// Returns the upstream's call count as well as the facilitator's, because for the token path
    /// "we did not serve" is the property that matters and a 402 alone does not establish it.
    fn app_with_verifier(
        facilitator: FakeFacilitator,
        upstream: FakeUpstream,
        verifier: FakeTokenVerifier,
    ) -> (Router, FakeCalls, UpstreamCalls) {
        let calls = facilitator.calls();
        let forwards = upstream.calls();
        let gateway = Gateway::new(facilitator, upstream, vec![requirements()]).unwrap();
        let token = TokenPath::new(Arc::new(verifier));
        (router(Access::new(gateway, Some(token))), calls, forwards)
    }

    fn completion_request(payment_header: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("POST").uri("/v1/chat/completions");
        if let Some(header) = payment_header {
            builder = builder.header(x402::HEADER_PAYMENT, header);
        }
        builder.body(Body::from(r#"{"model":"test","messages":[]}"#)).unwrap()
    }

    /// A completion request carrying a bearer token and no payment.
    fn tokened_request(token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(r#"{"model":"test","messages":[]}"#))
            .unwrap()
    }

    const HONOURED: &str = "a-token-the-verifier-honours";

    async fn send(app: Router, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// Like [`send`], but for a body that dies partway: collects what arrived and reports that
    /// it ended in an error. `to_bytes` is all-or-nothing, so it cannot express a partial read.
    async fn send_partial(app: Router, request: Request<Body>) -> (StatusCode, HeaderMap, String, bool) {
        use futures_util::StreamExt as _;
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let mut stream = response.into_body().into_data_stream();
        let (mut collected, mut errored) = (Vec::new(), false);
        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => collected.extend_from_slice(&bytes),
                Err(_) => {
                    errored = true;
                    break;
                }
            }
        }
        (status, headers, String::from_utf8(collected).unwrap(), errored)
    }

    fn challenge_error(body: &str) -> Option<String> {
        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        json["error"].as_str().map(str::to_string)
    }

    #[tokio::test]
    async fn health_needs_no_payment() {
        let request = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let (status, _, body) =
            send(app(FakeFacilitator::accepting(), FakeUpstream::streaming()), request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn no_payment_gets_a_challenge_describing_what_we_accept() {
        let (status, _, body) =
            send(app(FakeFacilitator::accepting(), FakeUpstream::streaming()), completion_request(None))
                .await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["x402Version"], serde_json::json!(X402_VERSION));
        assert_eq!(json["accepts"][0]["payTo"], serde_json::json!(FIXTURE_PAY_TO));
        assert_eq!(json["accepts"][0]["maxAmountRequired"], serde_json::json!("1000"));
        assert!(json.get("error").is_none(), "a first request has nothing to apologise for");
    }

    #[tokio::test]
    async fn malformed_payment_gets_a_challenge_that_says_why() {
        let (status, _, body) = send(
            app(FakeFacilitator::accepting(), FakeUpstream::streaming()),
            completion_request(Some("not!base64!")),
        )
        .await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert!(challenge_error(&body).unwrap().contains("base64"));
    }

    #[tokio::test]
    async fn payment_for_an_offer_we_did_not_make_is_refused() {
        let mut wrong = payment();
        wrong.network = "some-other-network".to_string();
        let (status, _, body) = send(
            app(FakeFacilitator::accepting(), FakeUpstream::streaming()),
            completion_request(Some(&x402::encode_payment(&wrong))),
        )
        .await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert!(challenge_error(&body).unwrap().contains("some-other-network"));
    }

    #[tokio::test]
    async fn a_rejected_payment_gets_another_challenge_with_the_reason() {
        let (app, calls) =
            app_with(FakeFacilitator::rejecting("insufficient funds"), FakeUpstream::streaming());
        let (status, headers, body) =
            send(app, completion_request(Some(&x402::encode_payment(&payment())))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert!(challenge_error(&body).unwrap().contains("insufficient funds"));
        assert!(headers.get(x402::HEADER_PAYMENT_RESPONSE).is_none());
        assert_eq!(calls.settles(), 0, "a payment we rejected must never be collected");
    }

    #[tokio::test]
    async fn an_unreachable_facilitator_is_our_fault_not_the_clients() {
        // The distinction that matters: a payment we never managed to evaluate must NOT come
        // back as 402, or clients will re-sign and re-send a payment that was fine all along.
        let (status, _, _) = send(
            app(FakeFacilitator::unavailable("connection refused"), FakeUpstream::streaming()),
            completion_request(Some(&x402::encode_payment(&payment()))),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn paid_request_streams_the_upstream_and_returns_a_receipt() {
        let (app, calls) = app_with(FakeFacilitator::accepting(), FakeUpstream::streaming());
        let (status, headers, body) =
            send(app, completion_request(Some(&x402::encode_payment(&payment())))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!((calls.verifies(), calls.settles()), (1, 1), "verified once, charged once");
        assert_eq!(body, FakeUpstream::streamed_text(), "every chunk must reach the client");

        let raw = headers.get(x402::HEADER_PAYMENT_RESPONSE).expect("receipt header");
        let receipt = x402::decode_receipt(raw.to_str().unwrap()).unwrap();
        assert_eq!(
            receipt,
            SettlementReceipt {
                success: true,
                transaction: Some("0xTEST-TX-HASH-NOT-A-REAL-TRANSACTION".to_string()),
                network: FIXTURE_NETWORK.to_string(),
                payer: None,
            }
        );
    }

    /// What `FakeUpstream::refusing` labels its error body with. One constant for both the paid and
    /// the token-path assertion: two literals could drift apart and still both pass, which would
    /// leave the "one `proxy_response`" claim unobserved again.
    const UPSTREAM_REFUSAL_CONTENT_TYPE: &str = "application/json";

    #[tokio::test]
    async fn an_upstream_error_is_passed_through_and_costs_nothing() {
        // Discriminating: an implementation that settled right after verify would still return
        // 503 with no receipt header here — the status and headers cannot tell the two apart.
        // The settle count can, which is why it is the assertion that matters.
        let (app, calls) = app_with(
            FakeFacilitator::accepting(),
            FakeUpstream::refusing(StatusCode::SERVICE_UNAVAILABLE),
        );
        let (status, headers, _) =
            send(app, completion_request(Some(&x402::encode_payment(&payment())))).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(headers.get(x402::HEADER_PAYMENT_RESPONSE).is_none());
        assert_eq!(calls.verifies(), 1, "we did check the payment");
        assert_eq!(calls.settles(), 0, "but must not charge for a request the upstream refused");
        // Returning `(status, body)` directly here would drop the upstream's content type, giving a
        // paying client an untyped error body where a token holder gets a typed one. Asserted here
        // and in the token-path analogue against the same constant, so that regression goes red.
        assert_eq!(
            headers.get(axum::http::header::CONTENT_TYPE).map(|v| v.to_str().unwrap()),
            Some(UPSTREAM_REFUSAL_CONTENT_TYPE),
            "the upstream's content type must survive on the paid path too",
        );
    }

    #[tokio::test]
    async fn an_unreachable_upstream_costs_nothing() {
        let (app, calls) = app_with(
            FakeFacilitator::accepting(),
            FakeUpstream::unreachable("connection refused"),
        );
        let (status, headers, _) =
            send(app, completion_request(Some(&x402::encode_payment(&payment())))).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(headers.get(x402::HEADER_PAYMENT_RESPONSE).is_none());
        assert_eq!(calls.settles(), 0, "an upstream we never reached must cost nothing");
    }

    #[tokio::test]
    async fn a_refused_settlement_is_the_clients_problem_not_a_bad_gateway() {
        // The verify path splits Rejected from Unavailable; the settle path must too. Calling a
        // refusal 502 would be the more dangerous lie of the two: 502 reads as transient, so
        // clients retry it harder than they retry a 402 — and every retry runs the upstream
        // again before settlement fails again.
        let (app, calls) = app_with(
            FakeFacilitator::rejecting_settlement("authorization already spent"),
            FakeUpstream::streaming(),
        );
        let (status, headers, body) =
            send(app, completion_request(Some(&x402::encode_payment(&payment())))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert!(challenge_error(&body).unwrap().contains("already spent"));
        assert!(headers.get(x402::HEADER_PAYMENT_RESPONSE).is_none());
        assert!(!body.contains("[DONE]"), "the answer must not be served for a refused payment");
        assert_eq!(calls.settles(), 1);
    }

    #[tokio::test]
    async fn an_unsuccessful_receipt_is_not_a_successful_settlement() {
        // `Ok(_)` from the facilitator is not the same as "we got paid". A gateway that trusts
        // the Result and never reads `success` serves the whole response for free.
        let (app, _) =
            app_with(FakeFacilitator::returning_unsuccessful_receipt(), FakeUpstream::streaming());
        let (status, headers, body) =
            send(app, completion_request(Some(&x402::encode_payment(&payment())))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert!(headers.get(x402::HEADER_PAYMENT_RESPONSE).is_none());
        assert!(!body.contains("[DONE]"), "an unsuccessful receipt must not buy the answer");
    }

    #[tokio::test]
    async fn a_midstream_failure_after_settlement_is_a_known_gap() {
        // NOT an aspiration — this pins what currently happens, so the limit of the
        // charge-ordering guarantee is visible instead of implied by a missing test.
        //
        // The head said 200, so we charged and emitted the receipt. The body then died. The
        // client has paid and holds a truncated answer, and the receipt header has already gone
        // out, so nothing downstream can retract it. Closing this needs a refund path, an
        // escrow, or settlement in trailers — see the module docs.
        let (app, calls) = app_with(FakeFacilitator::accepting(), FakeUpstream::failing_midstream());
        let (status, headers, body, errored) =
            send_partial(app, completion_request(Some(&x402::encode_payment(&payment())))).await;

        assert_eq!(status, StatusCode::OK, "the head already committed before the body failed");
        assert_eq!(calls.settles(), 1, "and we charged at head time");
        assert!(headers.get(x402::HEADER_PAYMENT_RESPONSE).is_some(), "receipt already emitted");
        assert!(errored, "the body really does fail partway — this is the gap, not a hypothetical");
        assert!(body.contains("Hel"), "the client keeps the chunks that did arrive");
        assert!(!body.contains("[DONE]"), "...but the answer is truncated: paid, not delivered");
    }

    #[tokio::test]
    async fn a_failed_settlement_does_not_serve_the_answer() {
        // We verified, the upstream was ready, and then we could not collect. Serving the
        // stream anyway would give the work away; claiming the payment was bad would be a lie.
        let (app, calls) =
            app_with(FakeFacilitator::failing_settlement("chain reorg"), FakeUpstream::streaming());
        let (status, headers, body) =
            send(app, completion_request(Some(&x402::encode_payment(&payment())))).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(headers.get(x402::HEADER_PAYMENT_RESPONSE).is_none());
        assert!(!body.contains("[DONE]"), "the upstream stream must not leak out unpaid");
        assert_eq!(calls.settles(), 1, "we did attempt to collect; it was collection that failed");
    }

    #[tokio::test]
    async fn a_header_unsafe_upstream_content_type_still_delivers_the_paid_answer() {
        // Discriminating: an unguarded `.header(CONTENT_TYPE, &str)` defers a bad value to
        // `.body()`, which would 502 a client who already paid. The CRLF here is also a
        // response-splitting attempt — `http` refuses to build it either way, so nothing injects;
        // the only question is whether the paid client loses their answer over it. They must not.
        let (app, calls) = app_with(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming_with_content_type("text/event-stream\r\nX-Injected: yes"),
        );
        let (status, headers, body) =
            send(app, completion_request(Some(&x402::encode_payment(&payment())))).await;
        assert_eq!(status, StatusCode::OK, "the client paid; a bad upstream header must not 502 them");
        assert_eq!(calls.settles(), 1, "the charge stands because the answer was delivered");
        assert!(headers.get(x402::HEADER_PAYMENT_RESPONSE).is_some(), "receipt still emitted");
        assert!(headers.get("x-injected").is_none(), "the smuggled header never lands");
        assert_eq!(body, FakeUpstream::streamed_text(), "the answer itself is untouched");
    }

    // --- multi-chain: many advertised options, client picks one (OBOL-003) -----------------------

    /// A second advertised option on a DISTINCT network, with its own asset and pay-to, so a test
    /// can tell *which* option the gateway settled against — not merely that it settled.
    const FIXTURE_NETWORK_B: &str = "test-network-b-not-a-real-caip2";
    const FIXTURE_PAY_TO_B: &str = "0xTEST-PAY-TO-B-NOT-REAL";
    const FIXTURE_ASSET_B: &str = "0xTEST-ASSET-B-NOT-REAL";

    fn requirements_b() -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: FIXTURE_NETWORK_B.to_string(),
            max_amount_required: "2000".to_string(),
            resource: "http://localhost:8402/v1/chat/completions".to_string(),
            description: "One inference request".to_string(),
            mime_type: "application/json".to_string(),
            pay_to: FIXTURE_PAY_TO_B.to_string(),
            max_timeout_seconds: 60,
            asset: FIXTURE_ASSET_B.to_string(),
            extra: None,
        }
    }

    fn payment_b() -> PaymentPayload {
        PaymentPayload {
            x402_version: X402_VERSION,
            scheme: SCHEME_EXACT.to_string(),
            network: FIXTURE_NETWORK_B.to_string(),
            payload: serde_json::json!({ "authorization": "opaque-to-phase-a" }),
        }
    }

    /// A gateway advertising option A (`requirements()`) THEN option B (`requirements_b()`).
    fn multichain_app_with(
        facilitator: FakeFacilitator,
        upstream: FakeUpstream,
    ) -> (Router, FakeCalls) {
        let calls = facilitator.calls();
        (
            router(Access::new(
                Gateway::new(facilitator, upstream, vec![requirements(), requirements_b()]).unwrap(),
                None,
            )),
            calls,
        )
    }

    #[tokio::test]
    async fn multichain_challenge_advertises_every_option() {
        let (app, _) = multichain_app_with(FakeFacilitator::accepting(), FakeUpstream::streaming());
        let (status, _, body) = send(app, completion_request(None)).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let accepts = json["accepts"].as_array().expect("accepts is an array");
        assert_eq!(accepts.len(), 2, "both advertised options reach the client");
        let networks: Vec<&str> = accepts.iter().map(|a| a["network"].as_str().unwrap()).collect();
        assert!(networks.contains(&FIXTURE_NETWORK), "network A advertised");
        assert!(networks.contains(&FIXTURE_NETWORK_B), "network B advertised");
    }

    #[tokio::test]
    async fn multichain_settles_against_the_second_option_when_thats_what_was_paid() {
        // The teeth: advertise A then B, pay B, and assert we verified AND settled against B's
        // requirement — B's asset and pay-to — not the first-listed A. Status and receipt alone
        // cannot tell these apart (both are a 200 with a receipt); the requirement handed to settle
        // is the only thing that distinguishes right-asset from wrong-asset settlement, which is
        // exactly the failure that would settle the wrong token against a real facilitator.
        let (app, calls) =
            multichain_app_with(FakeFacilitator::accepting(), FakeUpstream::streaming());
        let (status, _, _) =
            send(app, completion_request(Some(&x402::encode_payment(&payment_b())))).await;
        assert_eq!(status, StatusCode::OK);

        let settled = calls.settled_requirements();
        assert_eq!(settled.len(), 1, "charged exactly once");
        assert_eq!(settled[0].network, FIXTURE_NETWORK_B);
        assert_eq!(settled[0].asset, FIXTURE_ASSET_B, "settled the PAID option's asset, not [0]'s");
        assert_eq!(settled[0].pay_to, FIXTURE_PAY_TO_B, "and its pay-to");
        assert_eq!(settled[0].max_amount_required, "2000", "and its price");
        // And verify saw the same matched option.
        assert_eq!(calls.verified_requirements().last().unwrap().asset, FIXTURE_ASSET_B);
    }

    #[tokio::test]
    async fn multichain_settles_against_the_first_option_when_thats_what_was_paid() {
        // The mirror of the pay-second test: paying A must settle against A. The pair rules out both
        // an "always settle [0]" and an "always settle the last" implementation — either would pass
        // one of the two and fail the other.
        let (app, calls) =
            multichain_app_with(FakeFacilitator::accepting(), FakeUpstream::streaming());
        let (status, _, _) =
            send(app, completion_request(Some(&x402::encode_payment(&payment())))).await;
        assert_eq!(status, StatusCode::OK);
        let settled = calls.settled_requirements();
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].network, FIXTURE_NETWORK);
        assert_eq!(settled[0].asset, FIXTURE_ASSET, "settled against A, the option that was paid");
    }

    #[tokio::test]
    async fn multichain_payment_for_an_unlisted_network_is_refused_before_any_charge() {
        // A network we do not advertise is re-challenged and — discriminating — refused BEFORE any
        // facilitator call. An implementation that fell back to settling some option anyway would
        // show verifies() > 0 here.
        let mut wrong = payment();
        wrong.network = "test-network-c-unlisted".to_string();
        let (app, calls) =
            multichain_app_with(FakeFacilitator::accepting(), FakeUpstream::streaming());
        let (status, _, body) =
            send(app, completion_request(Some(&x402::encode_payment(&wrong)))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert!(challenge_error(&body).unwrap().contains("test-network-c-unlisted"));
        assert_eq!(calls.verifies(), 0, "an unlisted network never reaches verify");
        assert_eq!(calls.settles(), 0, "and certainly never settles");
    }

    /// An x402 **short name** — not CAIP-2, so `arming::is_provably_testnet` can never admit it and
    /// `arming::diagnose` names it as defective. The point of the test below is that "the arming
    /// guard cannot prove it" and "a client cannot pay it" are *different properties*, and only the
    /// first one is true.
    const FIXTURE_SHORT_NAME: &str = "base-sepolia";

    #[tokio::test]
    async fn an_id_the_arming_guard_cannot_prove_is_still_payable() {
        // Refutes, and keeps refuted, any claim that an id the arming guard cannot prove is thereby
        // one "no client can match either, so an armed gateway would 402 those requests just the
        // same". It is a live rail.
        //
        // The two comparisons are against different data and nothing keeps them in step:
        //   · `arming::is_provably_testnet` compares the id against TESTNET_NETWORKS.
        //   · `Gateway::accepted_for` compares it against `self.requirements` — what THIS gateway was
        //     configured to advertise.
        // A short name fails the first and passes the second, because `config::validated_option`
        // rejects only an *empty* network: everything else reaches `requirements` verbatim, is
        // advertised verbatim by `challenge`, and is matched verbatim on the way back in. Byte-exact
        // matching is what makes it payable, not what makes it dead.
        //
        // Discriminating on purpose: paid against the SHORT NAME, not against the CAIP-2 sibling, and
        // asserting the settled requirement is the short-name one. A 200 alone would not distinguish
        // this from a gateway that quietly settled option [0].
        let mut short_name = requirements();
        short_name.network = FIXTURE_SHORT_NAME.to_string();
        short_name.asset = FIXTURE_ASSET_B.to_string();
        let calls_holder = FakeFacilitator::accepting();
        let calls = calls_holder.calls();
        let app = router(Access::new(
            Gateway::new(calls_holder, FakeUpstream::streaming(), vec![requirements_b(), short_name])
                .unwrap(),
            None,
        ));

        let mut pay_short_name = payment();
        pay_short_name.network = FIXTURE_SHORT_NAME.to_string();
        let (status, _, _) =
            send(app, completion_request(Some(&x402::encode_payment(&pay_short_name)))).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "an id the arming guard cannot prove is STILL payable — it is advertised verbatim and \
             matched verbatim, so a client that echoes it back is served",
        );
        let settled = calls.settled_requirements();
        assert_eq!(settled.len(), 1, "and real money was moved for it, exactly once");
        assert_eq!(settled[0].network, FIXTURE_SHORT_NAME, "settled against the short name itself");
        assert_eq!(
            settled[0].asset, FIXTURE_ASSET_B,
            "and against ITS asset — this is what rules out 'settled option [0] anyway'",
        );
    }

    #[test]
    fn new_rejects_an_empty_option_list() {
        // A gateway that accepts nothing can never be paid — refused at construction, not served as
        // a route that 402s forever. (`.err()` rather than `.unwrap_err()` because `Gateway` is not
        // `Debug`; the error type is.)
        let err = Gateway::new(FakeFacilitator::accepting(), FakeUpstream::streaming(), vec![])
            .err()
            .expect("an empty option list must be rejected");
        assert!(matches!(err, GatewayError::NoPaymentOptions), "got {err:?}");
    }

    #[test]
    fn new_rejects_two_options_sharing_scheme_and_network() {
        // Same (scheme, network), different asset: indistinguishable from the opaque envelope, so
        // one would be unreachable and we could settle the wrong asset. The guard must bite at
        // construction — this asserts it does rather than assuming it. (`.err()` not `.unwrap_err()`
        // for the same reason as above: `Gateway` is not `Debug`, its error is.)
        let mut dup = requirements();
        dup.asset = "0xDIFFERENT-ASSET-SAME-NETWORK-NOT-REAL".to_string();
        let err = Gateway::new(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            vec![requirements(), dup],
        )
        .err()
        .expect("duplicate (scheme, network) must be rejected");
        assert!(matches!(err, GatewayError::DuplicateOption { .. }), "got {err:?}");
    }

    // ---- the access branch (OBOL-007) ----
    //
    // Every negative case asserts 402 **and** that the upstream was never reached. The status
    // alone cannot tell "refused the token" from "reached the upstream and something else went
    // wrong", and being served is the failure that costs us; being asked to pay is not.

    #[tokio::test]
    async fn an_honoured_token_is_served_without_touching_the_payment_path() {
        let (app, calls, forwards) = app_with_verifier(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            FakeTokenVerifier::honouring(HONOURED),
        );
        let (status, headers, body) = send(app, tokened_request(HONOURED)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, FakeUpstream::streamed_text());
        assert_eq!(forwards.count(), 1);
        // The load-bearing one. A branch that served the caller but still ran verify/settle
        // underneath would pass every assertion above and be charging a tokened client.
        assert_eq!(calls.verifies(), 0, "the token path must not verify a payment");
        assert_eq!(calls.settles(), 0, "the token path must not settle anything");
        assert!(
            !headers.contains_key(x402::HEADER_PAYMENT_RESPONSE),
            "nothing was paid, so there is no receipt to hand back",
        );
    }

    #[tokio::test]
    async fn a_rejected_token_pays_like_anyone_else_and_reaches_no_upstream() {
        let (app, _calls, forwards) = app_with_verifier(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            FakeTokenVerifier::honouring(HONOURED),
        );
        let (status, _headers, body) = send(app, tokened_request("not-the-honoured-token")).await;

        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(forwards.count(), 0);
        // The 402 must read exactly as an anonymous caller's. Naming the token failure would
        // hand an attacker an oracle for probing tokens against a gateway that is otherwise
        // anonymous by design.
        assert!(
            !body.contains("token"),
            "the challenge must not mention the token: {body}",
        );
    }

    #[tokio::test]
    async fn a_verifier_that_cannot_evaluate_the_token_still_charges() {
        // The arm a reviewer expects to be a 503. It is deliberately not: a legitimate holder
        // told to pay can pay or retry, whereas any status that might be read as "serve anyway"
        // is inference given away.
        let (app, _calls, forwards) = app_with_verifier(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            FakeTokenVerifier::always_unavailable("introspection endpoint down"),
        );
        let (status, _headers, _body) = send(app, tokened_request(HONOURED)).await;

        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(forwards.count(), 0);
    }

    #[tokio::test]
    async fn a_request_with_no_token_at_all_takes_the_paying_path() {
        let (app, _calls, forwards) = app_with_verifier(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            FakeTokenVerifier::honouring(HONOURED),
        );
        let (status, _headers, _body) = send(app, completion_request(None)).await;

        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(forwards.count(), 0);
    }

    #[tokio::test]
    async fn an_honoured_token_buys_nothing_when_no_verifier_is_configured() {
        // The unconfigured instance: no verifying key, so the token path does not exist and the
        // same token that works above is just an unrecognised header.
        let (app, forwards) = {
            let upstream = FakeUpstream::streaming();
            let forwards = upstream.calls();
            let gateway =
                Gateway::new(FakeFacilitator::accepting(), upstream, vec![requirements()]).unwrap();
            (router(Access::new(gateway, None)), forwards)
        };
        let (status, _headers, _body) = send(app, tokened_request(HONOURED)).await;

        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert_eq!(forwards.count(), 0);
    }

    #[tokio::test]
    async fn a_refusing_upstream_reaches_a_token_holder_the_same_way_it_reaches_a_payer() {
        // The paid path's analogue is `an_upstream_error_is_passed_through_and_costs_nothing`. Both
        // arms build their response through `proxy_response`, and that is the claim: an identical
        // upstream refusal comes back identically on both paths, content type included.
        let (app, calls, forwards) = app_with_verifier(
            FakeFacilitator::accepting(),
            FakeUpstream::refusing(StatusCode::SERVICE_UNAVAILABLE),
            FakeTokenVerifier::honouring(HONOURED),
        );
        let (status, headers, _body) = send(app, tokened_request(HONOURED)).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "the upstream's answer, not ours");
        assert_eq!(forwards.count(), 1, "the token was honoured, so the upstream was asked");
        assert_eq!(calls.settles(), 0, "and a token-holder is never charged, refusal or not");
        assert!(
            !headers.contains_key(x402::HEADER_PAYMENT_RESPONSE),
            "no payment, so no receipt",
        );
        assert_eq!(
            headers.get(axum::http::header::CONTENT_TYPE).map(|v| v.to_str().unwrap()),
            Some(UPSTREAM_REFUSAL_CONTENT_TYPE),
            "the same content type the paid path delivers — that is the convergence claim",
        );
    }

    #[tokio::test]
    async fn an_unreachable_upstream_is_a_bad_gateway_for_a_token_holder_too() {
        let (app, calls, forwards) = app_with_verifier(
            FakeFacilitator::accepting(),
            FakeUpstream::unreachable("connection refused"),
            FakeTokenVerifier::honouring(HONOURED),
        );
        let (status, _headers, _body) = send(app, tokened_request(HONOURED)).await;

        // 502, not the 402 every *rejection* on this path produces: the token was honoured and it
        // is our upstream that failed, so answering "pay me" would send a caller who did nothing
        // wrong to buy a request that was never going to be served.
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(forwards.count(), 1, "we did try the upstream");
        assert_eq!(calls.verifies(), 0, "and never touched the payment path on the way");
    }

    #[tokio::test]
    async fn a_paying_client_is_unaffected_by_the_token_path_existing() {
        let (app, calls, forwards) = app_with_verifier(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            FakeTokenVerifier::honouring(HONOURED),
        );
        let (status, headers, _body) =
            send(app, completion_request(Some(&x402::encode_payment(&payment())))).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(forwards.count(), 1);
        assert_eq!(calls.settles(), 1, "a paying client must still be charged");
        assert!(headers.contains_key(x402::HEADER_PAYMENT_RESPONSE));
    }

    #[tokio::test]
    async fn health_is_ungated_on_a_token_configured_instance() {
        let (app, _calls, _forwards) = app_with_verifier(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            FakeTokenVerifier::honouring(HONOURED),
        );
        let request = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let (status, _headers, body) = send(app, request).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }
}
