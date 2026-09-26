//! The toll booth itself: issue a 402, take payment, grant passage.
//!
//! # When we charge, and why the order is what it is
//!
//! `verify` → start upstream → `settle` → stream the body.
//!
//! Two constraints pull against each other. `PAYMENT-RESPONSE` is a *header*, so settlement
//! has to finish before the first byte of the body goes out — we cannot stream an answer and
//! then charge for it. But settling before we know the upstream will answer at all would
//! charge for work that never happened, and Obolus has no refund path.
//!
//! Splitting the upstream response into a head and a streaming body resolves it: we hold the
//! payment until the upstream has committed to a successful response, charge at that moment,
//! and only then emit headers and stream.
//!
//! ## The payment's own clock
//!
//! Holding the payment has a limit: it expires. The reference EVM client signs an authorization
//! valid for `maxTimeoutSeconds`, and a facilitator will not settle one about to lapse. A head
//! that arrives after that has bought work nobody can be charged for, and a 402 then would invite
//! the client to pay for the same wait again. So each paid request's wait for its head is bounded by
//! its window, less [`SETTLE_RESERVE_SECS`] kept back for settling. When that bound fires, the
//! request fails with a 504 and nothing is charged.
//!
//! ## Giving up on an upstream
//!
//! When the gateway abandons an upstream request — the payment window runs out before the head, or
//! settlement fails after it — it drops the request or the response. While the answer is still
//! arriving, dropping closes the upstream connection: the client neither reads the rest of the body
//! nor returns the connection to its pool. That close is the only signal the origin gets that nobody
//! is waiting for its answer; an origin that stops generating when its client goes away, as Ollama
//! 0.34.4's MLX runner was seen to, stops there. See
//! `an_upstream_abandoned_before_its_head_sees_its_connection_close` and the three
//! `an_upstream_abandoned_midstream_after_…` tests, one for each way a settle can fail.
//!
//! A body that has already arrived in full, as a short `stream: false` answer does with its head,
//! may be read out and the connection kept for reuse instead; nothing is still generating by then.
//! All of this is hyper's HTTP/1 client, which is all
//! [`OllamaUpstream`](crate::upstream::OllamaUpstream) builds. Under HTTP/2 a drop would reset the
//! stream rather than close the connection.
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
//! facilitator's gets a 502, except an upstream too slow for the payment's window, which gets a
//! 504. A payment that was never actually evaluated must never come back looking like a rejected
//! one.
//!
//! Every 402 carries its challenge twice: base64 in the `PAYMENT-REQUIRED` header, which is the one
//! an x402 v2 client reads, and as the JSON body, for a person with curl. Both are the same object,
//! and both are marked `Cache-Control: no-store`, since a challenge quotes a price for one request.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use serde::Deserialize;

use crate::access::{bearer_token, TokenPath};
use crate::backends::{Backend, Backends, RouteError};
use crate::facilitator::{Facilitator, FacilitatorError};
use crate::pricing::{PriceContext, PriceDeterminer, StaticPrice};
use crate::telemetry::{AccessPath, NoTelemetry, Offer, Outcome, Recorder, Telemetry, Trace};
use crate::upstream::{Upstream, UpstreamResponse};
use crate::arming::ArmedRequirements;
use crate::x402::{
    self, PaymentPayload, PaymentRequired, PaymentRequirements, ResourceInfo, SettlementReceipt,
    UnsupportedTransfer,
};

/// Why a [`Gateway`] could not be built from a set of payment options.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GatewayError {
    /// No options at all. A gateway that accepts nothing can never be paid — it would 402 every
    /// request forever — so it is refused at construction rather than served as a dead route.
    #[error("a gateway must accept at least one payment option, but none were configured")]
    NoPaymentOptions,

    /// Two options share a `(scheme, network)`.
    ///
    /// A payment names the whole option it accepted, and is matched on all of it
    /// ([`PaymentRequirements::is_accepted_by`]), so two options on one network — two assets, say —
    /// could be told apart when a payment arrives. What is not yet settled is whether offering them
    /// is wanted, and what else keys on the network alone; until that is decided (#76), multi-chain
    /// means *distinct networks*, and a configuration that says otherwise is refused rather than
    /// served on an assumption.
    #[error(
        "duplicate payment option: two entries share (scheme, network) = ({scheme}, {network}); \
         obolus advertises at most one option per exact (scheme, network). Network strings are \
         compared verbatim, not case- or whitespace-normalized (a CAIP-2 reference such as Solana's \
         base58 genesis hash is case-sensitive), so canonicalize your ids before configuring them"
    )]
    DuplicateOption { scheme: String, network: String },

    /// An option is for a scheme other than `exact`, the only one this gateway runs. Another scheme
    /// brings its own transfer methods and defaults (EVM `upto` defaults to `permit2`), none of which
    /// the transfer checks here know, so an option naming none would pass them unexamined.
    #[error(
        "payment option for network {network:?} uses scheme {scheme:?}, but obolus runs only \
         {exact:?}",
        exact = x402::SCHEME_EXACT
    )]
    UnsupportedScheme { scheme: String, network: String },

    /// An option names a transfer method or payment flow this gateway does not run. It would still
    /// verify, serve and settle, whatever the option promised, so the option is refused instead.
    #[error("payment option for network {network:?}: {refusal}")]
    UnsupportedTransfer { network: String, refusal: UnsupportedTransfer },

    /// An option's payment window is no longer than [`SETTLE_RESERVE_SECS`], so no upstream would
    /// get any time to answer and every paid request would fail.
    #[error(
        "payment option for network {network:?} advertises maxTimeoutSeconds = \
         {max_timeout_seconds}, but obolus keeps the last {reserve} seconds of every payment's \
         window for settlement, which leaves no time to serve the request; advertise more than \
         {reserve}",
        reserve = SETTLE_RESERVE_SECS
    )]
    WindowTooShort { network: String, max_timeout_seconds: u64 },
}

/// How much of each payment's window is kept back for settlement: the upstream's response head
/// must arrive at least this long before the window closes.
///
/// The window is `maxTimeoutSeconds`, counted from when the paid request reached the handler. The
/// client signed earlier than that (the reference EVM client sets `validBefore` to signing time
/// plus `maxTimeoutSeconds`), so counting from arrival *overstates* the time left. The reserve has
/// to cover:
///
/// - the floor the reference facilitator keeps before `validBefore`: it refuses to settle an
///   authorization with less than 6 s left;
/// - the settle call's trip to the facilitator;
/// - an ordinary gap between signing and arrival, plus the second the reference client can lose by
///   flooring its clock to whole seconds, plus modest clock skew between client and facilitator.
///
/// It cannot cover a gap the client makes arbitrarily long. Arrival is taken after the request body
/// has been read, so a client that uploads slowly spends its own window unseen. If that leaves
/// too little, the head is served and settlement is then refused: that request costs compute and
/// earns nothing, and the client does not receive the answer.
///
/// A live Base Sepolia round trip (#72) took about 10 s end to end, including about 4 s of
/// inference, so 15 s leaves room for a slower facilitator without taking much from a
/// minutes-long window.
///
/// Solana payments expire with their blockhash, not the window. This bound does not model that.
pub const SETTLE_RESERVE_SECS: u64 = 15;

/// A payment-gated route in front of a registry of upstream backends.
///
/// It can advertise several ways to pay at once — one entry per `(scheme, network)`, e.g. Base and
/// Solana — and settles each request against whichever advertised option the client actually paid.
///
/// It holds a [`Backends`] registry rather than a single upstream: each request is routed to a
/// backend by its `model` field (see [`Backends::route`]). A single Ollama origin is the `N = 1`
/// case — a one-entry catch-all registry that serves every model, which is what
/// [`Backends::single_ollama`] and a one-backend config both produce.
pub struct Gateway<F: Facilitator> {
    facilitator: F,
    backends: Arc<Backends>,
    /// What every challenge says is being paid for.
    resource: ResourceInfo,
    /// Non-empty and unique by `(scheme, network)` — enforced by [`Gateway::new`].
    requirements: Vec<PaymentRequirements>,
    /// Decides each request's price. Defaults to [`StaticPrice`] (today's fixed per-option amounts);
    /// [`Gateway::with_price_determiner`] installs a configured rate. Only ever prices the *amount* —
    /// the option set it prices is `requirements`, so it cannot alter which networks are advertised.
    price: Arc<dyn PriceDeterminer>,
    /// Where each request's [`crate::telemetry::RequestEvent`] goes. Defaults to [`NoTelemetry`];
    /// [`Gateway::with_telemetry`] installs a sink.
    telemetry: Arc<dyn Telemetry>,
}

impl<F: Facilitator> Gateway<F> {
    /// Build a gateway advertising `requirements` for `resource`. Fails if the list is empty, if two
    /// entries share a `(scheme, network)`, or if one is not `exact` or names a transfer method or
    /// payment flow this gateway does not run — see [`GatewayError`].
    ///
    /// `resource` has no default: it is the address a payer is told they are paying for, and only
    /// the caller knows where this gateway can be reached.
    ///
    /// The uniqueness and transfer invariants are enforced *here*, at the type that later hands one
    /// of these requirements to `settle`, rather than only at the config boundary — so they hold for
    /// a caller that builds a `Gateway` directly too.
    ///
    /// The arming invariant is enforced by the *parameter type*: an [`ArmedRequirements`] can only
    /// be obtained from [`arming::check_arming`](crate::arming::check_arming), so every option set
    /// that reaches this constructor has passed the guard — either provably testnet, or armed by
    /// name. A caller constructing a `Gateway` directly — the A3 real-facilitator integration
    /// tests, a second binary, an external crate — cannot skip it; there is no other way to produce
    /// the argument. The two invariants are held differently on purpose: uniqueness is a
    /// correctness property with no override, checked here; arming is a deployment policy with a
    /// deliberate, named override, decided by the caller and *witnessed* here by the type.
    /// Neither reads the environment.
    pub fn new(
        facilitator: F,
        backends: Arc<Backends>,
        resource: ResourceInfo,
        requirements: ArmedRequirements,
    ) -> Result<Self, GatewayError> {
        let requirements = requirements.into_requirements();
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
        for option in &requirements {
            if option.scheme != x402::SCHEME_EXACT {
                return Err(GatewayError::UnsupportedScheme {
                    scheme: option.scheme.clone(),
                    network: option.network.clone(),
                });
            }
            if let Some(refusal) = option.unsupported_transfer() {
                return Err(GatewayError::UnsupportedTransfer { network: option.network.clone(), refusal });
            }
            if option.max_timeout_seconds <= SETTLE_RESERVE_SECS {
                return Err(GatewayError::WindowTooShort {
                    network: option.network.clone(),
                    max_timeout_seconds: option.max_timeout_seconds,
                });
            }
        }
        Ok(Self {
            facilitator,
            backends,
            resource,
            requirements,
            price: Arc::new(StaticPrice),
            telemetry: Arc::new(NoTelemetry),
        })
    }

    /// Install a telemetry sink in place of the default [`NoTelemetry`]. Every request that reaches
    /// the completion handler is then recorded to it exactly once — see [`crate::telemetry`].
    pub fn with_telemetry(mut self, telemetry: Arc<dyn Telemetry>) -> Self {
        self.telemetry = telemetry;
        self
    }

    /// How the installed telemetry sink describes itself — read off the sink this gateway will
    /// actually record to, for `main`'s banner.
    pub fn telemetry(&self) -> &str {
        self.telemetry.description()
    }

    /// Install a price determiner in place of the default [`StaticPrice`]. `main` calls this to wire
    /// a configured rate; every other caller (tests, integration harnesses) gets today's fixed
    /// per-option pricing unless it opts in, so the seam changes no quote until it is used.
    pub fn with_price_determiner(mut self, price: Arc<dyn PriceDeterminer>) -> Self {
        self.price = price;
        self
    }

    /// This request's advertised options, each repriced for the routed backend.
    ///
    /// The option set is exactly `requirements` — same `(scheme, network)`, asset, and pay-to — and
    /// only `amount` is replaced, with the determiner's quote for that one option. So the
    /// arming guard still governs which networks are advertised (a determiner prices an option, it
    /// cannot add one), and the amount the 402 quotes is the same amount settlement later charges.
    ///
    /// Built once per paying request and threaded through the challenge and settle path, so every
    /// re-challenge quotes the price the client first saw. Never reached on the token path.
    fn priced(&self, model: Option<&str>, backend: &Backend) -> Vec<PaymentRequirements> {
        self.requirements
            .iter()
            .map(|requirement| {
                let amount = self.price.quote(PriceContext { model, backend, requirement });
                PaymentRequirements { amount: amount.to_string(), ..requirement.clone() }
            })
            .collect()
    }

}

/// The advertised option this payment is for, if any: the one its `accepted` matches in full —
/// scheme, network, amount, asset, pay-to and timeout, and our `extra` keys (see
/// [`PaymentRequirements::is_accepted_by`]).
///
/// `offered` is this request's priced option set (see [`Gateway::priced`]), so a payment for a price
/// no longer quoted matches nothing here; [`repriced_for`] tells that case apart. `Gateway::new`
/// made the `(scheme, network)` pairs unique, so at most one option can match.
fn accepted_for<'a>(
    offered: &'a [PaymentRequirements],
    payment: &PaymentPayload,
) -> Option<&'a PaymentRequirements> {
    offered.iter().find(|r| r.is_accepted_by(payment))
}

/// The offered option this payment would have matched at the amount it carries — so the only thing
/// wrong with it is the price. Worth telling apart from a payment for an option we never offered:
/// that client picked wrong, this one was quoted a price the gateway has since changed, and the
/// remedy is to pay the new one.
fn repriced_for<'a>(
    offered: &'a [PaymentRequirements],
    payment: &PaymentPayload,
) -> Option<&'a PaymentRequirements> {
    let paid = &payment.accepted().amount;
    offered.iter().find(|r| {
        PaymentRequirements { amount: paid.clone(), ..(*r).clone() }.is_accepted_by(payment)
    })
}

/// A 402 carrying *every* option offered for this request, optionally with why the last attempt did
/// not qualify. `offered` is the priced option set (see [`Gateway::priced`]), so the amounts it
/// quotes are the determined prices, not the raw armed ones.
///
/// The challenge goes in the `PAYMENT-REQUIRED` header — the only place an x402 v2 client reads it —
/// and, as the same object, in the JSON body.
fn challenge(resource: &ResourceInfo, offered: &[PaymentRequirements], error: Option<String>) -> Response {
    let mut challenge = PaymentRequired::offering_all(resource.clone(), offered.to_vec());
    if let Some(error) = error {
        challenge = challenge.with_error(error);
    }
    let encoded = x402::encode_payment_required(&challenge);
    let mut response = (StatusCode::PAYMENT_REQUIRED, Json(challenge)).into_response();
    let headers = response.headers_mut();
    // Base64 is always a valid header value, so this cannot fail. Were it ever to, the body alone
    // would still be a 402 a person can read — but no v2 client could pay it, so it is not ignored.
    match HeaderValue::from_str(&encoded) {
        Ok(value) => {
            headers.insert(x402::HEADER_PAYMENT_REQUIRED, value);
        }
        Err(err) => eprintln!("obolus: could not attach {}: {err}", x402::HEADER_PAYMENT_REQUIRED),
    }
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
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

/// The upstream did not answer early enough to settle this payment, so it was not settled and
/// nothing was charged.
///
/// Not a 402: a client that paid again would meet the same wait and the same expiry. A 504 rather
/// than [`upstream_failure`]'s 502, because the upstream may well be working, only too slowly for
/// the window.
fn payment_window_elapsed() -> Response {
    eprintln!("obolus: payment window elapsed before the upstream's response head; not settling");
    (
        StatusCode::GATEWAY_TIMEOUT,
        Json(serde_json::json!({
            "error": "the upstream did not answer within the payment window; nothing was charged",
        })),
    )
        .into_response()
}

async fn health() -> &'static str {
    "ok"
}

/// Just enough of the request body to route on. Every other field is ignored, and the *original*
/// bytes are what gets forwarded — this reads a copy to pick a backend, it never re-serializes the
/// request. `#[serde(default)]` so a body that omits `model` parses to `None` rather than failing.
#[derive(Deserialize)]
struct ModelField {
    #[serde(default)]
    model: Option<String>,
}

/// The `model` the request names, or `None` when it named none — including when the body is not JSON
/// we can read a `model` out of. A `None` routes to a catch-all if one exists (the single-backend
/// case, unchanged from before routing) and is a `400` otherwise; it is never a `500`.
fn requested_model(body: &Bytes) -> Option<String> {
    serde_json::from_slice::<ModelField>(body).ok().and_then(|parsed| parsed.model)
}

/// A routing failure rendered as the client's 4xx. The model name is the client's own input, so
/// echoing it back leaks nothing — unlike [`upstream_failure`], which hides server-side detail.
fn route_failure(err: RouteError) -> Response {
    match err {
        RouteError::UnknownModel { model } => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("no backend serves model {model:?}"),
            })),
        )
            .into_response(),
        RouteError::ModelRequired => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                // Covers all three inputs that resolve to "no model": a body that is not JSON, one
                // with no `model` field, and one whose `model` is not a string — the remedy for each
                // is the same, so the message names it rather than the parse detail behind it.
                "error": "request body must be JSON naming a model in its \"model\" field",
            })),
        )
            .into_response(),
    }
}

/// The paying path. Not an axum handler — [`completion`] is the route, and reaches this when the
/// caller presented no token we honour.
///
/// `priced` is this request's option set with the determined price on each option (see
/// [`Gateway::priced`]) — built once by [`completion`] on the paying path and used for the
/// challenge, the paid-option match, and settlement alike, so a client that retries is quoted the
/// same price it first saw and is charged exactly that.
///
/// Returns the response together with how the request ended, so that every exit has to name an
/// [`Outcome`] — the compiler, not a reviewer, holds "each request is recorded as something". The
/// facts gathered on the way (which option was paid, whether the upstream ran) go into `trace`.
///
/// `arrival` is when the handler first saw this request; the payment window is counted from it.
async fn paid_completion<F: Facilitator>(
    gateway: Arc<Gateway<F>>,
    upstream: Arc<dyn Upstream>,
    priced: Vec<PaymentRequirements>,
    headers: HeaderMap,
    body: Bytes,
    arrival: Instant,
    trace: &mut Trace,
) -> (Response, Outcome) {
    trace.offers = priced.iter().map(Offer::from).collect();
    let resource = &gateway.resource;

    let Some(raw) = headers.get(x402::HEADER_PAYMENT_SIGNATURE) else {
        return (challenge(resource, &priced, None), Outcome::PaymentRequired);
    };
    let Ok(raw) = raw.to_str() else {
        let error = format!("{} must be ASCII base64", x402::HEADER_PAYMENT_SIGNATURE);
        return (challenge(resource, &priced, Some(error)), Outcome::PaymentMalformed);
    };

    let payment = match x402::decode_payment(raw) {
        Ok(payment) => payment,
        Err(err) => {
            return (challenge(resource, &priced, Some(err.to_string())), Outcome::PaymentMalformed)
        }
    };

    // Our own policy check, not the facilitator's: which advertised option did the client pay? None
    // → they paid for an offer we are not making, so re-challenge with everything we DO accept. This
    // is the only place the paid option is chosen, and the *matched* `requirements` — not "the"
    // requirements — is what we verify and settle against.
    let Some(requirements) = accepted_for(&priced, &payment) else {
        let accepted = payment.accepted();
        let error = match repriced_for(&priced, &payment) {
            Some(current) => format!(
                "payment is for {} atomic units, but this resource now costs {} on {}; pay the \
                 amount this challenge quotes",
                accepted.amount, current.amount, current.network,
            ),
            None => format!(
                "payment accepts an option ({} on {}) that does not match any payment option this \
                 resource offers; accept one of the options in this challenge exactly as given",
                accepted.scheme, accepted.network,
            ),
        };
        return (challenge(resource, &priced, Some(error)), Outcome::OptionUnmatched);
    };
    // The option matched, but a client may add `extra` keys — including the two §6.1 reserves for
    // how and when a payment settles. One naming a method or flow this option does not resolve to
    // is paying for something this gateway does not run, so it goes no further than here.
    if let Some(disagreement) = requirements.transfer_disagreement(&payment) {
        let error = format!("{disagreement}; accept the option in this challenge exactly as given");
        return (challenge(resource, &priced, Some(error)), Outcome::OptionUnmatched);
    }
    if let Some(field) = payment.server_owned_extension_field() {
        let error = format!(
            "payment sets extensions.{field}, which only the server may set, and this gateway \
             advertises no extensions"
        );
        return (challenge(resource, &priced, Some(error)), Outcome::OptionUnmatched);
    }
    trace.paid = Some(Offer::from(requirements));

    match gateway.facilitator.verify(&payment, requirements).await {
        Ok(()) => {}
        Err(FacilitatorError::Rejected(reason)) => {
            return (challenge(resource, &priced, Some(reason)), Outcome::VerifyRejected)
        }
        Err(err @ FacilitatorError::Unavailable(_)) => {
            return (upstream_failure(err.to_string()), Outcome::VerifyUnavailable)
        }
    }

    // Payment is good. Commit the upstream BEFORE charging, but only for as long as the payment can
    // still be settled: its head has to arrive before the window, less the settle reserve, runs out.
    // `Gateway::new` refused any window no longer than the reserve, so the subtraction holds.
    let budget = Duration::from_secs(requirements.max_timeout_seconds - SETTLE_RESERVE_SECS);
    let remaining = budget.saturating_sub(arrival.elapsed());
    if remaining.is_zero() {
        return (payment_window_elapsed(), Outcome::PaymentWindowElapsed);
    }
    trace.upstream_invoked = true;
    // Giving up drops the request, which closes its upstream connection; see "Giving up on an
    // upstream" above.
    let response = match tokio::time::timeout(remaining, upstream.forward(body)).await {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => return (upstream_failure(err.to_string()), Outcome::UpstreamUnavailable),
        Err(_) => return (payment_window_elapsed(), Outcome::PaymentWindowElapsed),
    };
    trace.upstream_status = Some(response.status.as_u16());
    if !response.status.is_success() {
        // The upstream refused: charge nothing, and hand its answer back the same way every other
        // response here is built. Constructing it as `(status, body)` instead drops the upstream's
        // content type, so an identical `503 {"error":..}` reaches a paying client untyped and a
        // token-holder as `application/json` — a divergence between the paid and unpaid paths on
        // the very axis this module exists to close.
        return (proxy_response(response, None), Outcome::UpstreamRefused);
    }

    trace.settle_attempted = true;
    let receipt = match gateway.facilitator.settle(&payment, requirements).await {
        Ok(receipt) if receipt.success => receipt,
        // A receipt that reports its own failure is a refusal, not a success. Serving the
        // response on the strength of `Ok(_)` alone would give the work away for free.
        Ok(_) => {
            let error = "settlement did not complete".to_string();
            return (challenge(resource, &priced, Some(error)), Outcome::SettleRejected);
        }
        // The same split as verify. Returning 502 for a payment the facilitator actually
        // evaluated and refused would be both a lie and the more dangerous lie: 502 reads as
        // transient, so clients retry it harder than they retry a 402.
        Err(FacilitatorError::Rejected(reason)) => {
            return (challenge(resource, &priced, Some(reason)), Outcome::SettleRejected)
        }
        Err(err @ FacilitatorError::Unavailable(_)) => {
            return (upstream_failure(err.to_string()), Outcome::SettleUnavailable)
        }
    };
    // The receipt's "no transaction" is the empty string; telemetry's is absence.
    trace.transaction = Some(receipt.transaction.clone()).filter(|t| !t.is_empty());

    (proxy_response(response, Some(&receipt)), Outcome::Settled)
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
pub struct Access<F: Facilitator> {
    /// `None` switches the token path off entirely and every request pays — which is what an
    /// instance with no verifying key configured does, and is the behaviour to fall back to.
    token: Option<TokenPath>,
    gateway: Arc<Gateway<F>>,
}

impl<F: Facilitator> Access<F> {
    pub fn new(gateway: Gateway<F>, token: Option<TokenPath>) -> Self {
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

    /// How the telemetry sink this instance will actually record to describes itself. Same reason
    /// as [`Access::token_path`]: the banner is keyed on the routed value, not the configuration.
    pub fn telemetry(&self) -> &str {
        self.gateway.telemetry()
    }
}

/// Serve a caller we recognise; charge one we do not — and record what happened.
///
/// The route itself only records: [`serve`] decides the response and the outcome, and the
/// [`Recorder`] emits the request's one event when it is dropped. That drop happens here on a
/// finished request, and wherever the future is suspended on one the server cancels because the
/// client went away — so a request is recorded exactly once either way.
async fn completion<F: Facilitator>(
    State(access): State<Arc<Access<F>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Taken first, before routing or anything else can spend the payment's window. The body has
    // already been read by now, so its upload is not counted; see `SETTLE_RESERVE_SECS`.
    let arrival = Instant::now();
    let mut recorder = Recorder::new(access.gateway.telemetry.clone());
    let (response, outcome) = serve(&access, headers, body, arrival, &mut recorder.trace).await;
    recorder.complete(outcome);
    response
}

async fn serve<F: Facilitator>(
    access: &Arc<Access<F>>,
    headers: HeaderMap,
    body: Bytes,
    arrival: Instant,
    trace: &mut Trace,
) -> (Response, Outcome) {
    // Route before anything else. An unroutable request is refused here — before the token check
    // and before any payment — so it is never charged (Obolus has no refund path), and both the
    // recognised-caller path and the paying path forward to the same backend the model resolves to.
    let model = requested_model(&body);
    trace.model = model.clone();
    let backend = match access.gateway.backends.route(model.as_deref()) {
        Ok(backend) => backend,
        Err(err) => return (route_failure(err), Outcome::Unroutable),
    };
    trace.backend = Some(backend.id.clone());
    trace.backend_cost = backend.cost;
    let upstream = backend.upstream();

    if let (Some(path), Some(token)) = (&access.token, bearer_token(&headers)) {
        match path.verify(token) {
            Ok(()) => {
                trace.access = Some(AccessPath::Token);
                trace.upstream_invoked = true;
                let response = match upstream.forward(body).await {
                    Ok(response) => response,
                    Err(err) => {
                        return (upstream_failure(err.to_string()), Outcome::UpstreamUnavailable)
                    }
                };
                trace.upstream_status = Some(response.status.as_u16());
                // Proxied either way; the outcome only says which it was.
                let outcome = if response.status.is_success() {
                    Outcome::Served
                } else {
                    Outcome::UpstreamRefused
                };
                return (proxy_response(response, None), outcome);
            }
            // Every failure lands here, including a verifier that could not evaluate the token at
            // all, and every one of them continues to the paying path. The response then says
            // nothing about the token: naming why it failed would hand an attacker a probing
            // oracle against a gateway whose other path is anonymous by design.
            Err(err) => eprintln!("obolus: bearer token not honoured: {err}"),
        }
    }
    // Price this request now — on the paying path only. The token path returned above without ever
    // calling the determiner, so a recognised caller's request cannot reach `quote` and a determiner
    // fault can never turn a free, honoured request into a 500. The determined prices are quoted in
    // the challenge and charged at settlement (see [`paid_completion`]).
    trace.access = Some(AccessPath::Payment);
    let priced = access.gateway.priced(model.as_deref(), backend);
    paid_completion(access.gateway.clone(), upstream, priced, headers, body, arrival, trace).await
}

/// Wire an access surface into an OpenAI-compatible route plus an ungated health check.
///
/// Takes the constructed [`Access`] rather than its parts so that whatever `main` printed about the
/// token path was read off the same value that lands here.
pub fn router<F: Facilitator>(access: Access<F>) -> Router {
    Router::new()
        // Ungated on purpose: liveness is not a paid service, and a health check that needs a
        // wallet is a health check nothing can call.
        .route("/health", get(health))
        .route("/v1/chat/completions", post(completion::<F>))
        .with_state(Arc::new(access))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::FakeTokenVerifier;
    use crate::backends::Backend;
    use crate::facilitator::{FakeCalls, FakeFacilitator};
    use crate::pricing::{CostPlus, FlatPrice, Promotional, StaticPrice};
    use crate::telemetry::{FakeTelemetry, RequestEvent};
    use crate::upstream::{FakeUpstream, OllamaUpstream, UpstreamCalls};
    use crate::arming::{check_arming, is_provably_testnet};
    use crate::x402::{PaymentPayload, SettlementReceipt, SCHEME_EXACT, X402_VERSION};
    use serde_json::json;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    /// A one-backend catch-all registry wrapping `upstream`. Most tests here predate routing and do
    /// not care which backend serves; a sole catch-all takes every request, so the request `model`
    /// is irrelevant and the wiring matches the pre-routing single-upstream gateway.
    fn one_backend(upstream: impl Upstream + 'static) -> Arc<Backends> {
        Arc::new(Backends::from_parts(vec![Backend::for_test(
            "default",
            vec![],
            None,
            Arc::new(upstream),
        )]))
    }

    /// Obviously-synthetic fixtures — not real networks, addresses, or transactions.
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

    fn resource() -> ResourceInfo {
        ResourceInfo {
            url: "http://localhost:8402/v1/chat/completions".to_string(),
            description: Some("One inference request".to_string()),
            mime_type: Some("application/json".to_string()),
        }
    }

    /// A payment accepting `accepted`, with a payload Phase A never opens.
    fn paying(accepted: PaymentRequirements) -> PaymentPayload {
        let payload = json!({ "authorization": "opaque-to-phase-a" });
        PaymentPayload::new(None, accepted, payload.as_object().unwrap().clone())
    }

    /// A payment for the advertised option, exactly as offered.
    fn payment() -> PaymentPayload {
        paying(requirements())
    }

    /// Pass `reqs` through the arming guard, arming by name every network it cannot prove testnet.
    ///
    /// This suite tests payment flow, not arming policy — the fixture networks are deliberately
    /// not real CAIP-2 ids, so every one of them is unproven, and a `Gateway` cannot be built
    /// without the guard's witness. Arming them all is the honest statement of what these tests
    /// are about; the guard's own behaviour is `arming.rs`'s to test. Duplicate entries are kept
    /// (`new` is what rejects them) and named once.
    fn armed(reqs: Vec<PaymentRequirements>) -> ArmedRequirements {
        let mut unproven: Vec<String> = Vec::new();
        for r in &reqs {
            if !is_provably_testnet(&r.network) && !unproven.contains(&r.network) {
                unproven.push(r.network.clone());
            }
        }
        check_arming(&reqs, &unproven).expect("arming every unproven fixture network by name")
    }

    /// The wired router plus a handle on what the facilitator was actually asked to do.
    ///
    /// Needed because "we did not charge" is invisible in the response: a gateway that settled
    /// eagerly and then hit an upstream error returns the same status and the same missing
    /// receipt header as one that correctly never charged.
    fn app_with(facilitator: FakeFacilitator, upstream: FakeUpstream) -> (Router, FakeCalls) {
        let calls = facilitator.calls();
        let gateway =
            Gateway::new(facilitator, one_backend(upstream), resource(), armed(vec![requirements()])).unwrap();
        (router(Access::new(gateway, None)), calls)
    }

    /// Like [`app_with`], but with a price determiner installed in place of the default
    /// [`StaticPrice`] — for asserting that the determined price, not the raw armed amount, is what
    /// the challenge quotes and settlement charges.
    fn app_priced_with(
        facilitator: FakeFacilitator,
        upstream: FakeUpstream,
        price: Arc<dyn PriceDeterminer>,
    ) -> (Router, FakeCalls) {
        let calls = facilitator.calls();
        let gateway = Gateway::new(facilitator, one_backend(upstream), resource(), armed(vec![requirements()]))
            .unwrap()
            .with_price_determiner(price);
        (router(Access::new(gateway, None)), calls)
    }

    #[tokio::test]
    async fn the_challenge_quotes_the_determined_price_not_the_armed_amount() {
        // The armed option carries amount = "1000"; a flat determiner of 777 must
        // override it. This is the whole point of the seam: the 402 quotes the *determined* price.
        let (app, _) = app_priced_with(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            Arc::new(FlatPrice::new(777)),
        );
        let (status, _, body) = send(app, completion_request(None)).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["accepts"][0]["amount"], serde_json::json!("777"));
        // The determiner prices only the amount — network and pay-to are still the armed option's,
        // because a determiner cannot touch which network is advertised.
        assert_eq!(json["accepts"][0]["network"], serde_json::json!(FIXTURE_NETWORK));
        assert_eq!(json["accepts"][0]["payTo"], serde_json::json!(FIXTURE_PAY_TO));
    }

    #[tokio::test]
    async fn a_cost_plus_rate_quotes_cost_plus_margin_in_the_challenge() {
        // The rate `main` installs for OBOLUS_PRICING=cost-plus, exercised end to end: unlike the
        // flat cases above, the quoted amount is *computed* (cost + margin), so this proves
        // CostPlus's arithmetic reaches a real 402 through the seam, not just its unit tests. The
        // cost lives on the backend now (the config door guarantees one at boot), so the backend
        // carries 1000; marked up 2500 bps (25%) it must quote 1250.
        let backend = Backend::for_test("default", vec![], None, Arc::new(FakeUpstream::streaming()))
            .with_cost(1000);
        let gateway = Gateway::new(
            FakeFacilitator::accepting(),
            Arc::new(Backends::from_parts(vec![backend])),
            resource(),
            armed(vec![requirements()]),
        )
        .unwrap()
        .with_price_determiner(Arc::new(CostPlus::new(2500)));
        let app = router(Access::new(gateway, None));
        let (status, _, body) = send(app, completion_request(None)).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["accepts"][0]["amount"], serde_json::json!("1250"));
    }

    #[tokio::test]
    async fn a_promotional_rate_discounts_the_challenge() {
        // The promo modifier reaching a real 402 through the seam — the analogue of the cost-plus
        // challenge test above, and the coverage the per-rate house pattern requires. A determiner
        // installed and quoting in isolation is not the same as one whose discounted amount actually
        // lands in the advertised challenge; this asserts the latter. Promotional wraps the default
        // StaticPrice (which quotes the armed "1000") with an open window [0, u64::MAX) so the
        // discount is live, and 2500 bps off 1000 must quote 750 — not the armed amount, not the
        // undiscounted base.
        let (app, _) = app_priced_with(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            Arc::new(Promotional::new(2500, 0, u64::MAX, Arc::new(StaticPrice))),
        );
        let (status, _, body) = send(app, completion_request(None)).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["accepts"][0]["amount"], serde_json::json!("750"));
        // The discount prices only the amount — the armed network and pay-to are untouched, as for
        // every determiner.
        assert_eq!(json["accepts"][0]["network"], serde_json::json!(FIXTURE_NETWORK));
        assert_eq!(json["accepts"][0]["payTo"], serde_json::json!(FIXTURE_PAY_TO));
    }

    #[tokio::test]
    async fn settlement_charges_the_determined_price() {
        // A paid request must be settled against the determined price, not the armed "1000" — the
        // challenge and the charge have to agree, or a client pays a number it was never quoted.
        let (app, calls) = app_priced_with(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            Arc::new(FlatPrice::new(777)),
        );
        let quoted = paying(PaymentRequirements { amount: "777".to_string(), ..requirements() });
        let (status, _, _) =
            send(app, completion_request(Some(&x402::encode_payment(&quoted)))).await;
        assert_eq!(status, StatusCode::OK);
        let settled = calls.settled_requirements();
        assert_eq!(settled.len(), 1, "exactly one settlement");
        assert_eq!(settled[0].amount, "777", "at the determined price");
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
        let gateway =
            Gateway::new(facilitator, one_backend(upstream), resource(), armed(vec![requirements()])).unwrap();
        let token = TokenPath::new(Arc::new(verifier));
        (router(Access::new(gateway, Some(token))), calls, forwards)
    }

    fn completion_request(payment_header: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("POST").uri("/v1/chat/completions");
        if let Some(header) = payment_header {
            builder = builder.header(x402::HEADER_PAYMENT_SIGNATURE, header);
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

    /// The 402's two copies of its challenge must be one object: the `PAYMENT-REQUIRED` header
    /// (what a v2 client reads) decodes to exactly the JSON body (what a person reads), and the
    /// response is marked uncacheable. Returns the decoded challenge.
    fn assert_challenge_headers(headers: &HeaderMap, body: &str) -> PaymentRequired {
        let raw = headers
            .get(x402::HEADER_PAYMENT_REQUIRED)
            .expect("every 402 carries PAYMENT-REQUIRED")
            .to_str()
            .unwrap();
        let from_header = x402::decode_payment_required(raw).expect("a v2 challenge");
        let from_body: PaymentRequired = serde_json::from_str(body).unwrap();
        assert_eq!(from_header, from_body, "header and body must carry the same challenge");
        assert_eq!(
            headers.get(header::CACHE_CONTROL).map(|v| v.to_str().unwrap()),
            Some("no-store"),
            "a challenge quotes a price for one request and must not be cached"
        );
        from_header
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
        let (status, headers, body) =
            send(app(FakeFacilitator::accepting(), FakeUpstream::streaming()), completion_request(None))
                .await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["x402Version"], serde_json::json!(X402_VERSION));
        assert_eq!(json["resource"], serde_json::to_value(resource()).unwrap());
        assert_eq!(json["accepts"][0]["payTo"], serde_json::json!(FIXTURE_PAY_TO));
        assert_eq!(json["accepts"][0]["amount"], serde_json::json!("1000"));
        assert!(json.get("error").is_none(), "a first request has nothing to apologise for");
        let challenge = assert_challenge_headers(&headers, &body);
        assert_eq!(challenge.accepts, vec![requirements()]);
    }

    #[tokio::test]
    async fn a_rechallenge_carries_the_header_too() {
        // The header is not only for the first 402: a client whose payment was refused reads the
        // next challenge — and the reason — from the same place.
        let (status, headers, body) = send(
            app(FakeFacilitator::rejecting("insufficient_funds"), FakeUpstream::streaming()),
            completion_request(Some(&x402::encode_payment(&payment()))),
        )
        .await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let challenge = assert_challenge_headers(&headers, &body);
        assert_eq!(challenge.error.as_deref(), Some("insufficient_funds"));
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
        let wrong = paying(PaymentRequirements {
            network: "some-other-network".to_string(),
            ..requirements()
        });
        let (app, calls) = app_with(FakeFacilitator::accepting(), FakeUpstream::streaming());
        let (status, headers, body) =
            send(app, completion_request(Some(&x402::encode_payment(&wrong)))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        assert!(challenge_error(&body).unwrap().contains("some-other-network"));
        assert_challenge_headers(&headers, &body);
        assert_eq!(calls.verifies(), 0, "a payment for no offered option is never verified");
    }

    #[tokio::test]
    async fn a_payment_differing_from_the_offer_in_any_field_is_refused() {
        // The whole option is matched, not its (scheme, network): a payment that echoes our network
        // but names another asset or recipient is not for anything we offered. Under v1's
        // (scheme, network) matching every one of these would have reached the facilitator.
        for (field, accepted) in [
            ("asset", PaymentRequirements { asset: "0xOTHER-ASSET".to_string(), ..requirements() }),
            ("payTo", PaymentRequirements { pay_to: "0xOTHER-PAYEE".to_string(), ..requirements() }),
            ("maxTimeoutSeconds", PaymentRequirements { max_timeout_seconds: 61, ..requirements() }),
        ] {
            let (app, calls) = app_with(FakeFacilitator::accepting(), FakeUpstream::streaming());
            let (status, _, body) =
                send(app, completion_request(Some(&x402::encode_payment(&paying(accepted))))).await;
            assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{field}");
            assert!(
                challenge_error(&body).unwrap().contains("does not match any payment option"),
                "{field}: {body}"
            );
            assert_eq!(calls.verifies(), 0, "{field}: never verified");
        }
    }

    #[tokio::test]
    async fn a_payment_naming_a_flow_this_option_does_not_run_is_refused_before_the_facilitator() {
        // The option names no flow, so the client's added `paymentFlow` passes the extra-subset
        // match; it is the transfer check that refuses it.
        let upfront = paying(PaymentRequirements {
            extra: Some(serde_json::json!({ "paymentFlow": "upfront" })),
            ..requirements()
        });
        let (app, calls) = app_with(FakeFacilitator::accepting(), FakeUpstream::streaming());
        let (status, headers, body) =
            send(app, completion_request(Some(&x402::encode_payment(&upfront)))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let error = challenge_error(&body).unwrap();
        assert!(error.contains("extra.paymentFlow") && error.contains("upfront"), "{error}");
        assert_challenge_headers(&headers, &body);
        assert_eq!((calls.verifies(), calls.settles()), (0, 0), "the facilitator never sees it");

        let request = completion_request(Some(&x402::encode_payment(&upfront)));
        let event = recorded(FakeFacilitator::accepting(), FakeUpstream::streaming(), request).await;
        assert_eq!(event.outcome, Outcome::OptionUnmatched);
        assert_eq!(event.paid, None);
        assert!(!event.upstream_invoked);
    }

    #[tokio::test]
    async fn a_payment_setting_a_server_owned_extension_field_is_refused_before_the_facilitator() {
        let mut sent = serde_json::to_value(payment()).unwrap();
        sent["extensions"] = serde_json::json!({ "builder-code": { "info": { "a": "not-ours" } } });
        let header = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(sent.to_string())
        };
        let (app, calls) = app_with(FakeFacilitator::accepting(), FakeUpstream::streaming());
        let (status, headers, body) = send(app, completion_request(Some(&header))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let error = challenge_error(&body).unwrap();
        assert!(error.contains("extensions.builder-code.info.a"), "{error}");
        assert_challenge_headers(&headers, &body);
        assert_eq!((calls.verifies(), calls.settles()), (0, 0), "the facilitator never sees it");
    }

    #[tokio::test]
    async fn a_payment_at_a_price_no_longer_quoted_is_told_the_price_changed() {
        // Everything matches but the amount — the client paid a price the gateway has since moved
        // off. It is re-challenged, told so, and nothing is verified or charged.
        let stale = paying(PaymentRequirements { amount: "900".to_string(), ..requirements() });
        let (app, calls) = app_with(FakeFacilitator::accepting(), FakeUpstream::streaming());
        let (status, headers, body) =
            send(app, completion_request(Some(&x402::encode_payment(&stale)))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let error = challenge_error(&body).unwrap();
        assert!(error.contains("900") && error.contains("now costs 1000"), "{error}");
        assert_eq!(assert_challenge_headers(&headers, &body).accepts[0].amount, "1000");
        assert_eq!(calls.verifies(), 0);
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
                error_reason: None,
                transaction: "0xTEST-TX-HASH-NOT-A-REAL-TRANSACTION".to_string(),
                network: FIXTURE_NETWORK.to_string(),
                payer: None,
                amount: None,
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

    // --- multi-chain: many advertised options, client picks one ----------------------------------

    /// A second advertised option on a DISTINCT network, with its own asset and pay-to, so a test
    /// can tell *which* option the gateway settled against — not merely that it settled.
    const FIXTURE_NETWORK_B: &str = "test-network-b-not-a-real-caip2";
    const FIXTURE_PAY_TO_B: &str = "0xTEST-PAY-TO-B-NOT-REAL";
    const FIXTURE_ASSET_B: &str = "0xTEST-ASSET-B-NOT-REAL";

    fn requirements_b() -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: FIXTURE_NETWORK_B.to_string(),
            amount: "2000".to_string(),
            asset: FIXTURE_ASSET_B.to_string(),
            pay_to: FIXTURE_PAY_TO_B.to_string(),
            max_timeout_seconds: 60,
            extra: None,
        }
    }

    fn payment_b() -> PaymentPayload {
        paying(requirements_b())
    }

    /// A gateway advertising option A (`requirements()`) THEN option B (`requirements_b()`).
    fn multichain_app_with(
        facilitator: FakeFacilitator,
        upstream: FakeUpstream,
    ) -> (Router, FakeCalls) {
        let calls = facilitator.calls();
        (
            router(Access::new(
                Gateway::new(
                    facilitator,
                    one_backend(upstream),
                    resource(),
                    armed(vec![requirements(), requirements_b()]),
                )
                .unwrap(),
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
        assert_eq!(settled[0].amount, "2000", "and its price");
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
        let wrong = paying(PaymentRequirements {
            network: "test-network-c-unlisted".to_string(),
            ..requirements()
        });
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
            Gateway::new(
                calls_holder,
                one_backend(FakeUpstream::streaming()),
                resource(),
                armed(vec![requirements_b(), short_name.clone()]),
            )
            .unwrap(),
            None,
        ));

        let pay_short_name = paying(short_name);
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
        let err = Gateway::new(
            FakeFacilitator::accepting(),
            one_backend(FakeUpstream::streaming()),
            resource(),
            armed(vec![]),
        )
        .err()
        .expect("an empty option list must be rejected");
        assert!(matches!(err, GatewayError::NoPaymentOptions), "got {err:?}");
    }

    #[test]
    fn new_rejects_two_options_sharing_scheme_and_network() {
        // Same (scheme, network), different asset. A v2 payment could tell these apart, but offering
        // both is refused until #76 decides whether it is wanted. The guard must bite at
        // construction — this asserts it does rather than assuming it. (`.err()` not `.unwrap_err()`
        // for the same reason as above: `Gateway` is not `Debug`, its error is.)
        let mut dup = requirements();
        dup.asset = "0xDIFFERENT-ASSET-SAME-NETWORK-NOT-REAL".to_string();
        let err = Gateway::new(
            FakeFacilitator::accepting(),
            one_backend(FakeUpstream::streaming()),
            resource(),
            armed(vec![requirements(), dup]),
        )
        .err()
        .expect("duplicate (scheme, network) must be rejected");
        assert!(matches!(err, GatewayError::DuplicateOption { .. }), "got {err:?}");
    }

    #[test]
    fn construction_refuses_an_option_naming_a_flow_or_method_this_gateway_does_not_run() {
        // The configuration doors refuse these too, but a caller building options directly never
        // passes through them. An option promising `upfront` would still be verified, served and
        // settled — so it is refused here, where every gateway is built.
        for (key, value) in [("paymentFlow", "upfront"), ("assetTransferMethod", "permit2")] {
            let option = PaymentRequirements {
                extra: Some(serde_json::json!({ key: value })),
                ..requirements()
            };
            let err = Gateway::new(
                FakeFacilitator::accepting(),
                one_backend(FakeUpstream::streaming()),
                resource(),
                // Second, behind a clean option: every option is checked, not only the first.
                armed(vec![
                    PaymentRequirements {
                        network: "test-network-b-not-a-real-caip2".to_string(),
                        ..requirements()
                    },
                    option,
                ]),
            )
            .err()
            .unwrap_or_else(|| panic!("extra.{key} = {value:?} must be refused"));
            assert!(
                matches!(&err, GatewayError::UnsupportedTransfer { refusal, .. } if refusal.key == key),
                "got {err:?}"
            );
            assert!(err.to_string().contains(&format!("extra.{key} = \"{value}\"")), "{err}");
        }
        let authorization = PaymentRequirements {
            extra: Some(serde_json::json!({ "paymentFlow": "authorization" })),
            ..requirements()
        };
        let built = Gateway::new(
            FakeFacilitator::accepting(),
            one_backend(FakeUpstream::streaming()),
            resource(),
            armed(vec![authorization]),
        );
        assert!(built.is_ok(), "the flow obolus runs is accepted");
    }

    #[test]
    fn construction_refuses_a_scheme_other_than_exact_even_naming_no_method() {
        // EVM `upto` resolves an unnamed method to `permit2` in the reference; the transfer checks
        // know no `upto` default, so only the scheme itself can stop it.
        let upto = PaymentRequirements { scheme: "upto".to_string(), ..requirements() };
        assert_eq!(upto.unsupported_transfer(), None, "names no method, so passes that check");
        let err = Gateway::new(
            FakeFacilitator::accepting(),
            one_backend(FakeUpstream::streaming()),
            resource(),
            armed(vec![upto]),
        )
        .err()
        .expect("a non-exact scheme must be refused");
        assert!(
            matches!(&err, GatewayError::UnsupportedScheme { scheme, .. } if scheme == "upto"),
            "got {err:?}"
        );
        assert!(err.to_string().contains("obolus runs only \"exact\""), "{err}");
    }

    // ---- the access branch (#33) ----
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
            let gateway = Gateway::new(
                FakeFacilitator::accepting(),
                one_backend(upstream),
                resource(),
                armed(vec![requirements()]),
            )
            .unwrap();
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

    // ---- model routing across backends (#56) ----

    /// A gateway over two named backends, each a distinguishable fake. The two upstream call-counts
    /// are the positive evidence of *which* backend a request reached — a 200 alone cannot say that.
    fn app_two_backends() -> (Router, FakeCalls, UpstreamCalls, UpstreamCalls) {
        let facilitator = FakeFacilitator::accepting();
        let calls = facilitator.calls();
        let a = FakeUpstream::streaming();
        let b = FakeUpstream::streaming();
        let a_calls = a.calls();
        let b_calls = b.calls();
        let backends = Arc::new(Backends::from_parts(vec![
            Backend::for_test("a", vec!["llama3"], None, Arc::new(a)),
            Backend::for_test("b", vec!["mistral"], None, Arc::new(b)),
        ]));
        let gateway =
            Gateway::new(facilitator, backends, resource(), armed(vec![requirements()])).unwrap();
        (router(Access::new(gateway, None)), calls, a_calls, b_calls)
    }

    /// A paid completion request naming `model`.
    fn paid_request_for_model(model: &str) -> Request<Body> {
        let body = format!(r#"{{"model":{model:?},"messages":[]}}"#);
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(x402::HEADER_PAYMENT_SIGNATURE, x402::encode_payment(&payment()))
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn a_request_reaches_the_backend_that_serves_its_model() {
        // DoD item 4: the OpenAI-compatible route now selects a backend by the request's model.
        let (app, _calls, a_calls, b_calls) = app_two_backends();
        let (status, _headers, body) = send(app, paid_request_for_model("mistral")).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, FakeUpstream::streamed_text(), "the serving backend's answer reached the client");
        assert_eq!(b_calls.count(), 1, "the backend that lists mistral was reached");
        assert_eq!(a_calls.count(), 0, "the backend that lists only llama3 was not");
    }

    #[tokio::test]
    async fn an_unknown_model_is_a_404_charging_nothing() {
        // DoD item 2, and the resolve-before-pay property: a VALID payment rides along, but the model
        // is unroutable, so the request is refused BEFORE verify/settle — the client is never charged
        // for a request no backend could serve (Obolus has no refund path).
        let (app, calls, a_calls, b_calls) = app_two_backends();
        let (status, _headers, _body) = send(app, paid_request_for_model("gpt-4")).await;

        assert_eq!(status, StatusCode::NOT_FOUND, "a clean 4xx, never a 500 or a panic");
        assert_eq!(a_calls.count() + b_calls.count(), 0, "no backend was reached");
        assert_eq!(calls.verifies(), 0, "the payment was never even verified");
        assert_eq!(calls.settles(), 0, "and nothing was settled — an unroutable request costs nothing");
    }

    #[tokio::test]
    async fn a_request_naming_no_model_is_a_400_when_every_backend_is_named() {
        // With only named backends there is no catch-all to take a request that named no model, so it
        // is a clean 400 — again before any charge.
        let (app, calls, a_calls, b_calls) = app_two_backends();
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(x402::HEADER_PAYMENT_SIGNATURE, x402::encode_payment(&payment()))
            .body(Body::from(r#"{"messages":[]}"#))
            .unwrap();
        let (status, _headers, _body) = send(app, request).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(a_calls.count() + b_calls.count(), 0, "no backend was reached");
        assert_eq!(calls.verifies(), 0, "and nothing was charged");
    }

    // ---- telemetry (#58) ----

    /// The declared cost of the backend every telemetry test routes to — distinct from the armed
    /// amount (1000), so a test can tell cost from revenue in the record.
    const TEST_COST: u128 = 800;

    /// A gateway over one costed catch-all backend, recording to a fake sink, with the token path on
    /// when `verifier` is given.
    fn app_recording(
        facilitator: FakeFacilitator,
        upstream: FakeUpstream,
        verifier: Option<FakeTokenVerifier>,
    ) -> (Router, FakeTelemetry) {
        let sink = FakeTelemetry::default();
        let backend =
            Backend::for_test("default", vec![], None, Arc::new(upstream)).with_cost(TEST_COST);
        let gateway = Gateway::new(
            facilitator,
            Arc::new(Backends::from_parts(vec![backend])),
            resource(),
            armed(vec![requirements()]),
        )
        .unwrap()
        .with_telemetry(Arc::new(sink.clone()));
        let token = verifier.map(|verifier| TokenPath::new(Arc::new(verifier)));
        (router(Access::new(gateway, token)), sink)
    }

    /// Send `request` and return the one event it produced. [`FakeTelemetry::only`] fails the test
    /// on zero or several, so every test below also checks "recorded exactly once".
    async fn recorded(
        facilitator: FakeFacilitator,
        upstream: FakeUpstream,
        request: Request<Body>,
    ) -> RequestEvent {
        let (app, sink) = app_recording(facilitator, upstream, None);
        send(app, request).await;
        sink.only()
    }

    fn paid_request() -> Request<Body> {
        completion_request(Some(&x402::encode_payment(&payment())))
    }

    fn quoted() -> Offer {
        Offer::from(&requirements())
    }

    #[tokio::test]
    async fn a_settled_request_records_revenue_cost_and_the_transaction() {
        let event =
            recorded(FakeFacilitator::accepting(), FakeUpstream::streaming(), paid_request()).await;
        assert_eq!(
            event,
            RequestEvent {
                ts_ms: event.ts_ms,
                outcome: Outcome::Settled,
                access: Some(AccessPath::Payment),
                backend: Some("default".to_string()),
                model: Some("test".to_string()),
                offers: vec![quoted()],
                paid: Some(quoted()),
                upstream_invoked: true,
                upstream_status: Some(200),
                cost: Some(TEST_COST.to_string()),
                revenue: Some("1000".to_string()),
                transaction: Some("0xTEST-TX-HASH-NOT-A-REAL-TRANSACTION".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn the_recorded_offer_is_the_determined_price_not_the_armed_amount() {
        let sink = FakeTelemetry::default();
        let gateway = Gateway::new(
            FakeFacilitator::accepting(),
            one_backend(FakeUpstream::streaming()),
            resource(),
            armed(vec![requirements()]),
        )
        .unwrap()
        .with_price_determiner(Arc::new(FlatPrice::new(777)))
        .with_telemetry(Arc::new(sink.clone()));
        let quoted = paying(PaymentRequirements { amount: "777".to_string(), ..requirements() });
        let request = completion_request(Some(&x402::encode_payment(&quoted)));
        send(router(Access::new(gateway, None)), request).await;
        let event = sink.only();
        assert_eq!(event.offers[0].amount, "777");
        assert_eq!(event.revenue.as_deref(), Some("777"), "revenue is what settlement charged");
    }

    #[tokio::test]
    async fn an_unpaid_request_records_the_quote_and_costs_nothing() {
        let event =
            recorded(FakeFacilitator::accepting(), FakeUpstream::streaming(), completion_request(None))
                .await;
        assert_eq!(event.outcome, Outcome::PaymentRequired);
        assert_eq!(event.offers, vec![quoted()], "the price quoted is recorded");
        assert_eq!(event.paid, None);
        assert!(!event.upstream_invoked);
        assert_eq!(event.cost.as_deref(), Some("0"));
        assert_eq!(event.revenue.as_deref(), Some("0"));
    }

    #[tokio::test]
    async fn a_malformed_payment_is_recorded_as_such() {
        let request = completion_request(Some("not-base64!!"));
        let event = recorded(FakeFacilitator::accepting(), FakeUpstream::streaming(), request).await;
        assert_eq!(event.outcome, Outcome::PaymentMalformed);
        assert!(!event.upstream_invoked);
    }

    #[tokio::test]
    async fn a_payment_for_an_unoffered_option_is_recorded_as_unmatched() {
        let elsewhere = paying(PaymentRequirements {
            network: "some-other-network".to_string(),
            ..requirements()
        });
        let request = completion_request(Some(&x402::encode_payment(&elsewhere)));
        let event = recorded(FakeFacilitator::accepting(), FakeUpstream::streaming(), request).await;
        assert_eq!(event.outcome, Outcome::OptionUnmatched);
        assert_eq!(event.paid, None);
    }

    #[tokio::test]
    async fn a_rejected_verify_records_the_paid_option_but_no_cost() {
        let event =
            recorded(FakeFacilitator::rejecting("bad sig"), FakeUpstream::streaming(), paid_request())
                .await;
        assert_eq!(event.outcome, Outcome::VerifyRejected);
        assert_eq!(event.paid, Some(quoted()));
        assert!(!event.upstream_invoked);
        assert_eq!(event.cost.as_deref(), Some("0"));
    }

    #[tokio::test]
    async fn an_unavailable_verify_is_recorded_as_such() {
        let facilitator = FakeFacilitator::unavailable("connection refused");
        let event = recorded(facilitator, FakeUpstream::streaming(), paid_request()).await;
        assert_eq!(event.outcome, Outcome::VerifyUnavailable);
        assert!(!event.upstream_invoked);
    }

    #[tokio::test]
    async fn an_unreachable_upstream_still_costs_what_was_declared() {
        // The forward was attempted; whether the backend billed for it is not knowable from here, so
        // the declared cost is charged against the request.
        let upstream = FakeUpstream::unreachable("connection refused");
        let event = recorded(FakeFacilitator::accepting(), upstream, paid_request()).await;
        assert_eq!(event.outcome, Outcome::UpstreamUnavailable);
        assert!(event.upstream_invoked);
        assert_eq!(event.upstream_status, None);
        assert_eq!(event.cost, Some(TEST_COST.to_string()));
        assert_eq!(event.revenue.as_deref(), Some("0"));
    }

    #[tokio::test]
    async fn a_refusing_upstream_is_recorded_with_its_status() {
        let upstream = FakeUpstream::refusing(StatusCode::SERVICE_UNAVAILABLE);
        let event = recorded(FakeFacilitator::accepting(), upstream, paid_request()).await;
        assert_eq!(event.outcome, Outcome::UpstreamRefused);
        assert_eq!(event.upstream_status, Some(503));
        assert_eq!(event.revenue.as_deref(), Some("0"));
    }

    #[tokio::test]
    async fn a_rejected_settlement_records_the_cost_with_no_revenue() {
        // The loss case: the backend served, the charge did not land.
        let facilitator = FakeFacilitator::rejecting_settlement("insufficient funds");
        let event = recorded(facilitator, FakeUpstream::streaming(), paid_request()).await;
        assert_eq!(event.outcome, Outcome::SettleRejected);
        assert_eq!(event.cost, Some(TEST_COST.to_string()));
        assert_eq!(event.revenue.as_deref(), Some("0"));
        assert_eq!(event.transaction, None);
    }

    #[tokio::test]
    async fn an_unsuccessful_receipt_is_recorded_as_a_rejected_settlement() {
        let facilitator = FakeFacilitator::returning_unsuccessful_receipt();
        let event = recorded(facilitator, FakeUpstream::streaming(), paid_request()).await;
        assert_eq!(event.outcome, Outcome::SettleRejected);
        assert_eq!(event.revenue.as_deref(), Some("0"));
    }

    #[tokio::test]
    async fn an_unavailable_settlement_leaves_revenue_unknown() {
        let facilitator = FakeFacilitator::failing_settlement("timed out");
        let event = recorded(facilitator, FakeUpstream::streaming(), paid_request()).await;
        assert_eq!(event.outcome, Outcome::SettleUnavailable);
        assert_eq!(event.revenue, None);
        assert_eq!(event.cost, Some(TEST_COST.to_string()));
    }

    #[tokio::test]
    async fn a_midstream_failure_after_settlement_is_still_recorded_as_settled() {
        // The same known gap `a_midstream_failure_after_settlement_is_a_known_gap` pins for the
        // response: the charge landed at head time, and the record says what the ledger says.
        let (app, sink) =
            app_recording(FakeFacilitator::accepting(), FakeUpstream::failing_midstream(), None);
        send_partial(app, paid_request()).await;
        assert_eq!(sink.only().outcome, Outcome::Settled);
    }

    #[tokio::test]
    async fn an_unroutable_request_is_recorded_with_its_model_and_no_backend() {
        let sink = FakeTelemetry::default();
        let backends = Arc::new(Backends::from_parts(vec![Backend::for_test(
            "a",
            vec!["llama3"],
            None,
            Arc::new(FakeUpstream::streaming()),
        )]));
        let gateway = Gateway::new(
            FakeFacilitator::accepting(),
            backends,
            resource(),
            armed(vec![requirements()]),
        )
        .unwrap()
            .with_telemetry(Arc::new(sink.clone()));
        send(router(Access::new(gateway, None)), paid_request_for_model("gpt-4")).await;
        let event = sink.only();
        assert_eq!(event.outcome, Outcome::Unroutable);
        assert_eq!(event.access, None);
        assert_eq!(event.backend, None);
        assert_eq!(event.model.as_deref(), Some("gpt-4"));
        assert!(event.offers.is_empty(), "nothing was quoted");
        assert_eq!(event.cost.as_deref(), Some("0"));
    }

    #[tokio::test]
    async fn a_token_request_costs_but_earns_nothing() {
        let (app, sink) = app_recording(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            Some(FakeTokenVerifier::honouring(HONOURED)),
        );
        send(app, tokened_request(HONOURED)).await;
        let event = sink.only();
        assert_eq!(event.outcome, Outcome::Served);
        assert_eq!(event.access, Some(AccessPath::Token));
        assert!(event.offers.is_empty(), "the token path is never priced");
        assert_eq!(event.cost, Some(TEST_COST.to_string()));
        assert_eq!(event.revenue.as_deref(), Some("0"));
    }

    #[tokio::test]
    async fn a_token_request_to_an_unreachable_upstream_is_recorded_on_the_token_path() {
        let (app, sink) = app_recording(
            FakeFacilitator::accepting(),
            FakeUpstream::unreachable("connection refused"),
            Some(FakeTokenVerifier::honouring(HONOURED)),
        );
        send(app, tokened_request(HONOURED)).await;
        let event = sink.only();
        assert_eq!(event.outcome, Outcome::UpstreamUnavailable);
        assert_eq!(event.access, Some(AccessPath::Token));
    }

    #[tokio::test]
    async fn a_rejected_token_is_recorded_once_on_the_paying_path() {
        let (app, sink) = app_recording(
            FakeFacilitator::accepting(),
            FakeUpstream::streaming(),
            Some(FakeTokenVerifier::honouring(HONOURED)),
        );
        send(app, tokened_request("not-the-honoured-token")).await;
        let event = sink.only();
        assert_eq!(event.outcome, Outcome::PaymentRequired);
        assert_eq!(event.access, Some(AccessPath::Payment));
    }

    /// A facilitator that accepts every payment and whose `settle` never returns, or — with
    /// `hang_verify` — whose `verify` never returns. Stands in for a request the client abandons
    /// while that call is in flight.
    struct Hanging {
        hang_verify: bool,
    }

    impl Facilitator for Hanging {
        fn verify(
            &self,
            _payment: &PaymentPayload,
            _requirements: &PaymentRequirements,
        ) -> impl std::future::Future<Output = Result<(), FacilitatorError>> + Send {
            let hang = self.hang_verify;
            async move {
                if hang {
                    std::future::pending::<()>().await;
                }
                Ok(())
            }
        }

        fn settle(
            &self,
            _payment: &PaymentPayload,
            _requirements: &PaymentRequirements,
        ) -> impl std::future::Future<Output = Result<SettlementReceipt, FacilitatorError>> + Send
        {
            std::future::pending()
        }
    }

    fn hanging_app(hang_verify: bool) -> (Router, FakeTelemetry) {
        let sink = FakeTelemetry::default();
        let backend = Backend::for_test("default", vec![], None, Arc::new(FakeUpstream::streaming()))
            .with_cost(TEST_COST);
        let gateway = Gateway::new(
            Hanging { hang_verify },
            Arc::new(Backends::from_parts(vec![backend])),
            resource(),
            armed(vec![requirements()]),
        )
        .unwrap()
        .with_telemetry(Arc::new(sink.clone()));
        (router(Access::new(gateway, None)), sink)
    }

    #[tokio::test]
    async fn a_request_cancelled_mid_settle_is_recorded_abandoned_with_revenue_unknown() {
        // Dropping the in-flight future is what the server does to a handler whose client left.
        let (app, sink) = hanging_app(false);
        let in_flight =
            tokio::time::timeout(std::time::Duration::from_millis(100), app.oneshot(paid_request()))
                .await;
        assert!(in_flight.is_err(), "settle never returns, so the request was still in flight");
        let event = sink.only();
        assert_eq!(event.outcome, Outcome::Abandoned);
        assert_eq!(event.revenue, None, "the settle call may have landed");
        assert_eq!(event.cost, Some(TEST_COST.to_string()), "the upstream had already run");
        assert_eq!(event.paid, Some(quoted()));
    }

    #[tokio::test]
    async fn a_request_cancelled_before_settle_is_recorded_abandoned_with_no_revenue() {
        let (app, sink) = hanging_app(true);
        let in_flight =
            tokio::time::timeout(std::time::Duration::from_millis(100), app.oneshot(paid_request()))
                .await;
        assert!(in_flight.is_err(), "verify never returns, so the request was still in flight");
        let event = sink.only();
        assert_eq!(event.outcome, Outcome::Abandoned);
        assert_eq!(event.revenue.as_deref(), Some("0"), "nothing was charged before settle");
        assert_eq!(event.cost.as_deref(), Some("0"), "the upstream never ran");
    }

    #[tokio::test]
    async fn a_client_that_disconnects_mid_settle_is_still_recorded() {
        // The real server, not `oneshot`: this is the claim that hyper drops a handler whose client
        // closed the connection, and that the drop reaches the recorder. `oneshot` always runs the
        // handler to completion, so only a live connection can show it.
        use tokio::io::AsyncWriteExt as _;
        let (app, sink) = hanging_app(false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let body = r#"{"model":"test","messages":[]}"#;
        let request = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\n\
             {}: {}\r\ncontent-length: {}\r\n\r\n{body}",
            x402::HEADER_PAYMENT_SIGNATURE,
            x402::encode_payment(&payment()),
            body.len(),
        );
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        // Let the request reach the hanging settle, then leave.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(sink.events().is_empty(), "nothing is recorded while the request is in flight");
        drop(client);

        let recorded = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if !sink.events().is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(recorded.is_ok(), "the server never dropped the abandoned handler");
        let event = sink.only();
        assert_eq!(event.outcome, Outcome::Abandoned);
        assert_eq!(event.revenue, None);
    }

    struct PanickingSink;

    impl Telemetry for PanickingSink {
        fn record(&self, _event: RequestEvent) {
            panic!("a sink fault");
        }
    }

    #[tokio::test]
    async fn a_panicking_sink_does_not_fail_a_paid_request() {
        // The client paid; a telemetry fault must not cost them the answer or the receipt.
        let gateway = Gateway::new(
            FakeFacilitator::accepting(),
            one_backend(FakeUpstream::streaming()),
            resource(),
            armed(vec![requirements()]),
        )
        .unwrap()
        .with_telemetry(Arc::new(PanickingSink));
        let (status, headers, body) = send(router(Access::new(gateway, None)), paid_request()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(headers.contains_key(x402::HEADER_PAYMENT_RESPONSE));
        assert_eq!(body, FakeUpstream::streamed_text());
    }

    // ---- the payment window (#83) ----
    //
    // A payment expires on its own clock, and settle comes after the upstream's head. Each test
    // bounds its request with an outer timeout, so a missing bound fails the test instead of hanging
    // it.

    /// The shortest window a gateway accepts: one second left for the upstream's head.
    const SHORTEST_WINDOW: u64 = SETTLE_RESERVE_SECS + 1;

    /// Longer than any bound under test should let a request run.
    const OUTER_GUARD: Duration = Duration::from_secs(5);

    fn requirements_with_window(secs: u64) -> PaymentRequirements {
        PaymentRequirements { max_timeout_seconds: secs, ..requirements() }
    }

    /// A paid request for the one option of a `window`-second gateway, exactly as offered.
    fn paid_request_with_window(window: u64) -> Request<Body> {
        completion_request(Some(&x402::encode_payment(&paying(requirements_with_window(window)))))
    }

    /// A gateway advertising one option with a `window`-second payment window over one costed
    /// backend, recording to a fake sink.
    fn windowed_app<F: Facilitator>(
        facilitator: F,
        upstream: Arc<dyn Upstream>,
        window: u64,
    ) -> (Router, FakeTelemetry) {
        windowed_app_offering(facilitator, upstream, vec![requirements_with_window(window)])
    }

    /// A gateway advertising `options`, each with its own payment window, over one costed backend,
    /// recording to a fake sink.
    fn windowed_app_offering<F: Facilitator>(
        facilitator: F,
        upstream: Arc<dyn Upstream>,
        options: Vec<PaymentRequirements>,
    ) -> (Router, FakeTelemetry) {
        let sink = FakeTelemetry::default();
        let backend = Backend::for_test("default", vec![], None, upstream).with_cost(TEST_COST);
        let gateway = Gateway::new(
            facilitator,
            Arc::new(Backends::from_parts(vec![backend])),
            resource(),
            armed(options),
        )
        .unwrap()
        .with_telemetry(Arc::new(sink.clone()));
        (router(Access::new(gateway, None)), sink)
    }

    #[tokio::test]
    async fn an_upstream_that_outlasts_the_payment_window_fails_uncharged_before_settle() {
        let facilitator = FakeFacilitator::accepting();
        let calls = facilitator.calls();
        let upstream = FakeUpstream::hanging();
        let forwards = upstream.calls();
        let (app, sink) = windowed_app(facilitator, Arc::new(upstream), SHORTEST_WINDOW);

        let started = std::time::Instant::now();
        let (status, headers, body) =
            tokio::time::timeout(OUTER_GUARD, send(app, paid_request_with_window(SHORTEST_WINDOW)))
                .await
                .expect("the payment window must bound the wait for the upstream's head");
        assert!(
            started.elapsed() >= Duration::from_millis(900),
            "the upstream gets the window less the reserve, not nothing: gave up after {:?}",
            started.elapsed()
        );

        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        // Not a 402: a client that paid again would meet the same wait and the same expiry.
        assert!(headers.get(x402::HEADER_PAYMENT_REQUIRED).is_none());
        assert!(headers.get(x402::HEADER_PAYMENT_RESPONSE).is_none());
        assert!(body.contains("payment window"), "the client is told which bound fired: {body}");
        assert_eq!(calls.verifies(), 1);
        assert_eq!(calls.settles(), 0, "an authorization about to expire is not settled");
        assert_eq!(forwards.count(), 1, "the upstream was reached");

        let event = sink.only();
        assert_eq!(event.outcome, Outcome::PaymentWindowElapsed);
        assert!(event.upstream_invoked);
        assert_eq!(event.cost, Some(TEST_COST.to_string()), "the upstream ran, so it cost");
        assert_eq!(event.revenue.as_deref(), Some("0"));
    }

    #[tokio::test]
    async fn the_window_that_bounds_a_request_is_the_one_its_payment_matched() {
        // Offered first, with a window no test would wait out.
        let generous = requirements_with_window(3600);
        let brief = PaymentRequirements {
            network: "test-network-other-not-a-real-caip2".to_string(),
            ..requirements_with_window(SHORTEST_WINDOW)
        };
        let upstream = FakeUpstream::hanging();
        let (app, sink) = windowed_app_offering(
            FakeFacilitator::accepting(),
            Arc::new(upstream),
            vec![generous, brief.clone()],
        );

        let request = completion_request(Some(&x402::encode_payment(&paying(brief))));
        let (status, _, _) = tokio::time::timeout(OUTER_GUARD, send(app, request))
            .await
            .expect("a payment for the brief option is bounded by the brief option's window");

        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(sink.only().outcome, Outcome::PaymentWindowElapsed);
    }

    /// Accepts every payment, but only after `delay`; settles never.
    struct SlowVerify {
        delay: Duration,
    }

    impl Facilitator for SlowVerify {
        fn verify(
            &self,
            _payment: &PaymentPayload,
            _requirements: &PaymentRequirements,
        ) -> impl std::future::Future<Output = Result<(), FacilitatorError>> + Send {
            let delay = self.delay;
            async move {
                tokio::time::sleep(delay).await;
                Ok(())
            }
        }

        fn settle(
            &self,
            _payment: &PaymentPayload,
            _requirements: &PaymentRequirements,
        ) -> impl std::future::Future<Output = Result<SettlementReceipt, FacilitatorError>> + Send
        {
            std::future::pending()
        }
    }

    #[tokio::test]
    async fn a_verify_that_uses_up_the_payment_window_never_reaches_the_upstream() {
        let upstream = FakeUpstream::streaming();
        let forwards = upstream.calls();
        let facilitator = SlowVerify { delay: Duration::from_millis(1200) };
        let (app, sink) = windowed_app(facilitator, Arc::new(upstream), SHORTEST_WINDOW);

        let (status, headers, _) =
            tokio::time::timeout(OUTER_GUARD, send(app, paid_request_with_window(SHORTEST_WINDOW)))
                .await
                .expect("an expired window must not wait on settle");

        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert!(headers.get(x402::HEADER_PAYMENT_REQUIRED).is_none());
        assert_eq!(forwards.count(), 0, "no work is started that could not be paid for");
        let event = sink.only();
        assert_eq!(event.outcome, Outcome::PaymentWindowElapsed);
        assert!(!event.upstream_invoked);
        assert_eq!(event.cost.as_deref(), Some("0"));
    }

    #[tokio::test]
    async fn time_spent_in_verify_comes_out_of_the_upstreams_share_of_the_window() {
        // A 2 s share of the window, 1 s of it spent verifying: the upstream gets the other second,
        // not a fresh 2 s. Counting the share from the end of verify would give up at about 3 s.
        let upstream = FakeUpstream::hanging();
        let forwards = upstream.calls();
        let facilitator = SlowVerify { delay: Duration::from_secs(1) };
        let window = SETTLE_RESERVE_SECS + 2;
        let (app, sink) = windowed_app(facilitator, Arc::new(upstream), window);

        let started = std::time::Instant::now();
        let (status, _, _) =
            tokio::time::timeout(OUTER_GUARD, send(app, paid_request_with_window(window)))
                .await
                .expect("the payment window must bound the wait for the upstream's head");
        let took = started.elapsed();

        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(forwards.count(), 1, "a second was left, so the upstream was called");
        assert!(
            took < Duration::from_millis(2500),
            "the window is counted from arrival, so verify's second is not given back: took {took:?}"
        );
        assert_eq!(sink.only().outcome, Outcome::PaymentWindowElapsed);
    }

    #[tokio::test]
    async fn the_upstreams_own_head_timeout_still_governs_when_it_is_the_shorter() {
        // A real upstream whose origin accepts connections and never answers. Its 150 ms head
        // timeout is far inside the 60 s window less the reserve, so it is what fires, and the
        // request ends as an unreachable upstream rather than an elapsed window.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        let upstream = OllamaUpstream::new(format!("http://{addr}"))
            .with_head_timeout(Duration::from_millis(150));
        let (app, sink) = windowed_app(FakeFacilitator::accepting(), Arc::new(upstream), 60);

        let (status, _, _) = tokio::time::timeout(OUTER_GUARD, send(app, paid_request_with_window(60)))
            .await
            .expect("the head timeout must bound the wait");

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(sink.only().outcome, Outcome::UpstreamUnavailable);
    }

    // ---- abandoning an upstream (#31) ----
    //
    // When the gateway gives up on a request the model is still working on, the only signal the
    // model's server can act on is its connection closing. These tests stand up a raw origin that
    // reports when its side of the connection sees EOF or a reset.

    /// How long an abandoned connection may stay open once the gateway has answered.
    const CLOSE_BOUND: Duration = Duration::from_secs(2);

    /// A raw HTTP origin for one connection. It reads the request, writes `response` (if any), then
    /// waits, sending on the returned channel when the gateway's side closes the connection.
    async fn watched_origin(
        response: Option<&'static [u8]>,
    ) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (closed, closed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf).await;
            if let Some(response) = response {
                stream.write_all(response).await.unwrap();
            }
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            let _ = closed.send(());
        });
        (addr, closed_rx)
    }

    /// A real upstream to `addr`, and a second handle on it for the test to hold. `send` consumes the
    /// router and drops the gateway with it; if that took the upstream's client too, tearing down its
    /// pool would close every connection, and a test could not tell a close from a connection kept
    /// for reuse. Holding the handle across the wait keeps the pool alive.
    fn held_upstream(addr: std::net::SocketAddr) -> (Arc<dyn Upstream>, Arc<dyn Upstream>) {
        let upstream: Arc<dyn Upstream> = Arc::new(OllamaUpstream::new(format!("http://{addr}")));
        (upstream.clone(), upstream)
    }

    #[tokio::test]
    async fn an_upstream_abandoned_before_its_head_sees_its_connection_close() {
        let (addr, closed) = watched_origin(None).await;
        let (upstream, _held) = held_upstream(addr);
        let (app, _) = windowed_app(FakeFacilitator::accepting(), upstream, SHORTEST_WINDOW);

        let (status, _, _) =
            tokio::time::timeout(OUTER_GUARD, send(app, paid_request_with_window(SHORTEST_WINDOW)))
                .await
                .expect("the payment window bounds the wait");
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);

        tokio::time::timeout(CLOSE_BOUND, closed)
            .await
            .expect("the upstream's connection must close once the gateway gives up on it")
            .unwrap();
    }

    /// Serves a streaming head and one chunk, then nothing, so the model is still generating when
    /// `facilitator` fails the settle; asserts the gateway answers `expected` and the upstream's
    /// connection then closes.
    async fn assert_a_failed_settle_closes_a_midstream_upstream(
        facilitator: FakeFacilitator,
        expected: StatusCode,
    ) {
        let (addr, closed) = watched_origin(Some(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
              transfer-encoding: chunked\r\n\r\n5\r\nhello\r\n",
        ))
        .await;
        let (upstream, _held) = held_upstream(addr);
        let (app, _) = windowed_app(facilitator, upstream, 60);

        let (status, _, _) = tokio::time::timeout(OUTER_GUARD, send(app, paid_request_with_window(60)))
            .await
            .expect("a failed settle answers at once");
        assert_eq!(status, expected);

        tokio::time::timeout(CLOSE_BOUND, closed)
            .await
            .expect("the upstream's connection must close once the gateway drops its response")
            .unwrap();
    }

    #[tokio::test]
    async fn an_upstream_abandoned_midstream_after_a_refused_settle_sees_its_connection_close() {
        assert_a_failed_settle_closes_a_midstream_upstream(
            FakeFacilitator::rejecting_settlement("no"),
            StatusCode::PAYMENT_REQUIRED,
        )
        .await;
    }

    #[tokio::test]
    async fn an_upstream_abandoned_midstream_after_an_unsuccessful_receipt_sees_its_connection_close(
    ) {
        assert_a_failed_settle_closes_a_midstream_upstream(
            FakeFacilitator::returning_unsuccessful_receipt(),
            StatusCode::PAYMENT_REQUIRED,
        )
        .await;
    }

    #[tokio::test]
    async fn an_upstream_abandoned_midstream_after_an_unavailable_settle_sees_its_connection_close()
    {
        assert_a_failed_settle_closes_a_midstream_upstream(
            FakeFacilitator::failing_settlement("timed out"),
            StatusCode::BAD_GATEWAY,
        )
        .await;
    }

    #[tokio::test]
    async fn a_window_too_large_for_a_deadline_still_serves_and_settles() {
        // `maxTimeoutSeconds` is operator-supplied and unbounded above. An instant that far out does
        // not exist, and computing one must not panic the handler.
        let facilitator = FakeFacilitator::accepting();
        let calls = facilitator.calls();
        let (app, sink) = windowed_app(facilitator, Arc::new(FakeUpstream::streaming()), u64::MAX);

        let (status, headers, _) =
            tokio::time::timeout(OUTER_GUARD, send(app, paid_request_with_window(u64::MAX)))
                .await
                .expect("a fast upstream answers well inside any window");

        assert_eq!(status, StatusCode::OK);
        assert!(headers.contains_key(x402::HEADER_PAYMENT_RESPONSE));
        assert_eq!(calls.settles(), 1);
        assert_eq!(sink.only().outcome, Outcome::Settled);
    }

    #[test]
    fn construction_refuses_a_payment_window_no_longer_than_the_settle_reserve() {
        // A window the reserve swallows whole leaves no time for any upstream: every paid request
        // would fail. Refused where every gateway is built, as the configuration door does too.
        for window in [0, 1, SETTLE_RESERVE_SECS] {
            let err = Gateway::new(
                FakeFacilitator::accepting(),
                one_backend(FakeUpstream::streaming()),
                resource(),
                // Second, behind a clean option: every option is checked, not only the first.
                armed(vec![
                    PaymentRequirements {
                        network: "test-network-b-not-a-real-caip2".to_string(),
                        ..requirements()
                    },
                    requirements_with_window(window),
                ]),
            )
            .err()
            .unwrap_or_else(|| panic!("a {window}-second window must be refused"));
            assert!(
                matches!(&err, GatewayError::WindowTooShort { max_timeout_seconds, .. } if *max_timeout_seconds == window),
                "got {err:?}"
            );
            assert!(err.to_string().contains(&format!("maxTimeoutSeconds = {window}")), "{err}");
        }
        let built = Gateway::new(
            FakeFacilitator::accepting(),
            one_backend(FakeUpstream::streaming()),
            resource(),
            armed(vec![requirements_with_window(SHORTEST_WINDOW)]),
        );
        assert!(built.is_ok(), "one second more than the reserve is accepted");
    }
}
