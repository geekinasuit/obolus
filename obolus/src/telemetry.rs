//! What happened to each request, for an operator reckoning revenue against cost.
//!
//! One [`RequestEvent`] per request that reaches the completion handler, recorded by a [`Recorder`]
//! when it is dropped — after the response is decided, or when the handler is cancelled because the
//! client went away. One event rather than one per stage (priced, verified, settled) because a
//! per-stage stream needs a correlation id to be reassembled, and reassembly is where accounting goes
//! wrong: a lost "settled" line after a kept "verified" line is a request that looks free. A single
//! terminal record carries every stage's outcome together, so a consumer sums lines and never joins
//! them.
//!
//! # What an event can and cannot claim
//!
//! - **Revenue** is the price the gateway charged: the quoted amount of the option the client paid,
//!   and only on [`Outcome::Settled`]. It is a lower bound on what moved on chain, not a measurement
//!   of it. The receipt carries no amount, the payment payload is opaque here, and x402's `exact`
//!   scheme accepts an authorization for *at least* the quoted amount — so a client that authorized
//!   more may have been settled for more than this records. Every outcome that definitely took
//!   nothing records `"0"`. [`Outcome::SettleUnavailable`], and an [`Outcome::Abandoned`] request
//!   whose settlement had begun, record no revenue at all: whether the chain moved funds is not
//!   something this side can know.
//! - **Cost** is the routed backend's *declared* per-request cost, and is charged to any request
//!   whose upstream was invoked — including one whose settlement then failed, which is exactly the
//!   loss this record exists to expose, and one the upstream refused, since whether a refused call is
//!   billed depends on the backend, and overstating a loss is the safer error. A request that never
//!   reached the upstream costs `"0"`. A backend with no declared cost records no cost (not `"0"`):
//!   under the static rate nothing declares one, and an unknown cost written as zero would read as
//!   free.
//! - **Settled means the head committed**, not that the body arrived. A stream that dies after
//!   settlement is recorded as settled; see the gateway module's docs for why that gap exists.
//!
//! # What an event never carries
//!
//! The bearer token, the payment payload, the request or response body, the payer, and any free-text
//! error detail. Facilitator reasons and transport errors can name internal hosts; they go to stderr,
//! and an event says only *which* outcome occurred. The stream is pseudonymous rather than
//! anonymous: a settled event's `transaction` names the payer to anyone who looks it up on chain.
//!
//! # Recording never fails a request
//!
//! [`Telemetry::record`] returns nothing, and the gateway calls it through [`record`], which contains
//! a panicking sink. A sink that needs I/O must hand the event off rather than perform it on the
//! request path — the contract below says so, and the default sink is the no-op [`NoTelemetry`].

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::x402::PaymentRequirements;

/// The version of the line format [`json_line`] writes. Bumped when a field changes meaning or is
/// removed; adding a field is not a bump, so a consumer should ignore fields it does not know.
pub const SCHEMA_VERSION: u32 = 1;

/// The longest `model` an event records, in bytes. The model is the client's own input, and a
/// catch-all backend routes any string, so without a bound one request could write a line the size
/// of the request body. Longer names are cut at a character boundary at or below this length.
pub const MAX_MODEL_BYTES: usize = 256;

/// Where request events go.
///
/// Implementations must return promptly and must not block on I/O: `record` runs on the request
/// path — for a finished request, after the response is decided but before it is sent; for an
/// abandoned one, while the server tears the handler down. A transport (a log writer, OTel,
/// Kafka, a database) belongs behind a queue this call only enqueues to, and must drop rather than
/// wait when that queue is full.
pub trait Telemetry: Send + Sync {
    fn record(&self, event: RequestEvent);
}

/// The default sink: records nothing. A gateway emits no telemetry until one is installed with
/// [`crate::gateway::Gateway::with_telemetry`].
pub struct NoTelemetry;

impl Telemetry for NoTelemetry {
    fn record(&self, _event: RequestEvent) {}
}

/// Hand `event` to `sink`, containing a panic so that a faulty sink cannot fail the request whose
/// response is already decided.
pub fn record(sink: &dyn Telemetry, event: RequestEvent) {
    let _ = catch_unwind(AssertUnwindSafe(|| sink.record(event)));
}

/// How a request ended. A closed set: every exit from the completion route maps to exactly one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// No backend serves the requested model, or the request named none where one was required.
    Unroutable,
    /// A recognised caller was served on the token path.
    Served,
    /// No payment was presented; the client was challenged.
    PaymentRequired,
    /// A payment header was present but not a decodable x402 payment.
    PaymentMalformed,
    /// The payment named a `(scheme, network)` this gateway does not offer.
    OptionUnmatched,
    /// The facilitator evaluated the payment and refused it.
    VerifyRejected,
    /// The facilitator could not be asked to verify.
    VerifyUnavailable,
    /// The upstream could not be reached, or failed before a response head.
    UpstreamUnavailable,
    /// The upstream answered with a non-success status, which was passed back uncharged.
    UpstreamRefused,
    /// Settlement was refused, or reported that it did not complete. Nothing was charged.
    SettleRejected,
    /// The facilitator failed during settlement. Whether funds moved is unknown.
    SettleUnavailable,
    /// The payment settled and the upstream's response was served with a receipt.
    Settled,
    /// The handler was cancelled before it produced a response — the client disconnected. Revenue is
    /// unknown if settlement had begun, since the settle call may have landed.
    Abandoned,
}

/// Which way through the gate a routed request took.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPath {
    Token,
    Payment,
}

/// One priced payment option, as advertised to this request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Offer {
    pub scheme: String,
    pub network: String,
    pub asset: String,
    /// Atomic units, as a decimal string — the same shape as `maxAmountRequired`.
    pub amount: String,
}

impl From<&PaymentRequirements> for Offer {
    fn from(requirement: &PaymentRequirements) -> Self {
        Self {
            scheme: requirement.scheme.clone(),
            network: requirement.network.clone(),
            asset: requirement.asset.clone(),
            amount: requirement.max_amount_required.clone(),
        }
    }
}

/// Everything recorded about one request. Amounts are atomic-unit decimal strings, because a `u128`
/// does not survive a JSON number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestEvent {
    /// When the event was recorded, in Unix milliseconds — stamped once, by the gateway, so every
    /// sink reports the same instant however long it queues the event.
    pub ts_ms: u64,
    pub outcome: Outcome,
    /// `None` only for [`Outcome::Unroutable`], which is decided before the access path is.
    pub access: Option<AccessPath>,
    /// The routed backend's id; `None` when the request was unroutable.
    pub backend: Option<String>,
    /// The model the request named, bounded by [`MAX_MODEL_BYTES`].
    pub model: Option<String>,
    /// Every option this request was quoted, at its determined price. Empty off the payment path.
    pub offers: Vec<Offer>,
    /// The offer the client's payment matched, once one did.
    pub paid: Option<Offer>,
    /// Whether the upstream was called — the fact that decides whether the request cost anything.
    pub upstream_invoked: bool,
    /// The upstream's response status, when it produced a head.
    pub upstream_status: Option<u16>,
    /// The declared cost incurred; see the module docs for when this is `None`.
    pub cost: Option<String>,
    /// What was charged; see the module docs for when this is `None`.
    pub revenue: Option<String>,
    /// The settlement transaction, on [`Outcome::Settled`] when the facilitator reported one.
    pub transaction: Option<String>,
}

/// The facts the gateway gathers while serving one request, from which a [`RequestEvent`] is built.
///
/// Cost and revenue are not facts the gateway sets — they are derived in [`Trace::finish`] from the
/// outcome and whether the upstream ran, so the accounting rules live in one place rather than at
/// each of the route's exits.
#[derive(Debug, Default)]
pub struct Trace {
    pub access: Option<AccessPath>,
    pub backend: Option<String>,
    pub model: Option<String>,
    /// The routed backend's declared cost, whether or not the request ends up incurring it.
    pub backend_cost: Option<u128>,
    pub offers: Vec<Offer>,
    pub paid: Option<Offer>,
    pub upstream_invoked: bool,
    pub upstream_status: Option<u16>,
    /// Whether `settle` was called — the fact that makes an abandoned request's revenue unknowable.
    pub settle_attempted: bool,
    pub transaction: Option<String>,
}

impl Trace {
    /// Close the trace with the request's outcome, deriving cost and revenue. `ts_ms` is the
    /// recording instant in Unix milliseconds.
    pub fn finish(self, outcome: Outcome, ts_ms: u64) -> RequestEvent {
        let cost = if self.upstream_invoked {
            self.backend_cost.map(|cost| cost.to_string())
        } else {
            Some("0".to_string())
        };
        let zero = || Some("0".to_string());
        // Exhaustive on purpose: a new outcome must decide its revenue here rather than inherit one.
        let revenue = match outcome {
            Outcome::Settled => self.paid.as_ref().map(|paid| paid.amount.clone()),
            Outcome::SettleUnavailable => None,
            Outcome::Abandoned if self.settle_attempted => None,
            Outcome::Abandoned
            | Outcome::Unroutable
            | Outcome::Served
            | Outcome::PaymentRequired
            | Outcome::PaymentMalformed
            | Outcome::OptionUnmatched
            | Outcome::VerifyRejected
            | Outcome::VerifyUnavailable
            | Outcome::UpstreamUnavailable
            | Outcome::UpstreamRefused
            | Outcome::SettleRejected => zero(),
        };
        RequestEvent {
            ts_ms,
            outcome,
            access: self.access,
            backend: self.backend,
            model: self.model.map(bounded_model),
            offers: self.offers,
            paid: self.paid,
            upstream_invoked: self.upstream_invoked,
            upstream_status: self.upstream_status,
            cost,
            revenue,
            transaction: self.transaction,
        }
    }
}

fn bounded_model(mut model: String) -> String {
    if model.len() > MAX_MODEL_BYTES {
        let mut end = MAX_MODEL_BYTES;
        while !model.is_char_boundary(end) {
            end -= 1;
        }
        model.truncate(end);
    }
    model
}

/// Records one request's event when it is dropped.
///
/// A guard rather than a call at the end of the handler, because the handler does not always reach
/// its end: when a client disconnects, the server drops the handler's future wherever it is
/// suspended — possibly mid-settle, with a charge in flight. The recorder lives in that future, so it
/// is dropped with it and still records, as [`Outcome::Abandoned`]. A handler that finishes calls
/// [`Recorder::complete`], and the drop records its outcome instead. Either way the event is
/// recorded exactly once, from one place.
pub struct Recorder {
    sink: Arc<dyn Telemetry>,
    /// The facts gathered so far; the handler writes these as it goes.
    pub trace: Trace,
    outcome: Option<Outcome>,
}

impl Recorder {
    pub fn new(sink: Arc<dyn Telemetry>) -> Self {
        Self { sink, trace: Trace::default(), outcome: None }
    }

    /// Record the request as having ended in `outcome`.
    pub fn complete(mut self, outcome: Outcome) {
        self.outcome = Some(outcome);
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        let outcome = self.outcome.unwrap_or(Outcome::Abandoned);
        let event = std::mem::take(&mut self.trace).finish(outcome, now_ms());
        record(self.sink.as_ref(), event);
    }
}

/// The current time in Unix milliseconds; `0` for a clock set before the epoch, rather than a panic
/// on the request path.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[derive(Serialize)]
struct Line<'a> {
    v: u32,
    #[serde(flatten)]
    event: &'a RequestEvent,
}

/// `event` as one line of JSON, stamped with the schema version. No trailing newline. This is the
/// wire form `docs/telemetry.md` documents.
pub fn json_line(event: &RequestEvent) -> String {
    // Every field is a string, integer, bool, enum, or a sequence of those, so serialization has no
    // failure mode here; the fallback exists so that this function is total, not because it is
    // reachable.
    serde_json::to_string(&Line { v: SCHEMA_VERSION, event }).unwrap_or_else(|_| {
        format!("{{\"v\":{SCHEMA_VERSION},\"ts_ms\":{},\"outcome\":null}}", event.ts_ms)
    })
}

/// A sink that keeps every event it is handed, for asserting the stream in tests. Test-only, like
/// the other fakes, so no build of the binary can contain it.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct FakeTelemetry {
    events: std::sync::Arc<std::sync::Mutex<Vec<RequestEvent>>>,
}

#[cfg(test)]
impl FakeTelemetry {
    /// The events recorded so far, in order.
    pub fn events(&self) -> Vec<RequestEvent> {
        self.events.lock().unwrap().clone()
    }

    /// The single event recorded, failing the test if there is not exactly one.
    pub fn only(&self) -> RequestEvent {
        let events = self.events();
        assert_eq!(events.len(), 1, "expected exactly one telemetry event; got {events:#?}");
        events.into_iter().next().unwrap()
    }
}

#[cfg(test)]
impl Telemetry for FakeTelemetry {
    fn record(&self, event: RequestEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(amount: &str) -> Offer {
        Offer {
            scheme: "exact".to_string(),
            network: "test-network".to_string(),
            asset: "0xTEST-ASSET".to_string(),
            amount: amount.to_string(),
        }
    }

    fn paid_trace() -> Trace {
        Trace {
            access: Some(AccessPath::Payment),
            backend: Some("local".to_string()),
            model: Some("llama3".to_string()),
            backend_cost: Some(800),
            offers: vec![offer("1000")],
            paid: Some(offer("1000")),
            upstream_invoked: true,
            upstream_status: Some(200),
            settle_attempted: true,
            transaction: None,
        }
    }

    /// An arbitrary recording instant for tests that do not care about time.
    const TS: u64 = 1_700_000_000_000;

    #[test]
    fn a_settled_request_earns_the_paid_amount_and_costs_the_declared_cost() {
        let event = paid_trace().finish(Outcome::Settled, TS);
        assert_eq!(event.revenue.as_deref(), Some("1000"));
        assert_eq!(event.cost.as_deref(), Some("800"));
    }

    #[test]
    fn a_failed_settle_after_the_upstream_ran_still_costs() {
        // The loss this record exists to expose: the backend did the work, nothing was charged.
        let event = paid_trace().finish(Outcome::SettleRejected, TS);
        assert_eq!(event.revenue.as_deref(), Some("0"));
        assert_eq!(event.cost.as_deref(), Some("800"));
    }

    #[test]
    fn an_unavailable_settle_records_no_revenue_rather_than_zero() {
        // Funds may or may not have moved; "0" would be a claim this side cannot make.
        let event = paid_trace().finish(Outcome::SettleUnavailable, TS);
        assert_eq!(event.revenue, None);
        assert_eq!(event.cost.as_deref(), Some("800"));
    }

    #[test]
    fn an_abandoned_request_mid_settle_records_no_revenue_rather_than_zero() {
        // The client left while settle was in flight; the charge may have landed.
        let event = paid_trace().finish(Outcome::Abandoned, TS);
        assert_eq!(event.revenue, None);
        assert_eq!(event.cost.as_deref(), Some("800"));
    }

    #[test]
    fn an_abandoned_request_before_settle_took_nothing() {
        let trace = Trace { settle_attempted: false, ..paid_trace() };
        let event = trace.finish(Outcome::Abandoned, TS);
        assert_eq!(event.revenue.as_deref(), Some("0"));
    }

    #[test]
    fn a_request_that_never_reached_the_upstream_costs_zero() {
        let trace = Trace {
            upstream_invoked: false,
            upstream_status: None,
            settle_attempted: false,
            ..paid_trace()
        };
        let event = trace.finish(Outcome::VerifyRejected, TS);
        assert_eq!(event.cost.as_deref(), Some("0"));
        assert_eq!(event.revenue.as_deref(), Some("0"));
    }

    #[test]
    fn an_undeclared_cost_is_unknown_not_zero() {
        let trace = Trace { backend_cost: None, ..paid_trace() };
        let event = trace.finish(Outcome::Settled, TS);
        assert_eq!(event.cost, None);
    }

    #[test]
    fn a_long_model_is_cut_at_a_character_boundary() {
        // 'é' is two bytes; 200 of them straddle the limit, so a byte cut at 256 would split one.
        let model = "é".repeat(200);
        let trace = Trace { model: Some(model), ..Trace::default() };
        let recorded = trace.finish(Outcome::Unroutable, TS).model.unwrap();
        assert!(recorded.len() <= MAX_MODEL_BYTES);
        assert_eq!(recorded, "é".repeat(MAX_MODEL_BYTES / 2));
    }

    #[test]
    fn a_short_model_is_kept_verbatim() {
        let trace = Trace { model: Some("llama3".to_string()), ..Trace::default() };
        assert_eq!(trace.finish(Outcome::Unroutable, TS).model.as_deref(), Some("llama3"));
    }

    #[test]
    fn the_json_line_matches_the_documented_schema() {
        // docs/telemetry.md shows this exact line; a change here is a change to that contract.
        let trace = Trace { transaction: Some("0xTEST-TX".to_string()), ..paid_trace() };
        let line = json_line(&trace.finish(Outcome::Settled, TS));
        assert_eq!(
            line,
            concat!(
                r#"{"v":1,"ts_ms":1700000000000,"outcome":"settled","access":"payment","#,
                r#""backend":"local","model":"llama3","#,
                r#""offers":[{"scheme":"exact","network":"test-network","asset":"0xTEST-ASSET","amount":"1000"}],"#,
                r#""paid":{"scheme":"exact","network":"test-network","asset":"0xTEST-ASSET","amount":"1000"},"#,
                r#""upstream_invoked":true,"upstream_status":200,"cost":"800","revenue":"1000","#,
                r#""transaction":"0xTEST-TX"}"#,
            )
        );
    }

    #[test]
    fn an_unroutable_line_carries_nulls_not_omissions() {
        // A consumer reads a fixed set of keys; an absent key and a null one must not both occur.
        let line = json_line(&Trace::default().finish(Outcome::Unroutable, 0));
        assert_eq!(
            line,
            concat!(
                r#"{"v":1,"ts_ms":0,"outcome":"unroutable","access":null,"backend":null,"model":null,"#,
                r#""offers":[],"paid":null,"upstream_invoked":false,"upstream_status":null,"#,
                r#""cost":"0","revenue":"0","transaction":null}"#,
            )
        );
    }

    struct PanickingSink;

    impl Telemetry for PanickingSink {
        fn record(&self, _event: RequestEvent) {
            panic!("a sink fault");
        }
    }

    #[test]
    fn a_panicking_sink_does_not_escape_record() {
        record(&PanickingSink, Trace::default().finish(Outcome::Unroutable, TS));
    }

    #[test]
    fn a_completed_recorder_records_its_outcome_once() {
        let sink = FakeTelemetry::default();
        let recorder = Recorder::new(Arc::new(sink.clone()));
        recorder.complete(Outcome::PaymentRequired);
        assert_eq!(sink.only().outcome, Outcome::PaymentRequired);
    }

    #[test]
    fn a_recorder_dropped_without_an_outcome_records_it_abandoned() {
        let sink = FakeTelemetry::default();
        let mut recorder = Recorder::new(Arc::new(sink.clone()));
        recorder.trace.upstream_invoked = true;
        drop(recorder);
        let event = sink.only();
        assert_eq!(event.outcome, Outcome::Abandoned);
        assert!(event.upstream_invoked, "the facts gathered before the drop are kept");
    }

    #[test]
    fn a_recorder_stamps_the_recording_time() {
        let sink = FakeTelemetry::default();
        let before = now_ms();
        Recorder::new(Arc::new(sink.clone())).complete(Outcome::Unroutable);
        let after = now_ms();
        let ts_ms = sink.only().ts_ms;
        assert!(before <= ts_ms && ts_ms <= after, "{before} <= {ts_ms} <= {after}");
    }
}
