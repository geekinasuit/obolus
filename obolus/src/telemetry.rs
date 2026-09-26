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
//!   and only on [`Outcome::Settled`]. It is not a measurement of what moved on chain: the receipt
//!   carries no amount, and the signed authorization is opaque here, so the amount actually signed
//!   is checked by the facilitator, not by the gateway. Given a facilitator that enforces `exact`'s
//!   amount rule, it equals what moved on EVM, where the authorized amount must equal the quote,
//!   and is at most what moved on Solana, where the transfer must be at least the quote. For any
//!   other network, no amount rule is recorded here. Every outcome that definitely took nothing
//!   records `"0"`. [`Outcome::SettleUnavailable`], and an [`Outcome::Abandoned`] request whose
//!   settlement had begun, record no revenue at all: whether the chain moved funds is not something
//!   this side can know.
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

use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    /// What this sink does with an event, for the startup banner. Read off the installed sink, so the
    /// banner describes what is wired rather than what was configured.
    fn description(&self) -> &str {
        "a custom sink"
    }
}

/// The default sink: records nothing. A gateway emits no telemetry until one is installed with
/// [`crate::gateway::Gateway::with_telemetry`].
pub struct NoTelemetry;

impl Telemetry for NoTelemetry {
    fn record(&self, _event: RequestEvent) {}

    fn description(&self) -> &str {
        "off; no request events are recorded"
    }
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
    /// The option the payment accepted is not one this gateway offers as given — a different
    /// scheme, network, asset, pay-to, timeout or `extra`, a price the gateway no longer quotes, or
    /// a transfer method or payment flow the offered option does not resolve to, or an extension
    /// field only the server may set. The client was
    /// re-challenged; the line does not say which field differed.
    OptionUnmatched,
    /// The facilitator evaluated the payment and refused it.
    VerifyRejected,
    /// The facilitator could not be asked to verify.
    VerifyUnavailable,
    /// The upstream could not be reached, or failed before a response head.
    UpstreamUnavailable,
    /// The upstream answered with a non-success status, which was passed back uncharged.
    UpstreamRefused,
    /// The payment's window ran out before the upstream's response head arrived, leaving too little
    /// time to settle. Nothing was charged. The upstream was not called at all if verify alone used
    /// up the window.
    PaymentWindowElapsed,
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
    /// Atomic units, as a decimal string — the same shape as the option's `amount`.
    pub amount: String,
}

impl From<&PaymentRequirements> for Offer {
    fn from(requirement: &PaymentRequirements) -> Self {
        Self {
            scheme: requirement.scheme.clone(),
            network: requirement.network.clone(),
            asset: requirement.asset.clone(),
            amount: requirement.amount.clone(),
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
            | Outcome::PaymentWindowElapsed
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

fn bounded_model(model: String) -> String {
    if model.len() <= MAX_MODEL_BYTES {
        return model;
    }
    let mut end = MAX_MODEL_BYTES;
    while !model.is_char_boundary(end) {
        end -= 1;
    }
    // A copy rather than `truncate`, which keeps the whole original allocation: the bound is on the
    // memory an event holds while it waits in a sink's queue, not just the length it reports.
    model[..end].to_string()
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
    kind: &'static str,
    #[serde(flatten)]
    event: &'a RequestEvent,
}

/// `event` as one `"kind":"request"` line of JSON, stamped with the schema version. No trailing
/// newline. This is the wire form `docs/telemetry.md` documents.
pub fn json_line(event: &RequestEvent) -> String {
    // Every field is a string, integer, bool, enum, or a sequence of those, so serialization has no
    // failure mode here; the fallback exists so that this function is total, not because it is
    // reachable.
    serde_json::to_string(&Line { v: SCHEMA_VERSION, kind: "request", event }).unwrap_or_else(|_| {
        format!(
            "{{\"v\":{SCHEMA_VERSION},\"kind\":\"request\",\"ts_ms\":{},\"outcome\":null}}",
            event.ts_ms
        )
    })
}

/// A `"kind":"dropped"` line: `count` request events were lost before this point in the stream.
pub fn dropped_line(count: u64, ts_ms: u64) -> String {
    format!("{{\"v\":{SCHEMA_VERSION},\"kind\":\"dropped\",\"ts_ms\":{ts_ms},\"dropped\":{count}}}")
}

/// The queue depth the binary's stdout sink uses. The only field a caller controls is the model
/// name, capped at [`MAX_MODEL_BYTES`]; the rest comes from configuration or the facilitator. So a
/// full queue holds on the order of a megabyte of pending events, not an amount traffic can grow.
pub const DEFAULT_QUEUE: usize = 1024;

/// How often an idle line sink reports drops that no later event has carried out.
pub const DROP_REPORT_INTERVAL: Duration = Duration::from_secs(1);

/// A sink that writes each event as one JSON line, off the request path.
///
/// [`Telemetry::record`] only offers the event to a bounded queue and returns; a dedicated thread
/// drains the queue into the writer. When the queue is full — the writer is slower than traffic, or
/// stuck — the event is dropped and counted rather than waited for, and the count is written into
/// the same stream as a `"kind":"dropped"` line before the next event, or within
/// [`DROP_REPORT_INTERVAL`] if none follows. So loss is never silent, and the request path never
/// waits on I/O. Events still queued when the process exits are lost.
pub struct LineSink {
    tx: SyncSender<RequestEvent>,
    dropped: Arc<AtomicU64>,
    /// Set once the writer thread is gone, so its disappearance is reported once, not per event.
    orphaned: AtomicBool,
    description: String,
}

impl LineSink {
    /// One JSON line per request on the process's stdout.
    pub fn stdout() -> std::io::Result<Self> {
        Self::spawn(std::io::stdout(), "stdout", DEFAULT_QUEUE, DROP_REPORT_INTERVAL)
    }

    /// A sink writing to `writer` (named `target` in its description) through a queue of
    /// `capacity` events, reporting idle drops every `report_every`.
    pub fn spawn<W: Write + Send + 'static>(
        writer: W,
        target: &str,
        capacity: usize,
        report_every: Duration,
    ) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));
        let counter = dropped.clone();
        let target_name = target.to_string();
        std::thread::Builder::new()
            .name("obolus-telemetry".to_string())
            .spawn(move || drain(rx, writer, counter, &target_name, report_every))?;
        Ok(Self {
            tx,
            dropped,
            orphaned: AtomicBool::new(false),
            description: format!(
                "one JSON line per request on {target}, through a queue of {capacity} events; when \
                 the queue is full, events are dropped and counted in the stream, never waited on"
            ),
        })
    }
}

impl Telemetry for LineSink {
    fn record(&self, event: RequestEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // The writer thread is gone, so nothing will ever report these; say so once, here.
            Err(TrySendError::Disconnected(_)) => {
                if !self.orphaned.swap(true, Ordering::Relaxed) {
                    warn("obolus: telemetry writer stopped; request events are being lost");
                }
            }
        }
    }

    fn description(&self) -> &str {
        &self.description
    }
}

/// The writer thread: drain events into `writer`, one line each, preceded by a `dropped` line
/// whenever events were lost since the last write. Serialization happens here, not in `record`, so
/// the request path does no formatting work.
fn drain<W: Write>(
    rx: Receiver<RequestEvent>,
    mut writer: W,
    dropped: Arc<AtomicU64>,
    target: &str,
    report_every: Duration,
) {
    let mut failed = false;
    let mut write = |line: &str, writer: &mut W| {
        let result = writeln!(writer, "{line}").and_then(|()| writer.flush());
        // A closed stdout is an error here, not a signal: Rust ignores SIGPIPE. Report the first
        // failure where an operator will see it, and keep draining so `record` never backs up.
        if let Err(err) = result {
            if !failed {
                failed = true;
                warn(&format!(
                    "obolus: telemetry write to {target} failed ({err}); events are being lost"
                ));
            }
        }
    };
    loop {
        let next = rx.recv_timeout(report_every);
        // Checked on every wake, event or timeout, so drops that no later event carries out are
        // still reported within `report_every`.
        let lost = dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            write(&dropped_line(lost, now_ms()), &mut writer);
        }
        match next {
            Ok(event) => write(&json_line(&event), &mut writer),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// A line on stderr that cannot panic. `eprintln!` panics when stderr is unwritable, which would
/// kill the writer thread or, on the request path, lean on [`record`]'s containment.
fn warn(message: &str) {
    let _ = writeln!(std::io::stderr(), "{message}");
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
    fn a_long_model_does_not_keep_its_original_allocation() {
        // The model comes from the request body, which may be megabytes. An event can wait in a
        // sink's queue, so what bounds its memory is the capacity it holds, not the length it shows.
        let trace = Trace { model: Some("m".repeat(1 << 20)), ..Trace::default() };
        let recorded = trace.finish(Outcome::Unroutable, TS).model.unwrap();
        assert!(recorded.capacity() <= MAX_MODEL_BYTES, "capacity {}", recorded.capacity());
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
                r#"{"v":1,"kind":"request","ts_ms":1700000000000,"outcome":"settled","access":"payment","#,
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
                r#"{"v":1,"kind":"request","ts_ms":0,"outcome":"unroutable","access":null,"backend":null,"model":null,"#,
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
    fn a_dropped_line_matches_the_documented_schema() {
        assert_eq!(
            dropped_line(7, TS),
            r#"{"v":1,"kind":"dropped","ts_ms":1700000000000,"dropped":7}"#
        );
    }

    // ---- LineSink ----

    use std::sync::mpsc::{channel, Sender};
    use std::sync::Mutex;

    /// A writer that appends to a shared buffer the test can read.
    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Shared {
        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.0.lock().unwrap().clone())
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect()
        }

        /// Wait (bounded) until `pred` holds over the lines written so far.
        fn wait_for(&self, pred: impl Fn(&[String]) -> bool) -> Vec<String> {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let lines = self.lines();
                if pred(&lines) {
                    return lines;
                }
                assert!(std::time::Instant::now() < deadline, "timed out; lines so far: {lines:#?}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A writer whose first write announces itself and then blocks until released — a stuck stdout.
    struct Gated {
        inner: Shared,
        entered: Option<Sender<()>>,
        release: Option<Receiver<()>>,
    }

    impl Write for Gated {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
            }
            if let Some(release) = self.release.take() {
                let _ = release.recv();
            }
            self.inner.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn event(outcome: Outcome) -> RequestEvent {
        Trace::default().finish(outcome, TS)
    }

    /// Record `count` events on a separate thread and fail if they have not all returned within a
    /// deadline — so a `record` that blocks on a stuck writer fails the test instead of hanging it.
    fn record_within(sink: &Arc<LineSink>, count: u64, outcome: Outcome) {
        let recorder = sink.clone();
        let (done_tx, done_rx) = channel();
        std::thread::spawn(move || {
            for _ in 0..count {
                recorder.record(event(outcome));
            }
            let _ = done_tx.send(());
        });
        done_rx.recv_timeout(Duration::from_secs(5)).expect("record blocked on a stuck writer");
    }

    #[test]
    fn a_line_sink_writes_one_json_line_per_event() {
        let out = Shared::default();
        let sink = LineSink::spawn(out.clone(), "a buffer", 8, Duration::from_secs(60)).unwrap();
        sink.record(event(Outcome::PaymentRequired));
        sink.record(event(Outcome::Unroutable));
        let lines = out.wait_for(|lines| lines.len() == 2);
        assert_eq!(lines[0], json_line(&event(Outcome::PaymentRequired)));
        assert_eq!(lines[1], json_line(&event(Outcome::Unroutable)));
    }

    #[test]
    fn a_stuck_writer_never_blocks_record_and_every_drop_is_counted() {
        const CAPACITY: usize = 4;
        const OVERFLOW: u64 = 5;
        let out = Shared::default();
        let (entered_tx, entered_rx) = channel();
        let (release_tx, release_rx) = channel();
        let writer = Gated { inner: out.clone(), entered: Some(entered_tx), release: Some(release_rx) };
        let sink =
            Arc::new(LineSink::spawn(writer, "a stuck writer", CAPACITY, Duration::from_secs(60)).unwrap());

        // The first event reaches the writer, which then sticks: the queue is now empty and the
        // writer is not draining it.
        record_within(&sink, 1, Outcome::Served);
        entered_rx.recv_timeout(Duration::from_secs(5)).expect("the writer took the first event");

        // Fill the queue, then overflow it.
        record_within(&sink, CAPACITY as u64 + OVERFLOW, Outcome::PaymentRequired);

        release_tx.send(()).unwrap();
        let expected_dropped = dropped_line(OVERFLOW, 0);
        let lines = out.wait_for(|lines| lines.len() == 2 + CAPACITY);
        // The line after the stuck event reports exactly the overflow, before the queued events.
        assert_eq!(lines[0], json_line(&event(Outcome::Served)));
        assert!(
            lines[1].starts_with(r#"{"v":1,"kind":"dropped","#)
                && lines[1].ends_with(&format!(r#""dropped":{OVERFLOW}}}"#)),
            "expected a drop report of {OVERFLOW} like {expected_dropped}; got {}",
            lines[1]
        );
        assert!(lines[2..].iter().all(|line| *line == json_line(&event(Outcome::PaymentRequired))));
    }

    #[test]
    fn drops_are_reported_even_when_no_event_follows() {
        // A drop counted after the writer has drained the queue: a recorder that found the queue
        // full, then was preempted before counting. No event follows to carry the count out, and
        // the queue is empty, so only the idle wake can report it.
        let out = Shared::default();
        let sink = LineSink::spawn(out.clone(), "stdout", 4, Duration::from_millis(20)).unwrap();
        sink.dropped.fetch_add(3, Ordering::Relaxed);
        let lines = out.wait_for(|lines| lines.iter().any(|line| line.contains(r#""kind":"dropped""#)));
        assert_eq!(lines.len(), 1, "{lines:#?}");
        assert!(lines[0].ends_with(r#""dropped":3}"#), "{lines:#?}");
    }

    /// A writer whose every write fails, and which says when the first one has been attempted.
    struct Broken {
        failed: Option<Sender<()>>,
    }

    impl Write for Broken {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            if let Some(failed) = self.failed.take() {
                let _ = failed.send(());
            }
            Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_failing_writer_keeps_draining_so_record_never_backs_up() {
        // Were the writer thread to stop on a write error — exit, or stay alive stuck retrying — a
        // capacity-1 queue would fill at once and every later event would be dropped, and the drop
        // count would never be collected again. A writer that keeps draining collects it on its next
        // wake, so the count returning to zero is what shows it is still draining. The overflow is
        // recorded only after the first write has failed, so a writer that wedges on that failure is
        // certain to leave drops behind rather than having collected them all before it wedged.
        let (failed_tx, failed_rx) = channel();
        let writer = Broken { failed: Some(failed_tx) };
        let sink = LineSink::spawn(writer, "a closed pipe", 1, Duration::from_millis(20)).unwrap();
        sink.record(event(Outcome::Served));
        failed_rx.recv_timeout(Duration::from_secs(5)).expect("the writer never attempted a write");
        for _ in 0..50 {
            sink.record(event(Outcome::Served));
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while sink.dropped.load(Ordering::Relaxed) > 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the writer stopped draining after a write error"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(!sink.orphaned.load(Ordering::Relaxed), "the writer thread must survive write errors");
    }

    #[test]
    fn a_line_sink_describes_where_it_writes() {
        let sink = LineSink::spawn(Shared::default(), "stdout", 16, DROP_REPORT_INTERVAL).unwrap();
        assert!(sink.description().contains("on stdout"), "{}", sink.description());
        assert!(sink.description().contains("16 events"), "{}", sink.description());
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
