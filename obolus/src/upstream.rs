//! The service behind the toll booth.
//!
//! Obolus is a gateway, so the thing it guards is a seam too. Phase A ships
//! [`FakeUpstream`]; the real HTTP implementation that talks to Ollama lands at A3 alongside
//! the delegating facilitator, because both need the same HTTP client and both are the parts
//! that touch the outside world.
//!
//! The response is split into a *head* (status + content type) and a streaming body on
//! purpose — see [`crate::gateway`] for why that split decides when we charge.

use std::future::Future;
// Used only by the test-only fake below; gated so the `server` binary carries neither.
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

/// Why the upstream service could not be reached or refused to start a response.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("upstream unavailable: {0}")]
pub struct UpstreamError(pub String);

/// An upstream response whose head has arrived but whose body may still be streaming.
pub struct UpstreamResponse {
    pub status: StatusCode,
    pub content_type: Option<String>,
    pub body: Body,
}

/// Forward a request to the guarded service.
pub trait Upstream: Send + Sync + 'static {
    /// Send `body` upstream and return as soon as the response *head* is known, without
    /// waiting for the body. The gateway relies on that timing.
    fn forward(
        &self,
        body: Bytes,
    ) -> impl Future<Output = Result<UpstreamResponse, UpstreamError>> + Send;
}

/// An in-process upstream for hermetic tests and local development.
///
/// Its body is a real multi-chunk stream rather than one buffered blob, so tests exercise the
/// gateway's streaming path instead of quietly proving that a one-chunk response works.
///
/// Gated to `cfg(test)`: the `server` binary compiles the library without `cfg(test)`, so this
/// fake cannot be wired into a shipped gateway (OBOL-001) — the compiler enforces it.
#[cfg(test)]
pub struct FakeUpstream {
    status: StatusCode,
    content_type: Option<String>,
    chunks: Vec<&'static str>,
    error: Option<String>,
    /// Set to fail the body *after* the head has been returned.
    midstream_error: Option<String>,
    /// How many times `forward` was called.
    ///
    /// The access tests need "we did not serve" as a positive assertion. A 402 alone cannot
    /// supply it — a request that reached the upstream and then failed for some unrelated reason
    /// looks the same from outside as one the guard correctly refused.
    forwards: UpstreamCalls,
}

/// A shared count of `forward` calls, readable while the fake is owned by a gateway.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct UpstreamCalls(Arc<AtomicUsize>);

#[cfg(test)]
impl UpstreamCalls {
    pub fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// The content type a well-behaved streaming model sends. Used only by the test-only
/// [`FakeUpstream`], so it is gated to `cfg(test)` and never compiled into the `server` binary.
#[cfg(test)]
const EVENT_STREAM: &str = "text/event-stream";

#[cfg(test)]
impl FakeUpstream {
    /// Streams a small multi-chunk body, as a token-streaming model would.
    pub fn streaming() -> Self {
        Self {
            status: StatusCode::OK,
            content_type: Some(EVENT_STREAM.to_string()),
            chunks: vec![
                "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
                "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
                "data: [DONE]\n\n",
            ],
            error: None,
            midstream_error: None,
            forwards: UpstreamCalls::default(),
        }
    }

    /// A handle on how many times this fake was actually reached.
    pub fn calls(&self) -> UpstreamCalls {
        self.forwards.clone()
    }

    /// A normal streaming response, but carrying a content type the caller supplies — used to
    /// prove the gateway survives an upstream header value that is not header-safe.
    pub fn streaming_with_content_type(content_type: impl Into<String>) -> Self {
        Self { content_type: Some(content_type.into()), ..Self::streaming() }
    }

    /// The upstream answered, but with an error status (a bad model name, say).
    pub fn refusing(status: StatusCode) -> Self {
        Self {
            status,
            content_type: Some("application/json".to_string()),
            chunks: vec!["{\"error\":\"upstream refused\"}"],
            error: None,
            midstream_error: None,
            forwards: UpstreamCalls::default(),
        }
    }

    /// The upstream could not be reached at all.
    pub fn unreachable(reason: impl Into<String>) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: None,
            chunks: vec![],
            error: Some(reason.into()),
            midstream_error: None,
            forwards: UpstreamCalls::default(),
        }
    }

    /// A `200 OK` head, then a body that dies partway through.
    ///
    /// This is the shape the gateway *cannot* protect against, and it exists so that fact is
    /// visible and tested rather than implied by its absence. A token-streaming upstream sends
    /// its head before it has generated anything, so committing at head-time proves the request
    /// was accepted — not that it will be answered. See [`crate::gateway`] for the bound on
    /// what "costs the client nothing" actually covers.
    pub fn failing_midstream() -> Self {
        Self {
            status: StatusCode::OK,
            content_type: Some(EVENT_STREAM.to_string()),
            chunks: vec!["data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n"],
            error: None,
            midstream_error: Some("upstream closed the connection".to_string()),
            forwards: UpstreamCalls::default(),
        }
    }

    /// What [`streaming`](Self::streaming) will emit, concatenated — for test assertions.
    pub fn streamed_text() -> String {
        Self::streaming().chunks.concat()
    }
}

#[cfg(test)]
impl Upstream for FakeUpstream {
    async fn forward(&self, _body: Bytes) -> Result<UpstreamResponse, UpstreamError> {
        // Counted before the error arm: reaching an upstream that then refuses is still reaching
        // it, and the access tests care about arrival, not outcome.
        self.forwards.0.fetch_add(1, Ordering::SeqCst);
        if let Some(reason) = &self.error {
            return Err(UpstreamError(reason.clone()));
        }
        let mut chunks: Vec<Result<Bytes, std::io::Error>> =
            self.chunks.iter().map(|c| Ok(Bytes::from_static(c.as_bytes()))).collect();
        if let Some(reason) = &self.midstream_error {
            chunks.push(Err(std::io::Error::other(reason.clone())));
        }
        Ok(UpstreamResponse {
            status: self.status,
            content_type: self.content_type.clone(),
            body: Body::from_stream(futures_util::stream::iter(chunks)),
        })
    }
}

/// How long to wait for the response *head* before treating the upstream as unreachable.
///
/// Generous by design. `forward` resolves when the head arrives, and Ollama's timing splits on
/// `stream`: a streaming request sends its head at the first token (this bounds time-to-first-
/// token), but a **non-streaming** request (`stream:false`) withholds the head until generation
/// is complete — so for that shape this bounds *total generation time*, not connection setup.
/// (Measured on a local model: `stream:false` head at t=complete; `stream:true` head at first
/// token.) It is a hang-guard against an upstream that never answers, not a latency policy: the
/// failure lands after `verify` and before `settle`, so too tight a bound turns a slow-but-fine
/// completion into a 502 the client was never charged for. Set it well above the slowest
/// legitimate completion; the binary exposes `OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS` to tune it.
const DEFAULT_HEAD_TIMEOUT: Duration = Duration::from_secs(600);

/// The real upstream: a streaming reverse proxy to an Ollama server's OpenAI-compatible
/// `/v1/chat/completions` endpoint.
///
/// [`forward`](OllamaUpstream::forward) returns the moment the response *head* arrives; the body
/// then streams lazily as `hyper`'s `Incoming`, so the model's output is never buffered before
/// the gateway has decided whether to charge. That timing is the whole point of the head/body
/// split — see [`crate::gateway`].
///
/// It speaks plain HTTP: Ollama is a local origin (`http://127.0.0.1:11434`). TLS is not wired
/// here because no hermetic path needs it; a facilitator that lives behind HTTPS is a separate,
/// later concern (the connector, not this type, is where TLS would enter).
pub struct OllamaUpstream {
    /// Origin only — scheme + host + port, no trailing slash, no path
    /// (e.g. `http://127.0.0.1:11434`). The endpoint path is appended per request.
    base_url: String,
    client: Client<HttpConnector, Full<Bytes>>,
    /// Deadline for the response head to arrive; see [`DEFAULT_HEAD_TIMEOUT`].
    head_timeout: Duration,
}

impl OllamaUpstream {
    /// Build a proxy to the Ollama origin at `base_url` (e.g. `http://127.0.0.1:11434`).
    ///
    /// The client pools connections, so construct one and share it; a fresh client per request
    /// would defeat keep-alive.
    pub fn new(base_url: impl Into<String>) -> Self {
        // Trim trailing slashes so a base of `http://host:11434/` (common in hand-entered config)
        // does not produce `//v1/chat/completions` — Ollama would 404 that. The endpoint path is
        // always joined with a single leading slash.
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
        Self { base_url, client, head_timeout: DEFAULT_HEAD_TIMEOUT }
    }

    /// Override the response-head deadline; see [`DEFAULT_HEAD_TIMEOUT`] for what it bounds and
    /// why it stays generous. Tests use it to force the timeout without waiting the default.
    pub fn with_head_timeout(mut self, head_timeout: Duration) -> Self {
        self.head_timeout = head_timeout;
        self
    }
}

impl Upstream for OllamaUpstream {
    async fn forward(&self, body: Bytes) -> Result<UpstreamResponse, UpstreamError> {
        let uri = format!("{}/v1/chat/completions", self.base_url);
        let request = Request::post(uri)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(body))
            .map_err(|e| UpstreamError(format!("could not build upstream request: {e}")))?;

        // Bound the wait for the response *head*. Without this a hung upstream — one that accepted
        // the connection but never answers — blocks forever between `verify` and `settle`, pinning
        // the request in the single state where the client has been charged nothing yet is owed a
        // response. The body is deliberately NOT under this deadline: once the head is in hand the
        // stream's length is the model's business, not a timeout's. See [`DEFAULT_HEAD_TIMEOUT`]
        // for why, for a non-streaming upstream request, this is effectively a whole-generation
        // bound rather than a connection-setup one.
        let response = tokio::time::timeout(self.head_timeout, self.client.request(request))
            .await
            .map_err(|_| {
                UpstreamError(format!(
                    "upstream sent no response head within {:?}",
                    self.head_timeout
                ))
            })?
            .map_err(|e| UpstreamError(format!("could not reach upstream: {e}")))?;

        // Split the head off and hand the still-streaming body straight back. Do NOT await or
        // collect the body here: the gateway commits payment at head-time, so buffering the body
        // first would silently turn "charge when the model accepts the request" into "charge only
        // after the full answer streams" — exactly the property the delayed-chunk test guards.
        let (parts, incoming) = response.into_parts();
        let content_type = parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.to_string());
        Ok(UpstreamResponse { status: parts.status, content_type, body: Body::new(incoming) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use axum::response::Response;
    use axum::routing::post;
    use axum::Router;
    use futures_util::StreamExt;
    use tokio::net::TcpListener;
    use tokio::sync::Notify;

    /// Bind an ephemeral loopback port, serve `app` on it, and return its origin URL.
    ///
    /// The listener is bound — and so already accepting into the kernel backlog — before the
    /// serve task is spawned, so a client can connect immediately without racing readiness.
    async fn serve(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn it_forwards_the_request_body_to_the_completions_endpoint() {
        let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
        let seen_for_server = seen.clone();
        let app = Router::new().route(
            "/v1/chat/completions",
            post(move |body: Bytes| {
                let seen = seen_for_server.clone();
                async move {
                    *seen.lock().unwrap() = body.to_vec();
                    "ok"
                }
            }),
        );
        let base = serve(app).await;

        let sent = Bytes::from_static(b"{\"model\":\"llama\"}");
        let response = OllamaUpstream::new(base).forward(sent.clone()).await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        // Drain the body so the request has certainly completed before we inspect what arrived.
        let _ = axum::body::to_bytes(response.body, usize::MAX).await.unwrap();

        assert_eq!(seen.lock().unwrap().as_slice(), sent.as_ref());
    }

    #[tokio::test]
    async fn it_tolerates_a_trailing_slash_on_the_base_url() {
        // Without normalization a trailing-slash base becomes `//v1/chat/completions`, which the
        // route below would not match — so this fails (404, not OK) if `new` stops trimming.
        let app = Router::new().route("/v1/chat/completions", post(|| async { "ok" }));
        let base = serve(app).await;

        let response =
            OllamaUpstream::new(format!("{base}/")).forward(Bytes::new()).await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
    }

    #[tokio::test]
    async fn it_maps_the_upstream_status_and_content_type() {
        let app = Router::new().route(
            "/v1/chat/completions",
            post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/event-stream")
                    .body(Body::from("data: hi\n\n"))
                    .unwrap()
            }),
        );
        let base = serve(app).await;

        let response = OllamaUpstream::new(base).forward(Bytes::new()).await.unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.content_type.as_deref(), Some("text/event-stream"));
    }

    #[tokio::test]
    async fn a_non_success_status_is_conveyed_rather_than_turned_into_an_error() {
        // forward() only errors when it cannot reach the upstream at all; an HTTP error status the
        // upstream *did* return is a head like any other, and the gateway decides what it means.
        let app = Router::new().route(
            "/v1/chat/completions",
            post(|| async { (StatusCode::SERVICE_UNAVAILABLE, "model is loading") }),
        );
        let base = serve(app).await;

        let response = OllamaUpstream::new(base).forward(Bytes::new()).await.unwrap();
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn an_unreachable_upstream_is_an_error() {
        // Bind then immediately drop, handing back a port that is now closed: connecting to it is
        // refused, which is the transport failure forward() must surface as an error.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = listener.local_addr().unwrap();
        drop(listener);

        let result = OllamaUpstream::new(format!("http://{dead}")).forward(Bytes::new()).await;
        assert!(result.is_err(), "a refused connection must surface as an UpstreamError");
    }

    /// The property the whole head/body split exists to protect: `forward` returns once the
    /// response *head* is in hand, without waiting on — or buffering — the body.
    ///
    /// The fake upstream sends its head, then holds the final body chunk hostage until the test
    /// releases it. A correct `forward` never touches the body, so it returns promptly and the
    /// assertions below are reached. A `forward` that collected the body first would block on the
    /// withheld chunk until the timeout fires — turning this into a failure, which is the point:
    /// the test discriminates streaming from buffering rather than passing for both.
    #[tokio::test]
    async fn the_head_returns_before_the_body_finishes_streaming() {
        let release = Arc::new(Notify::new());
        let release_for_server = release.clone();
        let app = Router::new().route(
            "/v1/chat/completions",
            post(move || {
                let release = release_for_server.clone();
                async move {
                    let head_chunk = futures_util::stream::once(async {
                        Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(b"data: first\n\n"))
                    });
                    let gated_tail = futures_util::stream::once(async move {
                        release.notified().await;
                        Ok::<Bytes, std::convert::Infallible>(Bytes::from_static(
                            b"data: [DONE]\n\n",
                        ))
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "text/event-stream")
                        .body(Body::from_stream(head_chunk.chain(gated_tail)))
                        .unwrap()
                }
            }),
        );
        let base = serve(app).await;

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            OllamaUpstream::new(base).forward(Bytes::new()),
        )
        .await
        .expect("forward() must return at head-time, not after buffering the whole body")
        .expect("forward() should succeed");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.content_type.as_deref(), Some("text/event-stream"));

        // Only now free the withheld chunk, and confirm the body still streams through intact.
        release.notify_one();
        let streamed = axum::body::to_bytes(response.body, usize::MAX).await.unwrap();
        assert_eq!(&streamed[..], b"data: first\n\ndata: [DONE]\n\n");
    }

    /// The head-timeout fires when the upstream accepts the request but never sends a response
    /// head. Without the deadline this would hang until the outer 5s guard trips — so the test
    /// discriminates "bounded by `head_timeout`" from "unbounded", rather than passing for both.
    #[tokio::test]
    async fn a_withheld_head_times_out_rather_than_hanging() {
        let never = Arc::new(Notify::new());
        let never_for_server = never.clone();
        let app = Router::new().route(
            "/v1/chat/completions",
            post(move || {
                // The handler parks on a notify the test never sends, so the response head is
                // never produced — the withheld-head shape a real hung upstream presents.
                let never = never_for_server.clone();
                async move {
                    never.notified().await;
                    "unreachable"
                }
            }),
        );
        let base = serve(app).await;

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            OllamaUpstream::new(base)
                .with_head_timeout(Duration::from_millis(150))
                .forward(Bytes::new()),
        )
        .await
        .expect("head_timeout must bound the wait — forward() should not hang past it");
        if let Ok(response) = result {
            panic!(
                "a head that never arrives must surface as an UpstreamError, but forward() \
                 returned a response with status {}",
                response.status
            );
        }

        // Release the parked handler so the serve task does not leak past the test.
        never.notify_one();
    }
}
