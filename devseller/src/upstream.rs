//! What sits behind this development toll booth.
//!
//! Two choices, because both are useful for different work. A client author testing the *payment*
//! flow wants an upstream that answers instantly and identically every time, and does not need a
//! model on the machine at all. Someone testing an end-to-end integration wants the real thing.
//!
//! Both are just [`Upstream`] implementations — [`CannedUpstream`] here, and `obolus`'s own
//! [`OllamaUpstream`](obolus::upstream::OllamaUpstream) for the real path — and `main` picks one at
//! runtime as an `Arc<dyn Upstream>`. There is no enum dispatching between them: the trait is
//! object-safe, so the choice lives in the pointer the gateway holds, not in a type this crate has
//! to name.

use std::future::Future;
use std::pin::Pin;

use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use obolus::upstream::{Upstream, UpstreamError, UpstreamResponse};

/// The canned completion. Shaped like an OpenAI-compatible non-streaming response, because a
/// client testing the payment flow still has to parse *something* — and one that cannot be parsed
/// would send them debugging the wrong layer.
///
/// The content says what this is. A client author who wires this up and forgets is going to see
/// this string in their own output, which is the earliest possible place to notice.
const CANNED_BODY: &str = r#"{"id":"obolus-devseller","object":"chat.completion","created":0,"model":"obolus-devseller","choices":[{"index":0,"message":{"role":"assistant","content":"This response came from the Obolus development seller, not from a model. Nothing was inferred and no payment settled."},"finish_reason":"stop"}],"usage":{"prompt_tokens":0,"completion_tokens":0,"total_tokens":0}}"#;

/// A fixed response, served without touching anything outside this process.
pub struct CannedUpstream;

impl Upstream for CannedUpstream {
    fn forward(
        &self,
        _body: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<UpstreamResponse, UpstreamError>> + Send + '_>> {
        Box::pin(async {
            Ok(UpstreamResponse {
                status: StatusCode::OK,
                content_type: Some("application/json".to_string()),
                body: Body::from(CANNED_BODY),
            })
        })
    }
}

/// How this instance's upstream should be described in the startup banner.
///
/// Keyed on the configured URL rather than on the upstream value itself: `main` builds the canned
/// upstream exactly when no `OBOLUS_UPSTREAM_URL` is set, so the presence of a URL *is* the
/// distinction, and a `dyn Upstream` could not be matched on anyway.
pub fn describe(url: Option<&str>) -> String {
    match url {
        Some(url) => format!("real inference proxied to {url}"),
        None => "a canned response — NO model is contacted and nothing is inferred".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn the_canned_upstream_serves_something_a_client_can_parse() {
        let response = CannedUpstream
            .forward(Bytes::from_static(b"{}"))
            .await
            .expect("the canned upstream never fails");

        assert_eq!(response.status, StatusCode::OK);
        let body = response.body.collect().await.expect("collect the canned body").to_bytes();
        let parsed: serde_json::Value =
            serde_json::from_slice(&body).expect("the canned body must be valid JSON");
        // A client testing the payment flow parses this. If it stops being an OpenAI-shaped
        // completion, they debug their parser instead of their payment.
        assert!(parsed["choices"][0]["message"]["content"].is_string());
    }

    #[tokio::test]
    async fn the_canned_response_says_it_is_not_a_model() {
        // The one property that must survive any edit to the body: someone who forgets which
        // upstream they configured has to be able to see it in their own output.
        let response = CannedUpstream.forward(Bytes::from_static(b"{}")).await.unwrap();
        let body = response.body.collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&body);

        assert!(text.contains("development seller"), "got: {text}");
        assert!(text.contains("no payment settled"), "got: {text}");
    }

    #[test]
    fn the_banner_distinguishes_a_real_upstream_from_the_canned_one() {
        // These two lines are how an operator tells whether the answers they are looking at came
        // from a model. Printing the same text for both is the confusion worth preventing.
        assert!(describe(None).contains("NO model"));
        let real = describe(Some("http://127.0.0.1:11434"));
        assert!(real.contains("11434"), "got: {real}");
        assert!(!real.contains("NO model"), "got: {real}");
    }
}
