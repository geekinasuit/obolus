//! What the gateway reads out of a completion request body.
//!
//! The body is read once, into a [`RequestShape`], and only ever *read*: the bytes forwarded
//! upstream are always the client's originals, never a re-serialization of this.
//!
//! The read is tolerant by construction. `model` decides routing, so nothing else in the body may
//! be able to change what `model` reads as: a malformed `max_tokens` is recorded as malformed, not
//! allowed to fail the parse that `model` comes out of.

use serde::Deserialize;
use serde_json::{Map, Value};

/// The parts of a request body the gateway acts on: the `model` it routes and prices by, and the
/// output-token limit the client asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestShape {
    model: Option<String>,
    max_tokens: MaxTokens,
    max_completion_tokens: bool,
}

/// The request's `max_tokens` field, kept distinct in all three ways it can arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxTokens {
    /// The body has no `max_tokens` key (or is not a JSON object at all).
    Absent,
    /// A non-negative integer that fits a `u64`.
    Limit(u64),
    /// Present, but not a non-negative integer that fits a `u64`: a string, a float, a negative
    /// number, `null`, an out-of-range integer, or any other JSON value.
    Invalid,
}

/// The routing read. Exactly the `model` field and nothing else, so that only `model` itself can
/// make it fail: a body that is not a JSON object, a `model` that is not a string, or a `model` key
/// given twice all read as no model. `#[serde(default)]` so an omitted `model` is `None` rather than
/// a failure. Token fields are deliberately not here — see [`RequestShape::parse`].
#[derive(Deserialize)]
struct ModelField {
    #[serde(default)]
    model: Option<String>,
}

impl RequestShape {
    /// Read a request body. Never fails: whatever cannot be read reads as absent (`model: None`,
    /// [`MaxTokens::Absent`]), and a `max_tokens` that is there but unusable reads as
    /// [`MaxTokens::Invalid`].
    ///
    /// Two independent reads of the one body, so neither can spoil the other. `model` comes from
    /// a struct holding only `model`, whose failure modes are `model`'s own. The token fields come from a generic
    /// JSON object, where every value is accepted as-is and judged afterwards; deserializing them
    /// into typed fields beside `model` would let a `"max_tokens": "abc"`, or a `max_tokens` key
    /// given twice, fail the whole read and silently unroute the request.
    pub fn parse(body: &[u8]) -> Self {
        let model = serde_json::from_slice::<ModelField>(body).ok().and_then(|parsed| parsed.model);
        let object = serde_json::from_slice::<Map<String, Value>>(body).ok();
        let max_tokens = match object.as_ref().and_then(|o| o.get("max_tokens")) {
            None => MaxTokens::Absent,
            Some(value) => value.as_u64().map_or(MaxTokens::Invalid, MaxTokens::Limit),
        };
        let max_completion_tokens =
            object.as_ref().is_some_and(|o| o.contains_key("max_completion_tokens"));
        Self { model, max_tokens, max_completion_tokens }
    }

    /// The `model` the request names, or `None` when it named none — including when the body is not
    /// JSON a `model` can be read out of. A `None` routes to a catch-all if one exists and is a
    /// `400` otherwise; it is never a `500`.
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// The request's `max_tokens`, as one of its three possible states.
    pub fn max_tokens(&self) -> MaxTokens {
        self.max_tokens
    }

    /// Whether the body has a `max_completion_tokens` key at all. Only presence is recorded: the
    /// value is not read, because Ollama ignores the field, so it limits nothing.
    pub fn has_max_completion_tokens(&self) -> bool {
        self.max_completion_tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(body, model, max_tokens, max_completion_tokens present)`.
    type Case = (&'static str, Option<&'static str>, MaxTokens, bool);

    #[test]
    fn parses_every_body_shape() {
        let u64_max = format!(r#"{{"model":"m","max_tokens":{}}}"#, u64::MAX);
        let u64_max_plus_one = r#"{"model":"m","max_tokens":18446744073709551616}"#;
        let cases: Vec<(String, Option<&str>, MaxTokens, bool)> = [
            (r#"{"model":"m"}"#, Some("m"), MaxTokens::Absent, false),
            (r#"{"model":"m","max_tokens":256}"#, Some("m"), MaxTokens::Limit(256), false),
            (r#"{"model":"m","max_tokens":0}"#, Some("m"), MaxTokens::Limit(0), false),
            (r#"{"model":"m","max_tokens":"abc"}"#, Some("m"), MaxTokens::Invalid, false),
            (r#"{"model":"m","max_tokens":"256"}"#, Some("m"), MaxTokens::Invalid, false),
            (r#"{"model":"m","max_tokens":1.5}"#, Some("m"), MaxTokens::Invalid, false),
            (r#"{"model":"m","max_tokens":256.0}"#, Some("m"), MaxTokens::Invalid, false),
            (r#"{"model":"m","max_tokens":-1}"#, Some("m"), MaxTokens::Invalid, false),
            (r#"{"model":"m","max_tokens":null}"#, Some("m"), MaxTokens::Invalid, false),
            (r#"{"model":"m","max_tokens":[1]}"#, Some("m"), MaxTokens::Invalid, false),
            (u64_max_plus_one, Some("m"), MaxTokens::Invalid, false),
            // A key given twice: the routing read is untouched, and the last value wins, as in
            // serde_json's map (and Go's encoding/json, which Ollama uses).
            (r#"{"model":"m","max_tokens":1,"max_tokens":2}"#, Some("m"), MaxTokens::Limit(2), false),
            (r#"{"model":"m","max_completion_tokens":64}"#, Some("m"), MaxTokens::Absent, true),
            (r#"{"model":"m","max_completion_tokens":"x"}"#, Some("m"), MaxTokens::Absent, true),
            (r#"{"model":"m","max_completion_tokens":null}"#, Some("m"), MaxTokens::Absent, true),
            (
                r#"{"model":"m","max_tokens":32,"max_completion_tokens":64}"#,
                Some("m"),
                MaxTokens::Limit(32),
                true,
            ),
            (r#"{}"#, None, MaxTokens::Absent, false),
            (r#"{"messages":[]}"#, None, MaxTokens::Absent, false),
            (r#"{"max_tokens":8}"#, None, MaxTokens::Limit(8), false),
            // `model`'s own failure modes still read as no model, exactly as routing always has.
            (r#"{"model":5,"max_tokens":8}"#, None, MaxTokens::Limit(8), false),
            (r#"{"model":null}"#, None, MaxTokens::Absent, false),
            (r#"{"model":"a","model":"b"}"#, None, MaxTokens::Absent, false),
            ("not json", None, MaxTokens::Absent, false),
            ("", None, MaxTokens::Absent, false),
            (r#"[{"model":"m","max_tokens":8}]"#, None, MaxTokens::Absent, false),
            (r#""model""#, None, MaxTokens::Absent, false),
        ]
        .into_iter()
        .map(|(body, model, max, mct): Case| (body.to_string(), model, max, mct))
        .chain([(u64_max, Some("m"), MaxTokens::Limit(u64::MAX), false)])
        .collect();

        for (body, model, max_tokens, max_completion_tokens) in cases {
            let shape = RequestShape::parse(body.as_bytes());
            assert_eq!(shape.model(), model, "model of {body}");
            assert_eq!(shape.max_tokens(), max_tokens, "max_tokens of {body}");
            assert_eq!(
                shape.has_max_completion_tokens(),
                max_completion_tokens,
                "max_completion_tokens presence of {body}"
            );
        }
    }
}
