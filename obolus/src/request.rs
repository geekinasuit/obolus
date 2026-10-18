//! What the gateway reads out of a completion request body.
//!
//! The body is read in one pass into a [`RequestShape`] — a second read of `model` alone happens
//! only when a `max_tokens` value cannot be decoded (see [`RequestShape::parse`]) — and is only
//! ever *read*: the bytes forwarded upstream are always the client's originals, never a
//! re-serialization of this.
//!
//! The read is tolerant by construction. `model` decides routing, so nothing else in the body may
//! be able to change what `model` reads as: a malformed `max_tokens` is recorded as malformed, not
//! allowed to fail the parse that `model` comes out of. And `max_tokens` will decide what a request
//! may be charged for, so once the read reaches a `max_tokens` key nothing else in the body can
//! make it read as absent (see [`MaxTokens`] for exactly what that does and does not cover).

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

/// The parts of a request body the gateway acts on: the `model` it routes and prices by, and the
/// output-token limit the client asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestShape {
    model: Option<String>,
    max_tokens: MaxTokens,
    max_completion_tokens: bool,
}

/// The request's `max_tokens` field, kept distinct in all three ways it can arrive.
///
/// **Invariant:** this is never [`MaxTokens::Absent`] for a body that has a top-level `max_tokens`
/// key the read reached. Once the key is seen the answer is [`MaxTokens::Limit`] or
/// [`MaxTokens::Invalid`], even when its value cannot be read or the document fails to parse
/// further on. `Absent` means only that the key is not there, or that the read failed before
/// reaching it.
///
/// The second case is narrower than it sounds — a wrong-typed or repeated `model` does not stop the
/// read — but it is not empty, and a more lenient reader may still find a limit there. `serde_json`
/// stops at an invalid UTF-8 byte or a lone surrogate escape in a top-level key, or in the `model`
/// string; Go's `encoding/json`, which Ollama uses, substitutes U+FFFD and carries on. So such a
/// byte placed *before* `max_tokens` reads here as `Absent` while Ollama honours the limit.
///
/// Keys are compared after JSON unescaping. An exact `max_tokens` given more than once takes its
/// last value.
///
/// **A key that folds to `max_tokens` without being it makes the result [`MaxTokens::Invalid`]**,
/// whatever its value, wherever it sits relative to an exact `max_tokens`, and whether or not one
/// is present. Upstream readers disagree on such a key: a case-insensitive one (Go's
/// `encoding/json`, behind Ollama) may take its limit from it, while an exact one (a typical
/// Python server behind `openai-compat`) ignores it. So no limit read here could be trusted to be
/// the one the upstream applies, and the request is marked unusable rather than guessed at. A key
/// folds to `max_tokens` when it has the same number of characters and each one either equals the
/// target's ignoring ASCII case, or is U+212A KELVIN SIGN where the target has `k`, or U+017F
/// LATIN SMALL LETTER LONG S where it has `s` — the only non-ASCII characters whose Unicode simple
/// fold reaches an ASCII letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxTokens {
    /// The body has no top-level `max_tokens` key, or failed to parse before one.
    Absent,
    /// A non-negative integer that fits a `u64`.
    Limit(u64),
    /// Present, but not a non-negative integer that fits a `u64`: a string, a float, a negative
    /// number, `null`, an out-of-range integer, any other JSON value, or a value that could not be
    /// read at all.
    Invalid,
}

impl RequestShape {
    /// Read a request body. Never fails: whatever cannot be read reads as absent (`model: None`,
    /// [`MaxTokens::Absent`]), and a `max_tokens` that is there but unusable reads as
    /// [`MaxTokens::Invalid`].
    ///
    /// One pass over the top-level object, by a hand-written visitor that builds no document tree.
    /// It reads `model` exactly as a struct holding only `model` reads it — so a non-string or
    /// `null` model, a `model` key given twice, a body that is not an object, trailing bytes, and a
    /// leading byte-order mark all read as no model, as routing always has — and skips every other
    /// value with the same tolerant skip, so no other field can fail the read. A wrong-typed or
    /// repeated `model` reads as no model without ending the pass. `max_tokens` is judged as it is
    /// read, and `max_completion_tokens` is only noted as present.
    ///
    /// The one place the pass reads more strictly than a skip is the `max_tokens` value itself: a
    /// string there is decoded, so an invalid UTF-8 byte or a lone surrogate inside it, or a number
    /// too large for an `f64`, fails the pass where a skip would not. That case reads as
    /// [`MaxTokens::Invalid`], and `model` is then read again on its own, so that a broken
    /// `max_tokens` still cannot change routing.
    pub fn parse(body: &[u8]) -> Self {
        let mut scan = Scan::default();
        let mut reader = serde_json::Deserializer::from_slice(body);
        let read = TopLevel(&mut scan).deserialize(&mut reader).and_then(|()| reader.end());
        let model = match read {
            Ok(()) => scan.model,
            Err(_) if scan.in_max_tokens => model_only(body),
            Err(_) => None,
        };
        let max_tokens = if scan.max_tokens_variant { MaxTokens::Invalid } else { scan.max_tokens };
        Self { model, max_tokens, max_completion_tokens: scan.max_completion_tokens }
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

    /// Whether the body has a top-level `max_completion_tokens` key at all. Only presence is
    /// recorded, never the value. Whether the field limits output depends on the backend: Ollama
    /// 0.34.4 was measured to ignore it, while an OpenAI-compatible server may honour it. What to
    /// do about a request limited only through it is the caller's decision, per backend kind.
    pub fn has_max_completion_tokens(&self) -> bool {
        self.max_completion_tokens
    }
}

/// `model` read on its own, as a struct holding only `model` reads it. The fallback for a pass that
/// failed inside a `max_tokens` value (see [`RequestShape::parse`]): there, only this read can say
/// what `model` would have been.
fn model_only(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct ModelField {
        #[serde(default)]
        model: Option<String>,
    }
    serde_json::from_slice::<ModelField>(body).ok().and_then(|parsed| parsed.model)
}

/// What the pass has found so far. Kept outside the visitor so that what was seen before a parse
/// error survives it — which is how a `max_tokens` key seen before a later failure still counts.
struct Scan {
    model: Option<String>,
    max_tokens: MaxTokens,
    max_completion_tokens: bool,
    /// Set while a `max_tokens` value is being read, and cleared once it has been: still set after
    /// an error means the error was inside that value.
    in_max_tokens: bool,
    /// Set once a key that folds to `max_tokens` without being it has been seen. It makes the
    /// result [`MaxTokens::Invalid`] whatever else the body holds, because readers disagree on
    /// such a key: a case-insensitive one may take its limit from it, an exact one ignores it.
    max_tokens_variant: bool,
}

impl Default for Scan {
    fn default() -> Self {
        Self {
            model: None,
            max_tokens: MaxTokens::Absent,
            max_completion_tokens: false,
            in_max_tokens: false,
            max_tokens_variant: false,
        }
    }
}

/// The top-level keys the pass acts on, compared after JSON unescaping. Any other key is `Other`,
/// and its value is skipped.
enum Key {
    /// Exactly `model`, as a derived struct matches it.
    Model,
    /// Exactly `max_tokens`.
    MaxTokens,
    /// A key that is not `max_tokens` but that [`folds_to`] it: `MAX_TOKENS`, `Max_Tokens`, and
    /// the like. A reader that matches keys case-insensitively may take its limit from such a key,
    /// one that matches exactly will not, so the request's limit depends on who reads it.
    MaxTokensVariant,
    /// Exactly `max_completion_tokens`.
    MaxCompletionTokens,
    Other,
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_identifier(KeyVisitor)
    }
}

struct KeyVisitor;

impl<'de> Visitor<'de> for KeyVisitor {
    type Value = Key;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("an object key")
    }

    fn visit_str<E>(self, key: &str) -> Result<Key, E> {
        Ok(match key {
            "model" => Key::Model,
            "max_tokens" => Key::MaxTokens,
            "max_completion_tokens" => Key::MaxCompletionTokens,
            _ if folds_to(key, "max_tokens") => Key::MaxTokensVariant,
            _ => Key::Other,
        })
    }
}

/// Whether `key` matches the ASCII `target` under Unicode simple case folding. This is not an
/// attempt to reproduce any one reader's key matching; it is wide enough that every key a
/// case-insensitive reader (Go's `encoding/json` among them) could match to `target` is caught.
///
/// For an ASCII target that comes down to three rules per character, with the two strings the same
/// length in characters: the characters are equal ignoring ASCII case; or the target is `k` and the
/// character is U+212A KELVIN SIGN; or the target is `s` and the character is U+017F LATIN SMALL
/// LETTER LONG S. Those two are the only non-ASCII characters whose simple fold reaches an ASCII
/// letter.
fn folds_to(key: &str, target: &str) -> bool {
    const KELVIN_SIGN: u32 = 0x212A;
    const LONG_S: u32 = 0x017F;
    key.chars().count() == target.chars().count()
        && key.chars().zip(target.chars()).all(|(c, t)| {
            c.eq_ignore_ascii_case(&t)
                || (t == 'k' && c as u32 == KELVIN_SIGN)
                || (t == 's' && c as u32 == LONG_S)
        })
}

/// The pass over the top-level value. Mirrors what `#[derive(Deserialize)]` generates for a struct
/// whose one field is `#[serde(default)] model: Option<String>`, so `model` reads identically: an
/// object is read key by key, and an array is read positionally, its first element as `model`.
struct TopLevel<'s>(&'s mut Scan);

impl<'de> DeserializeSeed<'de> for TopLevel<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_struct("ModelField", &["model"], self)
    }
}

impl<'de> Visitor<'de> for TopLevel<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.0.model = seq.next_element::<Option<String>>()?.flatten();
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        // A `model` key given twice, or a `model` that is neither a string nor `null`, fails a
        // derived struct's read outright, so it reads as no model. Here it only *poisons* `model`
        // and the pass carries on, so a `max_tokens` after it is still seen.
        let mut model_seen = false;
        let mut poisoned = false;
        while let Some(key) = map.next_key::<Key>()? {
            match key {
                Key::Model if model_seen => {
                    poisoned = true;
                    map.next_value::<IgnoredAny>()?;
                }
                Key::Model => {
                    model_seen = true;
                    match map.next_value::<ModelValue>()? {
                        ModelValue::Named(model) => self.0.model = Some(model),
                        ModelValue::Null => {}
                        ModelValue::NotAString => poisoned = true,
                    }
                }
                Key::MaxTokens => {
                    // Recorded before the value is read, so a value that fails to read still
                    // leaves the key counted.
                    self.0.max_tokens = MaxTokens::Invalid;
                    self.0.in_max_tokens = true;
                    self.0.max_tokens = map.next_value::<Judged>()?.0;
                    self.0.in_max_tokens = false;
                }
                Key::MaxTokensVariant => {
                    // Sticky, whatever order the keys come in: see `Scan::max_tokens_variant`.
                    self.0.max_tokens_variant = true;
                    map.next_value::<IgnoredAny>()?;
                }
                Key::MaxCompletionTokens => {
                    self.0.max_completion_tokens = true;
                    map.next_value::<IgnoredAny>()?;
                }
                Key::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if poisoned {
            self.0.model = None;
        }
        Ok(())
    }
}

/// A `model` value, read as `Option<String>` reads it but without failing on a wrong type: a
/// string names a model, `null` names none, and anything else is skipped and reported, for the
/// caller to treat as the failure a derived read would have been.
enum ModelValue {
    Named(String),
    Null,
    NotAString,
}

impl<'de> Deserialize<'de> for ModelValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ModelValueVisitor)
    }
}

struct ModelValueVisitor;

impl<'de> Visitor<'de> for ModelValueVisitor {
    type Value = ModelValue;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_str<E>(self, model: &str) -> Result<ModelValue, E> {
        Ok(ModelValue::Named(model.to_owned()))
    }

    fn visit_string<E>(self, model: String) -> Result<ModelValue, E> {
        Ok(ModelValue::Named(model))
    }

    fn visit_unit<E>(self) -> Result<ModelValue, E> {
        Ok(ModelValue::Null)
    }

    fn visit_u64<E>(self, _: u64) -> Result<ModelValue, E> {
        Ok(ModelValue::NotAString)
    }

    fn visit_i64<E>(self, _: i64) -> Result<ModelValue, E> {
        Ok(ModelValue::NotAString)
    }

    fn visit_f64<E>(self, _: f64) -> Result<ModelValue, E> {
        Ok(ModelValue::NotAString)
    }

    fn visit_bool<E>(self, _: bool) -> Result<ModelValue, E> {
        Ok(ModelValue::NotAString)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<ModelValue, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(ModelValue::NotAString)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<ModelValue, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(ModelValue::NotAString)
    }
}

/// A `max_tokens` value, judged as it is read: any JSON value is accepted, and only a non-negative
/// integer that fits a `u64` is a [`MaxTokens::Limit`].
struct Judged(MaxTokens);

impl<'de> Deserialize<'de> for Judged {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Judge).map(Judged)
    }
}

struct Judge;

impl<'de> Visitor<'de> for Judge {
    type Value = MaxTokens;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_u64<E>(self, n: u64) -> Result<MaxTokens, E> {
        Ok(MaxTokens::Limit(n))
    }

    fn visit_i64<E>(self, n: i64) -> Result<MaxTokens, E> {
        Ok(u64::try_from(n).map_or(MaxTokens::Invalid, MaxTokens::Limit))
    }

    fn visit_f64<E>(self, _: f64) -> Result<MaxTokens, E> {
        Ok(MaxTokens::Invalid)
    }

    fn visit_bool<E>(self, _: bool) -> Result<MaxTokens, E> {
        Ok(MaxTokens::Invalid)
    }

    fn visit_str<E>(self, _: &str) -> Result<MaxTokens, E> {
        Ok(MaxTokens::Invalid)
    }

    fn visit_unit<E>(self) -> Result<MaxTokens, E> {
        Ok(MaxTokens::Invalid)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<MaxTokens, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(MaxTokens::Invalid)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<MaxTokens, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(MaxTokens::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The routing read as it stood before this module: the oracle `model` is held to on every
    /// body, so the pass can never route a request differently from it.
    fn old_model_read(body: &[u8]) -> Option<String> {
        #[derive(Deserialize)]
        struct ModelField {
            #[serde(default)]
            model: Option<String>,
        }
        serde_json::from_slice::<ModelField>(body).ok().and_then(|parsed| parsed.model)
    }

    fn bytes(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    /// `(body, model, max_tokens, max_completion_tokens present)`.
    fn cases() -> Vec<(Vec<u8>, Option<&'static str>, MaxTokens, bool)> {
        use MaxTokens::{Absent, Invalid, Limit};
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        let deep = deep.as_bytes();
        let text: Vec<(&str, Option<&'static str>, MaxTokens, bool)> = vec![
            (r#"{"model":"m"}"#, Some("m"), Absent, false),
            (r#"{"model":"m","max_tokens":256}"#, Some("m"), Limit(256), false),
            (r#"{"model":"m","max_tokens":0}"#, Some("m"), Limit(0), false),
            (r#"{"model":"m","max_tokens":"abc"}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":"256"}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":1.5}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":256.0}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":-1}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":null}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":true}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":[1]}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":{"n":1}}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":18446744073709551616}"#, Some("m"), Invalid, false),
            // A key given twice takes its last value.
            (r#"{"model":"m","max_tokens":1,"max_tokens":2}"#, Some("m"), Limit(2), false),
            (r#"{"model":"m","max_tokens":1,"max_tokens":"x"}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":"x","max_tokens":3}"#, Some("m"), Limit(3), false),
            (r#"{"model":"m","max_completion_tokens":64}"#, Some("m"), Absent, true),
            (r#"{"model":"m","max_completion_tokens":"x"}"#, Some("m"), Absent, true),
            (r#"{"model":"m","max_completion_tokens":null}"#, Some("m"), Absent, true),
            (r#"{"model":"m","max_tokens":32,"max_completion_tokens":64}"#, Some("m"), Limit(32), true),
            // A nested `max_tokens` is not the request's.
            (r#"{"model":"m","options":{"max_tokens":9}}"#, Some("m"), Absent, false),
            (r#"{}"#, None, Absent, false),
            (r#"{"messages":[]}"#, None, Absent, false),
            (r#"{"max_tokens":8}"#, None, Limit(8), false),
            // `model`'s own failure modes read as no model, exactly as routing always has, but do
            // not hide a `max_tokens` on either side of them.
            (r#"{"model":5,"max_tokens":8}"#, None, Limit(8), false),
            (r#"{"max_tokens":8,"model":5}"#, None, Limit(8), false),
            (r#"{"model":true,"max_tokens":8}"#, None, Limit(8), false),
            (r#"{"model":["m"],"max_tokens":8}"#, None, Limit(8), false),
            (r#"{"model":{"m":1},"max_tokens":8}"#, None, Limit(8), false),
            (r#"{"model":null}"#, None, Absent, false),
            (r#"{"model":null,"max_tokens":8}"#, None, Limit(8), false),
            (r#"{"model":"a","model":"b"}"#, None, Absent, false),
            (r#"{"model":"a","model":"b","max_tokens":5000}"#, None, Limit(5000), false),
            (r#"{"model":null,"model":"b","max_tokens":5000}"#, None, Limit(5000), false),
            (r#"{"model":"a","max_tokens":5,"model":"b"}"#, None, Limit(5), false),
            (r#"{"model":"m"} x"#, None, Absent, false),
            (r#"{"model":"m","max_tokens":5} x"#, None, Limit(5), false),
            (r#"{"model":"m","max_tokens":5000,"#, None, Limit(5000), false),
            ("not json", None, Absent, false),
            ("", None, Absent, false),
            (r#""model""#, None, Absent, false),
            // An array reads positionally, as a derived struct reads it: its first element is the
            // model. Odd, but it is what routing has always done, so it is kept.
            (r#"["m"]"#, Some("m"), Absent, false),
            (r#"[]"#, None, Absent, false),
            (r#"["m","extra"]"#, None, Absent, false),
            (r#"[{"model":"m","max_tokens":8}]"#, None, Absent, false),
            // A value the strict read of `max_tokens` rejects but a skip accepts: `Invalid`, and
            // `model` still read.
            (r#"{"model":"m","max_tokens":"\ud800"}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":1e400}"#, Some("m"), Invalid, false),
            (r#"{"model":"m","max_tokens":"\ud800""#, None, Invalid, false),
            // A lone surrogate elsewhere does not hide `max_tokens`, before it or after.
            (r#"{"model":"m","max_tokens":5000,"messages":[{"content":"\ud800"}]}"#, Some("m"), Limit(5000), false),
            (r#"{"messages":[{"content":"\ud800"}],"model":"m","max_tokens":5000}"#, Some("m"), Limit(5000), false),
            // Known residuals (see `MaxTokens`): a lone surrogate in a top-level key or in the
            // `model` string stops serde_json, so a `max_tokens` after it is not reached, where Go
            // would substitute U+FFFD and carry on. `model` still matches the old read.
            (r#"{"\ud800":1,"model":"m","max_tokens":5000}"#, None, Absent, false),
            (r#"{"model":"\ud800","max_tokens":5000}"#, None, Absent, false),
        ];
        let u64_max = format!(r#"{{"model":"m","max_tokens":{}}}"#, u64::MAX);
        let exact_escaped = ["max", &escape("005f"), "tokens"].concat();
        let built: Vec<(Vec<u8>, Option<&'static str>, MaxTokens, bool)> = vec![
            (u64_max.into_bytes(), Some("m"), Limit(u64::MAX), false),
            // Arrays nested past serde_json's document-tree depth limit, before and after the key.
            (bytes(&[br#"{"model":"m","max_tokens":5000,"x":"#, deep, b"}"]), Some("m"), Limit(5000), false),
            (bytes(&[br#"{"x":"#, deep, br#","model":"m","max_tokens":5000}"#]), Some("m"), Limit(5000), false),
            (bytes(&[br#"{"model":"m","max_tokens":"#, deep, b"}"]), Some("m"), Invalid, false),
            // A raw byte that is not UTF-8 inside a string, before and after the key.
            (
                bytes(&[br#"{"model":"m","max_tokens":5000,"messages":[{"content":"a"#, b"\xff", br#"b"}]}"#]),
                Some("m"),
                Limit(5000),
                false,
            ),
            (
                bytes(&[br#"{"messages":[{"content":"a"#, b"\xff", br#"b"}],"model":"m","max_tokens":5000}"#]),
                Some("m"),
                Limit(5000),
                false,
            ),
            (bytes(&[br#"{"model":"m","max_tokens":"a"#, b"\xff", br#"b"}"#]), Some("m"), Invalid, false),
            // Known residuals, as above, for a raw invalid UTF-8 byte.
            (bytes(&[br#"{"a"#, b"\xff", br#"":1,"model":"m","max_tokens":5000}"#]), None, Absent, false),
            (bytes(&[br#"{"model":"a"#, b"\xff", br#"","max_tokens":5000}"#]), None, Absent, false),
            // A leading byte-order mark is not JSON.
            (bytes(&[b"\xef\xbb\xbf", br#"{"model":"m","max_tokens":5}"#]), None, Absent, false),
            // Keys are compared after JSON unescaping: `max`, an escaped `_`, then `tokens` is the
            // exact key.
            (object(&[("model", r#""m""#), (&exact_escaped, "7")]), Some("m"), Limit(7), false),
            // Near misses that no reader folds to `max_tokens` are just other keys.
            (object(&[("model", r#""m""#), ("max_tokenss", "9")]), Some("m"), Absent, false),
            (object(&[("model", r#""m""#), ("max-tokens", "9")]), Some("m"), Absent, false),
            // A case variant stays `Invalid` when the parse fails after it: here on a key holding
            // a raw 0xff byte.
            (
                bytes(&[br#"{"model":"m","max_tokens":5,"MAX_TOKENS":100000,"a"#, &[0xFF_u8], br#"":1}"#]),
                None,
                Invalid,
                false,
            ),
        ];
        let folded: Vec<(Vec<u8>, Option<&'static str>, MaxTokens, bool)> = fold_variants()
            .iter()
            .flat_map(|variant| {
                let v = variant.as_str();
                [
                    // Alone, and before and after an exact key: always `Invalid`, never the
                    // exact key's value.
                    object(&[("model", r#""m""#), (v, "100000")]),
                    object(&[("model", r#""m""#), (v, "100000"), ("max_tokens", "5")]),
                    object(&[("model", r#""m""#), ("max_tokens", "5"), (v, "100000")]),
                    object(&[("model", r#""m""#), ("max_tokens", "5"), (v, "null")]),
                ]
            })
            .map(|body| (body, Some("m"), Invalid, false))
            .collect();
        text.into_iter()
            .map(|(body, model, max, mct)| (body.as_bytes().to_vec(), model, max, mct))
            .chain(built)
            .chain(folded)
            .collect()
    }

    /// A JSON escape for the code point `hex`, as six characters in the body. Assembled at run time
    /// so that the escape never appears in this source file, where editing tools decode it.
    fn escape(hex: &str) -> String {
        format!("{}u{hex}", '\\')
    }

    /// A JSON object of the given `(key, raw JSON value)` pairs, in order. Keys are written as
    /// given, so a key may carry escapes.
    fn object(entries: &[(&str, &str)]) -> Vec<u8> {
        let body: Vec<String> = entries.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
        format!("{{{}}}", body.join(",")).into_bytes()
    }

    /// Keys that fold to `max_tokens` (see `folds_to`) without being `max_tokens` itself.
    fn fold_variants() -> Vec<String> {
        let kelvin = char::from_u32(0x212A).unwrap().to_string();
        let long_s = char::from_u32(0x017F).unwrap().to_string();
        vec![
            "MAX_TOKENS".to_string(),
            "Max_Tokens".to_string(),
            ["max_to", &kelvin, "ens"].concat(),
            ["max_token", &long_s].concat(),
            // Escaped forms of a variant: an escaped `_` in an upper-case key, and the Kelvin sign
            // written as an escape.
            ["MAX", &escape("005f"), "TOKENS"].concat(),
            ["max_to", &escape("212a"), "ens"].concat(),
        ]
    }

    #[test]
    fn the_escaped_rows_really_carry_escapes() {
        // The escaped-key rows test unescaping only if the body holds a backslash escape rather
        // than the character it stands for.
        assert_eq!(escape("005f").as_bytes(), &[b'\\', b'u', b'0', b'0', b'5', b'f']);
        let body = object(&[(&["max", &escape("005f"), "tokens"].concat(), "7")]);
        assert!(!String::from_utf8(body).unwrap().contains("max_tokens"));
    }

    #[test]
    fn parses_every_body_shape() {
        for (body, model, max_tokens, max_completion_tokens) in cases() {
            let shown = String::from_utf8_lossy(&body);
            let shape = RequestShape::parse(&body);
            assert_eq!(shape.model(), model, "model of {shown}");
            assert_eq!(shape.max_tokens(), max_tokens, "max_tokens of {shown}");
            assert_eq!(
                shape.has_max_completion_tokens(),
                max_completion_tokens,
                "max_completion_tokens presence of {shown}"
            );
        }
    }

    #[test]
    fn model_reads_as_the_old_routing_read_did_on_every_body() {
        for (body, _, _, _) in cases() {
            let shown = String::from_utf8_lossy(&body);
            assert_eq!(
                RequestShape::parse(&body).model(),
                old_model_read(&body).as_deref(),
                "model of {shown}"
            );
        }
    }
}
