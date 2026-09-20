//! Turning a declarative backend configuration into the registry of upstreams a gateway serves
//! from.
//!
//! S0 made [`crate::upstream::Upstream`] object-safe so a gateway can hold a runtime-chosen
//! backend behind `Arc<dyn Upstream>`. This module is where that backend comes *from*: an operator
//! declares one or more backends — each a `(kind, base URL, optional key reference)` — and this
//! parses, validates, and constructs the registry at startup.
//!
//! Two properties are deliberate and load-bearing:
//!
//! * **Config faults fail loud at boot, not at first request.** A malformed or contradictory
//!   configuration — bad JSON, an unreadable / empty / non-header-safe key file, a non-`http://`
//!   origin, an unimplemented kind, more than one backend — refuses to start rather than 500-ing
//!   the first paid request weeks later, the same stance [`crate::config`] takes for the payment
//!   options. What boot cannot settle without dialing it does not claim to: the `baseUrl` check is
//!   scheme-only (as it is for `OBOLUS_UPSTREAM_URL`), so a well-formed-but-unreachable origin — or
//!   an `http://` value carrying an odd path — still surfaces at request time. Reachability is not
//!   a config property.
//! * **Keys are *referenced*, never inlined.** A backend names a `keyFile`; the loader reads it —
//!   through an injected reader, so the whole thing is hermetically testable — and the resolved
//!   secret lives only inside the [`OllamaUpstream`] that sends it, never in a config struct, a log
//!   line, or a `Debug`.
//!
//! ## Scope
//!
//! `ollama` and `openai-compat` are the same wire shape — both POST to `/v1/chat/completions` — so
//! both are served by [`OllamaUpstream`], the difference being only whether a bearer is attached.
//! `anthropic-compat` speaks a different wire format and is refused at boot as not-yet-implemented
//! (it is in the #53 hardening backlog).
//!
//! **Routing (S2).** More than one backend is allowed; a request is routed to a backend by its
//! `model` field, resolved through each backend's `models` aliases and `precedence` (see
//! [`Backends::route`]). A backend with an empty `models` list is a *catch-all* that serves any
//! model — allowed only when it is the sole backend (the `OBOLUS_UPSTREAM_URL` shim and a one-entry
//! config are this case). With more than one backend a nameless catch-all is refused at boot: under
//! a selector it would silently swallow traffic meant for a named sibling, the very surprise
//! fail-loud exists to prevent. Two backends that name the same alias at the same precedence are
//! refused too — the route would be ambiguous — as are two backends sharing an `id`.

use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderValue;
use serde::Deserialize;

use crate::upstream::{OllamaUpstream, Upstream};

/// The wire protocol a backend speaks. A closed set on purpose: an operator's `kind` string is
/// matched against exactly these, and an unknown one fails to parse rather than defaulting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// A local Ollama origin (or any keyless OpenAI-compatible server). No credential is sent.
    Ollama,
    /// A hosted OpenAI-compatible API. Same wire shape as [`Ollama`](Kind::Ollama); differs only
    /// in that it may carry a bearer token read from a `keyFile`.
    OpenaiCompat,
    /// Anthropic's Messages API. A different request/response shape from the OpenAI one, so it is
    /// not served by [`OllamaUpstream`] and is refused at boot until its own upstream lands.
    AnthropicCompat,
}

impl std::fmt::Display for Kind {
    /// The `kind` string an operator writes in the config — not the Rust variant name — so an
    /// error message names the value they must go and fix.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Kind::Ollama => "ollama",
            Kind::OpenaiCompat => "openai-compat",
            Kind::AnthropicCompat => "anthropic-compat",
        })
    }
}

/// One entry in the backend config array, exactly as written.
///
/// `deny_unknown_fields` for the reason [`crate::config::AcceptEntry`] uses it: a typo
/// (`baseURL`, `keyfile`) must fail loudly at startup, not be silently dropped and leave a backend
/// pointed at a default nobody meant. `models` and `precedence` default to empty/`None`: a backend
/// that omits `models` is a catch-all serving every request (legal only as the sole backend), and an
/// omitted `precedence` ranks below any explicit one.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackendEntry {
    id: String,
    kind: Kind,
    base_url: String,
    #[serde(default)]
    key_file: Option<String>,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    precedence: Option<i64>,
}

/// Why a backend configuration could not be turned into a registry. Every arm is a boot-time
/// refusal; none can arise at request time.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum BackendError {
    /// Not a JSON array of the expected shape — bad JSON, wrong type, an unknown/missing field, or
    /// an unrecognised `kind`.
    #[error(
        "backend config must be a JSON array of \
         {{\"id\",\"kind\",\"baseUrl\", optional \"keyFile\"/\"models\"/\"precedence\"}} objects: {0}"
    )]
    Malformed(String),

    /// A syntactically valid but empty array. A gateway with no backend has nothing to serve.
    #[error(
        "backend config is an empty array: declare at least one backend, or unset the config file \
         to use the single-backend OBOLUS_UPSTREAM_URL path instead"
    )]
    Empty,

    /// Two backends share an `id`. The id names the backend in diagnostics and routing; a duplicate
    /// makes both ambiguous.
    #[error("backend config declares two backends with id {id:?}; each backend's id must be unique")]
    DuplicateBackendId { id: String },

    /// A backend with an empty `models` list — a catch-all serving every model — declared alongside
    /// others. Refused because a catch-all under a selector silently swallows traffic meant for a
    /// named sibling: the same surprise the one-backend rule used to prevent. A sole backend may be
    /// a catch-all (it is the whole registry); a catch-all *with siblings* cannot.
    #[error(
        "backend {id:?} declares no models, making it a catch-all, but other backends are declared \
         too — a catch-all alongside named backends would silently swallow their traffic. Give it an \
         explicit models list, or declare it as the only backend."
    )]
    CatchAllWithSiblings { id: String },

    /// Two backends name the same model alias at the same precedence, so a request for that model
    /// has no single answer. Higher precedence would decide it; equal precedence cannot.
    #[error(
        "model {model:?} is served by more than one backend ({ids}) at the same precedence, so the \
         route is ambiguous — give one of them a higher precedence, or split the model between them."
    )]
    AmbiguousRoute { model: String, ids: String },

    /// A `kind` whose upstream does not exist yet — `anthropic-compat` in S1.
    #[error(
        "backend {id:?}: kind {kind} is not implemented yet — its wire format differs from the \
         OpenAI-compatible one and is tracked in the hardening backlog \
         (https://github.com/geekinasuit/obolus/issues/53). Use \"ollama\" or \"openai-compat\"."
    )]
    KindNotImplemented { id: String, kind: Kind },

    /// A backend with an empty `id`. The id names the backend in diagnostics and in routing, so an
    /// empty one is a configuration that cannot mean what it says.
    #[error("backend config has a backend with an empty id; id names the backend and must be set")]
    EmptyId,

    /// A `baseUrl` that is not an `http://` origin. The upstream client speaks plain HTTP only.
    #[error(
        "backend {id:?}: baseUrl must be an http:// origin (got {base_url:?}). The upstream client \
         speaks plain HTTP only (no TLS is wired), so reach a TLS origin through a local http→https \
         proxy — the same pattern OBOLUS_FACILITATOR_URL uses."
    )]
    BadBaseUrl { id: String, base_url: String },

    /// A `keyFile` on a `kind` that sends no credential. Flagged rather than ignored: an operator
    /// who set a key expects it to be used, and silently dropping it is the inert-config trap.
    #[error(
        "backend {id:?}: kind {kind} sends no credential, so it takes no keyFile. Use \
         \"openai-compat\" for a keyed API, or remove the keyFile."
    )]
    KeyOnKeylessKind { id: String, kind: Kind },

    /// The referenced `keyFile` could not be read. Carries the OS detail and names the file.
    #[error("backend {id:?}: could not read keyFile {file:?}: {detail}")]
    KeyFileUnreadable { id: String, file: String, detail: String },

    /// The referenced `keyFile` is present but empty (or whitespace-only) — it reached the process
    /// carrying no token. The usual causes are an unexpanded `${VAR}` written to it or a truncated
    /// mount.
    #[error("backend {id:?}: keyFile {file:?} is empty; it must hold the bearer token sent to the origin")]
    EmptyKeyFile { id: String, file: String },

    /// The referenced `keyFile` is not UTF-8. A bearer token is ASCII text.
    #[error("backend {id:?}: keyFile {file:?} is not valid UTF-8; a bearer token is ASCII text")]
    KeyNotText { id: String, file: String },

    /// The token in `keyFile` is not a valid HTTP header value (a control character, say), so
    /// `Authorization: Bearer <token>` could not be built. Caught here, at boot, rather than as a
    /// 500 on the first request that tries to send it.
    #[error(
        "backend {id:?}: keyFile {file:?} holds a value that is not a valid HTTP header — a bearer \
         token is visible ASCII with no control characters"
    )]
    KeyNotHeaderSafe { id: String, file: String },

    /// A `models` entry that is empty or whitespace-only. An empty alias names no model.
    #[error("backend {id:?}: a models entry is empty; a model alias must name a model")]
    EmptyModelAlias { id: String },
}

/// The registry of backends a gateway serves from.
///
/// Holds one or more backends; [`load_backends`] refuses an empty array. A request is dispatched to
/// one of them by [`route`](Backends::route), which resolves the request's `model` through each
/// backend's aliases and precedence. [`single_ollama`](Backends::single_ollama) builds the one-entry
/// catch-all registry the `OBOLUS_UPSTREAM_URL` path uses.
pub struct Backends {
    entries: Vec<Backend>,
}

/// Why a request could not be routed to a backend. Unlike [`BackendError`] these are *request*-time
/// outcomes, and each maps to a 4xx the client can act on — never a 5xx (the gateway is fine; the
/// request named a model it does not serve, or none at all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// The request named a model no backend serves. Maps to `404 Not Found`.
    UnknownModel { model: String },
    /// The request named no model, and no catch-all backend exists to take it. Maps to
    /// `400 Bad Request`. Only reachable with named backends: a sole catch-all takes it instead.
    ModelRequired,
}

/// One resolved backend: its declared metadata plus the constructed upstream. The upstream is
/// private, so a `Backend` can only be obtained from a [`Backends`] built by this module — and a
/// resolved key, if any, lives inside that upstream and nowhere on this struct.
pub struct Backend {
    /// The operator-chosen name, used in diagnostics and in routing.
    pub id: String,
    pub kind: Kind,
    /// The origin, trailing slash already trimmed by [`OllamaUpstream::new`]; kept for the banner.
    pub base_url: String,
    /// Model aliases this backend serves. An empty list makes it a *catch-all* that serves any model
    /// (allowed only as the sole backend — see [`Backends::route`]).
    pub models: Vec<String>,
    /// Precedence rank: when two backends serve the same model, the higher `precedence` wins. `None`
    /// ranks below any explicit value.
    pub precedence: Option<i64>,
    /// Whether a bearer credential is attached — a boolean for the banner, never the key itself.
    pub has_key: bool,
    upstream: Arc<dyn Upstream>,
}

impl Backend {
    /// A clone of this backend's upstream handle, for wiring into a gateway.
    pub fn upstream(&self) -> Arc<dyn Upstream> {
        self.upstream.clone()
    }

    /// Whether this backend serves `model`. A catch-all (empty `models`) serves everything; a
    /// backend with an explicit list serves exactly the aliases on it.
    fn serves(&self, model: &str) -> bool {
        self.is_catch_all() || self.models.iter().any(|m| m == model)
    }

    /// A backend that names no models and therefore serves any request. Legal only as the sole
    /// backend; [`load_backends`] refuses one declared alongside others.
    fn is_catch_all(&self) -> bool {
        self.models.is_empty()
    }
}

// `Debug` by hand, not derived: `Arc<dyn Upstream>` is not `Debug`, and — more to the point — the
// upstream is where a resolved bearer lives, so it is deliberately left out. `finish_non_exhaustive`
// prints the trailing `..` that says a field is hidden. What is shown is metadata only; the
// credential cannot be reached through this impl.
impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backend")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("base_url", &self.base_url)
            .field("models", &self.models)
            .field("precedence", &self.precedence)
            .field("has_key", &self.has_key)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Backends {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backends").field("entries", &self.entries).finish()
    }
}

impl Backends {
    /// The single-backend shim: the `OBOLUS_UPSTREAM_URL` path expressed as a one-entry registry —
    /// one keyless Ollama backend — so the N = 1 case is behaviourally identical to before this
    /// module existed. `base_url`'s scheme is validated by `main` (as it was before), matching the
    /// exact message an operator on that path already gets.
    pub fn single_ollama(base_url: &str, head_timeout: Duration) -> Self {
        let upstream = Arc::new(OllamaUpstream::new(base_url).with_head_timeout(head_timeout));
        Backends::single("default", Kind::Ollama, base_url.trim_end_matches('/'), upstream)
    }

    /// A one-backend catch-all registry wrapping an already-constructed upstream. With a single
    /// backend there is nothing to route between, so it serves every request — the shape a caller
    /// that built its own upstream wants (`single_ollama` above, and `obolus-devseller`, which puts a
    /// gateway in front of a canned seller upstream). `id`, `kind`, and `base_url` are banner
    /// metadata only; `has_key` is `false` because a keyed backend is resolved through
    /// [`load_backends`], never wrapped after the fact.
    pub fn single(
        id: impl Into<String>,
        kind: Kind,
        base_url: impl Into<String>,
        upstream: Arc<dyn Upstream>,
    ) -> Self {
        Backends {
            entries: vec![Backend {
                id: id.into(),
                kind,
                base_url: base_url.into(),
                models: Vec::new(),
                precedence: None,
                has_key: false,
                upstream,
            }],
        }
    }

    /// Every backend in the registry, in declaration order. The startup banner iterates this;
    /// [`route`](Self::route) is how a request picks one.
    pub fn backends(&self) -> &[Backend] {
        &self.entries
    }

    /// Pick the backend that serves `model`, or say why none does.
    ///
    /// `model` is the request's `model` field — `None` when the body named none (or was not JSON we
    /// could read a `model` out of). Resolution:
    ///
    /// * `Some(m)` → among the backends that serve `m` (an explicit alias, or a catch-all), the one
    ///   with the highest [`precedence`](Backend::precedence). None serve it → [`UnknownModel`].
    /// * `None` → the catch-all, if there is one; otherwise [`ModelRequired`].
    ///
    /// The winner is unambiguous by construction: [`load_backends`] refuses two backends that serve
    /// the same alias at the same precedence, and a catch-all may only exist as the sole backend, so
    /// the set this chooses from never contains a tie.
    ///
    /// [`UnknownModel`]: RouteError::UnknownModel
    /// [`ModelRequired`]: RouteError::ModelRequired
    pub fn route(&self, model: Option<&str>) -> Result<&Backend, RouteError> {
        match model {
            Some(model) => self
                .entries
                .iter()
                .filter(|b| b.serves(model))
                // `None` precedence sorts below any explicit rank; ties among the eligible set are
                // impossible (load_backends refuses them), so the max is the single winner.
                .max_by_key(|b| b.precedence)
                .ok_or_else(|| RouteError::UnknownModel { model: model.to_string() }),
            None => self.entries.iter().find(|b| b.is_catch_all()).ok_or(RouteError::ModelRequired),
        }
    }
}

/// Test-only constructors that inject a fake upstream, so a routing test can assert *which* backend
/// a request reached without standing up an HTTP origin. Kept behind `cfg(test)` for the same reason
/// [`crate::upstream::FakeUpstream`] is: it must not be reachable from a shipped gateway. These build
/// a registry directly and do not run [`check_registry`] — a routing test supplies its own
/// well-formed set; the boot rules are exercised through [`load_backends`] instead.
#[cfg(test)]
impl Backends {
    pub fn from_parts(entries: Vec<Backend>) -> Self {
        Backends { entries }
    }
}

#[cfg(test)]
impl Backend {
    /// A backend wrapping an arbitrary [`Upstream`], for gateway routing tests.
    pub fn for_test(
        id: impl Into<String>,
        models: Vec<&str>,
        precedence: Option<i64>,
        upstream: Arc<dyn Upstream>,
    ) -> Self {
        Backend {
            id: id.into(),
            kind: Kind::Ollama,
            base_url: "http://test.invalid".to_string(),
            models: models.into_iter().map(str::to_string).collect(),
            precedence,
            has_key: false,
            upstream,
        }
    }
}

/// Parse a backend-config JSON array, resolve each key reference through `read_key`, and construct
/// the registry — all at startup. `head_timeout` is applied to every constructed upstream (it is a
/// process-wide setting, not per-backend).
///
/// `read_key` is injected so the loader is hermetically testable without touching the filesystem;
/// `main` passes `std::fs::read`. Every referenced key is read here, before the registry is handed
/// back, so an unreadable one is a boot refusal rather than a mid-rotation surprise.
///
/// Each entry is validated and built in turn; then three whole-registry rules are checked, all of
/// which only bite once there is more than one backend: no two backends share an `id`, no catch-all
/// (empty `models`) is declared alongside siblings, and no model alias is served by two backends at
/// equal precedence. Each is a route that could not be resolved unambiguously at request time, moved
/// to boot.
pub fn load_backends<R>(
    raw: &str,
    head_timeout: Duration,
    read_key: R,
) -> Result<Backends, BackendError>
where
    R: Fn(&str) -> std::io::Result<Vec<u8>>,
{
    let entries: Vec<BackendEntry> =
        serde_json::from_str(raw).map_err(|e| BackendError::Malformed(e.to_string()))?;

    if entries.is_empty() {
        return Err(BackendError::Empty);
    }

    let backends: Vec<Backend> = entries
        .into_iter()
        .map(|entry| build_backend(entry, head_timeout, &read_key))
        .collect::<Result<_, _>>()?;

    check_registry(&backends)?;
    Ok(Backends { entries: backends })
}

/// The whole-registry rules that a single entry cannot self-check. All are vacuous at N = 1 (a lone
/// backend has no sibling to collide with and may be a catch-all), so the single-backend path — the
/// `OBOLUS_UPSTREAM_URL` shim and a one-entry config alike — is unaffected.
fn check_registry(backends: &[Backend]) -> Result<(), BackendError> {
    // Duplicate ids: the id names a backend in diagnostics and routing, so two of them make both
    // ambiguous. O(n^2), but n is a handful of operator-declared backends.
    for (i, a) in backends.iter().enumerate() {
        if backends[i + 1..].iter().any(|b| b.id == a.id) {
            return Err(BackendError::DuplicateBackendId { id: a.id.clone() });
        }
    }

    // A catch-all (empty models) is fine as the whole registry but not alongside named siblings: a
    // selector cannot tell what the operator meant it to catch, and it would swallow their traffic.
    if backends.len() > 1 {
        if let Some(catch_all) = backends.iter().find(|b| b.is_catch_all()) {
            return Err(BackendError::CatchAllWithSiblings { id: catch_all.id.clone() });
        }
    }

    // Ambiguous routes: a model alias served by two backends at equal precedence has no single
    // winner. Higher precedence would decide it; equal precedence (including two `None`s) cannot.
    for (i, a) in backends.iter().enumerate() {
        for model in &a.models {
            let clash: Vec<String> = backends[i + 1..]
                .iter()
                .filter(|b| b.precedence == a.precedence && b.models.iter().any(|m| m == model))
                .map(|b| format!("{:?}", b.id))
                .collect();
            if !clash.is_empty() {
                let mut ids = vec![format!("{:?}", a.id)];
                ids.extend(clash);
                return Err(BackendError::AmbiguousRoute {
                    model: model.clone(),
                    ids: ids.join(", "),
                });
            }
        }
    }

    Ok(())
}

/// Validate one entry and construct its upstream. Split out so the per-entry checks live in one
/// place; called once per declared backend.
fn build_backend<R>(
    entry: BackendEntry,
    head_timeout: Duration,
    read_key: &R,
) -> Result<Backend, BackendError>
where
    R: Fn(&str) -> std::io::Result<Vec<u8>>,
{
    let BackendEntry { id, kind, base_url, key_file, models, precedence } = entry;

    if id.trim().is_empty() {
        return Err(BackendError::EmptyId);
    }
    // http:// only, for the reason main.rs rejects a non-http OBOLUS_UPSTREAM_URL: the client wires
    // no TLS, so an https:// origin would fail every request. Case-insensitive so `HTTP://` passes.
    if !base_url.to_ascii_lowercase().starts_with("http://") {
        return Err(BackendError::BadBaseUrl { id, base_url });
    }
    if models.iter().any(|m| m.trim().is_empty()) {
        return Err(BackendError::EmptyModelAlias { id });
    }

    let (has_key, upstream): (bool, Arc<dyn Upstream>) = match kind {
        Kind::AnthropicCompat => return Err(BackendError::KindNotImplemented { id, kind }),
        Kind::Ollama => {
            if key_file.is_some() {
                return Err(BackendError::KeyOnKeylessKind { id, kind });
            }
            let upstream = OllamaUpstream::new(&base_url).with_head_timeout(head_timeout);
            (false, Arc::new(upstream))
        }
        Kind::OpenaiCompat => match key_file {
            // A keyless openai-compatible origin (a local server) is allowed: it is the same wire
            // shape as ollama, just chosen by an operator who wants that name for it.
            None => {
                let upstream = OllamaUpstream::new(&base_url).with_head_timeout(head_timeout);
                (false, Arc::new(upstream))
            }
            Some(path) => {
                let token = resolve_key(&id, &path, read_key)?;
                let upstream = OllamaUpstream::new(&base_url)
                    .with_head_timeout(head_timeout)
                    .with_bearer_token(token);
                (true, Arc::new(upstream))
            }
        },
    };

    Ok(Backend {
        id,
        kind,
        base_url: base_url.trim_end_matches('/').to_string(),
        models,
        precedence,
        has_key,
        upstream,
    })
}

/// Read a key file and return the bearer token it holds, validated as a real HTTP header value.
/// The trailing newline a key file almost always carries is trimmed; a token is not expected to
/// have significant leading/trailing whitespace.
fn resolve_key<R>(id: &str, path: &str, read_key: &R) -> Result<String, BackendError>
where
    R: Fn(&str) -> std::io::Result<Vec<u8>>,
{
    let bytes = read_key(path).map_err(|e| BackendError::KeyFileUnreadable {
        id: id.to_string(),
        file: path.to_string(),
        detail: e.to_string(),
    })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| BackendError::KeyNotText { id: id.to_string(), file: path.to_string() })?;
    let token = text.trim().to_string();
    if token.is_empty() {
        return Err(BackendError::EmptyKeyFile { id: id.to_string(), file: path.to_string() });
    }
    // Validate exactly what `OllamaUpstream::forward` will build, so an unsendable token is a boot
    // refusal here rather than a per-request error there.
    if HeaderValue::from_str(&format!("Bearer {token}")).is_err() {
        return Err(BackendError::KeyNotHeaderSafe { id: id.to_string(), file: path.to_string() });
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(600);

    /// A key reader that must not be called — asserts a keyless path reads no file.
    fn no_key(_: &str) -> std::io::Result<Vec<u8>> {
        panic!("no key file should be read on this path");
    }

    /// A key reader returning fixed bytes for any path.
    fn key_bytes(bytes: &'static [u8]) -> impl Fn(&str) -> std::io::Result<Vec<u8>> {
        move |_| Ok(bytes.to_vec())
    }

    /// A key reader that always fails, as a missing or unreadable file would.
    fn unreadable(_: &str) -> std::io::Result<Vec<u8>> {
        Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"))
    }

    #[test]
    fn parses_a_single_ollama_backend() {
        let raw = r#"[{"id":"local","kind":"ollama","baseUrl":"http://127.0.0.1:11434"}]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        let b = &registry.backends()[0];
        assert_eq!(b.id, "local");
        assert_eq!(b.kind, Kind::Ollama);
        assert_eq!(b.base_url, "http://127.0.0.1:11434");
        assert!(!b.has_key, "an ollama backend carries no key");
    }

    #[test]
    fn an_empty_array_is_rejected() {
        assert_eq!(load_backends("[]", T, no_key).unwrap_err(), BackendError::Empty);
    }

    #[test]
    fn malformed_json_is_rejected() {
        let err = load_backends("not json", T, no_key).unwrap_err();
        assert!(matches!(err, BackendError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn an_object_that_is_not_an_array_is_rejected() {
        let raw = r#"{"id":"x","kind":"ollama","baseUrl":"http://h"}"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert!(matches!(err, BackendError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn an_unknown_field_is_rejected_not_silently_dropped() {
        // deny_unknown_fields: a typo'd key must fail rather than leave the field defaulted.
        let raw = r#"[{"id":"x","kind":"ollama","baseUrl":"http://h","keyfile":"/k"}]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert!(matches!(err, BackendError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn an_unknown_kind_is_rejected() {
        let raw = r#"[{"id":"x","kind":"vllm","baseUrl":"http://h"}]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert!(matches!(err, BackendError::Malformed(_)), "got {err:?}");
    }

    #[test]
    fn multiple_named_backends_load() {
        let raw = r#"[
            {"id":"a","kind":"ollama","baseUrl":"http://a","models":["llama3"]},
            {"id":"b","kind":"ollama","baseUrl":"http://b","models":["mistral"]}
        ]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        assert_eq!(registry.backends().len(), 2);
    }

    #[test]
    fn a_model_offered_by_two_backends_routes_to_the_higher_precedence_one() {
        // DoD item 1. `fast` beats `slow` because 20 > 10, regardless of declaration order.
        let raw = r#"[
            {"id":"slow","kind":"ollama","baseUrl":"http://slow","models":["llama3"],"precedence":10},
            {"id":"fast","kind":"ollama","baseUrl":"http://fast","models":["llama3"],"precedence":20}
        ]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        assert_eq!(registry.route(Some("llama3")).unwrap().id, "fast");
    }

    #[test]
    fn a_model_routes_to_the_backend_that_lists_it() {
        let raw = r#"[
            {"id":"a","kind":"ollama","baseUrl":"http://a","models":["llama3"]},
            {"id":"b","kind":"ollama","baseUrl":"http://b","models":["mistral","mixtral"]}
        ]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        assert_eq!(registry.route(Some("llama3")).unwrap().id, "a");
        assert_eq!(registry.route(Some("mixtral")).unwrap().id, "b");
    }

    #[test]
    fn an_unknown_model_is_a_route_error_not_a_panic() {
        // DoD item 2: unknown model resolves to a clean 4xx-shaped error, never a panic.
        let raw = r#"[
            {"id":"a","kind":"ollama","baseUrl":"http://a","models":["llama3"]},
            {"id":"b","kind":"ollama","baseUrl":"http://b","models":["mistral"]}
        ]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        assert_eq!(
            registry.route(Some("gpt-4")).unwrap_err(),
            RouteError::UnknownModel { model: "gpt-4".to_string() }
        );
    }

    #[test]
    fn a_sole_catch_all_serves_any_model_and_a_missing_model() {
        // The OBOLUS_UPSTREAM_URL / one-entry-no-models case: it takes everything, named or not, so
        // the pre-S2 single-backend behaviour is unchanged.
        let raw = r#"[{"id":"local","kind":"ollama","baseUrl":"http://h"}]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        assert_eq!(registry.route(Some("anything-at-all")).unwrap().id, "local");
        assert_eq!(registry.route(None).unwrap().id, "local");
    }

    #[test]
    fn a_sole_named_backend_still_refuses_a_model_it_does_not_list() {
        // A single backend that DOES declare models is held to them — a request for an undeclared
        // model is unroutable rather than silently served.
        let raw = r#"[{"id":"only","kind":"ollama","baseUrl":"http://h","models":["llama3"]}]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        assert_eq!(registry.route(Some("llama3")).unwrap().id, "only");
        assert!(matches!(
            registry.route(Some("gpt-4")).unwrap_err(),
            RouteError::UnknownModel { .. }
        ));
    }

    #[test]
    fn a_missing_model_with_only_named_backends_requires_a_model() {
        let raw = r#"[
            {"id":"a","kind":"ollama","baseUrl":"http://a","models":["llama3"]},
            {"id":"b","kind":"ollama","baseUrl":"http://b","models":["mistral"]}
        ]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        assert_eq!(registry.route(None).unwrap_err(), RouteError::ModelRequired);
    }

    #[test]
    fn an_explicit_precedence_outranks_an_absent_one() {
        // `None` precedence sorts below any explicit value, so the ranked backend wins.
        let raw = r#"[
            {"id":"unranked","kind":"ollama","baseUrl":"http://u","models":["llama3"]},
            {"id":"ranked","kind":"ollama","baseUrl":"http://r","models":["llama3"],"precedence":1}
        ]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        assert_eq!(registry.route(Some("llama3")).unwrap().id, "ranked");
    }

    #[test]
    fn two_backends_sharing_an_id_are_rejected() {
        let raw = r#"[
            {"id":"dup","kind":"ollama","baseUrl":"http://a","models":["llama3"]},
            {"id":"dup","kind":"ollama","baseUrl":"http://b","models":["mistral"]}
        ]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert_eq!(err, BackendError::DuplicateBackendId { id: "dup".to_string() });
    }

    #[test]
    fn a_catch_all_declared_alongside_a_named_backend_is_rejected() {
        // The silent-swallow surprise the one-backend rule used to prevent, in its S2 form.
        let raw = r#"[
            {"id":"named","kind":"ollama","baseUrl":"http://a","models":["llama3"]},
            {"id":"greedy","kind":"ollama","baseUrl":"http://b"}
        ]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert_eq!(err, BackendError::CatchAllWithSiblings { id: "greedy".to_string() });
    }

    #[test]
    fn the_same_model_at_equal_precedence_is_an_ambiguous_route() {
        let raw = r#"[
            {"id":"a","kind":"ollama","baseUrl":"http://a","models":["llama3"],"precedence":5},
            {"id":"b","kind":"ollama","baseUrl":"http://b","models":["llama3"],"precedence":5}
        ]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert!(matches!(&err, BackendError::AmbiguousRoute { model, .. } if model == "llama3"), "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("\"a\"") && msg.contains("\"b\""), "names both ids: {msg}");
    }

    #[test]
    fn the_same_model_at_absent_precedence_on_both_is_also_ambiguous() {
        // Two `None`s are equal precedence too — neither outranks the other.
        let raw = r#"[
            {"id":"a","kind":"ollama","baseUrl":"http://a","models":["llama3"]},
            {"id":"b","kind":"ollama","baseUrl":"http://b","models":["llama3"]}
        ]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert!(matches!(&err, BackendError::AmbiguousRoute { .. }), "got {err:?}");
    }

    #[test]
    fn anthropic_compat_is_rejected_as_not_implemented() {
        let raw = r#"[{"id":"claude","kind":"anthropic-compat","baseUrl":"http://p"}]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert!(
            matches!(&err, BackendError::KindNotImplemented { kind: Kind::AnthropicCompat, .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_non_http_base_url_is_rejected() {
        let raw = r#"[{"id":"x","kind":"ollama","baseUrl":"https://secure.example"}]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert!(matches!(&err, BackendError::BadBaseUrl { .. }), "got {err:?}");
        assert!(err.to_string().contains("proxy"), "steers to the proxy pattern: {err}");
    }

    #[test]
    fn an_empty_id_is_rejected() {
        let raw = r#"[{"id":"  ","kind":"ollama","baseUrl":"http://h"}]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert_eq!(err, BackendError::EmptyId);
    }

    #[test]
    fn ollama_with_a_key_file_is_rejected() {
        // A key on the keyless kind is a config mistake, not silently dropped.
        let raw = r#"[{"id":"x","kind":"ollama","baseUrl":"http://h","keyFile":"/k"}]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert!(matches!(&err, BackendError::KeyOnKeylessKind { kind: Kind::Ollama, .. }), "got {err:?}");
    }

    #[test]
    fn openai_compat_without_a_key_is_a_keyless_backend() {
        let raw = r#"[{"id":"local-oai","kind":"openai-compat","baseUrl":"http://127.0.0.1:8000"}]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        let b = &registry.backends()[0];
        assert_eq!(b.kind, Kind::OpenaiCompat);
        assert!(!b.has_key, "no keyFile => no credential");
    }

    #[test]
    fn openai_compat_resolves_and_carries_its_key() {
        // The keyed path: the loader reads the referenced file and builds a bearer-carrying
        // upstream. That the bearer actually reaches the origin is proved in upstream.rs; here we
        // prove the loader resolves the reference and marks the backend keyed.
        let raw =
            r#"[{"id":"gemini","kind":"openai-compat","baseUrl":"http://127.0.0.1:9000","keyFile":"/secrets/gemini"}]"#;
        let registry = load_backends(raw, T, key_bytes(b"sk-test-abc-123\n")).unwrap();
        let b = &registry.backends()[0];
        assert_eq!(b.kind, Kind::OpenaiCompat);
        assert!(b.has_key, "a resolved keyFile => a credential is attached");
    }

    #[test]
    fn an_unreadable_key_file_is_rejected_at_load() {
        // The core of DoD item 4: a key problem is a boot refusal, not a first-request 500.
        let raw =
            r#"[{"id":"gemini","kind":"openai-compat","baseUrl":"http://h","keyFile":"/nope"}]"#;
        let err = load_backends(raw, T, unreadable).unwrap_err();
        assert!(matches!(&err, BackendError::KeyFileUnreadable { .. }), "got {err:?}");
        assert!(err.to_string().contains("/nope"), "names the file: {err}");
    }

    #[test]
    fn an_empty_key_file_is_rejected() {
        let raw = r#"[{"id":"g","kind":"openai-compat","baseUrl":"http://h","keyFile":"/k"}]"#;
        let err = load_backends(raw, T, key_bytes(b"   \n")).unwrap_err();
        assert!(matches!(&err, BackendError::EmptyKeyFile { .. }), "got {err:?}");
    }

    #[test]
    fn a_key_with_a_control_character_is_rejected() {
        // An embedded newline survives the trim and is not header-safe — caught at boot.
        let raw = r#"[{"id":"g","kind":"openai-compat","baseUrl":"http://h","keyFile":"/k"}]"#;
        let err = load_backends(raw, T, key_bytes(b"sk-abc\ndef")).unwrap_err();
        assert!(matches!(&err, BackendError::KeyNotHeaderSafe { .. }), "got {err:?}");
    }

    #[test]
    fn models_and_precedence_are_parsed_and_carried() {
        // The routing metadata survives parsing onto the backend verbatim — the raw material the
        // registry-level route checks and `Backends::route` then work from.
        let raw = r#"[{
            "id":"x","kind":"ollama","baseUrl":"http://h",
            "models":["llama3","llama3:70b"],"precedence":10
        }]"#;
        let registry = load_backends(raw, T, no_key).unwrap();
        let b = &registry.backends()[0];
        assert_eq!(b.models, vec!["llama3", "llama3:70b"]);
        assert_eq!(b.precedence, Some(10));
    }

    #[test]
    fn an_empty_model_alias_is_rejected() {
        let raw = r#"[{"id":"x","kind":"ollama","baseUrl":"http://h","models":["good",""]}]"#;
        let err = load_backends(raw, T, no_key).unwrap_err();
        assert!(matches!(&err, BackendError::EmptyModelAlias { .. }), "got {err:?}");
    }

    #[test]
    fn the_single_ollama_shim_builds_one_keyless_backend() {
        let registry = Backends::single_ollama("http://127.0.0.1:11434/", T);
        let b = &registry.backends()[0];
        assert_eq!(b.kind, Kind::Ollama);
        assert_eq!(b.base_url, "http://127.0.0.1:11434", "trailing slash trimmed for the banner");
        assert!(!b.has_key);
    }
}
