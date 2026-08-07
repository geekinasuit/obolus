//! The access seam — who gets served without paying.
//!
//! Obolus has two ways through one gate. A caller presenting a verifiable bearer token is served
//! directly; a caller without one gets the 402 challenge and pays per request. The second path is
//! the privacy-preserving one — it establishes no identity at all — so nothing here may quietly
//! make it the grudging option.
//!
//! Same shape as [`crate::facilitator::Facilitator`]: one trait, a real implementation and a
//! `#[cfg(test)]` fake, with the request path identical across both.

use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::sync::Arc;

/// Why a token did not grant access.
///
/// Both variants take the same branch — 402 — and the split exists so a log can tell the caller's
/// bad token from our broken verifier. **Control flow must not read it.** Any arrangement of
/// verifier failures that reached the upstream would be inference given away for free, and that is
/// the asymmetry: answering 402 to a legitimate token-holder costs them a retry, while serving an
/// unverified caller costs us the work.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum VerifyError {
    /// Well-formed but not honoured: bad signature, wrong issuer, expired, unknown algorithm.
    #[error("token rejected: {0}")]
    Rejected(String),
    /// We could not evaluate the token at all.
    #[error("token verifier unavailable: {0}")]
    Unavailable(String),
}

/// Decide whether a bearer token is one we honour.
pub trait TokenVerifier: Send + Sync + 'static {
    /// `Ok(())` is the only outcome that grants access.
    ///
    /// Deliberately returns nothing on success: slice 1 has no per-identity behaviour, and a
    /// claims struct nothing reads is an invitation to start logging identity next to anonymous
    /// traffic — which is how the two paths become correlatable.
    fn verify(&self, token: &str) -> Result<(), VerifyError>;

    /// How this verifier describes its own posture for the startup banner.
    ///
    /// On the trait rather than supplied by the caller, and that is the point. Round 3 found that
    /// composing this line in `main` from the same variables that *built* the verifier still lets
    /// the two drift: the banner named an audience while the verifier enforced none, because the
    /// text came from the local rather than from the thing doing the checking. An implementation
    /// must read its own enforcing state, so there is no configuration the banner can misreport.
    fn description(&self) -> String;
}

/// A configured token path: the verifier requests are checked against, and the one line the
/// startup banner uses to describe it.
///
/// One value rather than two, and that is the whole point. `src/main.rs` is compiled by no test
/// target, so nothing in the library suite can observe whether a verifier reached the router —
/// passing `None` at the wiring site turned the entire feature off with all 153 tests still green.
/// Binding the description to the verifier makes the startup banner *derived* from what is routed,
/// which is what lets `tests/server_arming.rs` check the wiring from outside: the ENABLED line
/// cannot print for an instance that has no verifier, because there is nothing to describe.
///
/// The description is taken *from* the verifier rather than passed alongside it, which is round 3's
/// correction: while the caller supplied the text, the line could describe a posture the verifier
/// did not hold, and it did — see [`TokenVerifier::description`].
pub struct TokenPath {
    verifier: Arc<dyn TokenVerifier>,
    description: String,
}

impl TokenPath {
    pub fn new(verifier: Arc<dyn TokenVerifier>) -> Self {
        let description = verifier.description();
        Self { verifier, description }
    }

    /// How this path describes itself at startup — issuer, and the audience posture.
    pub fn description(&self) -> &str {
        &self.description
    }

    pub(crate) fn verify(&self, token: &str) -> Result<(), VerifyError> {
        self.verifier.verify(token)
    }
}

/// The bearer token from an `Authorization` header, if it carries one.
///
/// The scheme is matched case-insensitively per RFC 7235 §2.1 — a case-sensitive match would turn
/// a spec-compliant client into an anonymous one. An empty token is no token.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

/// The most keys one instance will verify against.
///
/// A rotation window needs two, occasionally three. The cap exists because every key a token does
/// *not* match costs a signature verification, so an unbounded set makes the cost of rejecting a
/// junk token a function of configuration.
pub const MAX_KEYS: usize = 8;

/// One public key, and the `kid` its tokens name — when they name one.
///
/// `kid` is optional because tokens minted before a deployment had more than one key do not carry
/// it, and those are exactly the tokens a rotation must not break.
struct VerifyingKey {
    kid: Option<String>,
    key: DecodingKey,
}

/// Verifies EdDSA-signed JWTs against one or more public keys.
///
/// Obolus holds no secret here: these keys can check a signature, not mint one. Phase A's
/// "holds no credential" posture is about key custody and signing, so verifying someone else's
/// signature leaves it intact — worth stating, because the two get conflated.
///
/// More than one key is what makes rotation possible without a window in which valid tokens are
/// refused: the operator arms the new key alongside the old, switches the issuer over, waits for
/// the old tokens to expire, and only then drops the old key.
pub struct PublicKeyTokenVerifier {
    /// Non-empty, at most [`MAX_KEYS`], with no `kid` repeated — all three established at
    /// construction so nothing downstream has to re-check them.
    keys: Vec<VerifyingKey>,
    /// The only state this verifier has beyond the keys, and deliberately so: everything said about
    /// this verifier — the failure wording, the startup banner — is read back off these fields
    /// rather than off a copy of the arguments that produced them. A second field remembering what
    /// was *asked for* is a field that can disagree with what is *enforced*.
    ///
    /// One `Validation` for the whole set: the issuer, the audience posture and the pinned
    /// algorithm are properties of the deployment, not of which key happened to sign.
    validation: Validation,
}

/// Why a verifier could not be built from configuration. Startup only.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct KeyError(String);

/// One entry in `OBOLUS_TOKEN_KEYS`: the file holding a public key, and the `kid` that tokens
/// signed with it carry — when the issuer names one at all.
///
/// `deny_unknown_fields` for the same reason [`crate::config`]'s entries have it: a typo must fail
/// loudly at startup rather than be silently dropped, because a dropped key here is a key whose
/// tokens stop working at the moment of a rotation.
#[derive(Debug, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenKeyEntry {
    pub kid: Option<String>,
    pub file: String,
}

/// The single-key variable `OBOLUS_TOKEN_KEYS` supersedes.
///
/// Same shape as [`crate::config::SINGLE_CHAIN_VARS`], and for the same reason: when the array form
/// is set the single variable is inert, and an operator who set both has a key they believe is
/// armed and is not. For a *verifying* key that is the quiet kind of wrong — nothing fails until a
/// token signed with the ignored key shows up.
pub const SINGLE_KEY_VAR: &str = "OBOLUS_TOKEN_PUBKEY_FILE";

/// Parse `OBOLUS_TOKEN_KEYS` — a JSON array of `{"kid": "...", "file": "..."}` objects, `kid`
/// optional.
///
/// Shape only. Whether the *set* is coherent — key count, duplicate `kid`s, whether a file holds a
/// usable key — is [`PublicKeyTokenVerifier::with_keys`]'s job, so those rules have one home rather
/// than being half-checked in two.
pub fn parse_token_keys(raw: &str) -> Result<Vec<TokenKeyEntry>, KeyError> {
    let entries: Vec<TokenKeyEntry> = serde_json::from_str(raw).map_err(|err| {
        KeyError(format!(
            "OBOLUS_TOKEN_KEYS must be a JSON array of {{\"kid\",\"file\"}} objects (\"kid\" \
             optional): {err}"
        ))
    })?;
    if entries.is_empty() {
        return Err(KeyError(
            "OBOLUS_TOKEN_KEYS is an empty array: it asks for a token path and names no key to \
             build one from. Unset it to run with the 402 path alone."
                .to_string(),
        ));
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.file.is_empty() {
            return Err(KeyError(format!(
                "OBOLUS_TOKEN_KEYS entry {index} has an empty \"file\": it names no key to read"
            )));
        }
    }
    Ok(entries)
}

impl PublicKeyTokenVerifier {
    /// `pem` is an Ed25519 **public** key; `issuer` is the `iss` every honoured token must carry;
    /// `audience` is the `aud` it must carry, when the deployment uses one.
    ///
    /// The issuer is not optional. A signing key usually belongs to an identity provider rather
    /// than to one service, so without an `iss` check every token that key has ever minted — for
    /// anything at all — is free inference here.
    ///
    /// The audience *is* optional, but not ignorable: see the `validate_aud` note below for why
    /// leaving it unset refuses tokens rather than waving them through.
    pub fn new(pem: &[u8], issuer: &str, audience: Option<&str>) -> Result<Self, KeyError> {
        Self::with_keys(&[(None, pem.to_vec())], issuer, audience)
    }

    /// The same verifier over a set of keys, each optionally carrying the `kid` its tokens name.
    ///
    /// The set must be non-empty and at most [`MAX_KEYS`], no `kid` may repeat — a duplicate makes
    /// "the key named `x`" ambiguous, and silently picking one of them is how a retired key stays
    /// live — and no key material may repeat, since a set naming one key twice reads as a rotation
    /// that is not happening. Several *unnamed* keys are fine: that is what rotating an issuer which
    /// never used `kid` looks like from here.
    pub fn with_keys(
        keys: &[(Option<String>, Vec<u8>)],
        issuer: &str,
        audience: Option<&str>,
    ) -> Result<Self, KeyError> {
        if keys.is_empty() {
            return Err(KeyError("no verifying keys: a token path needs at least one".to_string()));
        }
        if keys.len() > MAX_KEYS {
            return Err(KeyError(format!(
                "{} verifying keys, but at most {MAX_KEYS} are allowed: every key a token does not \
                 match costs a signature check, so the set is bounded",
                keys.len(),
            )));
        }
        let mut seen: Vec<&str> = Vec::new();
        let mut armed: Vec<Vec<u8>> = Vec::new();
        let mut parsed = Vec::with_capacity(keys.len());
        for (kid, pem) in keys {
            if let Some(kid) = kid {
                if kid.is_empty() {
                    return Err(KeyError(
                        "a key has an empty kid: omit it rather than naming a key nothing can \
                         match"
                            .to_string(),
                    ));
                }
                if seen.contains(&kid.as_str()) {
                    return Err(KeyError(format!(
                        "two keys share the kid {kid:?}: which one a token naming it should be \
                         checked against is then undefined"
                    )));
                }
                seen.push(kid);
            }
            let described = match kid {
                Some(kid) => format!("key {kid:?}"),
                None => "key".to_string(),
            };
            // A set holding one key twice is a rotation that is not happening, and the banner would
            // announce it as one — the specific lie D4 exists to prevent. Compared as bytes with
            // whitespace removed rather than as parsed keys, because `DecodingKey` is opaque and has
            // no equality: that catches the same file named twice and the same key pasted twice
            // under different line endings, and misses a re-encoding that changes the base64 itself.
            let material: Vec<u8> = pem.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
            if armed.contains(&material) {
                return Err(KeyError(format!(
                    "{described} repeats key material already armed: the set would name two keys \
                     where only one can sign"
                )));
            }
            armed.push(material);
            let key = DecodingKey::from_ed_pem(pem).map_err(|err| {
                KeyError(format!("{described} is not a usable Ed25519 public key: {err}"))
            })?;
            parsed.push(VerifyingKey { kid: kid.clone(), key });
        }
        // Two independent defences against alg confusion, and either alone is sufficient: the
        // algorithm is ours rather than the token's (`Validation` checks the header's `alg` against
        // this list instead of obeying it), and the key is an Ed25519 key rather than opaque bytes,
        // which the library refuses to use for an HMAC algorithm. Measured: mutating either one on
        // its own leaves an HS256-signed-with-this-public-key token rejected.
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[issuer]);
        // Reject a token that is not valid yet, not just one that has expired. Off by default.
        validation.validate_nbf = true;

        let mut required = vec!["exp", "iss"];
        match audience {
            // Requiring `aud` alongside setting it: a token that simply omits the claim would
            // otherwise satisfy an audience check it never participated in.
            Some(audience) => {
                validation.set_audience(&[audience]);
                required.push("aud");
            }
            // `validate_aud` stays true with no expected audience, which makes the library reject
            // any token that *carries* an `aud` — deliberate, and the reason this is worth a
            // comment: `aud` names the service a token was minted for, so honouring one addressed
            // elsewhere is exactly the cross-service hole the `iss` requirement exists to close.
            // An operator whose tokens carry `aud` sets OBOLUS_TOKEN_AUDIENCE; the failure below
            // says so, because "InvalidAudience" on its own sends them looking in the wrong place.
            None => {}
        }
        // `set_issuer` alone checks `iss` only on tokens that carry one, so a token minted without
        // the claim would skip the check entirely. Requiring it converts absence into a rejection.
        // `exp` is required by default; naming it here too because this call replaces that default
        // rather than adding to it.
        validation.set_required_spec_claims(&required);
        Ok(Self { keys: parsed, validation })
    }

    /// Whether an expected audience is *enforced* — all three legs, not just the set one.
    ///
    /// `aud` alone is not the posture. The library consults three fields: the expected set, whether
    /// the check runs at all (`validate_aud`), and whether a token may satisfy it by omitting the
    /// claim (`required_spec_claims`). Turning off either of the other two leaves `aud` populated
    /// and the check gone, so anything keyed on `aud` alone reports an audience nobody has to
    /// carry. Read all three, once, here.
    fn audience_enforced(&self) -> bool {
        self.validation.aud.is_some()
            && self.validation.validate_aud
            && self.validation.required_spec_claims.contains("aud")
    }

    /// The keys to try, in order.
    ///
    /// This is the whole of what a token's own header is permitted to do here: **narrow** the set
    /// we try, never add to it, and never change *how* we verify. The `kid` arrives unverified and
    /// so is attacker-chosen — which costs nothing, because the signature still has to check out
    /// against whichever key it steered us to. `Header` carries `alg` on the very same struct this
    /// reads `kid` off; obeying that field instead of `validation`'s pinned algorithm is the
    /// classic confusion attack, and the distance between the safe read and the unsafe one is one
    /// field name.
    ///
    /// A `kid` matching nothing does not shrink the set and does not reject the token, it merely
    /// stops being a hint. That is not leniency: tokens minted before an operator had a second key
    /// carry no `kid` at all, so a set that only honoured its named keys would refuse every
    /// outstanding token the moment a second key was armed — the exact cutover this exists to
    /// remove.
    fn ordered_by(&self, kid: Option<&str>) -> Vec<&VerifyingKey> {
        let mut ordered: Vec<&VerifyingKey> = Vec::with_capacity(self.keys.len());
        if let Some(kid) = kid {
            ordered.extend(self.keys.iter().filter(|key| key.kid.as_deref() == Some(kid)));
        }
        ordered.extend(self.keys.iter().filter(|key| kid.is_none() || key.kid.as_deref() != kid));
        ordered
    }
}

/// `aud` in the two shapes RFC 7519 §4.1.3 allows, and no others.
///
/// The type is the check. See [`Claims::aud`].
#[derive(serde::Deserialize)]
#[serde(untagged)]
#[allow(dead_code)] // Nothing reads the values; the deserialise either succeeds or rejects the token.
enum Audience {
    One(String),
    Many(Vec<String>),
}

/// The claims we insist on being able to read.
///
/// Nothing reads the values — presence is enforced by `required_spec_claims` and the values by
/// `Validation`. Declaring them typed adds a second, independent rejection: a token whose `exp` is
/// a string, or whose `iss` is an object, fails to deserialise even if it satisfied validation.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct Claims {
    exp: usize,
    iss: String,
    /// Typed, and load-bearing rather than documentation. The library's own audience arm fires
    /// only on an `aud` it could parse, so with no expected audience configured a token carrying
    /// `{"aud": 12345}` or `{"aud": {..}}` was **honoured** while `{"aud": "the-wiki"}` was
    /// refused — measured, not inferred. That made "unset refuses any token carrying `aud`" true
    /// of the well-formed shapes only, which is the wrong half to be true. Declaring the type
    /// rejects the rest here, so the property holds for every `aud` a token can carry *a value in*.
    ///
    /// The one shape it does not cover is `"aud": null`, which `Option` resolves to `None` without
    /// consulting `Audience` — so in the unset posture such a token is honoured. That is correct
    /// rather than a gap: `null` carries no audience, so it is the `aud`-less token the unset
    /// posture is *for*, and it is refused in the configured posture like any other missing claim.
    /// Both halves are pinned below.
    aud: Option<Audience>,
}

impl TokenVerifier for PublicKeyTokenVerifier {
    fn verify(&self, token: &str) -> Result<(), VerifyError> {
        // Unverified at this point, and used for nothing but ordering — see `ordered_by`. A header
        // we cannot even parse yields no hint, and the token then fails the same decode below that
        // any other malformed one does.
        let kid = jsonwebtoken::decode_header(token).ok().and_then(|header| header.kid);

        // Exactly one rejection is reported, and which one is not arbitrary — see `names_a_cause`.
        // A per-key breakdown would answer "how many keys does this gateway hold, and what are they
        // called" to anyone willing to send a bad token.
        let mut reported: Option<jsonwebtoken::errors::Error> = None;
        for key in self.ordered_by(kid.as_deref()) {
            match jsonwebtoken::decode::<Claims>(token, &key.key, &self.validation) {
                Ok(_) => return Ok(()),
                Err(err) => {
                    let keep = match &reported {
                        None => true,
                        Some(held) => names_a_cause(&err) && !names_a_cause(held),
                    };
                    if keep {
                        reported = Some(err);
                    }
                }
            }
        }
        Err(VerifyError::Rejected(match &reported {
            Some(err) => describe(err, self.audience_enforced()),
            // Unreachable — `with_keys` refuses an empty set, so the loop ran at least once and
            // either returned or recorded. Fail closed rather than panic on the request path.
            None => "NO VERIFYING KEY WAS CONSULTED — this is a bug, not a setting".to_string(),
        }))
    }

    /// The startup line, rendered from the `Validation` that `verify` hands to the library — not
    /// from the arguments `new` was called with.
    ///
    /// The difference is the whole fix. While `main` formatted this line from its own locals, an
    /// instance could announce `audience obolus-prod` while its `Validation` enforced no audience
    /// at all: measured, with both test targets green. Every value below comes from a field
    /// `jsonwebtoken::decode` consults, so a posture that is not enforced cannot be announced.
    ///
    /// The two "not a setting" strings are unreachable through [`PublicKeyTokenVerifier::new`],
    /// which is why they say so: no operator input produces them, only an edit that decouples the
    /// legs of the audience check. They exist to be *loud* in that case rather than to be read.
    fn description(&self) -> String {
        // Sets, so unordered. Sort before joining: an exec test matches this text, and a set that
        // reorders between runs is a miserable flake to chase.
        let mut issuers: Vec<&str> =
            self.validation.iss.iter().flatten().map(String::as_str).collect();
        issuers.sort_unstable();
        let issuer = match (issuers.is_empty(), self.validation.required_spec_claims.contains("iss"))
        {
            (false, true) => format!("issuer {}", issuers.join(", ")),
            // `set_issuer` alone checks `iss` only on tokens that carry one, so an unrequired
            // issuer is not an enforced one however populated the set looks.
            _ => "NO ENFORCED ISSUER — this is a bug, not a setting".to_string(),
        };

        let mut expected: Vec<&str> =
            self.validation.aud.iter().flatten().map(String::as_str).collect();
        expected.sort_unstable();
        let audience = if self.audience_enforced() {
            format!("audience {}", expected.join(", "))
        } else if self.validation.aud.is_none() && self.validation.validate_aud {
            "no audience configured, so a token carrying `aud` is refused".to_string()
        } else {
            "AUDIENCE NOT ENFORCED — this is a bug, not a setting".to_string()
        };

        // Off the same `keys` field `verify` selects from, for the same reason as above: a banner
        // naming a key the request path would not consult is a banner that lies about rotation
        // state. Sorted, like the sets above, because an exec test matches this text.
        let mut named: Vec<&str> = self.keys.iter().filter_map(|key| key.kid.as_deref()).collect();
        named.sort_unstable();
        let total = self.keys.len();
        let noun = if total == 1 { "key" } else { "keys" };
        let keys = match (named.is_empty(), total - named.len()) {
            (true, 0) => "NO VERIFYING KEYS — this is a bug, not a setting".to_string(),
            (true, _) => format!("{total} {noun}, unnamed"),
            (false, 0) => format!("{total} {noun}: {}", named.join(", ")),
            (false, unnamed) => {
                format!("{total} {noun}: {}, plus {unnamed} unnamed", named.join(", "))
            }
        };

        format!("{issuer}, {audience}, {keys}")
    }
}

/// Render a verification failure for the operator reading the log.
///
/// Only the audience case is reworded, because it is the only one whose library wording points
/// somewhere useful-looking and wrong — but only on one of its two causes, which is why this needs
/// `audience_enforced`. `InvalidAudience` is raised both when no audience is set (the operator
/// has a setting to make, and bare "InvalidAudience" sends them hunting a mismatch instead) and
/// when one is set and the token names a different service (where the mismatch *is* the cause and
/// the hunt is the right instinct — there, telling them to set the variable they have already set
/// is the misdirection). Every other kind keeps the library's own text: paraphrasing errors we
/// have nothing to add to just puts a second vocabulary between the operator and the cause.
fn describe(err: &jsonwebtoken::errors::Error, audience_enforced: bool) -> String {
    match err.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidAudience if !audience_enforced => {
            "token audience not accepted — Obolus has no expected audience, so a token carrying \
             `aud` is refused rather than honoured. Set OBOLUS_TOKEN_AUDIENCE to the value Obolus \
             should answer to"
                .to_string()
        }
        jsonwebtoken::errors::ErrorKind::InvalidAudience => {
            "token audience not accepted — its `aud` is not the audience OBOLUS_TOKEN_AUDIENCE \
             names, so this token was minted for something else. The setting did reach this \
             process (the startup banner prints it)"
                .to_string()
        }
        _ => err.to_string(),
    }
}

/// Whether a rejection says anything beyond "not this key".
///
/// A token can be signed by at most one key in a set — `with_keys` refuses to arm the same material
/// twice — so at most one key can get past the signature to judge the claims, which makes a
/// non-signature error, where one exists, the only rejection that came from the key which actually
/// signed. The rest contribute `InvalidSignature`, restating the question. So there is no tie to
/// break and no ordering to prefer: keep the one that names a cause. Errors raised before any
/// signature is checked — a pinned-algorithm mismatch, a token too malformed to split — come out of
/// every key alike, and the first is as good as the last.
///
/// The conclusion does not actually rest on that uniqueness. A duplicate slipping past the arming
/// check (re-encoded, so the bytes differ) would put two keys past the signature, and they would
/// report the *same* claim error, since they agree on the token. Uniqueness makes the rule easy to
/// state; identical errors make it true either way.
fn names_a_cause(err: &jsonwebtoken::errors::Error) -> bool {
    !matches!(err.kind(), jsonwebtoken::errors::ErrorKind::InvalidSignature)
}

/// A verifier with no cryptography, for tests that are about the *branch* rather than the signature.
#[cfg(test)]
pub struct FakeTokenVerifier {
    honoured: String,
    otherwise: VerifyError,
    description: String,
}

#[cfg(test)]
impl FakeTokenVerifier {
    /// Honours exactly this token; everything else is rejected.
    pub fn honouring(token: impl Into<String>) -> Self {
        Self {
            honoured: token.into(),
            otherwise: VerifyError::Rejected("not the honoured token".to_string()),
            description: FAKE_DESCRIPTION.to_string(),
        }
    }

    /// Honours nothing, and fails the way a broken introspection endpoint would.
    pub fn always_unavailable(reason: impl Into<String>) -> Self {
        Self {
            // No token can equal this, so every call takes the `otherwise` arm.
            honoured: "\0".to_string(),
            otherwise: VerifyError::Unavailable(reason.into()),
            description: FAKE_DESCRIPTION.to_string(),
        }
    }
}

/// Deliberately not shaped like a real posture line: a test that accidentally asserts against this
/// text should read as obviously wrong rather than as a plausible issuer/audience pair.
#[cfg(test)]
const FAKE_DESCRIPTION: &str = "a fake verifier, not a configured one";

#[cfg(test)]
impl TokenVerifier for FakeTokenVerifier {
    fn verify(&self, token: &str) -> Result<(), VerifyError> {
        if token == self.honoured {
            Ok(())
        } else {
            Err(self.otherwise.clone())
        }
    }

    fn description(&self) -> String {
        self.description.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with(authorization: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(authorization).unwrap());
        headers
    }

    #[test]
    fn a_bearer_token_is_extracted_whatever_the_scheme_case() {
        for header in ["Bearer abc.def.ghi", "bearer abc.def.ghi", "BEARER abc.def.ghi"] {
            assert_eq!(bearer_token(&headers_with(header)), Some("abc.def.ghi"), "{header}");
        }
    }

    #[test]
    fn a_non_bearer_scheme_carries_no_token() {
        assert_eq!(bearer_token(&headers_with("Basic abc")), None);
        assert_eq!(bearer_token(&headers_with("Bearer")), None);
    }

    #[test]
    fn an_empty_bearer_value_is_not_a_token() {
        // Otherwise `verify("")` decides the outcome, and an empty string is the input a verifier
        // is least likely to have an opinion about.
        assert_eq!(bearer_token(&headers_with("Bearer    ")), None);
    }

    #[test]
    fn no_authorization_header_carries_no_token() {
        assert_eq!(bearer_token(&HeaderMap::new()), None);
    }

    #[test]
    fn a_public_key_verifier_needs_an_actual_public_key() {
        let err = PublicKeyTokenVerifier::new(b"-----BEGIN PUBLIC KEY-----\nnope\n", "iss", None);
        assert!(err.is_err(), "garbage PEM must fail at construction, not at first request");
    }
}

/// What [`PublicKeyTokenVerifier`] does against real signatures.
///
/// Every token here is minted at run time from a keypair generated at run time, so the repository
/// holds no key material and "signed by the wrong key" means a genuinely unrelated key rather than
/// a second copy of the same fixture.
#[cfg(test)]
mod signature_tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::time::{SystemTime, UNIX_EPOCH};

    const ISSUER: &str = "https://issuer.invalid/obolus";

    /// A throwaway keypair in the two shapes the test needs: the private half as the PKCS#8 DER
    /// `jsonwebtoken` signs with, and the public half as the PEM an operator configures.
    struct TestKey {
        pkcs8: Vec<u8>,
        public_pem: String,
    }

    impl TestKey {
        fn generate() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
            Self {
                pkcs8: pkcs8.as_ref().to_vec(),
                public_pem: spki_pem(pair.public_key().as_ref()),
            }
        }

        fn signing_key(&self) -> EncodingKey {
            EncodingKey::from_ed_der(&self.pkcs8)
        }

        fn verifier(&self) -> PublicKeyTokenVerifier {
            PublicKeyTokenVerifier::new(self.public_pem.as_bytes(), ISSUER, None).unwrap()
        }

        fn verifier_for_audience(&self, audience: &str) -> PublicKeyTokenVerifier {
            PublicKeyTokenVerifier::new(self.public_pem.as_bytes(), ISSUER, Some(audience)).unwrap()
        }

        /// The raw 32 public-key bytes — the secret an alg-confusion attacker would try.
        fn public_key_bytes(&self) -> Vec<u8> {
            let pair = Ed25519KeyPair::from_pkcs8(&self.pkcs8).unwrap();
            pair.public_key().as_ref().to_vec()
        }
    }

    /// Wrap raw Ed25519 public-key bytes as a SubjectPublicKeyInfo PEM — byte-for-byte what
    /// `openssl pkey -pubout` emits, so the tests exercise the same parse an operator's file takes.
    /// The prefix is the fixed Ed25519 SPKI header of RFC 8410 §4; the body is 44 bytes, so it
    /// encodes to 60 base64 characters and needs no line wrapping.
    fn spki_pem(public_key: &[u8]) -> String {
        const ED25519_SPKI_PREFIX: [u8; 12] =
            [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(public_key);
        format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", STANDARD.encode(der))
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn claims(issuer: &str, expires_at: u64) -> serde_json::Value {
        serde_json::json!({ "iss": issuer, "exp": expires_at })
    }

    #[test]
    fn a_token_from_the_configured_key_and_issuer_is_honoured() {
        let key = TestKey::generate();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims(ISSUER, now() + 3600),
            &key.signing_key(),
        )
        .unwrap();

        assert_eq!(key.verifier().verify(&token), Ok(()));
    }

    #[test]
    fn an_unsigned_alg_none_token_is_rejected() {
        let key = TestKey::generate();
        // Characterisation, not a check on our configuration: `Algorithm` has no `none` variant, so
        // this header fails to parse before any setting here is consulted, and no mutation of
        // `Validation` can make it pass. The same is true of the HS256 case below — measured, both
        // ways: the algorithm pin and the Ed25519-typed key each defeat it alone, so mutating
        // either one leaves it rejected. Both kept because that immunity is a property of the
        // library we chose, and a library swap is what these tests would notice.
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload =
            URL_SAFE_NO_PAD.encode(claims(ISSUER, now() + 3600).to_string().as_bytes());
        let token = format!("{header}.{payload}.");

        assert!(key.verifier().verify(&token).is_err(), "alg:none must never be honoured");
    }

    #[test]
    fn an_hmac_token_signed_with_the_public_key_is_rejected() {
        let key = TestKey::generate();
        // The classic alg-confusion pair: the attacker knows the public key, so they sign HS256
        // with it and hope the verifier picks its algorithm from the token header. Both encodings
        // of "the public key" are tried because either could be what a naive verifier feeds HMAC.
        let secrets: [Vec<u8>; 2] =
            [key.public_key_bytes(), key.public_pem.as_bytes().to_vec()];
        for (index, secret) in secrets.iter().enumerate() {
            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims(ISSUER, now() + 3600),
                &EncodingKey::from_secret(secret),
            )
            .unwrap();

            assert!(
                key.verifier().verify(&token).is_err(),
                "HS256 signed with the public key (secret {index}) must not verify"
            );
        }
    }

    #[test]
    fn a_token_signed_by_another_key_is_rejected() {
        let ours = TestKey::generate();
        let theirs = TestKey::generate();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims(ISSUER, now() + 3600),
            &theirs.signing_key(),
        )
        .unwrap();

        assert!(ours.verifier().verify(&token).is_err(), "a foreign signature must not verify");
    }

    #[test]
    fn an_expired_token_is_rejected() {
        let key = TestKey::generate();
        // An hour past, not a second: `Validation` allows 60s of clock leeway by default, so a
        // just-expired token would legitimately still verify and prove nothing.
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims(ISSUER, now() - 3600),
            &key.signing_key(),
        )
        .unwrap();

        assert!(key.verifier().verify(&token).is_err(), "an expired token must not verify");
    }

    #[test]
    fn a_token_from_another_issuer_is_rejected() {
        let key = TestKey::generate();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &claims("https://issuer.invalid/something-else", now() + 3600),
            &key.signing_key(),
        )
        .unwrap();

        assert!(key.verifier().verify(&token).is_err(), "a foreign issuer must not verify");
    }

    #[test]
    fn a_token_with_no_issuer_claim_is_rejected() {
        let key = TestKey::generate();
        // The hole `set_required_spec_claims` closes: jsonwebtoken checks `iss` only on tokens
        // that carry one, so without the requirement this token — correctly signed, but minted for
        // some other service entirely — would be served for free.
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &serde_json::json!({ "exp": now() + 3600 }),
            &key.signing_key(),
        )
        .unwrap();

        assert!(key.verifier().verify(&token).is_err(), "a token with no `iss` must not verify");
    }

    #[test]
    fn a_token_with_no_expiry_is_rejected() {
        let key = TestKey::generate();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &serde_json::json!({ "iss": ISSUER }),
            &key.signing_key(),
        )
        .unwrap();

        assert!(key.verifier().verify(&token).is_err(), "a token that never expires is not one");
    }

    #[test]
    fn a_token_that_is_not_valid_yet_is_rejected() {
        let key = TestKey::generate();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &serde_json::json!({ "iss": ISSUER, "exp": now() + 7200, "nbf": now() + 3600 }),
            &key.signing_key(),
        )
        .unwrap();

        assert!(key.verifier().verify(&token).is_err(), "an nbf in the future must not verify");
    }

    /// The audience cases. Worth their own cluster because the *default* here is the surprising
    /// one, and it is surprising in the direction that makes a working deployment look broken
    /// rather than a broken one look working.
    #[test]
    fn a_token_carrying_an_audience_is_refused_when_no_audience_is_configured() {
        let key = TestKey::generate();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &serde_json::json!({ "iss": ISSUER, "exp": now() + 3600, "aud": "obolus" }),
            &key.signing_key(),
        )
        .unwrap();

        // Not incidental: `aud` names the service a token was minted for, so a verifier with no
        // expected audience cannot tell "minted for us" from "minted for the wiki". Refusing is
        // the fail-closed answer, and the message has to say which knob fixes it.
        let err = key.verifier().verify(&token).expect_err("must not verify");
        assert!(
            format!("{err}").contains("Obolus has no expected audience"),
            "the refusal must name the setting that fixes it, got: {err}"
        );
    }

    #[test]
    fn a_token_whose_audience_is_not_a_string_is_refused_too() {
        let key = TestKey::generate();
        // The shapes the library's own audience arm cannot see. `Validation` reads `aud` as a
        // string or array of strings and treats anything else as unparseable, so before `Claims`
        // declared the type these were **honoured** while `"aud": "the-wiki"` was refused —
        // measured, in exactly the fail-open direction. A non-conformant `aud` is not what a
        // mainstream IdP mints, which is the point: the refusal has to hold for every shape a
        // token can carry, not for the ones a well-behaved issuer happens to produce.
        for aud in [serde_json::json!(12345), serde_json::json!({ "nested": "obolus" })] {
            let token = encode(
                &Header::new(Algorithm::EdDSA),
                &serde_json::json!({ "iss": ISSUER, "exp": now() + 3600, "aud": aud }),
                &key.signing_key(),
            )
            .unwrap();

            assert!(
                key.verifier().verify(&token).is_err(),
                "a token carrying aud {aud} must not verify with no audience configured"
            );
        }
    }

    #[test]
    fn a_non_conformant_audience_is_refused_in_the_configured_posture_too() {
        let key = TestKey::generate();
        // The other half of the shape question, and the half that was untested: everything above
        // probes the *unset* posture, where refusing is the fail-closed default anyway. This is the
        // posture an operator explicitly asked for, so a shape that slips through here honours a
        // token against an audience it never matched. `null` is in the list deliberately — with an
        // audience configured it must be refused as a *missing* claim, which is not the same
        // outcome it has when no audience is set.
        for aud in [
            serde_json::json!(12345),
            serde_json::json!({ "nested": "obolus" }),
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!(["obolus", 7]),
        ] {
            let token = encode(
                &Header::new(Algorithm::EdDSA),
                &serde_json::json!({ "iss": ISSUER, "exp": now() + 3600, "aud": aud }),
                &key.signing_key(),
            )
            .unwrap();

            assert!(
                key.verifier_for_audience("obolus").verify(&token).is_err(),
                "a token carrying aud {aud} must not verify against the configured audience"
            );
        }
    }

    #[test]
    fn a_verifier_describes_the_audience_it_actually_enforces() {
        let key = TestKey::generate();
        // Pins the wrap, not just the verifier. `TokenPath` is what `main` hands to `router`, and
        // the banner reads its description — so a `TokenPath::new` that stashed a literal instead
        // of asking the verifier would put us straight back to a line that can describe a posture
        // nothing holds. Asserted through the wrapper for that reason, not through the verifier.
        let configured = TokenPath::new(Arc::new(key.verifier_for_audience("obolus")));
        assert!(
            configured.description().contains("audience obolus"),
            "a configured audience must reach the banner, got: {}",
            configured.description()
        );

        let unset = TokenPath::new(Arc::new(key.verifier()));
        assert!(
            !unset.description().contains("audience obolus"),
            "an unconfigured verifier must not describe an audience, got: {}",
            unset.description()
        );
        assert!(
            unset.description().contains("no audience configured"),
            "the unset posture must say so rather than going quiet, got: {}",
            unset.description()
        );
    }

    #[test]
    fn a_token_for_the_configured_audience_is_honoured() {
        let key = TestKey::generate();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &serde_json::json!({ "iss": ISSUER, "exp": now() + 3600, "aud": "obolus" }),
            &key.signing_key(),
        )
        .unwrap();

        assert_eq!(key.verifier_for_audience("obolus").verify(&token), Ok(()));
    }

    #[test]
    fn a_token_for_another_audience_is_rejected() {
        let key = TestKey::generate();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &serde_json::json!({ "iss": ISSUER, "exp": now() + 3600, "aud": "the-wiki" }),
            &key.signing_key(),
        )
        .unwrap();

        let err = key.verifier_for_audience("obolus").verify(&token).expect_err("must not verify");
        // The wording, not just the rejection. Both audience failures raise the same
        // `InvalidAudience`, and until `describe` took the configured flag this one inherited the
        // other's text — telling an operator who *has* set OBOLUS_TOKEN_AUDIENCE to go and set it,
        // which sends them to check whether their setting arrived instead of at the token. Asserted
        // in both directions so the two messages cannot drift back into one.
        let message = format!("{err}");
        assert!(
            message.contains("was minted for something else"),
            "a configured-audience mismatch must say the token is addressed elsewhere, got: {err}"
        );
        assert!(
            !message.contains("Obolus has no expected audience"),
            "the unset-audience wording must not be reused where the audience IS set, got: {err}"
        );
    }

    #[test]
    fn a_token_with_no_audience_is_rejected_when_one_is_configured() {
        let key = TestKey::generate();
        let token = encode(
            &Header::new(Algorithm::EdDSA),
            &serde_json::json!({ "iss": ISSUER, "exp": now() + 3600 }),
            &key.signing_key(),
        )
        .unwrap();

        // Same shape as the `iss` hole: the library checks `aud` only on tokens that carry one, so
        // without the requirement a token that simply omits the claim passes an audience check it
        // never took part in.
        assert!(
            key.verifier_for_audience("obolus").verify(&token).is_err(),
            "omitting `aud` must not satisfy a configured audience"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Rotation over a key set (slice 2).
    //
    // `TestKey::verifier` above is left alone on purpose: the slice-1 characterisations must keep
    // exercising the single-key shape an operator still gets from OBOLUS_TOKEN_PUBKEY_FILE.
    // ---------------------------------------------------------------------------------------

    fn owned(keys: &[(Option<&str>, &TestKey)]) -> Vec<(Option<String>, Vec<u8>)> {
        keys.iter()
            .map(|(kid, key)| (kid.map(String::from), key.public_pem.as_bytes().to_vec()))
            .collect()
    }

    fn verifier_over(keys: &[(Option<&str>, &TestKey)]) -> PublicKeyTokenVerifier {
        PublicKeyTokenVerifier::with_keys(&owned(keys), ISSUER, None).unwrap()
    }

    /// A live token from `key`, carrying `kid` in its header when one is given.
    fn token_from(key: &TestKey, kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = kid.map(String::from);
        encode(&header, &claims(ISSUER, now() + 3600), &key.signing_key()).unwrap()
    }

    #[test]
    fn both_keys_of_a_rotation_window_are_honoured() {
        let old = TestKey::generate();
        let new = TestKey::generate();
        let verifier = verifier_over(&[(Some("old"), &old), (Some("new"), &new)]);

        // Deliberately **without** `kid`, which is what gives this teeth. A token that names its key
        // gets that key tried first, so a verifier which consulted only one key would still honour
        // it and this test would pass while proving nothing about the set. Measured: with `verify`
        // cut to `take(1)`, the `kid`-carrying version of this test passes and this one fails.
        //
        // It is also the realistic case. At the instant a second key is armed, every outstanding
        // token was minted when there was one key and no reason to name it.
        assert_eq!(verifier.verify(&token_from(&old, None)), Ok(()));
        assert_eq!(verifier.verify(&token_from(&new, None)), Ok(()));
    }

    /// The refusal a key set gives must still name the cause, not some other key's signature.
    ///
    /// At most one key in a set can get past the signature, so at most one claim-level rejection
    /// can exist and there is no tie to break. Every other key says only "not mine", which is the
    /// one thing the operator already knows. This is the multi-key half of
    /// `a_token_carrying_an_audience_is_refused_when_no_audience_is_configured`, which reaches the
    /// same code through the single-key shape where first, last and only coincide.
    ///
    /// **Both orderings, and neither is redundant.** `ordered_by` hands back configuration order
    /// for a `kid`-less token, so the position of the signing key decides which half of the rule
    /// runs: first, and the cause is merely *kept*; second, and the cause has to *displace* a
    /// signature failure already held. Measured — with the rule cut to keep-first, the
    /// signing-key-first case stays green and only this one fails.
    #[test]
    fn a_rejection_from_a_key_set_keeps_the_error_that_names_the_cause() {
        let signing = TestKey::generate();
        let other = TestKey::generate();

        for (label, keys) in [
            ("signing key tried first", vec![(None, &signing), (None, &other)]),
            ("signing key tried second", vec![(None, &other), (None, &signing)]),
        ] {
            let verifier = verifier_over(&keys);
            let token = encode(
                &Header::new(Algorithm::EdDSA),
                &serde_json::json!({ "iss": ISSUER, "exp": now() + 3600, "aud": "obolus" }),
                &signing.signing_key(),
            )
            .unwrap();

            let err = verifier.verify(&token).expect_err("must not verify");
            assert!(
                format!("{err}").contains("Obolus has no expected audience"),
                "{label}: a key set must not replace the cause with another key's signature \
                 failure, got: {err}"
            );
        }
    }

    #[test]
    fn a_key_outside_the_set_is_refused() {
        let armed = TestKey::generate();
        let stranger = TestKey::generate();
        // The inversion of the test above, and what gives it teeth: a `verify` that honoured any
        // well-formed token regardless of the set would pass that one and fail this one.
        let verifier = verifier_over(&[(Some("old"), &armed)]);

        assert_eq!(verifier.verify(&token_from(&armed, Some("old"))), Ok(()));
        assert!(verifier.verify(&token_from(&stranger, Some("new"))).is_err());
    }

    #[test]
    fn retiring_a_key_refuses_its_tokens_and_keeps_the_rest() {
        let old = TestKey::generate();
        let new = TestKey::generate();
        // The far end of a rotation: the old key is dropped once its tokens have expired. Narrowly
        // about *refusal after removal*, and it says nothing about whether the whole set is
        // consulted — a one-key set cannot. The rotation-window test above pins that.
        let after = verifier_over(&[(Some("new"), &new)]);

        assert!(after.verify(&token_from(&old, Some("old"))).is_err());
        // Also without the `kid`: a retired key must not come back through the fallthrough path.
        assert!(after.verify(&token_from(&old, None)).is_err());
        assert_eq!(after.verify(&token_from(&new, Some("new"))), Ok(()));
    }

    #[test]
    fn a_kid_naming_one_key_but_signed_by_another_is_still_honoured() {
        let alpha = TestKey::generate();
        let beta = TestKey::generate();
        let verifier = verifier_over(&[(Some("alpha"), &alpha), (Some("beta"), &beta)]);

        // `kid` narrows; it does not decide. The header is unverified, so letting a mismatch reject
        // would hand anyone the ability to refuse their own token — and, worse, would establish the
        // habit of trusting header fields, one of which is `alg`.
        assert_eq!(verifier.verify(&token_from(&beta, Some("alpha"))), Ok(()));
    }

    #[test]
    fn a_token_with_no_kid_is_honoured_by_a_named_key() {
        let alpha = TestKey::generate();
        let verifier = verifier_over(&[(Some("alpha"), &alpha)]);

        // The compatibility case that makes rotation possible at all: every token minted before an
        // operator had a second key carries no `kid`, so requiring a match would refuse the entire
        // outstanding population at the moment the second key was armed.
        assert_eq!(verifier.verify(&token_from(&alpha, None)), Ok(()));
    }

    #[test]
    fn an_unknown_kid_does_not_reject_a_validly_signed_token() {
        let alpha = TestKey::generate();
        let verifier = verifier_over(&[(Some("alpha"), &alpha)]);

        assert_eq!(verifier.verify(&token_from(&alpha, Some("nothing-we-hold"))), Ok(()));
    }

    #[test]
    fn a_matching_kid_does_not_rescue_a_bad_signature() {
        let alpha = TestKey::generate();
        let impostor = TestKey::generate();
        let verifier = verifier_over(&[(Some("alpha"), &alpha)]);

        assert!(verifier.verify(&token_from(&impostor, Some("alpha"))).is_err());
    }

    #[test]
    fn an_hmac_token_is_still_rejected_by_a_multi_key_verifier() {
        let alpha = TestKey::generate();
        let beta = TestKey::generate();
        let verifier = verifier_over(&[(Some("alpha"), &alpha), (Some("beta"), &beta)]);
        // Slice 1's alg-confusion characterisation, re-run against the multi-key path. Without this
        // the guarantee would be pinned only for one-key verifiers, which is not where it matters:
        // `verify` now loops, and a loop is where "just try the other key" creeps in. Every key in
        // the set is offered as the HMAC secret, since the attacker holds all the public halves.
        for (index, key) in [&alpha, &beta].iter().enumerate() {
            for secret in [key.public_key_bytes(), key.public_pem.as_bytes().to_vec()] {
                let token = encode(
                    &Header::new(Algorithm::HS256),
                    &claims(ISSUER, now() + 3600),
                    &EncodingKey::from_secret(&secret),
                )
                .unwrap();

                assert!(
                    verifier.verify(&token).is_err(),
                    "HS256 signed with armed key {index}'s public half must not verify"
                );
            }
        }
    }

    #[test]
    fn a_key_set_must_not_be_empty() {
        assert!(PublicKeyTokenVerifier::with_keys(&[], ISSUER, None).is_err());
    }

    #[test]
    fn a_key_set_is_bounded() {
        // Distinct keys, and that is the whole point: `with_keys` has more than one reason to refuse
        // a set, so a fixture cloning one PEM is refused as a duplicate and never reaches the count.
        // `is_err()` cannot tell two refusals apart, which is how an assertion named for the cap ends
        // up pinning something else. Both directions below, so a bound that drifted either way shows.
        let generated: Vec<TestKey> = (0..=MAX_KEYS).map(|_| TestKey::generate()).collect();
        let entry = |i: usize| (Some(format!("k{i}")), generated[i].public_pem.as_bytes().to_vec());

        let too_many: Vec<(Option<String>, Vec<u8>)> = (0..=MAX_KEYS).map(entry).collect();
        let err = match PublicKeyTokenVerifier::with_keys(&too_many, ISSUER, None) {
            Ok(_) => panic!("{} keys must not build a verifier", MAX_KEYS + 1),
            Err(err) => err,
        };
        assert!(
            format!("{err}").contains(&MAX_KEYS.to_string()),
            "the refusal must name the bound, so a different future refusal cannot quietly stand in \
             for this one: {err}"
        );

        // The other half. Without it a cap that drifted down to 7 would refuse a legal rotation at
        // startup — in production, with this suite green.
        let exactly_enough: Vec<(Option<String>, Vec<u8>)> = (0..MAX_KEYS).map(entry).collect();
        assert!(PublicKeyTokenVerifier::with_keys(&exactly_enough, ISSUER, None).is_ok());
    }

    #[test]
    fn two_keys_may_not_share_a_kid() {
        let alpha = TestKey::generate();
        let beta = TestKey::generate();
        // Which key "the one named alpha" means would otherwise be positional, and silently picking
        // the first is how a key an operator believes they retired keeps admitting tokens.
        let clashing = owned(&[(Some("alpha"), &alpha), (Some("alpha"), &beta)]);

        assert!(PublicKeyTokenVerifier::with_keys(&clashing, ISSUER, None).is_err());
    }

    #[test]
    fn one_key_may_not_be_armed_twice() {
        let key = TestKey::generate();
        // Two names for one key is a rotation that is not happening, and the banner would announce
        // it as one — "2 keys: old, new" for a set only `old` can sign for. Whitespace-insensitive,
        // because the near-miss an operator actually produces is the same key pasted twice with
        // different line endings.
        let twice = owned(&[(Some("old"), &key), (Some("new"), &key)]);
        assert!(PublicKeyTokenVerifier::with_keys(&twice, ISSUER, None).is_err());

        let padded = vec![
            (Some("old".to_string()), key.public_pem.as_bytes().to_vec()),
            (Some("new".to_string()), format!("{}\n", key.public_pem).into_bytes()),
        ];
        assert!(PublicKeyTokenVerifier::with_keys(&padded, ISSUER, None).is_err());
    }

    #[test]
    fn several_unnamed_keys_are_allowed() {
        let old = TestKey::generate();
        let new = TestKey::generate();
        // The duplicate-`kid` rule must not catch this: an issuer that never used `kid` still has to
        // be able to rotate, and from here both of its keys are simply unnamed.
        let verifier = verifier_over(&[(None, &old), (None, &new)]);

        assert_eq!(verifier.verify(&token_from(&old, None)), Ok(()));
        assert_eq!(verifier.verify(&token_from(&new, None)), Ok(()));
    }

    #[test]
    fn an_empty_kid_is_refused() {
        let key = TestKey::generate();

        assert!(PublicKeyTokenVerifier::with_keys(&owned(&[(Some(""), &key)]), ISSUER, None)
            .is_err());
    }

    #[test]
    fn a_key_set_entry_must_hold_a_usable_key() {
        let named = vec![(Some("alpha".to_string()), b"-----BEGIN PUBLIC KEY-----".to_vec())];
        // Not `expect_err`: a verifier holds key material, so it deliberately has no `Debug` to
        // print it with.
        let err = match PublicKeyTokenVerifier::with_keys(&named, ISSUER, None) {
            Ok(_) => panic!("garbage must not build a verifier"),
            Err(err) => err,
        };

        // Naming the offending entry is the whole point of the message: with several keys
        // configured, "not a usable Ed25519 public key" alone leaves the operator guessing which.
        assert!(
            format!("{err}").contains("alpha"),
            "the failure must name the entry that carries it, got: {err}"
        );
    }

    #[test]
    fn token_keys_parse_from_the_array_form() {
        let parsed = parse_token_keys(
            r#"[{"kid":"alpha","file":"/etc/obolus/alpha.pem"},{"file":"/etc/obolus/legacy.pem"}]"#,
        )
        .unwrap();

        assert_eq!(
            parsed,
            vec![
                TokenKeyEntry {
                    kid: Some("alpha".to_string()),
                    file: "/etc/obolus/alpha.pem".to_string()
                },
                TokenKeyEntry { kid: None, file: "/etc/obolus/legacy.pem".to_string() },
            ]
        );
    }

    #[test]
    fn token_keys_refuse_the_shapes_that_would_drop_a_key() {
        // Each of these would otherwise start a gateway holding fewer keys than the operator wrote.
        // A typo'd field is the dangerous one: `deny_unknown_fields` is what turns a silently
        // defaulted-away path into a startup failure.
        for raw in [
            "[]",                                    // asks for a token path, names no key
            r#"[{"kid":"alpha"}]"#,                  // no file
            r#"[{"file":""}]"#,                      // a file that names nothing
            r#"[{"kid":"alpha","filename":"a.pem"}]"#, // typo'd field
            r#"{"file":"a.pem"}"#,                   // an object, not an array
            "not json at all",
        ] {
            assert!(parse_token_keys(raw).is_err(), "must refuse: {raw}");
        }
    }

    #[test]
    fn the_banner_names_the_key_set() {
        let alpha = TestKey::generate();
        let beta = TestKey::generate();

        assert!(verifier_over(&[(Some("beta"), &beta), (Some("alpha"), &alpha)])
            .description()
            // Sorted, not in configuration order — an exec test matches this line.
            .contains("2 keys: alpha, beta"));
        assert!(verifier_over(&[(None, &alpha)]).description().contains("1 key, unnamed"));
        assert!(verifier_over(&[(Some("alpha"), &alpha), (None, &beta)])
            .description()
            .contains("2 keys: alpha, plus 1 unnamed"));
    }

    #[test]
    fn the_banner_changes_when_a_key_leaves_the_set() {
        let alpha = TestKey::generate();
        let beta = TestKey::generate();

        // The teeth for the banner: dropping a key at the wiring site — the one-line mutation that
        // half-disarms a rotation with every test green — must be visible from outside, and the
        // startup line is the only thing that can see it. `src/main.rs` is compiled by no test
        // target, so nothing in this suite observes the wiring directly.
        assert_ne!(
            verifier_over(&[(Some("alpha"), &alpha), (Some("beta"), &beta)]).description(),
            verifier_over(&[(Some("alpha"), &alpha)]).description(),
        );
    }

    /// A conformance check any [`TokenVerifier`] implementation's tests can run against itself: for
    /// each enforcement leg it has, a variant with that leg changed must describe itself
    /// differently.
    ///
    /// Round 3's single-variable inversion, lifted out of one implementation's tests so the next one
    /// inherits it rather than re-deriving it. It does **not** fully close the residual — an
    /// implementation that lies consistently in both `verify` and `description` still passes, and no
    /// trait-level test can catch that. What it does catch is the failure that actually happened: a
    /// description composed from the arguments a constructor was handed rather than from the state
    /// the request path consults.
    fn assert_description_tracks_enforcement(
        baseline: &dyn TokenVerifier,
        variants: &[(&str, &dyn TokenVerifier)],
    ) {
        let described = baseline.description();
        for (leg, variant) in variants {
            assert_ne!(
                variant.description(),
                described,
                "changing the {leg} leg left the description unchanged, so this banner is not \
                 rendered from what the verifier enforces"
            );
        }
    }

    #[test]
    fn the_public_key_verifier_describes_every_leg_it_enforces() {
        let alpha = TestKey::generate();
        let beta = TestKey::generate();
        let pems = owned(&[(Some("alpha"), &alpha)]);

        let baseline = PublicKeyTokenVerifier::with_keys(&pems, ISSUER, None).unwrap();
        let other_issuer =
            PublicKeyTokenVerifier::with_keys(&pems, "https://elsewhere.invalid", None).unwrap();
        let with_audience =
            PublicKeyTokenVerifier::with_keys(&pems, ISSUER, Some("obolus")).unwrap();
        let bigger_set = verifier_over(&[(Some("alpha"), &alpha), (Some("beta"), &beta)]);

        assert_description_tracks_enforcement(
            &baseline,
            &[
                ("issuer", &other_issuer),
                ("audience", &with_audience),
                ("key set", &bigger_set),
            ],
        );
    }
}
