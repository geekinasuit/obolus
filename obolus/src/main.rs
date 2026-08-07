//! The Obolus server binary — wired to a real facilitator and a real Ollama upstream.
//!
//! This is live-capable, and testnet-by-construction *unless an operator explicitly arms it*:
//! startup refuses to advertise any network it cannot prove is testnet (OBOL-004, see
//! [`obolus::arming`]), and `OBOLUS_ALLOW_MAINNET=1` is the only way past that refusal. Stating the
//! posture unconditionally would make this doc false on exactly the instance where it matters most.
//!
//! It delegates settlement to a third-party
//! x402 facilitator (`OBOLUS_FACILITATOR_URL`, required — the gateway never guesses where money
//! settles) and proxies inference to a local Ollama origin (`OBOLUS_UPSTREAM_URL`). The payment
//! placeholders below are deliberately not real addresses and must be overridden for any real
//! network; there is no mainnet signing path in this crate.
//!
//! The Phase-A fakes that used to drive the 402 handshake by hand are gone from this binary on
//! purpose. They are `#[cfg(test)]`-only now, so the `server` target — which compiles the library
//! without `cfg(test)` — physically cannot build an accept-every-payment facilitator or a pretend
//! upstream into a shipped artifact (OBOL-001). The compiler is the guarantee, not a code review.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use obolus::access::{
    parse_token_keys, PublicKeyTokenVerifier, TokenKeyEntry, TokenPath, SINGLE_KEY_VAR,
};
use obolus::arming::{check_arming, diagnose, legible, undiagnosed, PINNED_ON, PLACEHOLDER_NETWORK};
use obolus::config::{
    parse_accepts, superseded_single_chain_vars, validated_option, EntryDefect, EntryField,
    SharedOffer,
};
use obolus::facilitator::DelegatedFacilitator;
use obolus::gateway::{router, Access, Gateway};
use obolus::upstream::OllamaUpstream;
use obolus::x402::PaymentRequirements;

/// Deliberately not 8402, which x402 client-side tooling tends to bind.
const DEFAULT_ADDR: &str = "127.0.0.1:8403";

/// Ollama's default local origin: plain HTTP on loopback. The safe default upstream — overridden
/// with `OBOLUS_UPSTREAM_URL` for a remote or proxied model server.
const DEFAULT_UPSTREAM_URL: &str = "http://127.0.0.1:11434";

/// Placeholders that are obviously not real addresses. If one of these ever reaches a chain,
/// it fails loudly rather than paying someone.
///
/// The matching network placeholder is `obolus::arming::PLACEHOLDER_NETWORK`, imported above rather
/// than declared here: the arming allowlist must contain it (an unconfigured Obolus has to boot
/// without arming anything), and two copies of that string could drift apart.
const PLACEHOLDER_PAY_TO: &str = "0xTEST-PAY-TO-ADDRESS-NOT-REAL";
const PLACEHOLDER_ASSET: &str = "0xTEST-ASSET-ADDRESS-NOT-REAL";

/// Seconds added on top of the challenge's `maxTimeoutSeconds` to bound a single settle call.
/// Settlement can legitimately block while the facilitator waits for an on-chain receipt, so we
/// wait a little longer than the authorization we advertised is valid for, then give up as
/// unavailable rather than hanging.
const SETTLE_TIMEOUT_MARGIN_SECS: u64 = 15;

/// Generous by design — keep in step with `upstream::DEFAULT_HEAD_TIMEOUT`, which documents what
/// this bounds and why it stays loose. Override with `OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS`.
const DEFAULT_UPSTREAM_HEAD_TIMEOUT_SECS: u64 = 600;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read a `u64` seconds value from the environment, or fall back to `default`. A present-but-junk
/// value is a config error we refuse to start on rather than silently treating as the default.
fn env_u64(key: &str, default: u64) -> anyhow::Result<u64> {
    match std::env::var(key) {
        Ok(raw) => {
            raw.parse().map_err(|e| anyhow::anyhow!("{key} must be a whole number of seconds: {e}"))
        }
        Err(_) => Ok(default),
    }
}

/// Name a [`EntryDefect`] in the vocabulary of the single-chain path: the variable an operator has
/// to go and fix, not the array entry.
///
/// `parse_accepts` maps the same defects onto `OBOLUS_ACCEPTS entry for network "…"`. The check is
/// shared ([`validated_option`]); only this naming is not, because an operator can only act on the
/// one that matches how they configured it.
///
/// Each message says the variable is *set but empty* rather than missing, because that is the
/// distinction the operator cannot see from the outside: unset takes the placeholder default and
/// boots with `UNCONFIGURED NETWORK`, so if they are reading this the value did arrive — carrying
/// nothing. The usual causes are an unexpanded `${VAR}` in a compose file, an `EnvironmentFile`
/// line ending in `=`, or an empty ConfigMap key.
///
/// The match is exhaustive on [`EntryField`](obolus::config::EntryField); see that type for why it
/// carries no wildcard arm.
fn single_chain_defect(defect: EntryDefect) -> anyhow::Error {
    match &defect {
        EntryDefect::EmptyNetwork => anyhow::anyhow!(
            "OBOLUS_NETWORK is set but empty: {defect}. An empty network is not a chain this build \
             has not heard of — it is no chain at all, and no client can pay against it, so the \
             gateway would start cleanly and 402 every request forever. Unset it to run \
             un-configured on the built-in placeholder, or set a CAIP-2 id such as \
             \"eip155:84532\"."
        ),
        EntryDefect::EmptyField { field: EntryField::Asset } => anyhow::anyhow!(
            "OBOLUS_ASSET is set but empty: {defect}. The advertised challenge would name no token \
             for a client to pay in. Unset it to run un-configured on the built-in placeholder, or \
             set the asset contract address."
        ),
        EntryDefect::EmptyField { field: EntryField::PayTo } => anyhow::anyhow!(
            "OBOLUS_PAY_TO is set but empty: {defect}. The advertised challenge would send money \
             nowhere. Unset it to run un-configured on the built-in placeholder, or set the \
             receiving address."
        ),
        EntryDefect::BadAmount(detail) => anyhow::anyhow!("OBOLUS_PRICE: {detail}"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = env_or("OBOLUS_ADDR", DEFAULT_ADDR).parse()?;

    // A payment gateway must never GUESS where money settles. There is deliberately no default:
    // unset means refuse to start, not "pick something and hope".
    let facilitator_url = std::env::var("OBOLUS_FACILITATOR_URL").map_err(|_| {
        anyhow::anyhow!(
            "OBOLUS_FACILITATOR_URL is required: the base URL of the x402 facilitator that \
             verifies and settles payments (/verify and /settle are appended to it). Refusing to \
             start rather than guess where money settles. For the testnet rail, point it at the \
             x402.org facilitator base URL."
        )
    })?;

    // Advertised to the client in the 402 challenge AND the basis for the settle deadline below —
    // configurable so that derivation is not frozen in code.
    let max_timeout_seconds = env_u64("OBOLUS_MAX_TIMEOUT_SECS", 60)?;
    if max_timeout_seconds == 0 {
        anyhow::bail!(
            "OBOLUS_MAX_TIMEOUT_SECS must be greater than 0: it is advertised to payers as the \
             challenge's maxTimeoutSeconds (a 0-second payment window is unpayable) and it also \
             floors the settle deadline."
        );
    }
    let settle_timeout =
        Duration::from_secs(max_timeout_seconds.saturating_add(SETTLE_TIMEOUT_MARGIN_SECS));

    // `new` rejects an `https://` base (no TLS wired) and anything that is not an explicit
    // `http://` base, so a misconfiguration fails here at startup rather than later as an opaque
    // "unavailable" at connect time.
    let facilitator = DelegatedFacilitator::new(&facilitator_url)
        .map_err(|e| anyhow::anyhow!("OBOLUS_FACILITATOR_URL: {e}"))?
        .with_timeout(settle_timeout);

    let upstream_url = env_or("OBOLUS_UPSTREAM_URL", DEFAULT_UPSTREAM_URL);
    // Fail fast, symmetric with the facilitator URL above. Case-insensitive, so `HTTP://` is
    // accepted rather than rejected as a typo. Left to request time, a bad scheme 502s every paid
    // request while /health still reports OK.
    if !upstream_url.to_ascii_lowercase().starts_with("http://") {
        anyhow::bail!(
            "OBOLUS_UPSTREAM_URL must be an http:// origin (got {upstream_url:?}): the upstream \
             client speaks plain HTTP only (no TLS is wired), so an https:// or schemeless URL \
             cannot reach the model. Put a local http proxy in front of a TLS upstream if needed."
        );
    }
    let head_timeout_secs =
        env_u64("OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS", DEFAULT_UPSTREAM_HEAD_TIMEOUT_SECS)?;
    if head_timeout_secs == 0 {
        anyhow::bail!(
            "OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS must be greater than 0: a 0-second deadline fires \
             immediately, turning every request into an uncharged 502 before the upstream can \
             answer."
        );
    }
    let upstream =
        OllamaUpstream::new(&upstream_url).with_head_timeout(Duration::from_secs(head_timeout_secs));

    // The challenge tells the payer WHICH resource they are paying for, so `resource` must be an
    // address they can actually reach. Deriving it from the bind address is only right when that
    // address is routable — bind to `0.0.0.0` and the challenge advertises a resource nobody can
    // pay for. `OBOLUS_RESOURCE` is the override for anything behind a proxy, a container port map,
    // or a wildcard bind.
    let shared = SharedOffer {
        resource: env_or("OBOLUS_RESOURCE", &format!("http://{addr}/v1/chat/completions")),
        description: env_or("OBOLUS_DESCRIPTION", "One inference request"),
        max_timeout_seconds,
    };

    // One Obolus can advertise several chains at once (OBOL-003). `OBOLUS_ACCEPTS`, when set, is a
    // JSON array of `{network, asset, payTo, maxAmountRequired}` — the client picks one from the 402
    // and pays it. Unset, we build the single option from OBOLUS_NETWORK / OBOLUS_ASSET /
    // OBOLUS_PAY_TO / OBOLUS_PRICE. The `(scheme, network)` uniqueness of the resulting set is
    // enforced by `Gateway::new` below, not here.
    let requirements: Vec<PaymentRequirements> = match std::env::var("OBOLUS_ACCEPTS") {
        Ok(raw) => {
            // Set but empty, first — before the supersession bail below and before `parse_accepts`.
            //
            // This is the only payment variable whose *set-ness* picks which configuration path runs,
            // so an empty one silently changes the branch. Left to serde, an unexpanded `${VAR}` gets
            // "must be a JSON array … EOF while parsing a value at line 1 column 0" — every remedy in
            // which is wrong, since the operator did not mean to write JSON and the actual fix
            // (unset it) appears nowhere.
            //
            // Ordered before the supersession bail deliberately: that bail is actionable, but its
            // premise is false here. It would tell an operator whose array is empty that the array
            // supersedes their single-chain configuration, when the true statement is that it is set
            // but empty — configuring nothing while still superseding everything.
            if raw.trim().is_empty() {
                anyhow::bail!(
                    // Deliberately does not reuse the supersession bail's phrasing below: a needle
                    // asserting that bail is *absent* here would otherwise be satisfied by this
                    // message's own text.
                    "OBOLUS_ACCEPTS is set but empty: it reached this process carrying nothing — \
                     an unexpanded ${{VAR}} in a compose file, an EnvironmentFile line ending in \
                     `=`, an empty ConfigMap key. Set-but-empty is not the same as unset here: an \
                     empty array still takes precedence, so it would configure nothing while \
                     silencing everything. Unset it to configure a single chain with \
                     OBOLUS_NETWORK / OBOLUS_ASSET / OBOLUS_PAY_TO / OBOLUS_PRICE instead, or give \
                     it a JSON array of \
                     {{\"network\",\"asset\",\"payTo\",\"maxAmountRequired\"}} objects."
                );
            }
            // OBOLUS_ACCEPTS supersedes the single-chain vars, which then sit inert. An operator who
            // set both has most likely configured a network they believe is live but is not — the
            // one surprise a payment gateway must never ship. Refuse, naming exactly which vars are
            // being ignored, rather than starting with a silently-different advertisement.
            let ignored = superseded_single_chain_vars(|k| std::env::var(k).is_ok());
            if !ignored.is_empty() {
                anyhow::bail!(
                    "OBOLUS_ACCEPTS is set and supersedes the single-chain payment variables, but \
                     these are also set and would be silently ignored: {}. Remove them, or unset \
                     OBOLUS_ACCEPTS to configure a single chain with them instead.",
                    ignored.join(", ")
                );
            }
            parse_accepts(&raw, &shared)?
        }
        Err(_) => {
            // Through the same per-option seam `parse_accepts` uses, deliberately. These fields reach
            // a payment challenge by two doors and the defects are identical at both, so the
            // *checking* has to be one function or the two paths drift. Only the *naming* differs,
            // which is what `single_chain_defect` adds: an operator on this path has to be told which
            // variable to go and fix, not which array entry.
            //
            // An unset variable still takes its placeholder default — that is the un-configured
            // state, which boots and says so. What is rejected here is set-but-empty.
            vec![validated_option(
                env_or("OBOLUS_NETWORK", PLACEHOLDER_NETWORK),
                env_or("OBOLUS_ASSET", PLACEHOLDER_ASSET),
                env_or("OBOLUS_PAY_TO", PLACEHOLDER_PAY_TO),
                &env_or("OBOLUS_PRICE", "1000"),
                &shared,
            )
            .map_err(single_chain_defect)?]
        }
    };

    // Obolus holds no key, but the 402 challenge it advertises IS the real-money trigger: a
    // cooperating client reads (network, asset, pay-to) out of it and pays against it. So the guard
    // sits on the advertisement (OBOL-004). Fail-closed against a pinned testnet allowlist — a
    // mainnet id, a typo, or a testnet x402 added after this build all refuse to boot unarmed.
    //
    // Before the banner block below, deliberately: a refused configuration must never first print
    // "advertising N payment option(s)" for a gateway that is about to abort, and before
    // `Gateway::new`, so an unproven network never reaches a constructed router. That ordering is
    // checked, not merely asserted here — `a_refusal_never_advertises_anything_first` in
    // tests/server_arming.rs runs this binary and fails if the call moves. Exit status alone cannot
    // see it: a gateway that checks too late still exits non-zero, having already advertised.
    //
    // Exactly the string "1" arms it. Anything else — `true`, `yes`, empty, unset — does not, which
    // is the safe direction for a typo; the refusal message names the exact value required.
    let armed = std::env::var("OBOLUS_ALLOW_MAINNET").as_deref() == Ok("1");
    let unproven_networks = check_arming(&requirements, armed)?;

    // "starting on", not "listening on" — the bind is ~100 lines below and every check between here
    // and there can still refuse. A posture line an operator trusts must be true *where it is
    // printed*, and "listening" was false on every failed bind (port in use, privileged port, an
    // address that does not resolve). The real claim is made below, after `bind` returns.
    eprintln!("obolus: starting on http://{addr}");
    // "unless a bearer-token line below says otherwise" rather than a flat "payment-gated": on a
    // token-configured instance that route is gated by payment only for callers without an honoured
    // token, and the ENABLED line saying so lands well below this one. Same standard as "starting
    // on" above — a posture line has to be true where it is printed. Made conditional on the token
    // path instead would mean hoisting that block above the arming guard, which reorders which
    // refusal an operator sees when both their network and their token config are wrong.
    eprintln!(
        "obolus: POST /v1/chat/completions is gated; GET /health is not. The gate is payment for \
         every caller unless a bearer-token line below says otherwise."
    );
    eprintln!("obolus: facilitator (verify/settle) -> {facilitator_url}");
    eprintln!("obolus: upstream (inference) -> {upstream_url}");
    // The unconditional half of the posture: true on every instance, armed or not. The
    // testnet-by-construction claim is NOT stated here — on an armed instance it would be false, and
    // it sits one line above a MAINNET ARMED banner. It is asserted below, where it is checked.
    eprintln!(
        "obolus: LIVE WIRING — payments are verified and settled by the facilitator above, and \
         inference is proxied to the upstream above. No mainnet signing path exists in this binary; \
         pay-to / asset / network default to non-real placeholders and MUST be overridden for any \
         real network."
    );
    eprintln!("obolus: advertising {} payment option(s):", requirements.len());
    for r in &requirements {
        eprintln!(
            "obolus:   - network {} / asset {} / pay-to {} / {} atomic units",
            r.network, r.asset, r.pay_to, r.max_amount_required
        );
    }

    // Computed outside the arming branches on purpose. The placeholder is admitted by
    // `is_provably_testnet` through a clause of its own, so it never lands in `unproven_networks`;
    // whether an advertised option is a placeholder is independent of whether any *other* option is
    // unproven. Nested inside a branch, an armed array carrying both a real mainnet and a placeholder
    // would report the mainnet half and stay silent about the placeholder half — on the one instance
    // where money is real.
    let placeholders = requirements.iter().filter(|r| r.network == PLACEHOLDER_NETWORK).count();

    // The banner must not be able to lie. Armed-but-all-testnet is a legal state (the flag is set;
    // every advertised network is still on the allowlist), and shouting MAINNET there would plant a
    // log line someone trusts during an incident. So the loud banner is keyed on what is actually
    // unproven, not on the flag.
    if !unproven_networks.is_empty() {
        // Armed by construction: `check_arming` would have refused to return otherwise.
        //
        // Says "unproven", not "mainnet". The refusal's three cases apply here too — a mainnet, a
        // typo, or a testnet newer than this build — and over time a stale allowlist snapshot becomes
        // the *likeliest* trigger. A flat "real funds can move" would be false for two of the three,
        // and a banner an operator learns is usually an exaggeration is one they stop reading.
        //
        // But the disclaimer must also be *scoped*, because the same array can carry a real mainnet
        // and an id Obolus can fully explain (`base-sepolia` is not CAIP-2 and so can never match the
        // allowlist). `undiagnosed` splits the three reachable states on the data rather than on the
        // message, so the all-diagnosable case stops claiming a defect in "some of them" and stops
        // quantifying "for any it does not name" over an empty set.
        let diagnosis = diagnose(&unproven_networks);
        let unexplained = undiagnosed(&unproven_networks);
        let cause = if unexplained.len() == unproven_networks.len() {
            "Each is a mainnet, a typo, or a testnet added to x402 after this build — Obolus cannot \
             tell which, so treat this gateway as able to move real funds until you have confirmed \
             otherwise."
                .to_string()
        } else if unexplained.is_empty() {
            // Every one is explained, so there is no residue to disclaim about — saying "treat this
            // gateway as able to move real funds" here would be the flat disclaimer surviving into
            // the one state where Obolus has a specific answer for every entry.
            "Obolus can name a defect in every one of them — see below. Fixing those values is the \
             work; arming past them is not."
                .to_string()
        } else {
            format!(
                "Obolus can name a defect in some of them — see below. It cannot account for {}: \
                 each of those is a mainnet, a typo, or a testnet added to x402 after this build, \
                 and Obolus cannot tell which, so treat this gateway as able to move real funds \
                 until you have confirmed otherwise.",
                unexplained.iter().map(|n| legible(n)).collect::<Vec<_>>().join(", ")
            )
        };
        eprintln!(
            "obolus: *** MAINNET ARMED *** OBOLUS_ALLOW_MAINNET=1 — advertising {} network(s) NOT \
             on the pinned testnet allowlist: {}. {} That allowlist is a snapshot pinned {}; \
             if yours is a genuine testnet newer than that, the fix is a reviewed addition to \
             TESTNET_NETWORKS, not this flag — which has made this gateway indistinguishable from a \
             mainnet one in its own logs.{}",
            unproven_networks.len(),
            // Through `legible`, not `{:?}`: quoted so a trailing space is visible, and non-ASCII
            // escaped so a homoglyph or NO-BREAK SPACE does not reach the one banner an operator
            // reads during an incident looking exactly like the id they meant to configure. Same
            // rendering as the refusal, deliberately.
            unproven_networks.iter().map(|n| legible(n)).collect::<Vec<_>>().join(", "),
            cause,
            PINNED_ON,
            // Already prefixed with its own newline-and-bullet, and empty when nothing is
            // diagnosable — in which case this banner is byte-identical to the pre-round-7 one.
            diagnosis
        );
    } else if placeholders == 0 {
        // Two states, not one, and they must not print the same line. `is_provably_testnet` admits
        // PLACEHOLDER_NETWORK through a clause of its own, so an unconfigured boot reaches here too —
        // and the allowlist sentence would be flatly false about the only network advertised, false
        // in the *reassuring* direction. An operator whose OBOLUS_NETWORK never reached this process
        // would read it as confirmation their configuration took effect. Hence the `placeholders == 0`
        // guard on this line rather than an else-branch carrying both cases.
        eprintln!(
            "obolus: testnet-by-construction — every advertised network is on the pinned \
             testnet allowlist (OBOL-004)."
        );
    }

    // Deliberately outside the if/else above, and after it: an advertised placeholder is a fact about
    // the option set, not about arming, so it must be reported on BOTH branches.
    if placeholders > 0 {
        eprintln!(
            "obolus: UNCONFIGURED NETWORK — {placeholders} of {} advertised option(s) carry \
             the built-in placeholder network {PLACEHOLDER_NETWORK:?}, which is deliberately \
             not a real CAIP-2 id — Obolus invented it precisely so that no chain could match \
             it, so nothing should ever settle against those options. (Obolus does not itself \
             refuse them: like any advertised option they are published verbatim and matched \
             verbatim, and it is the facilitator that has no such network.) This is the \
             un-configured state, NOT testnet-by-construction. If you \
             believe you configured a network, exactly one of these is true: nothing was set and \
             this is the built-in default; OBOLUS_NETWORK was set but did not reach this process; \
             or OBOLUS_ACCEPTS did reach this process and one of its entries names the \
             placeholder itself. (Setting OBOLUS_ACCEPTS alongside the single-chain variables \
             cannot produce this line — that combination refuses to start.) Compare the \
             per-option lines above against what you set.",
            requirements.len()
        );
    }

    // Only meaningful when the flag changed nothing — on the armed branch the banner above has
    // already said far more than this would.
    if armed && unproven_networks.is_empty() {
        eprintln!(
            "obolus: OBOLUS_ALLOW_MAINNET is set but changed nothing here. Unset it so that an \
             armed instance stays recognisable by its environment alone."
        );
    }

    // Which variable, if either, names the verifying keys. Both forms collapse to one list here so
    // everything downstream — issuer, audience, file reading, the verifier — is written once rather
    // than twice and left to drift.
    //
    // `OBOLUS_TOKEN_KEYS` supersedes the single-key variable exactly as `OBOLUS_ACCEPTS` supersedes
    // the single-chain ones above, and refuses to start when both are set for the same reason. It is
    // worse here, if anything: an ignored payment variable produces a challenge nobody can pay, but
    // an ignored *verifying key* produces a gateway that looks correct until a token signed with
    // that key is refused — possibly weeks later, mid-rotation.
    let key_source: Option<(&str, Vec<TokenKeyEntry>)> =
        match (std::env::var("OBOLUS_TOKEN_KEYS"), std::env::var(SINGLE_KEY_VAR)) {
            // Set-but-empty first, and ahead of the supersession bail below, for the reason the
            // OBOLUS_ACCEPTS arms above give: that bail is actionable but its premise is false here.
            // It would tell an operator whose array arrived empty that it supersedes their
            // single-key configuration, when the true statement is that it configures nothing while
            // superseding everything. Whitespace-only counts as empty for the same reason it does
            // there — the operator did not mean to write JSON, so serde's "EOF while parsing a
            // value" names no remedy they can act on.
            (Ok(raw), _) if raw.trim().is_empty() => anyhow::bail!(
                "OBOLUS_TOKEN_KEYS is set but empty. It reached this process carrying nothing — an \
                 unexpanded ${{VAR}} or an EnvironmentFile line ending in `=` — which asks for a \
                 token path and names no key to build one from."
            ),
            (Ok(_), Ok(_)) => anyhow::bail!(
                "OBOLUS_TOKEN_KEYS and {SINGLE_KEY_VAR} are both set. The array form supersedes the \
                 single-key one, which would then sit inert — and an inert verifying key stays \
                 silent until a token signed with it is refused. Keep whichever one you meant."
            ),
            (Ok(raw), Err(_)) => Some(("OBOLUS_TOKEN_KEYS", parse_token_keys(&raw)?)),
            (Err(_), Ok(path)) if path.trim().is_empty() => anyhow::bail!(
                "{SINGLE_KEY_VAR} is set but empty. It is the variable whose presence decides \
                 whether a token path exists at all, so an empty one asks for a token path and \
                 names no key to build it from. Unset it to run with the 402 path alone, or point \
                 it at the public key tokens are signed with."
            ),
            (Err(_), Ok(path)) => {
                Some((SINGLE_KEY_VAR, vec![TokenKeyEntry { kid: None, file: path }]))
            }
            (Err(_), Err(_)) => None,
        };

    // The token path (OBOL-007). No key configured means no token path at all: every caller pays,
    // which is both the previous behaviour and the fail-closed direction to default to.
    let token: Option<TokenPath> = match key_source {
        None => {
            // ...but "no key configured" and "the key variable did not arrive" look identical from
            // here, and the second one is silent: no token path, no error, and every caller getting
            // a 402 is indistinguishable from a correctly working anonymous gateway. The operator
            // who set an issuer meant to have a token path. Same argument, and the same shape, as
            // `superseded_single_chain_vars` above — configuration that cannot mean what it says
            // must refuse rather than be dropped.
            let orphaned: Vec<&str> = ["OBOLUS_TOKEN_ISSUER", "OBOLUS_TOKEN_AUDIENCE"]
                .into_iter()
                .filter(|name| std::env::var(name).is_ok())
                .collect();
            if !orphaned.is_empty() {
                anyhow::bail!(
                    "{} set without OBOLUS_TOKEN_KEYS or {SINGLE_KEY_VAR}. Those configure a \
                     bearer-token path that cannot exist without a verifying key, so this would \
                     start a gateway that answers 402 to every caller while looking configured. \
                     Name the key(s), or unset {}.",
                    orphaned.join(" and "),
                    orphaned.join(" and "),
                );
            }
            None
        }
        Some((source, entries)) => {
            // Required alongside the key, not optional: a signing key usually belongs to an
            // identity provider rather than to one service, so with no `iss` to check, every token
            // that key has ever minted — for anything — would buy inference here.
            let issuer = std::env::var("OBOLUS_TOKEN_ISSUER").map_err(|_| {
                anyhow::anyhow!(
                    "{source} is set but OBOLUS_TOKEN_ISSUER is not. Set the issuer every honoured \
                     token must carry, or unset the key to run with the 402 path alone."
                )
            })?;
            // Set-but-empty is a startup error here for the same reason it is for the payment
            // vars: it means something arrived carrying nothing (an unexpanded `${VAR}`, an
            // `EnvironmentFile` line ending in `=`), and an empty issuer no token can match would
            // boot a token path that silently honours nobody.
            if issuer.is_empty() {
                anyhow::bail!(
                    "OBOLUS_TOKEN_ISSUER is set but empty. No token can carry an empty `iss`, so \
                     this would start a token path that refuses every caller."
                );
            }
            // Optional, and its absence is not permissive: with no expected audience a token
            // carrying `aud` is refused rather than honoured, because `aud` names the service the
            // token was minted for and we cannot tell "for us" from "for something else".
            let audience = match std::env::var("OBOLUS_TOKEN_AUDIENCE") {
                Err(_) => None,
                Ok(audience) if audience.is_empty() => anyhow::bail!(
                    "OBOLUS_TOKEN_AUDIENCE is set but empty. Unset it to refuse tokens that carry \
                     an `aud` claim, or give it the audience Obolus should answer to."
                ),
                Ok(audience) => Some(audience),
            };
            // Read every named file before building anything: a set half-loaded is a rotation half
            // armed, and the operator should hear about the unreadable one at startup rather than
            // discover it when a token signed with that key is refused.
            let mut keys = Vec::with_capacity(entries.len());
            for entry in entries {
                let pem = std::fs::read(&entry.file)
                    .map_err(|e| anyhow::anyhow!("{source} {}: {e}", entry.file))?;
                keys.push((entry.kid, pem));
            }
            let verifier = PublicKeyTokenVerifier::with_keys(&keys, &issuer, audience.as_deref())
                .map_err(|e| anyhow::anyhow!("{source}: {e}"))?;
            // No description composed here, deliberately. Round 3 found that this file *could*
            // still format one from `issuer` and `audience` that the verifier did not hold: with
            // `None` passed above, the banner announced the configured audience while the
            // `Validation` enforced none, and both test targets stayed green. The line now comes
            // off the verifier's own enforcing state — see `TokenVerifier::description`.
            Some(TokenPath::new(Arc::new(verifier)))
        }
    };

    // `new` rejects an empty option set or two options sharing (scheme, network) — a
    // misconfiguration that would otherwise settle the wrong asset. Fail here, at startup.
    let access = Access::new(
        Gateway::new(facilitator, upstream, requirements)
            .map_err(|e| anyhow::anyhow!("payment options: {e}"))?,
        token,
    );

    // Read off the access surface, not off the configuration that built it — and printed before
    // `router` consumes it. This file is compiled by no test target, so anything keyed on a local
    // would still print for an instance that does not hold what it claims: passing `None` at the
    // wiring site turns the whole feature off, and passing `None` for the audience leaves the banner
    // naming an audience the verifier never enforces — both with the library suite green. So both
    // legs are derived — *whether* there is a token path from the routed `Access`, and *what it
    // enforces* from the verifier's own `Validation` — and `tests/server_arming.rs` asserts this
    // line, which makes the wiring checkable from outside the process.
    //
    // Residual, stated rather than hidden: a *second* verifier or `Access` constructed purely to
    // describe would still defeat this. Mutating the real one does not, because the description has
    // no source but the object that does the checking.
    if let Some(description) = access.token_path() {
        eprintln!(
            "obolus: bearer-token access ENABLED ({description}). Callers without an honoured \
             token still get the 402 challenge — the paying path is unchanged."
        );
    }

    let app = router(access);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // The only line in this startup sequence entitled to say this, because it is the only one
    // printed after the socket exists. `tests/server_arming.rs` never observes it — that harness
    // holds the child's port so `bind` always fails, which is how those tests terminate at all — so
    // its discriminator is `starting on` above. See that file's `PAST_STARTUP`.
    eprintln!("obolus: listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
