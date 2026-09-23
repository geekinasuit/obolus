//! The Obolus server binary — wired to a real facilitator and a real Ollama upstream.
//!
//! This is live-capable, and testnet-by-construction *unless an operator explicitly arms it*:
//! startup refuses to advertise any network it cannot prove is testnet (see
//! [`obolus::arming`]), and `OBOLUS_ALLOW_MAINNET`, naming the exact network ids to arm, is the only
//! way past that refusal. Stating the posture unconditionally would make this doc false on exactly
//! the instance where it matters most.
//!
//! It delegates settlement to a third-party
//! x402 facilitator (`OBOLUS_FACILITATOR_URL`, required — the gateway never guesses where money
//! settles) and proxies inference to a backend: a single Ollama origin (`OBOLUS_UPSTREAM_URL`) by
//! default, or one of the backends declared in `OBOLUS_BACKENDS_FILE`, routed to by the request's
//! `model` (see [`obolus::backends`]). The payment
//! placeholders below are deliberately not real addresses and must be overridden for any real
//! network; there is no mainnet signing path in this crate.
//!
//! The Phase-A fakes are absent from this binary on purpose. They are `#[cfg(test)]`-only, so the
//! `obolus` target — which compiles the library without `cfg(test)` — physically cannot build an
//! accept-every-payment facilitator or a pretend upstream into a shipped artifact (#17). The
//! compiler is the guarantee, not a code review.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use obolus::access::{
    parse_token_keys, PublicKeyTokenVerifier, TokenKeyEntry, TokenPath, SINGLE_KEY_VAR,
};
use obolus::arming::{
    check_arming, legible, parse_arming, undiagnosed, PINNED_ON, PLACEHOLDER_NETWORK,
};
use obolus::config::{
    parse_accepts, require_backend_costs, select_pricing, select_promo, select_telemetry,
    superseded_single_chain_vars, validated_option, EntryDefect, EntryField, PricingChoice,
    SharedOffer, TelemetryChoice,
};
use obolus::backends::{load_backends, Backends};
use obolus::facilitator::DelegatedFacilitator;
use obolus::gateway::{router, Access, Gateway};
use obolus::pricing::{CostPlus, PriceDeterminer, Promotional, StaticPrice};
use obolus::telemetry::LineSink;
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
             start rather than guess where money settles. This binary speaks plain http:// to it \
             and has no outbound TLS client, while the public testnet facilitator is served over \
             https — so put a proxy in front: run a local proxy that accepts http:// and speaks \
             https:// to the facilitator, and point this variable at the proxy. Recipe: \
             https://github.com/geekinasuit/obolus#reaching-an-https-facilitator"
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

    // The response-head deadline is process-wide — it bounds the wait for *any* backend's head — so
    // it is read once here, before the registry is built, and applied to every backend in it.
    let head_timeout_secs =
        env_u64("OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS", DEFAULT_UPSTREAM_HEAD_TIMEOUT_SECS)?;
    if head_timeout_secs == 0 {
        anyhow::bail!(
            "OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS must be greater than 0: a 0-second deadline fires \
             immediately, turning every request into an uncharged 502 before the upstream can \
             answer."
        );
    }
    let head_timeout = Duration::from_secs(head_timeout_secs);

    // Where backends come from (#55, #56). `OBOLUS_BACKENDS_FILE`, when set, is a JSON file declaring
    // one or more backends — each a kind (`ollama` | `openai-compat` | `anthropic-compat`), base URL,
    // an optional key-file reference, and the models and precedence a request is routed on. It
    // supersedes the single-backend `OBOLUS_UPSTREAM_URL` exactly as `OBOLUS_ACCEPTS` supersedes the
    // single-chain payment variables, and refuses to start when both are set for the same reason: an
    // ignored upstream is a gateway serving a backend the operator did not think they configured.
    // Unset, the single Ollama backend is built from `OBOLUS_UPSTREAM_URL` — the N = 1 catch-all
    // path, behaviourally identical to before this module. `obolus::backends` fails loud at boot on a
    // malformed config, an unreadable key file, a non-http origin, or a registry whose routes are
    // ambiguous, so no such fault survives to the first paid request.
    let backends = match std::env::var("OBOLUS_BACKENDS_FILE") {
        // Set-but-empty first, ahead of the supersession bail below, for the reason the
        // OBOLUS_ACCEPTS arm gives: that bail is actionable but its premise is false here — the file
        // path itself never arrived, so nothing supersedes anything.
        Ok(path) if path.trim().is_empty() => anyhow::bail!(
            "OBOLUS_BACKENDS_FILE is set but empty: it reached this process carrying no path — an \
             unexpanded ${{VAR}} or an EnvironmentFile line ending in `=`. Unset it to build a \
             single backend from OBOLUS_UPSTREAM_URL, or point it at a backend-config JSON file."
        ),
        Ok(path) => {
            // Supersession, like OBOLUS_ACCEPTS: a single-backend variable set alongside the file
            // would sit inert. Refuse, naming it, rather than silently serving one and ignoring the
            // config the operator wrote.
            if std::env::var("OBOLUS_UPSTREAM_URL").is_ok() {
                anyhow::bail!(
                    "OBOLUS_BACKENDS_FILE and OBOLUS_UPSTREAM_URL are both set. The config file \
                     supersedes the single-backend variable, which would then sit inert. Keep \
                     whichever one you meant."
                );
            }
            // The cost twin of the refusal above. OBOLUS_UPSTREAM_COST is the *single* backend's
            // cost; with a file each backend declares its own per-entry "cost", so the env one would
            // sit inert. Refused unconditionally — on presence, not on whether the file happens to
            // set costs — so the rule is a property of the pairing, not of the config's contents.
            if std::env::var("OBOLUS_UPSTREAM_COST").is_ok() {
                anyhow::bail!(
                    "OBOLUS_BACKENDS_FILE and OBOLUS_UPSTREAM_COST are both set. OBOLUS_UPSTREAM_COST \
                     is the single-backend cost; with a config file each backend declares its own \
                     per-entry \"cost\", so the variable would sit inert. Set the cost per entry in \
                     the file, or unset OBOLUS_UPSTREAM_COST."
                );
            }
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("OBOLUS_BACKENDS_FILE {path:?}: {e}"))?;
            if raw.trim().is_empty() {
                anyhow::bail!(
                    "OBOLUS_BACKENDS_FILE {path:?} is empty. A backend config is a JSON array of \
                     backend objects; an empty file declares no backend to serve from."
                );
            }
            load_backends(&raw, head_timeout, |p: &str| std::fs::read(p))
                .map_err(|e| anyhow::anyhow!("OBOLUS_BACKENDS_FILE {path:?}: {e}"))?
        }
        Err(_) => {
            let upstream_url = env_or("OBOLUS_UPSTREAM_URL", DEFAULT_UPSTREAM_URL);
            // Fail fast, symmetric with the facilitator URL above. Case-insensitive, so `HTTP://` is
            // accepted rather than rejected as a typo. Left to request time, a bad scheme 502s every
            // paid request while /health still reports OK.
            if !upstream_url.to_ascii_lowercase().starts_with("http://") {
                anyhow::bail!(
                    "OBOLUS_UPSTREAM_URL must be an http:// origin (got {upstream_url:?}): the \
                     upstream client speaks plain HTTP only (no TLS is wired), so an https:// or \
                     schemeless URL cannot reach the model. Put a local http proxy in front of a \
                     TLS upstream if needed."
                );
            }
            Backends::single_ollama(&upstream_url, head_timeout)
        }
    };
    // The registry the gateway routes over. Kept owned for now: the pricing block below may still
    // attach the single-backend cost to it (`with_sole_cost`), which needs `&mut`. It is sealed into
    // an `Arc` there, once the rate is known and every backend's cost is settled.

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

    // One Obolus can advertise several chains at once. `OBOLUS_ACCEPTS`, when set, is a
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

    // Which rate prices each request (#57). Unset or `static` keeps the armed per-option amounts;
    // `cost-plus` determines the amount from a declared upstream cost and margin. Selected here,
    // before the arming guard and the banner, for the same reason the supersession refusals in the
    // requirements block are early: a pricing configuration this process will refuse must never
    // first advertise a price, and cost-plus makes the per-option amount inert — which the banner
    // below must then not print as if a client would pay it. `OBOLUS_ACCEPTS` and `OBOLUS_PRICE` are
    // already mutually exclusive by here (the block above refuses both at once), so the inert-amount
    // refusals inside can fire on at most one of them.
    let pricing = select_pricing(|k| std::env::var(k).ok())?;

    // A promotional discount, if one is configured, layered over whichever rate `select_pricing`
    // chose (see [`obolus::pricing::Promotional`]). Parsed here, beside the rate and before the
    // banner, for the same reason the rate is: a promotional window this process will refuse — one
    // that discounts nothing, everything, or has already closed — must never first be advertised.
    // The boot instant is read once and passed in, so the already-closed-window refusal is a pure
    // function of its inputs (the config door reads no clock of its own).
    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let promo = select_promo(|k| std::env::var(k).ok(), now_unix)?;

    // The telemetry sink, selected here with the other refusable doors so an unrecognised value
    // stops the process before any banner line. The writer thread is started later, once nothing
    // else can refuse.
    let telemetry = select_telemetry(|k| std::env::var(k).ok())?;

    // Land the single-backend cost on the sole backend, and check the whole registry against the
    // rate — both before the `Arc` seal, the arming guard, and the banner, for the same reason
    // `select_pricing` sits here: a pricing configuration this process will refuse must never first
    // advertise a price.
    //
    // Under cost-plus on the single-backend path, `OBOLUS_UPSTREAM_COST` arrives as `upstream_cost`
    // and is the sole backend's cost; `with_sole_cost` puts it there (the registry has exactly one
    // entry on that path). On the backends-file path `upstream_cost` is `None` — the env cost is
    // refused alongside a file above — and each backend already carries its own declared cost.
    let backends = match pricing {
        PricingChoice::CostPlus { upstream_cost: Some(cost), .. } => backends.with_sole_cost(cost),
        _ => backends,
    };
    // Cross-source coverage: cost-plus needs every backend to declare a cost (guessing one is a
    // fail-open); a declared cost under any other rate would sit unread. Either mismatch refuses,
    // naming the backends. `select_pricing` sees only the environment and `load_backends` only the
    // file — this is the one place that holds both.
    require_backend_costs(&backends, pricing)?;
    // Sealed now the rate is known and every cost is settled. Shared, so the banner below can read it.
    let backends = Arc::new(backends);

    // Obolus holds no key, but the 402 challenge it advertises IS the real-money trigger: a
    // cooperating client reads (network, asset, pay-to) out of it and pays against it. So the guard
    // sits on the advertisement. Fail-closed against a pinned testnet allowlist — a
    // mainnet id, a typo, or a testnet x402 added after this build all refuse to boot unarmed.
    //
    // Before the banner block below, deliberately: a refused configuration must never first print
    // "advertising N payment option(s)" for a gateway that is about to abort, and before
    // `Gateway::new`, so an unproven network never reaches a constructed router. That ordering is
    // checked, not merely asserted here — `a_refusal_never_advertises_anything_first` in
    // tests/server_arming.rs runs this binary and fails if the call moves. Exit status alone cannot
    // see it: a gateway that checks too late still exits non-zero, having already advertised.
    //
    // Arming names its target: the value is the comma-separated set of network ids to arm, and
    // `check_arming` admits an unproven network only if the set names it. The set must also name
    // nothing else — an unadvertised id, or one already on the allowlist, refuses — so the
    // environment can only describe exactly what it arms. The retired `=1` form is refused with a
    // pointer to this one; a value that names no advertised network (`true`, `yes`) refuses as a
    // mismatch, which is the safe direction for a typo.
    //
    // Read as an `OsString`, because `std::env::var` reports a non-UTF-8 value as an *error*, and
    // an error read carelessly looks like "unset" — the one value shape that would arm nothing and
    // refuse nothing. A value that is set is either a set of ids or a refusal; never silence.
    let raw_arming = match std::env::var_os("OBOLUS_ALLOW_MAINNET") {
        None => None,
        Some(value) => Some(value.into_string().map_err(|value| {
            anyhow::anyhow!(
                "OBOLUS_ALLOW_MAINNET is set but is not valid UTF-8 ({value:?}). A network id is \
                 ASCII, so this value can name nothing. Unset it, or set it to exactly the network \
                 id(s) to arm, comma-separated."
            )
        })?),
    };
    let armed_for = parse_arming(raw_arming.as_deref())?;
    let armed_requirements = check_arming(&requirements, &armed_for)?;
    // Read off the witness before it is consumed below. The diagnosis travels with the checked
    // set so that the armed banner cannot disclaim knowledge this module has.
    let unproven_networks = armed_requirements.unproven().to_vec();
    let diagnosis = armed_requirements.diagnosis().to_string();

    // The second check on the advertised option set, beside the first because they read the same
    // value: `new` rejects an empty set, and two options sharing (scheme, network) — a pair no
    // payment envelope can tell apart, so the second entry is unreachable and a payment matching it
    // could be settled against the wrong asset.
    //
    // Here rather than at the wiring site below, for the reason the guard above is here: a
    // configuration this process is about to refuse must not first be advertised. Past this point
    // the banner block prints the option set *and*, on the all-testnet path, the line saying every
    // advertised network is on the allowlist — an all-clear for a startup that never happens.
    // `a_duplicate_option_refuses_before_advertising_anything` in tests/server_arming.rs runs this
    // binary and fails if the call moves below it.
    //
    // `new` takes the guard's witness, not the vector: the type is what makes "checked before
    // advertised" a property of the constructor rather than of this file's ordering. The witness
    // holds its own copy of the option set; `requirements` stays for the banner below, and neither
    // is mutated after the guard ran, so they cannot drift.
    let gateway = Gateway::new(facilitator, backends.clone(), armed_requirements)
        .map_err(|e| anyhow::anyhow!("payment options: {e}"))?;
    // Install the selected rate, wrapped in the promotional discount if one is configured. The
    // arming guard's witness was consumed by `new` above, so no determiner — base or wrapped — can
    // alter which networks are advertised; it prices the amount and nothing else.
    //
    // The base is built explicitly even for static (which the constructor already defaults to) so a
    // promotion has a determiner to wrap uniformly: `Promotional` discounts whatever its base quotes,
    // static or cost-plus alike. Installing `StaticPrice` explicitly is the same behaviour as the
    // default.
    let base: Arc<dyn PriceDeterminer> = match pricing {
        PricingChoice::Static => Arc::new(StaticPrice),
        // The cost is not here: it lives on each backend and the determiner reads it per request
        // (see `CostPlus`). The margin is the gateway-wide half.
        PricingChoice::CostPlus { margin_bps, .. } => Arc::new(CostPlus::new(margin_bps)),
    };
    let determiner: Arc<dyn PriceDeterminer> = match promo {
        None => base,
        Some(p) => Arc::new(Promotional::new(p.discount_bps, p.start, p.end, base)),
    };
    let gateway = gateway.with_price_determiner(determiner);

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
    // Off the constructed registry, not the configuration that built it, so the line describes what
    // was actually wired. One line per backend the router can reach; the "keyed"/"keyless" note says
    // whether a bearer is attached without ever naming the credential. A backend with no `models` is
    // the catch-all that serves every request (the single-backend case).
    for backend in backends.backends() {
        let models = if backend.models.is_empty() {
            "any model".to_string()
        } else {
            backend.models.join(", ")
        };
        // The declared cost, when there is one. Present exactly on the cost-plus path (the coverage
        // check refuses a cost under any other rate), where it is the number this backend's quote is
        // marked up from — so it belongs on the backend's own line, not the single rate line above.
        let cost = match backend.cost {
            Some(c) => format!(", cost {c} atomic units"),
            None => String::new(),
        };
        eprintln!(
            "obolus: upstream (inference) -> backend {:?} kind {} at {} ({}, serves {}{})",
            backend.id,
            backend.kind,
            backend.base_url,
            if backend.has_key { "keyed" } else { "keyless" },
            models,
            cost,
        );
    }
    // The unconditional half of the posture: true on every instance, armed or not. The
    // testnet-by-construction claim is NOT stated here — on an armed instance it would be false, and
    // it sits one line above a MAINNET ARMED banner. It is asserted below, where it is checked.
    eprintln!(
        "obolus: LIVE WIRING — payments are verified and settled by the facilitator above, and \
         inference is proxied to the upstream above. No mainnet signing path exists in this binary; \
         pay-to / asset / network default to non-real placeholders and MUST be overridden for any \
         real network."
    );
    // The rate line, before the options. Under cost-plus each option's amount is determined by this
    // rate, not the armed value, so the per-option lines below omit the inert amount and the price
    // is stated once here. This prints the rate's *parameters*, never a computed quote: the quote is
    // what the determiner computes per request — and once a cost can vary by backend it is no longer
    // a single boot-time number — so a quote printed here would be a second source of truth that
    // could drift from what a client is actually charged. Same standard as the bearer-token line
    // below, read off the verifier rather than composed here.
    match pricing {
        PricingChoice::Static => {}
        PricingChoice::CostPlus { margin_bps, .. } => eprintln!(
            "obolus: pricing: cost-plus — every request quoted at its backend's declared cost \
             + {margin_bps} bps margin (each backend's cost is on its line above)."
        ),
    }
    // The promotional line, when a discount is configured. Its parameters, like the rate line: the
    // discount and the window bounds, never a computed post-discount amount (that is per-request and,
    // over cost-plus, per-backend). Printed only inside the window's lifetime — `select_promo`
    // already refused a window that closed before boot — so this never advertises a spent promotion.
    if let Some(p) = promo {
        eprintln!(
            "obolus: pricing: promotional — {} bps off the rate above during [{}, {}) (Unix \
             seconds); outside that window the rate above applies.",
            p.discount_bps, p.start, p.end
        );
    }
    eprintln!("obolus: advertising {} payment option(s):", requirements.len());
    for r in &requirements {
        match pricing {
            // Static: the armed amount IS the price, so it stays on the option line.
            PricingChoice::Static => eprintln!(
                "obolus:   - network {} / asset {} / pay-to {} / {} atomic units",
                r.network, r.asset, r.pay_to, r.max_amount_required
            ),
            // Cost-plus: the armed amount is inert (the rate above determines it), so print the
            // option without it rather than a number no client would pay.
            PricingChoice::CostPlus { .. } => eprintln!(
                "obolus:   - network {} / asset {} / pay-to {} / priced by the cost-plus rate above",
                r.network, r.asset, r.pay_to
            ),
        }
    }

    // Computed outside the arming branches on purpose. The placeholder is admitted by
    // `is_provably_testnet` through a clause of its own, so it never lands in `unproven_networks`;
    // whether an advertised option is a placeholder is independent of whether any *other* option is
    // unproven. Nested inside a branch, an armed array carrying both a real mainnet and a placeholder
    // would report the mainnet half and stay silent about the placeholder half — on the one instance
    // where money is real.
    let placeholders = requirements.iter().filter(|r| r.network == PLACEHOLDER_NETWORK).count();

    // The banner must not be able to lie. It is keyed on what is actually unproven, never on the
    // variable being set: `check_arming` refuses a value that names nothing unproven, so an
    // all-testnet gateway cannot reach here armed — and a banner keyed on anything but the list
    // would plant a log line someone trusts during an incident.
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
            "obolus: *** MAINNET ARMED *** OBOLUS_ALLOW_MAINNET names {} network(s) NOT on the \
             pinned testnet allowlist, advertised anyway: {}. {} That allowlist is a snapshot \
             pinned {}; if yours is a genuine testnet newer than that, the fix is a reviewed addition to \
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
             testnet allowlist."
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

    // The token path (#33). No key configured means no token path at all: every caller pays,
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
            // No description composed here, deliberately. This file *could* format one from
            // `issuer` and `audience` that the verifier does not hold — with `None` passed above,
            // a banner announcing the configured audience while the `Validation` enforces none
            // leaves both test targets green. The line comes off the verifier's own enforcing
            // state instead — see `TokenVerifier::description`.
            Some(TokenPath::new(Arc::new(verifier)))
        }
    };

    // Installed last, after every refusal: starting the writer thread is the one side effect of
    // selecting a sink, and a process that is about to refuse has nothing to record.
    let gateway = match telemetry {
        TelemetryChoice::Stdout => gateway.with_telemetry(Arc::new(LineSink::stdout()?)),
        TelemetryChoice::Off => gateway,
    };
    let access = Access::new(gateway, token);

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
    // Off the routed `Access`, like the token line above, so it describes the sink requests will
    // actually be recorded to. `tests/server_arming.rs` asserts it.
    eprintln!("obolus: telemetry: {}", access.telemetry());

    let app = router(access);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // The only line in this startup sequence entitled to say this, because it is the only one
    // printed after the socket exists. The address is the listener's own, so a port-0 bind names the
    // port it actually got. The arming harness in `tests/server_arming.rs` never observes it — it
    // holds the child's port so `bind` always fails, which is how those tests terminate at all — so
    // its discriminator is `starting on` above (see that file's `PAST_STARTUP`); the telemetry
    // tests there bind port 0 and read the port from this line.
    let bound = listener.local_addr()?;
    eprintln!("obolus: listening on http://{bound}");
    axum::serve(listener, app).await?;
    Ok(())
}
