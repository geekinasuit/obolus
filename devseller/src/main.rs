//! `obolus-devseller` — a counterparty to test an x402 client against.
//!
//! An x402 client is hard to develop against nothing. The protocol needs a seller that issues a
//! real 402 challenge, reads a real `X-PAYMENT` header, judges the authorization inside it, and
//! then *fails on command* — because the paths a client gets wrong are the failure paths, and a
//! real facilitator on a real testnet cannot be asked to reject the next payment, or to time out
//! settlement on an authorization it has already accepted.
//!
//! So this binary is that seller. It stands up the same [`obolus`] gateway the real binary does,
//! over a facilitator that verifies payments offline and settles nothing.
//!
//! # This settles no money, which is why it refuses to look as though it might
//!
//! Nothing here touches a chain. A payment this binary "settles" has not moved, so the inference
//! behind it was served for free — and startup therefore refuses two things outright, with no
//! override:
//!
//! - **any network it cannot prove is testnet.** `obolus` has `OBOLUS_ALLOW_MAINNET` for the
//!   operator who genuinely means it. This binary has no such flag: a gateway that hands out real
//!   inference for a payment it never collects has no business advertising a chain where the
//!   payment could have been real.
//! - **the built-in placeholder network.** `obolus::arming::is_provably_testnet` admits it through
//!   a clause of its own, so the check above passes it — and `obolus` boots on it deliberately, as
//!   the un-configured state. Here it is useless in both directions: no client can pay a challenge
//!   on a network no chain matches, and offline verification cannot even *run*, because the
//!   placeholder carries no `eip155:` chain id to build an EIP-712 domain from. A harness that
//!   comes up in that state passes and fails for reasons unrelated to what it is testing.
//!
//! # And it binds loopback
//!
//! Accept-every-payment, plus a real upstream, plus a routable interface is an unauthenticated
//! open proxy to somebody's inference endpoint — and the cost lands on whoever runs it. The
//! testnet refusal above does nothing about that; it guards the money path, not the exposure one.
//! So the default bind is `127.0.0.1`, a wider one is explicit, and the one genuinely dangerous
//! combination refuses without a second explicit acknowledgement.
//!
//! Testing a client on an Android device or another host does not need a wider bind: forward a
//! port to it (`adb reverse tcp:8404 tcp:8404`) and loopback is still loopback.

mod config;
mod facilitator;
mod upstream;
mod verify;

use std::net::SocketAddr;

use obolus::arming::{check_arming, PLACEHOLDER_NETWORK};
use obolus::config::{parse_accepts, superseded_single_chain_vars, validated_option, SharedOffer};
use obolus::gateway::{router, Access, Gateway};
use obolus::upstream::OllamaUpstream;
use obolus::x402::PaymentRequirements;

use crate::config::{VerifyMode, TOKEN_NAME_VAR, TOKEN_VERSION_VAR};
use crate::upstream::DevUpstream;
use crate::verify::TokenDomain;

/// Deliberately neither 8402 (which x402 client tooling tends to bind) nor 8403 (`obolus`), so a
/// development seller and a real gateway can run side by side without either moving.
const DEFAULT_ADDR: &str = "127.0.0.1:8404";

/// Placeholders matching `obolus`'s, so an operator who copies a configuration between the two
/// sees the same values mean the same things. Both are refused here before they can be advertised.
const PLACEHOLDER_PAY_TO: &str = "0xTEST-PAY-TO-ADDRESS-NOT-REAL";
const PLACEHOLDER_ASSET: &str = "0xTEST-ASSET-ADDRESS-NOT-REAL";

/// The acknowledgement that turns the open-proxy refusal off. Exactly the string `"1"`, matching
/// `OBOLUS_ALLOW_MAINNET`'s convention in `obolus` — the safe direction for a typo.
const ALLOW_OPEN_PROXY_VAR: &str = "OBOLUS_DEV_ALLOW_OPEN_PROXY";

/// What `--help` prints.
///
/// A literal rather than a string assembled from whatever `main` happens to read, because
/// `tests/guards.rs` checks it against the list of variables this binary is known to take: a help
/// text generated from the same source as the behaviour would agree with itself no matter which
/// variables it left out.
const USAGE: &str = "\
obolus-devseller — a development x402 seller, to test a client against.

*** NOT A GATEWAY. *** This process settles NO payment. It verifies authorizations offline and then
returns a synthetic receipt, so everything it serves is served for free. It exists to give an x402
client a counterparty that can be made to fail on demand — because the paths a client gets wrong are
the failure paths, and a real facilitator cannot be asked to reject the next payment. For a gateway
that takes real payment, run `obolus` instead.

USAGE
    obolus-devseller [--help]

There are no other arguments: this binary is configured entirely by environment variable.

WHERE IT LISTENS, AND WHAT IS BEHIND IT
    OBOLUS_ADDR                   bind address (default 127.0.0.1:8404 — see REFUSALS)
    OBOLUS_UPSTREAM_URL           http:// origin of a real model; unset serves a canned response
    OBOLUS_RESOURCE               resource id in the challenge (default: this address)
    OBOLUS_DESCRIPTION            human description in the challenge

WHAT IT CHARGES — two mutually exclusive doors, the same ones `obolus` offers
    OBOLUS_ACCEPTS                JSON array of payment options; supersedes the four below, and
                                  refuses to start if any of them is also set
    OBOLUS_NETWORK                CAIP-2 network id, e.g. eip155:84532 (testnets only)
    OBOLUS_ASSET                  20-byte token contract address
    OBOLUS_PAY_TO                 20-byte recipient address. There is no usable default: the
                                  built-in placeholder is not an address, so a client could not
                                  name it in an authorization, and startup refuses it.
    OBOLUS_PRICE                  price in atomic units (default 1000)

HOW IT SHOULD FAIL — the reason this binary exists. Two knobs, not one, because verification and
settlement fail independently: `verify` passing and settlement THEN failing is the case that decides
whether a client retries, whether it re-signs, and whether it double-pays. Only `succeed` and
`empty-receipt` serve the work; the other settle modes withhold it and answer 402 or 502, with a
nonce spent as far as the client knows.
    OBOLUS_DEV_VERIFY             verify (default) | accept | reject
    OBOLUS_DEV_REJECT_REASON      reason text for `reject`
    OBOLUS_DEV_SETTLE             succeed (default) | unsuccessful | unavailable | rejected |
                                  empty-receipt | timeout
    OBOLUS_DEV_SETTLE_REASON      reason text for `unavailable` and `rejected`
    OBOLUS_DEV_SETTLE_DELAY_SECS  seconds `timeout` blocks for (default 120)

THE EIP-712 TOKEN DOMAIN, which no x402 challenge carries, so both sides must agree out of band. A
mismatch here rejects correctly-signed payments.
    OBOLUS_DEV_TOKEN_NAME         EIP-712 domain name (default USDC)
    OBOLUS_DEV_TOKEN_VERSION      EIP-712 domain version (default 2)

REFUSALS, none of which are overridable except the last
    Any network it cannot prove is a testnet, and the built-in placeholder network. `obolus` has
    OBOLUS_ALLOW_MAINNET for an operator who means it; setting it here is itself a startup refusal,
    because a seller that gives inference away for a payment it never collects has no business
    advertising a chain where that payment could have been real.

    Binding beyond loopback, while accepting every payment uninspected, in front of a real model:
    that combination is an unauthenticated open proxy to somebody's inference endpoint, billed to
    whoever ran it. Forward a port instead (`adb reverse tcp:8404 tcp:8404`) and loopback stays
    loopback. Switching to OBOLUS_DEV_VERIFY=verify is NOT a fix: it checks a signature over a
    payer address the caller chooses, against no balance and no record of spent nonces, and
    nothing here settles, so a throwaway keypair satisfies it. Nothing this binary checks makes a
    routable bind safe in front of a model somebody pays for. To run it anyway:
    OBOLUS_DEV_ALLOW_OPEN_PROXY=1 acknowledge the open-proxy refusal
";

/// A configured value, or `default` when the variable is not set at all.
///
/// Set-but-empty is a refusal rather than a fall back to the default, applying the rule `config.rs`
/// states for its own variables to the rest of them: an empty value means something arrived carrying
/// nothing — an unexpanded `${VAR}`, an `EnvironmentFile` line ending in `=` — and silently taking
/// the default hides that the operator's chosen value never reached the process.
///
/// `OBOLUS_DEV_TOKEN_NAME` is the one that stings. An empty EIP-712 domain name is still a domain,
/// so verification runs, rejects every correctly-signed payment, and gives the payer no way to see
/// why from their side.
fn env_or(key: &str, default: &str) -> anyhow::Result<String> {
    match std::env::var(key) {
        Err(_) => Ok(default.to_string()),
        Ok(raw) if raw.trim().is_empty() => anyhow::bail!(
            "{key} is set but empty, so it reached this process carrying nothing. Unset it to take \
             the default ({default:?}), or give it a value."
        ),
        Ok(raw) => Ok(raw),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Before anything reads the environment. An unconfigured process falls through to the
    // placeholder network and refuses to start, so handling `--help` any later would answer a
    // request for documentation with a startup refusal about something else entirely.
    //
    // An unrecognised argument is refused rather than ignored: every knob here is an environment
    // variable, so `--port 9000` is a mistake that would otherwise take effect as silence.
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => anyhow::bail!(
                "unexpected argument {other:?}: obolus-devseller takes no arguments other than \
                 --help, because it is configured entirely by environment variable. Run \
                 `obolus-devseller --help` for the list."
            ),
        }
    }

    let addr: SocketAddr = env_or("OBOLUS_ADDR", DEFAULT_ADDR)?.parse()?;
    let dev = config::from_env(|key| std::env::var(key).ok())?;
    let token = TokenDomain {
        name: env_or(TOKEN_NAME_VAR, &TokenDomain::default().name)?,
        version: env_or(TOKEN_VERSION_VAR, &TokenDomain::default().version)?,
    };

    // Unset means the canned upstream — a development seller that needs a model running to test a
    // *payment* flow would be a worse tool than the one it replaces.
    let upstream_url = std::env::var("OBOLUS_UPSTREAM_URL").ok();
    let upstream = match &upstream_url {
        None => DevUpstream::Canned,
        Some(url) => {
            if !url.to_ascii_lowercase().starts_with("http://") {
                anyhow::bail!(
                    "OBOLUS_UPSTREAM_URL must be an http:// origin (got {url:?}): the upstream \
                     client speaks plain HTTP only. Unset it to serve a canned response instead."
                );
            }
            DevUpstream::Ollama(OllamaUpstream::new(url))
        }
    };

    let shared = SharedOffer {
        resource: env_or("OBOLUS_RESOURCE", &format!("http://{addr}/v1/chat/completions"))?,
        description: env_or("OBOLUS_DESCRIPTION", "One inference request (development seller)")?,
        max_timeout_seconds: 60,
    };

    // The same two configuration doors `obolus` offers, through the same shared checks, so a
    // configuration that works against one works against the other.
    let requirements: Vec<PaymentRequirements> = match std::env::var("OBOLUS_ACCEPTS") {
        Ok(raw) if raw.trim().is_empty() => anyhow::bail!(
            "OBOLUS_ACCEPTS is set but empty: it reached this process carrying nothing. Unset it \
             to configure a single chain with OBOLUS_NETWORK / OBOLUS_ASSET / OBOLUS_PAY_TO / \
             OBOLUS_PRICE instead."
        ),
        Ok(raw) => {
            let ignored = superseded_single_chain_vars(|k| std::env::var(k).is_ok());
            if !ignored.is_empty() {
                anyhow::bail!(
                    "OBOLUS_ACCEPTS is set and supersedes the single-chain payment variables, but \
                     these are also set and would be silently ignored: {}. Remove them, or unset \
                     OBOLUS_ACCEPTS.",
                    ignored.join(", ")
                );
            }
            parse_accepts(&raw, &shared)?
        }
        Err(_) => vec![validated_option(
            env_or("OBOLUS_NETWORK", PLACEHOLDER_NETWORK)?,
            env_or("OBOLUS_ASSET", PLACEHOLDER_ASSET)?,
            env_or("OBOLUS_PAY_TO", PLACEHOLDER_PAY_TO)?,
            &env_or("OBOLUS_PRICE", "1000")?,
            &shared,
        )
        .map_err(|e| anyhow::anyhow!("payment configuration: {e}"))?],
    };

    // ---- guards, all of them before anything is advertised -----------------------------------
    //
    // Same ordering rule as `obolus`'s: a refused configuration must never first tell the operator
    // it is advertising payment options. `tests/guards.rs` checks the ordering by
    // running this binary, because exit status cannot see it — a gateway that refuses too late
    // still exits non-zero, having already advertised.

    // No arming override exists here, and a flag that silently does nothing is worse than one that
    // is absent: an operator who sets it believes they have armed something.
    if std::env::var("OBOLUS_ALLOW_MAINNET").is_ok() {
        anyhow::bail!(
            "OBOLUS_ALLOW_MAINNET is set, and this binary has no arming override. \
             obolus-devseller settles no payment — it hands out whatever is behind it for free — \
             so it never advertises a network it cannot prove is testnet, armed or not. Unset the \
             variable. If you meant to run a gateway that can advertise a real chain, that is \
             `obolus`, not this."
        );
    }

    // `armed: false`, hardcoded — not a variable, not a parameter. Refuses on any network not on
    // the pinned testnet allowlist.
    check_arming(&requirements, false)?;

    // ...and separately, the placeholder, which the check above ADMITS through a clause of its own
    // (`obolus::arming::is_provably_testnet`). Two directions, two guards: deleting either one
    // leaves a startup this binary must not have.
    let placeholders: Vec<&PaymentRequirements> =
        requirements.iter().filter(|r| r.network == PLACEHOLDER_NETWORK).collect();
    if !placeholders.is_empty() {
        anyhow::bail!(
            "refusing to start on the built-in placeholder network {PLACEHOLDER_NETWORK:?} \
             ({} of {} advertised option(s)). Obolus invented that id precisely so no chain could \
             match it. `obolus` boots on it deliberately — that is its un-configured state — but \
             here it is useless in both directions: no client can pay a challenge on a network \
             that exists nowhere, and offline verification cannot even run against it, because it \
             carries no \"eip155:<chain-id>\" from which to build an EIP-712 domain. A test \
             harness that came up in this state would pass and fail for reasons unrelated to what \
             it is testing. Set OBOLUS_NETWORK to a testnet CAIP-2 id such as \"eip155:84532\".",
            placeholders.len(),
            requirements.len()
        );
    }

    // Every advertised EVM option must name a recipient a client can actually pay — in every mode,
    // which is why this is not folded into the `verify`-mode check below. `payTo` is what the
    // *client* puts in the authorization it signs, so an unreadable one makes the challenge unpayable
    // whether or not anything here would have inspected the result. `validated_option` only rejects
    // an empty `payTo`, and the built-in placeholder is not empty; it is simply not an address.
    //
    // EVM only because the shape being checked is the 20-byte address an EIP-3009 authorization has
    // to name. Obolus's pinned allowlist admits non-EVM testnets whose recipients are not hex at all
    // — Solana's are base58 — and refusing those would reject configurations this binary can
    // legitimately serve under `accept`. What cannot be checked is left alone rather than guessed at.
    let via_accepts = std::env::var("OBOLUS_ACCEPTS").is_ok();
    for (index, r) in requirements.iter().enumerate() {
        if verify::chain_id_of(&r.network).is_err() {
            continue;
        }
        verify::pay_to_of(r).map_err(|e| {
            // The remedy has to match the door the operator actually used. The two are mutually
            // exclusive, so telling an OBOLUS_ACCEPTS user to set OBOLUS_PAY_TO sends them into a
            // second refusal rather than out of the first. The contrast with `obolus` goes on the
            // single-chain branch for the same reason: only there is the offending value something
            // an *unset* variable defaulted to, so only there does it explain where it came from.
            let remedy = if via_accepts {
                "Give that entry's \"payTo\" key a 20-byte hex address. Setting OBOLUS_PAY_TO will \
                 not work here: OBOLUS_ACCEPTS supersedes the single-chain variables, so setting \
                 both is itself a startup refusal."
            } else {
                "Set OBOLUS_PAY_TO to a 20-byte hex address. `obolus` boots on the built-in \
                 placeholder this falls back to, because a gateway with no configured recipient is \
                 still a gateway waiting to be configured."
            };
            anyhow::anyhow!(
                "{e}\nAdvertised option {} of {} (network {}) cannot be paid. {remedy}\nA seller \
                 that cannot be paid exercises nothing, and the client author debugging it sees \
                 their own signing code fail.",
                index + 1,
                requirements.len(),
                r.network
            )
        })?;
    }

    // The same two-directions argument as the placeholder network, on the other placeholder. The
    // shape check above is scoped to EVM options because it cannot judge a base58 recipient — but
    // this value needs no address format to recognise, being a constant this file declares, so
    // leaving it to the shape check would let it ride through on every non-EVM network, which is
    // exactly where `OBOLUS_PAY_TO` is easiest to forget.
    //
    // After the shape check rather than beside its sibling: an EVM option carrying this value
    // reaches the refusal that knows about EIP-3009 and about which configuration door was used,
    // which is the more useful of the two. This is the backstop for what that one cannot see.
    let unpayable: Vec<&PaymentRequirements> =
        requirements.iter().filter(|r| r.pay_to == PLACEHOLDER_PAY_TO).collect();
    if !unpayable.is_empty() {
        anyhow::bail!(
            "refusing to start on the built-in placeholder recipient {PLACEHOLDER_PAY_TO:?} \
             ({} of {} advertised option(s)). It names no recipient on any chain, so a client that \
             reads it and pays it correctly has still paid nobody — and under \
             OBOLUS_DEV_VERIFY=accept it would be served and handed a successful receipt, which is \
             a green run against a sentinel. Set OBOLUS_PAY_TO to a recipient on that network, or \
             give the entry's \"payTo\" key one if you are configuring through OBOLUS_ACCEPTS.",
            unpayable.len(),
            requirements.len()
        );
    }

    // Under real verification every advertised option must actually be verifiable, and that is
    // knowable now. Left to request time it becomes a rejection on every payment, which reads to a
    // client author as "my signing is broken" rather than "the seller is misconfigured".
    if dev.verify == VerifyMode::Verify {
        for r in &requirements {
            verify::domain_for(r, &token).map_err(|e| {
                anyhow::anyhow!(
                    "{e}\nOBOLUS_DEV_VERIFY=verify checks signatures offline, so every advertised \
                     option must carry an EVM chain id and a 20-byte asset address. Fix the \
                     option, or set OBOLUS_DEV_VERIFY=accept to serve without inspecting payments."
                )
            })?;
        }
    }

    // The hazard publishing this binary creates, and the one the testnet refusal does nothing
    // about: it guards the money path, not the exposure one. Accept-mode plus a real upstream
    // plus a routable bind is an unauthenticated open proxy to somebody's inference endpoint, and
    // the bill lands on whoever ran it.
    let loopback = addr.ip().is_loopback();
    let real_upstream = upstream_url.is_some();
    let open_proxy_ack = std::env::var(ALLOW_OPEN_PROXY_VAR).as_deref() == Ok("1");
    if !loopback && real_upstream && dev.verify == VerifyMode::Accept && !open_proxy_ack {
        anyhow::bail!(
            "refusing to start: this configuration is an open proxy. The bind address {addr} is \
             not loopback, OBOLUS_DEV_VERIFY=accept serves every caller without inspecting their \
             payment, and OBOLUS_UPSTREAM_URL points at a real model — so anyone who can reach \
             this port gets unlimited inference at your expense. Bind loopback (the default) and \
             forward a port to reach it from another device — `adb reverse tcp:{port} \
             tcp:{port}` for Android. Note that OBOLUS_DEV_VERIFY=verify is NOT a fix for this: it \
             checks a signature over a payer address the caller chooses, against no balance and no \
             record of spent nonces, and nothing here ever settles — so a throwaway keypair \
             satisfies it as easily as a funded one. No check this binary can perform makes a \
             routable bind safe in front of a model somebody pays for. To run it anyway, set \
             {ALLOW_OPEN_PROXY_VAR}=1.",
            port = addr.port()
        );
    }

    // ---- past every guard; now say what this is ----------------------------------------------

    eprintln!("obolus-devseller: starting on http://{addr}");
    eprintln!(
        "obolus-devseller: *** DEVELOPMENT SELLER — NOT A GATEWAY *** This process settles NO \
         payment. It verifies authorizations offline and then returns a synthetic receipt, so \
         everything it serves is served for free. It is here to give an x402 client a counterparty \
         that can be made to fail on demand. Do not put it in front of anything you would not give \
         away."
    );
    eprintln!("obolus-devseller: behaviour -> {dev}");
    eprintln!("obolus-devseller: upstream -> {}", upstream::describe(&upstream, upstream_url.as_deref()));
    if dev.verify == VerifyMode::Verify {
        // The two fields no x402 challenge carries (#13). Printed unconditionally under
        // `verify` because a wrong one rejects every correct signature, and the payer cannot see
        // it from their side.
        eprintln!(
            "obolus-devseller: EIP-712 token domain -> name={:?} version={:?} (from \
             {TOKEN_NAME_VAR} / {TOKEN_VERSION_VAR}; x402 does not carry these, so a mismatch \
             here rejects correctly-signed payments)",
            token.name, token.version
        );
    }
    if !loopback {
        eprintln!(
            "obolus-devseller: *** BOUND BEYOND LOOPBACK *** {addr} is reachable from outside this \
             machine. Everything behind this gateway is being given away to anyone who can reach \
             that address."
        );
    }
    eprintln!("obolus-devseller: advertising {} payment option(s):", requirements.len());
    for r in &requirements {
        eprintln!(
            "obolus-devseller:   - network {} / asset {} / pay-to {} / {} atomic units",
            r.network, r.asset, r.pay_to, r.max_amount_required
        );
    }

    let gateway = Gateway::new(
        facilitator::DevFacilitator::new(dev.verify, dev.settle, token),
        upstream,
        requirements,
    )
    .map_err(|e| anyhow::anyhow!("payment options: {e}"))?;

    // No token path: this binary's whole purpose is exercising the *payment* path, and a bearer
    // token is the way to skip it.
    let app = router(Access::new(gateway, None));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("obolus-devseller: listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}
