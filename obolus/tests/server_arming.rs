//! `main`'s own behaviour exercised through the real `obolus` binary — the arming guard (OBOL-004)
//! and the bearer-token path's configuration and wiring (OBOL-007).
//!
//! # Why this exists as an exec test
//!
//! `arming.rs`'s unit tests call [`check_arming`] directly, and every teeth-measurement taken on
//! them mutated `arming.rs`. That proves the *function* and says nothing about the *call site* —
//! and the call site is where this guard can actually be defeated. `src/main.rs` is excluded from
//! the `obolus` library glob and is compiled by no other test target, so nothing else covers it:
//! hardcoding `armed` to `true`, swapping `?` for `unwrap_or_default()`, or moving `check_arming`
//! below `Gateway::new` all compile and leave the library suite fully green.
//!
//! So these tests run the shipped binary and read its behaviour off stderr and its exit status.
//! That is the only vantage point from which "the guard runs, and runs *before* the gateway
//! advertises anything" is a checkable claim rather than an assertion in a comment.
//!
//! # Why it terminates
//!
//! A gateway that passes its startup checks serves forever, which would hang a test. So the
//! harness holds a loopback port open and hands that address to the child: every startup check
//! and every banner runs to completion, then `tokio::net::TcpListener::bind` fails EADDRINUSE and
//! the process exits. Termination is therefore a property of the *last* line of startup, which
//! means anything printed before it is observable — including, deliberately, the lines a refused
//! configuration must NOT print.
//!
//! # Why it is hermetic
//!
//! Nothing here dials anything. `DelegatedFacilitator::new` and `OllamaUpstream::new` only parse
//! and validate their URLs — the hyper client is lazy and connects on first request, which never
//! happens because the process dies at bind. The facilitator URL below points at a discard port
//! that is never contacted.

use std::net::TcpListener;
use std::process::Command;

/// The prefix every variable `main` reads shares. Every inherited variable carrying it is cleared
/// before each run — by sweep, not by a hand-maintained list.
///
/// Cleared rather than `env_clear()`d: wiping the whole environment would also drop the loader
/// variables a Bazel-built binary may need on macOS. What has to be deterministic is Obolus's own
/// configuration, and an ambient `OBOLUS_ALLOW_MAINNET` leaking in from a developer's shell is
/// exactly the contamination that would turn the refusal tests green for the wrong reason.
///
/// A sweep rather than a hand-list, because a hand-list drifts silently and in the *unsafe*
/// direction: a variable added to `main` but not to the list stays inherited.
const OBOLUS_PREFIX: &str = "OBOLUS_";

/// The variables `main` reads today. Documentation and a drift alarm, **not** the clearing
/// mechanism — [`OBOLUS_PREFIX`] does the clearing, so this list going stale is harmless to
/// determinism. Held honest by `every_documented_variable_is_covered_by_the_prefix_sweep`.
const OBOLUS_VARS: &[&str] = &[
    "OBOLUS_ADDR",
    "OBOLUS_FACILITATOR_URL",
    "OBOLUS_MAX_TIMEOUT_SECS",
    "OBOLUS_UPSTREAM_URL",
    "OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS",
    "OBOLUS_RESOURCE",
    "OBOLUS_DESCRIPTION",
    "OBOLUS_ACCEPTS",
    "OBOLUS_NETWORK",
    "OBOLUS_PRICE",
    "OBOLUS_PAY_TO",
    "OBOLUS_ASSET",
    "OBOLUS_ALLOW_MAINNET",
    "OBOLUS_TOKEN_PUBKEY_FILE",
    "OBOLUS_TOKEN_KEYS",
    "OBOLUS_TOKEN_ISSUER",
    "OBOLUS_TOKEN_AUDIENCE",
];

/// Base mainnet — a real chain id, on no testnet allowlist. The point of the guard.
///
/// # `MAINNET` is a strict prefix of [`TESTNET`]
///
/// `"eip155:84532".contains("eip155:8453")` is `true` — the mainnet id is the testnet id minus its
/// last character. Any needle written bare against either of these is therefore satisfied by a
/// message naming the *other*, and `ACCEPTS_MAINNET_HIDDEN_AMONG_TESTNETS` puts both in one fixture.
///
/// Assert the **quoted** form — `format!("\"{MAINNET}\"")` — whenever the claim is "the message
/// names this id". Every offender in a refusal, and every network in the MAINNET ARMED banner, is
/// rendered through `arming::legible`, which quotes; the closing quote is what breaks the prefix
/// relation.
const MAINNET: &str = "eip155:8453";

/// Base Sepolia — the testnet Obolus actually expects to run on. See [`MAINNET`] on the prefix
/// relation between the two and what it means for any needle built from them.
const TESTNET: &str = "eip155:84532";

/// The line `main` prints immediately after the guard returns and before anything else — so its
/// presence is the observable boundary between "refused during startup" and "got past startup".
///
/// This is the discriminator these tests actually run on, because the child's *exit status* cannot
/// be one. The harness deliberately occupies the child's port so that `bind` — the last statement
/// of startup — always fails; that is what makes every banner observable, and it also means every
/// run in this file exits non-zero whether it refused or booted. An `assert!(!run.exited_ok)` here
/// would be true by construction and would keep passing if the guard were deleted outright.
///
/// # Why `starting on` and not `listening on`
///
/// This harness *depends* on `bind` failing, so `main`'s honest post-bind `listening on` line is
/// unobservable here by construction. Repointing at it would leave the
/// `must_have_got_past_startup` calls failing loudly — but
/// [`Run::must_have_refused_during_startup`] would become **always-true and silent**, because a
/// needle that is never printed is never found.
///
/// So the boundary this probes is "the guard let this through", not "a socket exists". Do not
/// repoint it at the post-bind line, and do not repoint it at `advertising` either: that needle is
/// already the independent claim in `a_refusal_never_advertises_anything_first`'s `must_not_say`,
/// and collapsing them would merge two distinct assertions into one.
const PAST_STARTUP: &str = "starting on";

/// Every line `main` prints is prefixed; every `anyhow` bail is prefixed by the runtime. One of the
/// two must appear or the child never got as far as running `main` at all.
const STARTUP_LINE: &str = "obolus: ";
const BAILED: &str = "Error:";

/// The x402-short-name diagnosis clause's lead-in, asserted both present and absent below. One
/// constant on purpose: a `must_not_say` written against a stale literal is satisfied by wording
/// drift exactly as happily as by correct behaviour, so the two directions have to share a needle
/// or the negative rots silently while the positive keeps it honest.
const SHORT_NAME_CLAUSE: &str = "Not a CAIP-2 identifier";

/// The refusal's closing steer away from `OBOLUS_ALLOW_MAINNET`. The LEAD-IN only, deliberately:
/// this guard's real protection is the operator not reaching for the flag, so what must be pinned is
/// that the steer is present at all — not the reason it happens to give today.
const ARMING_WONT_HELP: &str = "Arming helps none of the values named above";

/// The all-clear posture line's **distinctive claim** — never the phrase `testnet-by-construction`.
///
/// The obvious needle for "the all-clear did not print" is `testnet-by-construction`, and it is a
/// **needle collision**: the UNCONFIGURED NETWORK message contains the words *"NOT
/// testnet-by-construction"*, so on any fixture where both could appear the negative assertion fails
/// against the message that proves it right.
///
/// Same shape as the [`MAINNET`]/[`TESTNET`] prefix relation and [`ADVERTISEMENT_LINE`]: a needle
/// that is a substring of the text whose absence it checks. One shared constant so no test picks a
/// colliding one by hand again.
const ALL_CLEAR_CLAIM: &str = "every advertised network is on the pinned testnet allowlist";

/// The distinctive fragment of `main`'s advertisement line, `"obolus: advertising N payment
/// option(s):"` — the line `a_refusal_never_advertises_anything_first` checks the *absence* of.
///
/// Not the bare word `advertising`, which also appears in `diagnose`'s placeholder clause and in the
/// MAINNET ARMED banner — a negative assertion against it would be *satisfied by unrelated text*
/// rather than by the property under test. `payment option(s)` appears in this one line and nowhere
/// else; the ARMED banner counts `network(s) NOT`.
const ADVERTISEMENT_LINE: &str = "payment option(s)";

/// `OBOLUS_ACCEPTS` fixtures. Obviously-synthetic asset and pay-to values, never real or
/// partially-real addresses — these are payment-path fixtures and a plausible-looking address in
/// one is a hazard, not a convenience.
const ACCEPTS_ONE_TESTNET: &str = r#"[
    {"network":"eip155:84532","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"}
]"#;

/// A perfectly good Base Sepolia entry *plus* one naming the built-in placeholder. The only way an
/// operator reaches `UNCONFIGURED NETWORK`'s third enumerated state.
const ACCEPTS_TESTNET_PLUS_PLACEHOLDER: &str = r#"[
    {"network":"eip155:84532","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"},
    {"network":"test-network-not-a-real-caip2","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"}
]"#;

/// Base mainnet hidden between two genuine testnets — the configuration the ticket's Definition of
/// Done names, and one only `OBOLUS_ACCEPTS` can express.
const ACCEPTS_MAINNET_HIDDEN_AMONG_TESTNETS: &str = r#"[
    {"network":"eip155:84532","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"},
    {"network":"eip155:8453","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"},
    {"network":"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"}
]"#;

/// A genuine Base mainnet entry — exactly what `OBOLUS_ALLOW_MAINNET` exists for — *plus*
/// `base-sepolia`, the x402 short name the README documents as copyable straight out of x402's own
/// v1 spec payloads. Two entries about which Obolus knows *different amounts*: it can say nothing
/// specific about the first beyond "not on the allowlist", and can say of the second that it is not
/// a CAIP-2 id and so could never have matched.
///
/// **Diagnosable is not un-payable.** `Gateway::accepted_for` is byte-exact against the *advertised*
/// option set, which is where `base-sepolia` lives — so it is advertised, matchable and settleable
/// (`gateway::tests::an_id_the_arming_guard_cannot_prove_is_still_payable`). This fixture is about
/// what Obolus can *diagnose*, never about what a client can pay.
///
/// The gap it closes is a *distribution* gap rather than a missing assertion: every armed test before
/// it used a bare `eip155:8453` or `eip155:84532`, both values on which the banner's "Obolus cannot
/// tell which" disclaimer happens to be true. The armed suite was in-distribution with the very
/// assumption it would have had to falsify.
const ACCEPTS_MAINNET_PLUS_DEAD_SHORT_NAME: &str = r#"[
    {"network":"eip155:8453","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"},
    {"network":"base-sepolia","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"}
]"#;

/// Two x402 short names and nothing else — so every unproven value is diagnosable and the residue
/// `diagnose` cannot account for is **empty**. The third armed state; the other two are
/// all-unexplained (bare mainnets) and mixed (the fixture above).
///
/// Both are real x402 short names rather than invented ones, because the defect this guards is an
/// operator copying identifiers out of x402's own v1 payloads — an invented pair would test the
/// branch while misrepresenting how anyone reaches it.
const ACCEPTS_TWO_SHORT_NAMES: &str = r#"[
    {"network":"base-sepolia","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"},
    {"network":"polygon-amoy","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"}
]"#;

/// A genuine mainnet *and* Obolus's own placeholder in one array.
///
/// The interesting property is that these two land on **opposite sides** of the arming check:
/// `is_provably_testnet` admits the placeholder through a clause of its own, so only the mainnet
/// becomes "unproven". That is exactly why the placeholder report went missing on this branch — the
/// value that needs reporting is invisible to the predicate that chose the branch.
const ACCEPTS_MAINNET_PLUS_PLACEHOLDER: &str = r#"[
    {"network":"eip155:8453","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"},
    {"network":"test-network-not-a-real-caip2","asset":"0xTEST-ASSET-ADDRESS-NOT-REAL",
     "payTo":"0xTEST-PAY-TO-ADDRESS-NOT-REAL","maxAmountRequired":"1000"}
]"#;

/// The bearer-token path's startup line (OBOL-007). Asserted present by the positive case below and
/// absent by every token refusal, so — as with [`SHORT_NAME_CLAUSE`] — the two directions share one
/// needle and the negatives cannot rot into always-true while the positive keeps this honest.
///
/// The claim it carries is **wiring**, not wording. `main` derives this line from
/// `Access::token_path()`, so it can only print for an access surface that actually holds a
/// verifier — which is why its presence is evidence that the verifier reached the router. Nothing
/// else here can be: `src/main.rs` is compiled by no test target, the library tests build routers
/// directly, and dropping the verifier at the wiring site turns the whole feature off with every one
/// of those tests still green.
const TOKEN_ENABLED: &str = "bearer-token access ENABLED";

/// An Ed25519 SubjectPublicKeyInfo PEM built from 32 obviously-synthetic bytes (`01..20`).
///
/// A **public** key, so nothing here is a credential, and one nobody holds the private half of —
/// it was never generated from a keypair. That is sufficient for what these tests observe: the
/// startup path parses the SPKI and builds a verifier, and no token is ever presented to this
/// binary (the harness holds its port, so it never serves a request). Signature behaviour against
/// real keypairs is `access.rs`'s `signature_tests`, which generate throwaway keys at run time.
///
/// Written this way rather than generating a key here to keep `server_arming_test` std-only — see
/// BUILD.bazel. The 12-byte prefix is the fixed Ed25519 SPKI header of RFC 8410 §4.
const SYNTHETIC_PUBKEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
     MCowBQYDK2VwAyEAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n\
     -----END PUBLIC KEY-----\n";

/// A **second** synthetic public key, for the tests that arm a set of more than one.
///
/// Same construction as [`SYNTHETIC_PUBKEY_PEM`] over the next 32 counting bytes (`0x21..=0x40`)
/// instead of the first. Distinctness is load-bearing rather than tidy: `with_keys` refuses to arm
/// the same material twice, so a two-entry set built from one key is not a two-key set at all, and
/// a banner test fed one would be asserting the exact lie the banner exists to rule out.
const SECOND_SYNTHETIC_PUBKEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
     MCowBQYDK2VwAyEAISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=\n\
     -----END PUBLIC KEY-----\n";

/// The banner's *unconditional* disclaimer lead-in, asserted **absent** by the armed-diagnosis test:
/// when Obolus can name a defect, this flat form is false. A constant rather than an inline literal
/// for the same reason as `SHORT_NAME_CLAUSE` — a negative needle typed inline rots into a silent
/// always-pass the moment the wording moves.
const FLAT_DISCLAIMER: &str = "Each is a mainnet, a typo, or a testnet added to x402 after this build";

struct Run {
    stderr: String,
}

impl Run {
    fn says(&self, needle: &str) -> bool {
        self.stderr.contains(needle)
    }

    /// Assert on the whole captured stderr, and print it when the assertion fails — a bare
    /// `assert!(run.says(..))` on a startup banner gives no clue which of the branches ran.
    fn must_say(&self, needle: &str) {
        assert!(self.says(needle), "expected stderr to contain {needle:?}; got:\n{}", self.stderr);
    }

    fn must_not_say(&self, needle: &str) {
        assert!(
            !self.says(needle),
            "expected stderr NOT to contain {needle:?}; got:\n{}",
            self.stderr
        );
    }

    /// The single diagnosis bullet whose text contains `clause`. Panics if there is not exactly one.
    ///
    /// A plain `stderr.contains(..)` cannot express *which* bullet a value appears in — and "which
    /// bullet" is the entire content of a per-kind diagnosis. Asserting that `SHORT_NAME_CLAUSE` is
    /// present and `"base-sepolia"` is present is equally satisfied by a regression that listed
    /// **every** offender under the short-name clause, which is the flattening the grouped design
    /// exists to prevent.
    ///
    /// Bullets are `\n  · ` separated by `arming::diagnose`; the last one runs to the end of the
    /// banner line, so splitting on the separator and taking the matching segment is exact.
    fn bullet_containing(&self, clause: &str) -> String {
        let matches: Vec<&str> =
            self.stderr.split("\n  · ").filter(|bullet| bullet.contains(clause)).collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one diagnosis bullet containing {clause:?}, found {}; got:\n{}",
            matches.len(),
            self.stderr
        );
        matches[0].to_string()
    }

    /// `clause`'s bullet names `named` and does **not** name `not_named`.
    ///
    /// The negative half is the discriminating one: without it, a diagnosis that swept both
    /// offenders into one clause passes. Assert both in one call so a future test cannot take the
    /// positive and quietly drop the negative.
    fn clause_names_only(&self, clause: &str, named: &str, not_named: &str) {
        let bullet = self.bullet_containing(clause);
        assert!(
            bullet.contains(named),
            "the {clause:?} bullet should name {named:?}; bullet was:\n{bullet}"
        );
        assert!(
            !bullet.contains(not_named),
            "the {clause:?} bullet must NOT name {not_named:?} — that value is not this kind of \
             defect, and sweeping it in is the flattening this grouping exists to prevent; bullet \
             was:\n{bullet}"
        );
    }

    /// The guard fired: the process never reached `bind`.
    fn must_have_refused_during_startup(&self) {
        self.must_not_say(PAST_STARTUP);
    }

    /// The guard let this configuration through: the process reached `bind` (and then failed on the
    /// port this harness is holding, which is how it terminated at all).
    fn must_have_got_past_startup(&self) {
        self.must_say(PAST_STARTUP);
    }

    /// A token-path guard fired: the binary bailed for the stated reason and announced no token
    /// path.
    ///
    /// Deliberately **not** [`Self::must_have_refused_during_startup`]. That one asserts the absence
    /// of [`PAST_STARTUP`], which `main` prints ~130 lines *above* the token block — so every token
    /// refusal has already printed it, and reusing it here would assert something that is false by
    /// construction. What distinguishes a token refusal is the bail plus the absence of
    /// [`TOKEN_ENABLED`]: nothing was served, and nothing claimed a token path exists.
    fn must_have_refused_the_token_path(&self, because: &str) {
        self.must_say(BAILED);
        self.must_say(because);
        self.must_not_say(TOKEN_ENABLED);
    }
}

/// Write a fixture file for the child to read and hand back its path.
///
/// Under Bazel `TEST_TMPDIR` is the per-test scratch directory that the runner owns and cleans up.
/// Cargo has no equivalent, so a cargo run falls back to `temp_dir()` — shared, and not cleaned up
/// for us, which is why every caller passes a distinct name.
fn temp_file(name: &str, contents: &str) -> String {
    let dir = std::env::var("TEST_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write the fixture file");
    path.to_string_lossy().into_owned()
}

/// Run the real server binary to completion with `vars` applied over a fixed, valid baseline.
fn run(vars: &[(&str, &str)]) -> Run {
    // Both halves of the dual build, because both are supposed to pass. Bazel passes the path
    // through the rule's `env`; cargo sets `CARGO_BIN_EXE_<bin>` at compile time. `option_env!`
    // rather than `env!` because the latter is a compile error under Bazel, where cargo's variable
    // does not exist. The explicit variable wins where both are available, so pointing this suite at
    // some other build of the binary stays possible.
    let bin = std::env::var("OBOLUS_SERVER_BIN")
        .ok()
        .or_else(|| option_env!("CARGO_BIN_EXE_obolus").map(str::to_string))
        .expect(
            "no obolus server binary to run: OBOLUS_SERVER_BIN is unset (Bazel sets it from the \
             rule's env — see BUILD.bazel) and this was not built by cargo either",
        );

    // Occupy a loopback port and hand it to the child so that bind — the last statement of
    // startup — always fails. See the module docs.
    let occupied = TcpListener::bind("127.0.0.1:0").expect("occupy a loopback port");
    let addr = occupied.local_addr().expect("read back the occupied port");

    let mut cmd = Command::new(&bin);
    for (key, _) in std::env::vars() {
        if key.starts_with(OBOLUS_PREFIX) {
            cmd.env_remove(key);
        }
    }
    cmd.env("OBOLUS_ADDR", addr.to_string());
    // Required, never dialed: port 9 is discard, and startup only parses this URL.
    cmd.env("OBOLUS_FACILITATOR_URL", "http://127.0.0.1:9/facilitator");
    for (key, value) in vars {
        cmd.env(key, value);
    }

    let output = cmd.output().expect("run the server binary");
    // Explicit, so the listener's lifetime is obviously the child's lifetime and not an artefact
    // of where this function happens to end.
    drop(occupied);

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // Forecloses the vacuous pass for every test in this file at once. Most assertions here are
    // `must_not_say`, and a child that produced no output at all — wrong binary path, a crash
    // before the first `eprintln!`, stderr not captured — satisfies all of them. Every reachable
    // path through `main` prints at least one line, so empty stderr means the test observed
    // nothing, not that the property held.
    assert!(
        !stderr.trim().is_empty(),
        "the server binary produced no stderr; every assertion below would pass vacuously"
    );
    // Non-empty is necessary but weak — every path prints *something*, so on its own that check is
    // close to always-true. What it cannot distinguish is "the child ran `main` and refused" from
    // "the child never reached `main`": a bad runfiles path, a dyld failure, a panic in a static
    // initialiser. All three produce stderr, none of it recognisable, and all of it satisfies every
    // `must_not_say` in this file.
    assert!(
        stderr.contains(STARTUP_LINE) || stderr.contains(BAILED),
        "stderr contains neither a startup line nor a bail — the child probably never reached \
         `main`, so nothing below observes what it claims to; got:\n{stderr}"
    );

    Run { stderr }
}

#[test]
fn an_unarmed_mainnet_network_refuses_to_start() {
    let run = run(&[("OBOLUS_NETWORK", MAINNET)]);

    run.must_say("not on Obolus's pinned testnet allowlist");
    run.must_have_refused_during_startup();
}

#[test]
fn a_refusal_never_advertises_anything_first() {
    // The ordering claim in main's comment, checked rather than asserted. If `check_arming` moved
    // below the banner block — or below `Gateway::new` — the process would still exit non-zero,
    // so exit status alone cannot see this. What distinguishes the two is whether a gateway that
    // is about to abort first told the operator it was advertising payment options.
    let run = run(&[("OBOLUS_NETWORK", MAINNET)]);

    // Positive first, deliberately. The three absences below are the actual claim, but absences
    // alone are satisfied by a run that printed nothing at all — this pins that the refusal really
    // happened and that this run's stderr is the refusal's, so the absences are load-bearing.
    run.must_say("not on Obolus's pinned testnet allowlist");
    run.must_have_refused_during_startup();

    run.must_not_say(ADVERTISEMENT_LINE);
    run.must_not_say("MAINNET ARMED");
    run.must_not_say(ALL_CLEAR_CLAIM);
}

#[test]
fn only_the_exact_string_one_arms_the_gateway() {
    // main compares against `Ok("1")`. `true` is the plausible typo, and the safe direction for it
    // is "still refuses" — this is the call-site behaviour no unit test on `check_arming` can see,
    // because the string comparison lives in main.
    let run = run(&[("OBOLUS_NETWORK", MAINNET), ("OBOLUS_ALLOW_MAINNET", "true")]);

    run.must_say("not on Obolus's pinned testnet allowlist");
    run.must_have_refused_during_startup();
    run.must_not_say("MAINNET ARMED");
}

#[test]
fn an_armed_mainnet_network_boots_and_says_so_loudly() {
    let run = run(&[("OBOLUS_NETWORK", MAINNET), ("OBOLUS_ALLOW_MAINNET", "1")]);

    run.must_have_got_past_startup();
    run.must_say("*** MAINNET ARMED ***");
    run.must_say("advertising 1 payment option(s)");
    // The armed instance must never also claim the testnet posture.
    run.must_not_say(ALL_CLEAR_CLAIM);
    // The disclaimer's flat form is CORRECT here and must survive: a bare `eip155:8453` is not a
    // diagnosable defect, so Obolus genuinely cannot tell a mainnet from a typo from a newer
    // testnet. Paired deliberately with the opposite assertion in the test below — the round-7
    // change is that the sentence became conditional, not that it went away, and a fix that made
    // the scoped form unconditional would pass that test and fail this one.
    run.must_say(FLAT_DISCLAIMER);
}

#[test]
fn an_armed_gateway_diagnoses_a_dead_entry_among_a_real_mainnet() {
    // The armed branch must run the diagnosis clauses too, or the banner disclaims knowledge this
    // binary has.
    //
    // The discriminating property is not "a clause appears" but "the two entries are told apart":
    // both are unproven and both are named, only one is diagnosable, and a fix that flattened them
    // back together would satisfy a test that merely looked for the clause. `clause_names_only` is
    // the assertion that measures that — a whole-stderr `contains` cannot see which bullet a value
    // landed in.
    let run = run(&[
        ("OBOLUS_ACCEPTS", ACCEPTS_MAINNET_PLUS_DEAD_SHORT_NAME),
        ("OBOLUS_ALLOW_MAINNET", "1"),
    ]);

    run.must_have_got_past_startup();
    run.must_say("*** MAINNET ARMED ***");
    // Quoted: `eip155:8453` is a strict prefix of `eip155:84532`, and the offender list renders
    // through `arming::legible`, which quotes.
    run.must_say(&format!("\"{MAINNET}\""));
    run.must_say("\"base-sepolia\"");
    // Told apart, and measured: the short-name clause names the short name and NOT the mainnet.
    run.clause_names_only(SHORT_NAME_CLAUSE, "\"base-sepolia\"", &format!("\"{MAINNET}\""));
    // The steer away from the flag, scoped to "the values named above" so a genuine mainnet sharing
    // the offender set is not swept into it.
    run.must_say(ARMING_WONT_HELP);
    // ...and the flat disclaimer is gone, because it is false when a defect IS named. Its scoped
    // replacement still covers `eip155:8453`, which is why the negative is on the lead-in only.
    run.must_not_say(FLAT_DISCLAIMER);
    run.must_say("Obolus can name a defect in some of them");
    // The mixed-state arm: the residue is NAMED rather than gestured at. This distinguishes the
    // mixed banner from the all-diagnosable one, whose text would be wrong here, and it is the
    // assertion that fails if the three-way split collapses back to two.
    run.must_say(&format!("It cannot account for \"{MAINNET}\""));
    // Still not the testnet posture, and still not a refusal — arming worked.
    run.must_not_say(ALL_CLEAR_CLAIM);
}

#[test]
fn an_armed_gateway_whose_offenders_are_all_diagnosable_claims_no_residue() {
    // The third of three reachable armed states: EVERY unproven value is diagnosable, so the residue
    // is empty. Printing the mixed-state text here would quantify "for any it does not name" over the
    // empty set and tell the operator to treat the gateway as able to move real funds on the strength
    // of a set with nothing in it.
    //
    // Discriminated against the mixed arm by asserting the mixed lead-in is ABSENT — without that,
    // the all-arm text could be added while the mixed text still printed and this would not notice.
    let run = run(&[("OBOLUS_ACCEPTS", ACCEPTS_TWO_SHORT_NAMES), ("OBOLUS_ALLOW_MAINNET", "1")]);

    run.must_have_got_past_startup();
    run.must_say("*** MAINNET ARMED ***");
    run.must_say("Obolus can name a defect in every one of them");
    run.must_not_say("Obolus can name a defect in some of them");
    run.must_not_say("It cannot account for");
    // The flat disclaimer's central claim must not survive here either: there is no unexplained
    // value for "treat this gateway as able to move real funds" to be about.
    run.must_not_say(FLAT_DISCLAIMER);
    // Both are still named as offenders, and both under the one clause that fits them.
    run.must_say("\"base-sepolia\"");
    run.must_say("\"polygon-amoy\"");
    run.must_say(SHORT_NAME_CLAUSE);
}

#[test]
fn an_armed_gateway_reports_a_placeholder_option_alongside_the_mainnet_banner() {
    // The placeholder is admitted by `is_provably_testnet` through a clause of its own, so it never
    // lands in `unproven_networks`. Nest the placeholder report inside the all-proven branch and an
    // armed array carrying a real mainnet AND a placeholder prints the MAINNET banner and says
    // nothing about the placeholder half — on the one instance where money is real.
    //
    // Discriminating on the pairing, not on either line alone: both banners must appear in the SAME
    // run.
    let run = run(&[
        ("OBOLUS_ACCEPTS", ACCEPTS_MAINNET_PLUS_PLACEHOLDER),
        ("OBOLUS_ALLOW_MAINNET", "1"),
    ]);

    run.must_have_got_past_startup();
    run.must_say("*** MAINNET ARMED ***");
    run.must_say("UNCONFIGURED NETWORK");
    // And it must still not claim the all-clear posture, which is the reassuring-direction failure
    // the un-armed half of this pair guards.
    run.must_not_say(ALL_CLEAR_CLAIM);
}

#[test]
fn an_unconfigured_boot_is_not_reported_as_testnet_by_construction() {
    // With no OBOLUS_NETWORK the advertised id is PLACEHOLDER_NETWORK, which `is_provably_testnet`
    // admits through its own clause — it is deliberately NOT on the pinned allowlist. So the
    // all-clear line's specific claim ("every advertised network is on the pinned testnet
    // allowlist") is false here, and an operator whose OBOLUS_NETWORK silently failed to reach the
    // process would read it as confirmation that their configuration took effect.
    let run = run(&[]);

    run.must_have_got_past_startup();
    run.must_say("UNCONFIGURED NETWORK");
    run.must_not_say(ALL_CLEAR_CLAIM);
    run.must_not_say("MAINNET ARMED");
}

#[test]
fn a_configured_testnet_reports_the_testnet_posture() {
    let run = run(&[("OBOLUS_NETWORK", TESTNET)]);

    run.must_have_got_past_startup();
    run.must_say("testnet-by-construction");
    run.must_say(ALL_CLEAR_CLAIM);
    run.must_not_say("UNCONFIGURED NETWORK");
    run.must_not_say("MAINNET ARMED");
}

#[test]
fn an_x402_short_name_is_refused_with_a_diagnosis_the_operator_can_act_on() {
    // `base-sepolia` names a real testnet, in the form x402's own v1 spec examples use — and until
    // this round, the README's multi-chain example used it too. It is refused (comparison is
    // byte-exact), so the whole question is whether the refusal is actionable: the generic three
    // causes are each visibly false to an operator who knows they are on Base Sepolia, and a
    // refusal whose every stated cause is false is how an operator ends up at OBOLUS_ALLOW_MAINNET.
    // Exercised through the real binary, because this is a value that arrives via the environment.
    let run = run(&[("OBOLUS_NETWORK", "base-sepolia")]);

    run.must_say(SHORT_NAME_CLAUSE);
    // The clause's worked examples survived the wording. NOT "names the id to use instead" — the id
    // is hardcoded as an example of the *form*, so this passes for any short-name input, including
    // `solana-devnet` where the id to use is named nowhere.
    run.must_say(TESTNET);
    run.must_have_refused_during_startup();
    run.must_not_say("MAINNET ARMED");
}

#[test]
fn a_mainnet_hidden_among_testnets_in_accepts_refuses_to_start() {
    // The ticket's Definition of Done names this configuration, and an operator can only *produce*
    // it through OBOLUS_ACCEPTS — so a unit test on `check_arming` verifies it everywhere except
    // where it actually happens.
    let run = run(&[("OBOLUS_ACCEPTS", ACCEPTS_MAINNET_HIDDEN_AMONG_TESTNETS)]);

    run.must_say("not on Obolus's pinned testnet allowlist");
    // Quoted, because MAINNET is a strict prefix of TESTNET and this fixture advertises both — a
    // bare needle here is satisfied by a refusal naming the genuine Base Sepolia entry instead. See
    // the doc on MAINNET. The offender list renders through `arming::legible`, which quotes.
    run.must_say(&format!("\"{MAINNET}\"")); // names the offender, not just the count
    run.must_have_refused_during_startup();
    // The two genuine testnets must not be dragged into the refusal with it.
    run.must_not_say("advertise 3 network(s)");
}

#[test]
fn accepts_alongside_the_single_chain_vars_refuses_to_start() {
    // `superseded_single_chain_vars` is unit-tested as a pure function; the `if !ignored.is_empty()
    // { bail! }` that consumes it was not tested anywhere. It is a refusal with its own message on
    // the payment-configuration path, and it is what makes the parenthetical in UNCONFIGURED
    // NETWORK ("that combination refuses to start") true.
    let run = run(&[("OBOLUS_ACCEPTS", ACCEPTS_ONE_TESTNET), ("OBOLUS_NETWORK", TESTNET)]);

    run.must_say("supersedes the single-chain payment variables");
    run.must_say("OBOLUS_NETWORK"); // names which variable is being ignored
    run.must_have_refused_during_startup();
}

#[test]
fn an_accepts_entry_naming_the_placeholder_reports_unconfigured_not_testnet() {
    // The third state UNCONFIGURED NETWORK enumerates, and the only one reachable via ACCEPTS: the
    // configuration *did* arrive — two options, one a perfectly good Base Sepolia entry — and one of
    // its entries names the placeholder. That is why the line cannot say "the value did not reach
    // this process".
    let run = run(&[("OBOLUS_ACCEPTS", ACCEPTS_TESTNET_PLUS_PLACEHOLDER)]);

    run.must_have_got_past_startup();
    run.must_say("UNCONFIGURED NETWORK");
    run.must_say("1 of 2 advertised option(s)"); // the count is the claim
    run.must_not_say(ALL_CLEAR_CLAIM);
    run.must_not_say("MAINNET ARMED");
}

#[test]
fn an_empty_network_variable_refuses_to_start_and_names_the_variable() {
    // `std::env::var` yields `Ok("")` for a set-but-empty variable, so this reaches `main` as a real
    // value. Unchecked, it sails past to the arming guard, which diagnoses it as an x402 short name
    // and tells the operator to "look up the CAIP-2 id for that chain" — naming no chain, because
    // they named none, leaving the arming flag as the only actionable thing in the message.
    //
    // What the operator has to be told is which *variable* is empty, which is why the shared
    // per-option check is wrapped in single-chain naming rather than reused verbatim.
    let run = run(&[("OBOLUS_NETWORK", "")]);

    run.must_say("OBOLUS_NETWORK is set but empty");
    run.must_have_refused_during_startup();
    run.must_not_say(SHORT_NAME_CLAUSE);
    run.must_not_say("MAINNET ARMED");
}

#[test]
fn an_empty_asset_variable_refuses_to_start() {
    // Measured: disabling `asset.trim().is_empty()` in `config::validated_option` left this exec
    // suite fully green, because nothing here set OBOLUS_ASSET — the call-site convergence was
    // verified for `network` and `payTo` only.
    //
    // The negative assertion below is the other half: with a `{ .. }` catch-all in
    // `single_chain_defect`, the empty-asset defect would be reported against OBOLUS_PAY_TO, sending
    // the operator to clear a variable that was fine.
    let run = run(&[("OBOLUS_NETWORK", TESTNET), ("OBOLUS_ASSET", "")]);

    run.must_say("OBOLUS_ASSET is set but empty");
    run.must_not_say("OBOLUS_PAY_TO is set but empty"); // the catch-all's wording, on the wrong var
    run.must_have_refused_during_startup();
}

#[test]
fn an_empty_accepts_variable_refuses_to_start_and_says_so() {
    // `std::env::var` yields `Ok("")`, so an empty OBOLUS_ACCEPTS takes the multi-chain door and
    // reaches serde, which answers an unexpanded `${VAR}` with "must be a JSON array … EOF while
    // parsing a value at line 1 column 0". Every remedy in that message is wrong: the operator did
    // not mean to write JSON, and the fix — unset the variable — is not in it.
    let run = run(&[("OBOLUS_ACCEPTS", "")]);

    run.must_say("OBOLUS_ACCEPTS is set but empty");
    run.must_say("Unset it"); // the actual remedy, which the serde error never named
    run.must_not_say("EOF while parsing"); // the raw serde error, which names no remedy
    run.must_have_refused_during_startup();
}

#[test]
fn an_empty_accepts_alongside_single_chain_vars_reports_the_true_premise() {
    // Why the empty-value guard sits *above* the supersession bail. That bail is actionable on its
    // own ("unset OBOLUS_ACCEPTS" is in its text), but the premise it states is false here: it tells
    // an operator whose array is empty that the array supersedes their single-chain configuration.
    // Set-but-empty is the true statement, so it must win.
    //
    // The non-empty pairing is `accepts_alongside_the_single_chain_vars_refuses_to_start` above,
    // which still reaches the supersession bail — that is what keeps this ordering claim readable as
    // a choice between two live branches rather than as the only branch left.
    let run = run(&[("OBOLUS_ACCEPTS", ""), ("OBOLUS_NETWORK", TESTNET)]);

    run.must_say("OBOLUS_ACCEPTS is set but empty");
    // The supersession bail's own distinguishing clause, not the phrase both messages share
    // ("supersedes the single-chain payment variables") — that one is another needle collision: the
    // negative would be satisfied by the very text it checks for the absence of.
    run.must_not_say("would be silently ignored");
    run.must_have_refused_during_startup();
}

#[test]
fn an_empty_pay_to_variable_refuses_to_start() {
    // The asymmetry that convergence closed, stated as its own test because it is the one with
    // money attached: `parse_accepts` has always rejected an empty `payTo`, while the single-chain
    // branch advertised the challenge — an option that sends money nowhere — and started cleanly.
    let run = run(&[("OBOLUS_NETWORK", TESTNET), ("OBOLUS_PAY_TO", "")]);

    run.must_say("OBOLUS_PAY_TO is set but empty");
    run.must_have_refused_during_startup();
}

#[test]
fn an_armed_all_testnet_gateway_says_the_flag_changed_nothing() {
    // The fourth posture line, and the only one no test observed. Armed-but-all-testnet is a legal
    // state: the flag is set, every advertised network is still on the allowlist. The banner must
    // NOT cry mainnet here — that is the "banner cannot lie" property — but the flag being set and
    // inert has to be said, or an armed instance stops being recognisable by its environment alone.
    let run = run(&[("OBOLUS_NETWORK", TESTNET), ("OBOLUS_ALLOW_MAINNET", "1")]);

    run.must_have_got_past_startup();
    run.must_say("testnet-by-construction");
    run.must_say("OBOLUS_ALLOW_MAINNET is set but changed nothing here");
    run.must_not_say("MAINNET ARMED");
}

// ---- the bearer-token path's call site (OBOL-007) ------------------------------------------------
//
// Same argument as the arming guard's, one feature later: `access.rs` is unit-tested to death and
// none of it says whether `main` wires any of it up. These are the only tests that compile-and-run
// the OBOL-007 half of `main` at all.
//
// The path below is deliberately unreadable in the first four: all three configuration guards run
// before `std::fs::read`, so a path that cannot exist still reaches every one of them, and a test
// that needed a real key to check a guard about a missing issuer would be measuring two things.

/// Not a file, on purpose — see the section note above.
const ABSENT_KEY_PATH: &str = "/nonexistent/obolus-token-key.pem";
const TEST_ISSUER: &str = "https://issuer.invalid/obolus";

#[test]
fn a_token_key_without_an_issuer_refuses_to_start() {
    // Without `iss` every token the configured key ever minted — for any service sharing that IdP —
    // would buy inference here. The guard is in `main`, so nothing in the library suite sees it:
    // replacing the `?` with `unwrap_or_default()` leaves that suite green.
    let run = run(&[("OBOLUS_TOKEN_PUBKEY_FILE", ABSENT_KEY_PATH)]);

    run.must_have_refused_the_token_path("OBOLUS_TOKEN_ISSUER is not");
}

#[test]
fn an_empty_token_issuer_refuses_to_start() {
    // `Ok("")`, not `Err` — the unexpanded-`${VAR}` shape. An empty expected issuer no token can
    // carry would boot a token path that honours nobody, which from outside is indistinguishable
    // from a working anonymous gateway.
    let run = run(&[("OBOLUS_TOKEN_PUBKEY_FILE", ABSENT_KEY_PATH), ("OBOLUS_TOKEN_ISSUER", "")]);

    run.must_have_refused_the_token_path("OBOLUS_TOKEN_ISSUER is set but empty");
}

#[test]
fn an_empty_token_audience_refuses_to_start() {
    // Set-but-empty is not "unset": unset means "refuse any token carrying `aud`", and an empty
    // string would instead be an audience no token can match. Two different postures, one of which
    // the operator did not choose.
    let run = run(&[
        ("OBOLUS_TOKEN_PUBKEY_FILE", ABSENT_KEY_PATH),
        ("OBOLUS_TOKEN_ISSUER", TEST_ISSUER),
        ("OBOLUS_TOKEN_AUDIENCE", ""),
    ]);

    run.must_have_refused_the_token_path("OBOLUS_TOKEN_AUDIENCE is set but empty");
}

#[test]
fn an_unreadable_token_key_refuses_to_start_and_names_the_path() {
    // The failure an operator actually hits: a secret mount that did not render. Naming the path is
    // the whole value — "No such file or directory" alone does not say which of the process's files
    // is missing.
    let run = run(&[
        ("OBOLUS_TOKEN_PUBKEY_FILE", ABSENT_KEY_PATH),
        ("OBOLUS_TOKEN_ISSUER", TEST_ISSUER),
    ]);

    run.must_have_refused_the_token_path(ABSENT_KEY_PATH);
}

#[test]
fn an_empty_token_key_path_refuses_to_start() {
    // The variable whose set-ness *picks the branch*, and the only one that had no empty check: an
    // empty value takes the `Ok` arm, so it asks for a token path while naming no key to build one
    // from. Without the empty check the orphan guard does not fire (the variable *is* set), and the
    // operator is instead pointed at whichever of issuer/key-path fails next, which is never the one
    // they actually got wrong.
    let run = run(&[("OBOLUS_TOKEN_PUBKEY_FILE", ""), ("OBOLUS_TOKEN_ISSUER", TEST_ISSUER)]);

    run.must_have_refused_the_token_path("OBOLUS_TOKEN_PUBKEY_FILE is set but empty");
}

#[test]
fn token_variables_without_a_key_refuse_to_start_rather_than_going_quiet() {
    // The one case with no symptom: the key variable never arrives, the `Err` arm takes `None`, and
    // an operator who configured a token path gets a gateway that 402s everyone — which looks
    // exactly like a correctly working anonymous one. Both variables, separately, because the guard
    // must not be satisfied by whichever one happens to be checked first.
    for orphan in ["OBOLUS_TOKEN_ISSUER", "OBOLUS_TOKEN_AUDIENCE"] {
        let run = run(&[(orphan, TEST_ISSUER)]);

        run.must_have_refused_the_token_path(orphan);
        // Both key variables, because either one would have given this operator a token path. An
        // orphan check that named only the single-key form would send someone using the array form
        // looking for a variable they deliberately did not set.
        run.must_say("without OBOLUS_TOKEN_KEYS or OBOLUS_TOKEN_PUBKEY_FILE");
    }
}

#[test]
fn a_key_set_boots_and_the_banner_names_every_key() {
    // The exec-level half of the banner check. `src/main.rs` is compiled by no test target, so this
    // is the only vantage point on whether the key set an operator configured is the key set that
    // reached the router — the unit tests can only see a verifier they built themselves.
    let alpha = temp_file("obolus-token-alpha.pem", SYNTHETIC_PUBKEY_PEM);
    let beta = temp_file("obolus-token-beta.pem", SECOND_SYNTHETIC_PUBKEY_PEM);
    let keys = format!(
        "[{{\"kid\":\"alpha\",\"file\":\"{alpha}\"}},{{\"kid\":\"beta\",\"file\":\"{beta}\"}}]"
    );
    let run = run(&[("OBOLUS_TOKEN_KEYS", &keys), ("OBOLUS_TOKEN_ISSUER", TEST_ISSUER)]);

    run.must_have_got_past_startup();
    run.must_say(TOKEN_ENABLED);
    run.must_say(TEST_ISSUER);
    // Sorted, and naming both: dropping either entry at the wiring site changes this line, which is
    // what makes a half-armed rotation visible from outside the process.
    run.must_say("2 keys: alpha, beta");
}

#[test]
fn both_key_variables_at_once_refuse_to_start() {
    // The array form supersedes the single-key one, so accepting both would leave a verifying key
    // configured and inert — and an inert verifying key says nothing until a token signed with it
    // is refused, possibly long after the operator stopped watching.
    let key = temp_file("obolus-token-single.pem", SYNTHETIC_PUBKEY_PEM);
    let keys = format!("[{{\"kid\":\"alpha\",\"file\":\"{key}\"}}]");
    let run = run(&[
        ("OBOLUS_TOKEN_KEYS", &keys),
        ("OBOLUS_TOKEN_PUBKEY_FILE", &key),
        ("OBOLUS_TOKEN_ISSUER", TEST_ISSUER),
    ]);

    run.must_have_refused_the_token_path("are both set");
}

#[test]
fn an_empty_key_array_says_so_rather_than_blaming_supersession() {
    // The supersession message is actionable but its premise is false here: an array that arrived
    // empty configures nothing, so telling the operator it supersedes their single-key setting sends
    // them to delete the one variable that still works. Same ordering rule OBOLUS_ACCEPTS follows.
    let key = temp_file("obolus-token-empty-array.pem", SYNTHETIC_PUBKEY_PEM);

    // Whitespace-only too: an unexpanded ${VAR} in a compose file arrives looking like this, and
    // serde's "EOF while parsing a value" names no remedy the operator can act on.
    for raw in ["", "   "] {
        let run = run(&[
            ("OBOLUS_TOKEN_KEYS", raw),
            ("OBOLUS_TOKEN_PUBKEY_FILE", &key),
            ("OBOLUS_TOKEN_ISSUER", TEST_ISSUER),
        ]);

        run.must_have_refused_the_token_path("is set but empty");
        run.must_not_say("are both set");
    }
}

#[test]
fn a_malformed_key_array_refuses_rather_than_dropping_keys() {
    // Readable, so the empty-`kid` case reaches the check it is here for. Pointed at a missing file
    // it bails on the failed read instead, and would still pass with that check deleted.
    let readable = temp_file("obolus-token-malformed.pem", SYNTHETIC_PUBKEY_PEM);
    let empty_kid = format!(r#"[{{"file":"{readable}","kid":""}}]"#);

    // Each of these would otherwise arm fewer keys than the operator wrote — which is silent until
    // the missing key's tokens arrive.
    for raw in [
        "[]",
        "",
        r#"[{"kid":"alpha"}]"#,
        r#"[{"file":"/nope.pem","kid":"alpha"}]"#,
        empty_kid.as_str(),
    ] {
        let run = run(&[("OBOLUS_TOKEN_KEYS", raw), ("OBOLUS_TOKEN_ISSUER", TEST_ISSUER)]);

        run.must_say(BAILED);
        run.must_not_say(TOKEN_ENABLED);
    }
}

#[test]
fn a_configured_token_path_boots_and_says_which_verifier_it_wired() {
    // The wiring test, and the reason `main` derives this line from `Access::token_path()` rather
    // than from the local variable that built it. Dropping the verifier at the wiring site — a
    // one-line mutation that turns the entire feature off with the library suite green — removes
    // this banner, because there is no token path left to describe. Read the assertions as: the
    // verifier was built, it reached the access surface, and the access surface is what was routed.
    let key = temp_file("obolus-token-key.pem", SYNTHETIC_PUBKEY_PEM);
    let run = run(&[
        ("OBOLUS_TOKEN_PUBKEY_FILE", &key),
        ("OBOLUS_TOKEN_ISSUER", TEST_ISSUER),
    ]);

    run.must_have_got_past_startup();
    run.must_say(TOKEN_ENABLED);
    run.must_say(TEST_ISSUER); // the configured issuer, not a generic "enabled"
    // The default audience posture, stated rather than left to be inferred from silence.
    run.must_say("no audience configured");
    // And the 402 path is still live for everyone else — the whole reason this is a branch and not
    // a mode.
    run.must_say("still get the 402 challenge");
}

#[test]
fn a_configured_audience_is_named_in_the_banner() {
    // Discriminates the two audience postures at the banner, which is the operator's only view of
    // which one they are running: the paired assertion above says "no audience configured", so a
    // regression that printed one posture unconditionally fails one of the two.
    let key = temp_file("obolus-token-key-with-audience.pem", SYNTHETIC_PUBKEY_PEM);
    let run = run(&[
        ("OBOLUS_TOKEN_PUBKEY_FILE", &key),
        ("OBOLUS_TOKEN_ISSUER", TEST_ISSUER),
        ("OBOLUS_TOKEN_AUDIENCE", "obolus-test-audience"),
    ]);

    run.must_have_got_past_startup();
    run.must_say(TOKEN_ENABLED);
    run.must_say("audience obolus-test-audience");
    run.must_not_say("no audience configured");
}

#[test]
fn an_instance_with_no_token_configuration_announces_no_token_path() {
    // The default, and the fail-closed direction: absent `OBOLUS_TOKEN_PUBKEY_FILE` there is no
    // token path at all and every caller pays. Worth pinning because it is the negative half of the
    // shared `TOKEN_ENABLED` needle — without it, a banner that printed unconditionally would still
    // satisfy every positive assertion above.
    let run = run(&[("OBOLUS_NETWORK", TESTNET)]);

    run.must_have_got_past_startup();
    run.must_not_say(TOKEN_ENABLED);
}

#[test]
fn every_documented_variable_is_covered_by_the_prefix_sweep() {
    // The sweep is the mechanism and cannot drift; this only holds the documentation list honest,
    // so an entry that would NOT be cleared can never be listed as though it were. If `main` ever
    // grows a configuration variable outside the `OBOLUS_` namespace, this test cannot see it —
    // that is the residual, and the fix is to keep the namespace, not to reintroduce a hand-list.
    for var in OBOLUS_VARS {
        assert!(
            var.starts_with(OBOLUS_PREFIX),
            "{var:?} is documented as cleared but does not carry {OBOLUS_PREFIX:?}, so the sweep \
             in `run` never clears it"
        );
    }
}
