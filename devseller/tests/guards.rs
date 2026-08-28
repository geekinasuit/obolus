//! `main`'s startup refusals, exercised through the real `obolus-devseller` binary.
//!
//! # Why this exists as an exec test
//!
//! Every guard in `main` is unreachable from a unit test: `src/main.rs` is the binary's crate root,
//! and the checks it performs are statements in `main` rather than functions anything else calls.
//! Deleting the placeholder refusal, hardcoding `check_arming`'s `armed` to `true`, or moving
//! either below the advertisement banner all compile and leave the 30-test unit suite fully green.
//!
//! So these tests run the shipped binary and read its behaviour off stderr. That is the only
//! vantage point from which "the guard runs, and runs *before* anything is advertised" is a
//! checkable claim rather than an assertion in a comment.
//!
//! # Why it terminates
//!
//! Same device as `obolus`'s `server_arming` suite: the harness holds a loopback port open and
//! hands that address to the child, so every startup check and every banner runs to completion and
//! then `bind` fails. Termination is a property of the *last* line of startup, which is what makes
//! everything printed before it observable — including, deliberately, the lines a refused
//! configuration must NOT print.
//!
//! The non-loopback tests cannot use that trick, because the address under test is by definition
//! not the one the harness is holding. They use [`UNBINDABLE`] instead — see there.
//!
//! # Why it is hermetic
//!
//! Nothing dials anything. `OllamaUpstream::new` only parses its URL; the client is lazy and
//! connects on first request, which never happens because the process dies at bind. The upstream
//! URL below points at a discard port that is never contacted, and this binary has no facilitator
//! to reach — it verifies offline.

use std::net::TcpListener;
use std::process::Command;

/// The prefix every variable `main` reads shares. Every inherited variable carrying it is cleared
/// before each run — by sweep, not by a hand-maintained list, which would drift silently and in the
/// *unsafe* direction: a variable added to `main` but not to the list stays inherited.
const OBOLUS_PREFIX: &str = "OBOLUS_";

/// The variables `main` reads today. Documentation and a drift alarm, **not** the clearing
/// mechanism. Held honest by `every_documented_variable_is_covered_by_the_prefix_sweep`.
const OBOLUS_VARS: &[&str] = &[
    "OBOLUS_ADDR",
    "OBOLUS_UPSTREAM_URL",
    "OBOLUS_RESOURCE",
    "OBOLUS_DESCRIPTION",
    "OBOLUS_ACCEPTS",
    "OBOLUS_NETWORK",
    "OBOLUS_PRICE",
    "OBOLUS_PAY_TO",
    "OBOLUS_ASSET",
    "OBOLUS_ALLOW_MAINNET",
    "OBOLUS_DEV_VERIFY",
    "OBOLUS_DEV_REJECT_REASON",
    "OBOLUS_DEV_SETTLE",
    "OBOLUS_DEV_SETTLE_REASON",
    "OBOLUS_DEV_SETTLE_DELAY_SECS",
    "OBOLUS_DEV_TOKEN_NAME",
    "OBOLUS_DEV_TOKEN_VERSION",
    "OBOLUS_DEV_ALLOW_OPEN_PROXY",
];

/// Base mainnet — a real chain id, on no testnet allowlist. What `check_arming` exists to catch,
/// and what this binary refuses with no override available.
const MAINNET: &str = "eip155:8453";

/// Base Sepolia — the testnet this binary expects to run on.
const TESTNET: &str = "eip155:84532";

/// Obolus's own placeholder id, invented so no chain could match it. `is_provably_testnet` admits
/// it through a clause of its own, so `check_arming` passes it and the *second* guard is the only
/// thing that refuses it.
const PLACEHOLDER_NETWORK: &str = "test-network-not-a-real-caip2";

/// A syntactically valid 20-byte asset address for the runs that must get *past* startup: under
/// `verify` mode every advertised option has to yield an EIP-712 domain, and the built-in
/// placeholder asset is not hex.
///
/// The all-zero address deliberately — the EVM burn address, which is no token contract anywhere,
/// so nothing here resembles a real deployment. What it needs to be is parseable, not plausible.
const SYNTHETIC_ASSET: &str = "0x0000000000000000000000000000000000000000";

/// A syntactically valid recipient, for the same reason and with the same disclaimer as
/// [`SYNTHETIC_ASSET`]. The built-in placeholder `payTo` is not hex, and startup refuses it in every
/// verification mode because it is what a client has to name in the authorization it signs.
///
/// Deliberately a different value from [`SYNTHETIC_ASSET`]: if the two matched, code that compared
/// the wrong one of the pair would still pass every assertion here.
const SYNTHETIC_PAY_TO: &str = "0x000000000000000000000000000000000000dead";

/// The built-in `payTo`, which `obolus` boots on and this binary refuses. Not an address at all, so
/// the refusal is about being unpayable rather than about being the wrong recipient.
const PLACEHOLDER_PAY_TO: &str = "0xTEST-PAY-TO-ADDRESS-NOT-REAL";

/// Solana Devnet, one of the nine non-EVM testnets on Obolus's pinned allowlist. Its recipients are
/// base58 rather than 20-byte hex, which is why the `payTo` check is scoped to EVM options.
const SOLANA_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/// The built-in placeholder asset: not an address, so no EIP-712 domain can be built from it.
///
/// Load-bearing in two opposite directions. Under `verify` an option carrying it must refuse,
/// because the domain is what a signature would be checked against. On an **EVM** option under
/// `accept` it must *not* reach the recipient check — which is why
/// [`an_evm_option_is_still_checked_when_its_recipient_is_not_hex_shaped`] pairs it with a bad
/// recipient rather than using a decodable asset. Without that pairing, "the network is not EVM" and
/// "no domain can be built for this option" agree on every value in this file, so a recipient check
/// re-keyed to the asset holds the whole suite up while letting an unpayable EVM option advertise.
const UNVERIFIABLE_ASSET: &str = "0xTEST-ASSET-ADDRESS-NOT-REAL";

/// An address in RFC 5737's TEST-NET-1 documentation range, which is not assigned to any interface
/// on any host — so `bind` fails immediately with `EADDRNOTAVAIL`.
///
/// This is how the non-loopback tests terminate. The harness's occupied-port trick cannot serve
/// them: the whole point of those runs is an address other than the one the harness holds. Binding
/// `0.0.0.0` on the held port would *probably* also fail, but "probably" is the wrong property for
/// a test whose other outcome is a process that serves forever on every interface. An address that
/// cannot exist fails deterministically and exposes nothing on the way.
const UNBINDABLE: &str = "192.0.2.1:8404";

/// The line `main` prints immediately after the last guard and before anything else, so its
/// presence is the observable boundary between "refused during startup" and "got past startup".
///
/// The child's *exit status* cannot be that boundary: the harness deliberately makes `bind` fail,
/// so every run in this file exits non-zero whether it refused or booted. An `assert!(!exited_ok)`
/// would be true by construction and would keep passing with every guard deleted.
const PAST_STARTUP: &str = "starting on";

/// Every line `main` prints is prefixed; every `anyhow` bail is prefixed by the runtime. One of the
/// two must appear or the child never got as far as running `main` at all.
const STARTUP_LINE: &str = "obolus-devseller: ";
const BAILED: &str = "Error:";

/// The distinctive fragment of the advertisement line — what a refusal must not have printed first.
///
/// Not the bare word `advertising`, which also appears in the placeholder refusal's own text: a
/// negative assertion against that would be satisfied by unrelated wording rather than by the
/// property under test.
const ADVERTISEMENT_LINE: &str = "payment option(s)";

/// The non-loopback warning, asserted both present and absent below. One shared constant so the
/// negative cannot rot into an always-true pass while the positive keeps it honest.
const BEYOND_LOOPBACK: &str = "BOUND BEYOND LOOPBACK";

/// The open-proxy refusal's distinctive claim.
const OPEN_PROXY: &str = "this configuration is an open proxy";

struct Run {
    stderr: String,
}

impl Run {
    fn says(&self, needle: &str) -> bool {
        self.stderr.contains(needle)
    }

    /// Assert on the whole captured stderr, and print it when the assertion fails — a bare
    /// `assert!(run.says(..))` on a startup banner gives no clue which branch ran.
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

    /// A guard fired: the process never reached `bind`, and never advertised anything either.
    fn must_have_refused_during_startup(&self) {
        self.must_say(BAILED);
        self.must_not_say(PAST_STARTUP);
        self.must_not_say(ADVERTISEMENT_LINE);
    }

    /// The guards let this configuration through: the process reached `bind` (and then failed,
    /// which is how it terminated at all).
    fn must_have_got_past_startup(&self) {
        self.must_say(PAST_STARTUP);
    }
}

/// Run the real binary to completion with `vars` applied over the single-chain baseline.
///
/// The baseline is a configuration that gets past every guard, so any test that observes a refusal
/// is observing the effect of its own `vars` and not of an incidental gap in the setup.
fn run(vars: &[(&str, &str)]) -> Run {
    let mut all: Vec<(&str, &str)> = vec![
        ("OBOLUS_NETWORK", TESTNET),
        ("OBOLUS_ASSET", SYNTHETIC_ASSET),
        ("OBOLUS_PAY_TO", SYNTHETIC_PAY_TO),
    ];
    all.extend_from_slice(vars);
    exec(&all)
}

/// Run with an `OBOLUS_ACCEPTS` array and **no** single-chain baseline.
///
/// A separate entry point rather than one more override, because the two configuration doors are
/// mutually exclusive by design: `main` refuses a run that sets both rather than silently ignoring
/// one. A test that layered `OBOLUS_ACCEPTS` over the baseline would measure that refusal and never
/// reach the guard it claims to be about.
fn run_accepts(accepts: &str) -> Run {
    exec(&[("OBOLUS_ACCEPTS", accepts)])
}

/// The binary under test, located under whichever half of the dual build is running.
///
/// Bazel passes the path through the rule's `env`; cargo sets `CARGO_BIN_EXE_<bin>` at compile
/// time. `option_env!` rather than `env!` because the latter is a compile error under Bazel, where
/// cargo's variable does not exist.
fn binary() -> String {
    std::env::var("OBOLUS_DEVSELLER_BIN")
        .ok()
        .or_else(|| option_env!("CARGO_BIN_EXE_obolus-devseller").map(str::to_string))
        .expect(
            "no obolus-devseller binary to run: OBOLUS_DEVSELLER_BIN is unset (Bazel sets it from \
             the rule's env — see BUILD.bazel) and this was not built by cargo either",
        )
}

/// Strip every inherited `OBOLUS_*` variable, so what the developer happens to have exported cannot
/// change what these tests observe. By sweep rather than by list — see [`OBOLUS_PREFIX`].
fn without_ambient_config(cmd: &mut Command) {
    for (key, _) in std::env::vars() {
        if key.starts_with(OBOLUS_PREFIX) {
            cmd.env_remove(key);
        }
    }
}

fn exec(vars: &[(&str, &str)]) -> Run {
    // Occupy a loopback port and hand it to the child so that bind — the last statement of startup
    // — always fails. See the module docs.
    let occupied = TcpListener::bind("127.0.0.1:0").expect("occupy a loopback port");
    let addr = occupied.local_addr().expect("read back the occupied port");

    let mut cmd = Command::new(binary());
    without_ambient_config(&mut cmd);
    cmd.env("OBOLUS_ADDR", addr.to_string());
    for (key, value) in vars {
        cmd.env(key, value);
    }

    let output = cmd.output().expect("run the obolus-devseller binary");
    // Explicit, so the listener's lifetime is obviously the child's lifetime rather than an
    // artefact of where this function happens to end.
    drop(occupied);

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    // Forecloses the vacuous pass for every test in this file at once. Most assertions here are
    // `must_not_say`, and a child that produced no output at all — wrong binary path, a crash
    // before the first `eprintln!`, stderr not captured — satisfies all of them.
    assert!(
        !stderr.trim().is_empty(),
        "the binary produced no stderr; every assertion below would pass vacuously"
    );
    // Non-empty is necessary but weak. What it cannot distinguish is "the child ran `main` and
    // refused" from "the child never reached `main`": a bad runfiles path, a dyld failure, a panic
    // in a static initialiser. All three produce stderr, none of it recognisable, and all of it
    // satisfies every `must_not_say` here.
    assert!(
        stderr.contains(STARTUP_LINE) || stderr.contains(BAILED),
        "stderr contains neither a startup line nor a bail — the child probably never reached \
         `main`, so nothing below observes what it claims to; got:\n{stderr}"
    );

    Run { stderr }
}

/// Run `--help` and return stdout.
///
/// A runner of its own, because every assertion [`exec`] makes is inverted here. That one occupies
/// a port to force a *startup* run to terminate and then requires stderr to be non-empty; `--help`
/// must terminate without binding anything, exit zero, and say nothing on stderr at all.
///
/// No configuration is supplied, deliberately: answering with no configuration is the property.
fn help() -> String {
    let mut cmd = Command::new(binary());
    without_ambient_config(&mut cmd);
    let output = cmd.arg("--help").output().expect("run obolus-devseller --help");

    assert!(output.status.success(), "--help must exit 0; got {:?}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.is_empty(), "--help must print nothing to stderr; got:\n{stderr}");

    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// `--help` is answered before any configuration is read.
///
/// The ordering is the whole test. An unconfigured process falls through to the built-in
/// placeholder network and refuses to start, so a `--help` handled even a few statements later
/// answers a request for documentation with an unrelated startup refusal — which is exactly what
/// this binary did before it had one.
#[test]
fn help_is_answered_without_any_configuration() {
    let help = help();

    assert!(help.contains("USAGE"), "got:\n{help}");
    // The one thing this binary must never be mistaken for, stated in the place a stranger looks
    // first.
    assert!(help.contains("NOT A GATEWAY"), "got:\n{help}");
    assert!(!help.contains(PAST_STARTUP), "--help started a server; got:\n{help}");
    assert!(
        !help.contains(PLACEHOLDER_NETWORK),
        "--help was answered by the placeholder refusal rather than by usage; got:\n{help}"
    );
}

/// Every variable this binary reads is named in `--help`.
///
/// Drift runs one way here. A knob gets added to `main`, some test in this file goes red,
/// [`OBOLUS_VARS`] is updated to match — and the help text, which nothing was checking, quietly
/// stops describing the binary. Configuration is entirely by environment variable, so a variable
/// missing from `--help` is a variable nobody can find.
#[test]
fn the_help_text_names_every_variable_this_binary_reads() {
    let help = help();

    for var in OBOLUS_VARS {
        assert!(help.contains(var), "--help does not mention {var}; got:\n{help}");
    }
}

/// An unrecognised argument is refused rather than ignored, because every knob here is an
/// environment variable: `--port 9000` would otherwise take effect as silence, leaving the operator
/// believing they had configured something.
#[test]
fn an_unrecognised_argument_is_refused_by_name() {
    let mut cmd = Command::new(binary());
    without_ambient_config(&mut cmd);
    let output = cmd.args(["--port", "9000"]).output().expect("run obolus-devseller --port 9000");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Exit status is not the assertion. With the argument check deleted this run reaches the
    // placeholder network and exits non-zero anyway, so `!success` is true either way — the
    // observable difference is *which* refusal was printed.
    assert!(stderr.contains("unexpected argument"), "got:\n{stderr}");
    assert!(stderr.contains("--help"), "the refusal must point at --help; got:\n{stderr}");
    assert!(
        !stderr.contains(PLACEHOLDER_NETWORK),
        "the argument was ignored and startup ran on to the placeholder refusal; got:\n{stderr}"
    );
}

/// The positive control. Without it every refusal test below could pass on a binary that refuses
/// *everything*, which is the failure mode a suite of negatives cannot see.
#[test]
fn a_testnet_configuration_gets_past_startup() {
    let run = run(&[]);

    run.must_have_got_past_startup();
    run.must_say(ADVERTISEMENT_LINE);
    run.must_say(TESTNET);
    // The one thing this binary must never be mistaken for.
    run.must_say("NOT A GATEWAY");
    run.must_not_say(BEYOND_LOOPBACK);
}

#[test]
fn an_unarmed_mainnet_network_refuses_to_start() {
    let run = run(&[("OBOLUS_NETWORK", MAINNET)]);

    run.must_say("not on Obolus's pinned testnet allowlist");
    run.must_have_refused_during_startup();
}

/// The second guard, and the reason there are two: `check_arming` **admits** the placeholder
/// through a clause of its own, so this configuration passes the check above and would boot on a
/// network no client can pay and no verifier can build a domain for.
///
/// Deleting the explicit placeholder refusal leaves `an_unarmed_mainnet_network_refuses_to_start`
/// green — which is exactly why this is a separate test rather than another case in it.
#[test]
fn the_placeholder_network_refuses_to_start() {
    let run = run(&[("OBOLUS_NETWORK", PLACEHOLDER_NETWORK)]);

    run.must_say("refusing to start on the built-in placeholder network");
    // The refusal has to say what to do instead, or the operator's next move is to look for an
    // override that does not exist.
    run.must_say("eip155:84532");
    run.must_have_refused_during_startup();
}

/// The placeholder under `accept`, which is where the guard above is the **only** thing standing.
///
/// Under `verify` the startup domain check refuses the placeholder too, for its own reason — no
/// `eip155:` chain id, so no EIP-712 domain — which means the two tests above still refuse with the
/// placeholder guard deleted, just with a different message. They pin the wording; this pins the
/// behaviour. Switch verification off and the domain check does not run, and nothing but the
/// explicit refusal keeps this binary from booting on a network no client can pay.
#[test]
fn the_placeholder_network_refuses_even_when_nothing_verifies() {
    let run = run(&[("OBOLUS_NETWORK", PLACEHOLDER_NETWORK), ("OBOLUS_DEV_VERIFY", "accept")]);

    run.must_say("refusing to start on the built-in placeholder network");
    run.must_have_refused_during_startup();
}

/// The placeholder reached through `OBOLUS_ACCEPTS` alongside a perfectly good testnet — the
/// configuration where a guard written as "refuse if the *only* network is the placeholder" would
/// let it through.
#[test]
fn a_placeholder_hidden_among_good_networks_still_refuses() {
    let accepts = format!(
        r#"[
            {{"network":"{TESTNET}","asset":"{SYNTHETIC_ASSET}",
             "payTo":"{SYNTHETIC_PAY_TO}","maxAmountRequired":"1000"}},
            {{"network":"{PLACEHOLDER_NETWORK}","asset":"{SYNTHETIC_ASSET}",
             "payTo":"{SYNTHETIC_PAY_TO}","maxAmountRequired":"1000"}}
        ]"#
    );
    let run = run_accepts(&accepts);

    run.must_say("refusing to start on the built-in placeholder network");
    run.must_have_refused_during_startup();
}

/// Mainnet hidden between two testnets, which only `OBOLUS_ACCEPTS` can express.
#[test]
fn a_mainnet_hidden_among_testnets_refuses_to_start() {
    let accepts = format!(
        r#"[
            {{"network":"{TESTNET}","asset":"{SYNTHETIC_ASSET}",
             "payTo":"{SYNTHETIC_PAY_TO}","maxAmountRequired":"1000"}},
            {{"network":"{MAINNET}","asset":"{SYNTHETIC_ASSET}",
             "payTo":"{SYNTHETIC_PAY_TO}","maxAmountRequired":"1000"}}
        ]"#
    );
    let run = run_accepts(&accepts);

    run.must_say("not on Obolus's pinned testnet allowlist");
    run.must_have_refused_during_startup();
}

/// The override `obolus` has and this binary deliberately does not.
///
/// A flag that silently does nothing would be worse than one that is absent: an operator who sets
/// it believes they have armed something. So setting it is itself the refusal.
#[test]
fn the_arming_override_is_refused_rather_than_honoured() {
    // Set alongside a mainnet, which is what an operator reaching for this flag would be doing —
    // so the test measures the refusal on the configuration where honouring it would matter.
    let run = run(&[("OBOLUS_ALLOW_MAINNET", "1"), ("OBOLUS_NETWORK", MAINNET)]);

    run.must_say("this binary has no arming override");
    run.must_have_refused_during_startup();
}

/// Even with an otherwise perfect testnet configuration — so the refusal is attributable to the
/// flag itself and not to the network it was set alongside.
#[test]
fn the_arming_override_is_refused_even_on_a_testnet() {
    let run = run(&[("OBOLUS_ALLOW_MAINNET", "1")]);

    run.must_say("this binary has no arming override");
    run.must_have_refused_during_startup();
}

/// Under `verify` an advertised option that cannot yield an EIP-712 domain is a seller that will
/// reject every correct payment. Caught at startup, because at request time it reads to a client
/// author as "my signing is broken".
#[test]
fn an_unverifiable_asset_refuses_under_verify_mode() {
    // The built-in placeholder asset: not 20 bytes of hex, so no `verifyingContract` exists.
    let run = run(&[("OBOLUS_ASSET", UNVERIFIABLE_ASSET)]);

    run.must_say("OBOLUS_DEV_VERIFY=verify checks signatures offline");
    run.must_have_refused_during_startup();
}

/// ...and the same configuration boots under `accept`, which inspects nothing.
///
/// The discriminating half: without it the test above is equally satisfied by a binary that refuses
/// that asset unconditionally, and the claim being made is specifically that the check is tied to
/// verification being switched on.
#[test]
fn the_same_unverifiable_asset_is_fine_when_nothing_verifies() {
    let run = run(&[
        ("OBOLUS_ASSET", UNVERIFIABLE_ASSET),
        ("OBOLUS_DEV_VERIFY", "accept"),
    ]);

    run.must_have_got_past_startup();
}

/// The third mode runs through the binary too.
///
/// `reject` is one of the three behaviours [`USAGE`] documents, and every startup gate keyed on the
/// mode is a two-way comparison — so a sample containing only `verify` and `accept` cannot tell any
/// of them from its near neighbour. This is the third value, so the sample is no longer a proper
/// subset of the enum: `reject` verifies nothing, hence no domain check, and serves nothing, hence
/// no open-proxy exposure to refuse.
#[test]
fn the_refusing_mode_starts_and_announces_no_token_domain() {
    let run = run(&[
        ("OBOLUS_ASSET", UNVERIFIABLE_ASSET),
        ("OBOLUS_DEV_VERIFY", "reject"),
        ("OBOLUS_DEV_REJECT_REASON", "test-reject-reason-not-real"),
    ]);

    run.must_have_got_past_startup();
    run.must_not_say("EIP-712 token domain");
}

/// The advertised recipient has to be an address in EVERY mode — unlike the asset above, which only
/// has to be one when this binary is going to verify signatures against it.
///
/// This is the configuration a developer reaches by setting a network and forgetting
/// `OBOLUS_PAY_TO`, since the default is the built-in placeholder.
/// `obolus::config::validated_option` rejects only an *empty* `payTo`, and the placeholder is not
/// empty — it is simply not an address. Without this guard the binary boots and then rejects every
/// payment at request time, which a client author reads as their own signing being broken.
#[test]
fn an_unpayable_recipient_refuses_to_start() {
    let run = exec(&[
        ("OBOLUS_NETWORK", TESTNET),
        ("OBOLUS_ASSET", SYNTHETIC_ASSET),
        ("OBOLUS_PAY_TO", PLACEHOLDER_PAY_TO),
    ]);

    run.must_say("cannot use advertised payTo");
    run.must_have_refused_during_startup();
}

/// ...and under `accept` as well, which is the half that would rot first: nothing inspects a payment
/// in that mode, so nothing inside this binary would ever notice the recipient was unusable. The
/// client still cannot build an authorization naming it, which is whose problem it actually is.
#[test]
fn an_unpayable_recipient_refuses_even_when_nothing_verifies() {
    let run = exec(&[
        ("OBOLUS_NETWORK", TESTNET),
        ("OBOLUS_ASSET", SYNTHETIC_ASSET),
        ("OBOLUS_PAY_TO", PLACEHOLDER_PAY_TO),
        ("OBOLUS_DEV_VERIFY", "accept"),
    ]);

    run.must_say("cannot use advertised payTo");
    run.must_have_refused_during_startup();
}

/// The refusal names the recipient, not the asset.
///
/// Reporting both through one "unusable address" error is the tempting shortcut, and it is wrong in
/// a way that costs an operator real time: the asset's message explains itself by saying the asset
/// IS the EIP-712 `verifyingContract` — true there, false here — and sends the reader to inspect a
/// domain that is fine while the fault sits in a different variable.
#[test]
fn the_unpayable_recipient_refusal_does_not_blame_the_asset() {
    let run = exec(&[
        ("OBOLUS_NETWORK", TESTNET),
        ("OBOLUS_ASSET", SYNTHETIC_ASSET),
        ("OBOLUS_PAY_TO", PLACEHOLDER_PAY_TO),
    ]);

    // The positive first. Every other assertion here is a `must_not_say`, and a run that never
    // refused at all satisfies all of them — this test would then pass on exactly the binary the
    // two above exist to catch.
    run.must_say("cannot use advertised payTo");
    run.must_not_say("verifyingContract");
    run.must_not_say("advertised asset");
}

/// Set-but-empty is refused rather than silently taking the default — for the variables `main` reads
/// directly, not only the ones `config.rs` parses.
///
/// `OBOLUS_DEV_TOKEN_NAME` is the one worth pinning. An empty EIP-712 domain name is still a domain,
/// so verification would run and reject every correctly-signed payment while the startup banner
/// reported a token domain that looked configured — and the payer, who cannot see this side's
/// domain at all, has nothing to go on.
#[test]
fn a_set_but_empty_variable_is_refused_rather_than_defaulted() {
    let empty = run(&[("OBOLUS_DEV_TOKEN_NAME", "")]);
    empty.must_say("is set but empty");
    empty.must_have_refused_during_startup();

    // The discriminating half: unset still takes the default. Without it this passes on a binary
    // that refuses the variable outright, which is a different thing entirely.
    let defaulted = run(&[]);
    defaulted.must_have_got_past_startup();
}

/// The remedy names the door the operator actually used, and the refusal names which option failed.
///
/// The two configuration doors are mutually exclusive — setting `OBOLUS_PAY_TO` while
/// `OBOLUS_ACCEPTS` is set is itself a startup refusal — so advice to set that variable, given to
/// somebody who configured an array, is a closed loop: following it verbatim produces a second
/// refusal, and neither message names the thing that would actually fix it.
///
/// The array here has three entries with the middle one bad, because an array is where the position
/// is worth printing: with several similar-looking recipients the offending value alone does not say
/// which line to edit, and `PaymentRequirements` carries no other printed field to locate it by.
#[test]
fn the_unpayable_recipient_remedy_matches_the_configuration_door() {
    let good = format!(
        r#"{{"network":"{TESTNET}","asset":"{SYNTHETIC_ASSET}",
            "payTo":"{SYNTHETIC_PAY_TO}","maxAmountRequired":"1000"}}"#
    );
    let bad = format!(
        r#"{{"network":"{TESTNET}","asset":"{SYNTHETIC_ASSET}",
            "payTo":"{PLACEHOLDER_PAY_TO}","maxAmountRequired":"1000"}}"#
    );
    let via_array = run_accepts(&format!("[{good},{bad},{good}]"));

    via_array.must_say("cannot use advertised payTo");
    via_array.must_say("option 2 of 3");
    via_array.must_say(r#"payTo" key"#);
    via_array.must_not_say("Set OBOLUS_PAY_TO");
    // The contrast with `obolus` explains a *default* an unset variable falls back to. An array
    // entry has no default — the value is what the operator typed — so the explanation would be
    // describing a mechanism that did not produce it.
    via_array.must_not_say("boots on the built-in placeholder");
    via_array.must_have_refused_during_startup();

    // The discriminating half: the single-chain door does get pointed at the variable, and does get
    // the contrast that explains where the value came from. Without asserting both are *present*
    // here, the two `must_not_say`s above are satisfied by a message that says neither anywhere.
    let via_variables = run(&[("OBOLUS_PAY_TO", PLACEHOLDER_PAY_TO)]);
    via_variables.must_say("Set OBOLUS_PAY_TO");
    via_variables.must_say("boots on the built-in placeholder");
    via_variables.must_say("option 1 of 1");

    // A single-entry array, which is what somebody writes on the way to a multi-chain configuration.
    // Without it, "came through OBOLUS_ACCEPTS" and "advertises more than one option" are perfectly
    // confounded across this whole file, and a remedy keyed on the option count would read as
    // correct while sending single-entry-array users into the closed loop this test exists for.
    let via_one_entry_array = run_accepts(&format!("[{bad}]"));
    via_one_entry_array.must_say(r#"payTo" key"#);
    via_one_entry_array.must_not_say("Set OBOLUS_PAY_TO");
    via_one_entry_array.must_say("option 1 of 1");
}

/// The built-in placeholder recipient is refused on a network whose recipients cannot be inspected.
///
/// The shape check cannot reach this: it declines to judge a base58 recipient, correctly, and this
/// value is not one. But it is a constant this binary declares, so recognising it needs no address
/// format at all — and a non-EVM network is precisely where `OBOLUS_PAY_TO` is easiest to leave
/// unset, since none of the other guards on the way there mention it.
#[test]
fn the_placeholder_recipient_refuses_on_a_network_whose_shape_cannot_be_checked() {
    let run = exec(&[
        ("OBOLUS_NETWORK", SOLANA_DEVNET),
        ("OBOLUS_ASSET", "SOLANA-TEST-ASSET-NOT-REAL"),
        ("OBOLUS_PAY_TO", PLACEHOLDER_PAY_TO),
        ("OBOLUS_DEV_VERIFY", "accept"),
    ]);

    run.must_say("built-in placeholder recipient");
    run.must_have_refused_during_startup();
}

/// An EVM option is checked on the strength of its *network*, not of its recipient's shape.
///
/// The pair with [`a_non_evm_testnet_is_not_refused_for_its_recipient_shape`] is the point: this is
/// the configuration where "exempt because the network is not EVM" and the exemptions it correlates
/// with give different answers. Every other value in this file makes them agree, so without this
/// case a check keyed on any of those correlates holds the whole suite up while letting an unpayable
/// EVM option advertise.
///
/// Two correlates, so two deliberate choices here rather than one. The recipient is not `0x`-shaped,
/// which separates the network from the recipient. The asset is [`UNVERIFIABLE_ASSET`], which
/// separates the network from whether an EIP-712 domain can be built — and that one is worth
/// spelling out, because `domain_for` is live thirty lines further down `main`, so re-keying to it
/// is an ordinary refactor rather than a contrived edit.
#[test]
fn an_evm_option_is_still_checked_when_its_recipient_is_not_hex_shaped() {
    let run = exec(&[
        ("OBOLUS_NETWORK", TESTNET),
        ("OBOLUS_ASSET", UNVERIFIABLE_ASSET),
        ("OBOLUS_PAY_TO", "TEST-PAY-TO-WITH-NO-HEX-PREFIX"),
        ("OBOLUS_DEV_VERIFY", "accept"),
    ]);

    run.must_say("cannot use advertised payTo");
    run.must_have_refused_during_startup();
}

/// A non-EVM testnet still boots, recipient shape and all.
///
/// Obolus's pinned allowlist admits nine of them and their recipients are not 20-byte hex, so a
/// `payTo` check that ran on every advertised option would refuse configurations this binary can
/// legitimately serve under `accept`. Neither value below is valid base58 — deliberately, since the
/// property under test is that nothing here inspects a non-EVM recipient at all.
#[test]
fn a_non_evm_testnet_is_not_refused_for_its_recipient_shape() {
    let run = exec(&[
        ("OBOLUS_NETWORK", SOLANA_DEVNET),
        ("OBOLUS_ASSET", "SOLANA-TEST-ASSET-NOT-REAL"),
        ("OBOLUS_PAY_TO", "SOLANA-TEST-PAY-TO-NOT-REAL"),
        ("OBOLUS_DEV_VERIFY", "accept"),
    ]);

    run.must_have_got_past_startup();
    run.must_not_say("cannot use advertised payTo");
}

/// An upstream URL the client cannot speak to is refused at startup, not at the first request.
///
/// `https://` rather than some arbitrary non-URL, because it is both the mistake an operator
/// actually makes and the value that discriminates the check from its nearest correct-looking
/// relative: `"https://…"` contains `http`, so a guard keyed on containment rather than on the
/// scheme prefix accepts it and the refusal moves to request time, where a client author reads a
/// dead upstream as their own payment failing.
#[test]
fn an_upstream_url_that_is_not_plain_http_refuses_to_start() {
    let run = run(&[("OBOLUS_UPSTREAM_URL", "https://127.0.0.1:9")]);

    run.must_say("must be an http:// origin");
    // The remedy matters as much as the refusal: an operator who only wanted to test payments does
    // not need an upstream at all, and nothing else says so.
    run.must_say("Unset it to serve a canned response");
    run.must_have_refused_during_startup();
}

/// The hazard publishing this binary creates: accept-mode, plus a real upstream, plus an address
/// anyone can reach is an unauthenticated open proxy to somebody's inference endpoint.
#[test]
fn an_open_proxy_configuration_refuses_to_start() {
    let run = run(&[
        ("OBOLUS_ADDR", UNBINDABLE),
        ("OBOLUS_DEV_VERIFY", "accept"),
        ("OBOLUS_UPSTREAM_URL", "http://127.0.0.1:9"),
    ]);

    run.must_say(OPEN_PROXY);
    // The refusal must offer the way to do what the operator wanted, or they reach for the
    // acknowledgement variable instead of the port forward.
    run.must_say("adb reverse");
    run.must_have_refused_during_startup();
}

/// The refusal must not offer `verify` as the way out.
///
/// It is the natural thing to suggest and it is false. `verify` checks a signature over a payer
/// address the caller chooses, against no balance and no record of spent nonces, and nothing here
/// ever settles — so a throwaway keypair satisfies it as easily as a funded one. An operator who
/// took that advice would believe they had closed the hole while leaving it open, which is worse
/// than the refusal they were trying to get past.
#[test]
fn the_open_proxy_refusal_does_not_offer_verification_as_the_fix() {
    let run = run(&[
        ("OBOLUS_ADDR", UNBINDABLE),
        ("OBOLUS_DEV_VERIFY", "accept"),
        ("OBOLUS_UPSTREAM_URL", "http://127.0.0.1:9"),
    ]);

    run.must_say(OPEN_PROXY);
    run.must_say("NOT a fix for this");
    run.must_say("throwaway keypair");
}

/// Each leg of the triple, dropped one at a time. Every one of these is a configuration that is
/// *not* an open proxy, and all three must boot — otherwise the guard above is some blanket
/// non-loopback refusal wearing the open-proxy message, and its wording is a lie.
#[test]
fn dropping_any_leg_of_the_open_proxy_triple_is_not_refused() {
    // Not loopback, accept-mode — but the canned upstream, so there is no inference to steal.
    let canned = run(&[("OBOLUS_ADDR", UNBINDABLE), ("OBOLUS_DEV_VERIFY", "accept")]);
    canned.must_have_got_past_startup();
    canned.must_not_say(OPEN_PROXY);

    // Not loopback, real upstream, under `verify`. Outside the refused triple deliberately — a
    // client running on another device has to be able to reach a verifying seller at all — but NOT
    // therefore safe: `verify` checks a signature over a payer address the caller chooses, against
    // no balance and no record of spent nonces, and nothing here settles, so a throwaway keypair
    // satisfies it. The warning is the whole of what protects this case, so assert it fires.
    let verifying = run(&[
        ("OBOLUS_ADDR", UNBINDABLE),
        ("OBOLUS_UPSTREAM_URL", "http://127.0.0.1:9"),
    ]);
    verifying.must_have_got_past_startup();
    verifying.must_not_say(OPEN_PROXY);
    verifying.must_say(BEYOND_LOOPBACK);

    // Accept-mode, real upstream — but only reachable from this machine. The default bind, and the
    // configuration the guard's own error message recommends.
    let loopback = run(&[
        ("OBOLUS_DEV_VERIFY", "accept"),
        ("OBOLUS_UPSTREAM_URL", "http://127.0.0.1:9"),
    ]);
    loopback.must_have_got_past_startup();
    loopback.must_not_say(OPEN_PROXY);
    loopback.must_not_say(BEYOND_LOOPBACK);

    // The third mode, on the two legs that would otherwise compose. `reject` serves nobody, so this
    // is not an open proxy and must boot — and it is what tells the accept-leg apart from
    // `!= verify`, which the two other legs above cannot do because neither of them is `reject`.
    let refusing = run(&[
        ("OBOLUS_ADDR", UNBINDABLE),
        ("OBOLUS_DEV_VERIFY", "reject"),
        ("OBOLUS_UPSTREAM_URL", "http://127.0.0.1:9"),
    ]);
    refusing.must_have_got_past_startup();
    refusing.must_not_say(OPEN_PROXY);
    refusing.must_say(BEYOND_LOOPBACK);
}

/// The acknowledgement turns the refusal off — and the run that follows still says, loudly, what it
/// is. An operator who acknowledged the hazard once should not have to remember it afterwards.
#[test]
fn the_open_proxy_refusal_can_be_acknowledged() {
    let run = run(&[
        ("OBOLUS_ADDR", UNBINDABLE),
        ("OBOLUS_DEV_VERIFY", "accept"),
        ("OBOLUS_UPSTREAM_URL", "http://127.0.0.1:9"),
        ("OBOLUS_DEV_ALLOW_OPEN_PROXY", "1"),
    ]);

    run.must_have_got_past_startup();
    run.must_not_say(OPEN_PROXY);
    run.must_say(BEYOND_LOOPBACK);
}

/// Anything other than exactly `"1"` leaves the refusal armed — the safe direction for a typo, and
/// the same convention `OBOLUS_ALLOW_MAINNET` uses in `obolus`.
#[test]
fn a_misspelled_acknowledgement_does_not_arm_anything() {
    for value in ["true", "yes", "0", "", "1 "] {
        let run = run(&[
            ("OBOLUS_ADDR", UNBINDABLE),
            ("OBOLUS_DEV_VERIFY", "accept"),
            ("OBOLUS_UPSTREAM_URL", "http://127.0.0.1:9"),
            ("OBOLUS_DEV_ALLOW_OPEN_PROXY", value),
        ]);

        run.must_say(OPEN_PROXY);
        run.must_have_refused_during_startup();
    }
}

/// A misconfigured behaviour knob is refused at startup rather than defaulted, and the refusal
/// names the choices — the operator cannot see the valid set from anywhere else.
#[test]
fn an_unknown_behaviour_mode_refuses_and_names_the_choices() {
    let run = run(&[("OBOLUS_DEV_SETTLE", "explode")]);

    run.must_say("is not a settlement outcome");
    run.must_say("succeed");
    run.must_have_refused_during_startup();
}

/// The banner has to say which token domain it is verifying under, because x402 does not carry
/// `name`/`version` (#13) and a wrong one rejects every correctly-signed payment with a
/// message about signature recovery. The payer cannot see it from their side at all.
#[test]
fn the_startup_banner_names_the_eip712_token_domain() {
    let run = run(&[("OBOLUS_DEV_TOKEN_NAME", "USD Coin")]);

    run.must_have_got_past_startup();
    run.must_say("EIP-712 token domain");
    run.must_say("USD Coin");
}

/// Under `accept` nothing is verified, so there is no domain to report — and printing one would
/// describe a check that is not running.
#[test]
fn the_token_domain_is_not_announced_when_nothing_verifies() {
    let run = run(&[("OBOLUS_DEV_VERIFY", "accept")]);

    run.must_have_got_past_startup();
    run.must_not_say("EIP-712 token domain");
}

/// The drift alarm for [`OBOLUS_VARS`]. The list is documentation; [`OBOLUS_PREFIX`] does the
/// clearing. This fails if someone adds a variable to `main` under a different prefix, which would
/// leave it inherited from the developer's shell and make these tests non-deterministic.
#[test]
fn every_documented_variable_is_covered_by_the_prefix_sweep() {
    for var in OBOLUS_VARS {
        assert!(
            var.starts_with(OBOLUS_PREFIX),
            "{var} does not start with {OBOLUS_PREFIX:?}, so the sweep in `run` never clears it \
             and an ambient value would leak into every test in this file"
        );
    }
}
