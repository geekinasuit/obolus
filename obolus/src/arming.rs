//! The startup arming guard: refuse to advertise a network we cannot prove is testnet.
//!
//! Obolus never signs anything — it issues a 402 challenge and delegates verify/settle to a
//! facilitator. But **the challenge it advertises is the real-money trigger**: a cooperating client
//! reads the `(network, asset, pay-to)` out of the 402 body and pays against it. So "could this
//! gateway cause real money to move?" is answered by *what it advertises*, not by whether it holds a
//! key. This module sits on the only thing Obolus controls — the contents of the `accepts` array.
//!
//! # Fail-closed, by allowlist
//!
//! [`TESTNET_NETWORKS`] lists networks that are *provably* testnet. Anything not on it — a mainnet
//! id, a typo, or a testnet x402 added after this list was pinned — is **not provably testnet** and
//! refuses to boot unless the operator explicitly arms the instance. An allowlist rather than a
//! mainnet denylist is the whole point: a network nobody anticipated fails closed instead of sailing
//! through.
//!
//! The flag's name (`OBOLUS_ALLOW_MAINNET`, read in `main`) under-describes what it gates — the
//! predicate is *not provably testnet*, and mainnet is only its most important instance.
//!
//! # Arming names its target
//!
//! The override is not a boolean. `OBOLUS_ALLOW_MAINNET` lists the exact network ids being armed,
//! comma-separated, and [`check_arming`] admits an unproven network only if the value names it —
//! byte-exactly, the same comparison the allowlist makes, so a typo in the arming value fails closed
//! rather than widening it. The value must also name nothing else: an id the gateway does not
//! advertise, or one already on the allowlist, is refused rather than ignored. So the environment
//! can only ever describe exactly what it arms, and an operator reading
//! `OBOLUS_ALLOW_MAINNET=eip155:8453` learns which chain this instance is for. The boolean form
//! (`=1`) admitted every advertised option at once — a typo two entries below the intended mainnet
//! included — and survived every later edit to the network set; it is retired, and refused with a
//! pointer to this form (#28).
//!
//! # When a new testnet shows up
//!
//! Add it to [`TESTNET_NETWORKS`] — a reviewed code change, in the open. Do **not** reach for the
//! arming flag to run on a genuine testnet: an operator who sets `OBOLUS_ALLOW_MAINNET` as routine
//! ceremony has already lost the protection it exists to give.
//!
//! # Why the comparison is byte-exact
//!
//! Network ids are compared verbatim — no trimming, no case folding — so that what this guard checks
//! is byte-identical to what the gateway advertises. A case- or whitespace-variant of a testnet id
//! is therefore *not* on the allowlist and fails closed, which is the safe direction. Normalising
//! input belongs upstream at [`config::validated_option`](crate::config::validated_option), the
//! single per-option seam **both** configuration forms go through, so canonicalising there cannot
//! leave one path raw (#14).
//!
//! # Diagnosis is not admission
//!
//! Nothing in [`diagnose`] can let a network through; it only lets the refusal name the *true*
//! cause. That matters because this guard's real protection is the operator **not** reaching for the
//! flag, and a refusal whose stated causes are all visibly false is what makes the flag look like the
//! answer.

use crate::x402::PaymentRequirements;

/// The default `network` when an operator has configured none: deliberately not a real CAIP-2 id, so
/// that if it ever reached a chain it would fail there rather than pay a stranger.
///
/// It lives here, next to the guard that must admit it, rather than in `main`: a gateway whose own
/// default refused to boot un-armed would teach every new operator to set the arming flag before
/// they had configured anything. [`is_provably_testnet`] accepts it through a clause of its own; it
/// is deliberately absent from [`TESTNET_NETWORKS`], which stays a 1:1 mirror of the x402 source.
pub const PLACEHOLDER_NETWORK: &str = "test-network-not-a-real-caip2";

/// The date [`TESTNET_NETWORKS`] was transcribed from the x402 source.
///
/// A const rather than a comment because it is interpolated into the refusal and the armed banner. A
/// stale snapshot is the likeliest reason this guard ever fires wrongly, and it is the one cause
/// where the operator is **right** and the guard is wrong — so the age has to be legible at the
/// moment they are deciding whether to arm.
pub const PINNED_ON: &str = "2026-07-29";

/// Networks that are provably testnet, in x402's CAIP-2 (`namespace:reference`) form.
///
/// Pinned 2026-07-29 from the x402 primary source — <https://docs.x402.org/core-concepts/network-and-token-support>
/// — which states that "x402 uses CAIP-2 standard network identifiers (`namespace:reference`) for
/// unambiguous cross-chain support", and lists every network in that form. This is every network
/// that source marks as a testnet, not just the two Obolus expects to use: a shorter list would
/// force an operator on some other genuine testnet to set the mainnet arming flag, which is
/// precisely the habit this guard must not create.
///
/// Short names (`base-sepolia`) are **not** admitted, deliberately. x402's v1 spec examples still
/// use them, so an operator can plausibly copy one out of primary documentation — hence
/// [`is_not_caip2`] gives them a clause of their own rather than the generic three-cause text, all
/// three causes of which are false for a short name.
///
/// A **snapshot and nothing but a transcription** of that source, so re-verifying it is a mechanical
/// line-for-line diff. When x402 adds a testnet, add it here (see the module docs).
///
/// **Undetectable staleness case, recorded rather than implied away:** if x402 ever *re-points an
/// existing identifier* at a different chain, this list keeps asserting the old truth and the guard
/// keeps admitting the id. A rename or a new chain shows up as a diff against the source; a silently
/// reassigned reference does not, and fail-closed cannot help because the id still matches.
/// Re-reading the source is the only detection — mechanised by #29.
pub const TESTNET_NETWORKS: &[&str] = &[
    // EVM (eip155:<chain id>)
    "eip155:84532",  // Base Sepolia
    "eip155:421614", // Arbitrum Sepolia
    "eip155:2201",   // Stable Testnet
    "eip155:31611",  // Mezo Testnet
    "eip155:72344",  // Radius Testnet
    "eip155:181228", // HPP Sepolia
    "eip155:51",     // XDC Apothem Testnet
    // Non-EVM. Solana's reference is a base58 genesis hash and is case-SENSITIVE — see the module
    // docs on why nothing here is case-folded.
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", // Solana Devnet
    "tvm:-3",                                  // TON Testnet
    "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe", // Algorand Testnet
    "stellar:testnet",                         // Stellar Testnet
    "aptos:2",                                 // Aptos Testnet
    "hedera:testnet",                          // Hedera Testnet
    "keeta:1413829460",                        // Keeta Testnet
    "near:testnet",                            // NEAR Testnet
    "xrpl:1",                                  // XRPL Testnet
];

/// Byte-exact comparison failed — is `network` merely a whitespace- or case-variant of something the
/// allowlist admits?
///
/// The commonest real cause is a trailing space out of a `.env` file or a docker-compose block
/// scalar, for which the generic three causes — mainnet, typo, too-new — are all visibly false to an
/// operator who knows they are on Base Sepolia. Arming does not help either: the flag suppresses the
/// refusal without repairing the id, so the gateway comes up armed, prints a MAINNET banner against
/// what is really Base Sepolia plus a space, and advertises that value verbatim.
///
/// **Searches the allowlist only.** A variant of [`PLACEHOLDER_NETWORK`] must not match here — it
/// would tell the operator the id "differs from an allowlisted id" two lines under a header saying
/// it is not on the allowlist — and it needs opposite advice; see [`is_placeholder_variant`].
fn near_miss(network: &str) -> Option<&'static str> {
    let trimmed = network.trim();
    TESTNET_NETWORKS
        .iter()
        .find(|admitted| trimmed == **admitted || trimmed.eq_ignore_ascii_case(**admitted))
        .copied()
}

/// Is `network` a whitespace- or case-variant of Obolus's own [`PLACEHOLDER_NETWORK`] rather than of
/// anything on the allowlist?
///
/// Needs the **opposite** advice to [`near_miss`]. "Fix the value" followed literally — delete the
/// stray character — lands on `UNCONFIGURED NETWORK`: a gateway advertising a network Obolus
/// invented precisely so that no chain could match it. The remedy is to unset the variable or set a
/// real testnet id, not to repair the placeholder.
///
/// Not exotic: it is the documented default plus one character, on the default configuration path
/// the README quickstart uses. The upper-case form reaches it too. The byte-exact placeholder is
/// admitted by [`is_provably_testnet`] and never gets here; a variant of it is still refused.
fn is_placeholder_variant(network: &str) -> bool {
    let trimmed = network.trim();
    trimmed == PLACEHOLDER_NETWORK || trimmed.eq_ignore_ascii_case(PLACEHOLDER_NETWORK)
}

/// Render a network id the way a refusal has to: quoted, **and** with every non-ASCII character
/// escaped.
///
/// `{:?}` does only half the job. The quotes are load-bearing — they are what makes a trailing space
/// legible at all — but `Debug for str` escapes via `escape_debug`, which leaves *printable*
/// non-ASCII alone, rendering U+00A0 as an ordinary space and Cyrillic 'е' (U+0435) as 'e': exactly
/// the two characters an operator most needs to see. `escape_default` escapes those as `\u{...}`.
///
/// Every offender list in this crate — the refusal here and the MAINNET ARMED banner in `main.rs` —
/// goes through this one function, so the format cannot be legible in one message and lying in the
/// next.
pub fn legible(network: &str) -> String {
    format!("\"{}\"", network.escape_default())
}

/// Not byte-exact, and not a whitespace- or case-variant either — does `network` carry non-ASCII
/// characters that *render* as ASCII ones?
///
/// An id pasted out of a web page or chat client can carry a homoglyph — Cyrillic `е` (U+0435) for
/// ASCII `e` is the classic. The allowlist comparison fails correctly, but the id *looks* exactly
/// like the one the operator configured, so every generic cause reads as false.
///
/// **This clause and [`near_miss`] are not alternatives; the caller must run both.** A *substituted*
/// homoglyph is invisible to `near_miss` (`eq_ignore_ascii_case` folds only ASCII, so a multi-byte
/// character never matches a one-byte one); an *added* non-ASCII space is the opposite case, since
/// `str::trim` is Unicode-aware, so `near_miss` reports an exact hit while saying nothing about the
/// character that actually broke the comparison.
fn is_non_ascii(network: &str) -> bool {
    !network.is_ascii()
}

/// Is `network` not a CAIP-2 identifier at all — that is, an x402 *short name* like `base-sepolia`?
///
/// x402's v1 spec examples still carry `"network":"base-sepolia"` (see the `SPEC_SETTLE_*` fixtures
/// in `facilitator.rs`), so this is a value copied *from primary documentation* and refused.
/// [`near_miss`] cannot help — a short name is not a whitespace- or case-variant of any CAIP-2 id.
///
/// Structural, not a lookup table: a CAIP-2 id is `namespace:reference`, so no colon means not
/// CAIP-2. A short-name→CAIP-2 mapping would be a second thing to keep in sync with x402, and
/// belongs to the canonicalisation work anyway (#14).
///
/// **Three deliberate non-firings**, each because the short-name story would be *false* for it: a
/// malformed CAIP-2 attempt (`eip155:`, `:84532`) has a colon and the generic text is not misleading
/// for it; an empty value is not a short name ([`is_empty_value`]); and a variant of
/// [`PLACEHOLDER_NETWORK`] has no colon either, but calling Obolus's own default "an x402 short
/// name" is a false diagnosis one value over ([`is_placeholder_variant`]).
fn is_not_caip2(network: &str) -> bool {
    !network.trim().is_empty() && !is_placeholder_variant(network) && !network.contains(':')
}

/// Is `network` empty or whitespace-only — a variable that was set and carries nothing?
///
/// An unexpanded `${NETWORK}` in a compose file, an `EnvironmentFile` line ending in `=`, an empty
/// ConfigMap key: the id never arrived, and no other clause can say so.
///
/// **Unreachable from `main`, and kept anyway.** Both configuration paths go through
/// [`validated_option`](crate::config::validated_option), which rejects an empty network with the
/// same `trim().is_empty()` test. This clause is for [`check_arming`]'s *other* callers — every
/// `Gateway` is built through it, and a library consumer assembling requirements by hand gets no
/// upstream validation at all. A diagnosis that is only correct because of what some other module
/// happens to check is not a property of this one.
fn is_empty_value(network: &str) -> bool {
    network.trim().is_empty()
}

/// The gateway was asked to advertise at least one network it cannot prove is testnet, and was not
/// armed. Names every offender, not just the first: an operator fixing a multi-chain `OBOLUS_ACCEPTS`
/// one error per restart is an operator who eventually reaches for the flag.
///
/// Offenders are rendered through [`legible`], not bare, so that trailing whitespace — the commonest
/// cause, and invisible in every other line of the startup output — is actually legible in the one
/// message whose job is to explain the refusal, and so that a non-ASCII lookalike does not survive
/// the rendering intact.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error(
    "refusing to advertise {} network(s) not on Obolus's pinned testnet allowlist: {}.{}\n\
     Each is either a mainnet, a typo, or a testnet added to x402 after this build — and this \
     allowlist is a snapshot pinned {}, so a genuine testnet newer than that date lands here too. \
     Obolus holds no key, but the 402 challenge it advertises is what a real client pays against, \
     so it will not offer an unproven network by accident. Fix the network id, or — if it is \
     genuinely testnet — add it to TESTNET_NETWORKS in a reviewed change. Do NOT reach for \
     OBOLUS_ALLOW_MAINNET to run on a genuine testnet: that makes this gateway indistinguishable \
     from a mainnet one in its own logs. {}",
    .networks.len(),
    .networks.iter().map(|n| legible(n)).collect::<Vec<_>>().join(", "),
    .diagnosis,
    PINNED_ON,
    arming_remedy(.armed)
)]
pub struct NotProvablyTestnet {
    /// The offending network ids: distinct, in the order they are first advertised, and none of
    /// them named by the arming value.
    pub networks: Vec<String>,
    /// The ids the arming value already names — every one of them advertised and unproven, because
    /// [`ArmingMismatch`] is checked first. Chooses the remedy's wording: "set the variable to" when
    /// empty, "add to it" when not, so that following the text literally never drops an id that
    /// was already armed.
    pub armed: Vec<String>,
    /// Newline-separated bullets naming the true cause; empty when no offender has one. Rendered
    /// *before* the generic three-cause text, which it supersedes when it fires.
    ///
    /// One bullet per *kind*, listing every offender that carries it. **All** applicable kinds are
    /// emitted, never the first that matches — they overlap in both directions (a trailing U+00A0 is
    /// both a near-miss and non-ASCII; a short name with a homoglyph is both non-CAIP-2 and
    /// non-ASCII) and each names a different thing to fix. Suppressing later kinds is an easy defect
    /// to reintroduce, so [`diagnose`] runs independent passes, and each overlap direction has a
    /// regression test that names it: `a_non_ascii_space_is_both_a_near_miss_and_escaped` for the
    /// near-miss/non-ASCII direction, `a_short_name_carrying_a_homoglyph_gets_both_clauses` for the
    /// non-CAIP-2/non-ASCII one. Both assert two clauses fire on a single offender.
    pub diagnosis: String,
}

/// The refusal's closing remedy — how to arm the offenders above, phrased so that following it
/// literally cannot drop an id the value already names.
fn arming_remedy(armed: &[String]) -> String {
    if armed.is_empty() {
        "To advertise anyway, set OBOLUS_ALLOW_MAINNET to exactly the id(s) above, comma-separated \
         and nothing else — arming names its target, and a value naming anything else refuses to \
         start too. Real funds can then move against this gateway's challenge."
            .to_string()
    } else {
        format!(
            "To advertise anyway, add the id(s) above to OBOLUS_ALLOW_MAINNET, which already names \
             {}. Real funds can then move against this gateway's challenge.",
            armed.iter().map(|n| legible(n)).collect::<Vec<_>>().join(", ")
        )
    }
}

/// One rendered group of an [`ArmingMismatch`]: empty when the group is, else `lead` followed by
/// the quoted ids and a full stop, so a group with nothing in it leaves no dangling sentence.
fn mismatch_group(lead: &str, ids: &[String]) -> String {
    if ids.is_empty() {
        return String::new();
    }
    format!("{lead}{}.", ids.iter().map(|n| legible(n)).collect::<Vec<_>>().join(", "))
}

/// The quoted ids, or `none` when there are none — for the sentences that must still read when a
/// list is empty.
fn ids_or(ids: &[String], none: &str) -> String {
    if ids.is_empty() {
        return none.to_string();
    }
    ids.iter().map(|n| legible(n)).collect::<Vec<_>>().join(", ")
}

/// The one restart's worth of prescription an [`ArmingMismatch`] closes with: the exact value
/// that would start this configuration, or the instruction to unset when nothing advertised is
/// unproven. Both facts are known at the refusal; withholding them costs the operator a second
/// restart to learn what the first already knew.
fn arming_prescription(unproven: &[String]) -> String {
    match unproven {
        [] => "Here nothing is: unset the variable.".to_string(),
        [only] => format!("Here that is {}.", legible(only)),
        // The quoted list is for reading — it makes a stray byte visible — but it is not the value:
        // copied with its separators it would arm `" eip155:1"`. So the value is spelled out too,
        // exactly as it goes into the environment.
        many => format!(
            "Here that is {} (as one value: OBOLUS_ALLOW_MAINNET={}).",
            ids_or(many, ""),
            many.join(",")
        ),
    }
}

/// The arming value named something this gateway cannot arm.
///
/// Arming names its target, so the value must list exactly the advertised networks that are not
/// provably testnet — nothing more. An entry naming a network the gateway does not advertise, or
/// one already on the allowlist, is not inert: it is a value that has drifted from the
/// configuration it was written for, which is the sticky-flag failure the boolean form was retired
/// over (#28). Refused by name rather than reported as "set but changed nothing", so the environment
/// can only ever describe what it is arming.
///
/// Checked **before** [`NotProvablyTestnet`], so an arming value that is wrong about itself is
/// reported as that — an operator who typed `eip155:8543` for `eip155:8453` is told the value names
/// an unadvertised id, not that their mainnet is unproven with a remedy of setting the value they
/// believe they already set.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error(
    "OBOLUS_ALLOW_MAINNET names {} network id(s) this gateway cannot arm.{}{} This gateway \
     advertises {}. Arming names its target, so that an armed instance stays recognisable by its \
     environment alone: the value must list exactly the advertised network id(s) that are not on \
     the pinned testnet allowlist, comma-separated and compared byte-exactly, and nothing else. {}",
    .unadvertised.len() + .already_testnet.len(),
    mismatch_group(" Not advertised by this gateway: ", .unadvertised),
    mismatch_group(" Already provably testnet, so not armable: ", .already_testnet),
    ids_or(.advertised, "nothing"),
    arming_prescription(.unproven)
)]
pub struct ArmingMismatch {
    /// Named by the value, advertised by nobody. Includes the plausible typos for the retired
    /// boolean form (`true`, `yes`), which name no network at all.
    pub unadvertised: Vec<String>,
    /// Named by the value, advertised, and on the allowlist already — armed for no reason.
    pub already_testnet: Vec<String>,
    /// Everything this gateway advertises: distinct, in first-advertised order. Printed because
    /// this refusal runs before the per-option startup lines, so it is the operator's only view of
    /// what the process actually received — the value can be right and the advertisement the
    /// thing that went missing.
    pub advertised: Vec<String>,
    /// The advertised ids that are not provably testnet, named or not: the exact value that would
    /// start this configuration, so the fix is one restart rather than two.
    pub unproven: Vec<String>,
}

/// Why the assembled payment options cannot be advertised as configured: either the arming value
/// names something there is not, or an unproven network is advertised that the value does not
/// name. Both refuse to start.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ArmingRefusal {
    #[error(transparent)]
    Mismatch(#[from] ArmingMismatch),
    #[error(transparent)]
    NotProvablyTestnet(#[from] NotProvablyTestnet),
}

/// Why `OBOLUS_ALLOW_MAINNET`'s raw value could not be read as a set of network ids at all. These
/// are defects of the value's *shape*; what it names is [`check_arming`]'s question.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ArmingValueError {
    /// Set, and carrying nothing — the same "arrived empty" defect every other variable refuses.
    #[error(
        "OBOLUS_ALLOW_MAINNET is set but empty. The variable reached this process carrying nothing \
         — an unexpanded `${{VAR}}` in a compose file, an EnvironmentFile line ending in `=`. Unset \
         it to arm nothing, or set it to exactly the network id(s) to arm, comma-separated."
    )]
    SetButEmpty,
    /// The retired boolean form. Refused with a pointer rather than swept into the generic
    /// mismatch: it was the documented form, and an operator with old notes will reach for it.
    #[error(
        "OBOLUS_ALLOW_MAINNET=1 no longer arms anything: arming names its target now. Set the \
         variable to exactly the network id(s) to arm, comma-separated — the refusal an un-armed \
         start prints names them — and nothing else. A process-wide yes admitted every advertised \
         option at once, a typo two entries below the one you meant included, and survived every \
         later edit to the network set; naming the target closes both."
    )]
    RetiredBooleanForm,
    /// A comma with nothing on one side of it.
    #[error(
        "OBOLUS_ALLOW_MAINNET has an empty entry at position {position} (counting from 1): a \
         comma with nothing on one side of it. Each entry must be a network id, with no entry left \
         blank."
    )]
    EmptyEntry { position: usize },
    /// The same id twice — harmless to the check, but a value that is not a set is a value someone
    /// edited without reading, which is the habit this variable must not tolerate.
    #[error("OBOLUS_ALLOW_MAINNET names {} twice. List each network id once.", legible(.0))]
    Duplicate(String),
}

/// Read `OBOLUS_ALLOW_MAINNET`'s raw value as the set of network ids it arms.
///
/// `None` — the variable unset — arms nothing, and is the normal case. Entries are split on `,`
/// and taken **verbatim**: no trimming, no case folding, for the reason the module docs give — what
/// this value names has to be byte-identical to what the gateway advertises, or the check admits
/// one string and the challenge carries another. A stray space around a comma therefore surfaces
/// as an [`ArmingMismatch`] naming the quoted entry, where the space is visible.
///
/// Pure — the caller reads the environment — so this stays testable without process-global state,
/// as [`check_arming`] does.
pub fn parse_arming(raw: Option<&str>) -> Result<Vec<String>, ArmingValueError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    if raw.trim().is_empty() {
        return Err(ArmingValueError::SetButEmpty);
    }
    // Trimmed, unlike the ids: this branch only ever refuses, so recognising `1 ` or `1\r` — the
    // forms an old `.env` line or a CRLF-saved unit file actually produces — widens nothing, and
    // the operator with old notes is the one this pointer exists for.
    if raw.trim() == "1" {
        return Err(ArmingValueError::RetiredBooleanForm);
    }
    let mut ids: Vec<String> = Vec::new();
    for (index, entry) in raw.split(',').enumerate() {
        if entry.trim().is_empty() {
            return Err(ArmingValueError::EmptyEntry { position: index + 1 });
        }
        if ids.iter().any(|seen| seen == entry) {
            return Err(ArmingValueError::Duplicate(entry.to_string()));
        }
        ids.push(entry.to_string());
    }
    Ok(ids)
}

/// Whether `network` is provably testnet: on the pinned [`TESTNET_NETWORKS`] allowlist, or Obolus's
/// own [`PLACEHOLDER_NETWORK`]. Byte-exact; see the module docs.
///
/// The placeholder is admitted here rather than sitting in the const so that `TESTNET_NETWORKS`
/// remains a pure transcription of the x402 source — see that const's docs.
pub fn is_provably_testnet(network: &str) -> bool {
    network == PLACEHOLDER_NETWORK || TESTNET_NETWORKS.contains(&network)
}

/// Payment options that have passed [`check_arming`] — the guard's witness, and the only thing
/// [`Gateway::new`](crate::gateway::Gateway::new) accepts.
///
/// There is no other constructor. That is the whole point: a caller cannot build a `Gateway`
/// advertising a network the guard never saw, whoever the caller is — the `obolus` binary, a test
/// harness, an external crate. What the guard *admitted* is the caller's policy (everything
/// provably testnet, or armed by name); that it ran is the type's.
///
/// Carries what the caller needs after the check so that nothing has to be recomputed or
/// remembered: the unproven networks the arming value admitted, and their [`diagnose`]d
/// explanation, so that an armed banner printed from this value cannot disclaim knowledge the
/// guard already had.
#[derive(Debug, Clone, PartialEq)]
pub struct ArmedRequirements {
    requirements: Vec<PaymentRequirements>,
    unproven: Vec<String>,
    diagnosis: String,
}

impl ArmedRequirements {
    /// The checked option set, as it was handed to the guard — order and duplicates preserved
    /// (`Gateway::new` is what rejects the latter).
    pub fn requirements(&self) -> &[PaymentRequirements] {
        &self.requirements
    }

    /// The advertised networks that are not provably testnet — distinct, in first-advertised
    /// order, and every one of them named by the arming value, or this value would not exist.
    /// Empty means nothing was armed and everything advertised is on the allowlist: the only
    /// evidence on which a caller may claim testnet-by-construction.
    pub fn unproven(&self) -> &[String] {
        &self.unproven
    }

    /// [`diagnose`] of [`unproven`](Self::unproven): the per-kind explanation the refusal would
    /// have printed, for the banner that advertises them anyway. Empty when nothing is unproven,
    /// or when nothing about the unproven ids is diagnosable.
    pub fn diagnosis(&self) -> &str {
        &self.diagnosis
    }

    /// Give up the witness for the option set itself. For `Gateway::new`; a caller that wants the
    /// list without consuming the proof has [`requirements`](Self::requirements).
    pub fn into_requirements(self) -> Vec<PaymentRequirements> {
        self.requirements
    }
}

/// Check the assembled payment options before the gateway is built.
///
/// `armed` is the set of network ids `OBOLUS_ALLOW_MAINNET` names (see [`parse_arming`]). On
/// success, returns the [`ArmedRequirements`] witness carrying the option set and the networks
/// that are **not** provably testnet — distinct, in first-advertised order:
///
/// - `armed` names something that is not an advertised unproven network → [`ArmingMismatch`],
///   naming each such id and why; the caller refuses to start. Checked first, so a value that is
///   wrong about itself is reported as that.
/// - an unproven network is advertised that `armed` does not name → [`NotProvablyTestnet`], naming
///   every such network and none of the armed ones; the caller refuses to start.
/// - otherwise → `Ok`, with the unproven list, which is exactly the armed set, so the caller can
///   print a banner that names what is unproven. An empty list therefore means nothing was armed
///   and everything advertised is on the allowlist — the reason the caller must not print a
///   *mainnet* banner on any evidence but this list. A banner that cries mainnet on an all-testnet
///   gateway is a log line someone will trust during an incident.
///
/// The set is compared byte-exactly on both sides, so a typo in the arming value cannot widen it.
///
/// `armed` is passed in rather than read from the environment, mirroring
/// [`superseded_single_chain_vars`](crate::config::superseded_single_chain_vars): it keeps this pure
/// and testable without mutating process-global environment state, which would race other tests.
///
/// Every advertised option is checked, so a mainnet entry hiding among testnet entries is caught —
/// and so is one hiding beside a deliberately armed mainnet, which the boolean form let through.
///
/// # Keeping this true as Obolus grows
///
/// The guard's promise is "no network Obolus advertises is unproven", and it can only keep that
/// promise over what it is handed. Today one gateway advertises one set. If Obolus later routes to
/// several upstreams with per-route pricing (#32), each route's requirements must reach this
/// function — the union of everything advertised, not a default set with per-route overrides applied
/// afterwards. A route whose price is patched in after the check is a route the guard never saw.
///
/// A bearer-token path that skips payment entirely (#33) needs nothing here: it advertises no
/// challenge, so there is nothing to prove testnet. The guard stays at startup either way.
///
/// # Who calls this
///
/// Whoever builds a `Gateway`: [`Gateway::new`](crate::gateway::Gateway::new) takes the
/// [`ArmedRequirements`] this returns and nothing else, so the guard cannot be skipped. The `obolus`
/// binary calls it at startup, before the option set is announced; `obolus-devseller` calls it with
/// an empty arming set, since it has no override. The constructor still enforces `(scheme, network)`
/// uniqueness itself — a correctness invariant with no override, unlike this one.
pub fn check_arming(
    requirements: &[PaymentRequirements],
    armed: &[String],
) -> Result<ArmedRequirements, ArmingRefusal> {
    // Distinct, in first-advertised order. Two `OBOLUS_ACCEPTS` entries can name the same bad
    // network, and this guard runs before `Gateway::new`'s duplicate check would reject the pair —
    // so listing the id twice, with its whole diagnosis paragraph repeated byte-identically, is what
    // the operator would see.
    let mut unproven: Vec<String> = Vec::new();
    for r in requirements {
        if !is_provably_testnet(&r.network) && !unproven.contains(&r.network) {
            unproven.push(r.network.clone());
        }
    }

    // The value first: everything it names must be an advertised, unproven network.
    let mut unadvertised: Vec<String> = Vec::new();
    let mut already_testnet: Vec<String> = Vec::new();
    for id in armed {
        if unproven.contains(id) {
            continue;
        }
        if requirements.iter().any(|r| &r.network == id) {
            already_testnet.push(id.clone());
        } else {
            unadvertised.push(id.clone());
        }
    }
    if !unadvertised.is_empty() || !already_testnet.is_empty() {
        let mut advertised: Vec<String> = Vec::new();
        for r in requirements {
            if !advertised.contains(&r.network) {
                advertised.push(r.network.clone());
            }
        }
        return Err(ArmingMismatch { unadvertised, already_testnet, advertised, unproven }.into());
    }

    // Then the advertisement: every unproven network must be named. The armed ids are not
    // offenders and are kept out of the list — the refusal must not blame the id the operator
    // deliberately armed alongside the one they did not.
    let unnamed: Vec<String> = unproven.iter().filter(|n| !armed.contains(n)).cloned().collect();
    if !unnamed.is_empty() {
        let diagnosis = diagnose(&unnamed);
        return Err(NotProvablyTestnet { networks: unnamed, diagnosis, armed: armed.to_vec() }.into());
    }
    let diagnosis = if unproven.is_empty() { String::new() } else { diagnose(&unproven) };
    Ok(ArmedRequirements { requirements: requirements.to_vec(), unproven, diagnosis })
}

/// Build the diagnosis for a set of unproven networks: one bullet per *kind* of defect, naming every
/// offender that carries it. Empty string when no offender is diagnosable.
///
/// # Both branches, not just the refusal
///
/// `pub` because the **armed** path needs it too. An operator can arm for a genuine `eip155:8453`
/// entry while the same `OBOLUS_ACCEPTS` array carries `base-sepolia` — the short name x402's own v1
/// payloads still use. Obolus can say something specific about the second, and flattening both into
/// *"a mainnet, a typo, or a newer testnet, Obolus cannot tell which"* discards knowledge this
/// binary has.
///
/// **What Obolus must not claim about those values.** "This guard cannot prove the id" and "no one
/// can pay the id" are separate properties with nothing keeping them in step:
/// [`Gateway::accepted_for`](crate::gateway::Gateway) matches against what *this gateway advertises*,
/// not against [`TESTNET_NETWORKS`]. A short name reaches the advertised set verbatim, is published
/// verbatim in the challenge, and is matched verbatim on the way back in — so byte-exactness is what
/// makes it **payable**, not what makes it dead. Only the first property is Obolus's to assert;
/// whether `base-sepolia` settles is the facilitator's call.
/// `gateway::tests::an_id_the_arming_guard_cannot_prove_is_still_payable` pins that.
///
/// The closing "arming helps none of the values named above" line is scoped to *the values above* on
/// purpose: a genuine mainnet can share the offender set, and for that one arming is the documented
/// answer.
///
/// An armed caller does not call this itself: [`check_arming`] does, and the result travels in
/// [`ArmedRequirements::diagnosis`] beside the list it explains. A caller can still ignore a field
/// as easily as a function, so what holds the banner honest is
/// `an_armed_gateway_diagnoses_a_dead_entry_among_a_real_mainnet`, which runs the binary with exactly
/// that array.
///
/// # Why by kind, and not by offender
///
/// Emitting every firing clause per offender repeats a whole paragraph — and
/// `OBOLUS_ALLOW_MAINNET` — once per offender, so it degrades in the direction that matters: the
/// flag's salience rises with N while the fix for any one offender gets buried, and this guard's
/// protection is the operator *not* reaching for the flag.
///
/// Grouping by kind also makes the clauses structurally un-collapsible: independent passes over the
/// offender list cannot express a suppressing chain, because there is no chain to shorten. The
/// overlap tests remain, because a structure can be rewritten back:
/// `a_non_ascii_space_is_both_a_near_miss_and_escaped` and
/// `a_short_name_carrying_a_homoglyph_gets_both_clauses` each assert two clauses fire on one
/// offender, and `a_placeholder_variant_emits_both_its_clauses_and_no_false_one` covers the
/// placeholder/non-ASCII direction.
///
/// # Order
///
/// Emptiness first (it explains the least-informative-looking value), then placeholder-variant,
/// whitespace/case, non-ASCII, short-name. Roughly most-mechanical to most-conceptual, which is also
/// the order an operator can act on them.
///
/// # Every clause must be *true*, not merely fired
///
/// Two clauses once fired correctly-by-structure and lied by content on the same fixture: the
/// near-miss clause called the placeholder "an allowlisted id" (deliberately not on the allowlist)
/// and the short-name clause called it an x402 short name (it is Obolus's own default, chosen for
/// *not* being a chain id). The suite built that exact value and asserted only that three lead-ins
/// were *present*. When adding a clause, assert what it says about the fixture, not that it appeared.
pub fn diagnose(unproven: &[String]) -> String {
    let named = |predicate: fn(&str) -> bool| -> Vec<&str> {
        unproven.iter().map(String::as_str).filter(|n| predicate(n)).collect()
    };
    let list = |ids: &[&str]| -> String {
        ids.iter().map(|n| legible(n)).collect::<Vec<_>>().join(", ")
    };

    let mut clauses: Vec<String> = Vec::new();

    let empties = named(is_empty_value);
    if !empties.is_empty() {
        clauses.push(format!(
            "Set but empty: {}. The variable reached this process carrying nothing — an unexpanded \
             `${{VAR}}` in a compose file, an EnvironmentFile line ending in `=`, an empty \
             ConfigMap key. An empty network is not a chain this build has not heard of; it is no \
             chain at all, and no client can pay against it. Check that the value you set actually \
             arrived.",
            list(&empties)
        ));
    }

    // Before the near-miss clause and separate from it: the advice is opposite. Deliberately shares
    // no phrase with it either, so that the near-miss needle is not a substring of this clause and a
    // test asserting near-miss is *absent* cannot be satisfied by this text.
    let placeholders = named(is_placeholder_variant);
    if !placeholders.is_empty() {
        clauses.push(format!(
            "Names Obolus's built-in placeholder {}, with stray whitespace or a different letter \
             case: {}. That is not a network — it is what Obolus publishes when no chain has been \
             configured, chosen because no real chain could match it. Deleting the stray character \
             would boot this gateway un-configured, publishing that placeholder verbatim in the 402 \
             challenge: Obolus itself does not refuse those requests, it is the facilitator that \
             has no such network, so nothing should ever settle against them. Unset OBOLUS_NETWORK \
             if that is what you want, or set a real CAIP-2 testnet id such as \"eip155:84532\".",
            legible(PLACEHOLDER_NETWORK),
            list(&placeholders)
        ));
    }

    // Pairs, not a bare list: the whole content of this clause is *which* admitted id the offender
    // is one keystroke away from, and a list of offenders alone would withhold it.
    let near_misses: Vec<String> = unproven
        .iter()
        .filter_map(|n| {
            near_miss(n).map(|admitted| format!("{} vs {}", legible(n), legible(admitted)))
        })
        .collect();
    if !near_misses.is_empty() {
        clauses.push(format!(
            "Differs from an allowlisted id only by surrounding whitespace or letter case: {}. \
             That is a configuration error, not a mainnet — fix the value.",
            near_misses.join("; ")
        ));
    }

    // Both renderings when they differ, deliberately: `{:?}` is how the id looks in every *other*
    // tool the operator has (`escape_debug` leaves printable non-ASCII alone), and `legible` is
    // what it actually is. That contrast is the whole diagnosis for a homoglyph — `"еip155:84532"
    // is really "\u{435}ip155:84532"` — because the escaped form alone does not convey that the
    // thing they are looking at elsewhere is the *same* value.
    //
    // But `escape_debug` and `escape_default` do not disagree about every non-ASCII character, only
    // the printable ones. U+00A0 NO-BREAK SPACE is escaped by both, so the contrast collapses to
    // `"X" is really "X"` — which reads as a rendering bug and teaches the operator to distrust the
    // one message that has to be trusted. Show the pair only when it is a pair.
    let non_ascii: Vec<String> = named(is_non_ascii)
        .iter()
        .map(|n| {
            let as_debug = format!("{n:?}");
            let as_legible = legible(n);
            if as_debug == as_legible {
                as_legible
            } else {
                format!("{as_debug} is really {as_legible}")
            }
        })
        .collect();
    if !non_ascii.is_empty() {
        clauses.push(format!(
            "Contains non-ASCII characters: {}. Every id this guard admits is pure ASCII, so a \
             value containing non-ASCII can never match one however identical it looks — a \
             homoglyph such as Cyrillic 'е' (U+0435) for ASCII 'e' renders the same as its ASCII \
             twin everywhere else in this output. That is a configuration error, not a mainnet — \
             retype the id by hand rather than pasting it.",
            non_ascii.join("; ")
        ));
    }

    let short_names = named(is_not_caip2);
    if !short_names.is_empty() {
        clauses.push(format!(
            "Not a CAIP-2 identifier — no `namespace:reference` colon, so it looks like an x402 \
             short name: {}. x402's own example payloads still use short names, but this guard \
             compares against CAIP-2 ids byte-exactly, so a short name can never match one however \
             correct the chain it names. TESTNET_NETWORKS carries the CAIP-2 id for every testnet \
             Obolus admits, in that form — Base Sepolia is \"eip155:84532\", Arbitrum Sepolia is \
             \"eip155:421614\" — so look up the one for your chain and configure that. (These two \
             are examples of the form, not a guess at which chain you meant.)",
            list(&short_names)
        ));
    }

    if clauses.is_empty() {
        return String::new();
    }
    // Once, at the end, rather than once per clause — repeated inside every clause, this is most of
    // how `OBOLUS_ALLOW_MAINNET` came to appear seven times in a single refusal. Scoped to the values
    // named above on purpose: a genuine mainnet id can be in the same offender set, and for *that*
    // one arming is the documented answer.
    //
    // The advice must not be justified by "no client can match it either". That reasons from the
    // allowlist to a comparison `Gateway::accepted_for` makes against the *advertised* option set —
    // two different sets with nothing keeping them in step, so an id can fail the first and pass the
    // second. It is not merely unproven, it is live, which is dangerous in the reassuring direction.
    clauses.push(
        "Arming helps none of the values named above: the flag suppresses this refusal, it does not \
         repair an id. Each is still advertised to clients exactly as written above, and whether \
         anything settles against it is the facilitator's decision, not something Obolus can \
         promise either way — so fix the value rather than arming past it."
            .to_string(),
    );
    format!("\n  · {}", clauses.join("\n  · "))
}

/// The unproven networks [`diagnose`] can say **nothing** specific about — the ones that really are
/// "a mainnet, a typo, or a testnet added to x402 after this build, and Obolus cannot tell which".
///
/// `main` branches three ways on this: *none* of the offenders diagnosable, *some*, or *all*. Keying
/// the banner's disclaimer on `diagnose(..).is_empty()` instead collapses that to two, so the
/// all-diagnosable case claims a defect in "some of them" and then quantifies "for any it does not
/// name" over the empty set. A `String` cannot distinguish those; only the data can.
pub fn undiagnosed(unproven: &[String]) -> Vec<&str> {
    unproven.iter().map(String::as_str).filter(|n| !is_diagnosable(n)).collect()
}

/// Does [`diagnose`] name this value? Asked of `diagnose` itself rather than re-listing its
/// predicates, so the two cannot disagree.
///
/// Sound because `diagnose` returns the empty string exactly when no clause fired — it early-returns
/// *before* appending its closing "arming helps none of the values named above" line, so that line
/// cannot make a residue look diagnosable. Cost is one `String` per unproven network, once, at
/// startup.
///
/// Derived rather than enumerated because the enumerated version was a second hand-maintained list
/// of the same defect kinds, and the test meant to hold the two in step walked a *third* — so a
/// sixth clause added to `diagnose` alone was exercised by no fixture and the suite stayed green.
fn is_diagnosable(network: &str) -> bool {
    let one = [network.to_string()];
    !diagnose(&one).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::SCHEME_EXACT;

    /// Only `network` matters to the guard; everything else is filler.
    fn req(network: &str) -> PaymentRequirements {
        PaymentRequirements {
            scheme: SCHEME_EXACT.to_string(),
            network: network.to_string(),
            max_amount_required: "1000".to_string(),
            resource: "http://127.0.0.1:8403/v1/chat/completions".to_string(),
            description: "One inference request".to_string(),
            mime_type: "application/json".to_string(),
            pay_to: "0xTEST-PAY-TO-ADDRESS-NOT-REAL".to_string(),
            max_timeout_seconds: 60,
            asset: "0xTEST-ASSET-ADDRESS-NOT-REAL".to_string(),
            extra: None,
        }
    }

    /// Base mainnet. The teeth: if the guard were inverted, absent, or a no-op, this is the input
    /// that would sail through and let a gateway advertise a real-money challenge.
    const BASE_MAINNET: &str = "eip155:8453";

    /// Ethereum mainnet: a second unproven network, for the tests where one is armed and one is not.
    const ETH_MAINNET: &str = "eip155:1";

    /// The un-armed refusal every diagnosis test expects. A mismatch here is a test defect — none of
    /// those tests names anything in the arming set — so it panics with the message rather than
    /// letting a wrong variant satisfy a `to_string()` assertion by accident.
    fn unproven_of(err: ArmingRefusal) -> NotProvablyTestnet {
        match err {
            ArmingRefusal::NotProvablyTestnet(err) => err,
            ArmingRefusal::Mismatch(err) => panic!("expected NotProvablyTestnet, got: {err}"),
        }
    }

    /// The mirror: the refusal the arming-value tests expect.
    fn mismatch_of(err: ArmingRefusal) -> ArmingMismatch {
        match err {
            ArmingRefusal::Mismatch(err) => err,
            ArmingRefusal::NotProvablyTestnet(err) => panic!("expected ArmingMismatch, got: {err}"),
        }
    }

    fn armed(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    // One constant per clause, shared by the positive AND negative assertions on purpose. Half these
    // tests assert a clause is *absent* — that is what stops any one clause becoming a catch-all —
    // and a bare `!contains("literal")` is satisfied by wording drift as happily as by correct
    // behaviour. Sharing the constant means the positives fail loudly on drift, so the negatives
    // cannot rot quietly. Lead-ins, not fragments of clause bodies: several clauses discuss
    // non-ASCII and CAIP-2 in their explanatory text, so a loose needle matches the wrong bullet.
    const EMPTY_CLAUSE: &str = "Set but empty";
    const PLACEHOLDER_CLAUSE: &str = "Names Obolus's built-in placeholder";
    const NEAR_MISS_CLAUSE: &str = "only by surrounding whitespace or letter case";
    const NON_ASCII_CLAUSE: &str = "Contains non-ASCII characters";
    const SHORT_NAME_CLAUSE: &str = "Not a CAIP-2 identifier";
    const ARMING_WONT_HELP: &str = "Arming helps none of the values named above";

    /// One value per diagnosis clause, in clause order, plus the residue case. The residue must be a
    /// **real, well-formed mainnet id** — anything malformed would be diagnosable and stop being a
    /// residue, which is the whole property under test.
    fn one_fixture_per_defect_kind() -> Vec<(&'static str, &'static str)> {
        vec![
            ("", "empty"),
            ("  test-network-not-a-real-caip2  ", "placeholder variant"),
            (" eip155:84532", "near miss"),
            ("\u{435}ip155:84532", "non-ASCII (Cyrillic е)"),
            ("base-sepolia", "x402 short name"),
        ]
    }

    #[test]
    fn undiagnosed_names_exactly_what_diagnose_cannot_explain() {
        // `is_diagnosable` is DERIVED from `diagnose`, so the loop below cannot detect drift between
        // them — that is structural now. It is kept as a worked example that each kind really does
        // produce a clause. **The residue block underneath is where the teeth are:** it is the only
        // part that can fail, and it rules out a clause quietly becoming a catch-all.
        for (value, kind) in one_fixture_per_defect_kind() {
            let one = vec![value.to_string()];
            assert!(
                undiagnosed(&one).is_empty(),
                "{kind}: `is_diagnosable` does not know about this kind, but `diagnose` does — the \
                 armed banner would print a clause naming it AND count it as unexplained",
            );
            assert!(
                !diagnose(&one).is_empty(),
                "{kind}: `is_diagnosable` claims this is explainable but `diagnose` emits no clause \
                 for it — the banner would say 'a defect in every one of them' and then name none",
            );
        }

        // And the residue direction, which is what makes the two assertions above discriminating
        // rather than satisfiable by an always-true predicate.
        let residue = vec![BASE_MAINNET.to_string()];
        assert_eq!(
            undiagnosed(&residue),
            vec![BASE_MAINNET],
            "a well-formed mainnet id is exactly the case Obolus CANNOT explain",
        );
        assert!(
            diagnose(&residue).is_empty(),
            "and `diagnose` must emit nothing for it — otherwise some clause has become a catch-all",
        );
    }

    /// The **mainnet twin of every id in [`TESTNET_NETWORKS`]** — one row each, same order, so the
    /// correspondence is checkable by reading down two columns. Sourced from
    /// <https://docs.x402.org/core-concepts/network-and-token-support>.
    ///
    /// This exists because the allowlist is **data** and every other test here exercises *code*. A
    /// logic mutation (invert the predicate, stop iterating) fails those tests loudly; a
    /// *transcription* mutation — one digit slipped while adding an entry — changes no logic, so it
    /// passes all of them while silently admitting a mainnet id. The near-miss pairs are why a slipped
    /// digit is realistic rather than theoretical, and note the testnet id is **not** consistently the
    /// larger of the pair, so no rule of thumb catches a transposition: `eip155:51`/`eip155:50` (XDC),
    /// `aptos:2`/`aptos:1`, `xrpl:1`/`xrpl:0`, `eip155:31611`/`eip155:31612` (Mezo — testnet is
    /// *lower*), `eip155:72344`/`eip155:723487` (Radius), `eip155:2201`/`eip155:988` (Stable),
    /// `tvm:-3`/`tvm:-239` (TON), `keeta:1413829460`/`keeta:21378`.
    ///
    /// **Scope is derived from the allowlist, not transcribed from the page.** One twin per admitted
    /// testnet, with the length asserted *relationally* against `TESTNET_NETWORKS`. Three independent
    /// reads of the x402 source returned three different mainnet sets (22 / 21 / ≥23), so a
    /// transcribed count is a claim the next reader has to relitigate. Every id those reads disagreed
    /// about was a chain with no testnet on the allowlist, so no disputed id could have been the
    /// transposition this oracle exists to catch.
    ///
    /// **What this establishes is mutual consistency, NOT truth — read that limit before trusting
    /// it.** Both lists are transcriptions of the same page, so their errors are *correlated*, and an
    /// oracle whose errors correlate with the artefact it checks measures agreement rather than
    /// correctness. A misread row moves both together: believe XDC Apothem is `eip155:50` and XDC
    /// Network is `eip155:51`, write each into "its" list, and the two stay perfectly consistent, this
    /// test passes, and a real XDC *mainnet* id boots un-armed. Every near-miss pair lives on one
    /// source row, so the adjacency that makes a slip realistic is what makes it correlated.
    /// **Re-reading the primary source stays mandatory; a green suite is not a verification of this
    /// data.** Mechanising that re-read is #29. The testnet half is the better-attested one —
    /// three readers agree on all 16 ids byte-for-byte, every near-miss pair on the correct side — and
    /// it is the half that actually gates the guard.
    ///
    /// An id on **neither** list is out of scope: a chain x402 adds later, or a typo landing on no
    /// real network. The guard is fail-closed, so those refuse to boot un-armed anyway.
    // One row per TESTNET_NETWORKS entry, in the SAME ORDER, so a reader can diff the two lists down
    // the page. The trailing comment names the admitted testnet each one partners: the pairing IS the
    // content, and an entry whose partner nobody can name is doing no work.
    const MAINNET_NETWORKS: &[&str] = &[
        // EVM
        "eip155:8453",   // Base            <- eip155:84532  Base Sepolia
        "eip155:42161",  // Arbitrum One    <- eip155:421614 Arbitrum Sepolia
        "eip155:988",    // Stable          <- eip155:2201   Stable Testnet
        "eip155:31612",  // Mezo            <- eip155:31611  Mezo Testnet    (testnet is LOWER)
        "eip155:723487", // Radius          <- eip155:72344  Radius Testnet
        "eip155:190415", // HPP             <- eip155:181228 HPP Sepolia
        "eip155:50",     // XDC Network     <- eip155:51     XDC Apothem     (testnet is HIGHER)
        // Non-EVM
        "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", // Solana Mainnet <- solana:EtWTRABZ… Devnet
        "tvm:-239",                                // TON Mainnet    <- tvm:-3
        "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k", // Algorand Mainnet <- algorand:SGO1GKSz…
        "stellar:pubnet",                          // Stellar Pubnet <- stellar:testnet
        "aptos:1",                                 // Aptos Mainnet  <- aptos:2
        "hedera:mainnet",                          // Hedera Mainnet <- hedera:testnet
        "keeta:21378",                             // Keeta Mainnet  <- keeta:1413829460
        "near:mainnet",                            // NEAR Mainnet   <- near:testnet
        "xrpl:0",                                  // XRPL Mainnet   <- xrpl:1
    ];

    #[test]
    fn no_mainnet_network_is_on_the_testnet_allowlist() {
        // The data-defect guard. See MAINNET_NETWORKS' docs for why the other tests cannot see this.
        //
        // The count first, because without it this test's entire strength is silently editable to
        // zero: truncate the const to `&[]` and the loop runs no iterations and the suite stays
        // green. Measured — `&[]` plus a real mainnet (`eip155:50`, XDC Network) added to
        // TESTNET_NETWORKS booted un-armed and printed `testnet-by-construction` at a fully green
        // suite. Half a list is the realistic damage rather than the whole one: losing any one
        // near-miss pair silently drops detection for that pair while the test name still claims the
        // coverage.
        //
        // The count is **relational, not a literal**, because a literal would assert a number three
        // independent reads of the x402 page could not reproduce. Against `TESTNET_NETWORKS.len()` it
        // asserts something this module can know, and it catches the one case the loop cannot:
        // `eip155:137` (Polygon) added to the allowlist alone fails at `left: 16, right: 17` even
        // though Polygon's mainnet is not in the oracle for the loop to find. Deliberately not an
        // exact-contents pin — adding a testnet **and** its twin must stay a cheap, passing edit.
        //
        // **What the derived form cannot catch, named rather than left to be re-found.** Both columns
        // are now written in one act of transcription, so no check that compares them to each other
        // can be independent of it. A **column swap** on any chain added from here on passes
        // everything: put the mainnet id in TESTNET_NETWORKS and the testnet id in MAINNET_NETWORKS,
        // and the count is equal (17 == 17), the loop below asks `is_provably_testnet` of an id that
        // is — correctly — not on the allowlist, and `every_pinned_testnet_is_still_admitted` anchors
        // only the 16 ids pinned at review time, so a 17th chain has no independent anchor anywhere.
        // The transcribed oracle caught exactly that case, because its rows came from the x402 page
        // rather than from this list; the six rows the rescope dropped were decorrelated by *time* as
        // well, written before anyone knew which testnet would later need a twin. The signal that
        // closes this has to come from outside the file — a mechanised re-fetch-and-diff (#29).
        // Until it lands, **adding a chain here means reading the source twice, once per column.**
        assert_eq!(
            MAINNET_NETWORKS.len(),
            TESTNET_NETWORKS.len(),
            "the mainnet cross-check oracle no longer has exactly one twin per admitted testnet. \
             Either an allowlist entry was added without its mainnet counterpart, or the oracle was \
             truncated — and a shrunken oracle passes exactly like a correct one, so this count is \
             the only thing standing between a half-pasted re-transcription and a silently \
             unguarded allowlist.",
        );
        for mainnet in MAINNET_NETWORKS {
            assert!(
                !is_provably_testnet(mainnet),
                "{mainnet} is a MAINNET per the x402 source but is admitted as provably-testnet — \
                 a gateway would advertise a real-money challenge un-armed. Check TESTNET_NETWORKS \
                 for a transposed digit.",
            );
        }
    }

    #[test]
    fn the_allowlist_has_no_duplicate_or_blank_entries() {
        // A duplicate is the visible symptom of a copy-paste that was *meant* to add a new network —
        // i.e. one entry is probably wrong. A blank/whitespace entry would silently admit an empty
        // network, which `config::parse_accepts` separately rejects but which must never be
        // *provably testnet* here either.
        let mut seen = std::collections::BTreeSet::new();
        for n in TESTNET_NETWORKS {
            assert!(!n.trim().is_empty(), "TESTNET_NETWORKS contains a blank entry");
            assert!(seen.insert(*n), "TESTNET_NETWORKS contains {n} twice — one entry is likely a \
                                      copy-paste that was meant to become a different network");
        }
    }

    #[test]
    fn the_mainnet_oracle_has_no_duplicate_or_blank_entries() {
        // The mirror of the test above, for the list that *checks* the allowlist. Not redundant with
        // the length assertion in `no_mainnet_network_is_on_the_testnet_allowlist`: a duplicate
        // defeats that count in the direction that looks correct, holding `len()` equal to the
        // allowlist's while covering one fewer real mainnet — the likely residue of a paste meant to
        // add a *different* chain.
        let mut seen = std::collections::BTreeSet::new();
        for n in MAINNET_NETWORKS {
            assert!(!n.trim().is_empty(), "MAINNET_NETWORKS contains a blank entry");
            assert!(
                seen.insert(*n),
                "MAINNET_NETWORKS contains {n} twice — one entry is likely a copy-paste that was \
                 meant to become a different mainnet, which keeps the count matching \
                 TESTNET_NETWORKS while shrinking real coverage by one chain",
            );
        }
    }

    #[test]
    fn the_allowlist_is_a_pure_transcription_of_the_x402_source() {
        // Pins finding C's fix: the placeholder is admitted by the predicate, NOT by the const, so
        // re-verifying the const against the docs stays a mechanical line-for-line diff. If someone
        // moves it back into the list, this fails and says why.
        assert!(
            !TESTNET_NETWORKS.contains(&PLACEHOLDER_NETWORK),
            "PLACEHOLDER_NETWORK must not be in TESTNET_NETWORKS — that const is a 1:1 mirror of the \
             x402 source. is_provably_testnet admits the placeholder instead.",
        );
        assert!(is_provably_testnet(PLACEHOLDER_NETWORK), "the placeholder must still be admitted");
        // Every entry is CAIP-2 shaped (namespace:reference). A bare short name like "base-sepolia"
        // reaching this list would be a category error: x402 documents no short-name form, so it
        // could never match a real payment envelope and would be a dead advertised entry.
        for n in TESTNET_NETWORKS {
            let (ns, reference) = n.split_once(':').unwrap_or_else(|| {
                panic!("{n} is not CAIP-2 shaped (namespace:reference) — x402 documents no bare \
                        short-name network form")
            });
            assert!(!ns.is_empty() && !reference.is_empty(), "{n} has an empty CAIP-2 half");
        }
    }

    #[test]
    fn every_pinned_testnet_is_still_admitted() {
        // POSITIVE pin, and ADD-SAFE by construction: adding a network to TESTNET_NETWORKS can never
        // fire this, only REMOVING or MUTATING a pinned entry does.
        //
        // The damage it guards is the mirror of the mainnet cross-check and just as severe: drop or
        // fat-finger `eip155:421614` and an operator on Arbitrum Sepolia — a GENUINE testnet — cannot
        // boot. The refusal offers them three causes they can see are false, then the arming flag as
        // the way through. That is the guard training the operator to disarm it.
        let pinned_at_review = [
            "eip155:84532",  // Base Sepolia
            "eip155:421614", // Arbitrum Sepolia
            "eip155:2201",   // Stable Testnet
            "eip155:31611",  // Mezo Testnet
            "eip155:72344",  // Radius Testnet
            "eip155:181228", // HPP Sepolia
            "eip155:51",     // XDC Apothem Testnet
            "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", // Solana Devnet
            "tvm:-3",                                  // TON Testnet
            "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe", // Algorand Testnet
            "stellar:testnet",                         // Stellar Testnet
            "aptos:2",                                 // Aptos Testnet
            "hedera:testnet",                          // Hedera Testnet
            "keeta:1413829460",                        // Keeta Testnet
            "near:testnet",                            // NEAR Testnet
            "xrpl:1",                                  // XRPL Testnet
        ];
        // Same vacuous-pass hazard as the mainnet oracle, one severity lower: truncate this fixture
        // and the positive pin silently covers less with the test name unchanged. It costs nothing in
        // add-safety — the fixture is independent of the const, so this fires only when someone edits
        // *this list*, which is the deliberate moment.
        assert_eq!(
            pinned_at_review.len(),
            16,
            "this fixture is the whole strength of the removal check — a shortened list passes \
             exactly like a complete one",
        );
        for pinned in pinned_at_review {
            assert!(
                is_provably_testnet(pinned),
                "{pinned} was pinned from the x402 source on {PINNED_ON} and must stay admitted — \
                 dropping a genuine testnet pushes that chain's operator toward OBOLUS_ALLOW_MAINNET",
            );
        }
    }

    // ---- x402 source-audit mechanism (#29) ----------------------------------------------------
    //
    // The mainnet oracle above measures the two lists against EACH OTHER, and its own docs name the
    // limit: both columns are one act of transcription, so their errors correlate, and a green suite
    // is not a verification of the DATA. Closing that needs a signal from OUTSIDE the file — a re-read
    // of the x402 source. These functions are that re-read's mechanism: pull the CAIP-2 ids out of the
    // source, then diff the admitted lists against them. The source is NOT a machine-readable registry:
    // it attests networks in at least three differently-shaped places — the "Default Assets" tables
    // (chains with a default stablecoin), the "Network Identifiers" prose bullets, and per-facilitator
    // support tables. XRPL, for one, has no default-asset row — its testnet id reaches the bullets and
    // a facilitator table, its mainnet id the bullets alone. obolus's allowlist is sourced from all of
    // them, so the parse reads the WHOLE document rather than one section.
    //
    // This PR lands the MECHANISM plus a hermetic check against a checked-in verbatim snapshot of the
    // page; the scheduled lane that runs the same diff against the LIVE page is a follow-up (still
    // #29). The check is a TRANSCRIPTION-FIDELITY test, not a classifier. The page carries no
    // testnet/mainnet flag — only the row's NAME says which — and this module must not infer an
    // environment from a name, which is the very heuristic the arming guard refuses. So it answers one
    // question per tracked id: is it still on the page? A tracked id that VANISHED is a hard failure (a
    // dropped or renamed chain); an id on the page obolus does not track is INFORMATIONAL (obolus
    // admits a curated subset, so a newly-listed network is normal, not alarming). What presence
    // CANNOT see is a column SWAP of a newly-added pair — both ids stay on the page — because catching
    // that needs the page's name-encoded environment. Per-column human re-reading (see
    // `MAINNET_NETWORKS`' docs) stays the mitigation for that one; naming the gap beats a name
    // heuristic that would pass a swapped pair while claiming to cover it.

    /// A verbatim capture of the x402 source, pinned so the fidelity check below is hermetic. Refresh
    /// it in the same reviewed change that reconciles the allowlist to a source revision — never on
    /// its own, or the check silently re-baselines to whatever the page says today.
    const X402_SOURCE_SNAPSHOT: &str = include_str!("../tests/fixtures/x402-network-support.md");

    /// The x402 source could not be parsed for a network list — distinct from "parsed, and diverged".
    /// A scheduled lane must fail LOUDLY and DIFFERENTLY here: a layout change that yields zero ids
    /// must never read as "every tracked id was removed", nor pass silently as "nothing diverged".
    #[derive(Debug, PartialEq, Eq)]
    enum SourceParseError {
        /// The `## Default Assets …` header is gone — the page was restructured, or the fetch returned
        /// something else entirely (an error page, a redirect body). Kept as a structural anchor: its
        /// presence is how we prove we fetched the right document before trusting a "nothing missing".
        NoDefaultAssetsSection,
        /// The anchor is present but the document yields no CAIP-2-shaped ids at all — a layout the
        /// extractor no longer recognizes. Zero ids from a page that should hold dozens is a parse
        /// fault, not an empty allowlist.
        NoNetworkIds,
    }

    /// Extract every CAIP-2 id (`namespace:reference`) written in backticks anywhere on the page.
    ///
    /// Reads the WHOLE document, not one section: the ids are scattered across the Default Assets
    /// tables, the `## Network Identifiers` bullets, and the facilitator support tables (XRPL, for one,
    /// appears only in the latter two). The `## Default Assets …` header is required first as a
    /// structural anchor — its job is not "the section to parse" but "proof this is the x402 page and
    /// not an error body", so a fetch that lost it fails as a parse fault rather than as an empty diff.
    ///
    /// Fenced code blocks are skipped: the "Runtime Registration" examples contain ids like
    /// `eip155:43114` that are code, not the supported-network list. Skipping by a per-line fence
    /// toggle also keeps the ``` fences from breaking the per-line backtick parity. `<chainId>`-style
    /// format placeholders (any span with `<`/`>`) are dropped.
    /// A CAIP-2 namespace is `[-a-z0-9]{3,8}` (per the CAIP-2 spec). Checking the shape keeps two
    /// backtick spans on the page that happen to contain a colon out of the id set: `namespace:reference`
    /// (the literal format template, namespace 9 chars) and `primary_fungible_store::transfer` (an Aptos
    /// code symbol, `_` and over-length). Both would otherwise land in `untracked_on_page` and surface
    /// to a maintainer as spurious "untracked networks" in the scheduled lane.
    fn is_caip2_namespace(ns: &str) -> bool {
        (3..=8).contains(&ns.len())
            && ns.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }

    fn parse_source_caip2_ids(md: &str) -> Result<Vec<String>, SourceParseError> {
        if !md.contains("## Default Assets for Dollar-String Pricing") {
            return Err(SourceParseError::NoDefaultAssetsSection);
        }
        let mut ids = Vec::new();
        let mut in_fence = false;
        for line in md.lines() {
            if line.trim_start().starts_with("```") {
                in_fence = !in_fence;
                continue;
            }
            if in_fence {
                continue;
            }
            // Inline code does not span lines, so backtick parity is reliable per line: splitting on
            // '`', the ODD-indexed spans are the backtick-fenced ones.
            for (i, span) in line.split('`').enumerate() {
                if i % 2 == 0 {
                    continue;
                }
                let span = span.trim();
                if span.contains('<') || span.contains('>') || span.contains(' ') {
                    continue; // a `<chainId>` placeholder or a multi-token span, not a bare id
                }
                if let Some((ns, reference)) = span.split_once(':') {
                    if is_caip2_namespace(ns) && !reference.is_empty() {
                        ids.push(span.to_string());
                    }
                }
            }
        }
        if ids.is_empty() {
            return Err(SourceParseError::NoNetworkIds);
        }
        Ok(ids)
    }

    /// The result of diffing the admitted lists against the source.
    struct SourceAudit {
        /// Admitted ids the source no longer lists — a hard failure (a dropped or renamed chain).
        missing_tracked: Vec<String>,
        /// Source ids obolus does not admit — informational (a curated-out network), never a failure.
        untracked_on_page: Vec<String>,
    }

    fn audit_against_source(page_ids: &[String], tracked: &[&str]) -> SourceAudit {
        let page: std::collections::BTreeSet<&str> = page_ids.iter().map(String::as_str).collect();
        let tracked_set: std::collections::BTreeSet<&str> = tracked.iter().copied().collect();
        SourceAudit {
            missing_tracked: tracked_set
                .iter()
                .filter(|t| !page.contains(*t))
                .map(|t| t.to_string())
                .collect(),
            untracked_on_page: page
                .iter()
                .filter(|p| !tracked_set.contains(*p))
                .map(|p| p.to_string())
                .collect(),
        }
    }

    /// Every id obolus admits: the testnet allowlist plus its mainnet twin. `PLACEHOLDER_NETWORK` is
    /// deliberately excluded — it is obolus-internal and never appears on the x402 page, so including
    /// it would flag it as permanently "missing from the source".
    fn admitted_ids() -> Vec<&'static str> {
        TESTNET_NETWORKS.iter().chain(MAINNET_NETWORKS).copied().collect()
    }

    #[test]
    fn the_source_parser_reads_ids_from_tables_and_from_prose_bullets() {
        let ids = parse_source_caip2_ids(X402_SOURCE_SNAPSHOT).expect("snapshot has the anchor");
        // Ids from a Default Assets table row parse.
        assert!(ids.iter().any(|i| i == "eip155:84532"), "Base Sepolia (a table row) should parse");
        assert!(ids.iter().any(|i| i == "cardano:preprod"), "Cardano Preprod (a table row) should parse");
        // `xrpl:0` has NO default-asset row — it is attested ONLY in the `## Network Identifiers`
        // bullet (its testnet twin `xrpl:1` also reaches a facilitator support table; the x402.org
        // facilitator is testnet-only, so the mainnet id does not). obolus admits it, so the parser
        // must read the whole page, not just the tables, or the fidelity check below false-positives.
        assert!(ids.iter().any(|i| i == "xrpl:0"), "xrpl:0 (prose-only, no table row) should parse");
        // Format placeholders like `solana:<genesisHash>` are not ids.
        assert!(
            !ids.iter().any(|i| i.contains('<') || i.contains("genesisHash")),
            "a `<placeholder>` span must not be taken as an id",
        );
    }

    #[test]
    fn the_source_parser_skips_fenced_code_examples() {
        // The "Runtime Registration" code fences contain ids like `eip155:43114` as code, not as the
        // supported-network list. A fenced id must not enter the extracted set — and this pins the
        // fence toggle so a later "simplification" that drops it fails loudly.
        let md = "## Default Assets for Dollar-String Pricing\n\n\
                  | Chain | CAIP-2 |\n| ----- | ------ |\n| Base | `eip155:8453` |\n\n\
                  ```rust\nserver.register(`eip155:43114`);\n```\n";
        let ids = parse_source_caip2_ids(md).expect("the real table row anchors a non-empty parse");
        assert!(ids.contains(&"eip155:8453".to_string()), "the table id is read");
        assert!(!ids.contains(&"eip155:43114".to_string()), "the fenced code id is skipped");
    }

    #[test]
    fn every_admitted_id_appears_in_the_pinned_x402_snapshot() {
        // The correlated-oracle gap the mainnet-twin docs name, closed against a SECOND artefact: the
        // admitted lists are diffed not against each other but against a verbatim capture of the page.
        // A digit slipped while transcribing TESTNET_NETWORKS surfaces here as an id the capture does
        // not contain. This runs in the merge gate against the checked-in snapshot; the scheduled lane
        // (#29 follow-up) runs the same diff against the live page.
        let ids = parse_source_caip2_ids(X402_SOURCE_SNAPSHOT).expect("snapshot parses");
        let audit = audit_against_source(&ids, &admitted_ids());
        assert!(
            audit.missing_tracked.is_empty(),
            "these admitted ids are absent from the pinned x402 snapshot — a transcription slip, or a \
             snapshot gone stale that must be refreshed in the reviewed change that reconciles the \
             allowlist: {:?}",
            audit.missing_tracked,
        );
    }

    #[test]
    fn a_tracked_id_absent_from_the_source_is_named_as_missing() {
        // The source lists only Base Sepolia; obolus still admits Arbitrum Sepolia.
        let page = ["eip155:84532".to_string()];
        let audit = audit_against_source(&page, &["eip155:84532", "eip155:421614"]);
        assert_eq!(
            audit.missing_tracked,
            vec!["eip155:421614".to_string()],
            "an admitted id the source dropped must be reported by name",
        );
        assert!(audit.untracked_on_page.is_empty());
    }

    #[test]
    fn an_untracked_source_id_is_informational_not_a_failure() {
        // Sei Testnet is on the page; obolus does not admit it. That is a curated-out network, not a
        // divergence — it must not fail the lane.
        let page = ["eip155:84532".to_string(), "eip155:1328".to_string()];
        let audit = audit_against_source(&page, &["eip155:84532"]);
        assert!(audit.missing_tracked.is_empty(), "a curated-out network is not a divergence");
        assert_eq!(audit.untracked_on_page, vec!["eip155:1328".to_string()]);
    }

    #[test]
    fn a_source_without_the_default_assets_section_is_a_parse_fault() {
        // The load-bearing three-outcome distinction: a fetch that returns an error page or a
        // restructured doc must fail as "could not read the source", never as "every tracked id was
        // removed" — which is what a naive "zero ids parsed" would look like to the diff.
        let err = parse_source_caip2_ids("# Some other page\n\nNo tables here.\n").unwrap_err();
        assert_eq!(err, SourceParseError::NoDefaultAssetsSection);
    }

    #[test]
    fn an_anchored_page_with_no_ids_is_a_parse_fault_not_an_empty_diff() {
        // The anchor is present but the document carries no CAIP-2-shaped id — a layout the extractor
        // no longer recognizes. Zero ids from a page that should hold dozens is a fault, distinct from
        // "every tracked id was removed", which is what a naive empty parse would look like to the diff.
        let md = "## Default Assets for Dollar-String Pricing\n\n\
                  | Chain | Token |\n| ----- | ----- |\n| Base | USDC |\n";
        let err = parse_source_caip2_ids(md).unwrap_err();
        assert_eq!(err, SourceParseError::NoNetworkIds);
    }

    #[test]
    fn the_parser_excludes_colon_spans_that_are_not_caip2_ids() {
        // Two backtick spans on the real page carry a colon but are not networks: the literal
        // `namespace:reference` format template, and the Aptos code symbol
        // `primary_fungible_store::transfer`. The CAIP-2 namespace-shape check keeps both out, so the
        // scheduled lane's `untracked_on_page` report does not name them as spurious networks.
        let md = "## Default Assets for Dollar-String Pricing\n\n\
                  Format is `namespace:reference`; Aptos uses `primary_fungible_store::transfer`.\n\n\
                  | Chain | CAIP-2 |\n| ----- | ------ |\n| Base | `eip155:8453` |\n";
        let ids = parse_source_caip2_ids(md).expect("the real table row anchors a non-empty parse");
        assert_eq!(ids, vec!["eip155:8453".to_string()], "only the real id survives the shape filter");
    }

    #[test]
    #[ignore = "network: the scheduled staleness lane fetches the live page to $OBOLUS_X402_PAGE"]
    fn the_admitted_lists_still_match_the_live_x402_source() {
        // The out-of-file signal #29 is for: the same audit as `every_admitted_id_appears_in_the_pinned_
        // x402_snapshot`, but against the LIVE page rather than the checked-in snapshot. `#[ignore]`d so
        // it never runs in the hermetic merge gate (which forbids network); the scheduled workflow runs
        // it with `--ignored`. Network stays OUT of Rust — the workflow curls the page to a file and
        // passes the path in `OBOLUS_X402_PAGE`; this reads the file. Three outcomes, each distinct in
        // the run's output: clean pass / a named DIVERGENCE (a dropped or renamed admitted id) / a
        // PARSE FAULT (the page layout moved), the last never mistaken for the first.
        let path = std::env::var("OBOLUS_X402_PAGE")
            .expect("set OBOLUS_X402_PAGE to the path of the fetched x402 page");
        let md = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("could not read OBOLUS_X402_PAGE ({path}): {e}"));
        let ids = match parse_source_caip2_ids(&md) {
            Ok(ids) => ids,
            Err(e) => panic!(
                "PARSE FAULT reading the x402 source ({e:?}) — the page layout changed or the fetch \
                 returned something else. This is NOT a divergence: re-read the source and update the \
                 parser and the pinned snapshot. Fetched to: {path}"
            ),
        };
        let audit = audit_against_source(&ids, &admitted_ids());
        if !audit.untracked_on_page.is_empty() {
            // Informational, never a failure: networks on the page obolus does not admit (curated-out,
            // or newly added and awaiting a deliberate reviewed reconciliation).
            eprintln!(
                "INFO: {} id(s) on the x402 source that obolus does not admit: {:?}",
                audit.untracked_on_page.len(),
                audit.untracked_on_page,
            );
        }
        assert!(
            audit.missing_tracked.is_empty(),
            "DIVERGENCE: these admitted ids are no longer on the live x402 source — a dropped or \
             renamed chain. Reconcile TESTNET_NETWORKS / MAINNET_NETWORKS in a reviewed change (and \
             refresh the pinned snapshot in the same PR): {:?}",
            audit.missing_tracked,
        );
    }

    #[test]
    fn a_whitespace_variant_is_diagnosed_rather_than_blamed_on_mainnet() {
        // The commonest real config slip. Fail-closed is unchanged — what must change is that the
        // refusal names the TRUE cause instead of offering three false ones and then the arming flag.
        let err = unproven_of(check_arming(&[req("eip155:84532 ")], &[]).unwrap_err());
        let msg = err.to_string();
        assert!(msg.contains(NEAR_MISS_CLAUSE), "a near-miss must be diagnosed, got: {msg}");
        // Teeth for the near-miss/placeholder split: an *allowlist* near-miss must still get the
        // allowlist clause, not the placeholder one. Without this, collapsing the two back together —
        // or replacing the near-miss clause outright with the placeholder wording — passes every
        // other test.
        assert!(!msg.contains(PLACEHOLDER_CLAUSE), "not a placeholder variant, got: {msg}");
        assert!(msg.contains(ARMING_WONT_HELP), "must steer away from the flag, got: {msg}");
        // Quoted, so the trailing space is actually visible — it is invisible everywhere else.
        assert!(msg.contains("\"eip155:84532 \""), "offender must be quoted, got: {msg}");
        // Diagnosis is never admission: the guard still refuses.
        assert_eq!(err.networks, vec!["eip155:84532 ".to_string()]);
    }

    #[test]
    fn the_refusal_names_the_pin_date() {
        // Staleness is the one cause that grows by itself AND the one where the operator is right
        // that the guard is wrong. The age has to be visible where they decide about the flag.
        let err = unproven_of(check_arming(&[req("eip155:99999999")], &[]).unwrap_err());
        assert!(err.to_string().contains(PINNED_ON), "refusal must carry the pin date");
    }

    #[test]
    fn an_unarmed_mainnet_network_refuses_to_start() {
        let err = unproven_of(check_arming(&[req(BASE_MAINNET)], &[]).unwrap_err());
        assert_eq!(err.networks, vec![BASE_MAINNET.to_string()]);
        // The message must name the offender and the flag, or an operator cannot act on it.
        let msg = err.to_string();
        assert!(msg.contains(BASE_MAINNET), "must name the network, got: {msg}");
        assert!(
            msg.contains("set OBOLUS_ALLOW_MAINNET to exactly the id(s) above"),
            "must name the flag and the form its value takes, got: {msg}"
        );
        assert!(
            !msg.contains("OBOLUS_ALLOW_MAINNET=1"),
            "the retired boolean form must not be offered as the remedy, got: {msg}"
        );
    }

    #[test]
    fn the_same_mainnet_network_starts_when_armed() {
        let unproven = check_arming(&[req(BASE_MAINNET)], &[BASE_MAINNET.to_string()]).unwrap().unproven().to_vec();
        // Reported back, not swallowed: the caller needs it to print an honest banner.
        assert_eq!(unproven, vec![BASE_MAINNET.to_string()]);
    }

    #[test]
    fn a_known_testnet_starts_unarmed() {
        let unproven = check_arming(&[req("eip155:84532")], &[]).unwrap().unproven().to_vec();
        assert!(unproven.is_empty(), "Base Sepolia is on the allowlist, got {unproven:?}");
    }

    #[test]
    fn the_placeholder_default_starts_unarmed() {
        // An out-of-the-box Obolus must boot without arming anything — otherwise the first thing
        // every operator learns is how to set the mainnet flag.
        let unproven = check_arming(&[req(PLACEHOLDER_NETWORK)], &[]).unwrap().unproven().to_vec();
        assert!(unproven.is_empty(), "the default must not need arming, got {unproven:?}");
    }

    #[test]
    fn a_mainnet_entry_hidden_among_testnets_is_caught() {
        // Deliberately NOT at index 0: this fails against any implementation that checks only the
        // first requirement instead of iterating the whole advertised set.
        let reqs = [
            req("eip155:84532"),
            req("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"),
            req(BASE_MAINNET),
            req("eip155:421614"),
        ];
        let err = unproven_of(check_arming(&reqs, &[]).unwrap_err());
        assert_eq!(err.networks, vec![BASE_MAINNET.to_string()]);
    }

    #[test]
    fn an_unknown_network_refuses_to_start_unarmed() {
        // The discriminating case for allowlist-vs-denylist. This id is on no list of ours, mainnet
        // or testnet; a denylist implementation would wave it through, an allowlist refuses.
        let unknown = "eip155:99999999";
        let err = unproven_of(check_arming(&[req(unknown)], &[]).unwrap_err());
        assert_eq!(err.networks, vec![unknown.to_string()]);
    }

    #[test]
    fn every_offender_is_named_not_just_the_first() {
        let reqs = [req(BASE_MAINNET), req("eip155:84532"), req("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")];
        let err = unproven_of(check_arming(&reqs, &[]).unwrap_err());
        assert_eq!(
            err.networks,
            vec![BASE_MAINNET.to_string(), "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string()],
        );
    }

    #[test]
    fn a_case_variant_of_a_testnet_id_is_not_recognised() {
        // PINNED CURRENT BEHAVIOUR, not a wish. The comparison is byte-exact, so a case-variant
        // CAIP-2 namespace fails closed — safe, but not friendly. When #14 lands namespace-aware
        // canonicalization at `config::validated_option`, the canonical id reaches this guard and this
        // assertion should be UPDATED as an intentional consequence, not read as a regression. Verify
        // that update on **both** configuration paths; the shared per-option seam covers them by
        // construction, which is why it goes there.
        let variant = "EIP155:84532";
        assert!(!is_provably_testnet(variant));
        assert!(check_arming(&[req(variant)], &[]).is_err());
    }

    #[test]
    fn an_empty_requirement_set_is_not_this_guards_problem() {
        // `Gateway::new` already rejects an empty option set. The guard must not invent a second
        // opinion about it: nothing advertised is nothing unproven.
        assert!(check_arming(&[], &[]).unwrap().unproven().is_empty());
    }

    #[test]
    fn a_homoglyph_in_a_network_id_is_diagnosed_and_rendered_legibly() {
        // Cyrillic 'е' (U+0435) standing in for the ASCII 'e' of "eip155:84532". Byte-different,
        // visually identical — and `{:?}` does NOT escape printable non-ASCII, so the offender list
        // in the refusal renders this exactly like the correct id. Without the diagnosis clause the
        // operator sees a refusal naming what looks like a perfectly good Base Sepolia id, with all
        // three generic causes visibly false — the road to the arming flag.
        let homoglyph = "\u{435}ip155:84532";
        assert!(!homoglyph.is_ascii(), "the fixture must actually carry a non-ASCII byte");
        assert!(!is_provably_testnet(homoglyph));

        let err = unproven_of(check_arming(&[req(homoglyph)], &[]).unwrap_err());
        let rendered = err.to_string();

        // The escaped form is the whole point: `\u{435}` is the only place in this message where
        // the difference from ASCII 'e' is visible at all.
        assert!(
            rendered.contains("\\u{435}"),
            "the refusal must escape the homoglyph so it is readable; got:\n{rendered}"
        );
        assert!(rendered.contains(NON_ASCII_CLAUSE), "got:\n{rendered}");
        // It must be diagnosed as a config error, not left to the generic mainnet/typo/too-new text.
        assert!(rendered.contains(ARMING_WONT_HELP), "got:\n{rendered}");
        // The contrast is this clause's whole content for a homoglyph: `escape_debug` leaves
        // printable non-ASCII alone, so `{:?}` shows the operator what every other tool shows them,
        // and only `escape_default` shows what it really is.
        assert!(
            rendered.contains("is really"),
            "a homoglyph must be rendered as a debug-vs-escaped pair; got:\n{rendered}"
        );
    }

    #[test]
    fn a_non_ascii_space_is_both_a_near_miss_and_escaped() {
        // The two clauses are NOT mutually exclusive, and this is the case that proves it.
        // `str::trim` is Unicode-aware — U+00A0 NO-BREAK SPACE has the White_Space property — so a
        // trailing NBSP trims away and `near_miss` reports an exact hit. If the non-ASCII clause
        // were reachable only when `near_miss` misses, it would never run here, and the offender
        // would render through `escape_debug` as an ordinary-looking trailing space: the operator
        // deletes a space that was never there, retries, and gets the same refusal.
        let nbsp = "eip155:84532\u{a0}";
        assert!(!nbsp.is_ascii());
        assert!(!is_provably_testnet(nbsp));

        let err = unproven_of(check_arming(&[req(nbsp)], &[]).unwrap_err());
        let rendered = err.to_string();

        assert!(rendered.contains(NEAR_MISS_CLAUSE), "near-miss clause missing:\n{rendered}");
        assert!(rendered.contains(NON_ASCII_CLAUSE), "non-ASCII clause missing:\n{rendered}");
        assert!(rendered.contains("\\u{a0}"), "the NBSP must be escaped somewhere:\n{rendered}");
        // `escape_debug` and `escape_default` agree about U+00A0 — both escape it — so the
        // debug-vs-escaped pair the homoglyph case needs would collapse to `"X" is really "X"` here.
        // Suppressed on purpose: a message that appears to contradict itself is one an operator
        // stops trusting, and this is the message they have to trust.
        assert!(
            !rendered.contains("is really"),
            "a collapsed pair must not be printed as a contrast:\n{rendered}"
        );
    }

    #[test]
    fn an_ascii_offender_gets_no_non_ascii_clause() {
        // Teeth for the clause above: it must fire on non-ASCII and nothing else. A plain unknown
        // mainnet is pure ASCII and should reach the generic three-cause text untouched.
        let err = unproven_of(check_arming(&[req(BASE_MAINNET)], &[]).unwrap_err());
        assert!(!err.to_string().contains(NON_ASCII_CLAUSE), "got:\n{err}");
        // Same fixture is the teeth for the CAIP-2 clause: a real mainnet id has a colon, so the
        // short-name clause must stay silent. Without this the clause could fire on everything and
        // the test below would still pass.
        assert!(!err.to_string().contains(SHORT_NAME_CLAUSE), "got:\n{err}");
    }

    #[test]
    fn an_x402_short_name_is_diagnosed_as_such_not_as_a_possible_mainnet() {
        // `base-sepolia` is a genuine testnet, named the way x402's own v1 spec examples name it
        // (see the SPEC_SETTLE_* fixtures in facilitator.rs). It is refused — comparison is
        // byte-exact — so the refusal has to say *why*, or the operator reads three false causes
        // about an id they copied from the spec and the arming flag is the only actionable thing
        // left in the message.
        let err = unproven_of(check_arming(&[req("base-sepolia")], &[]).unwrap_err());
        let rendered = err.to_string();

        assert!(rendered.contains(SHORT_NAME_CLAUSE), "got:\n{rendered}");
        // The clause's worked examples survived the wording. NOT "names the id to use instead":
        // that id is hardcoded as an example of the *form*, and the clause says so in the same
        // breath, so this assertion passes for any short-name input — including `solana-devnet`,
        // whose actual replacement appears nowhere in the message.
        assert!(rendered.contains("eip155:84532"), "worked examples must survive:\n{rendered}");
        assert!(rendered.contains(ARMING_WONT_HELP), "got:\n{rendered}");
        // Not a whitespace/case slip, not non-ASCII, not empty — the other three clauses must stay
        // quiet, or this one is indistinguishable from a catch-all.
        assert!(!rendered.contains(NEAR_MISS_CLAUSE), "got:\n{rendered}");
        assert!(!rendered.contains(NON_ASCII_CLAUSE), "got:\n{rendered}");
        assert!(!rendered.contains(EMPTY_CLAUSE), "got:\n{rendered}");
    }

    #[test]
    fn a_malformed_caip2_attempt_gets_no_short_name_clause() {
        // Deliberate boundary: these carry a colon, so they are a CAIP-2 attempt, not a short name.
        // Telling an operator who typed `eip155:` that their value "looks like a short name" would
        // be a fourth wrong diagnosis, which is the failure mode this whole clause set exists to
        // avoid.
        for malformed in ["eip155:", ":84532"] {
            let err = unproven_of(check_arming(&[req(malformed)], &[]).unwrap_err());
            assert!(!err.to_string().contains(SHORT_NAME_CLAUSE), "{malformed:?} got:\n{err}");
        }
    }

    #[test]
    fn an_empty_network_is_diagnosed_as_empty_not_as_a_short_name() {
        // The short-name clause is a structural no-colon test and the empty string satisfies it, so
        // without an empty clause of its own the refusal tells an operator whose variable is empty to
        // "look up the CAIP-2 id for that chain" — naming no chain, because they named none. All four
        // clauses would then be false, which is the state this clause set exists to make impossible.
        //
        // Whitespace-only is the same defect wearing a disguise: it has no colon either, and
        // `near_miss` trims it to "" and matches nothing.
        for empty in ["", " ", "\t", "\u{a0}"] {
            let err = unproven_of(check_arming(&[req(empty)], &[]).unwrap_err());
            let rendered = err.to_string();
            assert!(
                rendered.contains(EMPTY_CLAUSE),
                "{empty:?} must be diagnosed as empty; got:\n{rendered}"
            );
            assert!(
                !rendered.contains(SHORT_NAME_CLAUSE),
                "{empty:?} is not a short name; got:\n{rendered}"
            );
        }
    }

    #[test]
    fn a_short_name_carrying_a_homoglyph_gets_both_clauses() {
        // A short name pasted from a rendered web page or a chat client. `near_miss` cannot see it —
        // `eq_ignore_ascii_case` folds only ASCII — but non-ASCII and not-CAIP-2 both fire, and
        // suppressing the later one would cost the operator a whole restart cycle: they retype the id
        // by hand as instructed, get `base-sepolia`, restart, and hit the refusal again, having spent
        // two restarts learning two facts both known at the first one.
        let err = unproven_of(check_arming(&[req("bas\u{435}-sepolia")], &[]).unwrap_err());
        let rendered = err.to_string();

        assert!(rendered.contains(NON_ASCII_CLAUSE), "got:\n{rendered}");
        assert!(rendered.contains(SHORT_NAME_CLAUSE), "got:\n{rendered}");
        assert!(rendered.contains("\\u{435}"), "got:\n{rendered}");
    }

    #[test]
    fn a_placeholder_variant_emits_both_its_clauses_and_no_false_one() {
        // The fixture is `PLACEHOLDER_NETWORK` plus one stray character — the documented default plus
        // an unquoted compose value or a YAML block scalar.
        //
        // No value can trip more than two clauses: `near_miss` only matches allowlisted ids, every one
        // of which contains a colon, so near-miss and not-CAIP-2 are mutually exclusive by
        // construction. What pins un-collapsibility is that structure (`diagnose` runs independent
        // passes; there is no chain to shorten), not this fixture's clause count.
        let variant = format!("{PLACEHOLDER_NETWORK}\u{a0}");

        // Preconditions asserted, not assumed: if any silently stopped holding, this would keep
        // passing while exercising less than its name claims.
        assert!(!is_provably_testnet(&variant), "fixture must actually be an offender");
        assert!(is_placeholder_variant(&variant), "must be a placeholder variant");
        assert!(is_non_ascii(&variant), "must carry non-ASCII");
        assert_eq!(near_miss(&variant), None, "must NOT near-miss anything on the allowlist");
        assert!(!is_not_caip2(&variant), "the placeholder is not an x402 short name");

        let err = unproven_of(check_arming(&[req(&variant)], &[]).unwrap_err());
        let rendered = err.to_string();

        // Both applicable clauses, so the overlap this fixture still demonstrates stays honest.
        assert!(rendered.contains(PLACEHOLDER_CLAUSE), "placeholder clause missing:\n{rendered}");
        assert!(rendered.contains(NON_ASCII_CLAUSE), "non-ASCII clause missing:\n{rendered}");
        assert!(rendered.contains("\\u{a0}"), "the stray NBSP must be escaped:\n{rendered}");

        // Content, not just presence — the half that was missing. Each of these was a sentence the
        // operator was told about this exact value, and each was false.
        assert!(
            !rendered.contains(NEAR_MISS_CLAUSE),
            "must not call the placeholder an allowlisted id — the header denies it:\n{rendered}"
        );
        assert!(
            !rendered.contains(SHORT_NAME_CLAUSE),
            "must not call Obolus's own default an x402 short name:\n{rendered}"
        );
        // The advice that replaced "fix the value", which led to the un-configured boot: a gateway
        // advertising the placeholder, which no facilitator has a network for.
        assert!(
            rendered.contains("Unset OBOLUS_NETWORK"),
            "must name the actual remedy:\n{rendered}"
        );
    }

    #[test]
    fn a_case_variant_of_the_placeholder_reaches_the_same_clause() {
        // The second door to the placeholder clause, with no whitespace involved:
        // `eq_ignore_ascii_case` is what catches it, so a variant that only trimmed would leave this
        // one getting all the false clauses.
        let shouted = PLACEHOLDER_NETWORK.to_ascii_uppercase();
        assert!(!is_provably_testnet(&shouted), "byte-exact comparison still refuses it");

        let err = unproven_of(check_arming(&[req(&shouted)], &[]).unwrap_err());
        let rendered = err.to_string();

        assert!(rendered.contains(PLACEHOLDER_CLAUSE), "got:\n{rendered}");
        assert!(!rendered.contains(NEAR_MISS_CLAUSE), "got:\n{rendered}");
        assert!(!rendered.contains(SHORT_NAME_CLAUSE), "got:\n{rendered}");
        assert!(!rendered.contains(NON_ASCII_CLAUSE), "pure ASCII fixture; got:\n{rendered}");
    }


    #[test]
    fn a_repeated_offender_is_named_and_diagnosed_once() {
        // Two `OBOLUS_ACCEPTS` entries can name the same bad network — `Gateway::new` would reject
        // the duplicate `(scheme, network)` pair, but this guard runs first and preempts it, so this
        // message is all the operator sees. Un-deduped it lists the id twice in the header and
        // repeats its whole ~470-character paragraph byte-identically, which reads as the message
        // being broken rather than the config.
        let err = unproven_of(check_arming(&[req("base-sepolia"), req("base-sepolia")], &[]).unwrap_err());
        let rendered = err.to_string();

        assert_eq!(err.networks, vec!["base-sepolia".to_string()], "offenders must be distinct");
        assert!(rendered.contains("advertise 1 network(s)"), "count must be distinct:\n{rendered}");
        assert_eq!(
            rendered.matches(SHORT_NAME_CLAUSE).count(),
            1,
            "the clause must appear exactly once:\n{rendered}"
        );
    }

    #[test]
    fn a_multi_offender_refusal_stays_readable_and_does_not_shout_the_flag() {
        // The composed rendering is what degrades as N grows, and every other diagnosis test here is
        // single-offender. Emitted per-offender rather than per-kind, this fixture measured at 3,377
        // characters on ONE line with `OBOLUS_ALLOW_MAINNET` appearing seven times — the term whose
        // salience this whole message layer exists to suppress, become its most repeated token.
        //
        // Both assertions are about the *shape*, deliberately loose on wording so this does not
        // become a change-detector — what must not regress is per-offender repetition returning.
        let err = unproven_of(check_arming(
            &[
                req("base-sepolia"),
                req("base-sepolia"),
                req("eip155:84532 "),
                req("solana-devnet"),
                req("arbitrum-sepolia"),
            ],
            &[],
        )
        .unwrap_err());
        let rendered = err.to_string();

        // One bullet per clause kind, not per offender: three kinds fire here (near-miss, short
        // name, and the shared closing line), over four distinct offenders.
        assert_eq!(
            rendered.matches(SHORT_NAME_CLAUSE).count(),
            1,
            "the short-name clause must be emitted once for all three short names:\n{rendered}"
        );
        assert_eq!(
            rendered.matches("\n  · ").count(),
            3,
            "one bullet per firing clause kind plus the closing line:\n{rendered}"
        );
        // Two today, both in the header and both load-bearing: the escape hatch has to be nameable
        // ("to advertise anyway, set OBOLUS_ALLOW_MAINNET to exactly the id(s) above") and warned
        // against ("do NOT reach for"). The clauses name it none. The bound allows one more for
        // headroom; anything past that is per-offender repetition creeping back, which measured at
        // seven.
        assert!(
            rendered.matches("OBOLUS_ALLOW_MAINNET").count() <= 3,
            "the flag must not gain salience with N; got {} mentions in:\n{rendered}",
            rendered.matches("OBOLUS_ALLOW_MAINNET").count()
        );
    }

    #[test]
    fn every_admitted_id_is_pure_ascii() {
        // `non_ascii_diagnosis` tells the operator that a value containing non-ASCII "can never
        // match" an admitted id. That claim holds only while this does. If x402 ever adds a testnet
        // whose CAIP-2 id carries a non-ASCII character, this test fails FIRST and the diagnosis
        // must be revisited before the id is added — otherwise the guard starts giving confidently
        // wrong advice on exactly the ids it is least able to reason about.
        for admitted in TESTNET_NETWORKS.iter().chain(std::iter::once(&PLACEHOLDER_NETWORK)) {
            assert!(admitted.is_ascii(), "{admitted:?} is not pure ASCII");
        }
    }

    // ── The witness ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn the_witness_carries_the_checked_set_and_what_was_armed() {
        // Order and duplicates preserved: the witness is the option set as handed over, and
        // `Gateway::new` is what rejects a duplicate pair.
        let reqs = [req("eip155:84532"), req(BASE_MAINNET), req("eip155:84532")];
        let witness = check_arming(&reqs, &armed(&[BASE_MAINNET])).unwrap();
        assert_eq!(witness.requirements(), &reqs[..]);
        assert_eq!(witness.unproven(), &armed(&[BASE_MAINNET])[..]);
        // The diagnosis is the one the refusal would have printed for the same ids.
        assert_eq!(witness.diagnosis(), diagnose(&armed(&[BASE_MAINNET])));
        assert_eq!(witness.clone().into_requirements(), reqs.to_vec());

        // Nothing unproven, nothing to diagnose — not even the placeholder, which is admitted.
        let clean = check_arming(&[req("eip155:84532"), req(PLACEHOLDER_NETWORK)], &[]).unwrap();
        assert!(clean.unproven().is_empty());
        assert_eq!(clean.diagnosis(), "");
    }

    // ── Arming names its target ─────────────────────────────────────────────────────────────────

    #[test]
    fn an_unset_arming_value_arms_nothing() {
        assert_eq!(parse_arming(None).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn arming_values_split_on_commas_and_are_taken_verbatim() {
        assert_eq!(parse_arming(Some(BASE_MAINNET)).unwrap(), armed(&[BASE_MAINNET]));
        assert_eq!(
            parse_arming(Some("eip155:8453,eip155:1")).unwrap(),
            armed(&[BASE_MAINNET, ETH_MAINNET])
        );
        // No trimming: the byte-exact rule applies to the arming value as it does to the
        // advertisement, so the space survives and is refused downstream, quoted, where an
        // operator can see it.
        assert_eq!(parse_arming(Some("eip155:8453, eip155:1")).unwrap(), armed(&[BASE_MAINNET, " eip155:1"]));
    }

    #[test]
    fn the_retired_boolean_form_is_refused_by_name() {
        let err = parse_arming(Some("1")).unwrap_err();
        assert_eq!(err, ArmingValueError::RetiredBooleanForm);
        let msg = err.to_string();
        assert!(msg.starts_with("OBOLUS_ALLOW_MAINNET=1 no longer arms anything"), "got: {msg}");
        assert!(msg.contains("network id(s) to arm"), "must point at the named form, got: {msg}");
        // The whitespace-adjacent forms old notes and CRLF files produce get the same pointer,
        // not the generic mismatch; a refusal either way, so this widens nothing.
        for cousin in ["1 ", " 1", "1\r", "\t1\n"] {
            assert_eq!(
                parse_arming(Some(cousin)).unwrap_err(),
                ArmingValueError::RetiredBooleanForm,
                "{cousin:?} must be recognised as the retired form"
            );
        }
        // But not the boolean's other spellings, which name no network and land in the mismatch.
        assert!(parse_arming(Some("true")).is_ok());
        assert!(parse_arming(Some("11")).is_ok());
    }

    #[test]
    fn a_set_but_empty_arming_value_is_refused() {
        assert_eq!(parse_arming(Some("")).unwrap_err(), ArmingValueError::SetButEmpty);
        assert_eq!(parse_arming(Some("  ")).unwrap_err(), ArmingValueError::SetButEmpty);
    }

    #[test]
    fn an_empty_entry_is_refused_with_its_position() {
        assert_eq!(
            parse_arming(Some("eip155:8453,")).unwrap_err(),
            ArmingValueError::EmptyEntry { position: 2 }
        );
        assert_eq!(
            parse_arming(Some(",eip155:8453")).unwrap_err(),
            ArmingValueError::EmptyEntry { position: 1 }
        );
        assert_eq!(
            parse_arming(Some("eip155:8453,,eip155:1")).unwrap_err(),
            ArmingValueError::EmptyEntry { position: 2 }
        );
    }

    #[test]
    fn a_duplicated_arming_entry_is_refused() {
        let err = parse_arming(Some("eip155:8453,eip155:1,eip155:8453")).unwrap_err();
        assert_eq!(err, ArmingValueError::Duplicate(BASE_MAINNET.to_string()));
        assert!(err.to_string().contains("\"eip155:8453\" twice"), "got: {err}");
    }

    #[test]
    fn arming_names_every_unproven_network_or_refuses() {
        // Two unproven networks advertised, one armed: the OTHER is refused — and the refusal
        // names only it, never the id the operator deliberately armed beside it.
        let reqs = [req(BASE_MAINNET), req("eip155:84532"), req(ETH_MAINNET)];
        let err = unproven_of(check_arming(&reqs, &armed(&[BASE_MAINNET])).unwrap_err());
        assert_eq!(err.networks, vec![ETH_MAINNET.to_string()]);
        assert_eq!(err.armed, armed(&[BASE_MAINNET]));
        let msg = err.to_string();
        assert!(msg.contains("\"eip155:1\""), "must name the unnamed offender, got: {msg}");
        // The remedy is "add to", naming what is already armed: an operator following "set the
        // variable to the id(s) above" literally would have dropped Base.
        assert!(
            msg.contains("add the id(s) above to OBOLUS_ALLOW_MAINNET, which already names \"eip155:8453\""),
            "the remedy must not tell the operator to overwrite an armed id, got: {msg}"
        );
        assert!(!msg.contains("set OBOLUS_ALLOW_MAINNET to exactly"), "got: {msg}");

        // Naming both starts, and reports exactly the unproven pair in advertised order.
        let both = check_arming(&reqs, &armed(&[ETH_MAINNET, BASE_MAINNET])).unwrap().unproven().to_vec();
        assert_eq!(both, armed(&[BASE_MAINNET, ETH_MAINNET]));
    }

    #[test]
    fn arming_an_unadvertised_network_is_a_mismatch() {
        // The typo case: the value names an id nothing advertises. Refused, not ignored — an
        // arming value that is wrong about itself must not be a value that "changed nothing".
        let reqs = [req(BASE_MAINNET)];
        let err = mismatch_of(check_arming(&reqs, &armed(&[BASE_MAINNET, "eip155:8543"])).unwrap_err());
        assert_eq!(err.unadvertised, armed(&["eip155:8543"]));
        assert!(err.already_testnet.is_empty());
        let msg = err.to_string();
        assert!(msg.starts_with("OBOLUS_ALLOW_MAINNET names 1 network id(s) this gateway cannot arm."), "got: {msg}");
        assert!(msg.contains("Not advertised by this gateway: \"eip155:8543\"."), "got: {msg}");
        assert!(!msg.contains("Already provably testnet"), "an empty group must leave no sentence, got: {msg}");
        // One restart, not two: the refusal says what is advertised and what the value must be.
        assert!(msg.contains("This gateway advertises \"eip155:8453\"."), "got: {msg}");
        assert!(msg.ends_with("Here that is \"eip155:8453\"."), "got: {msg}");

        // The boolean form's plausible cousins land here too: they name no network at all.
        let err = mismatch_of(check_arming(&reqs, &armed(&["true"])).unwrap_err());
        assert_eq!(err.unadvertised, armed(&["true"]));
        assert_eq!(err.advertised, armed(&[BASE_MAINNET]));
        assert_eq!(err.unproven, armed(&[BASE_MAINNET]));

        // The value right and the advertisement missing: what an operator sees when the network
        // variable did not reach the process and the placeholder is advertised instead. The remedy
        // must not be "remove the id" — it is to unset, with what arrived printed so the missing
        // variable is the obvious next question.
        let err = mismatch_of(check_arming(&[req(PLACEHOLDER_NETWORK)], &armed(&[BASE_MAINNET])).unwrap_err());
        let msg = err.to_string();
        assert!(msg.contains(&format!("This gateway advertises {}.", legible(PLACEHOLDER_NETWORK))), "got: {msg}");
        assert!(msg.ends_with("Here nothing is: unset the variable."), "got: {msg}");
        assert!(err.unproven.is_empty());

        // Nothing advertised at all reads the same way, rather than as an empty list.
        let err = mismatch_of(check_arming(&[], &armed(&[BASE_MAINNET])).unwrap_err());
        assert!(err.to_string().contains("This gateway advertises nothing."), "got: {err}");

        // Two or more to name: the quoted list is for reading, and the value is spelled out as it
        // goes into the environment — copying the quoted list with its separators would arm
        // `" eip155:1"`.
        let err = mismatch_of(
            check_arming(&[req(BASE_MAINNET), req(ETH_MAINNET)], &armed(&["eip155:8543"])).unwrap_err(),
        );
        let msg = err.to_string();
        assert!(
            msg.ends_with(
                "Here that is \"eip155:8453\", \"eip155:1\" (as one value: \
                 OBOLUS_ALLOW_MAINNET=eip155:8453,eip155:1)."
            ),
            "got: {msg}"
        );
    }

    #[test]
    fn arming_a_network_that_is_already_testnet_is_a_mismatch() {
        let reqs = [req("eip155:84532")];
        let err = mismatch_of(check_arming(&reqs, &armed(&["eip155:84532"])).unwrap_err());
        assert!(err.unadvertised.is_empty());
        assert_eq!(err.already_testnet, armed(&["eip155:84532"]));
        let msg = err.to_string();
        assert!(msg.contains("Already provably testnet, so not armable: \"eip155:84532\"."), "got: {msg}");
        assert!(!msg.contains("Not advertised"), "got: {msg}");
    }

    #[test]
    fn a_mismatch_is_reported_before_an_unarmed_offender() {
        // Both defects at once: the value names a typo AND the real mainnet goes unnamed. The
        // mismatch wins, because "your value names something that is not there" is the fact the
        // operator has to fix first — the NotProvablyTestnet remedy would tell them to set a value
        // they believe they already set.
        let reqs = [req(BASE_MAINNET), req("eip155:84532")];
        let err = mismatch_of(check_arming(&reqs, &armed(&["eip155:8543", "eip155:84532"])).unwrap_err());
        assert_eq!(err.unadvertised, armed(&["eip155:8543"]));
        assert_eq!(err.already_testnet, armed(&["eip155:84532"]));
        assert_eq!(err.advertised, armed(&[BASE_MAINNET, "eip155:84532"]));
        assert_eq!(err.unproven, armed(&[BASE_MAINNET]));
        let msg = err.to_string();
        assert!(msg.contains("names 2 network id(s)"), "got: {msg}");
        // ...and the mismatch still says what the value should have been, so the un-named mainnet
        // is learned at this restart, not the next.
        assert!(msg.contains("Here that is \"eip155:8453\""), "got: {msg}");
    }

    #[test]
    fn the_arming_comparison_is_byte_exact() {
        // A whitespace variant in the VALUE is a mismatch (unadvertised, quoted so the space shows),
        // not a match for the id it nearly spells.
        let reqs = [req(BASE_MAINNET)];
        let err = mismatch_of(check_arming(&reqs, &armed(&["eip155:8453 "])).unwrap_err());
        assert!(err.to_string().contains("\"eip155:8453 \""), "got: {err}");
        // And the reverse: a whitespace variant in the ADVERTISEMENT is not armed by the clean id —
        // which, advertised by nobody, is itself the mismatch reported.
        let err = mismatch_of(check_arming(&[req("eip155:8453 ")], &armed(&[BASE_MAINNET])).unwrap_err());
        assert_eq!(err.unadvertised, armed(&[BASE_MAINNET]));
    }
}
