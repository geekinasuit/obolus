# Obolus

> The obolus is the coin; Charon is the ferryman who takes it and grants the crossing.

An **x402 (HTTP-402) payment-gated serving gateway**. Obolus is the toll booth in front of an
AI or agentic service: it answers an unpaid request with a real HTTP 402 challenge, takes a
per-request USDC micropayment, and grants passage to the model behind it. The first service it
guards is local **Ollama** inference.

Tracked as **OBOL-001**.

## Standing alone

Two rules apply to every change here:

- **Public depends only on public.** Obolus may not take a dependency on anything internal.
- **It must stand alone.** No reaching sideways into a sibling project.

## Status: Phase A, and what that means

Phase A speaks the protocol and **delegates** verification and settlement to a facilitator
behind the `Facilitator` seam. There is **no cryptography in this crate** — no signature
checking, no key handling, no on-chain submission. It is not mainnet-capable by construction,
because there is no signing path to misuse.

| | |
|---|---|
| **Shipped (A0–A2)** | 402 challenge, `X-PAYMENT` / `X-PAYMENT-RESPONSE` codec, the `Facilitator` and `Upstream` seams, the fakes, the wired gateway |
| **Shipped (A3 rewire)** | The real HTTP clients wired into the `server` binary: `DelegatedFacilitator` (delegates `/verify` + `/settle` to a facilitator you point it at) and `OllamaUpstream` (proxies a real Ollama). The fakes are now `#[cfg(test)]`-only, so no shipped binary can select "accept every payment + real model". Live-path hardening addressed: upstream head deadline (OBOL-002 item 1), settle deadline derived from `maxTimeoutSeconds` (item 4), pooled-retry double-settle disabled (item 6) |
| **Next (A3 e2e + fast-follows)** | The post-merge **cron** that settles a real testnet payment against a third-party facilitator (touches the network, so cron-only, never per-PR). Plus the remaining OBOL-002 fast-follows: output/generation caps (item 2), settle-failure body drain/abort (item 3), and the 4xx-verdict contract confirmation (item 5, observable only against a live facilitator) |
| **Later (Phase B)** | A self-settling facilitator that verifies and submits on-chain itself — additive behind the same seam, gated separately |

The payment payload is **opaque** to Phase A: we decode the envelope (version / scheme /
network) and forward the inner authorization untouched. That boundary is what lets this ship
without crypto, and A1's types are built to preserve it.

## Layout

| File | What lives there |
|---|---|
| `obolus/src/x402.rs` | Protocol edges: the challenge we issue, the header codec, the version pin |
| `obolus/src/facilitator.rs` | The `Facilitator` seam + `DelegatedFacilitator` (real HTTP) + the test-only `FakeFacilitator` |
| `obolus/src/upstream.rs` | The `Upstream` seam + `OllamaUpstream` (real HTTP proxy) + the test-only `FakeUpstream` |
| `obolus/src/gateway.rs` | Route wiring, and the decision of *when we charge* |
| `obolus/src/main.rs` | The `server` binary, wired to the real facilitator + Ollama upstream (env-configured); testnet-by-construction |
| `docs/x402-ecosystem.html` | **Orientation:** what x402 is, who the participants are, the Bazaar discovery layer, and where Obolus sits on the rail. Start here if the protocol is new to you — this README assumes it |

## Build and test

```bash
bazel test //...
```

Every test is hermetic: no network, no chain, no model. That is deliberate and is the *only*
CI that gates a merge — external reality is exercised by a post-merge cron job so its flakiness
cannot block the merge pipeline.

`//...` is a registered CI lane, and that lane runs `bazel test` with **no
`|| test $? -eq 4` tolerance**. A state with no tests is surfaced as a red lane on purpose, so
do not delete the test target without a replacement.

## Run it locally

```bash
OBOLUS_FACILITATOR_URL=http://127.0.0.1:8404/facilitator bazel run //obolus:server
```

Listens on `127.0.0.1:8403` (deliberately not 8402, which x402 client-side tooling tends to bind).
`POST /v1/chat/completions`
is payment-gated; `GET /health` is not. On startup it announces the facilitator and upstream it is
wired to, and that it is **live wiring**: payments are verified and settled by the facilitator, and
inference is proxied to the upstream. It stays **testnet-by-construction** — the pay-to / asset /
network default to obvious non-real placeholders and must be overridden for any real network, and
there is no mainnet signing path in the binary.

**`OBOLUS_FACILITATOR_URL` is required and has no default** — a payment gateway must never guess where
money settles, so the server refuses to start without it. It is the base URL of the x402 facilitator
(`/verify` and `/settle` are appended); it must be `http://` (TLS is not wired in Phase A). The address
in the example above is a **placeholder** — point it at whatever x402 facilitator you actually run. Note
that the public testnet facilitator (`x402.org`) is served over `https`, so reaching it from this
http-only client means terminating TLS in front of it — that belongs to the not-yet-built testnet e2e
rail, not this binary.

Configuration is by environment variable:

| Variable | Default | Notes |
|---|---|---|
| `OBOLUS_FACILITATOR_URL` | **required** | Base URL of the x402 facilitator that verifies and settles payments (`/verify` + `/settle` appended). No default: the server refuses to start without it rather than guess where money settles. Must be `http://` (no TLS wired) or startup aborts. |
| `OBOLUS_UPSTREAM_URL` | `http://127.0.0.1:11434` | Ollama origin the gateway proxies to. Origin only (scheme + host + port); the `/v1/chat/completions` path is appended. Must be `http://` — the client speaks plain HTTP only (no TLS is wired), so an `https://` or schemeless value is rejected at startup rather than 502-ing every paid request. |
| `OBOLUS_ADDR` | `127.0.0.1:8403` | Bind address. Must parse as a socket address or the server refuses to start. |
| `OBOLUS_RESOURCE` | `http://<ADDR>/v1/chat/completions` | The resource the 402 challenge tells the payer to pay for, so it must be an address they can actually reach. The default is derived from the bind address, which is only correct when that address is routable — **set this explicitly** behind a reverse proxy, a container port map, or a wildcard (`0.0.0.0`) bind, or the challenge advertises a resource nobody can pay for. |
| `OBOLUS_PRICE` | `1000` | Price in the asset's atomic units. Must be a non-negative integer (no decimals, sign, separators, or exponent) or the server refuses to start — an unparseable price is one no client could pay. |
| `OBOLUS_MAX_TIMEOUT_SECS` | `60` | The `maxTimeoutSeconds` advertised in the challenge **and** the basis for the settle deadline (this value + a small margin bounds one `/settle` call, so the facilitator's own advertised budget is never undercut by our client timeout). Whole seconds, **must be > 0** (a 0-second window is unpayable and would floor the settle deadline); validated at startup. |
| `OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS` | `600` | Deadline for the upstream to send a response **head**. Generous by design: for a non-streaming request Ollama withholds the head until generation completes, so for that shape this bounds *total generation time*, not connection setup. A hang-guard against a dead upstream, not a latency policy — set it well above the slowest legitimate completion. Whole seconds, **must be > 0** (a 0-second deadline fires immediately and 502s every request); validated at startup. |
| `OBOLUS_NETWORK` | placeholder | Obviously-fake by default; override for a real (testnet) network. |
| `OBOLUS_PAY_TO` | placeholder | Obviously-fake by default; override for a real (testnet) network. |
| `OBOLUS_ASSET` | placeholder | Obviously-fake by default; override for a real (testnet) network. |
| `OBOLUS_DESCRIPTION` | `One inference request` | Free text shown in the challenge. |
| `OBOLUS_ALLOW_MAINNET` | unset | **Arming flag.** Unset, Obolus refuses to start if **any** advertised `network` is not on its pinned testnet allowlist — a mainnet id, a typo, or a testnet x402 added after this build. Set to exactly `1` to advertise one anyway; the startup log then carries a `*** MAINNET ARMED ***` banner naming every unproven network. Anything other than `1` (`true`, `yes`, empty) does **not** arm — the safe direction for a typo. See [Refusing to advertise an unproven network](#refusing-to-advertise-an-unproven-network-obol-004). |
| `OBOLUS_ACCEPTS` | unset | **Multi-chain override.** A JSON array of `{"network","asset","payTo","maxAmountRequired"}` objects — one per chain — advertised together in a single 402; the client picks one to pay. When set it **supersedes** the single-chain `OBOLUS_NETWORK` / `OBOLUS_ASSET` / `OBOLUS_PAY_TO` / `OBOLUS_PRICE` vars — and setting both at once is a **startup error** (the single-chain values would be inert, so the server refuses rather than advertise a config you did not intend). At most one entry per `(scheme, network)`; see [Advertising more than one chain](#advertising-more-than-one-chain-obol-003). |
| `OBOLUS_TOKEN_PUBKEY_FILE` | unset | **Turns the bearer-token path on.** Path to an Ed25519 **public** key in PEM (`openssl pkey -pubout`). Unset, there is no token path at all and every caller pays — the previous behaviour. Set, a caller presenting a token this key verifies is served without paying; everyone else still gets the 402. A file that is missing or is not an Ed25519 public key is a startup error, not a per-request one — and so is setting this to an empty string, which would otherwise ask for a token path while naming no key to build one from. See [Serving without payment](#serving-without-payment-obol-007). |
| `OBOLUS_TOKEN_KEYS` | unset | **The multi-key form, for rotation.** A JSON array of `{"kid": "...", "file": "..."}` objects; `kid` is optional. Supersedes `OBOLUS_TOKEN_PUBKEY_FILE`, and setting **both is a startup error** — the superseded one would sit inert, and an inert *verifying* key says nothing until a token signed with it is refused. A token naming a `kid` is checked against that key first, but a `kid` that matches nothing (or is absent) does not reject the token: it is checked against the rest of the set. At most 8 keys, no `kid` repeated, no key armed twice, every named file readable — each a startup error naming the offending entry. Set-but-empty (or whitespace-only) is its own startup error rather than the both-set one, since an array that arrived empty configures nothing. See [Rotating the signing key](#rotating-the-signing-key). |
| `OBOLUS_TOKEN_ISSUER` | **required with the keys** | The exact `iss` every honoured token must carry. Not optional and has no default: a signing key usually belongs to an identity provider rather than to one service, so with nothing to check `iss` against, every token that key has ever minted — for any audience — would buy inference here. Setting the key without this, or setting it empty, is a startup error — as is setting **this** without the key, which would otherwise be a silent no-op that 402s every caller while looking configured. |
| `OBOLUS_TOKEN_AUDIENCE` | unset | The `aud` an honoured token must carry. Set it and `aud` is both **checked and required**. **Leave it unset and a token carrying *any* `aud` is refused** — which is most IdP-issued tokens, so this is the setting to reach for when a token that should work does not. Refusing is deliberate rather than an oversight: `aud` names the service a token was minted for, and a verifier with no expected audience cannot tell "minted for us" from "minted for the wiki". Set-but-empty is a startup error, and so is setting it without `OBOLUS_TOKEN_KEYS` or `OBOLUS_TOKEN_PUBKEY_FILE`. |

`OBOLUS_ADDR`, `OBOLUS_PRICE`, `OBOLUS_MAX_TIMEOUT_SECS`, and `OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS` are
validated at startup and abort a bad launch; `OBOLUS_FACILITATOR_URL` must be present and `http://`,
and `OBOLUS_UPSTREAM_URL` (which has a valid default) must also be `http://` if overridden — the
upstream client speaks plain HTTP only, so an `https://` there fails fast rather than at request time.
The `OBOLUS_PAY_TO` / `OBOLUS_ASSET` defaults are *not* validated — they are obviously-fake
placeholders (`0xTEST-…-NOT-REAL`) chosen so that if one ever reached a chain it would fail there
rather than pay a stranger. Their real (testnet) forms are supplied by the operator; no mainnet
signing path exists in this binary. `OBOLUS_NETWORK` **is** validated, by the arming guard below.

Any of `OBOLUS_NETWORK` / `OBOLUS_ASSET` / `OBOLUS_PAY_TO` **set but empty** is a startup error
naming that variable. Leaving one unset takes the placeholder default and boots un-configured, which
the log says plainly; a variable that arrived carrying nothing is a different thing — an unexpanded
`${VAR}` in a compose file, an `EnvironmentFile` line ending in `=`, an empty ConfigMap key — and an
empty `payTo` would advertise a challenge that sends money nowhere. The same check runs on
`OBOLUS_ACCEPTS` entries; both forms go through one per-option validator, so they cannot disagree.

`OBOLUS_ACCEPTS` **set but empty** is a startup error too, and it is the one that matters most,
because this is the variable whose *set-ness* chooses which of the two configuration forms runs. An
empty value takes the multi-chain door and configures nothing, while still superseding every
single-chain variable — so the refusal says exactly that and tells you to unset it, rather than
handing you a JSON parser error about column 1 for a value you never meant to be JSON.

## Refusing to advertise an unproven network (OBOL-004)

Obolus holds no key and signs nothing. But the 402 challenge it emits **is** the real-money trigger:
a cooperating client reads `(network, asset, pay-to)` out of it and pays against that. So "can this
gateway cause real money to move?" is answered by *what it advertises*, not by whether it holds a key.

Placeholder defaults alone do not answer it. The moment an operator overrides them with real values —
the intended path to a working gateway — nothing distinguishes a real *testnet* configuration from a
real *mainnet* one. A fat-fingered `eip155:8453` (Base mainnet) where `eip155:84532` (Base Sepolia)
was meant is a one-character slip that yields a gateway advertising a mainnet challenge.

So at startup, after the payment options are assembled and **before** the router is built, every
advertised `network` is checked against a **pinned allowlist of provably-testnet identifiers**. Any
network not on it refuses to boot unless `OBOLUS_ALLOW_MAINNET=1`.

- **An allowlist, not a mainnet denylist.** An id nobody anticipated — a new chain, a typo, a
  malformed string — fails *closed*. A denylist would wave all three through.
- **Every option is checked**, so a mainnet entry hiding among testnet entries in a multi-chain
  `OBOLUS_ACCEPTS` array is caught, not just the first one.
- **The allowlist is the full documented x402 testnet set**, not only the two chains we expect to
  use. This is deliberate: a shorter list would force an operator on some other genuine testnet to
  set the *mainnet* flag, and an operator who sets `OBOLUS_ALLOW_MAINNET` as routine ceremony has
  already lost the protection it exists to give. When x402 adds a testnet, **add it to the allowlist**
  (`TESTNET_NETWORKS` in `obolus/src/arming.rs`) — a reviewed code change — rather than working around it
  with the flag.
- **Comparison is byte-exact.** What the guard checks must be byte-identical to what the gateway
  advertises, or there is a gap between the verified state and the served one. A case- or
  whitespace-variant of a testnet id is therefore *not* recognised and fails closed. Normalising it
  is OBOL-005's job, and it belongs upstream in `config::validated_option` — the single per-option
  seam **both** configuration forms go through — so the *stored* string becomes the canonical one.
  Not in `parse_accepts`: that is one of the two sites that build a payment option, and the other
  (the single-chain arm of `main`, which this README's own quickstart uses) would have been left
  raw.

The startup log states the resulting posture once, and only where it has been checked — one of three
lines, plus a note when the flag is set and changed nothing:

| what is advertised | line |
|---|---|
| something not on the allowlist (so: armed) | `*** MAINNET ARMED ***`, naming every unproven network, plus the same diagnosis the refusal gives for any of them it can diagnose |
| any advertised option carrying the built-in placeholder | `UNCONFIGURED NETWORK`, naming how many |
| a real, configured, allowlisted network set | `testnet-by-construction — every advertised network is on the pinned testnet allowlist` |
| (in addition) armed, but nothing advertised is unproven | `OBOLUS_ALLOW_MAINNET is set but changed nothing here` |

The placeholder row says *any*, not *nothing was configured*, because that is what the code checks
(`placeholders > 0` — any-of, not all-of). An `OBOLUS_ACCEPTS` array holding a good Base Sepolia entry
**and** one naming the placeholder prints this line, and telling an operator it means their
configuration is absent would send them looking in the wrong place.

That check is **not** conditioned on arming. Nested inside the all-proven branch it would leave an
array carrying a real mainnet *and* a placeholder printing the mainnet banner and saying nothing about
the placeholder — the operator hearing about the dangerous half and nothing about the placeholder half,
on the one kind of instance where the money is real. Rows 1 and 2 both print when both conditions hold,
which is what makes this table a description of the code rather than of one branch of it
(`an_armed_gateway_reports_a_placeholder_option_alongside_the_mainnet_banner`).

The last row says *nothing advertised is unproven*, not *everything advertised is allowlisted*. It is
printed by an `if armed && unproven.is_empty()`, which covers **both** of the preceding states —
including `UNCONFIGURED NETWORK`, where "everything is allowlisted" is false, because the placeholder is
deliberately absent from `TESTNET_NETWORKS` and admitted by a clause of `is_provably_testnet` instead.

The flag being set is not on its own enough to print the mainnet banner — an armed instance
advertising only testnet says so plainly instead, because a banner that cries mainnet on an
all-testnet gateway is a log line someone would trust during an incident.

The armed banner runs the same diagnosis clauses the refusal does, and for the same reason: an armed
array can hold entries Obolus knows different amounts about. Of a bare `eip155:8453` it can say only
"not on the allowlist"; of a `base-sepolia` beside it, it can say the value is not a CAIP-2 id and so
could never have matched. The banner therefore says what it can name and scopes the "could be a
mainnet, a typo, or a newer testnet — Obolus cannot tell which" warning to the entries it cannot. That
warning is stated flatly only when **nothing** is diagnosable, and dropped entirely when **everything**
is: three states, three messages, because claiming a residue that does not exist is as misleading as
missing one that does.

> **Unprovable is not un-payable.** An entry this guard cannot prove is testnet is still a live rail.
> Byte-exact `(scheme, network)` matching is against the option set **this gateway advertises**, which
> is where such an entry lives — so it is published in the 402 challenge, matched when a client echoes
> it back, and settled. `an_id_the_arming_guard_cannot_prove_is_still_payable` pays one and gets a 200.
> *Obolus cannot prove this id* and *no one can pay this id* are separate properties, and only the
> first is Obolus's to assert; what a facilitator does with a short name is the facilitator's business,
> and x402's own v1 payloads use short names. This matters most on an armed gateway, where calling
> such an entry inert would tell an operator an advertised, settleable rail was dead.

The unconfigured line is separate for the same reason. `is_provably_testnet` admits the placeholder
through a clause of its own (it is deliberately *absent* from `TESTNET_NETWORKS`, so that const stays
a pure transcription of the x402 source), so an unconfigured boot would otherwise be told that "every
advertised network is on the pinned testnet allowlist" — false, and false in the reassuring
direction: an operator whose `OBOLUS_NETWORK` never reached the process would read it as confirmation
that their configuration had taken effect.

All four lines are checked against the real binary by `obolus/tests/server_arming.rs`, which runs the
`server` target rather than calling the guard directly — `src/main.rs` is compiled by no other test
target, so the guard's call site would otherwise be untested. That file also drives the
`OBOLUS_ACCEPTS` branch, not only the single-chain one: the supersession bail, a placeholder among
real entries, and a mainnet id hidden between two testnets.

The identifiers are pinned from the x402 primary source
([Networks & Token Support](https://docs.x402.org/core-concepts/network-and-token-support), read
2026-07-29), which specifies CAIP-2 `namespace:reference` form and enumerates every network in it.

Short names have not disappeared from x402 — the v1 specification's own example payloads still carry
`"network": "base-sepolia"` — and **the arming guard** deliberately cannot prove them: its comparison
is byte-exact against CAIP-2 ids, so a short name is unproven even when it names a genuine testnet, and
an instance advertising one refuses to start un-armed. Because that is a value an operator can copy
straight out of primary documentation, the refusal diagnoses it by name rather than offering the
generic "mainnet, typo, or too-new" causes, all three of which would be false.

Note the scope of that sentence: it is about what the **guard** can prove, not about what the
**gateway** will serve. Nothing downstream rejects a short name — `config::validated_option` refuses
only an empty network, so the value is advertised and matched verbatim like any other. An operator who
arms past this refusal has a live rail, not a dead one.

## Advertising more than one chain (OBOL-003)

A single Obolus can offer several chains at once — for example Base and Solana. Set `OBOLUS_ACCEPTS`
to a JSON array with one object per chain:

```json
[
  {"network": "eip155:84532", "asset": "0x…usdc", "payTo": "0x…you", "maxAmountRequired": "1000"},
  {"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", "asset": "…usdc-mint", "payTo": "…you", "maxAmountRequired": "1000"}
]
```

`network` must be the **CAIP-2** `namespace:reference` id (Base Sepolia and Solana Devnet above), not
an x402 short name like `base-sepolia`. The arming guard compares byte-exactly against a CAIP-2
allowlist, so a short name refuses to boot even when it names a genuine testnet — the refusal
diagnoses it as a short name rather than blaming a mainnet, and points at `TESTNET_NETWORKS` for the
CAIP-2 form. It deliberately does **not** guess which chain you meant: the two ids it shows are
worked examples of the form, so look yours up in that list. (Said that way on purpose — this
paragraph used to promise the refusal "names the id to use instead", which is a *per-input* property
the clause disclaims, and the reader most likely to rely on it is the one configuring the Solana
Devnet entry above, where both worked examples are `eip155:`.)

Each entry becomes one option in the 402 `accepts` array; the client chooses which to pay, and
Obolus settles against the option it **actually paid**. The gateway-wide fields — `OBOLUS_RESOURCE`,
`OBOLUS_DESCRIPTION`, `OBOLUS_MAX_TIMEOUT_SECS`, and the `exact` scheme — are shared across every
entry, so an entry names only what a chain changes. Leaving `OBOLUS_ACCEPTS` unset is exactly the old
single-chain behaviour: one option built from `OBOLUS_NETWORK` / `OBOLUS_ASSET` / `OBOLUS_PAY_TO` /
`OBOLUS_PRICE`.

Two rules the startup checks enforce:

- **At most one entry per `(scheme, network)`.** A payment envelope exposes only its
  `(scheme, network)` — the asset lives *inside* the opaque authorization Obolus never parses — so
  two entries on the same network could not be told apart, and Obolus would not know which asset to
  settle against. Multi-chain therefore means *distinct networks*, not several tokens on one network.
  A duplicate aborts startup.
- **One facilitator serves every advertised chain.** `OBOLUS_FACILITATOR_URL` is singular, so
  whatever facilitator you point at must handle all the networks you advertise (the x402.org testnet
  facilitator covers Base-Sepolia and Solana devnet). A per-network facilitator map is a later
  addition, not wired yet.

`OBOLUS_ACCEPTS` is validated at startup: a set-but-empty value, a malformed or empty array, an unknown/missing field, an
empty `network` / `asset` / `payTo` (network is the match key, so an empty one can never match a real
payment and would 402 forever; an empty asset or pay-to would advertise an option that sends money
nowhere), or a `maxAmountRequired` that is not a plain integer aborts the launch rather than
advertising an unpayable or wrong challenge. Setting `OBOLUS_ACCEPTS` **together with** any of the
single-chain `OBOLUS_NETWORK` / `OBOLUS_ASSET` / `OBOLUS_PAY_TO` / `OBOLUS_PRICE` vars is likewise a
startup error, naming the ignored vars — a gateway that silently advertises a different network than
its operator configured is exactly the surprise to fail loudly on. It stays
**testnet-by-construction** the same way the single-chain vars do — Obolus has no signing path, so it
can advertise a challenge but never move funds itself. (A startup guard that refuses to *advertise* a
non-testnet network unless explicitly armed is tracked separately as OBOL-004.)

## Serving without payment (OBOL-007)

Payment is not the only reason to serve a request. An operator running Obolus in front of their own
model wants their own clients served directly, and wants strangers to pay — so Obolus takes a bearer
token as a second way through the same gate.

Set `OBOLUS_TOKEN_PUBKEY_FILE` (and `OBOLUS_TOKEN_ISSUER`) and a caller presenting a token that key
verifies is proxied straight to the upstream: no challenge, no facilitator call, nothing settled.
Leave the key unset and there is no token path at all — every caller pays, exactly as before.

**The 402 path is the privacy-preserving one, and stays first-class.** A paying caller identifies
themselves to nobody: no account, no token, no issuer that could be asked who they are. The token
path exists because an operator's own traffic shouldn't have to round-trip through a payment rail,
not because anonymous callers are second-class. Nothing here may quietly make paying the grudging
option.

Every way the token path can fail lands on the 402 challenge, never on the upstream:

| The caller sends | Obolus does |
|---|---|
| no `Authorization` header | 402 challenge |
| a non-`Bearer` scheme, or an empty bearer value | 402 challenge |
| a token this key rejects (bad signature, wrong or missing `iss`, expired, no `exp`) | 402 challenge |
| a token carrying an `aud` value with no `OBOLUS_TOKEN_AUDIENCE` set — whatever shape that value is | 402 challenge |
| a token whose `aud` is not the one `OBOLUS_TOKEN_AUDIENCE` names, or is missing, or is not a string or array of strings | 402 challenge |
| a token while the verifier itself cannot answer | 402 challenge |
| a token this key verifies | proxies to the upstream, unpaid |

That asymmetry is deliberate. Answering 402 to a legitimate token-holder costs them a retry;
serving an unverified caller costs us the inference. So a verifier that is *broken* is treated
exactly like a token that is *bad* — the split between the two exists so the log can tell an
operator which happened, and control flow never reads it.

### Rotating the signing key

With one key there is no way to change it without a window in which every outstanding token is
refused. `OBOLUS_TOKEN_KEYS` arms several at once so the window closes:

1. Add the new key alongside the old one and restart. Both are now honoured.
2. Point the issuer at the new key. Newly minted tokens are signed with it; the ones already out
   there keep working.
3. Wait out the longest `exp` you issue. That is what drains the old key's tokens — Obolus has no
   revocation, so expiry is the only thing that retires a token.
4. Drop the old entry and restart.

The startup banner names the armed set (`2 keys: alpha, beta`), which is the check that the restart
did what you meant — a set that half-arrived is otherwise invisible until a refused token turns up.

Two things worth knowing before you plan around `kid`. It is only a **hint**: it picks which key to
try first, and a token whose `kid` names nothing we hold is still checked against every armed key,
because it arrives unverified and the signature is what actually decides. And tokens minted before
you had a second key carry no `kid` at all, which is exactly why an unmatched one cannot be grounds
for refusal — treating it as one would break the entire outstanding population at step 1.

What the verifier insists on, and why:

- **The algorithm is ours, not the token's.** `Validation` is pinned to EdDSA and the key is built
  as an Ed25519 key rather than as opaque bytes, so a token that nominates `alg: none`, or an HS256
  token signed with this public key, is refused rather than verified on its own terms. Those are two
  independent defences and either alone is sufficient.
- **`iss` must be present and must match.** The JWT library checks `iss` only on tokens that carry
  one, so requiring the claim is what turns *absent* into *rejected* — otherwise a token minted by
  that key for some entirely different service would be served here for free.
- **`aud` is checked when you configure one, and refused when you do not.** The same
  present-only-if-carried rule applies, so a configured audience is required too, and the claim is
  typed — an `aud` that is neither a string nor an array of strings is refused rather than treated
  as absent, which the JWT library on its own does not do. A literal `"aud": null` is the one
  exception, and it is the harmless one: it carries no audience, so it is treated as an `aud`-less
  token — honoured when no audience is configured, refused as a missing claim when one is. See
  `OBOLUS_TOKEN_AUDIENCE` above — **this is the setting that explains a token which "should work"
  but does not.**
- **`exp` must be present, and `nbf` is honoured.** A token with no expiry is honoured forever,
  which is not a token; one that is not valid yet is not valid.

**A bearer token is a reusable credential on a plaintext wire.** Obolus speaks `http://` only — no
TLS is wired anywhere in this binary — so anyone who can see the traffic can lift a token and replay
it until it expires, and slice 1 has no revocation. Terminate TLS in front of Obolus before any
token crosses a network you do not control, and keep token lifetimes short. The 402 path does not
have this exposure in the same way: a payment authorization is scoped to one request, whereas a
token is a standing key to the door.

Obolus still holds no key it could sign with — this one verifies someone else's signature and can
mint nothing. The Phase-A "holds no credential" posture is about key custody and signing, and is
intact.

Not in this slice: revocation, token minting, per-token rate limits or accounting, and any
distinction between token-holders. See OBOL-007.

## The fake is never a gate

`FakeFacilitator` accepts payments it never examined; `FakeUpstream` serves canned bytes. Both are
now `#[cfg(test)]`-only — the `server` binary compiles the library without `cfg(test)`, so they are
physically absent from every shipped artifact and no configuration path can select "accept every
payment and serve the real model." They exist to drive the gateway's control flow in tests, and
nothing more.

We author both the client signer (STORY-056) and this verifier, so "my fake accepted my payment"
is worth nothing as evidence — a shared misunderstanding of the EIP-712 domain separator or the
`transferWithAuthorization` struct hash makes both sides agree with each other while a real
facilitator still rejects. The load-bearing checks are deliberately outside our own authorship:
the published EIP-3009 / EIP-712 known-answer vector, and a real testnet settle against a
third-party facilitator. Nothing in this crate may become the thing that decides whether the
signer is correct.
