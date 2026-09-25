# Obolus

> The obolus is the coin; Charon is the ferryman who takes it and grants the crossing.

An **x402 (HTTP-402) payment-gated serving gateway**. Obolus is the toll booth in front of an
AI or agentic service: it answers an unpaid request with a real HTTP 402 challenge, takes a
per-request USDC micropayment, and grants passage to the model behind it. The first service it
guards is local **Ollama** inference.

Tracked as [#17](https://github.com/geekinasuit/obolus/issues/17).

## Standing alone

Two rules apply to every change here:

- **Public depends only on public.** Obolus may not take a dependency on anything internal.
- **It must stand alone.** No reaching sideways into a sibling project.

## Status: Phase A, and what that means

Phase A speaks the protocol and **delegates** verification and settlement to a facilitator
behind the `Facilitator` seam. There is **no payment cryptography in this crate** — it checks no payment
signature, holds no payment key, and makes no on-chain submission. It is not mainnet-capable by
construction, because there is no signing path to misuse.

| | |
|---|---|
| **Shipped (A0–A2)** | 402 challenge, the x402 header codec — x402 v2 only since [#71](https://github.com/geekinasuit/obolus/issues/71): `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE`, with v1 support deferred to [#73](https://github.com/geekinasuit/obolus/issues/73) — the `Facilitator` and `Upstream` seams, the fakes, the wired gateway |
| **Shipped (A3 rewire)** | The real HTTP clients wired into the `obolus` binary: `DelegatedFacilitator` (delegates `/verify` + `/settle` to a facilitator you point it at) and `OllamaUpstream` (proxies a real Ollama). The fakes are now `#[cfg(test)]`-only, so no shipped binary can select "accept every payment + real model". Live-path hardening addressed: upstream head deadline ([#31](https://github.com/geekinasuit/obolus/issues/31) item 1), settle deadline derived from `maxTimeoutSeconds` (item 4), pooled-retry double-settle disabled (item 6), and a paid request's upstream wait bounded by its payment window (item 7, found real on the first live round trip; [#83](https://github.com/geekinasuit/obolus/issues/83)) |
| **Next (A3 e2e + fast-follows)** | The post-merge **cron** that settles a real testnet payment against a third-party facilitator (touches the network, so cron-only, never per-PR). Plus the remaining [#31](https://github.com/geekinasuit/obolus/issues/31) fast-follows: output/generation caps (item 2), settle-failure body drain/abort (item 3), and the 4xx-verdict contract confirmation (item 5), which needs a probe of the HTTP status a live facilitator puts on a refusal (`isValid: false` from `/verify`, `success: false` from `/settle`) |
| **Later (Phase B)** | A self-settling facilitator that verifies and submits on-chain itself — additive behind the same seam, gated separately |

The payment payload is **opaque** to Phase A: we decode the envelope (the version, and the
option the client says it `accepted`) and forward the inner authorization untouched. That boundary is what lets this ship
without crypto, and A1's types are built to preserve it.

## Layout

| File | What lives there |
|---|---|
| `obolus/src/x402.rs` | Protocol edges: the challenge we issue, the header codec, the version pin |
| `obolus/src/facilitator.rs` | The `Facilitator` seam + `DelegatedFacilitator` (real HTTP) + the test-only `FakeFacilitator` |
| `obolus/src/upstream.rs` | The `Upstream` seam + `OllamaUpstream` (real HTTP proxy) + the test-only `FakeUpstream` |
| `obolus/src/gateway.rs` | Route wiring, and the decision of *when we charge* |
| `obolus/src/telemetry.rs` | The `Telemetry` seam, the one event recorded per request, the `LineSink` that writes it as a JSON line without ever blocking a request, and the test-only `FakeTelemetry` |
| `obolus/src/main.rs` | The `obolus` binary, wired to the real facilitator + Ollama upstream (env-configured); testnet-by-construction |
| `docs/x402-ecosystem.html` | **Orientation:** what x402 is, who the participants are, the Bazaar discovery layer, and where Obolus sits on the rail. Start here if the protocol is new to you — this README assumes it |
| `docs/architecture.md` | **The map:** what Obolus is, the components and seams it is built from, and the paths a request takes — for a reader with no prior context |
| `docs/pricing.md` | **Pricing design:** how a request's price is decided — the cost-vs-quote denomination frame, the rate structures, the config, and the granularity decision |
| `docs/telemetry.md` | **Telemetry design:** the one event recorded per request, how its cost and revenue are derived, and the line format an operator's tooling reads |
| `docs/vision.md` | Product vision and the settled design directions the seams are built to honor |

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
OBOLUS_FACILITATOR_URL=http://127.0.0.1:8404/facilitator bazel run //obolus:obolus
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
(`/verify` and `/settle` are appended); it must be `http://`, because the binary has no outbound TLS
client. The public testnet facilitator (`x402.org`) is served over `https`, so reaching it means a
proxy in front of the gateway that speaks `https` on its behalf — the address in the example above
is where such a proxy would listen, and [Reaching an https facilitator](#reaching-an-https-facilitator)
gives the recipe.

Configuration is by environment variable:

| Variable | Default | Notes |
|---|---|---|
| `OBOLUS_FACILITATOR_URL` | **required** | Base URL of the x402 facilitator that verifies and settles payments (`/verify` + `/settle` appended). No default: the server refuses to start without it rather than guess where money settles. Must be `http://` (no outbound TLS client) or startup aborts; for an `https` facilitator, point this at a local TLS-terminating proxy — see [Reaching an https facilitator](#reaching-an-https-facilitator). |
| `OBOLUS_UPSTREAM_URL` | `http://127.0.0.1:11434` | Ollama origin the gateway proxies to. Origin only (scheme + host + port); the `/v1/chat/completions` path is appended. Must be `http://` — the client speaks plain HTTP only (no TLS is wired), so an `https://` or schemeless value is rejected at startup rather than 502-ing every paid request. |
| `OBOLUS_BACKENDS_FILE` | unset | **Multi-backend override.** Path to a JSON file declaring backends — an array of `{"id","kind","baseUrl", …}` objects, where `kind` is `ollama` \| `openai-compat` \| `anthropic-compat`, with an optional `keyFile` (a path to a file holding the bearer token — the key is *referenced*, never inlined), optional `models` (the aliases this backend serves) / `precedence` (higher wins when two backends serve the same model), and an optional `cost` (this backend's upstream cost in atomic units, a string, read by cost-plus pricing — see below). A request is **routed** to a backend by its `model` field; an unknown model is a clean `404` and a request naming no model is a `400`, unless a single **catch-all** backend — one declaring no `models` — is present, which serves every request (the single-backend case). A catch-all declared alongside named backends, two backends sharing an `id`, or two serving the same model at equal precedence are startup errors: the route would be swallowed or ambiguous. **Pricing can vary by backend.** Under `OBOLUS_PRICING=cost-plus` (below) each backend is quoted at its own declared `cost` plus a gateway-wide margin, so a free local model and a metered hosted one are billed differently; the default `static` rate charges each advertised option its own configured amount, unchanged. Under cost-plus **every** backend must declare a `cost` (one without is a startup error, named), and `OBOLUS_UPSTREAM_COST` — the single-backend cost — is refused alongside this file, since cost then comes per entry. Per-model and per-client rates remain later work. When set it **supersedes** `OBOLUS_UPSTREAM_URL` (and `OBOLUS_UPSTREAM_COST`), and setting **both at once is a startup error** (the single-backend value would sit inert). `ollama` is keyless (a `keyFile` on it is refused); `openai-compat` may carry a `keyFile` (a keyless one is allowed, sending no `Authorization`); `anthropic-compat` is refused as not-yet-implemented. A malformed file, an unreadable / empty / non-header-safe key file, a non-`http://` origin, a malformed or zero `cost`, or an empty `id` / model alias is a startup error, not a per-request one. Unset, the single Ollama backend is built from `OBOLUS_UPSTREAM_URL` above. |
| `OBOLUS_ADDR` | `127.0.0.1:8403` | Bind address. Must parse as a socket address or the server refuses to start. |
| `OBOLUS_RESOURCE` | `http://<ADDR>/v1/chat/completions` | The resource the 402 challenge tells the payer to pay for, so it must be an address they can actually reach. The default is derived from the bind address, which is only correct when that address is routable — **set this explicitly** behind a reverse proxy, a container port map, or a wildcard (`0.0.0.0`) bind, or the challenge advertises a resource nobody can pay for. |
| `OBOLUS_PRICE` | `1000` | Price in the asset's atomic units. Must be a non-negative integer (no decimals, sign, separators, or exponent) or the server refuses to start — an unparseable price is one no client could pay. Superseded by `OBOLUS_PRICING=cost-plus` (which sets the amount from cost and margin instead); setting it **explicitly** alongside cost-plus is a startup error, so it would sit inert. |
| `OBOLUS_PRICING` | `static` | **Selects the pricing rate.** Unset or `static` charges each advertised option its own configured amount (the rows above). `cost-plus` instead sets every request's amount from the routed backend's declared cost and a gateway-wide margin (the cost from `OBOLUS_UPSTREAM_COST` or a per-entry `cost` in the backends file; the margin from `OBOLUS_MARGIN_BPS`); any other value is a startup error, never a silent fallback to a price you did not choose. Cost-plus prices **per backend** — each backend's own cost — but the cost is still one atomic amount in one asset, so it is **single-chain only**: setting it alongside the multi-chain `OBOLUS_ACCEPTS` is a startup error (a cost is ambiguous across networks carrying different assets and decimals), as is setting it alongside an explicit `OBOLUS_PRICE` (which would sit inert). Under cost-plus every backend must declare a cost; a backend declaring a cost under any other rate is a startup error too (it would sit unread). |
| `OBOLUS_UPSTREAM_COST` | unset | The **single-backend** cost cost-plus marks up, in the asset's atomic units — attached to the sole backend at boot. Used only without a backends file; with `OBOLUS_BACKENDS_FILE` the cost is declared per entry and this variable is refused alongside it. A startup error when set without `OBOLUS_PRICING=cost-plus` (it would sit inert). A non-negative integer like `OBOLUS_PRICE`, but **zero is refused** — a zero cost is nothing to mark up, and serving free is a separate rate, not cost-plus. |
| `OBOLUS_MARGIN_BPS` | unset | The **gateway-wide** margin cost-plus adds, in **basis points** (`10000` = 100%, `2500` = 25%, `250` = 2.5%). **Required when `OBOLUS_PRICING=cost-plus`**, and a startup error otherwise. Worked example: a backend cost `1000` + `2500` bps → that backend's requests quoted **`1250`** atomic units. `0` is allowed — a break-even rate that charges the cost exactly. The markup is floored to whole atomic units, so a margin that works out to less than one unit rounds down to zero; price at an atomic scale where your margin is representable. |
| `OBOLUS_PROMO_DISCOUNT_BPS` | unset | A **promotional discount** off whichever rate `OBOLUS_PRICING` selects, in **basis points** (`2500` = 25% off) — a *modifier*, not a rate, so it layers over `static` or `cost-plus` alike. Set with the two window variables below: **all three, or none** (a partial set is a startup error). Must be in `1..10000`: `0` (discounts nothing) and `10000`+ (100% off = free, a separate rate) are both refused. During the window the quote is `floor(base × (10000 − bps) / 10000)`, rounded toward the payer; outside it the base rate stands. A payable base is never floored all the way to zero — a deep sub-100% discount that would round to `0` quotes one atomic unit instead, so a promotion never makes a request free (that is a separate rate). |
| `OBOLUS_PROMO_START` | unset | When the promotional window opens, **Unix seconds** (inclusive). Set with `OBOLUS_PROMO_DISCOUNT_BPS`. |
| `OBOLUS_PROMO_END` | unset | When the promotional window closes, **Unix seconds** (exclusive). Must be after `OBOLUS_PROMO_START` (an empty or inverted window is a startup error) and not already past at boot (an already-closed window would advertise a discount no client could get — a startup error). A window entirely in the future is fine: it discounts nothing until it opens. |
| `OBOLUS_MAX_TIMEOUT_SECS` | `300` | **The payment window.** Advertised in the challenge as `maxTimeoutSeconds`, which the reference EVM client makes the lifetime of the authorization it signs. It bounds each paid request: the upstream must send its response head within this many seconds of the request's arrival, less 15 s kept back for settling, or the request fails with a `504` and nothing is charged. Without that bound a slow completion would be served and then fail to settle against an expired authorization. It is also the basis for the settle deadline (this value + a small margin bounds one `/settle` call, so the facilitator's own advertised budget is never undercut by our client timeout). The default matches the TypeScript reference server; the spec's examples use `60`, which leaves a non-streaming completion 45 s. Whole seconds, **must be more than 15**; validated at startup. Solana payments expire with their blockhash (about 60–90 s) whatever this says. |
| `OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS` | `600` | Deadline for the upstream to send a response **head**. Generous by design: for a non-streaming request Ollama withholds the head until generation completes, so for that shape this bounds *total generation time*, not connection setup. A hang-guard against a dead upstream, not a latency policy — set it well above the slowest legitimate completion. On the paying path the payment window above bounds the same wait, and whichever is shorter fires; a bearer-token request has only this one. Whole seconds, **must be > 0** (a 0-second deadline fires immediately and 502s every request); validated at startup. |
| `OBOLUS_NETWORK` | placeholder | Obviously-fake by default; override for a real (testnet) network. |
| `OBOLUS_PAY_TO` | placeholder | Obviously-fake by default; override for a real (testnet) network. |
| `OBOLUS_ASSET` | placeholder | Obviously-fake by default; override for a real (testnet) network. |
| `OBOLUS_EXTRA` | unset | The single-chain option's `extra`: a JSON object, advertised as given. **Required when `OBOLUS_NETWORK` is an `eip155:` chain** — x402's `exact` scheme there defaults to EIP-3009 transfers, which need the token's EIP-712 domain as non-empty strings `name` and `version` (USDC on Base Sepolia: `{"name":"USDC","version":"2"}`), and a client without them cannot sign. Missing either, set-but-empty, or not a JSON object is a startup error. In a shell, single-quote the value — `OBOLUS_EXTRA='{"name":"USDC","version":"2"}'` — since unquoted the shell strips the JSON's double quotes (and, where the assignment is an argument, as to `env`, brace expansion splits it at the comma) before Obolus sees it. Obolus cannot tell whether the domain is right for the token contract: a wrong one boots, and every payment then fails at the facilitator. |
| `OBOLUS_DESCRIPTION` | `One inference request` | Free text shown in the challenge. |
| `OBOLUS_ALLOW_MAINNET` | unset | **Arming value.** Unset, Obolus refuses to start if **any** advertised `network` is not on its pinned testnet allowlist — a mainnet id, a typo, or a testnet x402 added after this build. To advertise one anyway, set this to **exactly the network id(s) to arm**, comma-separated (`eip155:8453`, or `eip155:8453,eip155:1`); the startup log then carries a `*** MAINNET ARMED ***` banner naming every armed network. The value must name every advertised unproven network and nothing else: an id the gateway does not advertise, or one already on the allowlist, is a startup refusal, and so is the retired boolean form `1`. Comparison is byte-exact, so a typo in the value fails closed. See [Refusing to advertise an unproven network](#refusing-to-advertise-an-unproven-network). |
| `OBOLUS_ACCEPTS` | unset | **Multi-chain override.** A JSON array of `{"network","asset","payTo","amount"}` objects (plus an `extra` object, advertised as given, which an `eip155:` entry must carry with the token's `name` and `version`) — one per chain — advertised together in a single 402; the client picks one to pay. When set it **supersedes** the single-chain `OBOLUS_NETWORK` / `OBOLUS_ASSET` / `OBOLUS_PAY_TO` / `OBOLUS_PRICE` / `OBOLUS_EXTRA` vars — and setting both at once is a **startup error** (the single-chain values would be inert, so the server refuses rather than advertise a config you did not intend). At most one entry per `(scheme, network)`; see [Advertising more than one chain](#advertising-more-than-one-chain). |
| `OBOLUS_TOKEN_PUBKEY_FILE` | unset | **Turns the bearer-token path on.** Path to an Ed25519 **public** key in PEM (`openssl pkey -pubout`). Unset, there is no token path at all and every caller pays — the previous behaviour. Set, a caller presenting a token this key verifies is served without paying; everyone else still gets the 402. A file that is missing or is not an Ed25519 public key is a startup error, not a per-request one — and so is setting this to an empty string, which would otherwise ask for a token path while naming no key to build one from. See [Serving without payment](#serving-without-payment). |
| `OBOLUS_TOKEN_KEYS` | unset | **The multi-key form, for rotation.** A JSON array of `{"kid": "...", "file": "..."}` objects; `kid` is optional. Supersedes `OBOLUS_TOKEN_PUBKEY_FILE`, and setting **both is a startup error** — the superseded one would sit inert, and an inert *verifying* key says nothing until a token signed with it is refused. A token naming a `kid` is checked against that key first, but a `kid` that matches nothing (or is absent) does not reject the token: it is checked against the rest of the set. At most 8 keys, no `kid` repeated, no key armed twice, every named file readable — each a startup error naming the offending entry. Set-but-empty (or whitespace-only) is its own startup error rather than the both-set one, since an array that arrived empty configures nothing. See [Rotating the signing key](#rotating-the-signing-key). |
| `OBOLUS_TOKEN_ISSUER` | **required with the keys** | The exact `iss` every honoured token must carry. Not optional and has no default: a signing key usually belongs to an identity provider rather than to one service, so with nothing to check `iss` against, every token that key has ever minted — for any audience — would buy inference here. Setting the key without this, or setting it empty, is a startup error — as is setting **this** without the key, which would otherwise be a silent no-op that 402s every caller while looking configured. |
| `OBOLUS_TOKEN_AUDIENCE` | unset | The `aud` an honoured token must carry. Set it and `aud` is both **checked and required**. **Leave it unset and a token carrying *any* `aud` is refused** — which is most IdP-issued tokens, so this is the setting to reach for when a token that should work does not. Refusing is deliberate rather than an oversight: `aud` names the service a token was minted for, and a verifier with no expected audience cannot tell "minted for us" from "minted for the wiki". Set-but-empty is a startup error, and so is setting it without `OBOLUS_TOKEN_KEYS` or `OBOLUS_TOKEN_PUBKEY_FILE`. |
| `OBOLUS_TELEMETRY` | `stdout` | **Where per-request telemetry goes.** Unset or `stdout` writes one JSON line per request to stdout, which carries nothing else (the banner and diagnostics go to stderr); `off` records nothing. Any other value is a startup error, so a typo cannot silently flip it. Every completion request writes a line, an unpaid 402 included, so the volume follows traffic you do not control: rotate or cap wherever stdout lands. The line format, and how to read revenue against cost from it, is in [`docs/telemetry.md`](docs/telemetry.md). |

`OBOLUS_ADDR`, `OBOLUS_PRICE`, `OBOLUS_MAX_TIMEOUT_SECS`, and `OBOLUS_UPSTREAM_HEAD_TIMEOUT_SECS` are
validated at startup and abort a bad launch; `OBOLUS_FACILITATOR_URL` must be present and `http://`,
and `OBOLUS_UPSTREAM_URL` (which has a valid default) must also be `http://` if overridden — the
upstream client speaks plain HTTP only, so an `https://` there fails fast rather than at request time.
When `OBOLUS_BACKENDS_FILE` is set instead, each declared backend's `baseUrl` faces that same
`http://`-only check at startup.
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
`OBOLUS_EXTRA` set but empty is refused the same way, and on an `eip155:` network leaving it unset is
refused too — there is no placeholder token domain to fall back on.

`OBOLUS_ACCEPTS` **set but empty** is a startup error too, and it is the one that matters most,
because this is the variable whose *set-ness* chooses which of the two configuration forms runs. An
empty value takes the multi-chain door and configures nothing, while still superseding every
single-chain variable — so the refusal says exactly that and tells you to unset it, rather than
handing you a JSON parser error about column 1 for a value you never meant to be JSON.

### Reaching an https facilitator

The gateway has no outbound TLS client, and the public testnet facilitator is served over `https`,
so between the two sits a proxy that accepts plain `http://` from the gateway and speaks `https://`
to the facilitator. That is a **deployment requirement, not an implementation detail.** Pointed
straight at an `https://` URL, the gateway refuses to start and says so. Pointed at a proxy that is
not running, it starts fine — the facilitator is only dialled when a payment arrives — and then
answers every paid request with a 502 while `/health` still reports OK.

One line does it with [Caddy](https://caddyserver.com/):

```bash
caddy reverse-proxy --from http://127.0.0.1:8404 --to https://x402.org --change-host-header
```

```bash
OBOLUS_FACILITATOR_URL=http://127.0.0.1:8404/facilitator bazel run //obolus:obolus
```

`--from` carries an explicit `http://` so Caddy serves plain HTTP on the loopback instead of minting
a local certificate, and `--change-host-header` rewrites `Host` to the upstream's, which a
facilitator behind a shared front end needs in order to route the request. The proxy validates the
facilitator's certificate, so peer authenticity is still checked — but by a process the gateway
cannot inspect. That is acceptable when both run on one host under one operator, and it is why an
in-process TLS client is still owed before anyone else deploys this
([#35](https://github.com/geekinasuit/obolus/issues/35)).

The proxy also sits inside the settle deadline. `OBOLUS_MAX_TIMEOUT_SECS` plus its margin bounds
one `/settle` call so that the facilitator's advertised budget is never undercut by the gateway's
own client — a proxy-side timeout shorter than that undercuts it anyway, and from the gateway's side
it is indistinguishable from the case it most wants to avoid: a 502 after the facilitator may
already have moved the money. The one-liner above sets no such timeout, and Caddy's documented
defaults are a 3-second dial timeout — which can only fire before a request is sent — and no
response-header, read, or write timeout. Keep it that way, or set anything you add above the
settle deadline.

This is **outbound** TLS: the gateway as a client. Inbound TLS — clients reaching the gateway — is a
separate question with the same answer for a different reason: it is terminated outside the process
so that the binary holds no private key. [Serving without payment](#serving-without-payment) says
what that costs on the token path, and [#26](https://github.com/geekinasuit/obolus/issues/26) tracks
the exposure guide.

## Refusing to advertise an unproven network

Obolus holds no key and signs nothing. But the 402 challenge it emits **is** the real-money trigger:
a cooperating client reads `(network, asset, pay-to)` out of it and pays against that. So "can this
gateway cause real money to move?" is answered by *what it advertises*, not by whether it holds a key.

Placeholder defaults alone do not answer it. The moment an operator overrides them with real values —
the intended path to a working gateway — nothing distinguishes a real *testnet* configuration from a
real *mainnet* one. A fat-fingered `eip155:8453` (Base mainnet) where `eip155:84532` (Base Sepolia)
was meant is a one-character slip that yields a gateway advertising a mainnet challenge.

So at startup, after the payment options are assembled and **before** the router is built, every
advertised `network` is checked against a **pinned allowlist of provably-testnet identifiers**. Any
network not on it refuses to boot unless `OBOLUS_ALLOW_MAINNET` names it.

- **Arming names its target.** The override is not a boolean: `OBOLUS_ALLOW_MAINNET` lists the exact
  network ids being armed, comma-separated, and the guard admits an unproven network only if the
  value names it. The value must also name nothing else — an id the gateway does not advertise, or
  one already on the allowlist, is refused rather than ignored — so the environment can only ever
  describe exactly what it arms, and `OBOLUS_ALLOW_MAINNET=eip155:8453` in a deployment file tells
  the reader which chain that instance is for. A process-wide `=1` admitted every advertised option
  at once, the typo two entries below the intended mainnet included, and survived every later edit to
  the network set; it is retired and refused with a pointer to this form
  ([#28](https://github.com/geekinasuit/obolus/issues/28)).
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
  belongs upstream in `config::validated_option` ([#14](https://github.com/geekinasuit/obolus/issues/14))
  — the single per-option seam **both** configuration forms go through — so the *stored* string
  becomes the canonical one.
  Not in `parse_accepts`: that is one of the two sites that build a payment option, and the other
  (the single-chain arm of `main`, which this README's own quickstart uses) would have been left
  raw.

The startup log states the resulting posture once, and only where it has been checked — one of three
lines:

| what is advertised | line |
|---|---|
| something not on the allowlist (so: armed, by name) | `*** MAINNET ARMED ***`, naming every unproven network, plus the same diagnosis the refusal gives for any of them it can diagnose |
| any advertised option carrying the built-in placeholder | `UNCONFIGURED NETWORK`, naming how many |
| a real, configured, allowlisted network set | `testnet-by-construction — every advertised network is on the pinned testnet allowlist` |

There is no "armed but nothing to arm" line, because that state cannot start: an arming value that
names a network the gateway does not advertise, or one already on the allowlist, is a refusal.

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

The last row is printed only when nothing advertised is unproven **and** nothing advertised is the
placeholder. The placeholder is deliberately absent from `TESTNET_NETWORKS` and admitted by a clause of
`is_provably_testnet` instead, so an unconfigured boot has nothing unproven and would otherwise be told
"every advertised network is on the pinned testnet allowlist" — false, in the reassuring direction. The
`UNCONFIGURED NETWORK` line takes its place there (see below).

The mainnet banner is keyed on that unproven list and never on the variable being set. There is no
way to be "armed" with only allowlisted networks advertised: such a value is a refusal (see above).
So a banner that cries mainnet on an all-testnet gateway — a log line someone would trust during an
incident — has no path that prints it.

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

All three lines are checked against the real binary by `obolus/tests/server_arming.rs`, which runs the
`obolus` target rather than calling the guard directly — `src/main.rs` is compiled by no other test
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

## Advertising more than one chain

A single Obolus can offer several chains at once — for example Base and Solana. Set `OBOLUS_ACCEPTS`
to a JSON array with one object per chain:

```json
[
  {"network": "eip155:84532", "asset": "0x…usdc", "payTo": "0x…you", "amount": "1000",
   "extra": {"name": "USDC", "version": "2"}},
  {"network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", "asset": "…usdc-mint", "payTo": "…you", "amount": "1000"}
]
```

`amount` is the price in the token's atomic units, as a decimal string. It is x402 v2's name for
what v1 called `maxAmountRequired`, and an entry still using the v1 key is refused by name rather
than read. `extra` is scheme-specific; Obolus advertises it exactly as given, and a payment must carry
every key it names, with the same value. On an EVM chain, x402's `exact` scheme transfers by
EIP-3009 unless `extra` names another `assetTransferMethod`, and EIP-3009 requires the token's
EIP-712 domain `name` and `version` there, as in the first entry — clients sign under it, and a
reference client refuses to sign without them. Obolus requires both, as non-empty strings, on every
`eip155:` entry, and refuses to start without them. Whether the values are *right* for the token
contract is not something Obolus can check; a wrong domain boots and fails at the facilitator.

The Solana entry above is not payable as written: x402's Solana `exact` client also needs
`extra.feePayer`, the facilitator's fee-paying account, which Obolus neither fills in nor requires yet
([#81](https://github.com/geekinasuit/obolus/issues/81)).

Two `extra` keys are reserved by the x402 spec rather than passed through as scheme data:
`assetTransferMethod` (how value moves) and `paymentFlow` (when settlement happens). Obolus advertises
only `exact`'s default method on the network — `eip3009` on `eip155:`, `default` on `solana:` — and only the
`authorization` flow (verify, serve, then settle). That governs what is offered, not how a payment
settles: on EVM, x402's facilitator picks the method from the shape of the payload, which Obolus does
not open. What Obolus checks is the option a client says it accepted. An `OBOLUS_ACCEPTS` entry or `OBOLUS_EXTRA` may
leave either out or name exactly that; anything else is refused at startup, and a payment that names
anything else is re-challenged.

`network` must be the **CAIP-2** `namespace:reference` id (Base Sepolia and Solana Devnet above), not
an x402 short name like `base-sepolia`. The arming guard compares byte-exactly against a CAIP-2
allowlist, so a short name refuses to boot even when it names a genuine testnet — the refusal
diagnoses it as a short name rather than blaming a mainnet, and points at `TESTNET_NETWORKS` for the
CAIP-2 form. It deliberately does **not** guess which chain you meant: the two ids it shows are
worked examples of the form, so look yours up in that list — particularly for a Solana entry, where
both worked examples are `eip155:`.

Each entry becomes one option in the 402 `accepts` array; the client chooses which to pay, and
Obolus settles against the option it **actually paid**. The gateway-wide fields — `OBOLUS_RESOURCE`,
`OBOLUS_DESCRIPTION`, `OBOLUS_MAX_TIMEOUT_SECS`, and the `exact` scheme — are shared across every
entry, so an entry names only what a chain changes. Leaving `OBOLUS_ACCEPTS` unset is exactly the old
single-chain behaviour: one option built from `OBOLUS_NETWORK` / `OBOLUS_ASSET` / `OBOLUS_PAY_TO` /
`OBOLUS_PRICE` / `OBOLUS_EXTRA`.

Two rules the startup checks enforce:

- **At most one entry per `(scheme, network)`.** A v2 payment names the whole option it accepted,
  so two entries on one network could now be told apart; whether offering several tokens on one
  network is wanted is still open ([#76](https://github.com/geekinasuit/obolus/issues/76)). Until
  it is decided, multi-chain means *distinct networks*, and a duplicate aborts startup.
- **One facilitator serves every advertised chain.** `OBOLUS_FACILITATOR_URL` is singular, so
  whatever facilitator you point at must handle all the networks you advertise (the x402.org testnet
  facilitator covers Base-Sepolia and Solana devnet). A per-network facilitator map is a later
  addition, not wired yet.

`OBOLUS_ACCEPTS` is validated at startup: a set-but-empty value, a malformed or empty array, an unknown/missing field, an
empty `network` / `asset` / `payTo` (network is the match key, so an empty one can never match a real
payment and would 402 forever; an empty asset or pay-to would advertise an option that sends money
nowhere), a missing `amount` or one that is not a plain integer, the v1 key `maxAmountRequired`,
an `extra` that is not a JSON object, an `eip155:` entry whose `extra` lacks the token's `name` or
`version`, or an `extra` naming a transfer method or payment flow Obolus does not run aborts the launch rather than advertising an unpayable or wrong challenge. Setting
`OBOLUS_ACCEPTS` **together with** any of the single-chain `OBOLUS_NETWORK` / `OBOLUS_ASSET` /
`OBOLUS_PAY_TO` / `OBOLUS_PRICE` / `OBOLUS_EXTRA` vars is likewise a
startup error, naming the ignored vars — a gateway that silently advertises a different network than
its operator configured is exactly the surprise to fail loudly on. It stays
**testnet-by-construction** the same way the single-chain vars do — Obolus has no signing path, so it
can advertise a challenge but never move funds itself. (A startup guard that refuses to *advertise* a
non-testnet network unless explicitly armed is a separate protection — see
[Refusing to advertise an unproven network](#refusing-to-advertise-an-unproven-network).)

## Serving without payment

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
distinction between token-holders. See [#33](https://github.com/geekinasuit/obolus/issues/33).

## The fake is never a gate

`FakeFacilitator` accepts payments it never examined; `FakeUpstream` serves canned bytes. Both are
now `#[cfg(test)]`-only — the `obolus` binary compiles the library without `cfg(test)`, so they are
physically absent from every shipped artifact and no configuration path can select "accept every
payment and serve the real model." They exist to drive the gateway's control flow in tests, and
nothing more.

We author both the client signer and this verifier, so "my fake accepted my payment"
is worth nothing as evidence — a shared misunderstanding of the EIP-712 domain separator or the
`transferWithAuthorization` struct hash makes both sides agree with each other while a real
facilitator still rejects. The load-bearing checks are deliberately outside our own authorship:
the published EIP-3009 / EIP-712 known-answer vector, and a real testnet settle against a
third-party facilitator. Nothing in this crate may become the thing that decides whether the
signer is correct.

`obolus-devseller` has the same blind spot in a sharper form. It verifies a payment under the
EIP-712 domain its own challenge advertised, so a client that follows the challenge always agrees
with it. A domain that is wrong for the real token contract — the wrong `name` or `version` in
`extra` — therefore passes the devseller and fails only at a real settle.
