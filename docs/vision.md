# Obolus — Vision

**Status:** second version, 2026-11-09. It restructures the first version (merged in
[#52](https://github.com/geekinasuit/obolus/pull/52)) and folds in the decisions made since then.
Christian has not yet reviewed this restructure. Where the [README](../README.md) describes what
obolus *is today*, this document describes where it is *going*. The [roadmap](roadmap.md) orders the
work.

**How to read this.** Statements are decisions unless marked:

- *(inference)* — follows from decisions but was not itself decided; revisit freely.
- *(open)* — an open question, listed again under [Open questions](#open-questions).
- *(deferred)* — deliberately not now; listed under [Deferred](#deferred). Don't build it, and
  don't make choices that rule it out.

Each decision cites the issue or pull request where it was made, so its reasoning can be read
there.

---

## Obolus in one paragraph

Obolus is an x402 (HTTP-402) payment-gated serving gateway: a toll booth in front of an inference
service. An unpaid request gets a real 402 challenge that states a price; the client pays per
request in a stablecoin; a facilitator verifies and settles the payment; the gateway then serves the
answer from whichever backend the request's model routes to. The goal is to make x402 serving easy:
an operator stands up a complete gateway with one command, can run it as a business, and can swap in
their own pricing, backends and policy through clean seams. The same codebase also gives x402
*client* authors a thin fake seller to test against.

## Pillars

1. **Make x402 serving easy** ([#52](https://github.com/geekinasuit/obolus/pull/52)). Lower the
   cost of selling inference over x402, so there can be more of it and more competition in it.
   A first run is one command; growing past it means swapping a seam, not forking the code.
2. **Clean, extractable seams.** Every capability — settlement, upstream serving, routing,
   pricing, access, telemetry, feature flags — sits behind a trait with swappable implementations. A seam can be
   in-process for a trivial setup or extracted into its own service for separate scaling and
   separate security, and every seam can be faked in a test.
3. **No accidental danger.** Obolus *can* take real money, but never by accident. The gateway holds
   no payment key and reaches no chain; it serves no network the arming guard has not admitted; and
   mainnet takes a deliberate, reviewed configuration that names each network
   ([#47](https://github.com/geekinasuit/obolus/pull/47),
   [#48](https://github.com/geekinasuit/obolus/pull/48)).
4. **Never charge for what wasn't served, and never serve what wasn't paid.** A request that cannot
   be routed, priced or capped is refused *before* payment; a payment is settled only after the
   upstream has committed to an answer; anything that is not a positively verified payment or token
   is asked to pay.
5. **Hermetic tests are the merge gate.** No network, no chain, no model in any test that gates a
   merge. External reality — a live facilitator, a real testnet settle, a live model — is checked out
   of band, so its flakiness cannot block the pipeline.
6. **Honest to run.** The operator can see what each request earned and cost, every refusal says
   what was wrong in words the operator can act on, and the startup banner states the posture the
   gateway actually holds.

## Who it is for

- **Operators** who want to sell inference over x402: a local model, a resold hosted API, or both.
- **x402 client authors**, who need a seller to test against that issues real challenges and fails
  on command (`obolus-devseller`).
- The first backend is local Ollama. The first rail is Base Sepolia, an EVM testnet, where a real
  payment has settled. Solana Devnet is admitted too, but no Solana payment has settled yet, and the
  reference client refuses a Solana challenge unless the operator supplies the facilitator's fee
  payer by hand ([#81](https://github.com/geekinasuit/obolus/issues/81)).

---

## Serving and settlement

- **x402 v2 only** ([#71](https://github.com/geekinasuit/obolus/issues/71)): the
  `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE` and `PAYMENT-RESPONSE` headers, with the `exact` scheme.
  Serving v1 clients alongside is wanted but waits *(deferred)*
  ([#73](https://github.com/geekinasuit/obolus/issues/73)).
- **Verification and settlement are delegated** to a facilitator behind the `Facilitator` seam
  (Phase A). The payment payload stays opaque: the gateway decodes the envelope and forwards the
  inner authorization untouched. Settlement can run in-process, as a separately secured service,
  or with a third party, in which case obolus holds no money at all.
- **Order of a paid request:** verify, start the upstream, settle once the upstream's response head
  has arrived, then stream the body. Settling before the upstream commits would charge for work that
  never happened, and there is no refund path. Settling at the head departs from the spec's §6.1
  ordering for streamed responses; the departure is disclosed in the README
  ([#101](https://github.com/geekinasuit/obolus/issues/101)).
- **A paid request's upstream wait is bounded by its payment window**
  ([#83](https://github.com/geekinasuit/obolus/issues/83)), and a facilitator's refusal is
  classified by its reason, not its HTTP status
  ([#109](https://github.com/geekinasuit/obolus/pull/109)).
- **Escrowed settlement** (x402's `auth-capture` scheme, which would let the gateway capture after
  the body) is revisited when a facilitator supports it *(deferred)*
  ([#118](https://github.com/geekinasuit/obolus/issues/118)).
- **Self-settlement (Phase B)** — our own verifier and on-chain submission — is additive behind the
  same seam and gated separately *(deferred)*.
- **Other rails:** Solana options need the facilitator's `feePayer`, which obolus neither supplies
  nor requires yet ([#81](https://github.com/geekinasuit/obolus/issues/81)). Bitcoin Lightning
  ([#80](https://github.com/geekinasuit/obolus/issues/80)) waits on a design conversation about its
  implications *(open)*.

## Backends and routing

- **The backend seam is an object-safe trait, open to third parties**
  ([#54](https://github.com/geekinasuit/obolus/issues/54)): a new backend is a trait
  implementation, not a patch to obolus.
- **Many backends from one file** ([#55](https://github.com/geekinasuit/obolus/issues/55)), each
  with an id, a kind, a base URL, an optional key file, the models it serves and a precedence.
- **Routing by model, then precedence** ([#56](https://github.com/geekinasuit/obolus/issues/56)):
  a request goes to the highest-precedence backend that serves its model. A catch-all backend is
  allowed only on its own; ambiguity is a startup error.
- **Wire formats:** `ollama` and `openai-compat` are served. `anthropic-compat` is declared and
  refused at startup until it is built.
- **Client-key pass-through** is an opt-in proxy mode, off by default: a request carrying its own
  backend key is proxied without an x402 charge, because a paid gateway should not spend its own
  budget on unpaid traffic. The key path is shaped as a fail-over, so an operator-issued bypass
  credential can be added later without reshaping it. Not built yet.
- **Non-inference backends** are not ruled out; the router is meant to grow into them *(deferred)*.

## Pricing

The design is in [`pricing.md`](pricing.md).

- **A price-determiner seam** ([#57](https://github.com/geekinasuit/obolus/issues/57)) quotes the
  amount for each advertised option; the arming guard alone decides which networks are offered.
- **Where a price comes from differs by backend:** a resold API has its own price to build on,
  while self-hosted inference needs an infrastructure-cost model instead. These are different
  algorithms behind the same seam.
- **Rates, all selectable at startup:** static (the configured amount), cost-plus (each backend's
  declared cost plus a gateway-wide margin in basis points), a time-bounded promotional discount over
  either, and per-model token rates in atomic units per million tokens
  ([#31](https://github.com/geekinasuit/obolus/issues/31)).
- **Token pricing quotes the worst case,** because `exact` settles a fixed amount: input is
  estimated as the body's bytes divided by four, rounded up, and output at the request's
  `max_tokens`. A paying request without a bounded `max_tokens` is refused, with a default cap of
  4096; the bearer-token path is not capped. Under token pricing an unrated model is refused.
- **Granularity:** per backend and per model. Per-client prices and cross-asset pricing (one price
  bridged across several assets) are *(deferred)*, for reasons given in `pricing.md`.
- **Pricing what was actually used** — output tokens beyond the estimate, the input undercount the
  estimate allows, and a remedy for large overpayment — is *(open)*
  ([#120](https://github.com/geekinasuit/obolus/issues/120)). The gateway cannot refund, since it
  holds no payment key, so the candidates are a settle-actual scheme (`upto`) or an escrow refund.
- **A free rate** waits on confirming a zero-amount settle end to end against a real facilitator
  *(deferred)* ([#67](https://github.com/geekinasuit/obolus/issues/67)).
- **Model and price listing** follows the ecosystem's leaders rather than inventing a format: the
  OpenAI `/v1/models` envelope with OpenRouter's `pricing` fields
  ([#34](https://github.com/geekinasuit/obolus/issues/34)). Not built yet.

## Access paths

- **Two ways through the same gate** ([#33](https://github.com/geekinasuit/obolus/issues/33)): an
  identified caller presents a bearer token and is served without the payment handshake; an
  anonymous caller pays per request.
- **The anonymous path is a privacy feature,** not a fallback: it is the only path that leaves no
  identity behind, so it must not become the second-class one.
- **Tokens are verified with public keys** that can check a signature but cannot mint one, so the
  gateway still holds no shared secret. Rotation over a bounded key set is shipped.
- **Per-identity quotas, revocation and fetching keys over HTTP (JWKS)** are *(deferred)*.

## Telemetry

- **One event per request** ([#58](https://github.com/geekinasuit/obolus/issues/58)), recording the
  routed backend and model, the outcome, the quote, and the derived cost and revenue. It is written
  as a JSON line on stdout and never blocks a request; lost events are counted in the stream.
  The format is in [`telemetry.md`](telemetry.md).
- **Revenue against cost is computable only under the cost-plus rate,** the one rate that requires
  every backend to declare a cost. Under the static and token rates the cost is recorded as unknown,
  so a token-priced channel shows what it earned but not whether it made money. Closing that gap is
  *(open)*, and part of [#120](https://github.com/geekinasuit/obolus/issues/120).
- **The transport behind the seam** — OpenTelemetry, a message topic, a database — is *(open)*.
- **Recording the upstream's reported usage** beside the quote is the first step of
  [#120](https://github.com/geekinasuit/obolus/issues/120) *(inference)*.

## Operating it

- **Built from source with either Bazel or Cargo,** and released as pre-built binaries from a
  reproducible `--config=release` build. An operator runs one service, or a set of them once seams
  are extracted.
- **The gateway speaks plain HTTP inbound.** TLS is terminated in front of it, so the binary holds
  no private key; [`exposure.md`](exposure.md) covers how.
- **Outbound TLS to a facilitator will be built into the gateway, in stages**
  ([#35](https://github.com/geekinasuit/obolus/issues/35)). Until then a local proxy terminates it,
  which means only the gateway's authors can deploy it today *(inference)*.
- **The MVP is stateless** ([#53](https://github.com/geekinasuit/obolus/issues/53)): configuration
  from the environment and files, telemetry fire-and-forget, no datastore. Admin UX, runtime feature
  flags and kill-switches, per-backend spend caps, and shared state for horizontal scale come after
  it, and each introduces state.
- **Feature flags are a seam too:** a provider trait, so an operator can plug in a hosted flag
  service or an alternative, with a thin built-in default for easy setup. Flags are what make
  per-backend kill-switches and spend caps possible.
- **Horizontal scale is a design target:** the gateway should stand up as scale-out nodes, with
  shared state kept outside the process.
- **How an operator declares configuration and secrets** — most of the "easy to set up" promise —
  is *(open)*.
- **What shared state horizontal scale needs, and where it lives,** is *(open)*.

## The client-testing fake

- **`obolus-devseller`** issues real challenges, verifies payments offline with the `eip3009`
  crate (itself checked against published known-answer vectors), and fails on command. It settles
  nothing, refuses any non-testnet network, and binds to loopback unless the operator explicitly
  acknowledges running an open proxy ([#104](https://github.com/geekinasuit/obolus/issues/104)).
- It is a separate package so that its signature-verification code can never enter the gateway's
  dependency graph.
- **Passing through to a real backend or testnet for end-to-end client tests** is part of the vision
  for it; the setup must stay thin *(inference)*.

---

## Architecture

These are current engineering decisions, recorded so work starts from them. Each can be revisited
through an issue when evidence calls for it. [`architecture.md`](architecture.md) has the map.

- **Rust, three crates:** the gateway (`obolus`), offline EIP-3009 verification (`eip3009`), and the
  development seller (`devseller`). `eip3009` must never be a dependency of the gateway; CI checks
  that under both builds.
- **Fakes are test-only:** the fake facilitator and fake upstream exist only under `#[cfg(test)]`,
  so no shipped binary can accept unexamined payments and serve a real model.
- **The arming guard's network list is transcribed from x402's own source** and re-checked weekly
  by a scheduled CI job ([#29](https://github.com/geekinasuit/obolus/issues/29)).
- **A gateway can only be built from requirements the arming guard admitted**
  ([#27](https://github.com/geekinasuit/obolus/issues/27)): the witness type has no public
  constructor.
- **No self-check decides whether a signer is correct.** The checks that count are ones we do not
  author: published known-answer vectors, and a real testnet settle against a third-party
  facilitator.
- **The live check runs in CI, outside the merge gate**
  ([#17](https://github.com/geekinasuit/obolus/issues/17)): after each merge to main and weekly, a
  job pays a real testnet payment to the gateway, in front of a stub backend. Its payer is a
  dedicated testnet-only key held as a secret in a GitHub Actions environment that only `main` can
  use, so no pull request can reach it. The key is created and funded by a maintainer, never by an
  agent.

## Deferred

Not now, and not to be ruled out:

- x402 v1 clients ([#73](https://github.com/geekinasuit/obolus/issues/73)).
- Escrowed settlement through `auth-capture` ([#118](https://github.com/geekinasuit/obolus/issues/118)).
- Self-settlement (Phase B).
- A free rate ([#67](https://github.com/geekinasuit/obolus/issues/67)).
- Per-client and cross-asset pricing.
- Per-identity quotas, token revocation, and JWKS over HTTP
  ([#33](https://github.com/geekinasuit/obolus/issues/33)).
- Non-inference backends.
- Operator-issued bypass credentials.

## Open questions

Each open question is, or should be, an issue; the issue is linked at the end of its item.

1. **Pricing what was used:** output beyond the estimate, the input undercount, how a token-priced
   channel reports what it cost, and a remedy for overpayment — settle-actual (`upto`), escrow
   refund, or something else — [#120](https://github.com/geekinasuit/obolus/issues/120).
2. **Refund and failure semantics:** paid, then the backend fails mid-stream. Today the client keeps
   a partial answer it paid for in full — [#118](https://github.com/geekinasuit/obolus/issues/118),
   [#120](https://github.com/geekinasuit/obolus/issues/120).
3. **Bitcoin Lightning:** what serving on Lightning implies for the design —
   [#80](https://github.com/geekinasuit/obolus/issues/80).
4. **Telemetry transport** behind the seam — no issue yet.
5. **Configuration and secrets surface** for operators — no issue yet.
6. **Shared state for horizontal scale:** what is shared (stats, flags, in-flight payments) and
   where it lives — no issue yet.
