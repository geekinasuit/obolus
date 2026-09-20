# Obolus — Vision

> Where the [README](../README.md) describes what obolus *is today* (Phase A: speak the
> protocol, delegate verify/settle behind the `Facilitator` seam), this describes where it is
> **going** and the shape it grows into. It is the north star for the roadmap tracked under
> [#17](https://github.com/geekinasuit/obolus/issues/17), not a description of shipped code.

## North star

**Make x402 serving easy.** Obolus should let anyone stand up a complete x402 (HTTP-402)
inference gateway — and run it as a business if they want — with clean seams to swap in their
own pricing, fulfillment, backends, and policy. Lower the infrastructure cost of selling
inference over x402 so there can be more of it, and more competition in it.

One codebase, two products:

- **The serving gateway** — a real, productizable x402 inference gateway an operator runs for
  money: price in the 402 reply, validate the payment, settle, then serve the inference.
- **A thin fake for client testing** — a network-layer fake so x402 *client* authors get a
  trivial test harness: serve canned fixture responses, or pass through to a real backend /
  testnet for e2e. Setup must be incredibly thin. (`obolus-devseller` is the seed of this.)

## Principles

- **Clean, extractable seams over monoliths.** Every capability — fulfillment/settlement,
  upstream serving, routing, pricing, telemetry, feature-flags — sits behind a trait with
  swappable backends. A seam can be baked in-process for trivial setup, or extracted into its
  own service for separate scaling and separate security. This is what makes obolus both easy
  to start and safe to grow, and it keeps the whole thing testable by faking a seam.
- **Safety is the absence of *accidental* danger, not the absence of capability.** Obolus
  *can* take real money — but only through a deliberate, reviewed mainnet configuration that
  can never happen by accident. The gateway crate holds no payment keys and reaches no chain;
  settlement lives behind the fulfillment seam and can be a separate, separately-secured
  service or a third party — in which case obolus holds no money at all. The arming guard
  enforces that no mainnet network is served unless explicitly and specifically allowed
  (Phase B is additive behind the same seam and gated separately; see the README).
- **Hermetic tests are the merge gate.** External reality — a live chain, a real facilitator,
  a live model — stays out-of-band so its flakiness can't block the pipeline. Seams are faked
  in tests; the live paths run out-of-band (post-merge cron, scheduled lanes).
- **Easy to start, honest to run.** Trivial defaults (in-process everything, thin built-in
  backends) so a first run is one command; accurate reporting so an operator can see whether a
  channel makes or loses money, and by how much.

## Capabilities the target includes

- **x402 serving core** — the 402 challenge, payment validation, settlement, and release of the
  served resource. (Shipped in part; see the README status table.)
- **Multi-backend mapping gateway** — route to many backends at once: local Ollama (some or all
  installed models), plus remote APIs such as Grok and Gemini via API keys. When the same model
  is offered by more than one backend, a configured **precedence order** decides who serves.
- **Pricing** — determine the quoted price per call, pluggably (see the seams below).
- **Telemetry & stats** — out-of-process, accurate reporting of throughput and, especially,
  predicted **revenue vs. cost per channel**.
- **Admin UX** — configure backends, keys, precedence, prices, and flags; see aggregated stats
  and profit/loss per channel.
- **Packaging** — buildable from source, with pre-built releases as a convenience. Run one
  service or a set.
- **API-compatibility routing** — special-case **OpenAI-API-compatible** and
  **Anthropic-API-compatible** inference, routing by model selection (or other criteria).
- **Client-key pass-through** — an operator-enabled mode where a client that supplies its own
  backend API key is proxied directly (see the design commitments below).
- **Horizontal scalability** — designed to stand up as scale-out nodes with shared state
  externalized.

## Seams (trait + swappable backends)

The extensibility model is one shape repeated: a trait per capability, with swappable backends
behind it. The trait *shape* differs by capability; the pattern does not.

- **Fulfillment** (verify + settle) — today the `Facilitator` seam; extractable to its own
  service or a third party. The gateway never signs.
- **Upstream** (serve the resource) — the inference backend(s).
- **Router / model identity** — a canonical model-id + per-backend capability/alias map, and a
  precedence order that resolves which backend serves a requested model. Special-cases
  OpenAI-compatible and Anthropic-compatible inference; non-inference backends are not
  foreclosed, but are not implemented yet.
- **Pricing / price-determiner** — emits the quoted price. Supports multiple structures:
  cost-in/margin-out, flat rate, promotional, and free. It can incorporate a backend's own
  price when there is one (a resold API), and falls back to an infra-cost model when there is
  not (self-hosted inference) — a different algorithm. Pluggable.
- **Telemetry / metrics** — out-of-process, pluggable extraction (DB, OpenTelemetry, Kafka
  topic, …) with thin defaults, feeding accurate revenue/cost reporting.
- **Feature-flags / kill-switch** — runtime-switchable config behind a provider trait (e.g.
  LaunchDarkly or an alternative), with a thin built-in default for easy setup. This is what
  makes per-backend kill-switches and spend caps possible.

## Design commitments

These are settled directions the seams above are built to honor.

- **Key-free gateway, extractable fulfillment.** The gateway crate holds no payment keys and
  reaches no chain. Settlement lives behind the fulfillment seam: run it in-process, extract it
  to a separately-secured service, or delegate to a third party — in which case obolus holds no
  money at all. The money-handling boundary stays clean, and mainnet stays deliberate.
- **Client-key pass-through is an opt-in proxy mode.** When enabled, a request that carries its
  own backend API key is proxied straight to that backend with no x402 charge — the client pays
  the upstream directly. It is **off by default**, because a paid gateway should not spend its
  own budget serving un-remunerated traffic; it is useful for local and internal use. The key
  resolution path is shaped as a fail-over — a presented key is checked, passed through if the
  mode is enabled, else rejected — so an operator-issued bypass credential can be added later
  without reshaping it.

## Open questions

- **Pricing configuration model & granularity** — the crux: *how* an operator specifies prices
  and structures, and at what level (global, per-backend, per-model, per-client).
- **Refund / failure semantics** — paid, then the backend errors or times out: refund, retry, or
  credit? An x402 business needs an answer.
- **Telemetry transport** — OpenTelemetry vs. Kafka vs. DB as the accurate-reporting backbone,
  behind the pluggable seam.
- **Config & secrets surface** — how backends, keys, precedence, prices, and flags are declared;
  this is most of the "easy to set up" promise.
- **Horizontal-scale state** — what shared state exists (stats, flags, in-flight payments) and
  where it lives.

## Not now, but not foreclosed

- Non-inference x402 serving backends — the router is designed to grow into them.
- Operator-issued bypass credentials — a credential the operator mints to authorize
  pass-through, distinct from a client presenting its own backend key.
