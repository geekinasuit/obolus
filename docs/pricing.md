# Obolus — Pricing

This document describes how Obolus decides what a request costs: the design of the pricing
subsystem, the rate structures it supports, how an operator configures them, and the one
question that governs the whole design — *in what units is a price even expressed?*

It assumes the gateway model from [`architecture.md`](architecture.md) (routing, the arming
guard, the seams). It marks clearly what is built today and what is planned.

## The frame: cost and quote are two different denominations

Every pricing decision spans two quantities that are easy to conflate and must not be:

- **Cost** — what serving a request costs *the operator*. A local model has an infrastructure
  cost; a resold API (Grok, Gemini) has a wholesale price the operator pays upstream. Cost is a
  fact about the *supply side*, and it naturally varies by backend, and ultimately by model.
- **Quote** — what the *client* pays, for one advertised payment option, on one chain, in one
  asset. A quote is denominated in **that asset's atomic units** — the smallest indivisible unit
  of the token, e.g. 1 USDC on a 6-decimal chain is 1,000,000 atomic units.

The gateway's job at the seam is to produce a *quote*, in the *requirement's* asset's atomic
units. So a rate that reasons about cost has to cross from one denomination to the other, and
**that crossing needs a denomination assumption**:

> How many atomic units of *this chain's asset* is one unit of *my cost*?

When the gateway advertises exactly one chain, that assumption is trivial: there is one asset, so
"cost in atomic units" and "quote in atomic units" are the same units, and the crossing is the
identity. This is why the cost-plus rate (below) is **single-chain only** — not an arbitrary
limit, but the precise condition under which "cost in atomic units" is well-defined.

When the gateway advertises several chains carrying different assets and decimals, the crossing is
a real conversion — a reference cost unit plus a per-chain rate — and that is deferred work with
its own design (see [Deferred](#deferred-work) below). Keeping the two denominations distinct is
what makes that future work legible as a *bridge* to build, rather than a feature that is somehow
missing.

```mermaid
flowchart LR
  cost["<b>Cost</b><br/>what serving costs the operator<br/>(per backend, per model)"]
  bridge{"denomination<br/>crossing"}
  quote["<b>Quote</b><br/>what the client pays<br/>(per network/asset, atomic units)"]
  cost --> bridge --> quote
  bridge -. "single-chain: identity (one asset)" .-> single["shipped"]
  bridge -. "multi-chain: reference unit + per-chain rate" .-> multi["deferred"]
```

## The seam

Pricing is a seam: a `PriceDeterminer` chosen at boot decides the amount for one advertised
payment requirement.

```rust
struct PriceContext<'a> {
    model: Option<&'a str>,   // the model the request named, if any
    backend: &'a Backend,     // the backend it routed to (id, kind, models, precedence, …)
    requirement: &'a PaymentRequirements, // the one advertised option being priced
}

trait PriceDeterminer: Send + Sync {
    fn quote(&self, ctx: PriceContext<'_>) -> u128;
}
```

Three properties are load-bearing:

- **A determiner prices the amount and nothing else.** It sees the requirement it is pricing but
  does not choose it — scheme, network, asset, and pay-to are copied through untouched by the
  caller. So a determiner cannot add, drop, or alter an advertised network; the arming guard
  remains the sole authority over which networks are offered. The seam widens *pricing*, not the
  attack surface.
- **Every price it can return is payable.** `quote` returns a `u128`, not a string. A `u128` is by
  definition a non-negative integer in atomic units — exactly what a configured amount is
  validated to be. A determiner therefore cannot compute a quote no conforming client could pay,
  and there is no revalidation step to forget.
- **`quote` must be total, and cheap.** It runs on the request path — including when a 402 is
  issued to an *unpaid* request, to state the challenge amount — so it is reachable by unpaid
  traffic. A panic there is a 500 charged to no one; an expensive or blocking `quote` is a
  denial-of-service surface a custom determiner could open. Determiners return a price on every
  input, quickly and without blocking; the fallible cases fail *closed* (see below), never by
  unwrapping into the hot path.

The determiner is called **once per advertised requirement**, on **every request except the token
bypass** — the bypass returns before pricing is ever consulted, but an unpaid request that gets a
402 is priced, because the challenge has to state the amount. It already receives the routed
`backend` and the request's `model`, so per-backend and per-model policies have the context they
need without any further plumbing.

## Rate structures

### Shipped

**`StaticPrice` — the identity default.** Quotes each requirement at its own configured amount.
This is the behavior a gateway has with no pricing configured: the price is whatever the armed
requirement carried. Its one fallible case — an amount that does not parse as `u128` — quotes
`u128::MAX`, which no client can pay. That is deliberate: a bug must fail closed (refuse to serve)
rather than open (serve for free).

**`FlatPrice` — one rate for everything.** Every advertised requirement is quoted the same amount,
regardless of model, backend, or network. The flat-rate seller's policy: a single price to use
the gateway, whichever chain the client pays on. It exists as a library rate — the `OBOLUS_PRICING`
config door (below) does not yet offer a `flat` selector, so an operator reaches it only in code,
not by configuration.

**`CostPlus` — cost-in, margin-out.** The "run it for money" rate. Each backend declares what a
request to it costs the operator upstream, and every request is quoted at the *routed backend's*
cost plus a gateway-wide margin:

```
quote = cost + floor(cost * margin_bps / 10000)
```

The margin is in **basis points** — `10000` bps = 100%, `2500` = 25%, `250` = 2.5%. Basis points,
not a percentage or a float, so the margin is an exact integer with sub-percent precision and no
float ever enters the money path. The *markup* is in whole atomic units and floored, so a markup
that works out to less than one atomic unit rounds down to zero — the quote is only ever rounded
toward the payer, and by less than one atomic unit. A `0` bps margin quotes the cost exactly, a
legitimate break-even rate. The arithmetic saturates: an absurd cost×margin that would overflow
`u128` yields a quote near the maximum — unpayable — the same fail-closed direction as
`StaticPrice`'s unparseable guard.

The cost is read per request from the routed backend, so two requests routed to backends with
different costs are quoted differently through the one rate; the margin is shared across all of
them. As shipped, cost-plus is **per-backend and single-chain**: each backend's own cost, one
gateway-wide margin, on the single advertised chain. Per the [frame](#the-frame-cost-and-quote-are-two-different-denominations),
one atomic cost is well-defined only against one asset — so the *cost* varies by backend but the
*denomination* does not. How costs are declared, and the boot refusals that keep every backend
covered, are in [The granularity decision](#the-granularity-decision) below.

### Planned

**Promotional and free.** A promotional rate (a temporary discount) and a genuinely free rate.
Free is not just "quote zero" — a zero quote reaches a settle-a-zero-amount path that the paid
flow does not exercise today, so it needs that path confirmed end-to-end first. It is a distinct
rate, not a degenerate cost-plus, which is why cost-plus refuses a zero cost rather than treating
it as free.

## Configuration

The pricing rate is selected by environment variables, parsed at boot by `select_pricing`.

| Variable | Meaning |
|---|---|
| `OBOLUS_PRICING` | The rate: unset or `static` (the default — each option keeps its own configured amount), or `cost-plus`. |
| `OBOLUS_UPSTREAM_COST` | Cost-plus, single-backend only: the sole backend's cost, in atomic units. With a backends file the cost is declared per entry instead (a `"cost"` on each backend), and this variable is refused alongside the file. |
| `OBOLUS_MARGIN_BPS` | Cost-plus only: the gateway-wide margin, in basis points (`10000` = 100%). Required under `cost-plus`. |

The cost is declared where the backend is: `OBOLUS_UPSTREAM_COST` for the single-backend
(env-configured) gateway, or a per-entry `"cost"` in `OBOLUS_BACKENDS_FILE` for a multi-backend
one. See [The granularity decision](#the-granularity-decision) for the shape and its refusals.

### Boot refusals

A gateway that priced wrongly — or advertised an amount it would not charge — is worse than one
that will not start. Every misconfiguration below is a boot refusal, fired **before** the banner,
so a refused configuration never first advertises anything (the same discipline the arming guard
follows). The rate parameters, not a computed quote, are what the banner prints when the gateway
does start: per-backend cost makes quotes vary, so a single boot-time number would drift — the
margin is stated once on the rate line and each backend's cost on its own line.

- **Unknown rate.** `OBOLUS_PRICING` names something that is neither `static` nor `cost-plus`
  (a typo, or an unexpanded `${VAR}` that arrived empty) — refused rather than guessed, so a
  mistyped rate never silently falls back to a price the operator did not choose.
- **Missing / malformed / zero cost or margin.** Cost-plus infers no money value, so a missing
  margin is a refusal, not a default; a missing *cost* is refused too, but as a coverage check
  over the backends (below), since the cost lives on the backend. A zero cost is refused
  specifically: there is nothing to mark up (any margin on zero is still zero), and a zero quote
  would reach the deferred zero-settle path. Serving free is a separate rate, not cost-plus.
- **Cost-plus with a backend that declares no cost.** The rate marks up each backend's own cost,
  so every backend needs one; guessing a cost is the fail-open these refusals exist to prevent.
  Refused, naming the backends that lack a cost. (This is the cross-source coverage check described
  under [the granularity decision](#the-granularity-decision) — it needs both the rate and the
  registry, so it does not live in `select_pricing`.)
- **A backends file alongside `OBOLUS_UPSTREAM_COST`.** With a file, cost is declared per entry, so
  the single-backend variable would sit inert. Refused unconditionally on presence — mirroring the
  existing refusal of a backends file alongside `OBOLUS_UPSTREAM_URL`.
- **Cost-plus alongside multi-chain `OBOLUS_ACCEPTS`.** One declared cost is ambiguous across
  several networks carrying different assets and decimals — the denomination crossing this rate
  does not yet make. Cost varies by *backend*, but a single backend's cost is still one atomic
  amount in one asset; several assets is the deferred cross-asset work. Refused until per-chain
  cost lands.
- **Cost-plus alongside an explicit `OBOLUS_PRICE`.** Under cost-plus the amount comes from cost
  and margin, so a configured price would sit inert — the silently-ignored-config surprise. Keyed
  on whether the price was *explicitly set*, so an operator who never set it (and gets its
  default) is not refused on a default they do not know exists.
- **Orphaned cost-plus parameters.** `OBOLUS_UPSTREAM_COST` / `OBOLUS_MARGIN_BPS` set without
  `cost-plus` selected would sit inert — refused rather than dropped. Its per-backend twin: a
  backend that declares a `"cost"` under a non-cost-plus rate is refused too, naming the entry.

## The granularity decision

The vision names an open question: *at what level does an operator specify prices — global,
per-backend, per-model, per-client?* The [frame](#the-frame-cost-and-quote-are-two-different-denominations)
resolves it by separating the axes.

**Decided:**

- **Per-backend cost** is the level built (and now shipped). It is the concrete operator need —
  resold APIs and local models have genuinely different costs — and it fit the seam and registry
  unchanged (`PriceContext` already carries the routed backend).
- **Margin stays gateway-wide.** Margin is a business policy, not a per-backend fact. Per-backend
  margin is a trivial later addition if a need appears; it is not built now.

**Deliberately deferred, with the reason:**

- **Per-model cost.** The seam already carries `model`, so this is a config-shape question, not a
  structural one. Deferred because a backend commonly maps to one upstream pricing tier, and
  per-model cost multiplies configuration for a need that has not yet appeared. Deferring it costs
  nothing structurally.
- **Per-client pricing.** Needs a notion of client identity that the stateless gateway does not
  have. Out of scope for the current milestone.
- **Cross-asset (multi-chain) cost-plus.** The denomination crossing. See below.

### How per-backend cost is declared

Cost is a fact about a backend, so it is declared with the backend. This follows the config model
already in place, where a multi-backend gateway is defined by a JSON file and a single-backend
gateway by environment variables:

- **Single-backend (no backends file).** `OBOLUS_UPSTREAM_COST` is the sole backend's cost — the
  gateway-wide value *is* per-backend when there is one backend. `main` attaches it to that
  backend at boot.
- **Multi-backend (`OBOLUS_BACKENDS_FILE`).** Each backend entry declares its own `"cost"`, in
  atomic units, as a string (an atomic amount can exceed the range a JSON number represents
  exactly, and every other atomic amount in the config is already a string). `OBOLUS_MARGIN_BPS`
  stays gateway-wide.

Two boot refusals guard this, each modeled on a rule already shipped:

- **A backends file set alongside `OBOLUS_UPSTREAM_COST`** is refused, unconditionally: if a file
  is present, cost comes from the file. This mirrors the refusal of a backends file alongside
  `OBOLUS_UPSTREAM_URL` — the file supersedes the single-backend variables.
- **Under cost-plus, every backend in the registry must declare a cost.** A backend without one
  cannot be marked up, and guessing a cost is exactly the fail-open the boot refusals exist to
  prevent. The refusal names the backends that are missing a cost, so an operator knows what to
  fix. A malformed or zero per-entry cost is refused where the backend entry is validated (the
  same place a bad `baseUrl` is caught), naming the offending backend — so the cost-coverage check
  is the clean question "is a cost present on every backend," not "present and parseable." Its
  mirror image also holds: a backend that declares a cost under a non-cost-plus rate is refused,
  since the cost would sit unread.

### Where the checks live in the boot sequence

Per-backend cost is declared in the backends file but the rate is selected from the environment,
so cost *completeness* is a cross-source check: it needs both the parsed registry and the selected
rate. It cannot live inside `select_pricing`, which sees the environment only. It is a distinct
validation stage (`require_backend_costs`), run after both parses and before the banner. The two
stages per-backend cost adds to the boot are the per-entry cost parsing (in the registry build)
and this cross-source coverage check.

```mermaid
flowchart TB
  be["build backends registry<br/>(per-entry cost parsed + validated here —<br/>malformed / zero cost refused, names the id)"] --> reqs["parse payment requirements"]
  reqs --> sel["select_pricing (env)<br/>rate + gateway-wide margin"]
  sel --> cov{"require_backend_costs:<br/>cost-plus → every backend has a cost?<br/>other rate → no backend has a cost?"}
  cov -->|"no → name the offending ids"| refuse(["refuse to start"])
  cov -->|"yes"| arm["check_arming → witness"]
  arm --> gw["build gateway + install determiner"]
  gw --> banner["banner (rate parameters, not a quote)"]
```

## Deferred work

**Cross-asset (multi-chain) cost-plus — the denomination bridge.** To price cost-plus across
several chains, a declared cost has to be denominated in a **reference unit** (say, a fiat cost or
a chosen reference asset), and each advertised chain needs a **conversion rate** from that
reference unit to the chain's atomic units. That conversion is the real design work: it needs a
rate source, and it introduces staleness (a rate is only as good as its last update) and
cross-decimal rounding — both of which must fail closed (a stale or missing rate refuses to quote
rather than guessing). Until that bridge exists, cost-plus stays single-chain and the multi-chain
combination is refused at boot. The single-chain restriction is not a wart to remove; it is the
absence of a bridge that has not been designed.

**Per-model and per-client cost**, as above — supported by the seam, deferred by config scope.

**Refund / failure semantics.** Paid, then the backend errors or times out: refund, retry, or
credit? The gateway has no refund path today and refuses to charge for work it cannot route, but a
mid-stream failure after settlement is an open question an x402 business ultimately has to answer.
It is a settlement-path concern, adjacent to pricing but not decided by it.
