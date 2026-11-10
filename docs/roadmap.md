# Obolus — Roadmap

**Status:** proposed, 2026-11-10. Christian has settled the order of Milestones 3–6 and the shape of
Milestone 3; the document as a whole awaits his review. Milestones 0–2 describe work that has
already merged. Later milestones are a sequence, not a commitment, and get their detail when the
milestone before them is under way.

## How milestones are cut

- A **milestone** is a package of demonstrable work. It ends with a demo Christian can run and
  review.
- Every milestone builds only on what the [vision](vision.md) marks as decided. Items it marks open
  or deferred stay out until an issue settles them.
- Open design questions are settled one milestone **before** the milestone that needs them, so each
  milestone names the design talks it carries for the next one.
- One milestone is active at a time. Each is tracked twice on this repository: a GitHub milestone
  holds its issues, and an epic issue holds its demo, its definition of done and the discussion.

## Milestone 0 — Foundation (complete)

The gateway and the `eip3009` verifier imported as a standalone public repository
([#1](https://github.com/geekinasuit/obolus/pull/1)); the Bazel and Cargo builds both gated in CI,
on Linux and macOS ([#3](https://github.com/geekinasuit/obolus/pull/3),
[#6](https://github.com/geekinasuit/obolus/pull/6)); release binaries from a reproducible build
([#5](https://github.com/geekinasuit/obolus/pull/5),
[#7](https://github.com/geekinasuit/obolus/pull/7)); tickets, research and plans moved to GitHub
issues ([#8](https://github.com/geekinasuit/obolus/pull/8)); and `obolus-devseller`, the seller to
test a client against ([#4](https://github.com/geekinasuit/obolus/pull/4)).

## Milestone 1 — A real 402 in front of a real model (demo held; closes with Milestone 3)

**Demo:** a client pays a real testnet payment through a third-party facilitator and gets an answer
from local Ollama. Held by hand on 2026-09-24 on Base Sepolia.

Epic: [#17](https://github.com/geekinasuit/obolus/issues/17) (Phase A).

Built: the protocol edges and header codec; the `Facilitator` and `Upstream` seams with test-only
fakes; the real delegating facilitator and Ollama proxy; the arming guard, scoped mainnet arming,
and the type that makes an unarmed gateway unconstructable
([#47](https://github.com/geekinasuit/obolus/pull/47),
[#48](https://github.com/geekinasuit/obolus/pull/48)); a weekly check that the guard's network list
still matches x402's source ([#50](https://github.com/geekinasuit/obolus/pull/50),
[#51](https://github.com/geekinasuit/obolus/pull/51)); x402 v2
([#74](https://github.com/geekinasuit/obolus/pull/74) to
[#84](https://github.com/geekinasuit/obolus/pull/84)); and the live-path hardening the round trip
called for ([#85](https://github.com/geekinasuit/obolus/pull/85),
[#90](https://github.com/geekinasuit/obolus/pull/90),
[#109](https://github.com/geekinasuit/obolus/pull/109)).

Phase A's last item, the round trip repeated automatically, is Milestone 3.

## Milestone 2 — Someone can run this for money (built; demo review pending)

**Demo:** one gateway in front of local Ollama and a hosted OpenAI-compatible backend. A request is
routed by its model under a precedence order and priced per backend (cost-plus) or per model (token
rates), and each request writes a telemetry line with what it earned. Under cost-plus the line also
shows what it cost, so an operator can see whether a backend makes money; under token rates the
cost is unknown, which Milestone 5's design talk takes up.

Epic: [#53](https://github.com/geekinasuit/obolus/issues/53).

Built: an object-safe backend seam ([#59](https://github.com/geekinasuit/obolus/pull/59)); many
backends from one file ([#60](https://github.com/geekinasuit/obolus/pull/60)); routing by model and
precedence ([#61](https://github.com/geekinasuit/obolus/pull/61)); the pricing seam, cost-plus,
per-backend cost and promotional rates ([#62](https://github.com/geekinasuit/obolus/pull/62) to
[#68](https://github.com/geekinasuit/obolus/pull/68)); telemetry
([#69](https://github.com/geekinasuit/obolus/pull/69),
[#70](https://github.com/geekinasuit/obolus/pull/70)); token pricing with an output cap
([#121](https://github.com/geekinasuit/obolus/pull/121) to
[#129](https://github.com/geekinasuit/obolus/pull/129)); and a batch of operator-facing hardening —
escaped startup output, refusal ordering, settlement receipts on refusal, the exposure guide
([#91](https://github.com/geekinasuit/obolus/pull/91) to
[#110](https://github.com/geekinasuit/obolus/pull/110)).

Left out: the free rate ([#67](https://github.com/geekinasuit/obolus/issues/67)), deferred until a
zero-amount settle is confirmed against a real facilitator.

## Milestone 3 — The live check runs itself (next)

**Demo:** after a merge to main, and once a week regardless, a GitHub Actions job starts the
gateway built from main in front of a stub backend, pays it a real Base Sepolia payment through the
`https://` x402.org facilitator with no proxy in between, and records the settlement's transaction
hash in its run. A broken settle path turns the run red. This closes Phase A
([#17](https://github.com/geekinasuit/obolus/issues/17)).

Epic: [#134](https://github.com/geekinasuit/obolus/issues/134).

Builds:

- an outbound TLS client for the facilitator, with an explicit trust-store posture
  ([#35](https://github.com/geekinasuit/obolus/issues/35)), and the startup-log redaction that must
  land before it ([#15](https://github.com/geekinasuit/obolus/issues/15));
- a stub OpenAI-compatible backend for the job, returning a canned answer: the payment path is
  under test, not the model;
- the paying client, pinned to exact versions of the reference x402 client;
- the workflow, run on pushes to main and weekly, reading the payer key from a GitHub Actions
  environment that only `main` can use, so no pull request can reach it
  ([#133](https://github.com/geekinasuit/obolus/issues/133)).

Decided: the payer is a new testnet-only key used for nothing else. Christian creates it, funds it
and stores it as the environment's secret; no agent handles the key. Each run moves about 0.001
testnet USDC.

Design talks carried for Milestone 4: none needed.

## Milestone 4 — Deployable by someone else (proposed)

**Demo:** someone who is not one of the gateway's authors downloads a release binary, follows the
README, points it at an `https://` testnet facilitator, and completes a paid round trip.

Builds:

- escaping operator text by construction rather than per call site
  ([#94](https://github.com/geekinasuit/obolus/issues/94)), bounding the facilitator's strings in a
  receipt ([#95](https://github.com/geekinasuit/obolus/issues/95)), and escaping bidirectional
  controls in telemetry ([#124](https://github.com/geekinasuit/obolus/issues/124));
- the configuration bugs that would confuse a new operator
  ([#127](https://github.com/geekinasuit/obolus/issues/127),
  [#128](https://github.com/geekinasuit/obolus/issues/128),
  [#130](https://github.com/geekinasuit/obolus/issues/130),
  [#14](https://github.com/geekinasuit/obolus/issues/14),
  [#115](https://github.com/geekinasuit/obolus/issues/115));
- a mechanical staleness check for the facilitator refusal reasons
  ([#114](https://github.com/geekinasuit/obolus/issues/114)).

Design talks carried for Milestone 5: pricing what was used, how a token-priced channel reports
what it cost, and a remedy for overpayment, all in
[#120](https://github.com/geekinasuit/obolus/issues/120).

## Milestone 5 — Honest prices (tentative)

**Demo:** a client lists the models and their prices before paying, pays, and the operator's
telemetry shows the quoted amount beside the usage the backend actually reported, and what a
token-priced request cost.

Builds: the model and price listing ([#34](https://github.com/geekinasuit/obolus/issues/34));
recording upstream usage and cost in telemetry, and whatever remedy for overpayment the design talk
chose ([#120](https://github.com/geekinasuit/obolus/issues/120)); reconciling a settlement the
facilitator reports as pending ([#75](https://github.com/geekinasuit/obolus/issues/75)); and more
than one payment option per network ([#76](https://github.com/geekinasuit/obolus/issues/76)).

Design talks carried for Milestone 6: the configuration and secrets surface, telemetry transport,
and shared state for horizontal scale (vision questions 4–6).

## Milestone 6 — The operator's console (tentative)

**Demo:** an operator changes a backend's price, kills a misbehaving backend, and reads revenue
against cost per backend, all without restarting the gateway.

Builds: the move from stateless to stateful; admin UX; runtime feature flags with per-backend
kill-switches and spend caps; telemetry beyond stdout.

## Side track — the client-testing fake

`obolus-devseller` improvements can run alongside any milestone, as client authors ask for them.

## Later, not yet ordered

The `anthropic-compat` wire format; client-key pass-through; per-identity quotas, revocation and
JWKS ([#33](https://github.com/geekinasuit/obolus/issues/33)); Solana's `feePayer`
([#81](https://github.com/geekinasuit/obolus/issues/81)); x402 v1 clients
([#73](https://github.com/geekinasuit/obolus/issues/73)); escrowed settlement
([#118](https://github.com/geekinasuit/obolus/issues/118)); Bitcoin Lightning, after its design
conversation ([#80](https://github.com/geekinasuit/obolus/issues/80)); horizontal scale;
self-settlement (Phase B); a deliberate mainnet configuration. Deferred items in the vision stay
deferred.
