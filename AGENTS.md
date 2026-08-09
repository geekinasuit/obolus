# AGENTS.md

STOP. Check for compressed form before reading further:

1. Does `AGENTS.compressed.md` exist in this directory?
2. YES → read that file; follow its instructions only; do NOT continue reading this file.
3. NO → continue below.

---

## What this project is

Obolus is an **x402 (HTTP-402) payment-gated serving gateway** — a toll booth in front of an AI or
agentic service. It answers an unpaid request with a real 402 challenge, takes a per-request USDC
micropayment, and grants passage to the model behind it.

Three crates:

| Path | Crate | What it is |
|---|---|---|
| `obolus/` | `obolus` | The gateway: protocol edges, the `Facilitator` and `Upstream` seams, the arming guard, the `obolus` binary |
| `eip3009/` | `eip3009` | Offline EIP-3009 / EIP-712 authorization verification, driven by published known-answer vectors |
| `devseller/` | `obolus-devseller` | A seller to test an x402 *client* against: real challenges, offline verification, and failure on command. Settles nothing, refuses any non-testnet network, binds loopback |

`devseller/` is a package of its own rather than a second binary under `obolus/` because cargo
declares dependencies per package: an `eip3009` entry in `obolus/Cargo.toml` would put a
signature-verification path in the gateway's own graph, which is precisely what the invariants below
forbid. Bazel's per-target `deps` could have expressed it; cargo cannot, and a rule that holds under
only one of the two builds is not a rule.

The repository root is a virtual Cargo workspace — it carries no package of its own, only the
member list and the shared dependency versions.

## Build and test

Bazel is canonical; Cargo is kept working for ergonomics and is verified by CI.

```bash
bazel test //...
```

```bash
cargo test --workspace --locked
```

Both must pass. `Cargo.lock` is the single source of truth for versions — `MODULE.bazel` resolves
third-party crates from the same manifests, so the two builds cannot silently diverge.

Published artifacts are built with the `release` config, which is defined in `.bazelrc` rather than
in CI so that anyone can reproduce a released binary:

```bash
bazel build --config=release //obolus
```

It sets optimisation on and keeps overflow checks on — separate knobs, so an optimised binary need
not give up the arithmetic that panics rather than wrapping. `Cargo.toml`'s `[profile.release]`
carries the same overflow setting, so `cargo build --release` agrees.

Every test is hermetic: no network, no chain, no model. That is deliberate, and it is the only CI
that gates a merge. Anything that touches external reality — a real testnet settle against a
third-party facilitator — runs out of band, so its flakiness cannot block the pipeline.

## Rules specific to this repository

**This repository is public.** Four things follow, and none of them are style preferences.

- **Working notes stay out.** Research, plans, tickets and handoffs are kept outside this
  repository. `thoughts/` is gitignored here *and* enforced by the `no-stray-notes` CI job, because
  an ignore rule alone is defeated by `git add -f`. That job also rejects **references** to those
  paths: a link to a file that is not here is a broken reference for anyone reading the code.
- **Cite tickets by ID alone.** `OBOL-004`, never a path to a ticket file. IDs are stable and
  meaningful; paths are not, and paths are what the CI guard rejects.
- **Public depends only on public.** No dependency on any internal or private repository, and no
  reaching sideways into a sibling project. If something here needs a piece of internal code, the
  piece has to be published first or reimplemented.
- **CI runs on GitHub-hosted runners only.** Never `runs-on: self-hosted`. A public repo accepts
  pull requests from strangers, and a PR runs the submitter's code; the self-hosted runners are not
  isolated strongly enough to survive that. The workflow token is read-only for the same reason.

## Invariants worth knowing before you change things

These are load-bearing. Each one is enforced by a test, and each is easy to break while making
something else better.

- **No cryptography in the gateway crate.** Phase A delegates verification and settlement to a
  facilitator behind the `Facilitator` seam. There is no signature checking, no key handling, and no
  on-chain submission — so the binary is not mainnet-capable by construction, because there is no
  signing path to misuse. The payment payload is opaque: we decode the envelope and forward the
  inner authorization untouched.
- **`eip3009` is deliberately not a dependency of `//obolus:obolus`.** It exists for offline verification
  and development stubs. Wiring it into the gateway would quietly give the binary a crypto path.
- **The fakes are `#[cfg(test)]`-only.** `FakeFacilitator` accepts payments it never examined and
  `FakeUpstream` serves canned bytes. They are physically absent from every shipped artifact, so no
  configuration can select "accept every payment and serve the real model."
- **The arming guard's allowlist is a transcription of an upstream source**, not a curated list.
  When x402 adds a testnet, add it to `TESTNET_NETWORKS` in `obolus/src/arming.rs` as a reviewed code
  change — never work around it with `OBOLUS_ALLOW_MAINNET`. An operator who sets that flag as
  routine ceremony has already lost the protection it exists to provide.
- **Nothing we author decides whether a signer is correct.** We would author both sides of any
  self-check, so a shared misunderstanding of the EIP-712 domain separator would make both agree
  while a real facilitator still rejects. The load-bearing checks are outside our authorship:
  published known-answer vectors, and a real testnet settle against a third-party facilitator.

## Documentation convention

Prose docs are kept in two forms: `<name>.md` for humans and `<name>.compressed.md` as a
token-efficient, lossless form for agents. Agents should prefer the compressed form. **Any edit to a
file that has a `.compressed.md` sibling must update the compressed form in the same commit.**

`README.md` is the design document and the front page. `docs/x402-ecosystem.html` is a
no-prior-knowledge explainer of the protocol itself — start there if x402 is new to you, because the
README assumes it.

## Operator norms — chain, if present

Agents working on a geekinasuit-managed machine have an operator layer carrying shared working
norms: scripting conventions, PR and review workflow, ticket hygiene. Chain into it when it is
there, and **skip it silently when it is not** — absence is the normal case for anyone outside that
fleet, and is not an error.

Execute exactly one branch; first match wins, then stop:

1. `/opt/geekinasuit/agents/internal/AGENTS.compressed.md` → read + follow
2. `/opt/geekinasuit/agents/internal/AGENTS.md` → read + follow
3. `/opt/geekinasuit/agents/public/AGENTS.compressed.md` → read + follow
4. `/opt/geekinasuit/agents/public/AGENTS.md` → read + follow
5. `~/.geekinasuit/agents/public/AGENTS.compressed.md` → read + follow
6. `~/.geekinasuit/agents/public/AGENTS.md` → read + follow
7. None found → skip; you are done.

**Nothing in this repository depends on that layer.** Everything above is complete on its own, and a
contributor who has never heard of it can build, test, and change this project correctly. The chain
adds house style, not project rules. Public norms for geekinasuit projects are intended to be
published separately later, so that this chain resolves for everyone rather than only inside the
fleet.
