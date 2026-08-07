# Obolus — docs

Living documentation for the Obolus gateway. Keep these updated alongside structural or protocol-surface changes, the same way the project `README.md` is maintained.

## Contents

| File | What it is | Audience |
|---|---|---|
| [`x402-ecosystem.html`](x402-ecosystem.html) | A **no-prior-knowledge** explainer of the x402 rail Obolus sells on: the five participant roles, the 402 handshake step by step, the challenge/`accepts` schema, the Bazaar discovery layer, the per-request-vs-per-token pricing seam, and an honest status of our own pieces. Self-contained, theme-aware HTML. | Anyone picking up Obolus; reviewers; strategy. |

It documents the **protocol and ecosystem**, not the gateway's internals — the project [`README.md`](../README.md) covers the code, and assumes the protocol knowledge this file provides.

## Published as a living Artifact

Kept synchronized with development and published as an updatable Artifact. The file is self-contained (no external assets — a strict CSP applies when published) and dark + light theme-aware.

Visual identity: cool-slate neutrals, sans for display, serif for the human voice, mono for the machine, and a semantic palette keyed in its own legend — **indigo = the rail**, **teal = settlement**, **amber = discovery**.

**It deliberately makes no reference to any sibling project.** Obolus must stand alone (see the project [`README.md`](../README.md)), and this file may be published on its own — so buyers are described generically as *agent harnesses* and *apps that need a resource for a fee*, never by name. Keep it that way when editing.

**When to sync:** when the x402 spec or the discovery layer moves (re-verify load-bearing facts before requoting — the footer records which claims came from the spec, which from CDP docs, and which from our own source); and whenever section 07 ("where our own pieces actually stand") drifts from reality — that section is the one most likely to silently become a lie.

> These files are standalone documentation. They are **not** wired into any Bazel target or the server build.
