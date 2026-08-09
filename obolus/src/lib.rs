//! **Obolus** — an x402 (HTTP-402) payment-gated serving gateway.
//!
//! The obolus is the coin; Charon is the ferryman who takes it and grants the crossing.
//! Obolus is the toll booth in front of an AI or agentic service: it answers an unpaid request
//! with a real HTTP 402 challenge, takes a per-request USDC micropayment, and grants passage
//! to the model behind it.
//!
//! # Phase A
//!
//! This crate currently implements Phase A: it speaks the protocol and **delegates** payment
//! verification and settlement to a facilitator behind the [`facilitator::Facilitator`] seam.
//! It contains no cryptography of its own — no signature checking, no key handling, no
//! on-chain submission. Phase B adds a self-settling facilitator behind that same seam without
//! touching the gateway.
//!
//! Nothing here is mainnet-capable by construction: there is no signing path to misuse. That covers
//! what Obolus can *do*. The other half of the posture is what it *advertises*, since a 402 challenge
//! is what a real client pays against — [`arming`] supplies the check for that, but note precisely
//! what that means: it is a **check this library offers, not an invariant this library enforces**.
//! `Gateway::new` does not call it. The `obolus` binary does, at startup, before constructing the
//! gateway. A different consumer of this library could build a `Gateway` advertising anything at all
//! (see OBOL-008 on whether that should be closed structurally).

pub mod access;
pub mod arming;
pub mod config;
pub mod facilitator;
pub mod gateway;
pub mod upstream;
pub mod x402;
