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
//! It contains no payment cryptography of its own — it checks no payment signature, holds no
//! payment key, and makes no on-chain submission. Phase B adds a self-settling facilitator behind
//! that same seam without touching the gateway.
//!
//! Nothing here is mainnet-capable by construction: there is no signing path to misuse. That covers
//! what Obolus can *do*. The other half of the posture is what it *advertises*, since a 402 challenge
//! is what a real client pays against — [`arming`] supplies the check for that, and the type system
//! enforces it: `Gateway::new` takes an [`arming::ArmedRequirements`], which only
//! [`arming::check_arming`] can produce. A consumer of this library — the `obolus` binary, a test
//! harness, an external crate — cannot build a `Gateway` advertising a network the guard never saw.
//! What the guard *admits* is the caller's policy: every advertised network must be provably testnet,
//! or armed by name (#28).

pub mod access;
pub mod arming;
pub mod backends;
pub mod config;
pub mod facilitator;
pub mod gateway;
pub mod pricing;
pub mod telemetry;
pub mod upstream;
pub mod x402;
