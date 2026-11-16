//! Outbound TLS: the gateway as a client of an `https://` facilitator (#35).
//!
//! The posture, written down because #35 asked for it to be chosen rather than inherited:
//!
//! * **Trust anchors are compiled in.** The roots are Mozilla's set as shipped in `webpki-roots`,
//!   fixed at build time. The host's trust store is not read, so a host with no CA bundle (a slim
//!   container) behaves the same as any other, and a CA added to the host is not trusted here. The
//!   cost is that the set only changes when the binary is rebuilt.
//! * **Verification cannot be turned off.** There is no setting that skips the certificate or
//!   hostname check, and no setting that adds a CA. Either can be added when a deployment needs it;
//!   neither is built ahead of that.
//! * **The crypto is ring**, chosen explicitly rather than through rustls's process-wide default.
//!   `jsonwebtoken` already builds ring, and the default provider (aws-lc-rs) is a C build.
//! * **TLS 1.2 and 1.3**, rustls's safe defaults; nothing older is offered.
//!
//! This is outbound only. The gateway still serves plain HTTP and holds no private key; inbound TLS
//! is terminated in front of it (see `docs/exposure.md`).

use std::sync::Arc;

use hyper_util::client::legacy::connect::HttpConnector;
use rustls::{ClientConfig, RootCertStore};

/// The connector the facilitator client is built on. It speaks `https://` with the posture above
/// and plain `http://` as before, chosen per request by the URL's scheme.
pub(crate) type HttpsConnector = hyper_rustls::HttpsConnector<HttpConnector>;

/// A connector that trusts the compiled-in roots. What every shipped client uses.
pub(crate) fn connector() -> HttpsConnector {
    connector_trusting(built_in_roots())
}

/// A connector that trusts exactly `roots`. Shipped code passes [`built_in_roots`]; tests pass a CA
/// they minted, so the trusted, untrusted and wrong-name cases run against a real handshake.
pub(crate) fn connector_trusting(roots: RootCertStore) -> HttpsConnector {
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(config_trusting(roots))
        .https_or_http()
        .enable_http1()
        .build()
}

fn built_in_roots() -> RootCertStore {
    RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() }
}

fn config_trusting(roots: RootCertStore) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_roots_are_not_empty() {
        // An empty store would refuse every https facilitator with an "unknown issuer" that looks
        // like the facilitator's fault.
        assert!(built_in_roots().len() > 100, "got {} roots", built_in_roots().len());
    }
}
