use std::fs;

use auth_client::{AuthClient, AuthClientScheme};
use cosmian_logger::log_init;

use crate::tests::IdP;

#[test]
fn test_client_creation_no_auth() {
    let client = AuthClient::new(
        "https://localhost:8443",
        &fs::read_to_string("src/tests/certificates/ec/auth.ca.pem")
            .expect("failed to read the CA certificate"),
        AuthClientScheme::None,
    );
    assert!(client.is_ok());
    let client = client.unwrap();
    assert_eq!(client.base_url(), "https://localhost:8443");
}

#[test]
fn test_client_creation_jwt_auth() {
    let rsa_idp =
        crate::tests::RsaIdp::new("test_auth_issuer").expect("failed to create dummy idp");
    let jwt_token = rsa_idp
        .issue_token("test@example.com", "test-api", 3600)
        .expect("failed to issue token");
    let client = AuthClient::new(
        "https://localhost:8443/",
        &fs::read_to_string("src/tests/certificates/ec/auth.ca.pem")
            .expect("failed to read the CA certificate"),
        AuthClientScheme::Jwt { token: jwt_token },
    );
    assert!(client.is_ok());
    let client = client.unwrap();
    // Trailing slash should be trimmed
    assert_eq!(client.base_url(), "https://localhost:8443");
}

#[test]
fn test_client_creation_client_cert_auth() {
    log_init(Some("debug"));
    let client = AuthClient::new(
        "https://localhost:8443",
        &fs::read_to_string("src/tests/certificates/ec/auth.ca.pem")
            .expect("failed to read the CA certificate"),
        AuthClientScheme::ClientCertificate {
            pkcs12_der: fs::read("src/tests/certificates/ec/auth.user1.p12")
                .expect("failed to read the PKCS#12 file"),
            password: "secret".to_owned(),
        },
    );
    assert!(
        client.is_ok(),
        "Failed to create client with certificate authentication: {:?}",
        client.err()
    );
}

#[test]
fn test_no_auth() {
    AuthClient::new(
        "https://localhost:8443",
        &fs::read_to_string("src/tests/certificates/ec/auth.ca.pem")
            .expect("failed to read the CA certificate"),
        AuthClientScheme::None,
    )
    .unwrap();
}
