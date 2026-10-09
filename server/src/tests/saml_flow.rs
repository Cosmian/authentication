//! SP-initiated SAML login end to end over HTTPS: `/saml/{realm}/login` → fake IdP →
//! `/saml/{realm}/acs` → session, plus `/saml/{realm}/metadata`. A browser is simulated
//! with redirects disabled and cookies passed by hand.

use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{
    Client, Response, StatusCode,
    header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE},
    redirect::Policy,
};
use samael::{
    crypto::UrlVerifier,
    metadata::{EntityDescriptorType, de},
};
use serde_json::Value;
use url::Url;

use crate::{
    AuthError, AuthResult, SamlParams,
    tests::{
        TestsContext, get_default_server_params,
        helpers::{
            admin_scheme, authenticate_as_admin, test_realm, test_saml_params, test_saml_sp_params,
        },
        init_test_logging,
        saml_idp::{TestIdp, TestResponse},
        start_default_test_server, start_test_server,
    },
};

const REALM: &str = "saml_flow";
const SP_CERTIFICATE_PEM: &str = include_str!("certificates/rsa/auth.server.cert.pem");

fn realm_params() -> SamlParams {
    SamlParams {
        role_attribute: Some("groups".to_string()),
        ..test_saml_params(REALM)
    }
}

async fn start_saml_server() -> AuthResult<TestsContext> {
    let mut params = get_default_server_params()?;
    params.saml_sp_params = Some(test_saml_sp_params());
    let ctx = start_test_server(params).await?;
    let mut realm = test_realm(REALM);
    realm.auth_params.saml_params = Some(realm_params());
    authenticate_as_admin(&ctx)
        .await?
        .create_realm_as_super_admin(&realm)
        .await?;
    Ok(ctx)
}

fn browser() -> Client {
    Client::builder()
        // Self-signed test certificate.
        .danger_accept_invalid_certs(true)
        .redirect(Policy::none())
        .build()
        .expect("test HTTP client")
}

fn http_error(e: reqwest::Error) -> AuthError {
    AuthError::Unexpected(format!("HTTP request failed: {e}"))
}

/// The `Set-Cookie` header setting `name`, as (`name=value`, whole header).
fn set_cookie(response: &Response, name: &str) -> Option<(String, String)> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|header| header.starts_with(&format!("{name}=")))
        .map(|header| {
            let pair = header.split(';').next().unwrap_or_default().to_string();
            (pair, header.to_string())
        })
}

fn query_value(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn login_url(ctx: &TestsContext, return_to: Option<&str>) -> Url {
    let mut url = Url::parse(&format!("{}/saml/{REALM}/login", ctx.get_client_url()))
        .expect("test server URL");
    if let Some(return_to) = return_to {
        url.query_pairs_mut().append_pair("return_to", return_to);
    }
    url
}

/// Start a login and return the IdP redirect and the login's request cookie (`name=value`).
async fn start_login(ctx: &TestsContext, return_to: Option<&str>) -> AuthResult<(Url, String)> {
    let response = browser()
        .get(login_url(ctx, return_to))
        .send()
        .await
        .map_err(http_error)?;
    assert_eq!(response.status(), StatusCode::FOUND);
    let (cookie, header) = set_cookie(&response, "_ea_saml").expect("request cookie");
    for attribute in ["Secure", "HttpOnly", "SameSite=None", "Path=/saml/"] {
        assert!(
            header.contains(attribute),
            "{attribute} missing from: {header}"
        );
    }
    let location = response.headers()[LOCATION]
        .to_str()
        .expect("ASCII Location");
    let location = Url::parse(location).expect("absolute Location");
    Ok((location, cookie))
}

/// The fake IdP's valid answer to the login redirected to `idp_url`.
fn idp_answer(idp_url: &Url) -> (String, String) {
    let relay_state = query_value(idp_url, "RelayState").expect("RelayState");
    let xml = TestIdp::new().sign(&TestResponse::answering(&relay_state, &realm_params()));
    (xml, relay_state)
}

async fn post_to_acs(
    ctx: &TestsContext,
    xml: &str,
    relay_state: &str,
    cookie: Option<&str>,
) -> AuthResult<Response> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("SAMLResponse", &STANDARD.encode(xml))
        .append_pair("RelayState", relay_state)
        .finish();
    let mut request = browser()
        .post(format!("{}/saml/{REALM}/acs", ctx.get_client_url()))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body);
    if let Some(cookie) = cookie {
        request = request.header(COOKIE, cookie);
    }
    request.send().await.map_err(http_error)
}

#[actix_web::test]
async fn a_saml_login_signs_the_user_in() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_saml_server().await?;

    let (idp_url, request_cookie) =
        start_login(&ctx, Some("https://app.example.com/dashboard")).await?;
    assert!(idp_url.as_str().starts_with("https://idp.example.com/sso?"));
    assert_eq!(
        query_value(&idp_url, "SigAlg").as_deref(),
        Some("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    );
    let verifier = UrlVerifier::from_x509_cert_pem(SP_CERTIFICATE_PEM).expect("SP certificate");
    assert!(
        verifier
            .verify_signed_request_url(&idp_url)
            .expect("verifiable redirect"),
        "the AuthnRequest must be signed with the SP key"
    );

    let (xml, relay_state) = idp_answer(&idp_url);
    let response = post_to_acs(&ctx, &xml, &relay_state, Some(&request_cookie)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let (session_cookie, _) = set_cookie(&response, "_ea_").expect("session cookie");
    let (_, cleared) = set_cookie(&response, "_ea_saml").expect("request cookie removal");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    let page = response.text().await.map_err(http_error)?;
    assert!(
        page.contains("url=https://app.example.com/dashboard"),
        "{page}"
    );

    let claims: Value = browser()
        .get(format!("{}/whoami?realm={REALM}", ctx.get_client_url()))
        .header(COOKIE, &session_cookie)
        .send()
        .await
        .map_err(http_error)?
        .json()
        .await
        .map_err(http_error)?;
    assert_eq!(claims["sub"], "alice");
    assert_eq!(claims["as_as"], "sa");
    assert_eq!(claims["as_rid"], REALM);
    assert_eq!(claims["roles"], serde_json::json!(["admins", "users"]));

    let replay = post_to_acs(&ctx, &xml, &relay_state, Some(&request_cookie)).await?;
    assert_eq!(
        replay.status(),
        StatusCode::UNAUTHORIZED,
        "a response is usable once"
    );

    ctx.stop_server().await
}

/// Login CSRF: a response posted without the cookie of the browser that started the login is
/// refused, and the refusal doesn't burn the pending login.
#[actix_web::test]
async fn the_acs_only_accepts_the_browser_that_started_the_login() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_saml_server().await?;
    let (idp_url, request_cookie) = start_login(&ctx, None).await?;
    let (xml, relay_state) = idp_answer(&idp_url);

    for cookie in [None, Some("_ea_saml=_another-login")] {
        let response = post_to_acs(&ctx, &xml, &relay_state, cookie).await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(set_cookie(&response, "_ea_").is_none());
    }

    let response = post_to_acs(&ctx, &xml, &relay_state, Some(&request_cookie)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let page = response.text().await.map_err(http_error)?;
    assert!(
        page.contains("url=https://app.example.com/home"),
        "the default return URL applies: {page}"
    );

    ctx.stop_server().await
}

#[actix_web::test]
async fn a_return_url_outside_the_allowed_origins_is_refused() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_saml_server().await?;
    for return_to in [
        "https://evil.example.com/",
        "http://app.example.com/",
        "not a url",
    ] {
        let response = browser()
            .get(login_url(&ctx, Some(return_to)))
            .send()
            .await
            .map_err(http_error)?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{return_to}");
    }
    ctx.stop_server().await
}

#[actix_web::test]
async fn the_sp_metadata_describes_this_server() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_saml_server().await?;

    let response = browser()
        .get(format!("{}/saml/{REALM}/metadata", ctx.get_client_url()))
        .send()
        .await
        .map_err(http_error)?;
    assert_eq!(
        response.headers()[CONTENT_TYPE],
        "application/samlmetadata+xml"
    );

    let xml = ctx
        .get_test_client(admin_scheme())
        .get_saml_metadata(REALM)
        .await?;
    let EntityDescriptorType::EntityDescriptor(metadata) =
        de::from_str::<EntityDescriptorType>(&xml).expect("valid SAML metadata")
    else {
        panic!("expected a single EntityDescriptor: {xml}");
    };
    let params = realm_params();
    assert_eq!(
        metadata.entity_id.as_deref(),
        Some(params.sp_entity_id.as_str())
    );
    let sp = &metadata.sp_sso_descriptors.expect("SPSSODescriptor")[0];
    assert_eq!(sp.authn_requests_signed, Some(true));
    assert_eq!(
        sp.assertion_consumer_services[0].location,
        params.sp_acs_url
    );
    let certificate: String = SP_CERTIFICATE_PEM
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    assert!(
        xml.contains(&certificate),
        "the SP signing certificate is published"
    );

    ctx.stop_server().await
}

#[actix_web::test]
async fn a_realm_without_saml_is_refused() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_saml_server().await?;
    let response = browser()
        .get(format!("{}/saml/_/login", ctx.get_client_url()))
        .send()
        .await
        .map_err(http_error)?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    ctx.stop_server().await
}

#[actix_web::test]
async fn there_are_no_saml_routes_without_a_signing_key() -> AuthResult<()> {
    init_test_logging(None);
    let ctx = start_default_test_server().await?;
    let response = browser()
        .get(format!("{}/saml/{REALM}/metadata", ctx.get_client_url()))
        .send()
        .await
        .map_err(http_error)?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    ctx.stop_server().await
}
