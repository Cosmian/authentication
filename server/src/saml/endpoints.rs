use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse,
    cookie::{Cookie, SameSite, time::Duration},
    get,
    http::header,
    post,
    web::{Data, Form, Path, Query},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::Utc;
use cosmian_logger::{info, warn};
use serde::Deserialize;
use url::Url;

use crate::{
    AuthError, AuthResult, AuthScheme, AuthenticatedClientScheme, Realm, SamlParams, build_cookie,
    database::Database,
    saml::{
        PendingSamlRequest, SamlRequestStore,
        authn_request::{new_request_id, signed_authn_request_url},
        create_saml_request_store,
        factory::start_saml_request_store_cleanup,
        identity_mapping::{SamlIdentity, map_identity},
        response_validation::validate_saml_response,
        sp_metadata::{escape_markup, render_sp_metadata},
        sp_signing_key::SamlSpSigningKey,
    },
    server::parameters::{DatabaseParams, ServerParams},
    session::{JwtTokenConfig, SessionStore, issue_token, session_id_from_cookie_value},
};

/// How long a user has to sign in at the IdP.
const PENDING_REQUEST_SECONDS: i64 = 600;

/// Binds a login to the browser that started it: the ACS requires it to match `RelayState`,
/// so a response obtained elsewhere can't be posted into a victim's browser (login CSRF).
const REQUEST_COOKIE: &str = "_ea_saml";

/// Upper bound for the ACS form; signed responses with certificates are typically 5–20 KiB.
pub(crate) const MAX_SAML_FORM_BYTES: usize = 256 * 1024;

/// SAML state shared by the `/saml` endpoints; exists only when `saml_sp_params` is set.
pub(crate) struct SamlState {
    pub(crate) signing_key: SamlSpSigningKey,
    pub(crate) store: Arc<dyn SamlRequestStore>,
}

impl SamlState {
    /// Open the request store on `store_params` (the session store's database) and start
    /// purging it every `cleanup_interval_seconds`.
    pub(crate) async fn start(
        signing_key: SamlSpSigningKey,
        store_params: &DatabaseParams,
        cleanup_interval_seconds: u64,
    ) -> AuthResult<Self> {
        let store = create_saml_request_store(store_params).await?;
        start_saml_request_store_cleanup(store.clone(), cleanup_interval_seconds);
        Ok(Self { signing_key, store })
    }
}

#[derive(Deserialize)]
pub(crate) struct LoginQuery {
    return_to: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct AcsForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: String,
}

/// Start an SP-initiated login: remember the request and send the browser to the IdP.
#[get("/{realm_id}/login")]
pub(crate) async fn saml_login(
    realm_id: Path<String>,
    query: Query<LoginQuery>,
    database: Data<Arc<dyn Database>>,
    state: Data<SamlState>,
) -> AuthResult<HttpResponse> {
    let (realm, params) = saml_realm(database.as_ref().as_ref(), &realm_id).await?;
    let return_url = resolve_return_url(&params, query.return_to.as_deref())?;
    let request_id = new_request_id();
    let now = Utc::now().timestamp();
    state
        .store
        .store_pending_request(&PendingSamlRequest {
            request_id: request_id.clone(),
            realm_id: realm.id.clone(),
            return_url,
            created_at: now,
            expires_at: now + PENDING_REQUEST_SECONDS,
        })
        .await?;
    let idp_url = signed_authn_request_url(&params, &request_id, &state.signing_key)?;
    Ok(HttpResponse::Found()
        .insert_header((header::LOCATION, idp_url.as_str()))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .cookie(request_cookie(&request_id))
        .finish())
}

/// Assertion Consumer Service: the IdP posts its response here (HTTP-POST binding). On success
/// the session cookie is set and the browser continues to the return URL of the login.
#[post("/{realm_id}/acs")]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn saml_acs(
    req: HttpRequest,
    realm_id: Path<String>,
    form: Form<AcsForm>,
    database: Data<Arc<dyn Database>>,
    session_store: Data<Arc<dyn SessionStore>>,
    jwt_token_config: Data<Arc<JwtTokenConfig>>,
    server_params: Data<Arc<ServerParams>>,
    state: Data<SamlState>,
) -> AuthResult<HttpResponse> {
    let result = consume_response(&req, &realm_id, &form, database.as_ref().as_ref(), &state).await;
    let (realm, pending, identity) = match result {
        Ok(accepted) => accepted,
        Err(e) => {
            warn!(event = "auth.login.failure", realm = %realm_id, auth_scheme = "saml", "SAML login rejected: {e}");
            return Err(e);
        }
    };

    let token = issue_token(
        &identity.subject,
        AuthScheme::Saml,
        &realm.id,
        identity.roles,
        identity.extra_claims,
        &jwt_token_config,
        realm.session_max_age_seconds,
    )?;
    let session_cookie = build_cookie(
        &token,
        realm.session_max_age_seconds,
        server_params.tls_params.is_some(),
    )?;
    let session_id = session_id_from_cookie_value(session_cookie.value().as_bytes())?;
    let client = AuthenticatedClientScheme {
        username: identity.subject,
        auth_scheme: AuthScheme::Saml,
    };
    session_store
        .upsert_session(&session_id, &realm, &client, &session_cookie.to_string())
        .await?;
    info!(
        event = "auth.login.success",
        realm = %realm.id,
        username = %client.username,
        auth_scheme = ?client.auth_scheme,
        session_id = %session_id,
        "login successful"
    );

    let mut used_request_cookie = request_cookie("");
    used_request_cookie.make_removal();
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::CONTENT_SECURITY_POLICY, "default-src 'none'"))
        .cookie(session_cookie)
        .cookie(used_request_cookie)
        .body(redirect_page(&pending.return_url)))
}

/// Our SP metadata for the realm, to import into the IdP.
#[get("/{realm_id}/metadata")]
pub(crate) async fn saml_metadata(
    realm_id: Path<String>,
    database: Data<Arc<dyn Database>>,
    state: Data<SamlState>,
) -> AuthResult<HttpResponse> {
    let (_, params) = saml_realm(database.as_ref().as_ref(), &realm_id).await?;
    Ok(HttpResponse::Ok()
        .content_type("application/samlmetadata+xml")
        .body(render_sp_metadata(&params, &state.signing_key)?))
}

/// Check the browser binding, consume the pending request and validate the response.
async fn consume_response(
    req: &HttpRequest,
    realm_id: &str,
    form: &AcsForm,
    database: &dyn Database,
    state: &SamlState,
) -> AuthResult<(Realm, PendingSamlRequest, SamlIdentity)> {
    if req
        .cookie(REQUEST_COOKIE)
        .map(|c| c.value().to_string())
        .as_deref()
        != Some(form.relay_state.as_str())
    {
        return Err(AuthError::Saml(
            "this sign-in was not started from this browser".to_string(),
        ));
    }
    let (realm, params) = saml_realm(database, realm_id).await?;
    let pending = state
        .store
        .take_pending_request(&form.relay_state, &realm.id)
        .await?
        .ok_or_else(|| AuthError::Saml("unknown or expired sign-in request".to_string()))?;
    // Some IdPs wrap the base64 in lines.
    let encoded: String = form
        .saml_response
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let xml = STANDARD
        .decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| AuthError::Saml("SAMLResponse is not base64-encoded UTF-8".to_string()))?;
    let assertion =
        validate_saml_response(&xml, &params, &pending.request_id, state.store.as_ref()).await?;
    let identity = map_identity(&assertion, &params)?;
    Ok((realm, pending, identity))
}

/// The realm and its SAML settings, or a 400 when it doesn't exist or doesn't use SAML.
async fn saml_realm(database: &dyn Database, realm_id: &str) -> AuthResult<(Realm, SamlParams)> {
    let realm = database.get_realm(realm_id).await?;
    let params = realm
        .as_ref()
        .and_then(|realm| realm.auth_params.saml_params.clone());
    match (realm, params) {
        (Some(realm), Some(params)) => Ok((realm, params)),
        _ => Err(AuthError::BadRequest(format!(
            "realm '{realm_id}' does not exist or does not use SAML"
        ))),
    }
}

/// `return_to` when it is an https URL under one of the realm's allowed origins, else the
/// realm's default; anything else is refused rather than silently replaced.
fn resolve_return_url(params: &SamlParams, return_to: Option<&str>) -> AuthResult<String> {
    let Some(raw) = return_to else {
        return Ok(params.default_return_url.clone());
    };
    let url = Url::parse(raw)
        .map_err(|_| AuthError::BadRequest("return_to is not a valid URL".to_string()))?;
    let allowed = url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && params
            .allowed_return_origins
            .iter()
            .filter_map(|origin| Url::parse(origin).ok())
            .any(|origin| origin.origin() == url.origin());
    if !allowed {
        return Err(AuthError::BadRequest(
            "return_to is not under an allowed return origin of this realm".to_string(),
        ));
    }
    Ok(url.to_string())
}

fn request_cookie(request_id: &str) -> Cookie<'static> {
    // SameSite=None: the IdP's form POST back to the ACS is a cross-site request.
    Cookie::build(REQUEST_COOKIE, request_id.to_string())
        .path("/saml/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::None)
        .max_age(Duration::seconds(PENDING_REQUEST_SECONDS))
        .finish()
}

/// Browsers may withhold the `SameSite=Strict` session cookie on the navigation that follows a
/// cross-site POST; continuing from a page of ours makes it a same-site navigation.
fn redirect_page(return_url: &str) -> String {
    let url = escape_markup(return_url);
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={url}"><title>Signing in</title></head>
<body><p><a href="{url}">Continue</a></p></body></html>
"#
    )
}
