//! OIDC authorization endpoint (front-channel) with an embedded login form and
//! consent screen.
//!
//! Flow (all steps are CSRF-protected by a short-lived, server-signed *flow
//! token* carried in a hidden field):
//!
//! 1. `GET  /oidc/authorize`         — validate the request, render the login form.
//! 2. `POST /oidc/authorize/login`   — authenticate the user (userpass + TOTP),
//!    render the consent screen.
//! 3. `POST /oidc/authorize/consent` — on approval, issue a single-use
//!    authorization code bound to the PKCE challenge and redirect back.

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::{
    HttpResponse,
    web::{Data, Form, Query},
};
use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::AuthError;
use crate::database::{AuthorizationCode, Database, OAuthClient};
use crate::oidc::{OidcState, pkce, tokens};

/// Lifetime of a flow token (login/consent continuation), seconds.
const FLOW_TOKEN_TTL_SECS: i64 = 600;

/// Server-signed continuation token binding the in-progress authorization
/// request across the login and consent steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FlowClaims {
    /// Marker so access tokens can never be replayed as flow tokens.
    flow: bool,
    /// `login` or `consent`.
    stage: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    realm: String,
    /// Authenticated subject (set once the login step completes).
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<i64>,
    exp: i64,
    iat: i64,
}

/// A validated authorization request.
struct AuthRequest {
    client: OAuthClient,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
}

/// Early validation failure: either render an error page (bad client/redirect,
/// which must NOT redirect) or redirect the error back to the client.
enum AuthzError {
    Render(String),
    Redirect {
        redirect_uri: String,
        error: String,
        description: String,
        state: Option<String>,
    },
}

/// Minimal HTML-escape for values interpolated into markup/attributes.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Append query parameters to a redirect URI, preserving any existing query.
fn redirect_with_params(base: &str, params: &[(&str, &str)]) -> String {
    let sep = if base.contains('?') { '&' } else { '?' };
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                k,
                url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>()
            )
        })
        .collect();
    format!("{base}{sep}{}", query.join("&"))
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

// ── Flow-token sign/verify ──────────────────────────────────────────────────

fn sign_flow_token(state: &OidcState, claims: &FlowClaims) -> Result<String, AuthError> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(state.signing_kid.clone());
    encode(&header, claims, &state.encoding_key)
        .map_err(|e| AuthError::Unexpected(format!("failed to sign flow token: {e}")))
}

fn verify_flow_token(state: &OidcState, token: &str) -> Result<FlowClaims, AuthError> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;
    validation.set_required_spec_claims(&["exp"]);
    validation.validate_aud = false;
    let data = decode::<FlowClaims>(token, &state.decoding_key, &validation)
        .map_err(|e| AuthError::Session(format!("invalid flow token: {e}")))?;
    if !data.claims.flow {
        return Err(AuthError::Session("not a flow token".to_string()));
    }
    Ok(data.claims)
}

// ── GET /oidc/authorize ─────────────────────────────────────────────────────

/// Validate the authorization request and render the login form.
pub async fn authorize(
    state: Data<Arc<OidcState>>,
    database: Data<Arc<dyn Database>>,
    query: Query<HashMap<String, String>>,
) -> Result<HttpResponse, AuthError> {
    let params = query.into_inner();
    match validate_authorize(&state, &database, &params).await {
        Ok(req) => {
            let flow = FlowClaims {
                flow: true,
                stage: "login".to_string(),
                client_id: req.client.client_id.clone(),
                redirect_uri: req.redirect_uri,
                scope: req.scope,
                state: req.state,
                nonce: req.nonce,
                code_challenge: req.code_challenge,
                code_challenge_method: req.code_challenge_method,
                realm: req.client.realm.clone(),
                sub: None,
                auth_time: None,
                exp: now_ts() + FLOW_TOKEN_TTL_SECS,
                iat: now_ts(),
            };
            let token = sign_flow_token(&state, &flow)?;
            Ok(render_login(&token, None))
        }
        Err(AuthzError::Render(msg)) => Ok(render_error_page(&msg)),
        Err(AuthzError::Redirect {
            redirect_uri,
            error,
            description,
            state,
        }) => {
            let mut params = vec![
                ("error", error.as_str()),
                ("error_description", description.as_str()),
            ];
            if let Some(s) = state.as_deref() {
                params.push(("state", s));
            }
            let location = redirect_with_params(&redirect_uri, &params);
            Ok(HttpResponse::Found()
                .insert_header(("Location", location))
                .finish())
        }
    }
}

/// Validate the authorization request parameters against the registered client.
async fn validate_authorize(
    state: &OidcState,
    database: &Arc<dyn Database>,
    params: &HashMap<String, String>,
) -> Result<AuthRequest, AuthzError> {
    let client_id = params
        .get("client_id")
        .ok_or_else(|| AuthzError::Render("missing client_id".to_string()))?;
    let client = database
        .get_oauth_client(client_id)
        .await
        .map_err(|e| AuthzError::Render(format!("client lookup failed: {e}")))?
        .ok_or_else(|| AuthzError::Render("unknown client_id".to_string()))?;

    let redirect_uri = params
        .get("redirect_uri")
        .ok_or_else(|| AuthzError::Render("missing redirect_uri".to_string()))?
        .clone();
    if !client.redirect_uris.contains(&redirect_uri) {
        return Err(AuthzError::Render(
            "redirect_uri does not match any registered URI".to_string(),
        ));
    }

    // From here, errors are redirected back to the (validated) redirect_uri.
    let req_state = params.get("state").cloned();
    let redirect_err = |error: &str, description: &str| AuthzError::Redirect {
        redirect_uri: redirect_uri.clone(),
        error: error.to_string(),
        description: description.to_string(),
        state: req_state.clone(),
    };

    let response_type = params
        .get("response_type")
        .map(String::as_str)
        .unwrap_or("");
    if response_type != "code" {
        return Err(redirect_err(
            "unsupported_response_type",
            "only response_type=code is supported",
        ));
    }
    if !client.grant_types.iter().any(|g| g == "authorization_code") {
        return Err(redirect_err(
            "unauthorized_client",
            "client is not allowed to use the authorization_code grant",
        ));
    }

    // PKCE is mandatory (S256 only).
    let code_challenge = params
        .get("code_challenge")
        .cloned()
        .ok_or_else(|| redirect_err("invalid_request", "missing PKCE code_challenge"))?;
    let code_challenge_method = params
        .get("code_challenge_method")
        .cloned()
        .unwrap_or_default();
    if code_challenge_method != pkce::S256 {
        return Err(redirect_err(
            "invalid_request",
            "code_challenge_method must be S256",
        ));
    }

    // Scope: filter to supported ∩ client scopes; must include openid.
    let requested = params.get("scope").map(String::as_str).unwrap_or("openid");
    let granted: Vec<String> = requested
        .split_whitespace()
        .filter(|s| state.supported_scopes.iter().any(|x| x == s))
        .filter(|s| client.scopes.is_empty() || client.scopes.iter().any(|x| x == s))
        .map(|s| s.to_string())
        .collect();
    if !granted.iter().any(|s| s == "openid") {
        return Err(redirect_err(
            "invalid_scope",
            "the openid scope is required",
        ));
    }

    Ok(AuthRequest {
        client,
        redirect_uri,
        scope: granted.join(" "),
        state: req_state,
        nonce: params.get("nonce").cloned(),
        code_challenge,
        code_challenge_method,
    })
}

// ── POST /oidc/authorize/login ──────────────────────────────────────────────

/// Authenticate the end-user and render the consent screen.
pub async fn authorize_login(
    state: Data<Arc<OidcState>>,
    database: Data<Arc<dyn Database>>,
    form: Form<HashMap<String, String>>,
) -> Result<HttpResponse, AuthError> {
    let form = form.into_inner();
    let token = form
        .get("flow_token")
        .ok_or_else(|| AuthError::Session("missing flow_token".to_string()))?;
    let mut flow = verify_flow_token(&state, token)?;
    if flow.stage != "login" {
        return Err(AuthError::Session("unexpected flow stage".to_string()));
    }

    let username = form.get("username").map(String::as_str).unwrap_or("");
    let password = form.get("password").map(String::as_str).unwrap_or("");
    if username.is_empty() || password.is_empty() {
        let fresh = refresh_login_token(&state, &flow)?;
        return Ok(render_login(
            &fresh,
            Some("Username and password are required"),
        ));
    }

    // Validate credentials against the client's realm.
    match database
        .validate_userpass(&flow.realm, username, password)
        .await
    {
        Ok(_) => {}
        Err(_) => {
            let fresh = refresh_login_token(&state, &flow)?;
            return Ok(render_login(&fresh, Some("Invalid username or password")));
        }
    }

    // TOTP second factor when enabled for this user.
    let totp_enabled = database
        .is_totp_enabled(&flow.realm, username)
        .await
        .unwrap_or(Some(false))
        .unwrap_or(false);
    if totp_enabled {
        let code = form.get("totp_code").map(String::as_str).unwrap_or("");
        if !verify_totp(&database, &flow.realm, username, code).await? {
            let fresh = refresh_login_token(&state, &flow)?;
            return Ok(render_login(&fresh, Some("Invalid or missing TOTP code")));
        }
    }

    // Advance to the consent stage.
    flow.stage = "consent".to_string();
    flow.sub = Some(username.to_string());
    flow.auth_time = Some(now_ts());
    flow.exp = now_ts() + FLOW_TOKEN_TTL_SECS;
    flow.iat = now_ts();
    let consent_token = sign_flow_token(&state, &flow)?;
    Ok(render_consent(&consent_token, &flow))
}

/// Re-sign a login-stage flow token with a refreshed expiry (for re-render).
fn refresh_login_token(state: &OidcState, flow: &FlowClaims) -> Result<String, AuthError> {
    let mut f = flow.clone();
    f.exp = now_ts() + FLOW_TOKEN_TTL_SECS;
    f.iat = now_ts();
    sign_flow_token(state, &f)
}

/// Validate a TOTP code for a user against the stored secret and realm params.
async fn verify_totp(
    database: &Arc<dyn Database>,
    realm_id: &str,
    username: &str,
    code: &str,
) -> Result<bool, AuthError> {
    if code.is_empty() {
        return Ok(false);
    }
    let secret = match database.get_totp_secret(realm_id, username).await {
        Ok(Some(s)) => s,
        _ => return Ok(false),
    };
    let realm = database.get_realm(realm_id).await.ok().flatten();
    let totp_params = realm
        .and_then(|r| r.auth_params.totp_params)
        .as_ref()
        .map(crate::totp::realm_params_to_totp_params)
        .transpose()?;
    let totps = crate::totp::Totps::from_secret(&secret, None, username.to_string(), totp_params)?;
    totps.validate_token(code)
}

// ── POST /oidc/authorize/consent ────────────────────────────────────────────

/// Record the consent decision; on approval issue an authorization code and
/// redirect back to the client.
pub async fn authorize_consent(
    state: Data<Arc<OidcState>>,
    database: Data<Arc<dyn Database>>,
    form: Form<HashMap<String, String>>,
) -> Result<HttpResponse, AuthError> {
    let form = form.into_inner();
    let token = form
        .get("flow_token")
        .ok_or_else(|| AuthError::Session("missing flow_token".to_string()))?;
    let flow = verify_flow_token(&state, token)?;
    if flow.stage != "consent" {
        return Err(AuthError::Session("unexpected flow stage".to_string()));
    }
    let subject = flow
        .sub
        .clone()
        .ok_or_else(|| AuthError::Session("flow token missing subject".to_string()))?;

    let decision = form.get("decision").map(String::as_str).unwrap_or("deny");
    if decision != "approve" {
        let mut params = vec![
            ("error", "access_denied"),
            ("error_description", "user denied the request"),
        ];
        if let Some(s) = flow.state.as_deref() {
            params.push(("state", s));
        }
        let location = redirect_with_params(&flow.redirect_uri, &params);
        return Ok(HttpResponse::Found()
            .insert_header(("Location", location))
            .finish());
    }

    // Issue a single-use authorization code bound to the PKCE challenge.
    let (raw_code, code_hash) = tokens::generate_opaque_token("code-");
    let record = AuthorizationCode {
        code_hash,
        client_id: flow.client_id.clone(),
        redirect_uri: flow.redirect_uri.clone(),
        scope: flow.scope.clone(),
        nonce: flow.nonce.clone(),
        code_challenge: flow.code_challenge.clone(),
        code_challenge_method: flow.code_challenge_method.clone(),
        subject,
        realm: flow.realm.clone(),
        auth_time: flow.auth_time.unwrap_or_else(now_ts),
        expiry: now_ts() + state.code_ttl_secs,
    };
    database.create_authorization_code(&record).await?;

    let mut params = vec![("code", raw_code.as_str())];
    if let Some(s) = flow.state.as_deref() {
        params.push(("state", s));
    }
    let location = redirect_with_params(&flow.redirect_uri, &params);
    Ok(HttpResponse::Found()
        .insert_header(("Location", location))
        .finish())
}

// ── HTML rendering ──────────────────────────────────────────────────────────

/// Shared CSS matching the admin-UI theme (branding.json tokens, Ant Design spacing).
///
/// Primary light: #e34319 | Primary dark: #9e6eff
/// Background light: #f0f2f5 | Background dark: #2a2d30
/// Card light: #ffffff | Card dark: #393E46
const PAGE_STYLE: &str = "\
:root{--primary:#e34319;--bg:#f0f2f5;--card:#fff;--border:#d9d9d9;\
--text:#292f52;--text2:#6b7280;--input-bg:#fff;--err-bg:#fff1f0;\
--err-border:#ff675f;--err-text:#a8071a;--scope-bg:#fff7f5;--scope-border:#e34319;}\
@media(prefers-color-scheme:dark){\
:root{--primary:#9e6eff;--bg:#2a2d30;--card:#393E46;--border:#34383f;\
--text:#e4dddd;--text2:#b9b9b9;--input-bg:#2f3239;\
--err-bg:#3b0a0a;--err-border:#ff4d4f;--err-text:#ffb3b0;\
--scope-bg:#2d1f3d;--scope-border:#9e6eff;}}\
*,*::before,*::after{box-sizing:border-box}\
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;\
background:var(--bg);color:var(--text);margin:0;\
display:flex;min-height:100vh;align-items:center;justify-content:center;}\
.card{background:var(--card);padding:2rem;border-radius:8px;\
box-shadow:0 1px 8px rgba(0,0,0,.12);width:400px;max-width:calc(100vw - 2rem)}\
.logo{text-align:center;margin-bottom:1.5rem}\
.logo-text{font-size:1.5rem;font-weight:700;color:var(--primary)}\
h1{font-size:1.1rem;font-weight:600;text-align:center;margin:0 0 1.5rem;color:var(--text)}\
.field{margin-bottom:1rem}\
.field label{display:block;font-size:.8125rem;font-weight:500;color:var(--text2);margin-bottom:.375rem}\
.input-wrap{position:relative}\
.input-wrap svg{position:absolute;left:.75rem;top:50%;transform:translateY(-50%);\
width:1rem;height:1rem;color:var(--text2);pointer-events:none}\
input{width:100%;padding:.5rem .75rem .5rem 2.375rem;border:1px solid var(--border);\
border-radius:6px;background:var(--input-bg);color:var(--text);\
font-size:.9375rem;transition:border-color .2s,box-shadow .2s;outline:none}\
input:focus{border-color:var(--primary);box-shadow:0 0 0 2px color-mix(in srgb,var(--primary) 20%,transparent)}\
input[type=password]{letter-spacing:.1em}\
.totp input{letter-spacing:.25em;font-variant-numeric:tabular-nums}\
button{margin-top:.75rem;width:100%;padding:.625rem 1rem;border:0;border-radius:6px;\
background:var(--primary);color:#fff;font-size:.9375rem;font-weight:500;\
cursor:pointer;transition:opacity .15s}\
button:hover{opacity:.88}button:active{opacity:.75}\
button.secondary{background:transparent;border:1px solid var(--border);\
color:var(--text);margin-top:.5rem}\
button.secondary:hover{border-color:var(--primary);color:var(--primary)}\
.err{background:var(--err-bg);border:1px solid var(--err-border);border-radius:6px;\
color:var(--err-text);font-size:.875rem;padding:.625rem .875rem;\
margin-bottom:1rem;display:flex;gap:.5rem;align-items:flex-start}\
.err svg{flex-shrink:0;margin-top:.1rem}\
.scope-list{list-style:none;padding:0;margin:.75rem 0 1rem;display:flex;flex-wrap:wrap;gap:.375rem}\
.scope-list li{background:var(--scope-bg);border:1px solid var(--scope-border);\
border-radius:4px;color:var(--primary);font-size:.8125rem;padding:.2rem .6rem}\
.consent-app{font-weight:600;color:var(--primary)}\
.consent-desc{font-size:.875rem;color:var(--text2);margin:.5rem 0 0}\
.row{display:flex;flex-direction:column;gap:0}\
footer{margin-top:1.5rem;text-align:center;font-size:.75rem;color:var(--text2)}";

/// Login page — strict `form-action 'self'` keeps the submission within the OP.
fn page_login(body: &str) -> HttpResponse {
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Sign in — Auth</title><style>{PAGE_STYLE}</style></head>\
         <body>{body}</body></html>"
    );
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'",
        ))
        .body(html)
}

/// Consent page — `form-action` is intentionally omitted.
///
/// The login page uses `form-action 'self'` to prevent the form from being
/// pointed at an attacker-controlled URL.  The consent page submits to the
/// same server (`/oidc/authorize/consent`, hardcoded in the HTML), but the
/// server then issues a 302 redirect to the client's registered `redirect_uri`
/// which is an external origin.
///
/// Several browsers (Firefox in particular) apply the `form-action` directive
/// to the *final redirect target*, not only the initial submission URL.  If
/// `form-action 'self'` were set here, Firefox would block the post-consent
/// redirect to the client application, making the Allow button appear broken.
///
/// Omitting `form-action` is safe because:
/// - The form action (`/oidc/authorize/consent`) is server-rendered, not
///   attacker-controlled.
/// - The redirect target is validated server-side against the registered
///   `redirect_uri`; an attacker cannot change it.
fn page_consent(body: &str) -> HttpResponse {
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Authorize — Auth</title><style>{PAGE_STYLE}</style></head>\
         <body>{body}</body></html>"
    );
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'",
        ))
        .body(html)
}

// Inline SVG icons (no external resource — compatible with CSP `default-src 'none'`).
const ICON_USER: &str = "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" \
stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\
<circle cx=\"12\" cy=\"8\" r=\"4\"/><path d=\"M4 20c0-4 3.6-7 8-7s8 3 8 7\"/></svg>";

const ICON_LOCK: &str = "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" \
stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\
<rect x=\"3\" y=\"11\" width=\"18\" height=\"11\" rx=\"2\"/>\
<path d=\"M7 11V7a5 5 0 0 1 10 0v4\"/></svg>";

const ICON_SHIELD: &str = "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" \
stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\
<path d=\"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z\"/></svg>";

const ICON_HASH: &str = "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" \
stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">\
<line x1=\"4\" y1=\"9\" x2=\"20\" y2=\"9\"/><line x1=\"4\" y1=\"15\" x2=\"20\" y2=\"15\"/>\
<line x1=\"10\" y1=\"3\" x2=\"8\" y2=\"21\"/><line x1=\"16\" y1=\"3\" x2=\"14\" y2=\"21\"/></svg>";

const ICON_ERR: &str = "<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" \
stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" style=\"width:1rem;height:1rem\">\
<circle cx=\"12\" cy=\"12\" r=\"10\"/>\
<line x1=\"12\" y1=\"8\" x2=\"12\" y2=\"12\"/>\
<line x1=\"12\" y1=\"16\" x2=\"12.01\" y2=\"16\"/></svg>";

fn render_login(flow_token: &str, error: Option<&str>) -> HttpResponse {
    let err_html = error
        .map(|e| {
            format!(
                "<div class=\"err\">{ICON_ERR}<span>{}</span></div>",
                html_escape(e)
            )
        })
        .unwrap_or_default();
    let body = format!(
        "<div class=\"card\">\
         <div class=\"logo\"><span class=\"logo-text\">Authentication Verifier</span></div>\
         <h1>Sign in</h1>\
         {err_html}\
         <form method=\"post\" action=\"/oidc/authorize/login\">\
         <input type=\"hidden\" name=\"flow_token\" value=\"{token}\">\
         <div class=\"field\">\
           <label for=\"u\">Username</label>\
           <div class=\"input-wrap\">{ICON_USER}<input id=\"u\" name=\"username\" \
autocomplete=\"username\" autofocus required placeholder=\"Enter your username\"></div>\
         </div>\
         <div class=\"field\">\
           <label for=\"p\">Password</label>\
           <div class=\"input-wrap\">{ICON_LOCK}<input id=\"p\" name=\"password\" type=\"password\" \
autocomplete=\"current-password\" required placeholder=\"Enter your password\"></div>\
         </div>\
         <div class=\"field totp\">\
           <label for=\"t\">TOTP code <span style=\"font-weight:400;font-size:.75rem\">(if enabled)</span></label>\
           <div class=\"input-wrap\">{ICON_HASH}<input id=\"t\" name=\"totp_code\" \
inputmode=\"numeric\" maxlength=\"6\" autocomplete=\"one-time-code\" placeholder=\"000000\"></div>\
         </div>\
         <button type=\"submit\">Sign in</button>\
         </form>\
         <footer>Cosmian Authentication Server</footer>\
         </div>",
        token = html_escape(flow_token)
    );
    page_login(&body)
}

fn render_consent(flow_token: &str, flow: &FlowClaims) -> HttpResponse {
    let scopes_html = flow
        .scope
        .split_whitespace()
        .map(|s| format!("<li>{}</li>", html_escape(s)))
        .collect::<String>();
    let body = format!(
        "<div class=\"card\">\
         <div class=\"logo\"><span class=\"logo-text\">Authentication Verifier</span></div>\
         <h1>Authorize access</h1>\
         <p style=\"text-align:center;margin:0 0 1.25rem\">\
           <span class=\"consent-app\">{app}</span> is requesting access to your account.\
         </p>\
         <div class=\"field\">\
           <label>Requested permissions</label>\
           <ul class=\"scope-list\">{scopes}</ul>\
         </div>\
         <form method=\"post\" action=\"/oidc/authorize/consent\">\
         <input type=\"hidden\" name=\"flow_token\" value=\"{token}\">\
         <div class=\"row\">\
           <button type=\"submit\" name=\"decision\" value=\"approve\">{ICON_SHIELD} Allow</button>\
           <button type=\"submit\" name=\"decision\" value=\"deny\" class=\"secondary\">Deny</button>\
         </div>\
         </form>\
         <footer>Cosmian Authentication Server</footer>\
         </div>",
        app = html_escape(&flow.client_id),
        scopes = scopes_html,
        token = html_escape(flow_token)
    );
    page_consent(&body)
}

fn render_error_page(message: &str) -> HttpResponse {
    let body = format!(
        "<div class=\"card\">\
         <div class=\"logo\"><span class=\"logo-text\">Authentication Verifier</span></div>\
         <h1>Authorization error</h1>\
         <div class=\"err\">{ICON_ERR}<span>{}</span></div>\
         <footer>Cosmian Authentication Server</footer>\
         </div>",
        html_escape(message)
    );
    // Bad client/redirect: 400 with an explanatory page (must not redirect).
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>Error — Auth</title><style>{PAGE_STYLE}</style></head>\
         <body>{body}</body></html>"
    );
    HttpResponse::BadRequest()
        .content_type("text/html; charset=utf-8")
        .body(html)
}
