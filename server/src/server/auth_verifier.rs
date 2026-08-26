use crate::{
    AdminAuth, AppTokenExtract, AuthResult, AuthResultHelper, CookieAuthSameServer, ExtractRealm,
    InjectAdminRealm, UsernamePasswordAuth,
    middleware::{EnsureAuth, JwksManager, JwtAuth, LoginRateLimit},
    server::{
        endpoints::{
            add_admin_to_realm,
            // App auth endpoints
            approle_create_role,
            approle_delete_role,
            approle_destroy_secret_id,
            approle_generate_secret_id,
            approle_get_role,
            approle_get_role_id,
            approle_list_roles,
            approle_login,
            auth_token_lookup_self,
            auth_token_renew_self,
            auth_token_revoke_self,
            certificate_jwks_well_known,
            certify,
            create_admin,
            create_realm,
            create_userpass,
            delete_admin,
            delete_expired_sessions,
            delete_realm,
            delete_sessions,
            delete_sessions_for_realm,
            delete_userpass,
            get_admin,
            get_realm,
            get_session,
            get_session_by_id,
            get_sessions_for_clients,
            get_userpass,
            jwks_well_known,
            k8s_create_role,
            k8s_delete_role,
            k8s_get_role,
            k8s_list_roles,
            k8s_login,
            list_admins,
            list_all_userpass,
            list_realms,
            list_userpass_by_realm,
            login,
            remove_admin_from_realm,
            roles_endpoint,
            totp_disable,
            totp_generate,
            totp_verify,
            update_admin,
            update_realm,
            update_userpass,
            upsert_session,
            version_endpoint,
            whoami,
        },
        parameters::{DatabaseBackend, DatabaseParams, ServerParams},
    },
    session::{self, JwksData, JwtTokenConfig},
};
use actix_cors::Cors;
use actix_web::{
    App, Error, HttpResponse, HttpServer,
    body::MessageBody,
    dev::{ServerHandle, ServiceFactory, ServiceRequest, ServiceResponse},
    web::{self, Data, JsonConfig, PayloadConfig},
};
use cosmian_logger::{debug, info, trace, warn};
use jsonwebtoken::Algorithm;
use std::{
    io,
    sync::{Arc, mpsc},
};

/// Build a `Cors` middleware for *admin* scopes.
///
/// When `allowed_origins` is non-empty, only those origins are allowed.
/// When empty (the default), the scope uses same-origin policy and rejects
/// all cross-origin preflight requests.
fn build_admin_cors(allowed_origins: &[String]) -> Cors {
    if allowed_origins.is_empty() {
        // No cross-origin access — only same-origin requests are permitted.
        Cors::default()
    } else {
        let mut cors = Cors::default().allow_any_method().allow_any_header();
        for origin in allowed_origins {
            cors = cors.allowed_origin(origin);
        }
        cors
    }
}

/// Fallback handler for any route not matched by a registered scope.
///
/// Returns a structured `404` with the standard `{"errors": [...]}` envelope
/// (instead of Actix's bare empty-body 404), so an unsupported auth method
/// (e.g. `cert_auth`, which has no route) fails closed with a diagnosable error.
async fn unsupported_route(req: actix_web::HttpRequest) -> HttpResponse {
    warn!(
        "auth-verifier: no route for {} {} (unsupported or misconfigured auth method?)",
        req.method(),
        req.path()
    );
    HttpResponse::NotFound().json(serde_json::json!({
        "errors": ["route not found or authentication method not supported"]
    }))
}

#[cfg(feature = "openssl")]
use crate::tls::openssl_config::{create_openssl_acceptor, extract_openssl_peer_certificate};

#[cfg(feature = "rustls")]
use crate::tls::rustls_config::{extract_rustls_peer_certificate, rustls_server_config};

/// Inner function to start the test server asynchronously.
pub async fn start_auth_verifier(
    server_params: Arc<ServerParams>,
    auth_verifier_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> AuthResult<()> {
    // Log the server configuration
    info!("Authentication Server configuration: {server_params:#?}");

    // Instantiate and prepare the Authentication server
    let (server, _collector_handle) = prepare_auth_verifier(server_params).await?;

    // send the server handle to the caller
    if let Some(tx) = &auth_verifier_handle_tx {
        info!("Sending the server handle to the caller...");
        tx.send(server.handle())
            .context("failed to send server handle")?;
    }

    info!("Starting the HTTPS Auth auth server...");
    // Run the server and return the result
    server
        .await
        .map_err(|e: io::Error| crate::AuthError::Unexpected(format!("{e}")))
}

/// Prepares the auth server with the given parameters and returns the server instance.
/// This function is responsible for setting up the database, session store, and Actix app configuration.
/// It does not start the server, allowing the caller to control when to run it.
///
/// # Returns
/// A tuple containing the prepared Actix server
/// and an optional JoinHandle for the stale session collector task (if applicable).
async fn prepare_auth_verifier(
    params: Arc<ServerParams>,
) -> AuthResult<(actix_web::dev::Server, Option<tokio::task::JoinHandle<()>>)> {
    // Determine the address to bind the server to.
    let address = format!("{}:{}", &params.host_name, params.host_port);

    let database_params = if let Some(ref db_params) = params.database_params {
        db_params.clone()
    } else {
        DatabaseParams {
            backend: DatabaseBackend::SQLite,
            connection_url: "sqlite::auth_verifier.db".to_string(),
            max_connections: 5,
            min_connections: 1,
            connect_timeout_secs: 5,
            idle_timeout_secs: 300,
            auto_init_schema: true,
        }
    };
    let database = crate::database::create_database(&database_params).await?;

    // If a dev_seed config is present, ensure the seeded realm and realm-admin exist.
    if let Some(seed) = &params.dev_seed {
        use crate::server::dev_seed::seed_dev_realm_admin;
        seed_dev_realm_admin(database.as_ref(), seed).await?;
    }

    let session_store_params = params
        .sessions_store_params
        .clone()
        .unwrap_or_else(|| database_params.clone());
    let collector_config = params
        .stale_session_collector_config
        .clone()
        .unwrap_or_default();
    let (session_store, collector_handle) = crate::session::create_session_store_with_collector(
        &session_store_params,
        collector_config,
    )
    .await?;

    let jwks_manager = JwksManager::new(params.proxy_params.as_ref()).await;

    // let auth_public_url = params.params.auth_public_url.clone().unwrap_or_else(|| {
    //     format!(
    //         "http{}://{}:{}",
    //         if tls_config.is_some() { "s" } else { "" },
    //         &params.params.http_hostname,
    //         &params.params.http_port
    //     )
    // });

    let jwt_token_config = Arc::new(JwtTokenConfig {
        algorithm: Algorithm::ES256,
        encoding_key: params.get_jwt_encoding_key()?,
        decoding_key: params.get_jwt_decoding_key()?,
    });

    // Build the JWKS document once from the JWT signing public key.
    // Reads the same PEM path that get_jwt_decoding_key() uses.
    let jwks_pem_path = params
        .session_jwt_params
        .as_ref()
        .map(|p| p.jwt_ec_public_key.clone())
        .or_else(|| {
            params
                .tls_params
                .as_ref()
                .map(|t| t.server_certificate.clone())
        })
        .ok_or_else(|| {
            crate::AuthError::Init(
                "No JWKS public key: set session_jwt_params or tls_params".to_owned(),
            )
        })?;
    let jwks_pem = std::fs::read_to_string(&jwks_pem_path).map_err(|e| {
        crate::AuthError::Init(format!(
            "Failed to read JWT public key PEM for JWKS ({jwks_pem_path}): {e}"
        ))
    })?;
    let jwks_data = Arc::new(
        crate::session::build_jwks_from_pem(&jwks_pem)
            .map_err(|e| crate::AuthError::Init(format!("Failed to build JWKS: {e}")))?,
    );

    // Certificate signing key for `POST /certify` — optional, and deliberately always ES256
    // regardless of the (generic) algorithm used for session JWTs. `None` when
    // `certificate_jwt_params` is unset: /certify and the certificate JWKS become unavailable
    // but the rest of the server is unaffected.
    let cert_jwt_config = match (
        params.get_certificate_encoding_key()?,
        params.get_certificate_decoding_key()?,
    ) {
        (Some(encoding_key), Some(decoding_key)) => Some(Arc::new(JwtTokenConfig {
            algorithm: Algorithm::ES256,
            encoding_key,
            decoding_key,
        })),
        _ => None,
    };
    let cert_jwks_data = params
        .certificate_jwt_params
        .as_ref()
        .map(|cert_params| {
            let pem = std::fs::read_to_string(&cert_params.cert_ec_public_key).map_err(|e| {
                crate::AuthError::Init(format!(
                    "Failed to read certificate public key PEM for JWKS ({}): {e}",
                    cert_params.cert_ec_public_key
                ))
            })?;
            crate::session::build_jwks_from_pem(&pem).map_err(|e| {
                crate::AuthError::Init(format!("Failed to build certificate JWKS: {e}"))
            })
        })
        .transpose()?
        .map(Arc::new);

    // Clone test server params for HttpServer closure
    let server_params = params.clone();

    let default_username = params.default_username.clone();

    // Redis session store - store implements Clone
    let http_server = HttpServer::new(move || {
        build_app(
            server_params.clone(),
            database.clone(),
            session_store.clone(),
            jwks_manager.clone(),
            default_username.clone(),
            jwt_token_config.clone(),
            jwks_data.clone(),
            cert_jwt_config.clone(),
            cert_jwks_data.clone(),
        )
    });
    let http_server = http_server
        .keep_alive(actix_web::http::KeepAlive::Timeout(
            std::time::Duration::from_secs(120),
        ))
        .client_request_timeout(std::time::Duration::from_secs(10));

    #[cfg(feature = "openssl")]
    let http_server = if let Some(tls_params) = params.tls_params.as_ref() {
        http_server
            .on_connect(extract_openssl_peer_certificate)
            .bind_openssl(&address, create_openssl_acceptor(tls_params)?)
            .map_err(|e| {
                crate::AuthError::Init(format!("Failed binding the OpenSSL TLS connector: {e}"))
            })?
    } else {
        info!("TLS disabled — binding plain HTTP (dev mode only)");
        http_server
            .bind(&address)
            .map_err(|e| crate::AuthError::Init(format!("Failed binding plain HTTP: {e}")))?
    };

    #[cfg(all(feature = "rustls", not(feature = "openssl")))]
    let http_server = if let Some(tls_params) = params.tls_params.as_ref() {
        http_server
            .on_connect(extract_rustls_peer_certificate)
            .bind_rustls_0_23(&address, rustls_server_config(tls_params)?)
            .map_err(|e| {
                crate::AuthError::Init(format!("Failed binding the Rustls TLS connector: {e}"))
            })?
    } else {
        info!("TLS disabled — binding plain HTTP (dev mode only)");
        http_server
            .bind(&address)
            .map_err(|e| crate::AuthError::Init(format!("Failed binding plain HTTP: {e}")))?
    };

    #[cfg(not(any(feature = "openssl", feature = "rustls")))]
    let http_server = http_server
        .bind(&address)
        .map_err(|e| crate::AuthError::Init(format!("Failed binding plain HTTP: {e}")))?;

    debug!("Starting Authentication Server on {} ", &address,);
    Ok((http_server.run(), collector_handle))
}

/// Builds the Actix App with the given session middleware.
///
/// This function is generic over the session store type to support both
/// `CookieSessionStore` and `RedisSessionStore`.
#[allow(clippy::too_many_arguments)]
fn build_app(
    server_params: Arc<ServerParams>,
    database: Arc<dyn crate::database::Database>,
    session_store: Arc<dyn session::SessionStore>,
    jwks_manager: Arc<JwksManager>,
    default_username: Option<String>,
    jwt_token_config: Arc<JwtTokenConfig>,
    jwks_data: Arc<JwksData>,
    cert_jwt_config: Option<Arc<JwtTokenConfig>>,
    cert_jwks_data: Option<Arc<JwksData>>,
) -> App<
    impl ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse<impl MessageBody>,
        Error = Error,
        InitError = (),
    >,
> {
    trace!("Configuring the Actix server application...");

    let allowed_origins = server_params.allowed_origins.clone();

    // Per-IP rate limiter for the /login endpoint (see ServerParams::login_rate_limit_per_second
    // / login_rate_limit_burst). This limits brute-force credential-stuffing without impacting
    // normal usage.
    let login_rate_limit = LoginRateLimit::new(
        server_params.login_rate_limit_per_second,
        server_params.login_rate_limit_burst,
    );

    // Create an `App` instance and configure the passed data and the various scopes
    let app = App::new()
        .app_data(Data::new(server_params.clone()))
        .app_data(Data::new(database.clone()))
        .app_data(Data::new(session_store.clone()))
        .app_data(Data::new(jwt_token_config.clone()))
        .app_data(Data::new(jwks_data.clone()))
        .app_data(Data::new(cert_jwt_config.clone()))
        .app_data(Data::new(cert_jwks_data.clone()))
        .app_data(PayloadConfig::new(1_000_000))
        .app_data(JsonConfig::default().limit(1_000_000));

    #[cfg(test)]
    let app = {
        let idp: std::sync::Arc<dyn crate::tests::IdP + Send + Sync> = std::sync::Arc::new(
            crate::tests::RsaIdp::new("test_auth_issuer").expect("failed to create dummy idp"),
        );
        app.app_data(Data::new(idp))
    };

    // The client scope — permissive CORS so browser-based and CLI clients can reach it
    // from any origin. Rate limited per IP via the Governor middleware.
    let client_scope = web::scope("/login")
        .wrap(EnsureAuth::new(true, default_username.as_deref()))
        .wrap(JwtAuth::new(jwks_manager.clone()))
        .wrap(UsernamePasswordAuth::new(database.clone()))
        .wrap(ExtractRealm::new(database.clone()))
        .wrap(login_rate_limit)
        .wrap(Cors::permissive())
        .route("", web::post().to(login));

    let whoami_scope = web::scope("/whoami")
        .wrap(CookieAuthSameServer::new(
            session_store.clone(),
            jwt_token_config.clone(),
        ))
        .wrap(ExtractRealm::new(database.clone()))
        .wrap(build_admin_cors(&allowed_origins))
        .route("", web::get().to(whoami));

    let certify_scope = web::scope("/certify")
        .wrap(CookieAuthSameServer::new(
            session_store.clone(),
            jwt_token_config.clone(),
        ))
        .wrap(build_admin_cors(&allowed_origins))
        .route("", web::post().to(certify));

    // The public scope
    let public_scope = web::scope("/public")
        .wrap(Cors::permissive())
        .route("/version", web::get().to(version_endpoint))
        .route("/roles", web::get().to(roles_endpoint));

    // The JWKS discovery endpoint lives at the OIDC-standard `/.well-known/jwks.json`
    // path (outside `/public`) but must share the same permissive CORS behavior as
    // the other unauthenticated endpoints so browser-based clients can fetch it.
    let well_known_scope = web::scope("/.well-known")
        .wrap(Cors::permissive())
        .route("/jwks.json", web::get().to(jwks_well_known))
        .route(
            "/certificate-jwks.json",
            web::get().to(certificate_jwks_well_known),
        );

    #[cfg(feature = "swagger-ui")]
    let public_scope = {
        use crate::server::endpoints::{openapi_yaml_endpoint, swagger_ui_endpoint};
        public_scope
            .route("/openapi.yaml", web::get().to(openapi_yaml_endpoint))
            .route("/swagger-ui", web::get().to(swagger_ui_endpoint))
    };

    #[cfg(test)]
    let public_scope = public_scope.route("/jwks", web::get().to(crate::tests::jwks_endpoint));

    // Realm CRUD — lives under /admins/realms so it shares the same AdminAuth +
    // InjectAdminRealm middleware stack as other admin-authority endpoints.
    let realms_crud_scope = web::scope("/admins/realms")
        .wrap(AdminAuth::new(database.clone()))
        .wrap(CookieAuthSameServer::new(
            session_store.clone(),
            jwt_token_config.clone(),
        ))
        .wrap(InjectAdminRealm::new(database.clone()))
        .wrap(build_admin_cors(&allowed_origins))
        .service(create_realm)
        .service(get_realm)
        .service(update_realm)
        .service(delete_realm)
        .service(list_realms);

    let app_scope = web::scope("/realms")
        .wrap(AdminAuth::new(database.clone()))
        .wrap(CookieAuthSameServer::new(
            session_store.clone(),
            jwt_token_config.clone(),
        ))
        .wrap(ExtractRealm::new(database.clone()))
        .wrap(build_admin_cors(&allowed_origins))
        .service(create_userpass)
        .service(get_userpass)
        .service(update_userpass)
        .service(delete_userpass)
        .service(list_userpass_by_realm)
        .service(totp_generate)
        .service(totp_verify)
        .service(totp_disable);

    let sessions_scope = web::scope("/sessions")
        .wrap(CookieAuthSameServer::new(
            session_store.clone(),
            jwt_token_config.clone(),
        ))
        .wrap(ExtractRealm::new(database.clone()))
        .wrap(build_admin_cors(&allowed_origins))
        .service(upsert_session)
        .service(get_session_by_id)
        .service(get_session)
        .service(get_sessions_for_clients)
        .service(delete_sessions)
        .service(delete_expired_sessions)
        .service(delete_sessions_for_realm);

    let admins_scope = web::scope("/admins")
        .wrap(AdminAuth::new(database.clone()))
        .wrap(CookieAuthSameServer::new(
            session_store.clone(),
            jwt_token_config.clone(),
        ))
        .wrap(InjectAdminRealm::new(database.clone()))
        .wrap(build_admin_cors(&allowed_origins))
        // list_all_userpass must be registered before get_admin/update_admin/delete_admin
        // so that GET /admins/userpass is matched before GET /admins/{id}
        .service(list_all_userpass)
        .service(list_admins)
        .service(create_admin)
        .service(get_admin)
        .service(update_admin)
        .service(delete_admin)
        .service(add_admin_to_realm)
        .service(remove_admin_from_realm);

    // ── AppRole-compatible auth scopes ─────────────────────────────────────────
    //
    // Scope prefixes are kept intentionally specific to avoid Actix-web's
    // FIFO matching swallowing requests before they reach the right scope.
    //
    // /auth/approle/login  — unauthenticated AppRole login (registered first, most specific)
    // /auth/kubernetes/login — unauthenticated K8s login
    // /auth/approle        — AppRole admin CRUD (CookieAuthSameServer + AdminAuth)
    // /auth/kubernetes     — K8s admin CRUD
    // /auth/token          — token self-service (AppTokenExtract middleware)

    // Unauthenticated AppRole login — scope must be registered BEFORE /auth/approle
    // so that /auth/approle/login requests don't fall into the admin scope.
    let approle_login_scope = web::scope("/auth/approle/login")
        .wrap(Cors::permissive())
        .service(approle_login);

    // Unauthenticated K8s login
    let k8s_login_scope = web::scope("/auth/kubernetes/login")
        .wrap(Cors::permissive())
        .service(k8s_login);

    // AppRole admin CRUD
    let approle_admin_scope = web::scope("/auth/approle")
        .wrap(AdminAuth::new(database.clone()))
        .wrap(CookieAuthSameServer::new(
            session_store.clone(),
            jwt_token_config.clone(),
        ))
        .wrap(build_admin_cors(&allowed_origins))
        .service(approle_create_role)
        .service(approle_get_role_id)
        .service(approle_generate_secret_id)
        .service(approle_destroy_secret_id)
        .service(approle_delete_role)
        .service(approle_get_role)
        .service(approle_list_roles);

    // K8s admin CRUD
    let k8s_admin_scope = web::scope("/auth/kubernetes")
        .wrap(AdminAuth::new(database.clone()))
        .wrap(CookieAuthSameServer::new(
            session_store.clone(),
            jwt_token_config.clone(),
        ))
        .wrap(build_admin_cors(&allowed_origins))
        .service(k8s_create_role)
        .service(k8s_delete_role)
        .service(k8s_get_role)
        .service(k8s_list_roles);

    // Token self-service (requires valid X-Vault-Token header)
    let auth_token_scope = web::scope("/auth/token")
        .wrap(AppTokenExtract::new(database.clone()))
        .wrap(Cors::permissive())
        .service(auth_token_lookup_self)
        .service(auth_token_renew_self)
        .service(auth_token_revoke_self);

    let app = app
        .service(public_scope)
        .service(well_known_scope)
        .service(client_scope)
        .service(whoami_scope)
        .service(certify_scope)
        .service(sessions_scope)
        .service(realms_crud_scope)
        .service(app_scope)
        .service(admins_scope)
        // App auth scopes — most-specific prefixes first so Actix-web doesn't
        // swallow requests before they reach the right scope.
        .service(approle_login_scope) // /auth/approle/login  (unauthenticated)
        .service(k8s_login_scope) // /auth/kubernetes/login (unauthenticated)
        .service(approle_admin_scope) // /auth/approle        (admin CRUD)
        .service(k8s_admin_scope) // /auth/kubernetes     (admin CRUD)
        .service(auth_token_scope) // /auth/token          (self-service)
        // Structured fallback for any unmatched route (e.g. a SPIRE server
        // misconfigured with an unsupported auth method such as `cert_auth`,
        // which has no `/auth/cert/*` handler). Without this, Actix returns a
        // bare 404 with an empty body; here we fail closed but *loudly*, with the
        // same `{"errors": [...]}` envelope every other endpoint uses.
        .default_service(web::route().to(unsupported_route));

    #[cfg(feature = "admin-ui")]
    let app = {
        if let Some(ref ui_path) = server_params.admin_ui_path {
            use actix_files::{Files, NamedFile};
            let abs_path = ui_path
                .canonicalize()
                .unwrap_or_else(|_| ui_path.to_path_buf());
            info!("Serving admin UI from: {}", abs_path.display());
            let index = abs_path.join("index.html");
            let abs_path_clone = abs_path.clone();
            app.service(
                Files::new("/admin-ui", &abs_path_clone)
                    .index_file("index.html")
                    .default_handler(move |req: actix_web::dev::ServiceRequest| {
                        let index = index.clone();
                        async move {
                            let (req, _payload) = req.into_parts();
                            let file = NamedFile::open(&index)?;
                            let res = file.into_response(&req);
                            Ok(actix_web::dev::ServiceResponse::new(req, res))
                        }
                    }),
            )
            .route(
                "/",
                web::get().to(|| async {
                    HttpResponse::Found()
                        .append_header(("Location", "/admin-ui"))
                        .finish()
                }),
            )
        } else {
            app
        }
    };

    app
}
