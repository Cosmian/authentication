use crate::{
    AdminAuth, AuthResult, AuthResultHelper, CookieAuthSameServer, ExtractRealm, InjectAdminRealm,
    UsernamePasswordAuth,
    middleware::{EnsureAuth, JwksManager, JwtAuth},
    server::{
        endpoints::{
            add_admin_to_realm, create_admin, create_realm, create_userpass, delete_admin,
            delete_expired_sessions, delete_realm, delete_sessions, delete_sessions_for_realm,
            delete_userpass, get_admin, get_realm, get_session, get_session_by_id,
            get_sessions_for_clients, get_userpass, list_admins, list_all_userpass, list_realms,
            list_userpass_by_realm, login, remove_admin_from_realm, totp_disable, totp_generate,
            totp_verify, update_admin, update_realm, update_userpass, upsert_session,
            version_endpoint, whoami,
        },
        parameters::{DatabaseBackend, DatabaseParams, DevSeedParams, ServerParams},
    },
    session::{self, JwtTokenConfig},
};
use actix_cors::Cors;
use actix_web::{
    App, Error, HttpServer,
    body::MessageBody,
    dev::{ServerHandle, ServiceFactory, ServiceRequest, ServiceResponse},
    web::{self, Data, JsonConfig, PayloadConfig},
};
use cosmian_logger::{debug, info, trace};
use jsonwebtoken::Algorithm;
use std::{
    io,
    sync::{Arc, mpsc},
};

#[cfg(feature = "openssl")]
use crate::tls::openssl_config::{create_openssl_acceptor, extract_openssl_peer_certificate};

#[cfg(feature = "rustls")]
use crate::tls::rustls_config::{extract_rustls_peer_certificate, rustls_server_config};

/// Seeds a realm and a realm-scoped admin account for development use.
/// All operations are idempotent — nothing is overwritten if it already exists.
async fn seed_dev_realm_admin(
    db: &dyn crate::database::Database,
    seed: &DevSeedParams,
) -> AuthResult<()> {
    use crate::database::hash_password_with_argon2;
    use crate::models::{ADMIN_REALM, Admin, Realm, UserPass};
    use crate::{RealmAuthParams, UsernamePasswordParams};

    // 1. Create the realm if it does not exist.
    if db.get_realm(&seed.realm_id).await?.is_none() {
        let realm = Realm {
            id: seed.realm_id.clone(),
            auth_params: RealmAuthParams {
                username_password_params: Some(UsernamePasswordParams {
                    allow_expired_passwords: false,
                }),
                ..Default::default()
            },
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 3600,
        };
        db.create_realm(&realm).await.map_err(|e| {
            crate::AuthError::Init(format!("dev_seed: failed to create realm '{}': {e}", seed.realm_id))
        })?;
        info!("dev_seed: created realm '{}'", seed.realm_id);
    }

    // 2. Create the credential in the admin realm if it does not exist.
    if db
        .get_userpass(ADMIN_REALM, &seed.admin_username)
        .await?
        .is_none()
    {
        let hashed = hash_password_with_argon2(&seed.admin_username, &seed.admin_password)
            .map_err(|e| {
                crate::AuthError::Init(format!(
                    "dev_seed: failed to hash password for '{}': {e}",
                    seed.admin_username
                ))
            })?;
        let userpass = UserPass {
            realm: ADMIN_REALM.to_string(),
            username: seed.admin_username.clone(),
            password: hashed,
            change_password: true,
        };
        db.create_userpass(&userpass).await.map_err(|e| {
            crate::AuthError::Init(format!(
                "dev_seed: failed to create credential for '{}': {e}",
                seed.admin_username
            ))
        })?;
        info!("dev_seed: created credential for '{}'", seed.admin_username);
    }

    // 3. Create the admin record if it does not exist.
    if db.get_admin(&seed.admin_username).await?.is_none() {
        let admin = Admin {
            id: seed.admin_username.clone(),
            realms: vec![seed.realm_id.clone()],
            userpass: Some(seed.admin_username.clone()),
            jwt: None,
            fido2: None,
            digital_credentials: None,
            client_certificate: None,
            totp_enabled: None,
            totp_secret: None,
            totp_auth_url: None,
        };
        db.create_admin(&admin).await.map_err(|e| {
            crate::AuthError::Init(format!(
                "dev_seed: failed to create admin '{}': {e}",
                seed.admin_username
            ))
        })?;
        info!(
            "dev_seed: created realm-admin '{}' for realm '{}'",
            seed.admin_username, seed.realm_id
        );
    }

    Ok(())
}

/// Inner function to start the test server asynchronously.
pub async fn start_auth_server(
    server_params: Arc<ServerParams>,
    auth_server_handle_tx: Option<mpsc::Sender<ServerHandle>>,
) -> AuthResult<()> {
    // Log the server configuration
    info!("Authentication Server configuration: {server_params:#?}");

    // Instantiate and prepare the Authentication server
    let (server, _collector_handle) = prepare_auth_server(server_params).await?;

    // send the server handle to the caller
    if let Some(tx) = &auth_server_handle_tx {
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
async fn prepare_auth_server(
    params: Arc<ServerParams>,
) -> AuthResult<(actix_web::dev::Server, Option<tokio::task::JoinHandle<()>>)> {
    // Determine the address to bind the server to.
    let address = format!("{}:{}", &params.host_name, params.host_port);

    let database_params = if let Some(ref db_params) = params.database_params {
        db_params.clone()
    } else {
        DatabaseParams {
            backend: DatabaseBackend::SQLite,
            connection_url: "sqlite::auth_server.db".to_string(),
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
        )
    });
    let http_server = http_server
        .keep_alive(actix_web::http::KeepAlive::Timeout(
            std::time::Duration::from_secs(120),
        ))
        .client_request_timeout(std::time::Duration::from_secs(10));

    #[cfg(feature = "openssl")]
    let http_server = http_server
        .on_connect(extract_openssl_peer_certificate)
        .bind_openssl(&address, create_openssl_acceptor(&params.tls_params)?)
        .map_err(|e| {
            crate::AuthError::Init(format!("Failed binding the OpenSSL TLS connector: {e}"))
        })?;

    #[cfg(feature = "rustls")]
    let http_server = http_server
        .on_connect(extract_rustls_peer_certificate)
        .bind_rustls_0_23(&address, rustls_server_config(&params.tls_params)?)
        .map_err(|e| {
            crate::AuthError::Init(format!("Failed binding the Rustls TLS connector: {e}"))
        })?;

    debug!("Starting Authentication Server on {} ", &address,);
    Ok((http_server.run(), collector_handle))
}

/// Builds the Actix App with the given session middleware.
///
/// This function is generic over the session store type to support both
/// `CookieSessionStore` and `RedisSessionStore`.
fn build_app(
    server_params: Arc<ServerParams>,
    database: Arc<dyn crate::database::Database>,
    session_store: Arc<dyn session::SessionStore>,
    jwks_manager: Arc<JwksManager>,
    default_username: Option<String>,
    jwt_token_config: Arc<JwtTokenConfig>,
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

    // Create an `App` instance and configure the passed data and the various scopes
    let app = App::new()
        .app_data(Data::new(server_params.clone()))
        .app_data(Data::new(database.clone()))
        .app_data(Data::new(session_store.clone()))
        .app_data(Data::new(jwt_token_config.clone()))
        .app_data(PayloadConfig::new(1_000_000))
        .app_data(JsonConfig::default().limit(1_000_000));

    #[cfg(test)]
    let app = {
        let idp: std::sync::Arc<dyn crate::tests::IdP + Send + Sync> = std::sync::Arc::new(
            crate::tests::RsaIdp::new("test_auth_issuer").expect("failed to create dummy idp"),
        );
        app.app_data(Data::new(idp))
    };

    // The client scope
    let client_scope = web::scope("/login")
        .wrap(EnsureAuth::new(true, default_username.as_deref()))
        .wrap(JwtAuth::new(jwks_manager.clone()))
        .wrap(UsernamePasswordAuth::new(database.clone()))
        .wrap(ExtractRealm::new(database.clone()))
        // TODO : Remove permissive CORS and replace with more restrictive configuration if needed
        .wrap(Cors::permissive())
        .route("", web::post().to(login));

    let whoami_scope = web::scope("/whoami")
        .wrap(CookieAuthSameServer::new(
            session_store.clone(),
            jwt_token_config.clone(),
        ))
        .wrap(ExtractRealm::new(database.clone()))
        .wrap(Cors::permissive())
        .route("", web::get().to(whoami));

    // The public scope
    let public_scope = web::scope("/public")
        .wrap(Cors::permissive())
        .route("/version", web::get().to(version_endpoint));

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
        .wrap(Cors::permissive())
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
        .wrap(Cors::permissive())
        .service(create_userpass)
        .service(get_userpass)
        .service(update_userpass)
        .service(delete_userpass)
        .service(list_userpass_by_realm)
        .service(totp_generate)
        .service(totp_verify)
        .service(totp_disable);

    let sessions_scope = web::scope("/sessions")
        .wrap(Cors::permissive())
        .wrap(ExtractRealm::new(database.clone()))
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
        .wrap(Cors::permissive())
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

    let app = app
        .service(public_scope)
        .service(client_scope)
        .service(whoami_scope)
        .service(sessions_scope)
        .service(realms_crud_scope)
        .service(app_scope)
        .service(admins_scope);

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
        } else {
            app
        }
    };

    app
}
