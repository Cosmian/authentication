use crate::{
    AuthResult, auth_error,
    client::{AuthClient, AuthClientScheme},
    server::parameters::ServerParams,
};
use actix_web::dev::ServerHandle;
use std::{fs, thread::JoinHandle};

#[derive(Debug)]
pub struct TestsContext {
    pub server_params: ServerParams,
    pub server_handle: ServerHandle,
    pub thread_handle: Option<JoinHandle<AuthResult<()>>>,
}

impl Drop for TestsContext {
    fn drop(&mut self) {
        // Ensure the server is stopped when the context is dropped (including
        // on test panic). This prevents port leaks that would cause subsequent
        // tests to fail with "Address already in use".
        // stop() sends the shutdown signal immediately via an internal channel;
        // the returned future is only for awaiting completion, which we cannot
        // do in Drop. Dropping the future is safe — the signal was already sent.
        drop(self.server_handle.stop(true));
    }
}

impl TestsContext {
    pub async fn stop_server(mut self) -> AuthResult<()> {
        self.server_handle.stop(false).await;
        if let Some(handle) = self.thread_handle.take() {
            handle
                .join()
                .map_err(|_e| auth_error!("failed joining the stop thread"))?
        } else {
            Ok(())
        }
    }

    pub fn get_client_url(&self) -> String {
        let host = if self.server_params.host_name == "localhost" {
            // failure to switch to IP will fail server CA verification on the client
            "127.0.0.1"
        } else {
            &self.server_params.host_name
        };
        format!("https://{}:{}", host, self.server_params.host_port)
    }

    pub fn get_test_client(&self, auth: AuthClientScheme) -> AuthClient {
        AuthClient::new(
            &self.get_client_url(),
            &fs::read_to_string("src/tests/certificates/ec/auth.ca.pem")
                .expect("failed to read the CA certificate"),
            auth,
        )
        .unwrap()
    }
}
