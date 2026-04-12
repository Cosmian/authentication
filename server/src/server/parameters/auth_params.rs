#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SessionJwtParams {
    /// The path to the JWT EC private key PEM file used for signing session tokens
    pub jwt_ec_private_key: String,

    /// The path to the JWT EC public key PEM file used for verifying session tokens
    pub jwt_ec_public_key: String,
}
