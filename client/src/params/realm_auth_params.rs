use serde::{Deserialize, Serialize};

use crate::{JwtParams, SamlParams, TotpRealmParams, UsernamePasswordParams};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RealmAuthParams {
    pub jwt_params: Option<JwtParams>,
    pub username_password_params: Option<UsernamePasswordParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_params: Option<TotpRealmParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_params: Option<SamlParams>,
}
