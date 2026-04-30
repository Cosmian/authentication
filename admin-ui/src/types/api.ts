/** Identity Provider parameters for JWT/OIDC validation */
export interface IdpParams {
    jwks_url: string;
    jwt_audience: string | null;
}

/** JWT authentication parameters */
export interface JwtParams {
    idp_params: IdpParams[];
    smallest_refresh_interval_seconds: number | null;
}

/** Username/password authentication parameters */
export interface UsernamePasswordParams {
    allow_expired_passwords: boolean;
}

/** TOTP algorithm variants */
export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

/** TOTP realm-level parameters */
export interface TotpRealmParams {
    algorithm?: TotpAlgorithm;
    step?: number;
}

/** Authentication parameters for a realm */
export interface RealmAuthParams {
    jwt_params: JwtParams | null;
    username_password_params: UsernamePasswordParams | null;
    totp_params: TotpRealmParams | null;
}

/** Realm configuration */
export interface Realm {
    id: string;
    auth_params: RealmAuthParams;
    session_max_age_seconds: number;
    session_max_stale_age_seconds: number;
}

/** Authentication scheme identifiers */
export type AuthScheme = "up" | "jwt" | "cc" | "f2" | "dc";

/** Admin account */
export interface Admin {
    id: string;
    realms: string[];
    userpass: string | null;
    jwt: string | null;
    fido2: string | null;
    digital_credentials: Record<string, string> | null;
    client_certificate: string | null;
    totp_enabled: boolean | null;
    totp_secret: string | null;
    totp_auth_url: string | null;
}

/** Username/password credential entry */
export interface UserPass {
    realm: string;
    username: string;
    password: number[];
    change_password: boolean;
}

/** Session data */
export interface SessionData {
    session_id: string;
    realm_id: string;
    username: string;
    auth_scheme: AuthScheme;
    cookie_string: string;
    max_age_seconds: number;
    max_stale_age_seconds: number;
    created_at: number;
}
