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

/** Authentication next step after login */
export type AuthenticationNextStep = "Authenticated" | "TotpRequired" | "ChangePassword";

/** Login request body */
export interface LoginRequest {
    public_key_pem?: string | null;
    totp_code?: string | null;
}

/** Authentication result from POST /login */
export interface AuthenticationResult {
    next_step: AuthenticationNextStep;
    session_id: string | null;
}

/** JWT claims from GET /whoami */
export interface ClientClaims {
    iss: string;
    sub: string;
    aud: string | string[];
    exp: number;
    iat: number;
    as_as: string;
    as_rid: string;
}

/** Delete sessions request body */
export interface DeleteSessionsRequest {
    session_ids: string[];
}

/** Sessions action for bulk session operations */
export type SessionsAction = "LogoutOtherSessions" | "LogoutAllSessions";

/** Request to get sessions for specific clients */
export interface GetSessionsForClientsRequest {
    authenticated_clients: AuthenticatedClientScheme[];
}

/** Authenticated client identification */
export interface AuthenticatedClientScheme {
    username: string;
    auth_scheme: string;
}

/** Response from get sessions for clients */
export interface GetSessionsForClientsResponse {
    session_ids: string[];
}

/** TOTP generate request body */
export interface TotpGenerateRequest {
    username: string;
    issuer?: string | null;
}

/** TOTP generate response */
export interface TotpGenerateResponse {
    secret_base32: string;
    otpauth_url: string;
}

/** TOTP verify request body */
export interface TotpVerifyRequest {
    username: string;
    code: string;
}
