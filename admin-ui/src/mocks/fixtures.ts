import { SUPER_ADMIN_REALM_ID } from "../constants/apiPaths";
import type { Admin, AuthenticationResult, ClientClaims, Realm, TotpGenerateResponse, UserPass } from "../types/api";

export const mockRealms: Realm[] = [
    {
        id: SUPER_ADMIN_REALM_ID,
        auth_params: {
            username_password_params: { allow_expired_passwords: false },
            jwt_params: null,
            totp_params: null,
        },
        session_max_age_seconds: 86400,
        session_max_stale_age_seconds: 3600,
    },
    {
        id: "my-service",
        auth_params: {
            username_password_params: { allow_expired_passwords: false },
            jwt_params: {
                idp_params: [
                    {
                        jwks_url: "https://accounts.google.com/.well-known/openid-configuration",
                        jwt_audience: "my-client-id.apps.googleusercontent.com",
                    },
                ],
                smallest_refresh_interval_seconds: 300,
            },
            totp_params: { algorithm: "SHA1", step: 30 },
        },
        session_max_age_seconds: 3600,
        session_max_stale_age_seconds: 1800,
    },
    {
        id: "internal-app",
        auth_params: {
            username_password_params: { allow_expired_passwords: true },
            jwt_params: null,
            totp_params: null,
        },
        session_max_age_seconds: 7200,
        session_max_stale_age_seconds: 900,
    },
];

export const mockVersion = { version: "mock-0.1.0" };

export const mockAdmins: Admin[] = [
    {
        id: "admin",
        realms: [SUPER_ADMIN_REALM_ID, "my-service"],
        userpass: "admin",
        jwt: null,
        fido2: null,
        digital_credentials: null,
        client_certificate: null,
        totp_enabled: false,
        totp_secret: null,
        totp_auth_url: null,
    },
    {
        id: "alice",
        realms: ["my-service"],
        userpass: "alice",
        jwt: null,
        fido2: null,
        digital_credentials: null,
        client_certificate: null,
        totp_enabled: true,
        totp_secret: null,
        totp_auth_url: null,
    },
    {
        id: "bob",
        realms: ["my-service", "internal-app"],
        userpass: "bob",
        jwt: "bob@example.com",
        fido2: null,
        digital_credentials: null,
        client_certificate: null,
        totp_enabled: false,
        totp_secret: null,
        totp_auth_url: null,
    },
];

/** Convenience alias for the logged-in admin (first entry) */
export const mockAdmin: Admin = mockAdmins[0];

export const mockCredentials: Record<string, UserPass[]> = {
    "my-service": [
        { realm: "my-service", username: "user1", password: [], change_password: false },
        { realm: "my-service", username: "user2", password: [], change_password: true },
    ],
    "internal-app": [
        { realm: "internal-app", username: "svc-account", password: [], change_password: false },
    ],
};

export const mockLoginSuccess: AuthenticationResult = {
    next_step: "Authenticated",
    session_id: "550e8400-e29b-41d4-a716-446655440000",
};

export const mockWhoamiClaims: ClientClaims = {
    iss: "auth-server",
    sub: "admin",
    aud: [SUPER_ADMIN_REALM_ID],
    exp: Math.floor(Date.now() / 1000) + 86400,
    iat: Math.floor(Date.now() / 1000),
    as_as: "up",
    as_rid: SUPER_ADMIN_REALM_ID,
};

export const mockTotpGenerate: TotpGenerateResponse = {
    secret_base32: "JBSWY3DPEHPK3PXP",
    otpauth_url: "otpauth://totp/auth-server:user1?secret=JBSWY3DPEHPK3PXP&issuer=auth-server",
};