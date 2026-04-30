import { SUPER_ADMIN_REALM_ID } from "../constants/apiPaths";
import type { Realm } from "../types/api";

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

export const mockVersion = "mock-0.1.0";