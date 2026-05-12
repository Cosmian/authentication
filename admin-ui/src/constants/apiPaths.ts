export const API_LOGIN = "/login";
export const API_WHOAMI = "/whoami";
export const API_SESSIONS = "/sessions";
export const API_SESSIONS_EXPIRED = "/sessions/expired";
export const API_REALMS = "/admins/realms";
export const API_ADMINS = "/admins";
export const API_VERSION = "/public/version";

/** Realm-scoped paths */
export const realmUserpassPath = (realmId: string): string => `/realms/${encodeURIComponent(realmId)}/userpass`;
export const realmUserpassUserPath = (realmId: string, username: string): string =>
    `/realms/${encodeURIComponent(realmId)}/userpass/${encodeURIComponent(username)}`;
export const realmTotpPath = (realmId: string): string => `/realms/${encodeURIComponent(realmId)}/totp`;
export const realmTotpGeneratePath = (realmId: string): string =>
    `/realms/${encodeURIComponent(realmId)}/totp/generate`;
export const realmTotpVerifyPath = (realmId: string): string =>
    `/realms/${encodeURIComponent(realmId)}/totp/verify`;
export const realmTotpUserPath = (realmId: string, username: string): string =>
    `/realms/${encodeURIComponent(realmId)}/totp/${encodeURIComponent(username)}`;

/** Session realm-scoped paths */
export const sessionsRealmPath = (realmId: string): string =>
    `/sessions/realms/${encodeURIComponent(realmId)}`;

/** Admin-by-ID paths */
export const adminPath = (adminId: string): string => `/admins/${encodeURIComponent(adminId)}`;
export const adminRealmPath = (adminId: string, realmId: string): string =>
    `/admins/${encodeURIComponent(adminId)}/realms/${encodeURIComponent(realmId)}`;

/** The special super-admin realm sentinel */
export const SUPER_ADMIN_REALM_ID = "_";
export const SUPER_ADMIN_REALM_LABEL = "Super-Admin";
