export const API_LOGIN = "/login";
export const API_WHOAMI = "/whoami";
export const API_SESSIONS = "/sessions";
export const API_REALMS = "/admin/realms";
export const API_REALM = "/admin/realm";
export const API_USERS = "/users";
export const API_USER = "/users/user";
export const API_VERSION = "/public/version";

/** Realm-scoped paths — call with realmUserpassPath(realmId) */
export const realmUserpassPath = (realmId: string): string => `/realms/${encodeURIComponent(realmId)}/userpass`;
export const realmTotpPath = (realmId: string): string => `/realms/${encodeURIComponent(realmId)}/totp`;

/** The special admin realm sentinel */
export const ADMIN_REALM_ID = "_";
export const ADMIN_REALM_LABEL = "Admin";
