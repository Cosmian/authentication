import type { UserPass } from "../types/api";
import { apiDelete, apiGet, apiPost, apiPut } from "./api";

export function createCredentialsApi(baseUrl: string) {
    const basePath = (realmId: string) => `/realms/${encodeURIComponent(realmId)}/userpass`;
    const userPath = (realmId: string, username: string) => `${basePath(realmId)}/${encodeURIComponent(username)}`;

    return {
        list: (realmId: string): Promise<UserPass[]> => apiGet<UserPass[]>(baseUrl, basePath(realmId)),

        get: (realmId: string, username: string): Promise<UserPass> => apiGet<UserPass>(baseUrl, userPath(realmId, username)),

        create: (realmId: string, userpass: UserPass): Promise<UserPass> => apiPost<UserPass>(baseUrl, basePath(realmId), userpass),

        update: (realmId: string, username: string, userpass: UserPass): Promise<UserPass> =>
            apiPut<UserPass>(baseUrl, userPath(realmId, username), userpass),

        delete: (realmId: string, username: string): Promise<void> => apiDelete(baseUrl, userPath(realmId, username)),
    };
}

export type CredentialsApi = ReturnType<typeof createCredentialsApi>;
