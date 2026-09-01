import type { OAuthClientRequest, OAuthClientResponse } from "../types/api";
import { apiDelete, apiGet, apiPost, apiPut } from "./api";

/**
 * CRUD service for OIDC / OAuth 2.0 clients registered within a realm.
 *
 * Routes:
 *   GET    /realms/{realm}/clients
 *   POST   /realms/{realm}/clients
 *   GET    /realms/{realm}/clients/{client_id}
 *   PUT    /realms/{realm}/clients/{client_id}
 *   DELETE /realms/{realm}/clients/{client_id}
 */
export function createOidcClientsApi(baseUrl: string) {
    const basePath = (realmId: string) => `/realms/${encodeURIComponent(realmId)}/clients`;
    const clientPath = (realmId: string, clientId: string) => `${basePath(realmId)}/${encodeURIComponent(clientId)}`;

    return {
        list: (realmId: string): Promise<OAuthClientResponse[]> => apiGet<OAuthClientResponse[]>(baseUrl, basePath(realmId)),

        get: (realmId: string, clientId: string): Promise<OAuthClientResponse> =>
            apiGet<OAuthClientResponse>(baseUrl, clientPath(realmId, clientId)),

        create: (realmId: string, req: OAuthClientRequest): Promise<OAuthClientResponse> =>
            apiPost<OAuthClientResponse>(baseUrl, basePath(realmId), req),

        update: (realmId: string, clientId: string, req: OAuthClientRequest): Promise<OAuthClientResponse> =>
            apiPut<OAuthClientResponse>(baseUrl, clientPath(realmId, clientId), req),

        delete: (realmId: string, clientId: string): Promise<void> => apiDelete(baseUrl, clientPath(realmId, clientId)),
    };
}

export type OidcClientsApi = ReturnType<typeof createOidcClientsApi>;
