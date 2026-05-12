import { apiDelete } from "./api";

export function createSessionsApi(baseUrl: string) {
    return {
        revokeAllForRealm: (realmId: string): Promise<void> =>
            apiDelete(baseUrl, `/sessions/realms/${encodeURIComponent(realmId)}`),

        purgeExpired: (): Promise<void> => apiDelete(baseUrl, "/sessions/expired"),
    };
}

export type SessionsApi = ReturnType<typeof createSessionsApi>;
