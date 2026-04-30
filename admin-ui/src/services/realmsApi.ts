import type { Realm } from "../types/api";
import { apiDelete, apiGet, apiPost, apiPut } from "./api";

const REALMS_PATH = "/admins/realms";

export function createRealmsApi(baseUrl: string) {
    return {
        list: (): Promise<Realm[]> => apiGet<Realm[]>(baseUrl, REALMS_PATH),

        get: (realmId: string): Promise<Realm> =>
            apiGet<Realm>(baseUrl, `${REALMS_PATH}/${encodeURIComponent(realmId)}`),

        create: (realm: Realm): Promise<Realm> => apiPost<Realm>(baseUrl, REALMS_PATH, realm),

        update: (realmId: string, realm: Realm): Promise<Realm> =>
            apiPut<Realm>(baseUrl, `${REALMS_PATH}/${encodeURIComponent(realmId)}`, realm),

        delete: (realmId: string): Promise<void> =>
            apiDelete(baseUrl, `${REALMS_PATH}/${encodeURIComponent(realmId)}`),
    };
}

export type RealmsApi = ReturnType<typeof createRealmsApi>;
