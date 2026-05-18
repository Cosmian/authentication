import type { Admin } from "../types/api";
import { apiDelete, apiDeleteJson, apiGet, apiPost, apiPut } from "./api";

const ADMINS_PATH = "/admins";

export function createAdminsApi(baseUrl: string) {
    const adminPath = (adminId: string) => `${ADMINS_PATH}/${encodeURIComponent(adminId)}`;
    const adminRealmPath = (adminId: string, realmId: string) => `${adminPath(adminId)}/realms/${encodeURIComponent(realmId)}`;

    return {
        list: (): Promise<Admin[]> => apiGet<Admin[]>(baseUrl, ADMINS_PATH),

        get: (adminId: string): Promise<Admin> => apiGet<Admin>(baseUrl, adminPath(adminId)),

        create: (admin: Admin): Promise<Admin> => apiPost<Admin>(baseUrl, ADMINS_PATH, admin),

        update: (adminId: string, admin: Admin): Promise<Admin> => apiPut<Admin>(baseUrl, adminPath(adminId), admin),

        delete: (adminId: string): Promise<void> => apiDelete(baseUrl, adminPath(adminId)),

        addToRealm: (adminId: string, realmId: string): Promise<Admin> => apiPut<Admin>(baseUrl, adminRealmPath(adminId, realmId), null),

        removeFromRealm: (adminId: string, realmId: string): Promise<Admin> =>
            apiDeleteJson<Admin>(baseUrl, adminRealmPath(adminId, realmId)),
    };
}

export type AdminsApi = ReturnType<typeof createAdminsApi>;
