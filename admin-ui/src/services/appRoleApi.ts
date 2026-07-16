import type { AppRoleRoleConfig, AppRoleRoleRequest, AppRoleSecretIdRequest, AppRoleSecretIdResult } from "../types/api";
import { API_APPROLE } from "../constants/apiPaths";
import { apiDelete, apiGet, apiPost } from "./api";

/** Client for the Vault-compatible AppRole admin endpoints (global, cookie-authed). */
export function createAppRoleApi(baseUrl: string) {
    const rolePath = (name: string) => `${API_APPROLE}/role/${encodeURIComponent(name)}`;

    return {
        list: async (): Promise<string[]> => {
            const res = await apiGet<{ data: { keys: string[] } }>(baseUrl, `${API_APPROLE}/role?list=true`);
            return res.data.keys;
        },

        get: async (name: string): Promise<AppRoleRoleConfig> => {
            const res = await apiGet<{ data: AppRoleRoleConfig }>(baseUrl, rolePath(name));
            return res.data;
        },

        save: (name: string, role: AppRoleRoleRequest): Promise<unknown> => apiPost<unknown>(baseUrl, rolePath(name), role),

        delete: (name: string): Promise<void> => apiDelete(baseUrl, rolePath(name)),

        generateSecretId: async (name: string, req: AppRoleSecretIdRequest): Promise<AppRoleSecretIdResult> => {
            const res = await apiPost<{ data: AppRoleSecretIdResult }>(baseUrl, `${rolePath(name)}/secret-id`, req);
            return res.data;
        },

        destroySecretId: (name: string, secretIdAccessor: string): Promise<unknown> =>
            apiPost<unknown>(baseUrl, `${rolePath(name)}/secret-id/destroy`, { secret_id_accessor: secretIdAccessor }),
    };
}

export type AppRoleApi = ReturnType<typeof createAppRoleApi>;
