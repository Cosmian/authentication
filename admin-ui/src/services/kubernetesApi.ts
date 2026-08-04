import type { K8sRoleConfig, K8sRoleRequest } from "../types/api";
import { API_KUBERNETES } from "../constants/apiPaths";
import { apiDelete, apiGet, apiPost } from "./api";

/** Client for the Vault-compatible Kubernetes role admin endpoints (global, cookie-authed). */
export function createKubernetesApi(baseUrl: string) {
    const rolePath = (name: string) => `${API_KUBERNETES}/role/${encodeURIComponent(name)}`;

    return {
        list: async (): Promise<string[]> => {
            const res = await apiGet<{ data: { keys: string[] } }>(baseUrl, `${API_KUBERNETES}/role?list=true`);
            return res.data.keys;
        },

        get: async (name: string): Promise<K8sRoleConfig> => {
            const res = await apiGet<{ data: K8sRoleConfig }>(baseUrl, rolePath(name));
            return res.data;
        },

        save: (name: string, role: K8sRoleRequest): Promise<unknown> => apiPost<unknown>(baseUrl, rolePath(name), role),

        delete: (name: string): Promise<void> => apiDelete(baseUrl, rolePath(name)),
    };
}

export type KubernetesApi = ReturnType<typeof createKubernetesApi>;
