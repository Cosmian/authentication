import type { TokenInfo } from "../types/api";
import { API_TOKEN } from "../constants/apiPaths";
import { apiGetWithToken, apiPostWithToken } from "./api";

/** New lease duration (seconds) returned when renewing a token. */
export interface TokenRenewResult {
    lease_duration: number;
    renewable: boolean;
    policies: string[];
}

/**
 * Client for the Vault-compatible token self-service endpoints. These authenticate
 * via the `X-Vault-Token` header (a pasted machine token), NOT the admin cookie.
 */
export function createTokenApi(baseUrl: string) {
    return {
        lookup: async (token: string): Promise<TokenInfo> => {
            const res = await apiGetWithToken<{ data: TokenInfo }>(baseUrl, `${API_TOKEN}/lookup-self`, token);
            return res.data;
        },

        renew: async (token: string): Promise<TokenRenewResult> => {
            const res = await apiPostWithToken<{ auth: TokenRenewResult }>(baseUrl, `${API_TOKEN}/renew-self`, token);
            return res.auth;
        },

        revoke: (token: string): Promise<void> => apiPostWithToken<void>(baseUrl, `${API_TOKEN}/revoke-self`, token),
    };
}

export type TokenApi = ReturnType<typeof createTokenApi>;
