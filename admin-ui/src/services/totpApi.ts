import type { TotpGenerateRequest, TotpGenerateResponse, TotpVerifyRequest } from "../types/api";
import { apiDelete, apiPost } from "./api";

export function createTotpApi(baseUrl: string) {
    const generatePath = (realmId: string) => `/realms/${encodeURIComponent(realmId)}/totp/generate`;
    const verifyPath = (realmId: string) => `/realms/${encodeURIComponent(realmId)}/totp/verify`;
    const disablePath = (realmId: string, username: string) =>
        `/realms/${encodeURIComponent(realmId)}/totp/${encodeURIComponent(username)}`;

    return {
        generate: (realmId: string, request: TotpGenerateRequest): Promise<TotpGenerateResponse> =>
            apiPost<TotpGenerateResponse>(baseUrl, generatePath(realmId), request),

        verify: (realmId: string, request: TotpVerifyRequest): Promise<void> => apiPost<void>(baseUrl, verifyPath(realmId), request),

        disable: (realmId: string, username: string): Promise<void> => apiDelete(baseUrl, disablePath(realmId, username)),
    };
}

export type TotpApi = ReturnType<typeof createTotpApi>;
