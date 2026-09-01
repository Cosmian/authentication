import type { OAuthClientRequest } from "../../types/api";

/** Convert the flat form values to an {@link OAuthClientRequest}. */
export function formValuesToRequest(values: Record<string, unknown>): OAuthClientRequest {
    const redirectUris = (values.redirect_uris as string)
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean);

    return {
        client_name: values.client_name as string,
        redirect_uris: redirectUris,
        grant_types: (values.grant_types as string[]) ?? ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scopes: (values.scopes as string[]) ?? ["openid", "profile", "email"],
        token_endpoint_auth_method: values.token_endpoint_auth_method as string,
    };
}
