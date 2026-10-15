import { ApiError } from "../services/api";

/**
 * Claim names this server sets itself in session JWTs and certificates (see
 * `reserved_claim_names` in client/src/models/claim_policy.rs); mapped attributes can't use them.
 */
export const RESERVED_CLAIM_NAMES: readonly string[] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "roles",
    "as_as",
    "as_rid",
    "realm_id",
    "auth_scheme",
    "verification_key",
];

/** Signing certificates within this many days of expiry are flagged. */
export const CERTIFICATE_WARNING_DAYS = 30;

export type ExpiryLevel = "expired" | "soon" | "ok";

export function expiryLevel(notAfter: Date, now: Date = new Date()): ExpiryLevel {
    const days = (notAfter.getTime() - now.getTime()) / 86_400_000;
    if (days <= 0) return "expired";
    return days <= CERTIFICATE_WARNING_DAYS ? "soon" : "ok";
}

/** `https://host[:port]` with nothing after it, as the server requires for return origins. */
export function isBareHttpsOrigin(value: string): boolean {
    try {
        const url = new URL(value);
        return url.protocol === "https:" && url.pathname === "/" && !url.search && !url.hash && !url.username;
    } catch {
        return false;
    }
}

export function acsUrlError(value: string, realmId: string): string | null {
    if (!value.startsWith("https://")) return "must be an https URL";
    const expected = `/saml/${realmId}/acs`;
    if (realmId && !value.endsWith(expected)) return `must end with ${expected}`;
    return null;
}

export function defaultReturnUrlError(value: string, origins: string[]): string | null {
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        return "must be a valid URL";
    }
    if (url.protocol !== "https:") return "must use https";
    const allowed = origins.some((origin) => {
        try {
            return new URL(origin).origin === url.origin;
        } catch {
            return false;
        }
    });
    return allowed ? null : "its origin must be listed in the allowed return origins";
}

export interface ClaimMapping {
    attribute?: string;
    claim?: string;
}

export function reservedClaimError(claim: string): string | null {
    return RESERVED_CLAIM_NAMES.includes(claim.trim()) ? `'${claim.trim()}' is a reserved claim name` : null;
}

/** An attribute or claim name used by more than one mapping, or null. */
export function duplicateMappingError(mappings: ClaimMapping[]): string | null {
    const attributes = new Set<string>();
    const claims = new Set<string>();
    for (const { attribute = "", claim = "" } of mappings) {
        if (attribute && attributes.has(attribute)) return `attribute '${attribute}' is mapped twice`;
        if (claim && claims.has(claim)) return `claim '${claim}' is mapped twice`;
        attributes.add(attribute);
        claims.add(claim);
    }
    return null;
}

export interface SamlFieldError {
    field: string;
    message: string;
}

/** A server 400 naming a SAML setting (`saml_params.<field>: <reason>`), or null. */
export function samlFieldError(error: unknown): SamlFieldError | null {
    if (!(error instanceof ApiError) || error.status !== 400) return null;
    const match = /saml_params\.([a-z_]+): ([\s\S]*)$/.exec(serverMessage(error));
    return match ? { field: match[1], message: match[2] } : null;
}

/** The server's error text: its JSON string body without the variant prefix. */
export function serverMessage(error: ApiError): string {
    let body: unknown = error.message;
    try {
        body = JSON.parse(error.message);
    } catch {
        // Not JSON: use the raw text.
    }
    const text = typeof body === "string" ? body : error.message;
    return text.replace(/^Bad Request: /, "");
}
