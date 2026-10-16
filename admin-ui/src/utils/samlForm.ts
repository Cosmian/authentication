import type { SamlParams } from "../types/api";
import type { ClaimMapping } from "./samlValidation";

/** The SAML section's form values; the IdP fields are left out since the server derives them. */
export interface SamlFormValues {
    metadata_xml: string;
    sp_entity_id: string;
    sp_acs_url: string;
    subject_attribute?: string;
    normalize_subject_case: boolean;
    role_attribute?: string;
    claim_map: ClaimMapping[];
    allowed_return_origins: string[];
    default_return_url: string;
}

/** Where this server's SAML endpoints for `realmId` live, as seen from `baseUrl`. */
export function defaultSpUrls(baseUrl: string, realmId: string): { entityId: string; acsUrl: string } {
    const realm = encodeURIComponent(realmId);
    return { entityId: `${baseUrl}/saml/${realm}`, acsUrl: `${baseUrl}/saml/${realm}/acs` };
}

export function toSamlFormValues(params: SamlParams | null | undefined): SamlFormValues {
    return {
        metadata_xml: params?.metadata_xml ?? "",
        sp_entity_id: params?.sp_entity_id ?? "",
        sp_acs_url: params?.sp_acs_url ?? "",
        subject_attribute: params?.subject_attribute,
        normalize_subject_case: params?.normalize_subject_case ?? false,
        role_attribute: params?.role_attribute,
        claim_map: Object.entries(params?.attribute_claim_map ?? {}).map(([attribute, claim]) => ({ attribute, claim })),
        allowed_return_origins: params?.allowed_return_origins ?? [],
        default_return_url: params?.default_return_url ?? "",
    };
}

function optional(value: string | undefined): string | undefined {
    const trimmed = value?.trim();
    return trimmed ? trimmed : undefined;
}

export function toSamlParams(values: Partial<SamlFormValues> | undefined): SamlParams {
    return {
        idp_entity_id: "",
        idp_sso_url: "",
        idp_signing_certificates: [],
        metadata_xml: values?.metadata_xml?.trim() ?? "",
        sp_entity_id: values?.sp_entity_id?.trim() ?? "",
        sp_acs_url: values?.sp_acs_url?.trim() ?? "",
        subject_attribute: optional(values?.subject_attribute),
        normalize_subject_case: values?.normalize_subject_case ?? false,
        role_attribute: optional(values?.role_attribute),
        attribute_claim_map: Object.fromEntries(
            (values?.claim_map ?? []).map(({ attribute = "", claim = "" }) => [attribute.trim(), claim.trim()]),
        ),
        allowed_return_origins: (values?.allowed_return_origins ?? []).map((origin) => origin.trim()),
        default_return_url: values?.default_return_url?.trim() ?? "",
    };
}

/** Whether the SAML form values differ from the saved settings. */
export function isSamlDirty(current: Partial<SamlFormValues> | undefined, saved: SamlParams | null | undefined): boolean {
    return JSON.stringify(toSamlParams(current)) !== JSON.stringify(toSamlParams(toSamlFormValues(saved)));
}
