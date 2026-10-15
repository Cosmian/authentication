import { describe, expect, it } from "vitest";
import { ApiError } from "../../../src/services/api";
import type { SamlParams } from "../../../src/types/api";
import { isSamlDirty, toSamlFormValues, toSamlParams } from "../../../src/utils/samlForm";
import {
    acsUrlError,
    defaultReturnUrlError,
    duplicateMappingError,
    expiryLevel,
    isBareHttpsOrigin,
    reservedClaimError,
    samlFieldError,
} from "../../../src/utils/samlValidation";

const saved: SamlParams = {
    idp_entity_id: "https://idp.example.com/metadata",
    idp_sso_url: "https://idp.example.com/sso",
    idp_signing_certificates: ["-----BEGIN CERTIFICATE-----"],
    metadata_xml: "<md:EntityDescriptor/>",
    sp_entity_id: "https://auth.example.com/saml/acme",
    sp_acs_url: "https://auth.example.com/saml/acme/acs",
    subject_attribute: "email",
    normalize_subject_case: true,
    attribute_claim_map: { department: "dept" },
    allowed_return_origins: ["https://app.example.com"],
    default_return_url: "https://app.example.com/home",
};

describe("SAML field checks", () => {
    it("accepts only bare https origins", () => {
        expect(isBareHttpsOrigin("https://app.example.com")).toBe(true);
        expect(isBareHttpsOrigin("https://app.example.com:8443/")).toBe(true);
        for (const bad of [
            "http://app.example.com",
            "https://app.example.com/path",
            "https://u@app.example.com",
            "https://a.com/?q",
            "app.example.com",
        ]) {
            expect(isBareHttpsOrigin(bad)).toBe(false);
        }
    });

    it("requires the ACS URL of this realm over https", () => {
        expect(acsUrlError("https://auth.example.com/saml/acme/acs", "acme")).toBeNull();
        expect(acsUrlError("http://auth.example.com/saml/acme/acs", "acme")).toContain("https");
        expect(acsUrlError("https://auth.example.com/saml/other/acs", "acme")).toContain("/saml/acme/acs");
    });

    it("requires the default return URL under an allowed origin", () => {
        expect(defaultReturnUrlError("https://app.example.com/home", ["https://app.example.com"])).toBeNull();
        expect(defaultReturnUrlError("https://evil.example.com/", ["https://app.example.com"])).toContain("allowed return origins");
        expect(defaultReturnUrlError("http://app.example.com/", ["https://app.example.com"])).toContain("https");
        expect(defaultReturnUrlError("nope", [])).toContain("valid URL");
    });

    it("rejects reserved claim names and duplicate mappings", () => {
        expect(reservedClaimError("dept")).toBeNull();
        expect(reservedClaimError("sub")).toContain("reserved");
        expect(reservedClaimError(" roles ")).toContain("reserved");
        expect(duplicateMappingError([{ attribute: "department", claim: "dept" }])).toBeNull();
        expect(
            duplicateMappingError([
                { attribute: "a", claim: "x" },
                { attribute: "b", claim: "x" },
            ]),
        ).toContain("mapped twice");
        expect(
            duplicateMappingError([
                { attribute: "a", claim: "x" },
                { attribute: "a", claim: "y" },
            ]),
        ).toContain("mapped twice");
    });

    it("classifies certificate expiry", () => {
        const now = new Date("2027-01-01T00:00:00Z");
        expect(expiryLevel(new Date("2026-12-31T00:00:00Z"), now)).toBe("expired");
        expect(expiryLevel(new Date("2027-01-20T00:00:00Z"), now)).toBe("soon");
        expect(expiryLevel(new Date("2027-06-01T00:00:00Z"), now)).toBe("ok");
    });
});

describe("samlFieldError", () => {
    it("reads the field and reason from a server 400", () => {
        const error = new ApiError(400, JSON.stringify("Bad Request: saml_params.sp_acs_url: must end with /saml/acme/acs"));
        expect(samlFieldError(error)).toEqual({ field: "sp_acs_url", message: "must end with /saml/acme/acs" });
    });

    it("ignores other errors", () => {
        expect(samlFieldError(new ApiError(400, JSON.stringify("Bad Request: SAML is not enabled on this server")))).toBeNull();
        expect(samlFieldError(new ApiError(500, JSON.stringify("saml_params.x: y")))).toBeNull();
        expect(samlFieldError(new Error("network"))).toBeNull();
    });
});

describe("SAML form values", () => {
    it("round-trips the settings the admin edits and leaves IdP fields to the server", () => {
        const params = toSamlParams(toSamlFormValues(saved));
        expect(params).toEqual({ ...saved, idp_entity_id: "", idp_sso_url: "", idp_signing_certificates: [], role_attribute: undefined });
    });

    it("detects edits", () => {
        const values = toSamlFormValues(saved);
        expect(isSamlDirty(values, saved)).toBe(false);
        expect(isSamlDirty({ ...values, role_attribute: "groups" }, saved)).toBe(true);
        expect(isSamlDirty({ ...values, claim_map: [] }, saved)).toBe(true);
    });
});
