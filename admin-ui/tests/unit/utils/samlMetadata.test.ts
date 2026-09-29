import { describe, expect, it } from "vitest";
import { earliestExpiry, readCertificateInfo } from "../../../src/utils/x509";
import { parseIdpMetadata } from "../../../src/utils/samlMetadata";
import { IDP_CERT_BASE64, IDP_CERT_NOT_AFTER, IDP_CERT_PEM, IDP_CERT_SUBJECT, idpMetadata } from "../fixtures/saml";

describe("readCertificateInfo", () => {
    it("reads the subject common name and validity of a DER certificate", () => {
        const info = readCertificateInfo(IDP_CERT_BASE64);
        expect(info.subject).toBe(IDP_CERT_SUBJECT);
        expect(info.notAfter).toEqual(IDP_CERT_NOT_AFTER);
        expect(info.notBefore).toEqual(new Date("2026-04-11T16:04:06Z"));
    });

    it("rejects input that is not a certificate", () => {
        expect(() => readCertificateInfo("not base64!")).toThrow("not valid base64");
        expect(() => readCertificateInfo(btoa("garbage"))).toThrow();
        expect(() => readCertificateInfo(IDP_CERT_BASE64.slice(0, 200))).toThrow();
    });

    it("finds the earliest expiry among PEM certificates and skips unreadable ones", () => {
        expect(earliestExpiry([IDP_CERT_PEM, "-----BEGIN CERTIFICATE-----\nforged\n-----END CERTIFICATE-----"])).toEqual(
            IDP_CERT_NOT_AFTER,
        );
        expect(earliestExpiry([])).toBeNull();
    });
});

describe("parseIdpMetadata", () => {
    it("extracts what the server will derive", () => {
        const summary = parseIdpMetadata(idpMetadata());
        expect(summary.entityId).toBe("https://idp.example.com/metadata");
        expect(summary.ssoUrl).toBe("https://idp.example.com/sso");
        expect(summary.nameIdFormats).toEqual(["urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]);
        expect(summary.certificates).toHaveLength(1);
        expect(summary.certificates[0].info?.subject).toBe(IDP_CERT_SUBJECT);
    });

    it("accepts unprefixed metadata and keys without a use", () => {
        const xml = idpMetadata({ keyUse: null })
            .replace(/<md:/g, "<")
            .replace(/<\/md:/g, "</")
            .replace("xmlns:md=", "xmlns=");
        expect(parseIdpMetadata(xml).certificates).toHaveLength(1);
    });

    it.each([
        ["<not-xml", "not well-formed XML"],
        ['<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>', "federation bundle"],
        [idpMetadata({ entityId: "" }), "no entityID"],
        [idpMetadata({ validUntil: "2000-01-01T00:00:00Z" }), "expired"],
        [idpMetadata({ ssoBinding: "post" }), "HTTP-Redirect"],
        [idpMetadata({ ssoUrl: "http://idp.example.com/sso" }), "https"],
        [idpMetadata({ keyUse: "encryption" }), "no signing certificate"],
        ["x".repeat(256 * 1024 + 1), "256 KiB"],
    ])("rejects invalid metadata (%#)", (xml, message) => {
        expect(() => parseIdpMetadata(xml)).toThrow(message);
    });
});
