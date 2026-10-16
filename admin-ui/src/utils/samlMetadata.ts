import { type CertificateInfo, readCertificateInfo } from "./x509";

const SAML2_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
const HTTP_REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
/** Same limit as the server. */
const MAX_METADATA_BYTES = 256 * 1024;

export interface MetadataCertificate {
    base64: string;
    info: CertificateInfo | null;
    error: string | null;
}

/** What the server will derive from pasted IdP metadata, shown to the admin before saving. */
export interface IdpMetadataSummary {
    entityId: string;
    ssoUrl: string;
    certificates: MetadataCertificate[];
    nameIdFormats: string[];
}

function elements(root: Element, localName: string): Element[] {
    return Array.from(root.getElementsByTagNameNS("*", localName));
}

function childElements(parent: Element, localName: string): Element[] {
    return Array.from(parent.children).filter((child) => child.localName === localName);
}

function parseRoot(xml: string): Element {
    if (new TextEncoder().encode(xml).length > MAX_METADATA_BYTES) {
        throw new Error("the metadata is larger than 256 KiB");
    }
    const document = new DOMParser().parseFromString(xml, "application/xml");
    const root = document.documentElement;
    if (!root || document.getElementsByTagName("parsererror").length > 0) {
        throw new Error("the metadata is not well-formed XML");
    }
    if (root.localName === "EntitiesDescriptor") {
        throw new Error("this is a federation bundle with several entities; paste the metadata of the single IdP");
    }
    if (root.localName !== "EntityDescriptor") throw new Error("the metadata has no EntityDescriptor");
    return root;
}

function signingCertificates(idp: Element): MetadataCertificate[] {
    // A KeyDescriptor without `use` serves both signing and encryption (SAMLMeta §2.4.1.1).
    const descriptors = childElements(idp, "KeyDescriptor").filter((key) => (key.getAttribute("use") ?? "signing") === "signing");
    return descriptors
        .flatMap((key) => elements(key, "X509Certificate"))
        .map((element) => {
            const base64 = (element.textContent ?? "").replace(/\s+/g, "");
            try {
                return { base64, info: readCertificateInfo(base64), error: null };
            } catch (e) {
                return { base64, info: null, error: e instanceof Error ? e.message : "unreadable certificate" };
            }
        });
}

/** Parse pasted IdP metadata with the same acceptance rules as the server; throws a readable Error. */
export function parseIdpMetadata(xml: string): IdpMetadataSummary {
    const root = parseRoot(xml.trim());
    const entityId = root.getAttribute("entityID") ?? "";
    if (!entityId) throw new Error("the EntityDescriptor has no entityID");
    const validUntil = root.getAttribute("validUntil");
    if (validUntil && new Date(validUntil).getTime() <= Date.now()) {
        throw new Error(`the metadata expired on ${validUntil}`);
    }
    const idp = childElements(root, "IDPSSODescriptor").find((descriptor) =>
        (descriptor.getAttribute("protocolSupportEnumeration") ?? "").split(/\s+/).includes(SAML2_PROTOCOL),
    );
    if (!idp) throw new Error("the metadata has no SAML 2.0 IDPSSODescriptor");
    const sso = childElements(idp, "SingleSignOnService").find((service) => service.getAttribute("Binding") === HTTP_REDIRECT_BINDING);
    const ssoUrl = sso?.getAttribute("Location") ?? "";
    if (!ssoUrl) throw new Error("the IdP has no HTTP-Redirect SingleSignOnService");
    if (!ssoUrl.startsWith("https://")) throw new Error("the IdP SingleSignOnService must use https");
    const certificates = signingCertificates(idp);
    if (certificates.length === 0) throw new Error("the IdP has no signing certificate");
    const nameIdFormats = childElements(idp, "NameIDFormat").map((format) => (format.textContent ?? "").trim());
    return { entityId, ssoUrl, certificates, nameIdFormats };
}
