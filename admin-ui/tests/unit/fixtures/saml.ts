/** Test IdP signing certificate (server/src/tests/certificates/rsa/auth.user2.cert.pem). */
export const IDP_CERT_BASE64 = [
    "MIIFXDCCA0SgAwIBAgIUMql22toWMwSAQXMzpi5B+/232E8wDQYJKoZIhvcNAQELBQAwEzERMA8GA1UE",
    "AwwIYWNtZS5jb20wHhcN",
    "MjYwNDExMTYwNDA2WhcNMjcwNDExMTYwNDA2WjAZMRcwFQYDVQQDDA51c2VyMi5hY21lLmNvbTCCAiIw",
    "DQYJKoZIhvcNAQEBBQAD",
    "ggIPADCCAgoCggIBAMOB0DaQ1L/SuU9+d+u1jfOmxUmH0pwdhbBJloBtzB6A10/uh+nexkqg56ftKRqq",
    "Lt0HKoH0ujNDjCkqzSo1",
    "BIcXbxWjiX05jeRvlnDc8SLNzDeaN/g/0XAqyOhSshwwBu38Mvt2Z5gNKOOK0ZkoevFfZLNk4XLHTJTD",
    "eDromInoSUfRUuLdkFpZ",
    "m9qqCYGdtUtoDa8X+BY8+k8b8e10VGXgIs+J9T/61d8vrAbpdI/4eS48YFuuDS+a9z4ffkNruNHK8Lkd",
    "o0wt/v2Ibu1M75kA4gjR",
    "Q6XxSa+FFZbWRQ64ZDcDS9ETKH9wU49nImXD17DKeS/M8BrNFIUybdc1HY+s13HIZfwTzdIx8ZWa0KbW",
    "vzC93FUyrMBM9ueXKhxx",
    "gPh8DInQH4W/q83N+9LAMt+uqY3GahewpcVOvZZGt+MVhr8+n+zZX6GzEIJ1BJ0Eoola9z6GHQC9B3s1",
    "b475ZdP/UEgSf2ap1MUN",
    "ZN8DzKEPzrrZCWfVRsOnfS1WrxekqeqnJiGEuMjI9xr+IR3tqRZITDP65cAXLdXfJ+djkcle9711t1DL",
    "tTQwzjykTT9s2Q+fTsKW",
    "UzjUE6QpyZhiQg7QSfA3sHbYoml2c+h1f085MiBIqB2KfwtAlK4dmaRXbu1bgQI12Nwsy7ORqQtm/6vs",
    "IXnPbM8r7Kb9q1M1cquP",
    "AgMBAAGjgaEwgZ4wCwYDVR0PBAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMCkGA1UdHwQiMCAwHqAc",
    "oBqGGGh0dHBzOi8vYWNt",
    "ZS5jb20vY3JsLnBlbTAPBgNVHREECDAGhwR/AAABMB0GA1UdDgQWBBQ7W4chRF/iv5swh7ra0DhM10s8",
    "JzAfBgNVHSMEGDAWgBRc",
    "mjxht2F86Fqo+TAA5GkBnubWDTANBgkqhkiG9w0BAQsFAAOCAgEAPFrcguAn6mWOpspVIO/F4JYDr0KK",
    "PboCOXlSOgScIpw9p7lL",
    "5tnDkf2yQ3D1M/NJVN4qq1hudXrbEzlyBjSz/72E4VZSP6doWxDuYG55DXmRIf9pqXAsrRbGq5AMhYhS",
    "uJdYnsdeHgszUUp9BnX7",
    "fEJ/rUk+WGe9LlM+SS5BcFcDUVuzAOL6vI78Y1l8O6wCEHOXU7pKXfsQmmDJOsn8hvCkerp6MBt0RxCj",
    "WdrEB/80De8aF4vwF75n",
    "Lfq9l0kiW8yjaa43oAF9/HDbIHV8BWco7ZTjIiSGC7jjVV5u0zE6mCtNgiDUzzfujAvtb6oA+Daowsyu",
    "Bxnhv/IydlZ68GZOGnsB",
    "KVPITw+J4dUHpRNtK+OrHtX3YcOcsIbYUXtqbfM7/qeGPI3EVNpcs80zvQFUNYBShicuDdzzA626eh9h",
    "0Qq1njj7eW0CQdRgyYsD",
    "TQZKQ0CnTEt6kP1z+Hbp+i4BJ+qBtogFUvDYg/7AQwjIEcQuJJyd/rMxufIrYVYzlfBqBdU/5RCjW7H2",
    "i5Ui58Gbd3VXefoOqG7v",
    "Z/7edXo88jCWkfFroPsqZUlLXUcK+W52CtDKSE24gR4nceSc0PSDk2yrpihwlPhw14X4hOHCIRLctZ+1",
    "+n4Twr7xzQmx+j2JScsd",
    "SxkiC2b0NAA65Ey79tkvylW73mbVcY19Jt8=",
].join("");

export const IDP_CERT_SUBJECT = "user2.acme.com";
export const IDP_CERT_NOT_AFTER = new Date("2027-04-11T16:04:06Z");

export const IDP_CERT_PEM = `-----BEGIN CERTIFICATE-----\n${IDP_CERT_BASE64.replace(/(.{64})/g, "$1\n")}\n-----END CERTIFICATE-----\n`;

const REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

export interface MetadataOptions {
    keyUse?: string | null;
    ssoBinding?: "redirect" | "post";
    ssoUrl?: string;
    extra?: string;
    entityId?: string;
    validUntil?: string;
}

/** IdP metadata signing with the test certificate, in the shape IdPs export. */
export function idpMetadata(options: MetadataOptions = {}): string {
    const use = options.keyUse === undefined ? ' use="signing"' : options.keyUse === null ? "" : ` use="${options.keyUse}"`;
    const binding = options.ssoBinding === "post" ? POST : REDIRECT;
    const validUntil = options.validUntil ? ` validUntil="${options.validUntil}"` : "";
    return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="${options.entityId ?? "https://idp.example.com/metadata"}"${validUntil}>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor${use}><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${IDP_CERT_BASE64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>${options.extra ?? ""}
    <md:SingleSignOnService Binding="${binding}" Location="${options.ssoUrl ?? "https://idp.example.com/sso"}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
}
