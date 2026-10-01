/** What the admin needs to recognise an X.509 certificate: its subject and validity. */
export interface CertificateInfo {
    subject: string;
    notBefore: Date;
    notAfter: Date;
}

/** A DER tag-length-value: `start`/`end` bound its content. */
interface Tlv {
    tag: number;
    start: number;
    end: number;
}

const COMMON_NAME_OID = [0x55, 0x04, 0x03];
const UTC_TIME = 0x17;
const EXPLICIT_VERSION = 0xa0;

function readTlv(bytes: Uint8Array, offset: number): Tlv {
    const tag = bytes[offset];
    let length = bytes[offset + 1];
    let start = offset + 2;
    if (tag === undefined || length === undefined) throw new Error("truncated certificate");
    if (length & 0x80) {
        const count = length & 0x7f;
        if (count === 0 || count > 4) throw new Error("unsupported certificate encoding");
        length = 0;
        for (let i = 0; i < count; i++) length = length * 256 + (bytes[start + i] ?? 0);
        start += count;
    }
    const end = start + length;
    if (end > bytes.length) throw new Error("truncated certificate");
    return { tag, start, end };
}

function children(bytes: Uint8Array, parent: Tlv): Tlv[] {
    const result: Tlv[] = [];
    for (let offset = parent.start; offset < parent.end; ) {
        const child = readTlv(bytes, offset);
        result.push(child);
        offset = child.end;
    }
    return result;
}

function text(bytes: Uint8Array, tlv: Tlv): string {
    return new TextDecoder().decode(bytes.subarray(tlv.start, tlv.end));
}

/** UTCTime (`YYMMDDhhmmssZ`) or GeneralizedTime (`YYYYMMDDhhmmssZ`), RFC 5280 §4.1.2.5. */
function readTime(bytes: Uint8Array, tlv: Tlv): Date {
    const digits = text(bytes, tlv).replace(/Z$/, "");
    const utc = tlv.tag === UTC_TIME;
    let year = Number(digits.slice(0, utc ? 2 : 4));
    if (utc) year += year < 50 ? 2000 : 1900;
    const rest = digits.slice(utc ? 2 : 4);
    const part = (from: number): number => Number(rest.slice(from, from + 2) || 0);
    const date = new Date(Date.UTC(year, part(0) - 1, part(2), part(4), part(6), part(8)));
    if (Number.isNaN(date.getTime())) throw new Error("invalid certificate validity date");
    return date;
}

function commonName(bytes: Uint8Array, name: Tlv): string {
    for (const rdn of children(bytes, name)) {
        for (const attribute of children(bytes, rdn)) {
            const [oid, value] = children(bytes, attribute);
            const isCommonName =
                oid !== undefined && oid.end - oid.start === 3 && COMMON_NAME_OID.every((b, i) => bytes[oid.start + i] === b);
            if (isCommonName && value) return text(bytes, value);
        }
    }
    return "";
}

/** Read the subject common name and validity of a base64 DER certificate (as in `<X509Certificate>`). */
export function readCertificateInfo(base64: string): CertificateInfo {
    let bytes: Uint8Array;
    try {
        bytes = Uint8Array.from(atob(base64.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
    } catch {
        throw new Error("certificate is not valid base64");
    }
    const [tbs] = children(bytes, readTlv(bytes, 0));
    if (!tbs) throw new Error("not an X.509 certificate");
    const fields = children(bytes, tbs);
    // TBSCertificate: [0] version?, serial, signature, issuer, validity, subject, … (RFC 5280 §4.1)
    const first = fields[0]?.tag === EXPLICIT_VERSION ? 1 : 0;
    const validity = fields[first + 3];
    const subject = fields[first + 4];
    if (!validity || !subject) throw new Error("not an X.509 certificate");
    const [notBefore, notAfter] = children(bytes, validity);
    if (!notBefore || !notAfter) throw new Error("certificate has no validity period");
    return {
        subject: commonName(bytes, subject),
        notBefore: readTime(bytes, notBefore),
        notAfter: readTime(bytes, notAfter),
    };
}

/** The base64 body of a PEM certificate. */
export function pemBody(pem: string): string {
    return pem
        .split("\n")
        .filter((line) => !line.startsWith("-----"))
        .join("")
        .trim();
}

/** The soonest expiry among PEM certificates, ignoring unreadable ones; null if none is readable. */
export function earliestExpiry(pems: string[]): Date | null {
    let earliest: Date | null = null;
    for (const pem of pems) {
        try {
            const { notAfter } = readCertificateInfo(pemBody(pem));
            if (!earliest || notAfter < earliest) earliest = notAfter;
        } catch {
            // The server validated these; an unreadable one is simply not reported here.
        }
    }
    return earliest;
}
