import { Tag } from "antd";
import React, { useState } from "react";
import { CERTIFICATE_WARNING_DAYS, expiryLevel } from "../../utils/samlValidation";

export interface CertificateExpiryTagProps {
    notAfter: Date;
}

const DAY_MS = 86_400_000;

/** Validity of an IdP signing certificate: red once expired, orange within the warning window. */
export const CertificateExpiryTag: React.FC<CertificateExpiryTagProps> = ({ notAfter }) => {
    const [now] = useState(() => new Date());
    const level = expiryLevel(notAfter, now);
    const date = notAfter.toISOString().slice(0, 10);
    if (level === "expired") return <Tag color="red">Expired on {date}</Tag>;
    if (level === "soon") {
        const days = Math.ceil((notAfter.getTime() - now.getTime()) / DAY_MS);
        return (
            <Tag color="orange" title={`Warning shown within ${CERTIFICATE_WARNING_DAYS} days of expiry`}>
                Expires in {days} day{days === 1 ? "" : "s"} ({date})
            </Tag>
        );
    }
    return <Tag color="green">Valid until {date}</Tag>;
};
