import { Descriptions, Space, Typography } from "antd";
import React from "react";
import type { IdpMetadataSummary } from "../../utils/samlMetadata";
import { CertificateExpiryTag } from "./CertificateExpiryTag";

export interface SamlMetadataPreviewProps {
    summary: IdpMetadataSummary;
}

/** What the server will take from the pasted metadata, for the admin to confirm before saving. */
export const SamlMetadataPreview: React.FC<SamlMetadataPreviewProps> = ({ summary }) => (
    <Descriptions size="small" column={1} bordered className="mb-4" aria-label="Parsed IdP metadata">
        <Descriptions.Item label="IdP entity ID">
            <Typography.Text code>{summary.entityId}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="Sign-in URL">
            <Typography.Text code>{summary.ssoUrl}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="Signing certificates">
            <Space direction="vertical" size={4}>
                {summary.certificates.map((certificate) =>
                    certificate.info ? (
                        <Space key={certificate.base64} size={4} wrap>
                            <Typography.Text>{certificate.info.subject || "(no common name)"}</Typography.Text>
                            <CertificateExpiryTag notAfter={certificate.info.notAfter} />
                        </Space>
                    ) : (
                        <Typography.Text key={certificate.base64} type="danger">
                            Unreadable certificate: {certificate.error}
                        </Typography.Text>
                    ),
                )}
            </Space>
        </Descriptions.Item>
        <Descriptions.Item label="NameID formats">
            {summary.nameIdFormats.length > 0 ? (
                summary.nameIdFormats.join(", ")
            ) : (
                <Typography.Text type="secondary">none advertised</Typography.Text>
            )}
        </Descriptions.Item>
    </Descriptions>
);
