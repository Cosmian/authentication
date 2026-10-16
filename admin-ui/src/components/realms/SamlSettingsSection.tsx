import { DownloadOutlined } from "@ant-design/icons";
import { Alert, Button, Divider, Form, Input, Select } from "antd";
import React from "react";
import { acsUrlError, defaultReturnUrlError, isBareHttpsOrigin } from "../../utils/samlValidation";
import { CopyableInput } from "./CopyableInput";
import { SamlIdentityMapping } from "./SamlIdentityMapping";
import { SamlMetadataField } from "./SamlMetadataField";

export interface SamlSettingsSectionProps {
    /** The realm ID being edited or created, which the ACS URL must end with. */
    realmId: string;
    /** Our SP metadata URL, once SAML settings have been saved for this realm. */
    metadataUrl: string | null;
}

const ORIGINS = ["saml", "allowed_return_origins"];

/** SAML settings of a realm: the IdP, this server's SP identity, identity mapping, redirects. */
export const SamlSettingsSection: React.FC<SamlSettingsSectionProps> = ({ realmId, metadataUrl }) => (
    <>
        <SamlMetadataField />

        <Divider plain>This server (give these to the IdP)</Divider>
        <Form.Item
            name={["saml", "sp_entity_id"]}
            label="SP entity ID"
            rules={[{ required: true, whitespace: true, message: "SP entity ID is required" }]}
        >
            <CopyableInput copyLabel="Copy SP entity ID" placeholder={`https://auth.example.com/saml/${realmId}`} />
        </Form.Item>
        <Form.Item
            name={["saml", "sp_acs_url"]}
            label="Assertion Consumer Service URL"
            dependencies={["id"]}
            rules={[
                { required: true, message: "ACS URL is required" },
                {
                    validator: async (_rule, value: unknown) => {
                        const error = typeof value === "string" && value ? acsUrlError(value, realmId) : null;
                        if (error) throw new Error(error);
                    },
                },
            ]}
        >
            <CopyableInput copyLabel="Copy ACS URL" placeholder={`https://auth.example.com/saml/${realmId}/acs`} />
        </Form.Item>
        {metadataUrl ? (
            <Button icon={<DownloadOutlined />} href={metadataUrl} target="_blank" rel="noreferrer" className="mb-4">
                Download SP metadata
            </Button>
        ) : (
            <Alert type="info" showIcon className="mb-4" message="Save the realm to download this server's SP metadata for the IdP." />
        )}

        <Divider plain>Identity mapping</Divider>
        <SamlIdentityMapping />

        <Divider plain>After sign-in</Divider>
        <Form.Item
            name={ORIGINS}
            label="Allowed return origins"
            extra="Origins (https://host[:port]) that sign-ins may return to."
            rules={[
                { required: true, type: "array", min: 1, message: "At least one return origin is required" },
                {
                    validator: async (_rule, origins: string[] | undefined) => {
                        const invalid = (origins ?? []).find((origin) => !isBareHttpsOrigin(origin));
                        if (invalid) throw new Error(`'${invalid}' must be an https origin such as https://app.example.com`);
                    },
                },
            ]}
        >
            <Select mode="tags" open={false} tokenSeparators={[",", " "]} placeholder="https://app.example.com" />
        </Form.Item>
        <Form.Item
            name={["saml", "default_return_url"]}
            label="Default return URL"
            dependencies={[ORIGINS]}
            rules={[
                { required: true, whitespace: true, message: "Default return URL is required" },
                ({ getFieldValue }) => ({
                    validator: async (_rule, value: unknown) => {
                        if (typeof value !== "string" || !value.trim()) return;
                        const error = defaultReturnUrlError(value.trim(), (getFieldValue(ORIGINS) as string[] | undefined) ?? []);
                        if (error) throw new Error(error);
                    },
                }),
            ]}
        >
            <Input placeholder="https://app.example.com/" />
        </Form.Item>
    </>
);
