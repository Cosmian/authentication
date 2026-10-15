import { Form, Input } from "antd";
import React from "react";
import { parseIdpMetadata } from "../../utils/samlMetadata";
import { SamlMetadataPreview } from "./SamlMetadataPreview";

const FIELD = ["saml", "metadata_xml"];

function tryParse(xml: unknown): ReturnType<typeof parseIdpMetadata> | null {
    if (typeof xml !== "string" || !xml.trim()) return null;
    try {
        return parseIdpMetadata(xml);
    } catch {
        return null;
    }
}

/** The IdP metadata textarea: parse errors show under it, the parsed summary once it's valid. */
export const SamlMetadataField: React.FC = () => {
    const xml: unknown = Form.useWatch(FIELD);
    const summary = tryParse(xml);
    return (
        <>
            <Form.Item
                name={FIELD}
                label="IdP metadata XML"
                extra="Paste the SAML 2.0 metadata exported from your identity provider."
                rules={[
                    { required: true, whitespace: true, message: "IdP metadata is required" },
                    {
                        validator: async (_rule, value: unknown) => {
                            if (typeof value !== "string" || !value.trim()) return;
                            parseIdpMetadata(value);
                        },
                    },
                ]}
            >
                <Input.TextArea rows={6} spellCheck={false} placeholder='<md:EntityDescriptor entityID="https://idp.example.com/…">' />
            </Form.Item>
            {summary && <SamlMetadataPreview summary={summary} />}
        </>
    );
};
