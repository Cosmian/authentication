import { MinusCircleOutlined, PlusOutlined } from "@ant-design/icons";
import { Button, Checkbox, Form, Input, Space } from "antd";
import React from "react";
import { type ClaimMapping, duplicateMappingError, reservedClaimError } from "../../utils/samlValidation";

/** How assertion attributes become the session subject, roles and extra claims. */
export const SamlIdentityMapping: React.FC = () => (
    <>
        <Form.Item
            name={["saml", "subject_attribute"]}
            label="Subject attribute"
            extra="Attribute whose single value becomes the user name. Leave empty to use the NameID; required when the IdP sends transient NameIDs."
        >
            <Input placeholder="e.g. email" />
        </Form.Item>
        <Form.Item name={["saml", "normalize_subject_case"]} valuePropName="checked">
            <Checkbox>Lowercase the user name</Checkbox>
        </Form.Item>
        <Form.Item name={["saml", "role_attribute"]} label="Role attribute" extra="Attribute whose values become the session roles.">
            <Input placeholder="e.g. groups" />
        </Form.Item>
        <Form.List
            name={["saml", "claim_map"]}
            rules={[
                {
                    validator: async (_rule, mappings: ClaimMapping[] | undefined) => {
                        const error = duplicateMappingError(mappings ?? []);
                        if (error) throw new Error(error);
                    },
                },
            ]}
        >
            {(fields, { add, remove }, { errors }) => (
                <Form.Item label="Extra claims" extra="Only the attributes listed here are copied into the session.">
                    {fields.map(({ key, name, ...rest }) => (
                        <Space key={key} align="baseline" className="flex mb-2">
                            <Form.Item
                                {...rest}
                                name={[name, "attribute"]}
                                noStyle
                                rules={[{ required: true, whitespace: true, message: "SAML attribute required" }]}
                            >
                                <Input placeholder="SAML attribute" aria-label="SAML attribute" />
                            </Form.Item>
                            <Form.Item
                                {...rest}
                                name={[name, "claim"]}
                                noStyle
                                rules={[
                                    { required: true, whitespace: true, message: "Claim name required" },
                                    {
                                        validator: async (_rule, claim: unknown) => {
                                            const error = typeof claim === "string" ? reservedClaimError(claim) : null;
                                            if (error) throw new Error(error);
                                        },
                                    },
                                ]}
                            >
                                <Input placeholder="claim name" aria-label="Claim name" />
                            </Form.Item>
                            <MinusCircleOutlined aria-label="Remove mapping" onClick={() => remove(name)} />
                        </Space>
                    ))}
                    <Button type="dashed" onClick={() => add({ attribute: "", claim: "" })} icon={<PlusOutlined />}>
                        Add claim mapping
                    </Button>
                    <Form.ErrorList errors={errors} />
                </Form.Item>
            )}
        </Form.List>
    </>
);
