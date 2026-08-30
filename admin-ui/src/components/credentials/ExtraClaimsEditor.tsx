import { MinusCircleOutlined, PlusOutlined } from "@ant-design/icons";
import { Button, Form, Input, Space } from "antd";
import React from "react";

interface ExtraClaimsEditorProps {
    /** Form.List field name to bind the key/value pairs under. */
    name: string;
}

/**
 * Dynamic key/value editor for `UserPass.extra_claims`, bound to a Form.List.
 * Values are kept as plain strings — the server accepts arbitrary JSON per key,
 * but the common case (e.g. `as_registrant: "acme-corp"`) is a string.
 */
export const ExtraClaimsEditor: React.FC<ExtraClaimsEditorProps> = ({ name }) => (
    <Form.List name={name}>
        {(fields, { add, remove }) => (
            <>
                {fields.map(({ key, name: fieldName, ...rest }) => (
                    <Space key={key} style={{ display: "flex", marginBottom: 8 }} align="baseline">
                        <Form.Item {...rest} name={[fieldName, "key"]} rules={[{ required: true, message: "Claim name required" }]} noStyle>
                            <Input placeholder="claim name (e.g. as_registrant)" />
                        </Form.Item>
                        <Form.Item {...rest} name={[fieldName, "value"]} rules={[{ required: true, message: "Value required" }]} noStyle>
                            <Input placeholder="value" />
                        </Form.Item>
                        <MinusCircleOutlined onClick={() => remove(fieldName)} />
                    </Space>
                ))}
                <Form.Item noStyle>
                    <Button type="dashed" onClick={() => add()} icon={<PlusOutlined />}>
                        Add claim
                    </Button>
                </Form.Item>
            </>
        )}
    </Form.List>
);
