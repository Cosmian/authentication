import { Button, Form, Input, InputNumber, Space } from "antd";
import { MinusCircleOutlined, PlusOutlined } from "@ant-design/icons";
import React from "react";

export const JwtIdpList: React.FC = () => (
    <>
        <Form.List name="idp_params">
            {(fields, { add, remove }) => (
                <>
                    {fields.map((field) => (
                        <Space key={field.key} align="start" className="flex mb-2">
                            <Form.Item
                                {...field}
                                name={[field.name, "jwks_url"]}
                                rules={[{ required: true, message: "JWKS URL required" }]}
                                className="mb-0"
                            >
                                <Input placeholder="JWKS URL" style={{ width: 220 }} />
                            </Form.Item>
                            <Form.Item {...field} name={[field.name, "jwt_audience"]} className="mb-0">
                                <Input placeholder="Audience (optional)" style={{ width: 180 }} />
                            </Form.Item>
                            <MinusCircleOutlined onClick={() => remove(field.name)} />
                        </Space>
                    ))}
                    <Button type="dashed" onClick={() => add()} icon={<PlusOutlined />} className="mb-2">
                        Add Identity Provider
                    </Button>
                </>
            )}
        </Form.List>
        <Form.Item name="smallest_refresh_interval_seconds" label="JWKS Refresh Interval (seconds)">
            <InputNumber min={1} className="w-full" />
        </Form.Item>
    </>
);
