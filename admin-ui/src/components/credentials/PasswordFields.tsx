import { Form, Input, Radio } from "antd";
import React from "react";

export type PasswordMode = "plain" | "hashed";

interface PasswordFieldsProps {
    mode: PasswordMode;
    onModeChange: (mode: PasswordMode) => void;
}

/**
 * Toggles between a plaintext password (+ confirmation) and a pre-computed Argon2id PHC
 * string, mutually exclusive per `UserPass.password`/`hashed_password`. The server requires
 * the pre-hashed value to use exactly its own cost parameters (m=65536,t=3,p=4).
 */
export const PasswordFields: React.FC<PasswordFieldsProps> = ({ mode, onModeChange }) => (
    <>
        <Form.Item label="Password source">
            <Radio.Group
                value={mode}
                onChange={(e) => onModeChange(e.target.value as PasswordMode)}
                options={[
                    { label: "Plaintext", value: "plain" },
                    { label: "Pre-hashed (Argon2)", value: "hashed" },
                ]}
            />
        </Form.Item>
        {mode === "plain" ? (
            <>
                <Form.Item name="password" label="Password" rules={[{ required: true, message: "Password is required" }]}>
                    <Input.Password />
                </Form.Item>
                <Form.Item
                    name="confirm"
                    label="Confirm Password"
                    dependencies={["password"]}
                    rules={[
                        { required: true, message: "Please confirm the password" },
                        ({ getFieldValue }) => ({
                            validator(_, value) {
                                if (!value || getFieldValue("password") === value) {
                                    return Promise.resolve();
                                }
                                return Promise.reject(new Error("Passwords do not match"));
                            },
                        }),
                    ]}
                >
                    <Input.Password />
                </Form.Item>
            </>
        ) : (
            <Form.Item
                name="hashed_password"
                label="Pre-hashed password (Argon2id, this server's own parameters only)"
                rules={[
                    { required: true, message: "Hashed password is required" },
                    {
                        pattern: /^\$argon2id\$v=19\$m=65536,t=3,p=4\$/,
                        message: "Must be argon2id with this server's exact parameters (m=65536,t=3,p=4)",
                    },
                ]}
            >
                <Input.TextArea rows={2} placeholder="$argon2id$v=19$m=65536,t=3,p=4$..." />
            </Form.Item>
        )}
    </>
);
