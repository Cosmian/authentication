import { Checkbox, Form, Input, Modal } from "antd";
import React, { useEffect, useState } from "react";

interface CreateCredentialModalProps {
    open: boolean;
    onCancel: () => void;
    onSubmit: (username: string, password: number[], changePassword: boolean) => Promise<void>;
}

export const CreateCredentialModal: React.FC<CreateCredentialModalProps> = ({ open, onCancel, onSubmit }) => {
    const [form] = Form.useForm();
    const [loading, setLoading] = useState(false);
    const [canSubmit, setCanSubmit] = useState(false);

    const watchedValues = Form.useWatch([], form);
    useEffect(() => {
        let cancelled = false;
        form
            .validateFields({ validateOnly: true })
            .then(() => { if (!cancelled) setCanSubmit(true); })
            .catch(() => { if (!cancelled) setCanSubmit(false); });
        return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [watchedValues]);

    const handleOk = async () => {
        try {
            const values = await form.validateFields();
            setLoading(true);
            const passwordBytes = Array.from(new TextEncoder().encode(values.password));
            await onSubmit(values.username, passwordBytes, values.change_password ?? false);
            form.resetFields();
        } catch {
            // validation errors are shown inline
        } finally {
            setLoading(false);
        }
    };

    const handleCancel = () => {
        form.resetFields();
        onCancel();
    };

    return (
        <Modal
            title="New Credential"
            open={open}
            onOk={handleOk}
            onCancel={handleCancel}
            confirmLoading={loading}
            okText="Create"
            okButtonProps={{ disabled: !canSubmit }}
            destroyOnHidden
        >
            <Form form={form} layout="vertical" autoComplete="off">
                <Form.Item
                    name="username"
                    label="Username"
                    rules={[{ required: true, message: "Username is required" }]}
                >
                    <Input />
                </Form.Item>
                <Form.Item
                    name="password"
                    label="Password"
                    rules={[{ required: true, message: "Password is required" }]}
                >
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
                <Form.Item name="change_password" valuePropName="checked">
                    <Checkbox>Require password change on next login</Checkbox>
                </Form.Item>
            </Form>
        </Modal>
    );
};
