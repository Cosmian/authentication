import { Form, Input, Modal } from "antd";
import React, { useEffect, useState } from "react";

interface ResetPasswordModalProps {
    open: boolean;
    username: string;
    onCancel: () => void;
    onSubmit: (password: number[]) => Promise<void>;
}

export const ResetPasswordModal: React.FC<ResetPasswordModalProps> = ({ open, username, onCancel, onSubmit }) => {
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
            await onSubmit(passwordBytes);
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
            title={`Reset password for "${username}"`}
            open={open}
            onOk={handleOk}
            onCancel={handleCancel}
            confirmLoading={loading}
            okText="Reset Password"
            okButtonProps={{ disabled: !canSubmit }}
            destroyOnHidden
        >
            <Form form={form} layout="vertical" autoComplete="off">
                <Form.Item
                    name="password"
                    label="New Password"
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
            </Form>
        </Modal>
    );
};
