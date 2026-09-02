import { Alert, Checkbox, Form, Input, message, Modal } from "antd";
import React, { useEffect, useState } from "react";
import type { UserPass } from "../../types/api";
import { SUPER_ADMIN_REALM_ID } from "../../constants/apiPaths";
import { useAuth } from "../../contexts/AuthContext";
import { createCredentialsApi } from "../../services/credentialsApi";

interface AdminCredentialModalProps {
    open: boolean;
    adminId: string;
    /** Whether the admin already has a userpass credential linked */
    hasCredential: boolean;
    onClose: () => void;
    onSuccess: () => void;
}

export const AdminCredentialModal: React.FC<AdminCredentialModalProps> = ({ open, adminId, hasCredential, onClose, onSuccess }) => {
    const { serverUrl } = useAuth();
    const [form] = Form.useForm();
    const [loading, setLoading] = useState(false);
    const [canSubmit, setCanSubmit] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);

    useEffect(() => {
        if (!open) {
            setSubmitError(null);
            return;
        }
        form.resetFields();
    }, [open, form]);

    const watchedValues = Form.useWatch([], form);
    useEffect(() => {
        setSubmitError(null);
        let cancelled = false;
        form.validateFields({ validateOnly: true })
            .then(() => {
                if (!cancelled) setCanSubmit(true);
            })
            .catch(() => {
                if (!cancelled) setCanSubmit(false);
            });
        return () => {
            cancelled = true;
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [watchedValues]);

    const handleOk = async () => {
        try {
            const values = await form.validateFields();
            setLoading(true);
            const api = createCredentialsApi(serverUrl);

            const userpass: UserPass = {
                realm: SUPER_ADMIN_REALM_ID,
                username: adminId,
                password_hash: "",
                password_input: { plaintext: values.password as string },
                change_password: (values.change_password as boolean | undefined) ?? false,
                roles: [],
            };

            if (hasCredential) {
                await api.update(SUPER_ADMIN_REALM_ID, adminId, userpass);
                message.success(`Password updated for admin "${adminId}"`);
            } else {
                await api.create(SUPER_ADMIN_REALM_ID, userpass);
                message.success(`Credential created for admin "${adminId}"`);
            }

            form.resetFields();
            onSuccess();
        } catch (err) {
            if (err instanceof Error) {
                setSubmitError(err.message);
            }
        } finally {
            setLoading(false);
        }
    };

    const handleCancel = () => {
        setSubmitError(null);
        form.resetFields();
        onClose();
    };

    return (
        <Modal
            title={hasCredential ? `Change Password — ${adminId}` : `Create Credential — ${adminId}`}
            open={open}
            onOk={handleOk}
            onCancel={handleCancel}
            confirmLoading={loading}
            okText={hasCredential ? "Update Password" : "Create"}
            okButtonProps={{ disabled: !canSubmit }}
            destroyOnHidden
        >
            <Form form={form} layout="vertical" autoComplete="off">
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
                <Form.Item name="change_password" valuePropName="checked">
                    <Checkbox>Require password change on next login</Checkbox>
                </Form.Item>
                {submitError && (
                    <Form.Item>
                        <Alert type="error" message={submitError} showIcon />
                    </Form.Item>
                )}
            </Form>
        </Modal>
    );
};
