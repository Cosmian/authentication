import { Alert, Checkbox, Form, Input, message, Modal, Select } from "antd";
import React, { useEffect, useState } from "react";
import type { UserPass } from "../../types/api";
import { useAuth } from "../../contexts/AuthContext";
import { createCredentialsApi } from "../../services/credentialsApi";
import { createRolesApi } from "../../services/rolesApi";

interface CredentialModalProps {
    open: boolean;
    /** null → create mode; non-null → edit mode (only roles are editable) */
    credential: UserPass | null;
    realmId: string;
    onClose: () => void;
    onSuccess: () => void;
}

export const CredentialModal: React.FC<CredentialModalProps> = ({ open, credential, realmId, onClose, onSuccess }) => {
    const { serverUrl } = useAuth();
    const [form] = Form.useForm();
    const [loading, setLoading] = useState(false);
    const [canSubmit, setCanSubmit] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);
    const [availableRoles, setAvailableRoles] = useState<string[]>([]);

    const isEdit = credential !== null;

    // Fetch available roles whenever the modal opens
    useEffect(() => {
        if (!open) return;
        const api = createRolesApi(serverUrl);
        api.list()
            .then(setAvailableRoles)
            .catch(() => setAvailableRoles([]));
    }, [open, serverUrl]);

    // Pre-fill form in edit mode; reset in create mode
    useEffect(() => {
        if (!open) {
            setSubmitError(null);
            return;
        }
        if (credential) {
            form.setFieldsValue({ roles: credential.roles ?? [] });
        } else {
            form.resetFields();
        }
    }, [open, credential, form]);

    // Track form validity to control the OK button
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

            if (isEdit) {
                const updated: UserPass = { ...credential, roles: values.roles ?? [] };
                await api.update(realmId, credential.username, updated);
                message.success(`Roles updated for "${credential.username}"`);
            } else {
                const passwordBytes = Array.from(new TextEncoder().encode(values.password as string));
                const userpass: UserPass = {
                    realm: realmId,
                    username: values.username as string,
                    password: passwordBytes,
                    change_password: (values.change_password as boolean | undefined) ?? false,
                    roles: (values.roles as string[] | undefined) ?? [],
                };
                await api.create(realmId, userpass);
                message.success(`Credential "${values.username as string}" created`);
            }

            form.resetFields();
            onSuccess();
        } catch (err) {
            if (err instanceof Error) {
                setSubmitError(err.message);
            }
            // else: form validation errors — shown inline
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
            title={isEdit ? `Edit roles — ${credential?.username ?? ""}` : "New Credential"}
            open={open}
            onOk={handleOk}
            onCancel={handleCancel}
            confirmLoading={loading}
            okText={isEdit ? "Save" : "Create"}
            okButtonProps={{ disabled: !canSubmit }}
            destroyOnHidden
        >
            <Form form={form} layout="vertical" autoComplete="off">
                {!isEdit && (
                    <>
                        <Form.Item name="username" label="Username" rules={[{ required: true, message: "Username is required" }]}>
                            <Input />
                        </Form.Item>
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
                    </>
                )}
                <Form.Item name="roles" label="Roles">
                    <Select
                        mode="multiple"
                        allowClear
                        placeholder={isEdit ? "No roles" : "No roles (optional)"}
                        options={availableRoles.map((r) => ({ label: r, value: r }))}
                    />
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
