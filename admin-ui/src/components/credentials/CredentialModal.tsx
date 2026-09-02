import { Alert, Checkbox, Form, Input, message, Modal, Select } from "antd";
import React, { useEffect, useState } from "react";
import type { UserPass } from "../../types/api";
import { useAuth } from "../../contexts/AuthContext";
import { createCredentialsApi } from "../../services/credentialsApi";
import { createRolesApi } from "../../services/rolesApi";
import { ExtraClaimsEditor } from "./ExtraClaimsEditor";
import { PasswordFields, type PasswordMode } from "./PasswordFields";

interface ExtraClaimPair {
    key: string;
    value: string;
}

const toExtraClaims = (pairs: ExtraClaimPair[] | undefined): Record<string, string> | undefined =>
    pairs && pairs.length > 0 ? Object.fromEntries(pairs.map((p) => [p.key, p.value])) : undefined;

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
    const [passwordMode, setPasswordMode] = useState<PasswordMode>("plain");

    const isEdit = credential !== null;

    // Fetch available roles whenever the modal opens
    useEffect(() => {
        if (!open) return;
        let cancelled = false;
        const api = createRolesApi(serverUrl);
        api.list()
            .then((roles) => {
                if (!cancelled) setAvailableRoles(roles);
            })
            .catch(() => {
                if (!cancelled) setAvailableRoles([]);
            });
        return () => {
            cancelled = true;
        };
    }, [open, serverUrl]);

    // Pre-fill form in edit mode; reset in create mode
    useEffect(() => {
        if (!open) {
            setSubmitError(null);
            return;
        }
        setPasswordMode("plain");
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
                const userpass: UserPass = {
                    realm: realmId,
                    username: values.username as string,
                    password_hash: "",
                    password_input:
                        passwordMode === "plain" ? { plaintext: values.password as string } : { hashed: values.hashed_password as string },
                    change_password: (values.change_password as boolean | undefined) ?? false,
                    roles: (values.roles as string[] | undefined) ?? [],
                    extra_claims: toExtraClaims(values.extraClaims as ExtraClaimPair[] | undefined),
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
                        <PasswordFields mode={passwordMode} onModeChange={setPasswordMode} />
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
                {!isEdit && (
                    <Form.Item label="Extra claims (optional)">
                        <ExtraClaimsEditor name="extraClaims" />
                    </Form.Item>
                )}
                {submitError && (
                    <Form.Item>
                        <Alert type="error" message={submitError} showIcon />
                    </Form.Item>
                )}
            </Form>
        </Modal>
    );
};
