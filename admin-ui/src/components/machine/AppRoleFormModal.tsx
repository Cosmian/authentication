import { Alert, Checkbox, Form, Input, InputNumber, message, Modal, Select } from "antd";
import React, { useEffect, useState } from "react";
import type { AppRoleRoleConfig, AppRoleRoleRequest } from "../../types/api";
import { useAuth } from "../../contexts/AuthContext";
import { createAppRoleApi } from "../../services/appRoleApi";

interface AppRoleFormModalProps {
    open: boolean;
    /** null → create mode; non-null → edit mode (name is fixed). */
    role: { name: string; config: AppRoleRoleConfig } | null;
    onClose: () => void;
    onSuccess: () => void;
}

interface FormValues {
    name: string;
    token_ttl: number;
    secret_id_ttl: number;
    bind_secret_id: boolean;
    token_policies: string[];
}

export const AppRoleFormModal: React.FC<AppRoleFormModalProps> = ({ open, role, onClose, onSuccess }) => {
    const { serverUrl } = useAuth();
    const [form] = Form.useForm<FormValues>();
    const [loading, setLoading] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);

    const isEdit = role !== null;

    useEffect(() => {
        if (!open) {
            setSubmitError(null);
            return;
        }
        if (role) {
            form.setFieldsValue({
                name: role.name,
                token_ttl: role.config.token_ttl,
                secret_id_ttl: role.config.secret_id_ttl,
                bind_secret_id: role.config.bind_secret_id,
                token_policies: role.config.token_policies,
            });
        } else {
            form.resetFields();
            form.setFieldsValue({ token_ttl: 3600, secret_id_ttl: 0, bind_secret_id: true, token_policies: [] });
        }
    }, [open, role, form]);

    const handleOk = async () => {
        try {
            const values = await form.validateFields();
            setLoading(true);
            const req: AppRoleRoleRequest = {
                token_ttl: values.token_ttl,
                secret_id_ttl: values.secret_id_ttl,
                bind_secret_id: values.bind_secret_id,
                token_policies: values.token_policies ?? [],
            };
            await createAppRoleApi(serverUrl).save(values.name, req);
            message.success(`AppRole "${values.name}" saved`);
            form.resetFields();
            onSuccess();
        } catch (err) {
            if (err instanceof Error) setSubmitError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <Modal
            title={isEdit ? `Edit AppRole — ${role?.name ?? ""}` : "New AppRole"}
            open={open}
            onOk={handleOk}
            onCancel={onClose}
            confirmLoading={loading}
            okText={isEdit ? "Save" : "Create"}
            destroyOnHidden
        >
            <Form form={form} layout="vertical" autoComplete="off">
                <Form.Item name="name" label="Role name" rules={[{ required: true, message: "Role name is required" }]}>
                    <Input disabled={isEdit} />
                </Form.Item>
                <Form.Item name="token_ttl" label="Token TTL (seconds)" rules={[{ required: true }]}>
                    <InputNumber min={0} className="w-full" />
                </Form.Item>
                <Form.Item name="secret_id_ttl" label="SecretID TTL (seconds, 0 = no expiry)" rules={[{ required: true }]}>
                    <InputNumber min={0} className="w-full" />
                </Form.Item>
                <Form.Item name="token_policies" label="Token policies">
                    <Select mode="tags" allowClear placeholder="e.g. CryptoOfficer" />
                </Form.Item>
                <Form.Item name="bind_secret_id" valuePropName="checked">
                    <Checkbox>Require a SecretID at login (bind_secret_id)</Checkbox>
                </Form.Item>
                {submitError && <Alert type="error" message={submitError} showIcon />}
            </Form>
        </Modal>
    );
};
