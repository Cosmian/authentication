import { Alert, Form, Input, InputNumber, message, Modal, Select } from "antd";
import React, { useEffect, useState } from "react";
import type { K8sRoleConfig, K8sRoleRequest } from "../../types/api";
import { useAuth } from "../../contexts/AuthContext";
import { createKubernetesApi } from "../../services/kubernetesApi";

interface K8sFormModalProps {
    open: boolean;
    /** null → create mode; non-null → edit mode (name is fixed). */
    role: { name: string; config: K8sRoleConfig } | null;
    onClose: () => void;
    onSuccess: () => void;
}

interface FormValues {
    name: string;
    jwks_url: string;
    bound_service_account_names: string[];
    bound_service_account_namespaces: string[];
    token_ttl: number;
    expected_issuer?: string;
    bound_audiences: string[];
}

export const K8sFormModal: React.FC<K8sFormModalProps> = ({ open, role, onClose, onSuccess }) => {
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
                jwks_url: role.config.jwks_url,
                bound_service_account_names: role.config.bound_service_account_names,
                bound_service_account_namespaces: role.config.bound_service_account_namespaces,
                token_ttl: role.config.token_ttl,
                expected_issuer: role.config.expected_issuer ?? undefined,
                bound_audiences: role.config.bound_audiences,
            });
        } else {
            form.resetFields();
            form.setFieldsValue({
                token_ttl: 3600,
                bound_service_account_names: [],
                bound_service_account_namespaces: [],
                bound_audiences: [],
            });
        }
    }, [open, role, form]);

    const handleOk = async () => {
        try {
            const values = await form.validateFields();
            setLoading(true);
            const req: K8sRoleRequest = {
                jwks_url: values.jwks_url,
                bound_service_account_names: values.bound_service_account_names ?? [],
                bound_service_account_namespaces: values.bound_service_account_namespaces ?? [],
                token_ttl: values.token_ttl,
                expected_issuer: values.expected_issuer?.trim() ? values.expected_issuer.trim() : null,
                bound_audiences: values.bound_audiences ?? [],
            };
            await createKubernetesApi(serverUrl).save(values.name, req);
            message.success(`Kubernetes role "${values.name}" saved`);
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
            title={isEdit ? `Edit Kubernetes role — ${role?.name ?? ""}` : "New Kubernetes role"}
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
                <Form.Item
                    name="jwks_url"
                    label="JWKS URL"
                    rules={[
                        { required: true, message: "JWKS URL is required" },
                        { pattern: /^https:\/\//, message: "URL must use https://" },
                    ]}
                >
                    <Input placeholder="https://kubernetes.default.svc/openid/v1/jwks" />
                </Form.Item>
                <Form.Item name="bound_service_account_names" label="Bound service account names">
                    <Select mode="tags" allowClear placeholder="e.g. spire-agent" />
                </Form.Item>
                <Form.Item name="bound_service_account_namespaces" label="Bound namespaces">
                    <Select mode="tags" allowClear placeholder="e.g. spire" />
                </Form.Item>
                <Form.Item name="bound_audiences" label="Bound audiences">
                    <Select mode="tags" allowClear placeholder="e.g. cosmian-auth" />
                </Form.Item>
                <Form.Item name="token_ttl" label="Token TTL (seconds)" rules={[{ required: true }]}>
                    <InputNumber min={0} className="w-full" />
                </Form.Item>
                <Form.Item name="expected_issuer" label="Expected issuer (optional)">
                    <Input placeholder="https://kubernetes.default.svc" />
                </Form.Item>
                {submitError && <Alert type="error" message={submitError} showIcon />}
            </Form>
        </Modal>
    );
};
