import { Alert, Form, Modal, Select } from "antd";
import React, { useEffect, useState } from "react";
import type { UserPass } from "../../types/api";

interface EditCredentialModalProps {
    open: boolean;
    credential: UserPass | null;
    availableRoles: string[];
    onCancel: () => void;
    onSubmit: (updated: UserPass) => Promise<void>;
}

export const EditCredentialModal: React.FC<EditCredentialModalProps> = ({ open, credential, availableRoles, onCancel, onSubmit }) => {
    const [form] = Form.useForm();
    const [loading, setLoading] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);

    useEffect(() => {
        if (open && credential) {
            form.setFieldsValue({
                roles: credential.roles ?? [],
            });
        }
        if (!open) {
            setSubmitError(null);
        }
    }, [open, credential, form]);

    const handleOk = async () => {
        if (!credential) return;
        try {
            const values = await form.validateFields();
            setLoading(true);
            const updated: UserPass = {
                ...credential,
                roles: values.roles ?? [],
            };
            await onSubmit(updated);
            form.resetFields();
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
        onCancel();
    };

    return (
        <Modal
            title={`Edit roles — ${credential?.username ?? ""}`}
            open={open}
            onOk={handleOk}
            onCancel={handleCancel}
            confirmLoading={loading}
            okText="Save"
            destroyOnHidden
        >
            <Form form={form} layout="vertical">
                <Form.Item name="roles" label="Roles">
                    <Select
                        mode="multiple"
                        allowClear
                        placeholder="No roles"
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
