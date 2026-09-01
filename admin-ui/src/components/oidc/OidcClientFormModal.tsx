import { Alert, Form, Modal, message } from "antd";
import React, { useState } from "react";
import type { OAuthClientResponse } from "../../types/api";
import { OidcClientForm } from "./OidcClientForm";
import { formValuesToRequest } from "./oidcClientUtils";
import { createOidcClientsApi } from "../../services/oidcClientsApi";

interface OidcClientFormModalProps {
    open: boolean;
    realmId: string;
    serverUrl: string;
    /** Existing client when editing; null when creating. */
    existing: OAuthClientResponse | null;
    onClose: () => void;
    /** Called with the full response — caller may inspect `client_secret`. */
    onSuccess: (client: OAuthClientResponse) => void;
}

/**
 * Modal for creating or editing an OIDC / OAuth 2.0 client.
 *
 * On creation the server returns a `client_secret` exactly once;
 * the parent page should show {@link OidcClientSecretModal} with it.
 */
const OidcClientFormModal: React.FC<OidcClientFormModalProps> = ({ open, realmId, serverUrl, existing, onClose, onSuccess }) => {
    const [form] = Form.useForm();
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const isEdit = existing !== null;
    const title = isEdit ? `Edit client "${existing.client_name}"` : "Register new OIDC client";

    const handleOk = async () => {
        let values: Record<string, unknown>;
        try {
            values = await form.validateFields();
        } catch {
            return; // validation errors shown inline
        }

        setSaving(true);
        setError(null);
        const api = createOidcClientsApi(serverUrl);
        const req = formValuesToRequest(values);

        try {
            const result = isEdit ? await api.update(realmId, existing.client_id, req) : await api.create(realmId, req);
            message.success(isEdit ? "Client updated" : "Client registered");
            form.resetFields();
            onSuccess(result);
        } catch (e) {
            setError(e instanceof Error ? e.message : "Operation failed");
        } finally {
            setSaving(false);
        }
    };

    const handleCancel = () => {
        form.resetFields();
        setError(null);
        onClose();
    };

    return (
        <Modal
            open={open}
            title={title}
            onOk={handleOk}
            onCancel={handleCancel}
            confirmLoading={saving}
            okText={isEdit ? "Save" : "Register"}
            destroyOnClose
            width={600}
            data-testid="oidc-client-form-modal"
        >
            {error && <Alert type="error" showIcon message={error} className="mb-4" data-testid="oidc-client-form-error" />}
            <Form form={form} layout="vertical" requiredMark="optional">
                <OidcClientForm form={form} existing={existing} />
            </Form>
        </Modal>
    );
};

export default OidcClientFormModal;
