import { Alert, Button, Drawer, Form, Input, message, Select } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import type { Admin } from "../../types/api";
import { SUPER_ADMIN_REALM_ID } from "../../constants/apiPaths";
import { useAuth } from "../../contexts/AuthContext";
import { useRealm } from "../../contexts/RealmContext";
import { createAdminsApi } from "../../services/adminsApi";

interface AdminFormDrawerProps {
    open: boolean;
    admin: Admin | null;
    onClose: () => void;
    onSuccess: () => void;
}

export const AdminFormDrawer: React.FC<AdminFormDrawerProps> = ({ open, admin, onClose, onSuccess }) => {
    const [form] = Form.useForm();
    const { serverUrl } = useAuth();
    const { realms } = useRealm();
    const [loading, setLoading] = useState(false);
    const [canSubmit, setCanSubmit] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);
    // Store original admin for dirty detection — ref so no extra re-render cycle
    const originalAdminRef = useRef<Admin | null>(null);

    const isEdit = admin !== null;

    const checkCanSubmit = useCallback(
        (_?: unknown, allValues?: { id?: string; realms?: string[]; jwt?: string }) => {
            setSubmitError(null);
            const values = allValues ?? form.getFieldsValue();
            const hasId = !!values.id?.trim();
            const hasRealms = Array.isArray(values.realms) && values.realms.length > 0;
            const valid = hasId && hasRealms;

            if (!valid) {
                setCanSubmit(false);
            } else if (!isEdit) {
                setCanSubmit(true);
            } else if (originalAdminRef.current !== null) {
                const orig = originalAdminRef.current;
                const isDirty =
                    (values.jwt ?? "") !== (orig.jwt ?? "") ||
                    JSON.stringify([...(values.realms ?? [])].sort()) !== JSON.stringify([...orig.realms].sort());
                setCanSubmit(isDirty);
            }
        },
        [form, isEdit],
    );

    // Fields silently preserved on PUT
    const [preservedFields, setPreservedFields] = useState<Partial<Admin>>({});

    const realmOptions = realms.map((r) => ({
        label: r.id === SUPER_ADMIN_REALM_ID ? "_ (Super-Admin)" : r.id,
        value: r.id,
    }));

    useEffect(() => {
        if (open && admin) {
            originalAdminRef.current = admin;
            setSubmitError(null);
            const values = {
                id: admin.id,
                realms: admin.realms,
                jwt: admin.jwt ?? "",
            };
            form.setFieldsValue(values);
            setPreservedFields({
                fido2: admin.fido2,
                digital_credentials: admin.digital_credentials,
                client_certificate: admin.client_certificate,
                totp_enabled: admin.totp_enabled,
                totp_secret: admin.totp_secret,
                totp_auth_url: admin.totp_auth_url,
            });
        } else if (open) {
            originalAdminRef.current = null;
            setSubmitError(null);
            form.resetFields();
            setPreservedFields({});
        }
    }, [open, admin, form]);

    const handleSubmit = async () => {
        try {
            const values = await form.validateFields();
            setLoading(true);
            const adminsApi = createAdminsApi(serverUrl);
            const adminId: string = isEdit ? admin!.id : values.id;

            const payload: Admin = {
                id: adminId,
                realms: values.realms,
                userpass: isEdit ? (admin!.userpass ?? null) : null,
                jwt: values.jwt || null,
                fido2: preservedFields.fido2 ?? null,
                digital_credentials: preservedFields.digital_credentials ?? null,
                client_certificate: preservedFields.client_certificate ?? null,
                totp_enabled: preservedFields.totp_enabled ?? null,
                totp_secret: preservedFields.totp_secret ?? null,
                totp_auth_url: preservedFields.totp_auth_url ?? null,
            };

            if (isEdit) {
                await adminsApi.update(admin!.id, payload);
                message.success(`Admin "${admin!.id}" updated`);
            } else {
                await adminsApi.create(payload);
                message.success(`Admin "${adminId}" created`);
            }
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

    return (
        <Drawer
            title={isEdit ? `Edit Admin: ${admin?.id}` : "New Admin"}
            open={open}
            onClose={onClose}
            width={480}
            footer={
                <Button type="primary" block loading={loading} disabled={!canSubmit} onClick={handleSubmit}>
                    {isEdit ? "Save" : "Create"}
                </Button>
            }
            destroyOnClose
        >
            <div className="flex flex-col h-full justify-between">
                <Form form={form} layout="vertical" autoComplete="off" onValuesChange={checkCanSubmit}>
                    <Form.Item name="id" label="Admin ID" rules={[{ required: true, message: "Admin ID is required" }]}>
                        <Input disabled={isEdit} placeholder="e.g. alice" />
                    </Form.Item>
                    <Form.Item name="realms" label="Realms" rules={[{ required: true, message: "At least one realm is required" }]}>
                        <Select mode="multiple" options={realmOptions} placeholder="Select realms" />
                    </Form.Item>

                    <Form.Item name="jwt" label="JWT">
                        <Input placeholder="JWT identifier" />
                    </Form.Item>
                    {submitError && (
                        <Form.Item>
                            <Alert type="error" message={submitError} showIcon />
                        </Form.Item>
                    )}
                </Form>
            </div>
        </Drawer>
    );
};
