import { Button, Drawer, Form, Input, message, Select } from "antd";
import React, { useEffect, useRef, useState } from "react";
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
    // Store original admin for dirty detection — ref so no extra re-render cycle
    const originalAdminRef = useRef<Admin | null>(null);

    const isEdit = admin !== null;

    // Re-validate whenever any field changes; in edit mode also require dirty
    const watchedValues = Form.useWatch([], form);
    useEffect(() => {
        let cancelled = false;
        form
            .validateFields({ validateOnly: true })
            .then(() => {
                if (cancelled) return;
                if (!isEdit) {
                    setCanSubmit(true);
                } else if (originalAdminRef.current !== null) {
                    const cur = form.getFieldsValue();
                    const orig = originalAdminRef.current;
                    const isDirty =
                        (cur.userpass ?? "") !== (orig.userpass ?? "") ||
                        (cur.jwt ?? "") !== (orig.jwt ?? "") ||
                        JSON.stringify([...(cur.realms ?? [])].sort()) !==
                            JSON.stringify([...orig.realms].sort());
                    setCanSubmit(isDirty);
                }
                // else: edit mode, original not yet stored — stay disabled
            })
            .catch(() => { if (!cancelled) setCanSubmit(false); });
        return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [watchedValues, isEdit]);

    // Fields silently preserved on PUT
    const [preservedFields, setPreservedFields] = useState<Partial<Admin>>({});

    const realmOptions = realms.map((r) => ({
        label: r.id === SUPER_ADMIN_REALM_ID ? "_ (Super-Admin)" : r.id,
        value: r.id,
    }));

    useEffect(() => {
        if (open && admin) {
            originalAdminRef.current = admin;
            const values = {
                id: admin.id,
                realms: admin.realms,
                userpass: admin.userpass ?? "",
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
            form.resetFields();
            setPreservedFields({});
        }
    }, [open, admin, form]);

    const handleSubmit = async () => {
        try {
            const values = await form.validateFields();
            setLoading(true);
            const api = createAdminsApi(serverUrl);

            const payload: Admin = {
                id: values.id,
                realms: values.realms,
                userpass: values.userpass || null,
                jwt: values.jwt || null,
                fido2: preservedFields.fido2 ?? null,
                digital_credentials: preservedFields.digital_credentials ?? null,
                client_certificate: preservedFields.client_certificate ?? null,
                totp_enabled: preservedFields.totp_enabled ?? null,
                totp_secret: preservedFields.totp_secret ?? null,
                totp_auth_url: preservedFields.totp_auth_url ?? null,
            };

            if (isEdit) {
                await api.update(admin!.id, payload);
                message.success(`Admin "${admin!.id}" updated`);
            } else {
                await api.create(payload);
                message.success(`Admin "${values.id}" created`);
            }
            onSuccess();
        } catch {
            // validation errors shown inline
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
                <Button
                    type="primary"
                    block
                    loading={loading}
                    disabled={!canSubmit}
                    onClick={handleSubmit}
                >
                    {isEdit ? "Save" : "Create"}
                </Button>
            }
            destroyOnClose
        >
            <Form form={form} layout="vertical" autoComplete="off">
                <Form.Item
                    name="id"
                    label="Admin ID"
                    rules={[{ required: true, message: "Admin ID is required" }]}
                >
                    <Input disabled={isEdit} placeholder="e.g. alice" />
                </Form.Item>
                <Form.Item
                    name="realms"
                    label="Realms"
                    rules={[{ required: true, message: "At least one realm is required" }]}
                >
                    <Select mode="multiple" options={realmOptions} placeholder="Select realms" />
                </Form.Item>
                <Form.Item name="userpass" label="Userpass">
                    <Input placeholder="Username/password reference" />
                </Form.Item>
                <Form.Item name="jwt" label="JWT">
                    <Input placeholder="JWT identifier" />
                </Form.Item>
            </Form>
        </Drawer>
    );
};
