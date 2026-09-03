import { Alert, Button, Checkbox, Drawer, Form, Input, message, Select } from "antd";
import React, { useCallback, useEffect, useRef, useState } from "react";
import type { Admin } from "../../types/api";
import { SUPER_ADMIN_REALM_ID } from "../../constants/apiPaths";
import { useAuth } from "../../contexts/AuthContext";
import { useRealm } from "../../contexts/RealmContext";
import { createAdminsApi } from "../../services/adminsApi";
import { createCredentialsApi } from "../../services/credentialsApi";
import { TotpManagementModal } from "./TotpManagementModal";

interface AdminFormDrawerProps {
    open: boolean;
    admin: Admin | null;
    onClose: () => void;
    onSuccess: () => void;
    onTotpSetup?: (adminId: string) => void;
}

export const AdminFormDrawer: React.FC<AdminFormDrawerProps> = ({ open, admin, onClose, onSuccess, onTotpSetup }) => {
    const [form] = Form.useForm();
    const { serverUrl } = useAuth();
    const { realms } = useRealm();
    const [loading, setLoading] = useState(false);
    const [canSubmit, setCanSubmit] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);
    const [totpSetupAdmin, setTotpSetupAdmin] = useState<string | null>(null);
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
                    !!values.password ||
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

                // Update userpass credential if a new password was provided
                if (values.password) {
                    const credentialsApi = createCredentialsApi(serverUrl);
                    const passwordInput = { plaintext: values.password as string };
                    if (admin!.userpass) {
                        // Update existing credential
                        await credentialsApi.update(SUPER_ADMIN_REALM_ID, adminId, {
                            realm: SUPER_ADMIN_REALM_ID,
                            username: adminId,
                            password_hash: "",
                            password_input: passwordInput,
                            change_password: (values.change_password as boolean | undefined) ?? false,
                            roles: [],
                        });
                    } else {
                        // Create new credential (auto-links admin.userpass on server)
                        await credentialsApi.create(SUPER_ADMIN_REALM_ID, {
                            realm: SUPER_ADMIN_REALM_ID,
                            username: adminId,
                            password_hash: "",
                            password_input: passwordInput,
                            change_password: (values.change_password as boolean | undefined) ?? false,
                            roles: [],
                        });
                    }
                    message.success(`Password updated for admin "${adminId}"`);
                }
            } else {
                await adminsApi.create(payload);
                message.success(`Admin "${adminId}" created`);

                // Create userpass credential if a password was provided
                if (values.password) {
                    const credentialsApi = createCredentialsApi(serverUrl);
                    await credentialsApi.create(SUPER_ADMIN_REALM_ID, {
                        realm: SUPER_ADMIN_REALM_ID,
                        username: adminId,
                        password_hash: "",
                        password_input: { plaintext: values.password as string },
                        change_password: (values.change_password as boolean | undefined) ?? false,
                        roles: [],
                    });
                    message.success(`Credential created for admin "${adminId}"`);
                }
            }
            onSuccess();

            // Open TOTP setup modal after drawer closes
            if (!isEdit && values.enable_totp) {
                if (onTotpSetup) {
                    onTotpSetup(adminId);
                } else {
                    setTotpSetupAdmin(adminId);
                }
            }
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

                    <Form.Item
                        name="password"
                        label={isEdit ? "New Password" : "Password"}
                        rules={[
                            ({ getFieldValue }) => ({
                                validator(_, value) {
                                    // Required in create mode (unless TOTP is enabled)
                                    if (!isEdit && !value && !getFieldValue("enable_totp")) {
                                        return Promise.reject(new Error("Password is required (or enable TOTP)"));
                                    }
                                    return Promise.resolve();
                                },
                            }),
                        ]}
                    >
                        <Input.Password placeholder={isEdit ? "Leave empty to keep current" : "Admin login password"} />
                    </Form.Item>
                    <Form.Item
                        name="confirm"
                        label="Confirm Password"
                        dependencies={["password"]}
                        rules={[
                            ({ getFieldValue }) => ({
                                validator(_, value) {
                                    const password = getFieldValue("password");
                                    if (!password) return Promise.resolve();
                                    if (!value) return Promise.reject(new Error("Please confirm the password"));
                                    if (password !== value) return Promise.reject(new Error("Passwords do not match"));
                                    return Promise.resolve();
                                },
                            }),
                        ]}
                    >
                        <Input.Password placeholder="Confirm password" />
                    </Form.Item>
                    <Form.Item name="change_password" valuePropName="checked">
                        <Checkbox>Require password change on next login</Checkbox>
                    </Form.Item>

                    {!isEdit && (
                        <Form.Item name="enable_totp" valuePropName="checked">
                            <Checkbox>Enable TOTP (two-factor authentication)</Checkbox>
                        </Form.Item>
                    )}

                    {submitError && (
                        <Form.Item>
                            <Alert type="error" message={submitError} showIcon />
                        </Form.Item>
                    )}
                </Form>
            </div>

            {totpSetupAdmin && (
                <TotpManagementModal
                    open={!!totpSetupAdmin}
                    adminId={totpSetupAdmin}
                    realmId={SUPER_ADMIN_REALM_ID}
                    totpEnabled={false}
                    onClose={() => setTotpSetupAdmin(null)}
                    onSuccess={() => {
                        setTotpSetupAdmin(null);
                        onSuccess();
                    }}
                />
            )}
        </Drawer>
    );
};
