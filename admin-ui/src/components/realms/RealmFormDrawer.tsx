import {
    Button,
    Checkbox,
    Divider,
    Drawer,
    Form,
    Input,
    InputNumber,
    message,
    Select,
    Space,
} from "antd";
import React, { useEffect, useMemo, useState } from "react";
import type { Realm, RealmAuthParams, TotpAlgorithm } from "../../types/api";
import { useAuth } from "../../contexts/AuthContext";
import { createRealmsApi } from "../../services/realmsApi";
import { JwtIdpList } from "./JwtIdpList";

export interface RealmFormDrawerProps {
    open: boolean;
    realm: Realm | null;
    onClose: () => void;
    onSuccess: () => void;
}

const TOTP_ALGORITHMS: { value: TotpAlgorithm; label: string }[] = [
    { value: "SHA1", label: "SHA-1" },
    { value: "SHA256", label: "SHA-256" },
    { value: "SHA512", label: "SHA-512" },
];

export const RealmFormDrawer: React.FC<RealmFormDrawerProps> = ({ open, realm, onClose, onSuccess }) => {
    const [form] = Form.useForm();
    const { serverUrl } = useAuth();
    const api = useMemo(() => createRealmsApi(serverUrl), [serverUrl]);
    const [submitting, setSubmitting] = useState(false);

    const isEdit = realm !== null;

    // Track which auth method sections are enabled
    const [upEnabled, setUpEnabled] = useState(false);
    const [jwtEnabled, setJwtEnabled] = useState(false);
    const [totpEnabled, setTotpEnabled] = useState(false);

    useEffect(() => {
        if (!open) return;
        if (realm) {
            form.setFieldsValue({
                id: realm.id,
                session_max_age_seconds: realm.session_max_age_seconds,
                session_max_stale_age_seconds: realm.session_max_stale_age_seconds,
                allow_expired_passwords: realm.auth_params.username_password_params?.allow_expired_passwords ?? false,
                idp_params: realm.auth_params.jwt_params?.idp_params ?? [],
                smallest_refresh_interval_seconds: realm.auth_params.jwt_params?.smallest_refresh_interval_seconds ?? 300,
                totp_algorithm: realm.auth_params.totp_params?.algorithm ?? "SHA1",
                totp_step: realm.auth_params.totp_params?.step ?? 30,
            });
            setUpEnabled(realm.auth_params.username_password_params !== null);
            setJwtEnabled(realm.auth_params.jwt_params !== null);
            setTotpEnabled(realm.auth_params.totp_params !== null);
        } else {
            form.resetFields();
            setUpEnabled(true);
            setJwtEnabled(false);
            setTotpEnabled(false);
        }
    }, [open, realm, form]);

    const handleSubmit = async (): Promise<void> => {
        const values = await form.validateFields();
        setSubmitting(true);

        const authParams: RealmAuthParams = {
            username_password_params: upEnabled ? { allow_expired_passwords: values.allow_expired_passwords ?? false } : null,
            jwt_params: jwtEnabled
                ? {
                      idp_params: values.idp_params ?? [],
                      smallest_refresh_interval_seconds: values.smallest_refresh_interval_seconds ?? null,
                  }
                : null,
            totp_params: totpEnabled
                ? {
                      algorithm: values.totp_algorithm ?? "SHA1",
                      step: values.totp_step ?? 30,
                  }
                : null,
        };

        const payload: Realm = {
            id: values.id,
            auth_params: authParams,
            session_max_age_seconds: values.session_max_age_seconds,
            session_max_stale_age_seconds: values.session_max_stale_age_seconds,
        };

        try {
            if (isEdit) {
                await api.update(realm.id, payload);
                message.success(`Realm "${realm.id}" updated`);
            } else {
                await api.create(payload);
                message.success(`Realm "${values.id}" created`);
            }
            onSuccess();
        } catch {
            message.error(isEdit ? "Failed to update realm" : "Failed to create realm");
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <Drawer
            title={isEdit ? `Edit Realm: ${realm.id}` : "Create Realm"}
            open={open}
            onClose={onClose}
            width={520}
            destroyOnClose
            extra={
                <Space>
                    <Button onClick={onClose}>Cancel</Button>
                    <Button type="primary" loading={submitting} onClick={handleSubmit}>
                        {isEdit ? "Save" : "Create"}
                    </Button>
                </Space>
            }
        >
            <Form form={form} layout="vertical" initialValues={{ session_max_age_seconds: 3600, session_max_stale_age_seconds: 1800 }}>
                <Form.Item name="id" label="Realm ID" rules={[{ required: true, message: "Realm ID is required" }]}>
                    <Input disabled={isEdit} placeholder="my-service" />
                </Form.Item>

                <Form.Item
                    name="session_max_age_seconds"
                    label="Session Max Age (seconds)"
                    rules={[{ required: true, message: "Required" }]}
                >
                    <InputNumber min={1} step={10} className="w-full" />
                </Form.Item>

                <Form.Item
                    name="session_max_stale_age_seconds"
                    label="Session Stale Age (seconds)"
                    rules={[{ required: true, message: "Required" }]}
                >
                    <InputNumber min={1} step={10} className="w-full" />
                </Form.Item>

                <Divider>Authentication Methods</Divider>

                {/* Username/Password */}
                <div className="mb-4">
                    <Checkbox checked={upEnabled} onChange={(e) => setUpEnabled(e.target.checked)}>
                        Username / Password
                    </Checkbox>
                    {upEnabled && (
                        <Form.Item name="allow_expired_passwords" valuePropName="checked" className="ml-6 mt-2 mb-0">
                            <Checkbox>Allow expired passwords</Checkbox>
                        </Form.Item>
                    )}
                </div>

                {/* JWT / OIDC */}
                <div className="mb-4">
                    <Checkbox checked={jwtEnabled} onChange={(e) => setJwtEnabled(e.target.checked)}>
                        JWT / OIDC
                    </Checkbox>
                    {jwtEnabled && (
                        <div className="ml-6 mt-2">
                            <JwtIdpList />
                        </div>
                    )}
                </div>

                {/* TOTP */}
                <div className="mb-4">
                    <Checkbox checked={totpEnabled} onChange={(e) => setTotpEnabled(e.target.checked)}>
                        TOTP (Two-Factor)
                    </Checkbox>
                    {totpEnabled && (
                        <div className="ml-6 mt-2">
                            <Form.Item name="totp_algorithm" label="Algorithm">
                                <Select options={TOTP_ALGORITHMS} />
                            </Form.Item>
                            <Form.Item name="totp_step" label="Step (seconds)">
                                <InputNumber min={1} className="w-full" />
                            </Form.Item>
                        </div>
                    )}
                </div>
            </Form>
        </Drawer>
    );
};
