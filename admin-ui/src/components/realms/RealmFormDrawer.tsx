import { Button, Checkbox, Divider, Drawer, Form, Input, InputNumber, message, Select } from "antd";
import React, { useEffect, useMemo, useRef, useState } from "react";
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
    const [canSubmit, setCanSubmit] = useState(false);
    // Store original realm for dirty detection — ref so no extra re-render cycle
    const originalRealmRef = useRef<Realm | null>(null);

    const isEdit = realm !== null;

    // Track which auth method sections are enabled
    const [upEnabled, setUpEnabled] = useState(false);
    const [jwtEnabled, setJwtEnabled] = useState(false);
    const [totpEnabled, setTotpEnabled] = useState(false);

    // Re-validate whenever any field or toggle changes; in edit mode also require dirty
    const watchedValues = Form.useWatch([], form);
    useEffect(() => {
        let cancelled = false;
        form.validateFields({ validateOnly: true })
            .then(() => {
                if (cancelled) return;
                if (!isEdit) {
                    setCanSubmit(true);
                } else if (originalRealmRef.current !== null) {
                    const cur = form.getFieldsValue();
                    const orig = originalRealmRef.current;
                    const toggleDirty =
                        upEnabled !== (orig.auth_params.username_password_params !== null) ||
                        jwtEnabled !== (orig.auth_params.jwt_params !== null) ||
                        totpEnabled !== (orig.auth_params.totp_params !== null);
                    const formDirty =
                        cur.session_max_age_seconds !== orig.session_max_age_seconds ||
                        cur.session_max_stale_age_seconds !== orig.session_max_stale_age_seconds ||
                        (upEnabled &&
                            (cur.allow_expired_passwords ?? false) !==
                                (orig.auth_params.username_password_params?.allow_expired_passwords ?? false)) ||
                        (jwtEnabled &&
                            cur.smallest_refresh_interval_seconds !==
                                (orig.auth_params.jwt_params?.smallest_refresh_interval_seconds ?? null)) ||
                        (totpEnabled && (cur.totp_algorithm ?? "SHA1") !== (orig.auth_params.totp_params?.algorithm ?? "SHA1")) ||
                        (totpEnabled && (cur.totp_step ?? 30) !== (orig.auth_params.totp_params?.step ?? 30));
                    setCanSubmit(formDirty || toggleDirty);
                }
                // else: edit mode, original not yet stored — stay disabled
            })
            .catch(() => {
                if (!cancelled) setCanSubmit(false);
            });
        return () => {
            cancelled = true;
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [watchedValues, isEdit, upEnabled, jwtEnabled, totpEnabled]);

    useEffect(() => {
        if (!open) return;
        if (realm) {
            originalRealmRef.current = realm;
            const values = {
                id: realm.id,
                session_max_age_seconds: realm.session_max_age_seconds,
                session_max_stale_age_seconds: realm.session_max_stale_age_seconds,
                allow_expired_passwords: realm.auth_params.username_password_params?.allow_expired_passwords ?? false,
                idp_params: realm.auth_params.jwt_params?.idp_params ?? [],
                smallest_refresh_interval_seconds: realm.auth_params.jwt_params?.smallest_refresh_interval_seconds ?? 300,
                totp_algorithm: realm.auth_params.totp_params?.algorithm ?? "SHA1",
                totp_step: realm.auth_params.totp_params?.step ?? 30,
            };
            form.setFieldsValue(values);
            const up = realm.auth_params.username_password_params !== null;
            const jwt = realm.auth_params.jwt_params !== null;
            const totp = realm.auth_params.totp_params !== null;
            setUpEnabled(up);
            setJwtEnabled(jwt);
            setTotpEnabled(totp);
        } else {
            originalRealmRef.current = null;
            form.resetFields();
            setUpEnabled(true);
            setJwtEnabled(false);
            setTotpEnabled(false);
        }
    }, [open, realm, form]);

    const handleSubmit = async (): Promise<void> => {
        let values: Awaited<ReturnType<typeof form.validateFields>>;
        try {
            values = await form.validateFields();
        } catch {
            // Ant Design rejects validateFields when validation fails — the inline
            // error messages are already rendered by the form; nothing more to do.
            return;
        }
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
            footer={
                <Button type="primary" block loading={submitting} disabled={!canSubmit} onClick={handleSubmit}>
                    {isEdit ? "Save" : "Create"}
                </Button>
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
