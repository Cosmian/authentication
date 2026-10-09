import { Alert, Button, Checkbox, Divider, Drawer, Form, Input, InputNumber, message, Select } from "antd";
import type { FormInstance } from "antd";
import React, { useEffect, useMemo, useRef, useState } from "react";
import type { Realm, RealmAuthParams, TotpAlgorithm } from "../../types/api";
import { useAuth } from "../../contexts/AuthContext";
import { ApiError } from "../../services/api";
import { createRealmsApi } from "../../services/realmsApi";
import { defaultSpUrls, isSamlDirty, toSamlFormValues, toSamlParams } from "../../utils/samlForm";
import { samlFieldError, serverMessage } from "../../utils/samlValidation";
import { JwtIdpList } from "./JwtIdpList";
import { SamlSettingsSection } from "./SamlSettingsSection";

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

/** Form fields the server's `saml_params.<field>` errors belong to. */
const SAML_ERROR_FIELDS: Record<string, string> = {
    metadata_xml: "metadata_xml",
    sp_entity_id: "sp_entity_id",
    sp_acs_url: "sp_acs_url",
    subject_attribute: "subject_attribute",
    attribute_claim_map: "claim_map",
    allowed_return_origins: "allowed_return_origins",
    default_return_url: "default_return_url",
};

/**
 * Show a failed save where it belongs: a SAML setting's error on its field, any other 4xx
 * inline (returned), anything else as a toast.
 */
function reportSubmitError(error: unknown, form: FormInstance, isEdit: boolean): string | null {
    const fieldError = samlFieldError(error);
    const field = fieldError ? SAML_ERROR_FIELDS[fieldError.field] : undefined;
    if (fieldError && field) {
        form.setFields([{ name: ["saml", field], errors: [fieldError.message] }]);
        return null;
    }
    if (error instanceof ApiError && error.status >= 400 && error.status < 500) return serverMessage(error);
    message.error(isEdit ? "Failed to update realm" : "Failed to create realm");
    return null;
}

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
    const [samlEnabled, setSamlEnabled] = useState(false);
    const [submitError, setSubmitError] = useState<string | null>(null);
    const realmId: unknown = Form.useWatch("id", form);

    const toggleSaml = (checked: boolean): void => {
        setSamlEnabled(checked);
        const id: unknown = form.getFieldValue("id");
        if (!checked || typeof id !== "string" || !id || form.getFieldValue(["saml", "sp_acs_url"])) return;
        const urls = defaultSpUrls(serverUrl || window.location.origin, id);
        form.setFieldValue(["saml", "sp_entity_id"], urls.entityId);
        form.setFieldValue(["saml", "sp_acs_url"], urls.acsUrl);
    };

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
                        totpEnabled !== Boolean(orig.auth_params.totp_params) ||
                        samlEnabled !== Boolean(orig.auth_params.saml_params);
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
                        (totpEnabled && (cur.totp_step ?? 30) !== (orig.auth_params.totp_params?.step ?? 30)) ||
                        (samlEnabled && isSamlDirty(cur.saml, orig.auth_params.saml_params));
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
    }, [watchedValues, isEdit, upEnabled, jwtEnabled, totpEnabled, samlEnabled]);

    useEffect(() => {
        if (!open) return;
        setSubmitError(null);
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
                saml: toSamlFormValues(realm.auth_params.saml_params),
            };
            form.setFieldsValue(values);
            const up = realm.auth_params.username_password_params !== null;
            const jwt = realm.auth_params.jwt_params !== null;
            const totp = Boolean(realm.auth_params.totp_params);
            setUpEnabled(up);
            setJwtEnabled(jwt);
            setTotpEnabled(totp);
            setSamlEnabled(Boolean(realm.auth_params.saml_params));
        } else {
            originalRealmRef.current = null;
            form.resetFields();
            setUpEnabled(true);
            setJwtEnabled(false);
            setTotpEnabled(false);
            setSamlEnabled(false);
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
        setSubmitError(null);
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
            saml_params: samlEnabled ? toSamlParams(values.saml) : null,
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
        } catch (error) {
            setSubmitError(reportSubmitError(error, form, isEdit));
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
                {submitError && (
                    <Alert type="error" showIcon className="mb-4" message="The server refused these settings" description={submitError} />
                )}
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

                {/* SAML */}
                <div className="mb-4">
                    <Checkbox checked={samlEnabled} onChange={(e) => toggleSaml(e.target.checked)}>
                        SAML 2.0 (single sign-on)
                    </Checkbox>
                    {samlEnabled && (
                        <div className="ml-6 mt-2">
                            <SamlSettingsSection
                                realmId={typeof realmId === "string" ? realmId : ""}
                                metadataUrl={
                                    isEdit && realm.auth_params.saml_params
                                        ? `${serverUrl}/saml/${encodeURIComponent(realm.id)}/metadata`
                                        : null
                                }
                            />
                        </div>
                    )}
                </div>
            </Form>
        </Drawer>
    );
};
