import { Divider, Form, Input, Select, Space, Switch, Typography } from "antd";
import React, { useEffect } from "react";
import type { OAuthClientResponse } from "../../types/api";

const { Text } = Typography;

const GRANT_TYPE_OPTIONS = [
    { label: "Authorization Code", value: "authorization_code" },
    { label: "Refresh Token", value: "refresh_token" },
    { label: "Client Credentials", value: "client_credentials" },
];

const SCOPE_OPTIONS = [
    { label: "openid", value: "openid" },
    { label: "profile", value: "profile" },
    { label: "email", value: "email" },
    { label: "offline_access", value: "offline_access" },
    { label: "roles", value: "roles" },
];

const AUTH_METHOD_OPTIONS = [
    { label: "client_secret_basic (recommended)", value: "client_secret_basic" },
    { label: "client_secret_post", value: "client_secret_post" },
    { label: "none (public / PKCE-only)", value: "none" },
];

interface OidcClientFormProps {
    form: ReturnType<typeof Form.useForm>[0];
    /** Existing client when editing; null when creating. */
    existing: OAuthClientResponse | null;
}

/**
 * Shared form body used in both the Create and Edit drawers.
 * The caller is responsible for wrapping in a `<Modal>` or `<Drawer>`.
 */
export const OidcClientForm: React.FC<OidcClientFormProps> = ({ form, existing }) => {
    useEffect(() => {
        if (existing) {
            form.setFieldsValue({
                client_name: existing.client_name,
                redirect_uris: existing.redirect_uris.join("\n"),
                grant_types: existing.grant_types,
                scopes: existing.scopes,
                token_endpoint_auth_method: existing.token_endpoint_auth_method,
                pkce_only: existing.token_endpoint_auth_method === "none",
            });
        } else {
            form.setFieldsValue({
                grant_types: ["authorization_code", "refresh_token"],
                scopes: ["openid", "profile", "email"],
                token_endpoint_auth_method: "client_secret_basic",
                pkce_only: false,
            });
        }
    }, [existing, form]);

    return (
        <>
            <Form.Item name="client_name" label="Client Name" rules={[{ required: true, message: "Client name is required" }]}>
                <Input data-testid="oidc-client-name-input" placeholder="e.g. cosmian-kms-ui" />
            </Form.Item>

            <Form.Item
                name="redirect_uris"
                label="Redirect URIs"
                tooltip="One URI per line. Exact-match validation at the authorization endpoint."
                rules={[
                    { required: true, message: "At least one redirect URI is required" },
                    {
                        validator(_, value: string) {
                            const uris = (value ?? "")
                                .split("\n")
                                .map((s) => s.trim())
                                .filter(Boolean);
                            for (const uri of uris) {
                                try {
                                    new URL(uri);
                                } catch {
                                    return Promise.reject(new Error(`Invalid URI: ${uri}`));
                                }
                            }
                            return uris.length > 0 ? Promise.resolve() : Promise.reject(new Error("At least one redirect URI is required"));
                        },
                    },
                ]}
            >
                <Input.TextArea
                    data-testid="oidc-redirect-uris-input"
                    rows={3}
                    placeholder={"http://localhost:9998/ui/callback\nhttps://app.example.com/callback"}
                />
            </Form.Item>

            <Form.Item name="grant_types" label="Grant Types">
                <Select mode="multiple" data-testid="oidc-grant-types-select" options={GRANT_TYPE_OPTIONS} />
            </Form.Item>

            <Form.Item name="scopes" label="Allowed Scopes">
                <Select mode="tags" data-testid="oidc-scopes-select" options={SCOPE_OPTIONS} placeholder="openid profile email …" />
            </Form.Item>

            <Divider orientationMargin={0}>Token Endpoint Authentication</Divider>

            <Form.Item
                name="pkce_only"
                label="Public client (PKCE-only)"
                valuePropName="checked"
                tooltip="When enabled, no client secret is required. The token endpoint uses 'none' as the auth method."
            >
                <Switch
                    data-testid="oidc-pkce-only-switch"
                    onChange={(checked) => {
                        form.setFieldValue("token_endpoint_auth_method", checked ? "none" : "client_secret_basic");
                    }}
                />
            </Form.Item>

            <Form.Item noStyle shouldUpdate={(prev, cur) => prev.pkce_only !== cur.pkce_only}>
                {({ getFieldValue }) =>
                    !getFieldValue("pkce_only") ? (
                        <Form.Item name="token_endpoint_auth_method" label="Auth Method">
                            <Select data-testid="oidc-auth-method-select" options={AUTH_METHOD_OPTIONS} />
                        </Form.Item>
                    ) : (
                        <Form.Item name="token_endpoint_auth_method" hidden>
                            <Input />
                        </Form.Item>
                    )
                }
            </Form.Item>

            {existing && (
                <Space direction="vertical" size={2} className="w-full mt-2">
                    <Text type="secondary" className="text-xs">
                        Client ID:{" "}
                    </Text>
                    <Text code copyable data-testid="oidc-client-id-display" className="text-xs">
                        {existing.client_id}
                    </Text>
                    <Text type="secondary" className="text-xs mt-1">
                        Client secret: only shown once at creation time. Rotate by deleting and re-creating the client.
                    </Text>
                </Space>
            )}
        </>
    );
};
