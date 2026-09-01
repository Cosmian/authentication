import { Alert, Button, Collapse, message, Popconfirm, Space, Table, Tag, Typography } from "antd";
import { DeleteOutlined, EditOutlined, PlusOutlined } from "@ant-design/icons";
import React, { useCallback, useEffect, useState } from "react";
import type { OAuthClientResponse } from "../types/api";
import { SUPER_ADMIN_REALM_ID } from "../constants/apiPaths";
import { useAuth } from "../contexts/AuthContext";
import { useRealm } from "../contexts/RealmContext";
import { createOidcClientsApi } from "../services/oidcClientsApi";
import { PageHeader } from "../components/common/PageHeader";
import { LoadingState } from "../components/common/LoadingState";
import { EmptyState } from "../components/common/EmptyState";
import OidcClientFormModal from "../components/oidc/OidcClientFormModal";
import OidcClientSecretModal from "../components/oidc/OidcClientSecretModal";

const { Text } = Typography;

// ── Per-realm panel (used in super-admin view) ─────────────────────────────

const RealmClientsPanel: React.FC<{
    realmId: string;
    serverUrl: string;
    refreshKey?: number;
}> = ({ realmId, serverUrl, refreshKey = 0 }) => {
    const [clients, setClients] = useState<OAuthClientResponse[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [editTarget, setEditTarget] = useState<OAuthClientResponse | null>(null);
    const [newSecret, setNewSecret] = useState<{ clientId: string; secret: string } | null>(null);

    const api = createOidcClientsApi(serverUrl);

    const reload = useCallback(() => {
        setLoading(true);
        setError(null);
        api.list(realmId)
            .then(setClients)
            .catch(() => setError("Failed to load OIDC clients"))
            .finally(() => setLoading(false));
    }, [realmId, serverUrl, refreshKey]); // eslint-disable-line react-hooks/exhaustive-deps

    useEffect(() => {
        reload();
    }, [reload]);

    const handleDelete = async (clientId: string) => {
        try {
            await api.delete(realmId, clientId);
            message.success("Client deleted");
            reload();
        } catch {
            message.error("Failed to delete client");
        }
    };

    const columns = buildColumns((client) => setEditTarget(client), handleDelete);

    if (loading) return <LoadingState message="Loading…" />;
    if (error) return <Alert type="error" showIcon message={error} />;
    if (clients.length === 0) return <Text type="secondary">No OIDC clients in this realm.</Text>;

    return (
        <>
            <Table dataSource={clients} columns={columns} rowKey="client_id" pagination={false} size="small" />
            <OidcClientFormModal
                open={editTarget !== null}
                realmId={realmId}
                serverUrl={serverUrl}
                existing={editTarget}
                onClose={() => setEditTarget(null)}
                onSuccess={() => {
                    setEditTarget(null);
                    reload();
                }}
            />
            {newSecret && (
                <OidcClientSecretModal
                    open
                    clientId={newSecret.clientId}
                    clientSecret={newSecret.secret}
                    issuerUrl={serverUrl}
                    onClose={() => setNewSecret(null)}
                />
            )}
        </>
    );
};

// ── Main page ───────────────────────────────────────────────────────────────

const OidcClientsPage: React.FC = () => {
    const { serverUrl } = useAuth();
    const { selectedRealm, realmLabel, realms } = useRealm();

    const [clients, setClients] = useState<OAuthClientResponse[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const [createOpen, setCreateOpen] = useState(false);
    const [editTarget, setEditTarget] = useState<OAuthClientResponse | null>(null);
    const [newSecret, setNewSecret] = useState<{ clientId: string; secret: string } | null>(null);

    // Super-admin: per-realm create modals
    const [createTargetRealm, setCreateTargetRealm] = useState<string | null>(null);
    const [refreshKeys, setRefreshKeys] = useState<Record<string, number>>({});

    const api = createOidcClientsApi(serverUrl);

    const fetchClients = useCallback(async () => {
        if (selectedRealm === SUPER_ADMIN_REALM_ID) return;
        setLoading(true);
        setError(null);
        try {
            setClients(await api.list(selectedRealm));
        } catch {
            setError("Failed to load OIDC clients");
        } finally {
            setLoading(false);
        }
    }, [serverUrl, selectedRealm]); // eslint-disable-line react-hooks/exhaustive-deps

    useEffect(() => {
        fetchClients();
    }, [fetchClients]);

    const handleDelete = async (clientId: string) => {
        try {
            await api.delete(selectedRealm, clientId);
            message.success("Client deleted");
            fetchClients();
        } catch {
            message.error("Failed to delete client");
        }
    };

    const handleCreated = (client: OAuthClientResponse) => {
        setCreateOpen(false);
        if (client.client_secret) {
            setNewSecret({ clientId: client.client_id, secret: client.client_secret });
        }
        fetchClients();
    };

    const handleSuperAdminCreated = (targetRealm: string) => (client: OAuthClientResponse) => {
        if (client.client_secret) {
            setNewSecret({ clientId: client.client_id, secret: client.client_secret });
        }
        setRefreshKeys((prev) => ({ ...prev, [targetRealm]: (prev[targetRealm] ?? 0) + 1 }));
        setCreateTargetRealm(null);
    };

    const columns = buildColumns((client) => setEditTarget(client), handleDelete);

    // ── Super-admin: overview across all realms ───────────────────────────
    if (selectedRealm === SUPER_ADMIN_REALM_ID) {
        const concreteRealms = realms.filter((r) => r.id !== SUPER_ADMIN_REALM_ID);
        return (
            <div style={{ maxWidth: 1000 }}>
                <PageHeader title="OIDC Clients" description="All realms — select a realm in the header to manage a single realm" />
                {concreteRealms.length === 0 ? (
                    <Alert type="info" showIcon message="No realms yet" description="Create a realm first to register OIDC clients." />
                ) : (
                    <Collapse
                        accordion={false}
                        defaultActiveKey={concreteRealms.map((r) => r.id)}
                        items={concreteRealms.map((r) => ({
                            key: r.id,
                            label: (
                                <div
                                    style={{
                                        display: "flex",
                                        alignItems: "center",
                                        justifyContent: "space-between",
                                        paddingRight: 8,
                                    }}
                                >
                                    <Text strong>{r.id}</Text>
                                    <Button
                                        size="small"
                                        type="primary"
                                        icon={<PlusOutlined />}
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            setCreateTargetRealm(r.id);
                                        }}
                                    >
                                        New Client
                                    </Button>
                                </div>
                            ),
                            children: <RealmClientsPanel realmId={r.id} serverUrl={serverUrl} refreshKey={refreshKeys[r.id] ?? 0} />,
                        }))}
                    />
                )}

                <OidcClientFormModal
                    open={createTargetRealm !== null}
                    realmId={createTargetRealm ?? ""}
                    serverUrl={serverUrl}
                    existing={null}
                    onClose={() => setCreateTargetRealm(null)}
                    onSuccess={handleSuperAdminCreated(createTargetRealm ?? "")}
                />

                {newSecret && (
                    <OidcClientSecretModal
                        open
                        clientId={newSecret.clientId}
                        clientSecret={newSecret.secret}
                        issuerUrl={serverUrl}
                        onClose={() => setNewSecret(null)}
                    />
                )}
            </div>
        );
    }

    // ── Realm-scoped view ─────────────────────────────────────────────────
    if (loading) return <LoadingState message="Loading OIDC clients…" />;
    if (error) return <Alert type="error" showIcon message="Error" description={error} />;

    return (
        <div style={{ maxWidth: 1000 }}>
            <PageHeader
                title="OIDC Clients"
                description={`Realm: ${realmLabel(selectedRealm)}`}
                actionLabel="New Client"
                onAction={() => setCreateOpen(true)}
            />

            {clients.length === 0 ? (
                <EmptyState
                    description="No OIDC clients registered in this realm"
                    actionLabel="New Client"
                    onAction={() => setCreateOpen(true)}
                />
            ) : (
                <Table dataSource={clients} columns={columns} rowKey="client_id" pagination={false} />
            )}

            <OidcClientFormModal
                open={createOpen}
                realmId={selectedRealm}
                serverUrl={serverUrl}
                existing={null}
                onClose={() => setCreateOpen(false)}
                onSuccess={handleCreated}
            />

            <OidcClientFormModal
                open={editTarget !== null}
                realmId={selectedRealm}
                serverUrl={serverUrl}
                existing={editTarget}
                onClose={() => setEditTarget(null)}
                onSuccess={() => {
                    setEditTarget(null);
                    fetchClients();
                }}
            />

            {newSecret && (
                <OidcClientSecretModal
                    open
                    clientId={newSecret.clientId}
                    clientSecret={newSecret.secret}
                    issuerUrl={serverUrl}
                    onClose={() => setNewSecret(null)}
                />
            )}
        </div>
    );
};

// ── Column definitions ───────────────────────────────────────────────────────

function buildColumns(onEdit: (client: OAuthClientResponse) => void, onDelete: (clientId: string) => void) {
    return [
        {
            title: "Name",
            dataIndex: "client_name",
            key: "client_name",
            width: "20%",
            render: (name: string, record: OAuthClientResponse) => (
                <Space direction="vertical" size={0}>
                    <Text strong>{name}</Text>
                    <Text type="secondary" className="text-xs" copyable>
                        {record.client_id}
                    </Text>
                </Space>
            ),
        },
        {
            title: "Redirect URIs",
            dataIndex: "redirect_uris",
            key: "redirect_uris",
            width: "30%",
            render: (uris: string[]) =>
                uris.map((u) => (
                    <Text key={u} code className="block text-xs">
                        {u}
                    </Text>
                )),
        },
        {
            title: "Grant Types",
            dataIndex: "grant_types",
            key: "grant_types",
            width: "20%",
            render: (grants: string[]) => grants.map((g) => <Tag key={g}>{g}</Tag>),
        },
        {
            title: "Scopes",
            dataIndex: "scopes",
            key: "scopes",
            width: "15%",
            render: (scopes: string[]) =>
                scopes.map((s) => (
                    <Tag key={s} color="blue">
                        {s}
                    </Tag>
                )),
        },
        {
            title: "Auth",
            dataIndex: "token_endpoint_auth_method",
            key: "token_endpoint_auth_method",
            width: "10%",
            render: (method: string) => (
                <Tag color={method === "none" ? "orange" : "green"}>
                    {method === "none" ? "PKCE-only" : method.replace("client_secret_", "")}
                </Tag>
            ),
        },
        {
            title: "Actions",
            key: "actions",
            width: "15%",
            render: (_: unknown, record: OAuthClientResponse) => (
                <Space>
                    <Button
                        size="small"
                        icon={<EditOutlined />}
                        onClick={() => onEdit(record)}
                        data-testid={`oidc-edit-${record.client_id}`}
                    >
                        Edit
                    </Button>
                    <Popconfirm
                        title={`Delete client "${record.client_name}"?`}
                        description="This cannot be undone. Any application using this client will stop working."
                        onConfirm={() => onDelete(record.client_id)}
                        okText="Delete"
                        okType="danger"
                    >
                        <Button size="small" danger icon={<DeleteOutlined />} data-testid={`oidc-delete-${record.client_id}`}>
                            Delete
                        </Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];
}

export default OidcClientsPage;
