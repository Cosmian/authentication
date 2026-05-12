import { Alert, Badge, Button, Collapse, message, Popconfirm, Space, Table, Typography } from "antd";
import { DeleteOutlined, KeyOutlined, SwapOutlined } from "@ant-design/icons";
import React, { useCallback, useEffect, useState } from "react";
import type { UserPass } from "../types/api";
import { SUPER_ADMIN_REALM_ID } from "../constants/apiPaths";
import { useAuth } from "../contexts/AuthContext";
import { useRealm } from "../contexts/RealmContext";
import { createCredentialsApi } from "../services/credentialsApi";
import { PageHeader } from "../components/common/PageHeader";
import { LoadingState } from "../components/common/LoadingState";
import { EmptyState } from "../components/common/EmptyState";
import { CreateCredentialModal } from "../components/credentials/CreateCredentialModal";
import { ResetPasswordModal } from "../components/credentials/ResetPasswordModal";

/** Fetches and displays credentials for a single realm — used in the super-admin overview. */
const RealmCredentialsPanel: React.FC<{ realmId: string; serverUrl: string }> = ({ realmId, serverUrl }) => {
    const api = createCredentialsApi(serverUrl);
    const [credentials, setCredentials] = useState<UserPass[]>([]);
    const [loading, setLoading] = useState(true);
    const [resetTarget, setResetTarget] = useState<UserPass | null>(null);

    useEffect(() => {
        api.list(realmId)
            .then(setCredentials)
            .catch(() => { /* shown inline below */ })
            .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [realmId]);

    const handleResetPassword = async (password: number[]) => {
        if (!resetTarget) return;
        await api.update(realmId, resetTarget.username, { ...resetTarget, password });
        message.success(`Password reset for "${resetTarget.username}"`);
        setResetTarget(null);
        const data = await api.list(realmId);
        setCredentials(data);
    };

    const handleDelete = async (username: string) => {
        try {
            await api.delete(realmId, username);
            message.success(`Credential "${username}" deleted`);
            const data = await api.list(realmId);
            setCredentials(data);
        } catch {
            message.error(`Failed to delete credential "${username}"`);
        }
    };

    if (loading) return <LoadingState message="Loading…" />;
    if (credentials.length === 0) return <Typography.Text type="secondary">No credentials in this realm.</Typography.Text>;

    const columns = [
        { title: "Username", dataIndex: "username", key: "username", width: "30%" },
        {
            title: "Status",
            dataIndex: "change_password",
            key: "change_password",
            width: "25%",
            render: (val: boolean) =>
                val ? <Badge status="warning" text="Pending change" /> : <Badge status="success" text="Active" />,
        },
        {
            title: "Actions",
            key: "actions",
            width: "45%",
            render: (_: unknown, record: UserPass) => (
                <Space>
                    <Button size="small" icon={<KeyOutlined />} onClick={() => setResetTarget(record)}>
                        Reset Password
                    </Button>
                    <Popconfirm
                        title={`Delete credential "${record.username}"?`}
                        onConfirm={() => handleDelete(record.username)}
                        okText="Delete"
                        okType="danger"
                    >
                        <Button size="small" danger icon={<DeleteOutlined />}>Delete</Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    return (
        <>
            <Table dataSource={credentials} columns={columns} rowKey="username" pagination={false} size="small" />
            <ResetPasswordModal
                open={resetTarget !== null}
                username={resetTarget?.username ?? ""}
                onCancel={() => setResetTarget(null)}
                onSubmit={handleResetPassword}
            />
        </>
    );
};

const CredentialsPage: React.FC = () => {
    const { serverUrl } = useAuth();
    const { selectedRealm, realmLabel, realms } = useRealm();
    const api = createCredentialsApi(serverUrl);

    const [credentials, setCredentials] = useState<UserPass[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Create modal
    const [createOpen, setCreateOpen] = useState(false);

    // Reset password modal
    const [resetTarget, setResetTarget] = useState<UserPass | null>(null);

    const fetchCredentials = useCallback(async () => {
        if (selectedRealm === SUPER_ADMIN_REALM_ID) return;
        setLoading(true);
        setError(null);
        try {
            const data = await api.list(selectedRealm);
            setCredentials(data);
        } catch {
            setError("Failed to load credentials");
        } finally {
            setLoading(false);
        }
    }, [api, selectedRealm]);

    useEffect(() => {
        fetchCredentials();
    }, [fetchCredentials]);

    const handleCreate = async (username: string, password: number[], changePassword: boolean) => {
        const userpass: UserPass = {
            realm: selectedRealm,
            username,
            password,
            change_password: changePassword,
        };
        await api.create(selectedRealm, userpass);
        message.success(`Credential "${username}" created`);
        setCreateOpen(false);
        fetchCredentials();
    };

    const handleResetPassword = async (password: number[]) => {
        if (!resetTarget) return;
        const updated: UserPass = {
            ...resetTarget,
            password,
        };
        await api.update(selectedRealm, resetTarget.username, updated);
        message.success(`Password reset for "${resetTarget.username}"`);
        setResetTarget(null);
        fetchCredentials();
    };

    const handleToggleChangePassword = async (record: UserPass) => {
        const updated: UserPass = {
            ...record,
            password: [],
            change_password: !record.change_password,
        };
        try {
            await api.update(selectedRealm, record.username, updated);
            message.success(`change_password toggled for "${record.username}"`);
            fetchCredentials();
        } catch {
            message.error("Failed to update credential");
        }
    };

    const handleDelete = async (username: string) => {
        try {
            await api.delete(selectedRealm, username);
            message.success(`Credential "${username}" deleted`);
            fetchCredentials();
        } catch {
            message.error(`Failed to delete credential "${username}"`);
        }
    };

    if (selectedRealm === SUPER_ADMIN_REALM_ID) {
        const concreteRealms = realms.filter((r) => r.id !== SUPER_ADMIN_REALM_ID);
        return (
            <div>
                <PageHeader
                    title="Credentials"
                    description="All realms — select a realm in the header to manage a single realm"
                />
                {concreteRealms.length === 0 ? (
                    <Alert
                        type="info"
                        showIcon
                        message="No realms yet"
                        description="Create a realm first to manage credentials."
                    />
                ) : (
                    <Collapse
                        accordion={false}
                        defaultActiveKey={concreteRealms.map((r) => r.id)}
                        items={concreteRealms.map((r) => ({
                            key: r.id,
                            label: <Typography.Text strong>{r.id}</Typography.Text>,
                            children: <RealmCredentialsPanel realmId={r.id} serverUrl={serverUrl} />,
                        }))}
                    />
                )}
            </div>
        );
    }

    if (loading) return <LoadingState message="Loading credentials..." />;
    if (error) return <Alert type="error" showIcon message="Error" description={error} />;

    const columns = [
        {
            title: "Username",
            dataIndex: "username",
            key: "username",
        },
        {
            title: "Status",
            dataIndex: "change_password",
            key: "change_password",
            render: (val: boolean) =>
                val ? (
                    <Badge status="warning" text="Pending change" />
                ) : (
                    <Badge status="success" text="Active" />
                ),
        },
        {
            title: "Actions",
            key: "actions",
            render: (_: unknown, record: UserPass) => (
                <Space>
                    <Button size="small" icon={<KeyOutlined />} onClick={() => setResetTarget(record)}>
                        Reset Password
                    </Button>
                    <Button
                        size="small"
                        icon={<SwapOutlined />}
                        onClick={() => handleToggleChangePassword(record)}
                    >
                        Toggle Change
                    </Button>
                    <Popconfirm
                        title={`Delete credential "${record.username}"?`}
                        onConfirm={() => handleDelete(record.username)}
                        okText="Delete"
                        okType="danger"
                    >
                        <Button size="small" danger icon={<DeleteOutlined />}>
                            Delete
                        </Button>
                    </Popconfirm>
                </Space>
            ),
        },
    ];

    return (
        <div>
            <PageHeader
                title="Credentials"
                description={`Realm: ${realmLabel(selectedRealm)}`}
                actionLabel="New Credential"
                onAction={() => setCreateOpen(true)}
            />

            {credentials.length === 0 ? (
                <EmptyState
                    description="No credentials in this realm"
                    actionLabel="New Credential"
                    onAction={() => setCreateOpen(true)}
                />
            ) : (
                <Table dataSource={credentials} columns={columns} rowKey="username" pagination={false} />
            )}

            <CreateCredentialModal
                open={createOpen}
                onCancel={() => setCreateOpen(false)}
                onSubmit={handleCreate}
            />

            <ResetPasswordModal
                open={resetTarget !== null}
                username={resetTarget?.username ?? ""}
                onCancel={() => setResetTarget(null)}
                onSubmit={handleResetPassword}
            />
        </div>
    );
};

export default CredentialsPage;
