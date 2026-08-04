import { Alert, Button, message, Popconfirm, Space, Table, Tag, Typography } from "antd";
import { DeleteOutlined, EditOutlined, KeyOutlined, PlusOutlined } from "@ant-design/icons";
import React, { useCallback, useEffect, useState } from "react";
import type { AppRoleRoleConfig, AppRoleSecretIdResult } from "../../types/api";
import { useAuth } from "../../contexts/AuthContext";
import { createAppRoleApi } from "../../services/appRoleApi";
import { LoadingState } from "../common/LoadingState";
import { EmptyState } from "../common/EmptyState";
import { AppRoleFormModal } from "./AppRoleFormModal";
import { SecretIdResultModal } from "./SecretIdResultModal";

interface AppRoleRow {
    name: string;
    config: AppRoleRoleConfig;
}

/** Manages Vault-compatible AppRole roles (list, create/edit, delete, generate SecretID). */
export const AppRoleTab: React.FC = () => {
    const { serverUrl } = useAuth();
    const [rows, setRows] = useState<AppRoleRow[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [formTarget, setFormTarget] = useState<AppRoleRow | null>(null);
    const [formOpen, setFormOpen] = useState(false);
    const [secretResult, setSecretResult] = useState<{ name: string; roleId: string; result: AppRoleSecretIdResult } | null>(null);

    const load = useCallback(async () => {
        const api = createAppRoleApi(serverUrl);
        setLoading(true);
        setError(null);
        try {
            const names = await api.list();
            const configs = await Promise.all(names.map((name) => api.get(name).then((config) => ({ name, config }))));
            setRows(configs);
        } catch {
            setError("Failed to load AppRole roles");
        } finally {
            setLoading(false);
        }
    }, [serverUrl]);

    useEffect(() => {
        load();
    }, [load]);

    const handleDelete = async (name: string) => {
        try {
            await createAppRoleApi(serverUrl).delete(name);
            message.success(`AppRole "${name}" deleted`);
            load();
        } catch {
            message.error(`Failed to delete AppRole "${name}"`);
        }
    };

    const handleGenerateSecret = async (row: AppRoleRow) => {
        try {
            const result = await createAppRoleApi(serverUrl).generateSecretId(row.name, { ttl: 0, num_uses: 0 });
            setSecretResult({ name: row.name, roleId: row.config.role_id, result });
        } catch {
            message.error(`Failed to generate SecretID for "${row.name}"`);
        }
    };

    if (loading) return <LoadingState message="Loading AppRole roles…" />;
    if (error) return <Alert type="error" showIcon message={error} />;

    const openCreate = () => {
        setFormTarget(null);
        setFormOpen(true);
    };

    const columns = [
        { title: "Name", dataIndex: "name", key: "name", width: "18%" },
        {
            title: "RoleID",
            key: "role_id",
            width: "26%",
            render: (_: unknown, r: AppRoleRow) => (
                <Typography.Text copyable code className="text-xs">
                    {r.config.role_id}
                </Typography.Text>
            ),
        },
        { title: "Token TTL", key: "token_ttl", width: "10%", render: (_: unknown, r: AppRoleRow) => `${r.config.token_ttl}s` },
        {
            title: "Policies",
            key: "policies",
            width: "18%",
            render: (_: unknown, r: AppRoleRow) =>
                r.config.token_policies.length > 0 ? (
                    r.config.token_policies.map((p) => (
                        <Tag key={p} color="blue">
                            {p}
                        </Tag>
                    ))
                ) : (
                    <Typography.Text type="secondary">—</Typography.Text>
                ),
        },
        {
            title: "Actions",
            key: "actions",
            render: (_: unknown, r: AppRoleRow) => (
                <Space wrap>
                    <Button size="small" icon={<KeyOutlined />} onClick={() => handleGenerateSecret(r)}>
                        SecretID
                    </Button>
                    <Button
                        size="small"
                        icon={<EditOutlined />}
                        onClick={() => {
                            setFormTarget(r);
                            setFormOpen(true);
                        }}
                    >
                        Edit
                    </Button>
                    <Popconfirm
                        title={`Delete AppRole "${r.name}"?`}
                        onConfirm={() => handleDelete(r.name)}
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
        <>
            <div className="flex justify-end mb-3">
                <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
                    New AppRole
                </Button>
            </div>
            {rows.length === 0 ? (
                <EmptyState description="No AppRole roles yet" actionLabel="New AppRole" onAction={openCreate} />
            ) : (
                <Table dataSource={rows} columns={columns} rowKey="name" pagination={false} size="small" />
            )}
            <AppRoleFormModal
                open={formOpen}
                role={formTarget}
                onClose={() => setFormOpen(false)}
                onSuccess={() => {
                    setFormOpen(false);
                    load();
                }}
            />
            <SecretIdResultModal
                open={secretResult !== null}
                roleName={secretResult?.name ?? ""}
                roleId={secretResult?.roleId ?? ""}
                result={secretResult?.result ?? null}
                onClose={() => setSecretResult(null)}
            />
        </>
    );
};
