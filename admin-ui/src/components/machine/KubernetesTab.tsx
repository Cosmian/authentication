import { Alert, Button, message, Popconfirm, Space, Table, Tag, Typography } from "antd";
import { DeleteOutlined, EditOutlined, PlusOutlined } from "@ant-design/icons";
import React, { useCallback, useEffect, useState } from "react";
import type { K8sRoleConfig } from "../../types/api";
import { useAuth } from "../../contexts/AuthContext";
import { createKubernetesApi } from "../../services/kubernetesApi";
import { LoadingState } from "../common/LoadingState";
import { EmptyState } from "../common/EmptyState";
import { K8sFormModal } from "./K8sFormModal";

interface K8sRow {
    name: string;
    config: K8sRoleConfig;
}

const tagsOrDash = (values: string[]) =>
    values.length > 0 ? (
        values.map((v) => (
            <Tag key={v} color="geekblue">
                {v}
            </Tag>
        ))
    ) : (
        <Typography.Text type="secondary">—</Typography.Text>
    );

/** Manages Vault-compatible Kubernetes roles (list, create/edit, delete). */
export const KubernetesTab: React.FC = () => {
    const { serverUrl } = useAuth();
    const [rows, setRows] = useState<K8sRow[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [formTarget, setFormTarget] = useState<K8sRow | null>(null);
    const [formOpen, setFormOpen] = useState(false);

    const load = useCallback(async () => {
        const api = createKubernetesApi(serverUrl);
        setLoading(true);
        setError(null);
        try {
            const names = await api.list();
            const configs = await Promise.all(names.map((name) => api.get(name).then((config) => ({ name, config }))));
            setRows(configs);
        } catch {
            setError("Failed to load Kubernetes roles");
        } finally {
            setLoading(false);
        }
    }, [serverUrl]);

    useEffect(() => {
        load();
    }, [load]);

    const handleDelete = async (name: string) => {
        try {
            await createKubernetesApi(serverUrl).delete(name);
            message.success(`Kubernetes role "${name}" deleted`);
            load();
        } catch {
            message.error(`Failed to delete Kubernetes role "${name}"`);
        }
    };

    if (loading) return <LoadingState message="Loading Kubernetes roles…" />;
    if (error) return <Alert type="error" showIcon message={error} />;

    const openCreate = () => {
        setFormTarget(null);
        setFormOpen(true);
    };

    const columns = [
        { title: "Name", dataIndex: "name", key: "name", width: "16%" },
        {
            title: "Service accounts",
            key: "sa",
            width: "22%",
            render: (_: unknown, r: K8sRow) => tagsOrDash(r.config.bound_service_account_names),
        },
        {
            title: "Namespaces",
            key: "ns",
            width: "20%",
            render: (_: unknown, r: K8sRow) => tagsOrDash(r.config.bound_service_account_namespaces),
        },
        { title: "Token TTL", key: "ttl", width: "10%", render: (_: unknown, r: K8sRow) => `${r.config.token_ttl}s` },
        {
            title: "Actions",
            key: "actions",
            render: (_: unknown, r: K8sRow) => (
                <Space wrap>
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
                        title={`Delete Kubernetes role "${r.name}"?`}
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
                    New Kubernetes role
                </Button>
            </div>
            {rows.length === 0 ? (
                <EmptyState description="No Kubernetes roles yet" actionLabel="New Kubernetes role" onAction={openCreate} />
            ) : (
                <Table dataSource={rows} columns={columns} rowKey="name" pagination={false} size="small" />
            )}
            <K8sFormModal
                open={formOpen}
                role={formTarget}
                onClose={() => setFormOpen(false)}
                onSuccess={() => {
                    setFormOpen(false);
                    load();
                }}
            />
        </>
    );
};
