import { Alert, Button, message, Space, Table, Tag, Typography } from "antd";
import { DeleteOutlined, EditOutlined } from "@ant-design/icons";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import type { Realm } from "../types/api";
import { useAuth } from "../contexts/AuthContext";
import { useRealm } from "../contexts/RealmContext";
import { createRealmsApi } from "../services/realmsApi";
import { PageHeader } from "../components/common/PageHeader";
import { LoadingState } from "../components/common/LoadingState";
import { EmptyState } from "../components/common/EmptyState";
import { ConfirmDeleteModal } from "../components/common/ConfirmDeleteModal";
import { RealmFormDrawer } from "../components/realms/RealmFormDrawer";

const RealmsPage: React.FC = () => {
    const { serverUrl } = useAuth();
    const { isSuperAdmin } = useRealm();
    const api = useMemo(() => createRealmsApi(serverUrl), [serverUrl]);

    const [realms, setRealms] = useState<Realm[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Drawer state
    const [drawerOpen, setDrawerOpen] = useState(false);
    const [editingRealm, setEditingRealm] = useState<Realm | null>(null);

    // Delete modal state
    const [deleteTarget, setDeleteTarget] = useState<Realm | null>(null);
    const [deleting, setDeleting] = useState(false);

    const fetchRealms = useCallback(async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await api.list();
            setRealms(data);
        } catch {
            setError("Failed to load realms");
        } finally {
            setLoading(false);
        }
    }, [api]);

    useEffect(() => {
        fetchRealms();
    }, [fetchRealms]);

    const handleCreate = (): void => {
        setEditingRealm(null);
        setDrawerOpen(true);
    };

    const handleEdit = (realm: Realm): void => {
        setEditingRealm(realm);
        setDrawerOpen(true);
    };

    const handleDrawerClose = (): void => {
        setDrawerOpen(false);
        setEditingRealm(null);
    };

    const handleDrawerSuccess = (): void => {
        setDrawerOpen(false);
        setEditingRealm(null);
        fetchRealms();
    };

    const handleDelete = async (): Promise<void> => {
        if (!deleteTarget) return;
        setDeleting(true);
        try {
            await api.delete(deleteTarget.id);
            message.success(`Realm "${deleteTarget.id}" deleted`);
            setDeleteTarget(null);
            fetchRealms();
        } catch {
            message.error(`Failed to delete realm "${deleteTarget.id}"`);
        } finally {
            setDeleting(false);
        }
    };

    if (!isSuperAdmin) {
        return (
            <Alert
                type="error"
                showIcon
                message="Access Denied"
                description="Realm management requires Super-Admin privileges. Switch to the Super-Admin realm to access this page."
            />
        );
    }

    if (loading) return <LoadingState message="Loading realms..." />;

    if (error) {
        return <Alert type="error" showIcon message="Error" description={error} />;
    }

    const columns = [
        {
            title: "ID",
            dataIndex: "id",
            key: "id",
            render: (id: string, record: Realm) => (
                <Typography.Link onClick={() => handleEdit(record)}>{id}</Typography.Link>
            ),
        },
        {
            title: "Auth Methods",
            key: "auth_methods",
            render: (_: unknown, record: Realm) => {
                const methods: string[] = [];
                if (record.auth_params.username_password_params) methods.push("Password");
                if (record.auth_params.jwt_params) methods.push("JWT");
                if (record.auth_params.totp_params) methods.push("TOTP");
                return (
                    <Space size={4}>
                        {methods.map((m) => (
                            <Tag key={m}>{m}</Tag>
                        ))}
                    </Space>
                );
            },
        },
        {
            title: "Session Max Age",
            dataIndex: "session_max_age_seconds",
            key: "session_max_age_seconds",
            render: (v: number) => `${v}s`,
        },
        {
            title: "Stale Age",
            dataIndex: "session_max_stale_age_seconds",
            key: "session_max_stale_age_seconds",
            render: (v: number) => `${v}s`,
        },
        {
            title: "Actions",
            key: "actions",
            render: (_: unknown, record: Realm) => (
                <Space>
                    <Button size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
                        Edit
                    </Button>
                    <Button size="small" danger icon={<DeleteOutlined />} onClick={() => setDeleteTarget(record)}>
                        Delete
                    </Button>
                </Space>
            ),
        },
    ];

    return (
        <div>
            <PageHeader
                title="Realms"
                description="Manage authentication realms and their configuration"
                actionLabel="Create Realm"
                onAction={handleCreate}
            />

            {realms.length === 0 ? (
                <EmptyState description="No realms configured" actionLabel="Create Realm" onAction={handleCreate} />
            ) : (
                <Table dataSource={realms} columns={columns} rowKey="id" pagination={false} />
            )}

            <RealmFormDrawer
                open={drawerOpen}
                realm={editingRealm}
                onClose={handleDrawerClose}
                onSuccess={handleDrawerSuccess}
            />

            <ConfirmDeleteModal
                open={deleteTarget !== null}
                itemName={deleteTarget?.id ?? ""}
                onConfirm={handleDelete}
                onCancel={() => setDeleteTarget(null)}
                loading={deleting}
            />
        </div>
    );
};

export default RealmsPage;
