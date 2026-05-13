import { Alert, Button, Card, Col, message, Row, Space, Tag, Typography } from "antd";
import { DeleteOutlined, EditOutlined, PlusOutlined } from "@ant-design/icons";
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

/** Format seconds into a human-readable duration */
function formatDuration(seconds: number): string {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
    return `${Math.floor(seconds / 86400)}d`;
}

const RealmsPage: React.FC = () => {
    const { serverUrl } = useAuth();
    const { isGlobalAdmin, refreshRealms } = useRealm();
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
        refreshRealms();
    };

    const handleDelete = async (): Promise<void> => {
        if (!deleteTarget) return;
        setDeleting(true);
        try {
            await api.delete(deleteTarget.id);
            message.success(`Realm "${deleteTarget.id}" deleted`);
            setDeleteTarget(null);
            fetchRealms();
            refreshRealms();
        } catch {
            message.error(`Failed to delete realm "${deleteTarget.id}"`);
        } finally {
            setDeleting(false);
        }
    };

    if (!isGlobalAdmin) {
        return (
            <Alert
                type="error"
                showIcon
                message="Access Denied"
                description="Realm management requires Super-Admin privileges."
            />
        );
    }

    if (loading) return <LoadingState message="Loading realms..." />;

    if (error) {
        return <Alert type="error" showIcon message="Error" description={error} />;
    }

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
                <Row gutter={[16, 16]}>
                    {realms.map((realm) => {
                        const methods: string[] = [];
                        if (realm.auth_params.username_password_params) methods.push("Password");
                        if (realm.auth_params.jwt_params) methods.push("JWT");
                        if (realm.auth_params.totp_params) methods.push("TOTP");

                        return (
                            <Col xs={24} sm={12} lg={8} key={realm.id}>
                                <Card
                                    title={realm.id}
                                    actions={[
                                        <Button
                                            key="edit"
                                            type="text"
                                            icon={<EditOutlined />}
                                            onClick={() => handleEdit(realm)}
                                        >
                                            Edit
                                        </Button>,
                                        <Button
                                            key="delete"
                                            type="text"
                                            danger
                                            icon={<DeleteOutlined />}
                                            onClick={() => setDeleteTarget(realm)}
                                        >
                                            Delete
                                        </Button>,
                                    ]}
                                >
                                    <div className="flex flex-col gap-2">
                                        <div>
                                            <Typography.Text type="secondary">Session: </Typography.Text>
                                            <Typography.Text>{formatDuration(realm.session_max_age_seconds)}</Typography.Text>
                                            <Typography.Text type="secondary"> / Stale: </Typography.Text>
                                            <Typography.Text>{formatDuration(realm.session_max_stale_age_seconds)}</Typography.Text>
                                        </div>
                                        <Space size={4} wrap>
                                            {methods.map((m) => (
                                                <Tag key={m}>{m}</Tag>
                                            ))}
                                            {methods.length === 0 && (
                                                <Typography.Text type="secondary">No auth methods</Typography.Text>
                                            )}
                                        </Space>
                                    </div>
                                </Card>
                            </Col>
                        );
                    })}
                    {/* Add new realm card */}
                    <Col xs={24} sm={12} lg={8}>
                        <Card
                            hoverable
                            onClick={handleCreate}
                            className="h-full flex items-center justify-center"
                            style={{ minHeight: 160 }}
                        >
                            <div className="flex flex-col items-center gap-2 text-center">
                                <PlusOutlined style={{ fontSize: 24 }} />
                                <Typography.Text type="secondary">New Realm</Typography.Text>
                            </div>
                        </Card>
                    </Col>
                </Row>
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
