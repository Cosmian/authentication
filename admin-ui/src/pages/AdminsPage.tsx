import { Alert, Badge, Button, Form, Input, message, Popconfirm, Result, Space, Table, Tag, Typography } from "antd";
import { DeleteOutlined, EditOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import type { Admin } from "../types/api";
import { SUPER_ADMIN_REALM_ID } from "../constants/apiPaths";
import { useAuth } from "../contexts/AuthContext";
import { useRealm } from "../contexts/RealmContext";
import { createAdminsApi } from "../services/adminsApi";
import { PageHeader } from "../components/common/PageHeader";
import { LoadingState } from "../components/common/LoadingState";
import { EmptyState } from "../components/common/EmptyState";
import { AdminFormDrawer } from "../components/admins/AdminFormDrawer";
import { TotpManagementModal } from "../components/admins/TotpManagementModal";

const AdminsPage: React.FC = () => {
    const { serverUrl } = useAuth();
    const { isSuperAdmin, selectedRealm, realms, realmLabel } = useRealm();
    const api = useMemo(() => createAdminsApi(serverUrl), [serverUrl]);

    const [admins, setAdmins] = useState<Admin[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Drawer state
    const [drawerOpen, setDrawerOpen] = useState(false);
    const [editingAdmin, setEditingAdmin] = useState<Admin | null>(null);

    // TOTP modal state
    const [totpTarget, setTotpTarget] = useState<Admin | null>(null);

    // Check realm-admin ownership for non-super-admin mode
    const userRealmIds = realms.map((r) => r.id).filter((id) => id !== SUPER_ADMIN_REALM_ID);
    const canAdministerSelected = isSuperAdmin || userRealmIds.includes(selectedRealm);

    const fetchAdmins = useCallback(async () => {
        if (!isSuperAdmin) return;
        setLoading(true);
        setError(null);
        try {
            const data = await api.list();
            setAdmins(data);
        } catch {
            setError("Failed to load admins");
        } finally {
            setLoading(false);
        }
    }, [api, isSuperAdmin]);

    useEffect(() => {
        fetchAdmins();
    }, [fetchAdmins]);

    const handleCreate = (): void => {
        setEditingAdmin(null);
        setDrawerOpen(true);
    };

    const handleEdit = (admin: Admin): void => {
        setEditingAdmin(admin);
        setDrawerOpen(true);
    };

    const handleDrawerClose = (): void => {
        setDrawerOpen(false);
        setEditingAdmin(null);
    };

    const handleDrawerSuccess = (): void => {
        setDrawerOpen(false);
        setEditingAdmin(null);
        fetchAdmins();
    };

    const handleDelete = async (adminId: string) => {
        try {
            await api.delete(adminId);
            message.success(`Admin "${adminId}" deleted`);
            fetchAdmins();
        } catch {
            message.error(`Failed to delete admin "${adminId}"`);
        }
    };

    const handleTotpSuccess = () => {
        message.success("TOTP updated");
        setTotpTarget(null);
        fetchAdmins();
    };

    // ── Realm-admin mode (specific realm selected) ──
    // TODO: The page has two completely different UIs depending on isSuperAdmin (full table vs.
    //       a bare create-only form), with no clear indication of context to the user. Revisit
    //       this split: consider a unified layout that shows realm-scoped admins for realm-admins
    //       and the full cross-realm table for super-admins, with consistent chrome (PageHeader,
    //       empty states, loading states) in both cases.
    if (!isSuperAdmin) {
        if (!canAdministerSelected) {
            return <Result status="403" title="Access Denied" subTitle="You do not administer this realm." />;
        }

        return <RealmAdminCreateForm selectedRealm={selectedRealm} realmLabel={realmLabel} api={api} />;
    }

    // ── Super-admin mode ──
    if (loading) return <LoadingState message="Loading admins..." />;
    if (error) return <Alert type="error" showIcon message="Error" description={error} />;

    const columns = [
        {
            title: "ID",
            dataIndex: "id",
            key: "id",
            render: (id: string, record: Admin) => (
                <Typography.Link onClick={() => handleEdit(record)}>{id}</Typography.Link>
            ),
        },
        {
            title: "Realms",
            dataIndex: "realms",
            key: "realms",
            render: (adminRealms: string[]) => (
                <Space size={4} wrap>
                    {adminRealms.map((r) => (
                        <Tag key={r} color={r === SUPER_ADMIN_REALM_ID ? "gold" : undefined}>
                            {r === SUPER_ADMIN_REALM_ID ? "_ (Super)" : r}
                        </Tag>
                    ))}
                </Space>
            ),
        },
        {
            title: "Userpass",
            dataIndex: "userpass",
            key: "userpass",
            render: (v: string | null) => v ?? "—",
        },
        {
            title: "JWT",
            dataIndex: "jwt",
            key: "jwt",
            render: (v: string | null) => v ?? "—",
        },
        {
            title: "TOTP",
            dataIndex: "totp_enabled",
            key: "totp_enabled",
            render: (v: boolean | null) =>
                v ? <Badge status="success" text="Enabled" /> : <Badge status="default" text="Disabled" />,
        },
        {
            title: "Actions",
            key: "actions",
            render: (_: unknown, record: Admin) => (
                <Space>
                    <Button size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
                        Edit
                    </Button>
                    <Button
                        size="small"
                        icon={<SafetyCertificateOutlined />}
                        onClick={() => setTotpTarget(record)}
                    >
                        TOTP
                    </Button>
                    {!record.realms.includes(SUPER_ADMIN_REALM_ID) && (
                        <Popconfirm
                            title={`Delete admin "${record.id}"?`}
                            onConfirm={() => handleDelete(record.id)}
                            okText="Delete"
                            okType="danger"
                        >
                            <Button size="small" danger icon={<DeleteOutlined />}>
                                Delete
                            </Button>
                        </Popconfirm>
                    )}
                </Space>
            ),
        },
    ];

    return (
        <div>
            <PageHeader
                title="Admins"
                description="Manage administrator accounts"
                actionLabel="New Admin"
                onAction={handleCreate}
            />

            {admins.length === 0 ? (
                <EmptyState description="No admins found" actionLabel="New Admin" onAction={handleCreate} />
            ) : (
                <Table dataSource={admins} columns={columns} rowKey="id" pagination={false} />
            )}

            <AdminFormDrawer
                open={drawerOpen}
                admin={editingAdmin}
                onClose={handleDrawerClose}
                onSuccess={handleDrawerSuccess}
            />

            {totpTarget && (
                <TotpManagementModal
                    open={totpTarget !== null}
                    adminId={totpTarget.id}
                    realmId={SUPER_ADMIN_REALM_ID}
                    totpEnabled={totpTarget.totp_enabled ?? false}
                    onClose={() => setTotpTarget(null)}
                    onSuccess={handleTotpSuccess}
                />
            )}
        </div>
    );
};

// ── Realm-admin create-only form ──

interface RealmAdminCreateFormProps {
    selectedRealm: string;
    realmLabel: (id: string) => string;
    api: ReturnType<typeof createAdminsApi>;
}

const RealmAdminCreateForm: React.FC<RealmAdminCreateFormProps> = ({ selectedRealm, realmLabel, api }) => {
    const [form] = Form.useForm();
    const [loading, setLoading] = useState(false);

    const handleSubmit = async () => {
        try {
            const values = await form.validateFields();
            setLoading(true);
            const admin: Admin = {
                id: values.id,
                realms: [selectedRealm],
                userpass: values.userpass || null,
                jwt: values.jwt || null,
                fido2: null,
                digital_credentials: null,
                client_certificate: null,
                totp_enabled: null,
                totp_secret: null,
                totp_auth_url: null,
            };
            await api.create(admin);
            message.success(`Admin "${values.id}" created for realm "${selectedRealm}"`);
            form.resetFields();
        } catch {
            message.error("Failed to create admin");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div>
            <PageHeader title="Admins" description={`Create admin for realm: ${realmLabel(selectedRealm)}`} />
            <Alert
                type="info"
                showIcon
                message="Realm-admin mode"
                description="You can create new admins scoped to this realm. Switch to Super-Admin mode to view and manage all admins."
                className="mb-4"
            />
            <div style={{ maxWidth: 480 }}>
                <Form form={form} layout="vertical" autoComplete="off" onFinish={handleSubmit}>
                    <Form.Item
                        name="id"
                        label="Admin ID"
                        rules={[{ required: true, message: "Admin ID is required" }]}
                    >
                        <Input placeholder="e.g. alice" />
                    </Form.Item>
                    <Form.Item name="userpass" label="Userpass">
                        <Input placeholder="Username/password reference" />
                    </Form.Item>
                    <Form.Item name="jwt" label="JWT">
                        <Input placeholder="JWT identifier" />
                    </Form.Item>
                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={loading}>
                            Create Admin
                        </Button>
                    </Form.Item>
                </Form>
            </div>
        </div>
    );
};

export default AdminsPage;
