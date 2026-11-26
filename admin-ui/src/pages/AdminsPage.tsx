import { Alert, Badge, Button, message, Popconfirm, Space, Table, Tag, Tooltip, Typography } from "antd";
import { DeleteOutlined, EditOutlined, KeyOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
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
import { AdminCredentialModal } from "../components/admins/AdminCredentialModal";
import { TotpManagementModal } from "../components/admins/TotpManagementModal";

const READ_ONLY_HINT = "This admin belongs to a realm that has its own admins: only they can change it.";

const AdminsPage: React.FC = () => {
    const { serverUrl } = useAuth();
    const { isSuperAdmin, isSuperAdminMode, canManageRealm, selectedRealm, realmLabel, loading: realmsLoading, refreshRealms } = useRealm();
    const api = useMemo(() => createAdminsApi(serverUrl), [serverUrl]);

    const [admins, setAdmins] = useState<Admin[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Drawer state
    const [drawerOpen, setDrawerOpen] = useState(false);
    const [editingAdmin, setEditingAdmin] = useState<Admin | null>(null);

    // TOTP modal state
    const [totpTarget, setTotpTarget] = useState<Admin | null>(null);

    // Credential modal state
    const [credentialTarget, setCredentialTarget] = useState<Admin | null>(null);

    // The server only lists the admins the user may read; the Super-Admin view shows them all, a realm view the realm's.
    const visibleAdmins = isSuperAdminMode ? admins : admins.filter((admin) => admin.realms.includes(selectedRealm));
    const canCreate = isSuperAdminMode || canManageRealm(selectedRealm);
    // An admin without realms is only for super admins; otherwise every one of its realms must be manageable.
    const canManageAdmin = (admin: Admin): boolean => (admin.realms.length === 0 ? isSuperAdmin : admin.realms.every(canManageRealm));

    const fetchAdmins = useCallback(async () => {
        if (realmsLoading) return;
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
    }, [api, realmsLoading]);

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

    // Adding a realm's first admin claims it, deleting its last one releases it.
    const handleDrawerSuccess = (): void => {
        setDrawerOpen(false);
        setEditingAdmin(null);
        fetchAdmins();
        refreshRealms();
    };

    const handleDelete = async (adminId: string) => {
        try {
            await api.delete(adminId);
            message.success(`Admin "${adminId}" deleted`);
            fetchAdmins();
            refreshRealms();
        } catch {
            message.error(`Failed to delete admin "${adminId}"`);
        }
    };

    const handleTotpSuccess = () => {
        message.success("TOTP updated");
        setTotpTarget(null);
        fetchAdmins();
    };

    const handleCredentialSuccess = () => {
        setCredentialTarget(null);
        fetchAdmins();
    };

    if (realmsLoading || loading) return <LoadingState message="Loading admins..." />;
    if (error) return <Alert type="error" showIcon message="Error" description={error} />;

    const columns = [
        {
            title: "ID",
            dataIndex: "id",
            key: "id",
            render: (id: string, record: Admin) =>
                canManageAdmin(record) ? <Typography.Link onClick={() => handleEdit(record)}>{id}</Typography.Link> : id,
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
            render: (v: boolean | null) => (v ? <Badge status="success" text="Enabled" /> : <Badge status="default" text="Disabled" />),
        },
        {
            title: "Actions",
            key: "actions",
            render: (_: unknown, record: Admin) =>
                canManageAdmin(record) ? (
                    <Space>
                        <Button size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
                            Edit
                        </Button>
                        <Button size="small" icon={<SafetyCertificateOutlined />} onClick={() => setTotpTarget(record)}>
                            TOTP
                        </Button>
                        <Button size="small" icon={<KeyOutlined />} onClick={() => setCredentialTarget(record)}>
                            Credential
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
                ) : (
                    <Tooltip title={READ_ONLY_HINT}>
                        <Tag>Read-only</Tag>
                    </Tooltip>
                ),
        },
    ];

    return (
        <div>
            <PageHeader
                title="Admin Management"
                description={isSuperAdminMode ? "Manage administrator accounts" : `Administrators of realm: ${realmLabel(selectedRealm)}`}
                actionLabel={canCreate ? "New Admin" : undefined}
                onAction={handleCreate}
            />

            {!canCreate && (
                <Alert
                    type="info"
                    showIcon
                    className="mb-4"
                    message="This realm has its own admins"
                    description="You can see them to get in touch, but only they can add or change admins of this realm."
                />
            )}

            {visibleAdmins.length === 0 ? (
                <EmptyState description="No admins found" actionLabel={canCreate ? "New Admin" : undefined} onAction={handleCreate} />
            ) : (
                <Table dataSource={visibleAdmins} columns={columns} rowKey="id" pagination={false} />
            )}

            <AdminFormDrawer
                open={drawerOpen}
                admin={editingAdmin}
                defaultRealm={isSuperAdminMode ? undefined : selectedRealm}
                onClose={handleDrawerClose}
                onSuccess={handleDrawerSuccess}
                onTotpSetup={(adminId) =>
                    setTotpTarget({
                        id: adminId,
                        realms: [],
                        userpass: null,
                        jwt: null,
                        fido2: null,
                        digital_credentials: null,
                        client_certificate: null,
                        totp_enabled: false,
                    })
                }
            />

            {totpTarget && (
                <TotpManagementModal
                    open={totpTarget !== null}
                    adminId={totpTarget.userpass ?? totpTarget.id}
                    realmId={SUPER_ADMIN_REALM_ID}
                    totpEnabled={totpTarget.totp_enabled ?? false}
                    onClose={() => setTotpTarget(null)}
                    onSuccess={handleTotpSuccess}
                />
            )}

            {credentialTarget && (
                <AdminCredentialModal
                    open={credentialTarget !== null}
                    adminId={credentialTarget.userpass ?? credentialTarget.id}
                    hasCredential={credentialTarget.userpass !== null}
                    onClose={() => setCredentialTarget(null)}
                    onSuccess={handleCredentialSuccess}
                />
            )}
        </div>
    );
};

export default AdminsPage;
