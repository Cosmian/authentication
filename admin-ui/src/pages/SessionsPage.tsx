import { Alert, Button, message } from "antd";
import { DeleteOutlined, ClearOutlined } from "@ant-design/icons";
import React, { useMemo, useState } from "react";
import { SUPER_ADMIN_REALM_ID } from "../constants/apiPaths";
import { useAuth } from "../contexts/AuthContext";
import { useRealm } from "../contexts/RealmContext";
import { createSessionsApi } from "../services/sessionsApi";
import { PageHeader } from "../components/common/PageHeader";
import { ConfirmDeleteModal } from "../components/common/ConfirmDeleteModal";

const SessionsPage: React.FC = () => {
    const { serverUrl } = useAuth();
    const { selectedRealm, isSuperAdmin, realmLabel } = useRealm();
    const api = useMemo(() => createSessionsApi(serverUrl), [serverUrl]);

    const [revokeModalOpen, setRevokeModalOpen] = useState(false);
    const [purging, setPurging] = useState(false);

    const handleRevokeAll = async () => {
        try {
            await api.revokeAllForRealm(selectedRealm);
            message.success(`All sessions revoked for realm "${realmLabel(selectedRealm)}"`);
            setRevokeModalOpen(false);
        } catch {
            message.error("Failed to revoke sessions");
        }
    };

    const handlePurgeExpired = async () => {
        setPurging(true);
        try {
            await api.purgeExpired();
            message.success("Expired sessions purged");
        } catch {
            message.error("Failed to purge expired sessions");
        } finally {
            setPurging(false);
        }
    };

    if (selectedRealm === SUPER_ADMIN_REALM_ID) {
        return (
            <div>
                <PageHeader title="Sessions" />
                <Alert
                    type="info"
                    showIcon
                    message="Select a realm"
                    description="Choose a realm from the header selector to manage its sessions."
                    className="mb-4"
                />
                {isSuperAdmin && (
                    <div className="mt-4">
                        <Button icon={<ClearOutlined />} onClick={handlePurgeExpired} loading={purging}>
                            Purge Expired Sessions
                        </Button>
                    </div>
                )}
            </div>
        );
    }

    return (
        <div>
            <PageHeader title="Sessions" description={`Realm: ${realmLabel(selectedRealm)}`} />

            <Alert
                type="info"
                showIcon
                message="Session browsing not yet available"
                description="A server-side endpoint for listing sessions is required. You can revoke all sessions for this realm."
                className="mb-4"
            />

            <div className="mt-6">
                <Button danger type="primary" icon={<DeleteOutlined />} onClick={() => setRevokeModalOpen(true)}>
                    Revoke All Sessions
                </Button>
            </div>

            <ConfirmDeleteModal
                open={revokeModalOpen}
                itemName={realmLabel(selectedRealm)}
                onConfirm={handleRevokeAll}
                onCancel={() => setRevokeModalOpen(false)}
                loading={false}
            />
        </div>
    );
};

export default SessionsPage;
