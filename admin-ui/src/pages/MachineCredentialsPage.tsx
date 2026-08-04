import { Alert, Tabs } from "antd";
import React from "react";
import { useRealm } from "../contexts/RealmContext";
import { PageHeader } from "../components/common/PageHeader";
import { AppRoleTab } from "../components/machine/AppRoleTab";
import { KubernetesTab } from "../components/machine/KubernetesTab";
import { TokenTab } from "../components/machine/TokenTab";

/**
 * Super-admin page for managing Vault-compatible machine-authentication methods:
 * AppRole roles, Kubernetes roles, and token self-service. These credentials are
 * global (not realm-scoped).
 */
const MachineCredentialsPage: React.FC = () => {
    const { isGlobalAdmin } = useRealm();

    if (!isGlobalAdmin) {
        return (
            <Alert
                type="warning"
                showIcon
                message="Super-admin only"
                description="Machine credentials are global and can only be managed by a super-admin."
            />
        );
    }

    return (
        <div style={{ maxWidth: 1000 }}>
            <PageHeader title="Machine Credentials" description="Vault-compatible AppRole, Kubernetes, and token self-service" />
            <Tabs
                defaultActiveKey="approle"
                items={[
                    { key: "approle", label: "AppRole", children: <AppRoleTab /> },
                    { key: "kubernetes", label: "Kubernetes", children: <KubernetesTab /> },
                    { key: "token", label: "Token", children: <TokenTab /> },
                ]}
            />
        </div>
    );
};

export default MachineCredentialsPage;
