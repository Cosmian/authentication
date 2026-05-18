import { Layout, Menu, MenuProps } from "antd";
import React, { useMemo } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { menuItems } from "../../menuItems";
import { useRealm } from "../../contexts/RealmContext";
import { useBranding } from "../../contexts/useBranding";
import { SUPER_ADMIN_REALM_ID } from "../../constants/apiPaths";

export interface SidebarProps {
    collapsed: boolean;
    onCollapse: (collapsed: boolean) => void;
    isDarkMode: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onCollapse, isDarkMode }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const { isGlobalAdmin, realms, selectedRealm } = useRealm();
    const branding = useBranding();

    const filteredItems = useMemo(() => {
        // The user administers the selected realm if they are a global super-admin
        // OR the selected realm is in their realm list (non-"_" realms)
        const userRealmIds = realms.map((r) => r.id).filter((id) => id !== SUPER_ADMIN_REALM_ID);
        const canAdministerSelected = isGlobalAdmin || userRealmIds.includes(selectedRealm);

        return menuItems
            .filter((item) => {
                if (item.superAdminOnly && !isGlobalAdmin) return false;
                if (item.requiresRealmOwnership && !isGlobalAdmin && !canAdministerSelected) return false;
                return true;
            })
            .map((item) => ({
                key: item.key,
                label: item.label,
                icon: item.icon,
                children: item.children,
            }));
    }, [isGlobalAdmin, realms, selectedRealm]);

    const selectedKey = location.pathname === "/" ? "/" : location.pathname;

    return (
        <Layout.Sider
            collapsible
            collapsed={collapsed}
            onCollapse={onCollapse}
            theme={branding.menuTheme ?? (isDarkMode ? "dark" : "light")}
            className="overflow-auto"
            style={{ height: "calc(100vh - 64px)" }}
        >
            <Menu
                mode="inline"
                selectedKeys={[selectedKey]}
                items={filteredItems as MenuProps["items"]}
                onClick={({ key }) => navigate(key)}
            />
        </Layout.Sider>
    );
};
