import { Layout, Menu, MenuProps } from "antd";
import React, { useMemo } from "react";
import { useLocation, useNavigate } from "react-router";
import { menuItems } from "../../menuItems";
import { useRealm } from "../../contexts/RealmContext";
import { useTheme } from "../../contexts/ThemeProvider";

export interface SidebarProps {
    collapsed: boolean;
    onCollapse: (collapsed: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onCollapse }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const { isSuperAdmin, canManageRealm, selectedRealm } = useRealm();
    const { isDarkMode, branding } = useTheme();

    const filteredItems = useMemo(() => {
        // A super admin always gets Admins: it lists the admins of claimed realms read-only.
        return menuItems
            .filter((item) => {
                if (item.superAdminOnly && !isSuperAdmin) return false;
                if (item.requiresRealmOwnership && !isSuperAdmin && !canManageRealm(selectedRealm)) return false;
                return true;
            })
            .map((item) => ({
                key: item.key,
                label: item.label,
                icon: item.icon,
                children: item.children,
            }));
    }, [isSuperAdmin, canManageRealm, selectedRealm]);

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
