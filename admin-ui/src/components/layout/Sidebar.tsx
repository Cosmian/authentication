import { Layout, Menu, MenuProps } from "antd";
import React, { useMemo } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { menuItems } from "../../menuItems";
import { useRealm } from "../../contexts/RealmContext";

export interface SidebarProps {
    collapsed: boolean;
    onCollapse: (collapsed: boolean) => void;
    isDarkMode: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onCollapse, isDarkMode }) => {
    const navigate = useNavigate();
    const location = useLocation();
    const { isSuperAdmin } = useRealm();

    const filteredItems = useMemo(
        () =>
            menuItems
                .filter((item) => !item.superAdminOnly || isSuperAdmin)
                .map(({ superAdminOnly: _, ...rest }) => rest),
        [isSuperAdmin],
    );

    const selectedKey = location.pathname === "/" ? "/" : location.pathname;

    return (
        <Layout.Sider
            collapsible
            collapsed={collapsed}
            onCollapse={onCollapse}
            theme={isDarkMode ? "dark" : "light"}
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
