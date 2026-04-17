import { Layout, Menu, MenuProps } from "antd";
import React from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { menuItems } from "../../menuItems";

interface SidebarProps {
    collapsed: boolean;
    onCollapse: (collapsed: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ collapsed, onCollapse }) => {
    const navigate = useNavigate();
    const location = useLocation();

    const selectedKey = location.pathname === "/" ? "/" : location.pathname;

    return (
        <Layout.Sider
            collapsible
            collapsed={collapsed}
            onCollapse={onCollapse}
            theme="light"
            className="overflow-auto"
            style={{ height: "calc(100vh - 64px)" }}
        >
            <Menu
                mode="inline"
                selectedKeys={[selectedKey]}
                items={menuItems as MenuProps["items"]}
                onClick={({ key }) => navigate(key)}
            />
        </Layout.Sider>
    );
};
