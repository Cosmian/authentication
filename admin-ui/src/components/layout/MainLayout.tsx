import { Alert, Layout } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { API_VERSION } from "../../constants/apiPaths";
import { useAuth } from "../../contexts/AuthContext";
import { useRealm } from "../../contexts/RealmContext";
import { useTheme } from "../../contexts/ThemeProvider";
import { apiGet } from "../../services/api";
import type { VersionResponse } from "../../types/api";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { Footer } from "./Footer";

export const MainLayout: React.FC = () => {
    const [collapsed, setCollapsed] = useState(false);
    const [serverVersion, setServerVersion] = useState("");
    const { serverUrl } = useAuth();
    const { isSuperAdmin } = useRealm();
    const { isDarkMode, setIsDarkMode, superAdminBannerStyle } = useTheme();

    const fetchVersion = useCallback(async () => {
        try {
            const { version } = await apiGet<VersionResponse>(serverUrl, API_VERSION);
            setServerVersion(version);
        } catch {
            setServerVersion("Unavailable");
        }
    }, [serverUrl]);

    useEffect(() => {
        fetchVersion();
    }, [fetchVersion]);

    return (
        <Layout>
            {isSuperAdmin && (
                <Alert
                    banner
                    type="error"
                    message="Super-Admin mode — changes can affect all realms"
                    showIcon={false}
                    className="text-center font-semibold"
                    style={{
                        position: "fixed",
                        top: 0,
                        left: 0,
                        right: 0,
                        zIndex: 900,
                        backgroundColor: superAdminBannerStyle?.backgroundColor,
                        borderColor: superAdminBannerStyle?.borderColor,
                        color: superAdminBannerStyle?.color,
                    }}
                />
            )}
            <Layout.Header
                className={`fixed w-full z-10 p-0 h-16 border-b flex items-center ${isDarkMode ? "border-gray-600" : "border-gray-300"}`}
                style={{ top: isSuperAdmin ? 32 : 0 }}
            >
                <Header />
            </Layout.Header>
            <Layout style={{ marginTop: isSuperAdmin ? 96 : 64, height: `calc(100vh - ${isSuperAdmin ? 96 : 64}px)` }}>
                <Sidebar collapsed={collapsed} onCollapse={setCollapsed} />
                <Layout className="flex flex-col overflow-hidden">
                    <Layout.Content id="main-content" className="flex-grow overflow-auto p-4">
                        <Outlet />
                    </Layout.Content>
                    <Footer version={serverVersion} />
                </Layout>
            </Layout>
        </Layout>
    );
};
