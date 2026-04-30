import { Alert, Layout } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { API_VERSION } from "../../constants/apiPaths";
import { useRealm } from "../../contexts/RealmContext";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { Footer } from "./Footer";

interface MainLayoutProps {
    isDarkMode: boolean;
    setIsDarkMode: (value: boolean) => void;
}

export const MainLayout: React.FC<MainLayoutProps> = ({ isDarkMode, setIsDarkMode }) => {
    const [collapsed, setCollapsed] = useState(false);
    const [serverVersion, setServerVersion] = useState("");
    const { isSuperAdmin } = useRealm();

    const fetchVersion = useCallback(async () => {
        try {
            const res = await fetch(API_VERSION);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data: unknown = await res.json();
            setServerVersion(typeof data === "string" ? data : String(data));
        } catch {
            setServerVersion("Unavailable");
        }
    }, []);

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
                    style={{ position: "fixed", top: 0, left: 0, right: 0, zIndex: 900 }}
                />
            )}
            <Layout.Header
                className={`fixed w-full z-10 p-0 h-16 border-b flex items-center ${isDarkMode ? "border-gray-600" : "border-gray-300"}`}
                style={{ top: isSuperAdmin ? 32 : 0 }}
            >
                <Header isDarkMode={isDarkMode} setIsDarkMode={setIsDarkMode} />
            </Layout.Header>
            <Layout style={{ marginTop: isSuperAdmin ? 96 : 64, height: `calc(100vh - ${isSuperAdmin ? 96 : 64}px)` }}>
                <Sidebar collapsed={collapsed} onCollapse={setCollapsed} isDarkMode={isDarkMode} />
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
