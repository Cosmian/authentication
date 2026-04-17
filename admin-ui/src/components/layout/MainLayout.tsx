import { Layout } from "antd";
import React, { useCallback, useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { API_VERSION } from "../../constants/apiPaths";
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
            <Layout.Header className="fixed w-full z-10 p-0 h-16 border-b flex items-center border-gray-300">
                <Header isDarkMode={isDarkMode} setIsDarkMode={setIsDarkMode} />
            </Layout.Header>
            <Layout style={{ marginTop: 64, height: "calc(100vh - 64px)" }}>
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
