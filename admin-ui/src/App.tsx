import { ConfigProvider, theme } from "antd";
import { useEffect, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import { RealmProvider } from "./contexts/RealmContext";
import { MainLayout } from "./components/layout/MainLayout";
import DashboardPage from "./pages/DashboardPage";
import PlaceholderPage from "./pages/PlaceholderPage";
import NotFoundPage from "./pages/NotFoundPage";

const LS_DARKMODE_KEY = "admin-ui-darkMode";

const App: React.FC = () => {
    const [isDarkMode, setIsDarkMode] = useState(() => localStorage.getItem(LS_DARKMODE_KEY) === "true");

    useEffect(() => {
        localStorage.setItem(LS_DARKMODE_KEY, String(isDarkMode));
    }, [isDarkMode]);

    return (
        <ConfigProvider
            theme={{
                algorithm: isDarkMode ? theme.darkAlgorithm : theme.defaultAlgorithm,
            }}
        >
            <AuthProvider>
                <RealmProvider>
                    <Routes>
                        <Route element={<MainLayout isDarkMode={isDarkMode} setIsDarkMode={setIsDarkMode} />}>
                            <Route index element={<DashboardPage />} />
                            <Route path="users" element={<PlaceholderPage title="Users" />} />
                            <Route path="credentials" element={<PlaceholderPage title="Credentials" />} />
                            <Route path="sessions" element={<PlaceholderPage title="Sessions" />} />
                            <Route path="totp" element={<PlaceholderPage title="TOTP" />} />
                            <Route path="*" element={<NotFoundPage />} />
                        </Route>
                    </Routes>
                </RealmProvider>
            </AuthProvider>
        </ConfigProvider>
    );
};

export default App;
