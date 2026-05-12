import { ConfigProvider, theme } from "antd";
import { useEffect, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import { RealmProvider } from "./contexts/RealmContext";
import { MainLayout } from "./components/layout/MainLayout";
import { ProtectedRoute } from "./components/common/ProtectedRoute";
import AdminsPage from "./pages/AdminsPage";
import CredentialsPage from "./pages/CredentialsPage";
import DashboardPage from "./pages/DashboardPage";
import LoginPage from "./pages/LoginPage";
import NotFoundPage from "./pages/NotFoundPage";
import RealmsPage from "./pages/RealmsPage";
import SessionsPage from "./pages/SessionsPage";
import TotpPage from "./pages/TotpPage";
import { darkTheme, lightTheme } from "./theme";

const LS_DARKMODE_KEY = "admin-ui-darkMode";

const App: React.FC = () => {
    const [isDarkMode, setIsDarkMode] = useState(() => localStorage.getItem(LS_DARKMODE_KEY) === "true");

    useEffect(() => {
        localStorage.setItem(LS_DARKMODE_KEY, String(isDarkMode));
    }, [isDarkMode]);

    const activeTheme = isDarkMode ? darkTheme : lightTheme;

    return (
        <ConfigProvider
            theme={{
                ...theme.defaultConfig,
                ...activeTheme,
                token: activeTheme.token,
            }}
        >
            <AuthProvider>
                <Routes>
                    <Route path="login" element={<LoginPage />} />
                    <Route
                        element={
                            <ProtectedRoute>
                                <RealmProvider>
                                    <MainLayout isDarkMode={isDarkMode} setIsDarkMode={setIsDarkMode} />
                                </RealmProvider>
                            </ProtectedRoute>
                        }
                    >
                        <Route index element={<DashboardPage />} />
                        <Route path="realms" element={<RealmsPage />} />
                        <Route path="admins" element={<AdminsPage />} />
                        <Route path="credentials" element={<CredentialsPage />} />
                        <Route path="sessions" element={<SessionsPage />} />
                        <Route path="totp" element={<TotpPage />} />
                    </Route>
                    <Route path="*" element={<NotFoundPage />} />
                </Routes>
            </AuthProvider>
        </ConfigProvider>
    );
};

export default App;
