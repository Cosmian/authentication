import { ConfigProvider } from "antd";
import { Route, Routes } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import { RealmProvider } from "./contexts/RealmContext";
import { useTheme } from "./contexts/ThemeProvider";
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

const App: React.FC = () => {
    const { antTheme } = useTheme();

    return (
        <ConfigProvider theme={antTheme}>
            <AuthProvider>
                <Routes>
                    <Route path="login" element={<LoginPage />} />
                    <Route
                        element={
                            <ProtectedRoute>
                                <RealmProvider>
                                    <MainLayout />
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
