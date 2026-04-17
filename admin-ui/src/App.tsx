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

const lightTheme = {
    token: {
        colorPrimary: "#e34319",
        colorText: "#292f52",
    },
    components: {
        Layout: {
            headerBg: "#ffffff",
            footerPadding: "5px 50px",
        },
        Card: {
            colorBgContainer: "#ffffff",
            borderRadiusLG: 8,
        },
        Switch: {
            trackHeight: 32,
            handleSize: 28,
        },
        Button: {
            defaultHoverBorderColor: "#6e31e8",
            defaultHoverColor: "#6e31e8",
        },
    },
};

const darkTheme = {
    token: {
        colorPrimary: "#9e6eff",
        colorText: "#e4dddd",
        colorBgBase: "#2a2d30",
        colorTextPlaceholder: "#b9b9b9",
        colorError: "#e23030",
        colorBorder: "#4d4b4b",
        colorSplit: "#4d4b4b",
        colorBorderSecondary: "#4d4b4b",
    },
    components: {
        Layout: {
            headerBg: "#272d33",
            footerPadding: "5px 50px",
        },
        Menu: {
            itemSelectedBg: "#393E46",
            itemSelectedColor: "#9e6eff",
            itemHoverBg: "#2e3238",
            itemActiveBg: "#393E46",
            itemActiveColor: "#9e6eff",
        },
        Button: {
            primaryShadow: "None",
            dangerShadow: "None",
            defaultBorderColor: "#e4dddd",
        },
        Select: {
            selectorBg: "#2f3239",
            colorBorder: "#34383f",
            optionActiveBg: "#9e6eff",
            optionActiveColor: "#2a2d30",
            optionSelectedBg: "#9e6eff",
            optionSelectedColor: "#2a2d30",
            colorIcon: "#9e6eff",
        },
        Input: {
            colorBorder: "#34383f",
        },
        Card: {
            colorBgContainer: "#393E46",
            borderRadiusLG: 8,
        },
        Switch: {
            trackHeight: 32,
            handleSize: 28,
        },
    },
};

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
