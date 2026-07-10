/* eslint-disable react-refresh/only-export-components */
import React, { createContext, useContext, useEffect, useState } from "react";
import { theme as antdTheme } from "antd";
import type { ThemeConfig } from "antd";
import { darkTheme, lightTheme } from "../theme";
import type { Branding } from "../utils/branding";

const LS_DARKMODE_KEY = "admin-ui-darkMode";

type SuperAdminBannerStyle = {
    backgroundColor?: string;
    borderColor?: string;
    color?: string;
};

export type ThemeContextValue = {
    isDarkMode: boolean;
    setIsDarkMode: (v: boolean) => void;
    branding: Branding;
    antTheme: ThemeConfig;
    superAdminBannerStyle: SuperAdminBannerStyle | undefined;
};

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

export function useTheme(): ThemeContextValue {
    const ctx = useContext(ThemeContext);
    if (!ctx) {
        throw new Error("useTheme must be used within ThemeProvider");
    }
    return ctx;
}

export function ThemeProvider({ branding, children }: { branding: Branding; children: React.ReactNode }) {
    const [isDarkMode, setIsDarkMode] = useState(() => localStorage.getItem(LS_DARKMODE_KEY) === "true");

    useEffect(() => {
        localStorage.setItem(LS_DARKMODE_KEY, String(isDarkMode));
    }, [isDarkMode]);

    const activeTheme = isDarkMode ? darkTheme : lightTheme;
    const brandingTokens = isDarkMode ? branding.tokens?.dark : branding.tokens?.light;
    const antTheme: ThemeConfig = {
        ...antdTheme.defaultConfig,
        ...activeTheme,
        token: {
            ...(activeTheme as ThemeConfig).token,
            ...brandingTokens,
        },
    };

    const superAdminBannerStyle = isDarkMode ? branding.superAdminBanner?.dark : branding.superAdminBanner?.light;

    return (
        <ThemeContext.Provider value={{ isDarkMode, setIsDarkMode, branding, antTheme, superAdminBannerStyle }}>
            {children}
        </ThemeContext.Provider>
    );
}
