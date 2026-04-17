import { createContext, ReactNode, useContext } from "react";

/* eslint-disable react-refresh/only-export-components */

interface AuthContextType {
    isAuthenticated: boolean;
    username: string | null;
    serverUrl: string;
    login: () => void;
    logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const resolveServerUrl = (): string => {
    const configured = import.meta.env.VITE_AUTH_URL as string | undefined;
    const trimmed = configured?.trim();
    return trimmed && trimmed.length > 0 ? trimmed : "https://localhost:8443";
};

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    // Stub: authentication is not implemented yet.
    // When real auth is wired, these will be replaced by state + API calls.
    const value: AuthContextType = {
        isAuthenticated: true,
        username: "admin",
        serverUrl: resolveServerUrl(),
        login: () => {},
        logout: () => {},
    };

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error("useAuth must be used within an AuthProvider");
    }
    return context;
};
