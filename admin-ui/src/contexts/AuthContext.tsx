import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from "react";
import { API_LOGIN, API_WHOAMI, API_SESSIONS, SUPER_ADMIN_REALM_ID } from "../constants/apiPaths";
import type { AuthenticationResult, ClientClaims, DeleteSessionsRequest, LoginRequest } from "../types/api";

/* eslint-disable react-refresh/only-export-components */

export type LoginStatus = "authenticated" | "totp_required" | "change_password" | "error";

export interface LoginResult {
    status: LoginStatus;
    message?: string;
}

interface AuthState {
    isAuthenticated: boolean;
    username: string | null;
    sessionId: string | null;
    exp: number | null;
}

interface AuthContextType extends AuthState {
    serverUrl: string;
    loading: boolean;
    login: (username: string, password: string, totpCode?: string) => Promise<LoginResult>;
    logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const resolveServerUrl = (): string => {
    const configured = import.meta.env.VITE_AUTH_URL as string | undefined;
    const trimmed = configured?.trim();
    return trimmed && trimmed.length > 0 ? trimmed : "https://localhost:8443";
};

const INITIAL_STATE: AuthState = {
    isAuthenticated: false,
    username: null,
    sessionId: null,
    exp: null,
};

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const serverUrl = resolveServerUrl();
    const [state, setState] = useState<AuthState>(INITIAL_STATE);
    const [loading, setLoading] = useState(true);
    const expiryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

    const clearExpiryTimer = useCallback(() => {
        if (expiryTimerRef.current) {
            clearTimeout(expiryTimerRef.current);
            expiryTimerRef.current = null;
        }
    }, []);

    const scheduleExpiry = useCallback(
        (exp: number) => {
            clearExpiryTimer();
            const msUntilExpiry = exp * 1000 - Date.now();
            if (msUntilExpiry <= 0) {
                setState(INITIAL_STATE);
                return;
            }
            expiryTimerRef.current = setTimeout(() => {
                setState(INITIAL_STATE);
            }, msUntilExpiry);
        },
        [clearExpiryTimer],
    );

    // Check existing session on mount via GET /whoami
    useEffect(() => {
        const checkSession = async () => {
            try {
                const res = await fetch(`${serverUrl}${API_WHOAMI}?realm=${SUPER_ADMIN_REALM_ID}`, {
                    credentials: "include",
                });
                if (!res.ok) {
                    setState(INITIAL_STATE);
                    return;
                }
                const claims: ClientClaims = await res.json();
                setState({
                    isAuthenticated: true,
                    username: claims.sub,
                    sessionId: null, // session_id not available from whoami
                    exp: claims.exp,
                });
                scheduleExpiry(claims.exp);
            } catch {
                setState(INITIAL_STATE);
            } finally {
                setLoading(false);
            }
        };

        checkSession();
    }, [serverUrl, scheduleExpiry]);

    const login = useCallback(
        async (username: string, password: string, totpCode?: string): Promise<LoginResult> => {
            const body: LoginRequest = {
                totp_code: totpCode ?? null,
            };

            try {
                const res = await fetch(`${serverUrl}${API_LOGIN}?realm=${SUPER_ADMIN_REALM_ID}`, {
                    method: "POST",
                    credentials: "include",
                    headers: {
                        "Content-Type": "application/json",
                        Authorization: `Basic ${btoa(`${username}:${password}`)}`,
                    },
                    body: JSON.stringify(body),
                });

                if (!res.ok) {
                    const text = await res.text().catch(() => "Authentication failed");
                    return { status: "error", message: text };
                }

                const result: AuthenticationResult = await res.json();

                switch (result.next_step) {
                    case "TotpRequired":
                        return { status: "totp_required" };

                    case "ChangePassword":
                        return {
                            status: "change_password",
                            message: "Your password has expired. Contact a super admin to reset it via the Credentials page.",
                        };

                    case "Authenticated": {
                        // Fetch claims to get exp and username
                        const whoamiRes = await fetch(`${serverUrl}${API_WHOAMI}?realm=${SUPER_ADMIN_REALM_ID}`, {
                            credentials: "include",
                        });
                        let exp = Math.floor(Date.now() / 1000) + 3600; // fallback 1h
                        let sub = username;
                        if (whoamiRes.ok) {
                            const claims: ClientClaims = await whoamiRes.json();
                            exp = claims.exp;
                            sub = claims.sub;
                        }

                        setState({
                            isAuthenticated: true,
                            username: sub,
                            sessionId: result.session_id,
                            exp,
                        });
                        scheduleExpiry(exp);
                        return { status: "authenticated" };
                    }
                }
            } catch {
                return { status: "error", message: "Network error. Is the server reachable?" };
            }
        },
        [serverUrl, scheduleExpiry],
    );

    const logout = useCallback(async () => {
        clearExpiryTimer();
        if (state.sessionId) {
            try {
                const body: DeleteSessionsRequest = { session_ids: [state.sessionId] };
                await fetch(`${serverUrl}${API_SESSIONS}`, {
                    method: "DELETE",
                    credentials: "include",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(body),
                });
            } catch {
                // Best-effort — clear local state regardless
            }
        }
        setState(INITIAL_STATE);
    }, [serverUrl, state.sessionId, clearExpiryTimer]);

    return (
        <AuthContext.Provider
            value={{
                ...state,
                serverUrl,
                loading,
                login,
                logout,
            }}
        >
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = (): AuthContextType => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error("useAuth must be used within an AuthProvider");
    }
    return context;
};
