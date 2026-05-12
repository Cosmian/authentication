import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { message } from "antd";
import { SUPER_ADMIN_REALM_ID, SUPER_ADMIN_REALM_LABEL, API_REALMS } from "../constants/apiPaths";
import type { Realm } from "../types/api";
import { useAuth } from "./AuthContext";

/* eslint-disable react-refresh/only-export-components */

const LS_SELECTED_REALM_KEY = "admin-ui-selected-realm";

interface RealmContextType {
    realms: Realm[];
    selectedRealm: string;
    setSelectedRealm: (realmId: string) => void;
    realmLabel: (realmId: string) => string;
    isSuperAdmin: boolean;
    /** True when the logged-in admin is a genuine super-admin (has `_` in their server-side realm list),
     *  regardless of which realm is currently selected. */
    isGlobalAdmin: boolean;
    loading: boolean;
    error: string | null;
}

const SUPER_ADMIN_REALM: Realm = {
    id: SUPER_ADMIN_REALM_ID,
    auth_params: { username_password_params: null, jwt_params: null, totp_params: null },
    session_max_age_seconds: 0,
    session_max_stale_age_seconds: 0,
};

const RealmContext = createContext<RealmContextType | undefined>(undefined);

export const RealmProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const { serverUrl, isAuthenticated } = useAuth();
    const [realms, setRealms] = useState<Realm[]>([SUPER_ADMIN_REALM]);
    const [selectedRealm, setSelectedRealmState] = useState<string>(
        () => localStorage.getItem(LS_SELECTED_REALM_KEY) ?? SUPER_ADMIN_REALM_ID,
    );
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [isGlobalAdmin, setIsGlobalAdmin] = useState(false);

    const isSuperAdmin = selectedRealm === SUPER_ADMIN_REALM_ID;

    const setSelectedRealm = useCallback((realmId: string) => {
        setSelectedRealmState(realmId);
        localStorage.setItem(LS_SELECTED_REALM_KEY, realmId);
    }, []);

    const realmLabel = useCallback(
        (realmId: string): string => {
            if (realmId === SUPER_ADMIN_REALM_ID) return SUPER_ADMIN_REALM_LABEL;
            return realms.find((r) => r.id === realmId)?.id ?? realmId;
        },
        [realms],
    );

    useEffect(() => {
        if (!isAuthenticated) {
            setLoading(false);
            return;
        }

        const fetchRealms = async () => {
            try {
                const res = await fetch(`${serverUrl}${API_REALMS}`, { credentials: "include" });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data: Realm[] = await res.json();

                if (data.length === 0) {
                    setRealms([SUPER_ADMIN_REALM]);
                    setIsGlobalAdmin(false);
                } else {
                    const hasAdmin = data.some((r) => r.id === SUPER_ADMIN_REALM_ID);
                    setRealms(hasAdmin ? data : [SUPER_ADMIN_REALM, ...data]);
                    setIsGlobalAdmin(hasAdmin);
                }
                setError(null);
            } catch {
                message.error("Failed to load realms");
                setRealms([SUPER_ADMIN_REALM]);
                setError("Failed to load realms");
            } finally {
                setLoading(false);
            }
        };

        fetchRealms();
    }, [isAuthenticated, serverUrl]);

    return (
        <RealmContext.Provider value={{ realms, selectedRealm, setSelectedRealm, realmLabel, isSuperAdmin, isGlobalAdmin, loading, error }}>
            {children}
        </RealmContext.Provider>
    );
};

export const useRealm = (): RealmContextType => {
    const context = useContext(RealmContext);
    if (!context) {
        throw new Error("useRealm must be used within a RealmProvider");
    }
    return context;
};
