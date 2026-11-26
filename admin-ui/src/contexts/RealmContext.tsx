import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from "react";
import { message } from "antd";
import { SUPER_ADMIN_REALM_ID, SUPER_ADMIN_REALM_LABEL, API_REALMS } from "../constants/apiPaths";
import type { Realm } from "../types/api";
import { useAuth } from "./AuthContext";
import { useRealmPermissions } from "./useRealmPermissions";

/* eslint-disable react-refresh/only-export-components */

const LS_SELECTED_REALM_KEY = "admin-ui-selected-realm";

interface RealmContextType {
    realms: Realm[];
    selectedRealm: string;
    setSelectedRealm: (realmId: string) => void;
    realmLabel: (realmId: string) => string;
    /** The Super-Admin view (realm `_`) is selected in the header; says nothing about who is logged in. */
    isSuperAdminMode: boolean;
    isSuperAdmin: boolean;
    /** Whether the server lets the logged-in admin change the realm: a super admin loses that once the realm has its own admins. */
    canManageRealm: (realmId: string) => boolean;
    loading: boolean;
    error: string | null;
    refreshRealms: () => void;
}

const RealmContext = createContext<RealmContextType | undefined>(undefined);

export const RealmProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const { serverUrl, isAuthenticated } = useAuth();
    const [realms, setRealms] = useState<Realm[]>([]);
    const [selectedRealm, setSelectedRealmState] = useState<string>(
        () => localStorage.getItem(LS_SELECTED_REALM_KEY) ?? SUPER_ADMIN_REALM_ID,
    );
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [isSuperAdmin, setIsSuperAdmin] = useState(false);

    const isSuperAdminMode = selectedRealm === SUPER_ADMIN_REALM_ID;

    // Guards against setState-after-unmount: fetchRealms is also exposed as refreshRealms
    // for manual re-fetch, so a request can still be in flight when the provider unmounts.
    const mountedRef = useRef(true);
    useEffect(() => {
        mountedRef.current = true;
        return () => {
            mountedRef.current = false;
        };
    }, []);

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

    const { canManageRealm, loadClaimedRealms, clearClaimedRealms } = useRealmPermissions(serverUrl, mountedRef, isSuperAdmin, realms);

    const fetchRealms = useCallback(async () => {
        if (!isAuthenticated) {
            if (mountedRef.current) setLoading(false);
            return;
        }

        try {
            const res = await fetch(`${serverUrl}${API_REALMS}`, { credentials: "include" });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data: Realm[] = await res.json();
            if (!mountedRef.current) return;

            const hasAdmin = data.some((r) => r.id === SUPER_ADMIN_REALM_ID);
            // Trust the server response — only show realms the admin can actually access.
            // Do not artificially inject SUPER_ADMIN_REALM for non-super-admins.
            setRealms(data);
            setIsSuperAdmin(hasAdmin);
            // If the previously selected realm is no longer accessible, fall back to
            // the first realm in the list (or SUPER_ADMIN_REALM_ID as a safe default).
            setSelectedRealmState((prev) => {
                if (data.some((r) => r.id === prev)) return prev;
                return data[0]?.id ?? SUPER_ADMIN_REALM_ID;
            });
            setError(null);
            await loadClaimedRealms(hasAdmin);
        } catch {
            if (!mountedRef.current) return;
            message.error("Failed to load realms");
            setRealms([]);
            clearClaimedRealms();
            setError("Failed to load realms");
        } finally {
            if (mountedRef.current) setLoading(false);
        }
    }, [isAuthenticated, serverUrl, loadClaimedRealms, clearClaimedRealms]);

    useEffect(() => {
        fetchRealms();
    }, [fetchRealms]);

    return (
        <RealmContext.Provider
            value={{
                realms,
                selectedRealm,
                setSelectedRealm,
                realmLabel,
                isSuperAdminMode,
                isSuperAdmin,
                canManageRealm,
                loading,
                error,
                refreshRealms: fetchRealms,
            }}
        >
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
