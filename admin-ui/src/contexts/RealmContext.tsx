import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from "react";
import { message } from "antd";
import { SUPER_ADMIN_REALM_ID, SUPER_ADMIN_REALM_LABEL, API_REALMS } from "../constants/apiPaths";
import type { Admin, Realm } from "../types/api";
import { createAdminsApi } from "../services/adminsApi";
import { useAuth } from "./AuthContext";

/* eslint-disable react-refresh/only-export-components */

const LS_SELECTED_REALM_KEY = "admin-ui-selected-realm";

/** Realms with at least one admin of their own; realm `_` is excluded, it belongs to the super admins. */
function claimedRealmIds(admins: Admin[]): string[] {
    const ids = new Set(admins.flatMap((admin) => admin.realms));
    ids.delete(SUPER_ADMIN_REALM_ID);
    return [...ids];
}

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
    const [claimedRealms, setClaimedRealms] = useState<string[]>([]);

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

    const canManageRealm = useCallback(
        (realmId: string): boolean => {
            if (!isSuperAdmin) return realms.some((r) => r.id === realmId);
            return realmId === SUPER_ADMIN_REALM_ID || !claimedRealms.includes(realmId);
        },
        [isSuperAdmin, realms, claimedRealms],
    );

    // Only a super admin can list every admin. If this fails, claimed realms stay unmarked and the server still refuses the change.
    const loadClaimedRealms = useCallback(
        async (superAdmin: boolean) => {
            if (!superAdmin) {
                setClaimedRealms([]);
                return;
            }
            try {
                const admins = await createAdminsApi(serverUrl).list();
                if (mountedRef.current) setClaimedRealms(claimedRealmIds(admins));
            } catch {
                if (!mountedRef.current) return;
                message.error("Failed to load admins");
                setClaimedRealms([]);
            }
        },
        [serverUrl],
    );

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
            setClaimedRealms([]);
            setError("Failed to load realms");
        } finally {
            if (mountedRef.current) setLoading(false);
        }
    }, [isAuthenticated, serverUrl, loadClaimedRealms]);

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
