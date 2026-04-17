import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { message } from "antd";
import { ADMIN_REALM_ID, ADMIN_REALM_LABEL, API_REALMS } from "../constants/apiPaths";

/* eslint-disable react-refresh/only-export-components */

const LS_SELECTED_REALM_KEY = "admin-ui-selected-realm";

export interface RealmEntry {
    id: string;
    label: string;
}

interface RealmContextType {
    realms: RealmEntry[];
    selectedRealm: string;
    setSelectedRealm: (realmId: string) => void;
    realmLabel: (realmId: string) => string;
    loading: boolean;
    error: string | null;
}

const ADMIN_ENTRY: RealmEntry = { id: ADMIN_REALM_ID, label: ADMIN_REALM_LABEL };

const RealmContext = createContext<RealmContextType | undefined>(undefined);

const toRealmEntry = (raw: { id: string }): RealmEntry => ({
    id: raw.id,
    label: raw.id === ADMIN_REALM_ID ? ADMIN_REALM_LABEL : raw.id,
});

export const RealmProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
    const [realms, setRealms] = useState<RealmEntry[]>([ADMIN_ENTRY]);
    const [selectedRealm, setSelectedRealmState] = useState<string>(
        () => localStorage.getItem(LS_SELECTED_REALM_KEY) ?? ADMIN_REALM_ID,
    );
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const setSelectedRealm = useCallback((realmId: string) => {
        setSelectedRealmState(realmId);
        localStorage.setItem(LS_SELECTED_REALM_KEY, realmId);
    }, []);

    const realmLabel = useCallback(
        (realmId: string): string => {
            const entry = realms.find((r) => r.id === realmId);
            return entry?.label ?? realmId;
        },
        [realms],
    );

    useEffect(() => {
        const fetchRealms = async () => {
            try {
                const res = await fetch(API_REALMS);
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data: { id: string }[] = await res.json();
                const entries = data.map(toRealmEntry);

                if (entries.length === 0) {
                    setRealms([ADMIN_ENTRY]);
                } else {
                    const hasAdmin = entries.some((e) => e.id === ADMIN_REALM_ID);
                    setRealms(hasAdmin ? entries : [ADMIN_ENTRY, ...entries]);
                }
                setError(null);
            } catch {
                message.error("Failed to load realms");
                setRealms([ADMIN_ENTRY]);
                setError("Failed to load realms");
            } finally {
                setLoading(false);
            }
        };

        fetchRealms();
    }, []);

    return (
        <RealmContext.Provider value={{ realms, selectedRealm, setSelectedRealm, realmLabel, loading, error }}>
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
