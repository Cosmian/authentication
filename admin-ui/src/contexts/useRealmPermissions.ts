import { useCallback, useState, type RefObject } from "react";
import { message } from "antd";
import { SUPER_ADMIN_REALM_ID } from "../constants/apiPaths";
import type { Admin, Realm } from "../types/api";
import { createAdminsApi } from "../services/adminsApi";

/** Realms with at least one admin of their own; realm `_` is excluded, it belongs to the super admins. */
function claimedRealmIds(admins: Admin[]): string[] {
    const ids = new Set(admins.flatMap((admin) => admin.realms));
    ids.delete(SUPER_ADMIN_REALM_ID);
    return [...ids];
}

export interface RealmPermissions {
    canManageRealm: (realmId: string) => boolean;
    loadClaimedRealms: (superAdmin: boolean) => Promise<void>;
    clearClaimedRealms: () => void;
}

/** Which realms the server lets the logged-in admin change, mirroring `can_manage_realm` on the server. */
export function useRealmPermissions(
    serverUrl: string,
    mountedRef: RefObject<boolean>,
    isSuperAdmin: boolean,
    realms: Realm[],
): RealmPermissions {
    const [claimedRealms, setClaimedRealms] = useState<string[]>([]);

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
        [serverUrl, mountedRef],
    );

    const clearClaimedRealms = useCallback(() => setClaimedRealms([]), []);

    return { canManageRealm, loadClaimedRealms, clearClaimedRealms };
}
