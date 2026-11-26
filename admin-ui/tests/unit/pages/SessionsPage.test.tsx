import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router";
import SessionsPage from "../../../src/pages/SessionsPage";

vi.mock("../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({ isAuthenticated: true, username: "admin", serverUrl: "", loading: false }),
}));

const mockRealm = {
    realms: [],
    selectedRealm: "_",
    setSelectedRealm: vi.fn(),
    realmLabel: (id: string) => (id === "_" ? "Super-Admin" : id),
    isSuperAdminMode: true,
    isSuperAdmin: true,
    canManageRealm: (() => true) as (realmId: string) => boolean,
    loading: false,
    error: null,
    refreshRealms: vi.fn(),
};

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: () => mockRealm,
}));

const renderPage = async () => {
    await act(async () => {
        render(
            <MemoryRouter>
                <SessionsPage />
            </MemoryRouter>,
        );
    });
};

describe("SessionsPage", () => {
    beforeEach(() => {
        mockRealm.selectedRealm = "demo";
        mockRealm.isSuperAdminMode = false;
        mockRealm.canManageRealm = () => true;
    });

    it("offers to revoke all sessions of a realm the user manages", async () => {
        await renderPage();

        expect(screen.getByRole("button", { name: /Revoke All Sessions/ })).toBeInTheDocument();
        expect(screen.queryByText("This realm has its own admins")).not.toBeInTheDocument();
    });

    it("explains instead of offering revocation on a realm that has its own admins", async () => {
        mockRealm.canManageRealm = (realmId) => realmId !== "demo";

        await renderPage();

        expect(screen.getByText("This realm has its own admins")).toBeInTheDocument();
        expect(screen.queryByRole("button", { name: /Revoke All Sessions/ })).not.toBeInTheDocument();
    });

    it("asks the super admin to select a realm in the Super-Admin view, and offers the purge", async () => {
        mockRealm.selectedRealm = "_";
        mockRealm.isSuperAdminMode = true;

        await renderPage();

        expect(screen.getByText("Select a realm")).toBeInTheDocument();
        expect(screen.getByRole("button", { name: /Purge Expired Sessions/ })).toBeInTheDocument();
    });
});
