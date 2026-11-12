import { render, screen, act, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router";
import AdminsPage from "../../../src/pages/AdminsPage";
import type { Admin } from "../../../src/types/api";

const admin = (id: string, login: Partial<Admin>): Admin => ({
    id,
    realms: ["my-service"],
    userpass: null,
    jwt: null,
    fido2: null,
    digital_credentials: null,
    client_certificate: null,
    totp_enabled: false,
    ...login,
});

vi.mock("../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({ isAuthenticated: true, username: "admin", serverUrl: "", loading: false }),
}));

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: () => ({
        realms: [{ id: "_", label: "Super-Admin" }],
        selectedRealm: "_",
        realmLabel: (id: string) => id,
        isSuperAdmin: true,
    }),
}));

describe("AdminsPage", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it("offers 2FA only to admins with a username/password login", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValue(
            new Response(JSON.stringify([admin("alice", { userpass: "alice" }), admin("oidc-bob", { jwt: "bob-subject" })]), {
                status: 200,
                headers: { "Content-Type": "application/json" },
            }),
        );

        await act(async () => {
            render(
                <MemoryRouter>
                    <AdminsPage />
                </MemoryRouter>,
            );
        });

        await screen.findByText("bob-subject");
        const row = (text: string) => screen.getAllByRole("row").find((r) => r.textContent?.includes(text)) as HTMLElement;
        expect(within(row("alice")).getByRole("button", { name: /TOTP/ })).toBeInTheDocument();
        expect(within(row("bob-subject")).queryByRole("button", { name: /TOTP/ })).not.toBeInTheDocument();
    });
});
