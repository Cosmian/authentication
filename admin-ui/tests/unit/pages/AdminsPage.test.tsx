import { render, screen, act, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router";
import AdminsPage from "../../../src/pages/AdminsPage";
import type { Admin, Realm } from "../../../src/types/api";

const makeAdmin = (id: string, realms: string[]): Admin => ({
    id,
    realms,
    userpass: `${id}-login`,
    jwt: null,
    fido2: null,
    digital_credentials: null,
    client_certificate: null,
    totp_enabled: false,
});

const makeRealm = (id: string): Realm => ({
    id,
    auth_params: { username_password_params: null, jwt_params: null, totp_params: null },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
});

const superAdmin = makeAdmin("admin", ["_"]);
const demoAdmin = makeAdmin("demo-admin", ["demo"]);
const demoColleague = makeAdmin("demo-colleague", ["demo"]);
const freeAdmin = makeAdmin("free-admin", ["free"]);
const unaffiliated = makeAdmin("nobody", []);

vi.mock("../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({ isAuthenticated: true, username: "admin", serverUrl: "", loading: false }),
}));

const mockRealm = {
    realms: [makeRealm("_"), makeRealm("demo"), makeRealm("free")],
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

const renderPage = async (admins: Admin[]) => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(admins), { status: 200 }));
    await act(async () => {
        render(
            <MemoryRouter>
                <AdminsPage />
            </MemoryRouter>,
        );
    });
    return fetchSpy;
};

const rowOf = (adminId: string) => within(screen.getByText(adminId).closest("tr") as HTMLElement);

/** A super admin: realm `_` and the unclaimed `free` are theirs, `demo` has its own admins. */
const asSuperAdmin = (selectedRealm: string) => {
    mockRealm.isSuperAdmin = true;
    mockRealm.isSuperAdminMode = selectedRealm === "_";
    mockRealm.selectedRealm = selectedRealm;
    mockRealm.canManageRealm = (realmId) => realmId !== "demo";
};

/** A realm admin of `demo`. */
const asRealmAdmin = () => {
    mockRealm.isSuperAdmin = false;
    mockRealm.isSuperAdminMode = false;
    mockRealm.selectedRealm = "demo";
    mockRealm.canManageRealm = (realmId) => realmId === "demo";
};

describe("AdminsPage", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
        mockRealm.loading = false;
        asSuperAdmin("_");
    });

    describe("Super-Admin view", () => {
        it("should list every admin and offer all actions on the ones it can change", async () => {
            await renderPage([superAdmin, freeAdmin, unaffiliated]);

            expect(screen.getByText("New Admin")).toBeInTheDocument();
            const free = rowOf("free-admin");
            for (const name of [/Edit/, /TOTP/, /Credential/, /Delete/]) {
                expect(free.getByRole("button", { name })).toBeInTheDocument();
            }
            expect(rowOf("nobody").getByRole("button", { name: /Edit/ })).toBeInTheDocument();
            // The super admin's own record cannot be deleted from the UI.
            expect(rowOf("admin").queryByRole("button", { name: /Delete/ })).not.toBeInTheDocument();
        });

        it("should show the admins of a claimed realm read-only, without any action", async () => {
            await renderPage([superAdmin, demoAdmin, freeAdmin]);

            const claimed = rowOf("demo-admin");
            expect(claimed.getByText("Read-only")).toBeInTheDocument();
            expect(claimed.queryByRole("button")).not.toBeInTheDocument();
            expect(rowOf("free-admin").queryByText("Read-only")).not.toBeInTheDocument();
        });

        it("should not offer actions on an admin that mixes a claimed and an unclaimed realm", async () => {
            await renderPage([makeAdmin("mixed", ["demo", "free"])]);

            expect(rowOf("mixed").getByText("Read-only")).toBeInTheDocument();
        });
    });

    describe("realm view", () => {
        it("should show a realm admin only the admins of the selected realm, with all actions and New Admin", async () => {
            asRealmAdmin();
            await renderPage([demoAdmin, demoColleague, freeAdmin]);

            expect(screen.getByText("demo-admin")).toBeInTheDocument();
            expect(screen.getByText("demo-colleague")).toBeInTheDocument();
            expect(screen.queryByText("free-admin")).not.toBeInTheDocument();
            expect(screen.getByText("New Admin")).toBeInTheDocument();
            for (const name of [/Edit/, /TOTP/, /Credential/, /Delete/]) {
                expect(rowOf("demo-colleague").getByRole("button", { name })).toBeInTheDocument();
            }
            expect(screen.queryByText("Read-only")).not.toBeInTheDocument();
        });

        it("should let a realm admin create the first admin of an empty list", async () => {
            asRealmAdmin();
            await renderPage([]);

            expect(screen.getByText("No admins found")).toBeInTheDocument();
            expect(screen.getAllByText("New Admin").length).toBeGreaterThan(0);
        });

        it("should show the super admin the admins of a claimed realm to contact, without New Admin or actions", async () => {
            asSuperAdmin("demo");
            await renderPage([superAdmin, demoAdmin, freeAdmin]);

            expect(screen.getByText("This realm has its own admins")).toBeInTheDocument();
            expect(screen.queryByText("New Admin")).not.toBeInTheDocument();
            expect(screen.queryByText("free-admin")).not.toBeInTheDocument();
            expect(rowOf("demo-admin").getByText("Read-only")).toBeInTheDocument();
        });

        it("should let the super admin create admins in an unclaimed realm", async () => {
            asSuperAdmin("free");
            await renderPage([freeAdmin]);

            expect(screen.getByText("New Admin")).toBeInTheDocument();
            expect(screen.queryByText("This realm has its own admins")).not.toBeInTheDocument();
        });
    });

    it("should refresh the claimed realms after deleting an admin, which can release its realm", async () => {
        asRealmAdmin();
        mockRealm.refreshRealms = vi.fn();
        const fetchSpy = await renderPage([demoAdmin, demoColleague]);
        fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

        await act(async () =>
            rowOf("demo-colleague")
                .getByRole("button", { name: /Delete/ })
                .click(),
        );
        await act(async () => screen.getAllByRole("button", { name: "Delete" }).at(-1)?.click());

        expect(fetchSpy).toHaveBeenCalledWith(
            expect.stringContaining("/admins/demo-colleague"),
            expect.objectContaining({ method: "DELETE" }),
        );
        expect(mockRealm.refreshRealms).toHaveBeenCalledTimes(1);
    });

    it("should show an error when the admins cannot be loaded", async () => {
        vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Network error"));
        await act(async () => {
            render(
                <MemoryRouter>
                    <AdminsPage />
                </MemoryRouter>,
            );
        });

        expect(screen.getByText("Failed to load admins")).toBeInTheDocument();
    });

    it("should wait for the realms before loading admins", async () => {
        mockRealm.loading = true;
        const fetchSpy = await renderPage([superAdmin]);

        expect(screen.getByText("Loading admins...")).toBeInTheDocument();
        expect(fetchSpy).not.toHaveBeenCalled();
    });
});
