import { render, screen, act, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router";
import RealmsPage from "../../../src/pages/RealmsPage";
import type { Realm } from "../../../src/types/api";
import { IDP_CERT_PEM } from "../fixtures/saml";

const mockRealms: Realm[] = [
    {
        id: "_",
        auth_params: { username_password_params: { allow_expired_passwords: false }, jwt_params: null, totp_params: null },
        session_max_age_seconds: 86400,
        session_max_stale_age_seconds: 3600,
    },
    {
        id: "my-service",
        auth_params: {
            username_password_params: { allow_expired_passwords: false },
            jwt_params: {
                idp_params: [{ jwks_url: "https://example.com/jwks", jwt_audience: null }],
                smallest_refresh_interval_seconds: 300,
            },
            totp_params: { algorithm: "SHA1", step: 30 },
        },
        session_max_age_seconds: 3600,
        session_max_stale_age_seconds: 1800,
    },
];

// Mock contexts
vi.mock("../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({
        isAuthenticated: true,
        username: "admin",
        serverUrl: "",
        loading: false,
        sessionId: null,
        exp: null,
        login: vi.fn(),
        logout: vi.fn(),
    }),
}));

const mockRealmContext = {
    realms: [{ id: "_", label: "Super-Admin" }],
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
    useRealm: () => mockRealmContext,
}));

const renderPage = async () => {
    await act(async () => {
        render(
            <MemoryRouter>
                <RealmsPage />
            </MemoryRouter>,
        );
    });
};

const cardOf = (realmId: string) => screen.getByText(realmId).closest(".ant-card") as HTMLElement;

describe("RealmsPage", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
        mockRealmContext.isSuperAdmin = true;
        mockRealmContext.canManageRealm = () => true;
    });

    it("should show loading state initially", async () => {
        // Never-resolving fetch to keep loading
        vi.spyOn(globalThis, "fetch").mockReturnValue(new Promise(() => {}));

        await act(async () => {
            render(
                <MemoryRouter>
                    <RealmsPage />
                </MemoryRouter>,
            );
        });

        expect(screen.getByText("Loading realms...")).toBeInTheDocument();
    });

    it("should display realms in a table", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify(mockRealms), { status: 200 }));

        await act(async () => {
            render(
                <MemoryRouter>
                    <RealmsPage />
                </MemoryRouter>,
            );
        });

        expect(screen.getByText("my-service")).toBeInTheDocument();
        // Both realms have Password tags; verify at least one exists
        expect(screen.getAllByText("Password").length).toBeGreaterThan(0);
        expect(screen.getByText("JWT")).toBeInTheDocument();
        expect(screen.getByText("TOTP")).toBeInTheDocument();
    });

    it("should tag SAML realms and flag an IdP certificate close to expiry", async () => {
        const samlRealm: Realm = {
            id: "acme",
            auth_params: {
                username_password_params: null,
                jwt_params: null,
                totp_params: null,
                saml_params: {
                    idp_entity_id: "https://idp.example.com/metadata",
                    idp_sso_url: "https://idp.example.com/sso",
                    idp_signing_certificates: [IDP_CERT_PEM],
                    sp_entity_id: "https://auth.example.com/saml/acme",
                    sp_acs_url: "https://auth.example.com/saml/acme/acs",
                    normalize_subject_case: false,
                    attribute_claim_map: {},
                    allowed_return_origins: ["https://app.example.com"],
                    default_return_url: "https://app.example.com/home",
                },
            },
            session_max_age_seconds: 3600,
            session_max_stale_age_seconds: 1800,
        };
        vi.useFakeTimers({ toFake: ["Date"], now: new Date("2027-04-01T00:00:00Z") });
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify([samlRealm]), { status: 200 }));

        try {
            await act(async () => {
                render(
                    <MemoryRouter>
                        <RealmsPage />
                    </MemoryRouter>,
                );
            });

            expect(screen.getByText("SAML")).toBeInTheDocument();
            expect(screen.getByText(/Expires in 11 days/)).toBeInTheDocument();
        } finally {
            vi.useRealTimers();
        }
    });

    it("should show empty state when no realms exist", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }));

        await act(async () => {
            render(
                <MemoryRouter>
                    <RealmsPage />
                </MemoryRouter>,
            );
        });

        expect(screen.getByText("No realms configured")).toBeInTheDocument();
    });

    it("should show error alert on fetch failure", async () => {
        vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("Network error"));

        await act(async () => {
            render(
                <MemoryRouter>
                    <RealmsPage />
                </MemoryRouter>,
            );
        });

        expect(screen.getByText("Failed to load realms")).toBeInTheDocument();
    });

    it("should let a realm admin open the page, edit its realm and not create realms", async () => {
        mockRealmContext.isSuperAdmin = false;
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify([mockRealms[1]]), { status: 200 }));

        await renderPage();

        expect(screen.queryByText("Access Denied")).not.toBeInTheDocument();
        expect(within(cardOf("my-service")).getByRole("button", { name: /Edit/ })).toBeEnabled();
        expect(within(cardOf("my-service")).getByRole("button", { name: /Delete/ })).toBeEnabled();
        expect(screen.queryByText("Create Realm")).not.toBeInTheDocument();
        expect(screen.queryByText("New Realm")).not.toBeInTheDocument();
        expect(screen.queryByText("Claimed")).not.toBeInTheDocument();
    });

    it("should show a realm admin without realms an empty state with no create action", async () => {
        mockRealmContext.isSuperAdmin = false;
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }));

        await renderPage();

        expect(screen.getByText("You don't administer any realm")).toBeInTheDocument();
        expect(screen.queryByText("Create Realm")).not.toBeInTheDocument();
    });

    it("should mark a claimed realm for the super admin: Edit disabled, Delete still available", async () => {
        mockRealmContext.canManageRealm = (realmId) => realmId !== "my-service";
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify(mockRealms), { status: 200 }));

        await renderPage();

        const claimed = within(cardOf("my-service"));
        expect(claimed.getByText("Claimed")).toBeInTheDocument();
        expect(claimed.getByRole("button", { name: /Edit/ })).toBeDisabled();
        expect(claimed.getByRole("button", { name: /Delete/ })).toBeEnabled();
        expect(screen.getAllByText("Claimed")).toHaveLength(1);
    });

    it("should warn before the super admin deletes a claimed realm", async () => {
        mockRealmContext.canManageRealm = (realmId) => realmId !== "my-service";
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify(mockRealms), { status: 200 }));

        await renderPage();
        await act(async () =>
            within(cardOf("my-service"))
                .getByRole("button", { name: /Delete/ })
                .click(),
        );

        expect(screen.getByText(/Its admins are left without a realm/)).toBeInTheDocument();
    });

    it("should not warn when the super admin deletes a realm without admins", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify(mockRealms), { status: 200 }));

        await renderPage();
        await act(async () =>
            within(cardOf("my-service"))
                .getByRole("button", { name: /Delete/ })
                .click(),
        );

        expect(screen.getByText(/Delete "my-service"/)).toBeInTheDocument();
        expect(screen.queryByText(/Its admins are left without a realm/)).not.toBeInTheDocument();
    });

    it("should warn a realm admin before it deletes its own realm", async () => {
        mockRealmContext.isSuperAdmin = false;
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify([mockRealms[1]]), { status: 200 }));

        await renderPage();
        await act(async () =>
            within(cardOf("my-service"))
                .getByRole("button", { name: /Delete/ })
                .click(),
        );

        expect(screen.getByText(/Its admins are left without a realm/)).toBeInTheDocument();
    });

    it("should show Create Realm button", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify(mockRealms), { status: 200 }));

        await act(async () => {
            render(
                <MemoryRouter>
                    <RealmsPage />
                </MemoryRouter>,
            );
        });

        expect(screen.getByText("Create Realm")).toBeInTheDocument();
    });

    it("should show auth method tags for each realm", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify(mockRealms), { status: 200 }));

        await act(async () => {
            render(
                <MemoryRouter>
                    <RealmsPage />
                </MemoryRouter>,
            );
        });

        // The my-service realm has all three auth methods shown as tags in its card
        const card = screen.getByText("my-service").closest(".ant-card") as HTMLElement;
        expect(within(card).getByText("Password")).toBeInTheDocument();
        expect(within(card).getByText("JWT")).toBeInTheDocument();
        expect(within(card).getByText("TOTP")).toBeInTheDocument();
    });
});
