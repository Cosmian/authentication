import { render, screen, act, within } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router";
import RealmsPage from "../../../src/pages/RealmsPage";
import type { Realm } from "../../../src/types/api";

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
    isSuperAdmin: true,
    isGlobalAdmin: true,
    loading: false,
    error: null,
    refreshRealms: vi.fn(),
};

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: () => mockRealmContext,
}));

describe("RealmsPage", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
        mockRealmContext.isGlobalAdmin = true;
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

    it("should show access denied when not super admin", async () => {
        mockRealmContext.isGlobalAdmin = false;

        await act(async () => {
            render(
                <MemoryRouter>
                    <RealmsPage />
                </MemoryRouter>,
            );
        });

        expect(screen.getByText("Access Denied")).toBeInTheDocument();
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
