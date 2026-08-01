import { act, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it, vi } from "vitest";
import { MainLayout } from "../../../src/components/layout/MainLayout";

vi.mock("../../../src/contexts/ThemeProvider", () => ({
    useTheme: vi.fn(() => ({
        isDarkMode: false,
        setIsDarkMode: vi.fn(),
        branding: {
            title: "Auth Admin",
            logoAlt: "Auth Admin",
            logoLightUrl: "",
            logoDarkUrl: "",
            loginTitle: "Auth Admin",
            backgroundImageUrl: "",
        },
        antTheme: {},
        superAdminBannerStyle: undefined,
    })),
}));

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

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: () => ({
        realms: [
            {
                id: "_",
                auth_params: { username_password_params: null, jwt_params: null, totp_params: null },
                session_max_age_seconds: 0,
                session_max_stale_age_seconds: 0,
            },
        ],
        selectedRealm: "_",
        setSelectedRealm: vi.fn(),
        realmLabel: (id: string) => (id === "_" ? "Admin" : id),
        isSuperAdmin: true,
        isGlobalAdmin: true,
        loading: false,
        error: null,
    }),
}));

vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify("0.2.1"), { status: 200 }));

describe("MainLayout", () => {
    it("should render header, sidebar, and footer", async () => {
        await act(async () => {
            render(
                <MemoryRouter initialEntries={["/"]}>
                    <MainLayout />
                </MemoryRouter>,
            );
        });

        expect(screen.getByText("Auth Admin")).toBeInTheDocument();
        expect(screen.getByText("Dashboard")).toBeInTheDocument();
        expect(screen.getByText(/Authentication Verifier/)).toBeInTheDocument();
    });

    it("should render content outlet area", async () => {
        await act(async () => {
            render(
                <MemoryRouter initialEntries={["/"]}>
                    <MainLayout />
                </MemoryRouter>,
            );
        });

        expect(document.getElementById("main-content")).toBeInTheDocument();
    });
});
