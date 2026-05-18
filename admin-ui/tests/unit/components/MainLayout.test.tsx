import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { MainLayout } from "../../../src/components/layout/MainLayout";

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

vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify("0.1.0"), { status: 200 }));

describe("MainLayout", () => {
    it("should render header, sidebar, and footer", async () => {
        await act(async () => {
            render(
                <MemoryRouter initialEntries={["/"]}>
                    <MainLayout isDarkMode={false} setIsDarkMode={() => {}} />
                </MemoryRouter>,
            );
        });

        expect(screen.getByText("Auth Admin")).toBeInTheDocument();
        expect(screen.getByText("Dashboard")).toBeInTheDocument();
        expect(screen.getByText(/Auth Server/)).toBeInTheDocument();
    });

    it("should render content outlet area", async () => {
        await act(async () => {
            render(
                <MemoryRouter initialEntries={["/"]}>
                    <MainLayout isDarkMode={false} setIsDarkMode={() => {}} />
                </MemoryRouter>,
            );
        });

        expect(document.getElementById("main-content")).toBeInTheDocument();
    });
});
