import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import DashboardPage from "../../../src/pages/DashboardPage";
import { useRealm } from "../../../src/contexts/RealmContext";

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: vi.fn(),
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

const concreteRealm = {
    id: "my-service",
    auth_params: {
        username_password_params: { allow_expired_passwords: false },
        jwt_params: null,
        totp_params: null,
    },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
};

const superAdminRealm = {
    id: "_",
    auth_params: { username_password_params: null, jwt_params: null, totp_params: null },
    session_max_age_seconds: 0,
    session_max_stale_age_seconds: 0,
};

const defaultRealmContext = {
    realms: [superAdminRealm, concreteRealm],
    selectedRealm: "_",
    setSelectedRealm: vi.fn(),
    realmLabel: (id: string) => (id === "_" ? "Super-Admin" : id),
    isSuperAdmin: true,
    isGlobalAdmin: true,
    loading: false,
    error: null,
};

describe("DashboardPage", () => {
    beforeEach(() => {
        vi.mocked(useRealm).mockReturnValue(defaultRealmContext);
        vi.spyOn(globalThis, "fetch").mockResolvedValue(
            new Response(JSON.stringify({ version: "mock-0.1.0" }), { status: 200 }),
        );
    });

    it("should render the dashboard heading in established mode", () => {
        render(
            <MemoryRouter>
                <DashboardPage />
            </MemoryRouter>,
        );
        expect(screen.getByText("Dashboard")).toBeInTheDocument();
    });

    it("should render realm cards in established mode", () => {
        render(
            <MemoryRouter>
                <DashboardPage />
            </MemoryRouter>,
        );
        expect(screen.getByText("my-service")).toBeInTheDocument();
    });

    it("should show onboarding mode when no concrete realms exist", () => {
        vi.mocked(useRealm).mockReturnValue({
            ...defaultRealmContext,
            realms: [superAdminRealm],
        });
        render(
            <MemoryRouter>
                <DashboardPage />
            </MemoryRouter>,
        );
        expect(screen.getByText("Welcome")).toBeInTheDocument();
        expect(screen.getByText("Create a realm")).toBeInTheDocument();
    });

    it("should show error alert when realm context has an error", () => {
        vi.mocked(useRealm).mockReturnValue({
            ...defaultRealmContext,
            error: "Failed to load realms",
        });
        render(
            <MemoryRouter>
                <DashboardPage />
            </MemoryRouter>,
        );
        expect(screen.getByRole("alert")).toBeInTheDocument();
    });
});
