import { render, screen, act, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import CredentialsPage from "../../../src/pages/CredentialsPage";
import { useRealm } from "../../../src/contexts/RealmContext";
import type { UserPass } from "../../../src/types/api";

// ── Context mocks ─────────────────────────────────────────────────────────────

vi.mock("../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({
        isAuthenticated: true,
        username: "admin",
        serverUrl: "https://auth.example.com",
        loading: false,
        sessionId: null,
        exp: null,
        login: vi.fn(),
        logout: vi.fn(),
    }),
}));

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: vi.fn(),
}));

// ── API mock ──────────────────────────────────────────────────────────────────
// We mock the module so we can observe how many times `list` is called.

const mockList = vi.fn<(realmId: string) => Promise<UserPass[]>>();

vi.mock("../../../src/services/credentialsApi", () => ({
    createCredentialsApi: () => ({
        list: mockList,
        get: vi.fn(),
        create: vi.fn(),
        update: vi.fn(),
        delete: vi.fn(),
    }),
}));

// ── Fixtures ──────────────────────────────────────────────────────────────────

const superAdminRealm = {
    id: "_",
    auth_params: { username_password_params: null, jwt_params: null, totp_params: null },
    session_max_age_seconds: 0,
    session_max_stale_age_seconds: 0,
};

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

const anotherRealm = {
    id: "internal-app",
    auth_params: {
        username_password_params: { allow_expired_passwords: false },
        jwt_params: null,
        totp_params: null,
    },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
};

const mockCredentials: UserPass[] = [
    { realm: "my-service", username: "alice", password: [], change_password: false },
    { realm: "my-service", username: "bob", password: [], change_password: true },
];

const defaultRealmContext = {
    realms: [superAdminRealm, concreteRealm, anotherRealm],
    selectedRealm: "my-service",
    setSelectedRealm: vi.fn(),
    realmLabel: (id: string) => (id === "_" ? "Super-Admin" : id),
    isSuperAdmin: false,
    isGlobalAdmin: false,
    loading: false,
    error: null,
    refreshRealms: vi.fn(),
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("CredentialsPage", () => {
    beforeEach(() => {
        mockList.mockReset();
        vi.mocked(useRealm).mockReturnValue({ ...defaultRealmContext });
    });

    // ── Regression: no infinite loop ─────────────────────────────────────────

    it("calls list exactly once on mount (no infinite loop)", async () => {
        mockList.mockResolvedValue(mockCredentials);

        await act(async () => {
            render(
                <MemoryRouter>
                    <CredentialsPage />
                </MemoryRouter>,
            );
        });

        // Wait for any pending re-renders to settle
        await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());

        // Allow a few extra ticks to surface any loop
        await act(async () => {
            await new Promise((r) => setTimeout(r, 50));
        });

        expect(mockList).toHaveBeenCalledTimes(1);
    });

    it("calls list exactly once more when selectedRealm changes (no extra loops)", async () => {
        mockList.mockResolvedValue(mockCredentials);

        const ctx = { ...defaultRealmContext };
        vi.mocked(useRealm).mockReturnValue(ctx);

        const { rerender } = render(
            <MemoryRouter>
                <CredentialsPage />
            </MemoryRouter>,
        );

        await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());

        // Switch realm
        vi.mocked(useRealm).mockReturnValue({ ...ctx, selectedRealm: "internal-app" });
        mockList.mockResolvedValue([]);

        await act(async () => {
            rerender(
                <MemoryRouter>
                    <CredentialsPage />
                </MemoryRouter>,
            );
        });

        // Allow time to settle
        await act(async () => {
            await new Promise((r) => setTimeout(r, 50));
        });

        expect(mockList).toHaveBeenCalledTimes(2);
    });

    // ── Normal rendering ──────────────────────────────────────────────────────

    it("shows loading state initially", async () => {
        mockList.mockReturnValue(new Promise(() => {})); // never resolves

        await act(async () => {
            render(
                <MemoryRouter>
                    <CredentialsPage />
                </MemoryRouter>,
            );
        });

        expect(screen.getByText("Loading credentials...")).toBeInTheDocument();
    });

    it("renders credentials in a table", async () => {
        mockList.mockResolvedValue(mockCredentials);

        await act(async () => {
            render(
                <MemoryRouter>
                    <CredentialsPage />
                </MemoryRouter>,
            );
        });

        await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());
        expect(screen.getByText("bob")).toBeInTheDocument();
        expect(screen.getByText("Pending change")).toBeInTheDocument();
    });

    it("shows empty state when no credentials", async () => {
        mockList.mockResolvedValue([]);

        await act(async () => {
            render(
                <MemoryRouter>
                    <CredentialsPage />
                </MemoryRouter>,
            );
        });

        await waitFor(() => expect(screen.getByText("No credentials in this realm")).toBeInTheDocument());
    });

    it("shows error alert on fetch failure", async () => {
        mockList.mockRejectedValue(new Error("Network error"));

        await act(async () => {
            render(
                <MemoryRouter>
                    <CredentialsPage />
                </MemoryRouter>,
            );
        });

        await waitFor(() => expect(screen.getByText("Failed to load credentials")).toBeInTheDocument());
    });

    // ── Super-admin view ──────────────────────────────────────────────────────

    it("shows Collapse with one panel per concrete realm in super-admin view", async () => {
        mockList.mockResolvedValue(mockCredentials);
        vi.mocked(useRealm).mockReturnValue({
            ...defaultRealmContext,
            selectedRealm: "_",
            isSuperAdmin: true,
            isGlobalAdmin: true,
        });

        await act(async () => {
            render(
                <MemoryRouter>
                    <CredentialsPage />
                </MemoryRouter>,
            );
        });

        // Both concrete realm labels should appear as Collapse panel headers
        await waitFor(() => expect(screen.getByText("my-service")).toBeInTheDocument());
        expect(screen.getByText("internal-app")).toBeInTheDocument();
        // The super-admin realm itself should not appear as a panel
        expect(screen.queryByText("_")).not.toBeInTheDocument();
    });
});
