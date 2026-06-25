import { render, screen, act, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { CredentialModal } from "../../../../src/components/credentials/CredentialModal";

vi.mock("../../../../src/contexts/AuthContext", () => ({
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

vi.mock("../../../../src/services/rolesApi", () => ({
    createRolesApi: () => ({
        list: vi.fn().mockResolvedValue([]),
    }),
}));

vi.mock("../../../../src/services/credentialsApi", () => ({
    createCredentialsApi: () => ({
        create: vi.fn(),
        update: vi.fn(),
    }),
}));

describe("CredentialModal — create mode submit button state", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it("button is disabled initially (empty form)", async () => {
        await act(async () => {
            render(<CredentialModal open={true} credential={null} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("button is disabled when only username is filled", async () => {
        await act(async () => {
            render(<CredentialModal open={true} credential={null} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("button is disabled when password and confirm are missing", async () => {
        await act(async () => {
            render(<CredentialModal open={true} credential={null} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
            fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("button is disabled when passwords don't match", async () => {
        await act(async () => {
            render(<CredentialModal open={true} credential={null} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
            fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
            fireEvent.change(screen.getByLabelText("Confirm Password"), {
                target: { value: "different" },
            });
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("button is enabled when all fields are valid (passwords match)", async () => {
        await act(async () => {
            render(<CredentialModal open={true} credential={null} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
            fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
            fireEvent.change(screen.getByLabelText("Confirm Password"), { target: { value: "secret" } });
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).not.toBeDisabled());
    });

    it("shows only roles field in edit mode", async () => {
        const credential = { realm: "realm1", username: "alice", password: [], change_password: false, roles: ["Admin"] };
        await act(async () => {
            render(<CredentialModal open={true} credential={credential} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        expect(screen.queryByLabelText("Username")).toBeNull();
        expect(screen.queryByLabelText("Password")).toBeNull();
        expect(screen.getByLabelText("Roles")).toBeDefined();
        expect(screen.getByRole("button", { name: "Save" })).toBeDefined();
    });
});
