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

const mockCreate = vi.fn().mockResolvedValue(undefined);
const mockUpdate = vi.fn().mockResolvedValue(undefined);

vi.mock("../../../../src/services/credentialsApi", () => ({
    createCredentialsApi: () => ({
        create: mockCreate,
        update: mockUpdate,
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

describe("CredentialModal — hashed password and extra claims", () => {
    beforeEach(() => {
        mockCreate.mockReset().mockResolvedValue(undefined);
        mockUpdate.mockReset().mockResolvedValue(undefined);
    });

    it("switching to 'Pre-hashed' hides Password/Confirm and shows the PHC field", async () => {
        await act(async () => {
            render(<CredentialModal open={true} credential={null} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.click(screen.getByRole("radio", { name: "Pre-hashed (Argon2)" }));
        });

        expect(screen.queryByLabelText("Password")).toBeNull();
        expect(screen.queryByLabelText("Confirm Password")).toBeNull();
        expect(screen.getByLabelText("Pre-hashed password (Argon2 PHC string)")).toBeDefined();
    });

    it("submit is disabled for a hashed_password that isn't a valid PHC string", async () => {
        await act(async () => {
            render(<CredentialModal open={true} credential={null} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Username"), { target: { value: "bob" } });
            fireEvent.click(screen.getByRole("radio", { name: "Pre-hashed (Argon2)" }));
            fireEvent.change(screen.getByLabelText("Pre-hashed password (Argon2 PHC string)"), {
                target: { value: "not-a-phc-string" },
            });
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("submits password: [] and hashed_password set when a valid PHC string is provided", async () => {
        await act(async () => {
            render(<CredentialModal open={true} credential={null} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        const phc = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";
        await act(async () => {
            fireEvent.change(screen.getByLabelText("Username"), { target: { value: "bob" } });
            fireEvent.click(screen.getByRole("radio", { name: "Pre-hashed (Argon2)" }));
            fireEvent.change(screen.getByLabelText("Pre-hashed password (Argon2 PHC string)"), {
                target: { value: phc },
            });
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).not.toBeDisabled());
        await act(async () => {
            fireEvent.click(btn);
        });

        await waitFor(() => expect(mockCreate).toHaveBeenCalledTimes(1));
        const [, submitted] = mockCreate.mock.calls[0] as [string, { password: number[]; hashed_password?: string }];
        expect(submitted.password).toEqual([]);
        expect(submitted.hashed_password).toBe(phc);
    });

    it("with no extra claims added, extra_claims is omitted from the submitted payload", async () => {
        await act(async () => {
            render(<CredentialModal open={true} credential={null} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Username"), { target: { value: "carol" } });
            fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
            fireEvent.change(screen.getByLabelText("Confirm Password"), { target: { value: "secret" } });
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).not.toBeDisabled());
        await act(async () => {
            fireEvent.click(btn);
        });

        await waitFor(() => expect(mockCreate).toHaveBeenCalledTimes(1));
        const [, submitted] = mockCreate.mock.calls[0] as [string, { extra_claims?: Record<string, string> }];
        expect(submitted.extra_claims).toBeUndefined();
    });

    it("adds a claim key/value pair and submits it in extra_claims", async () => {
        await act(async () => {
            render(<CredentialModal open={true} credential={null} realmId="realm1" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Username"), { target: { value: "dave" } });
            fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
            fireEvent.change(screen.getByLabelText("Confirm Password"), { target: { value: "secret" } });
            fireEvent.click(screen.getByRole("button", { name: /Add claim/ }));
        });

        await act(async () => {
            fireEvent.change(screen.getByPlaceholderText("claim name (e.g. as_registrant)"), {
                target: { value: "as_registrant" },
            });
            fireEvent.change(screen.getByPlaceholderText("value"), { target: { value: "acme-corp" } });
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).not.toBeDisabled());
        await act(async () => {
            fireEvent.click(btn);
        });

        await waitFor(() => expect(mockCreate).toHaveBeenCalledTimes(1));
        const [, submitted] = mockCreate.mock.calls[0] as [string, { extra_claims?: Record<string, string> }];
        expect(submitted.extra_claims).toEqual({ as_registrant: "acme-corp" });
    });
});
