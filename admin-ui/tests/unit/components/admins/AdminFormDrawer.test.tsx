import { render, screen, act, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AdminFormDrawer } from "../../../../src/components/admins/AdminFormDrawer";
import type { Admin } from "../../../../src/types/api";

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

vi.mock("../../../../src/contexts/RealmContext", () => ({
    useRealm: () => ({
        realms: [
            {
                id: "realm-a",
                auth_params: { username_password_params: null, jwt_params: null, totp_params: null },
                session_max_age_seconds: 3600,
                session_max_stale_age_seconds: 1800,
            },
        ],
        selectedRealm: "realm-a",
        isSuperAdmin: false,
        isGlobalAdmin: false,
        realmLabel: (id: string) => id,
    }),
}));

const existingAdmin: Admin = {
    id: "alice",
    realms: ["realm-a"],
    userpass: "alice",
    jwt: null,
    fido2: null,
    digital_credentials: null,
    client_certificate: null,
    totp_enabled: false,
    totp_secret: null,
    totp_auth_url: null,
};

/** Find the primary footer submit button (last in the DOM). */
function getSubmitButton(name: string | RegExp) {
    const buttons = screen.getAllByRole("button", { name });
    return buttons[buttons.length - 1];
}

describe("AdminFormDrawer — submit button state", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    // ── Create mode ──────────────────────────────────────────────────────────

    it("create mode: button is disabled initially (no values)", async () => {
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={null} onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        const btn = getSubmitButton("Create");
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("create mode: button is still disabled when only Admin ID is filled (realm required)", async () => {
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={null} onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Admin ID"), { target: { value: "bob" } });
        });

        const btn = getSubmitButton("Create");
        // Realms is still empty → button must stay disabled
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("create mode: button is enabled after Admin ID + realm are filled", async () => {
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={null} onClose={vi.fn()} onSuccess={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Admin ID"), { target: { value: "bob" } });
        });

        // Open the Realms multi-select and click the only option
        await act(async () => {
            const combobox = screen.getByRole("combobox");
            fireEvent.mouseDown(combobox);
        });

        const option = await screen.findByTitle("realm-a");
        await act(async () => {
            fireEvent.click(option);
        });

        const btn = getSubmitButton("Create");
        await waitFor(() => expect(btn).not.toBeDisabled());
    });

    // ── Edit mode ─────────────────────────────────────────────────────────────

    it("edit mode: button is disabled initially (form matches original)", async () => {
        await act(async () => {
            render(
                <AdminFormDrawer open={true} admin={existingAdmin} onClose={vi.fn()} onSuccess={vi.fn()} />,
            );
        });

        const btn = getSubmitButton("Save");
        // Form is pre-filled with the admin's data — nothing has changed yet
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("edit mode: button is enabled after changing a field", async () => {
        await act(async () => {
            render(
                <AdminFormDrawer open={true} admin={existingAdmin} onClose={vi.fn()} onSuccess={vi.fn()} />,
            );
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Userpass"), {
                target: { value: "alice-changed" },
            });
        });

        const btn = getSubmitButton("Save");
        await waitFor(() => expect(btn).not.toBeDisabled());
    });

    it("edit mode: button is disabled again after reverting the change", async () => {
        await act(async () => {
            render(
                <AdminFormDrawer open={true} admin={existingAdmin} onClose={vi.fn()} onSuccess={vi.fn()} />,
            );
        });

        // Change
        await act(async () => {
            fireEvent.change(screen.getByLabelText("Userpass"), {
                target: { value: "alice-changed" },
            });
        });
        const btn = getSubmitButton("Save");
        await waitFor(() => expect(btn).not.toBeDisabled());

        // Revert to original value
        await act(async () => {
            fireEvent.change(screen.getByLabelText("Userpass"), {
                target: { value: existingAdmin.userpass },
            });
        });
        await waitFor(() => expect(btn).toBeDisabled());
    });
});
