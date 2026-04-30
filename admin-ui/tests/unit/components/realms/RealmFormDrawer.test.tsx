import { render, screen, act, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { RealmFormDrawer } from "../../../../src/components/realms/RealmFormDrawer";
import type { Realm } from "../../../../src/types/api";

vi.mock("../../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({ isAuthenticated: true, username: "admin", serverUrl: "", login: vi.fn(), logout: vi.fn() }),
}));

const existingRealm: Realm = {
    id: "test-realm",
    auth_params: {
        username_password_params: { allow_expired_passwords: false },
        jwt_params: null,
        totp_params: { algorithm: "SHA1", step: 30 },
    },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
};

describe("RealmFormDrawer", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it("should render create mode when realm is null", async () => {
        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={null} onClose={vi.fn()} onSuccess={vi.fn()} />,
            );
        });

        expect(screen.getByText("Create Realm")).toBeInTheDocument();
        expect(screen.getByLabelText("Realm ID")).not.toBeDisabled();
    });

    it("should render edit mode with realm data", async () => {
        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={existingRealm} onClose={vi.fn()} onSuccess={vi.fn()} />,
            );
        });

        expect(screen.getByText("Edit Realm: test-realm")).toBeInTheDocument();
        expect(screen.getByLabelText("Realm ID")).toBeDisabled();
    });

    it("should show auth method checkboxes", async () => {
        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={null} onClose={vi.fn()} onSuccess={vi.fn()} />,
            );
        });

        expect(screen.getByText("Username / Password")).toBeInTheDocument();
        expect(screen.getByText("JWT / OIDC")).toBeInTheDocument();
        expect(screen.getByText("TOTP (Two-Factor)")).toBeInTheDocument();
    });

    it("should call onClose when cancel is clicked", async () => {
        const onClose = vi.fn();
        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={null} onClose={onClose} onSuccess={vi.fn()} />,
            );
        });

        fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
        expect(onClose).toHaveBeenCalled();
    });

    it("should call API and onSuccess on valid create submission", async () => {
        const onSuccess = vi.fn();
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify({ id: "new-realm" }), { status: 201 }),
        );

        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={null} onClose={vi.fn()} onSuccess={onSuccess} />,
            );
        });

        // Fill required fields
        const idInput = screen.getByLabelText("Realm ID");
        fireEvent.change(idInput, { target: { value: "new-realm" } });

        // Submit
        const createBtn = screen.getAllByRole("button", { name: "Create" });
        fireEvent.click(createBtn[createBtn.length - 1]);

        await waitFor(() => expect(onSuccess).toHaveBeenCalled());
    });

    it("should not render when open is false", () => {
        render(
            <RealmFormDrawer open={false} realm={null} onClose={vi.fn()} onSuccess={vi.fn()} />,
        );

        expect(screen.queryByText("Create Realm")).not.toBeInTheDocument();
    });
});
