import { render, screen, act, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { RealmFormDrawer } from "../../../../src/components/realms/RealmFormDrawer";
import type { Realm } from "../../../../src/types/api";

vi.mock("../../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({ isAuthenticated: true, username: "admin", serverUrl: "", loading: false, sessionId: null, exp: null, login: vi.fn(), logout: vi.fn() }),
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

    it("should call onClose when the drawer close icon is clicked", async () => {
        const onClose = vi.fn();
        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={null} onClose={onClose} onSuccess={vi.fn()} />,
            );
        });

        // The Cancel button was removed; drawer is closed via the Ant Design close icon.
        fireEvent.click(screen.getByRole("button", { name: "Close" }));
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

        // Fill required field — this triggers form validation and enables the submit button.
        const idInput = screen.getByLabelText("Realm ID");
        fireEvent.change(idInput, { target: { value: "new-realm" } });

        // Wait for canSubmit to become true (async validateFields resolves).
        const createBtn = screen.getAllByRole("button", { name: "Create" });
        const submitBtn = createBtn[createBtn.length - 1];
        await waitFor(() => expect(submitBtn).not.toBeDisabled());

        fireEvent.click(submitBtn);

        await waitFor(() => expect(onSuccess).toHaveBeenCalled());
    });

    it("should not render when open is false", () => {
        render(
            <RealmFormDrawer open={false} realm={null} onClose={vi.fn()} onSuccess={vi.fn()} />,
        );

        expect(screen.queryByText("Create Realm")).not.toBeInTheDocument();
    });

    it("should disable the submit button when Realm ID is empty", async () => {
        const onSuccess = vi.fn();
        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={null} onClose={vi.fn()} onSuccess={onSuccess} />,
            );
        });

        // Button starts disabled when the required Realm ID field is empty.
        const createBtn = screen.getAllByRole("button", { name: "Create" });
        const submitBtn = createBtn[createBtn.length - 1];
        await waitFor(() => expect(submitBtn).toBeDisabled());
        expect(onSuccess).not.toHaveBeenCalled();
    });

    it("should not call onSuccess when the API returns an error", async () => {
        const onSuccess = vi.fn();
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify({ message: "Internal Server Error" }), { status: 500 }),
        );

        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={null} onClose={vi.fn()} onSuccess={onSuccess} />,
            );
        });

        // Fill required field.
        const idInput = screen.getByLabelText("Realm ID");
        fireEvent.change(idInput, { target: { value: "new-realm" } });

        // Wait for the submit button to be enabled.
        const createBtn = screen.getAllByRole("button", { name: "Create" });
        const submitBtn = createBtn[createBtn.length - 1];
        await waitFor(() => expect(submitBtn).not.toBeDisabled());

        // Submit.
        await act(async () => {
            fireEvent.click(submitBtn);
        });

        // Wait for the fetch to be called (form submitted and API was hit).
        await waitFor(() => expect(fetchSpy).toHaveBeenCalled());

        // The API failed, so onSuccess must NOT have been called.
        expect(onSuccess).not.toHaveBeenCalled();
    });

    it("should call API with PUT and invoke onSuccess in edit mode", async () => {
        const onSuccess = vi.fn();
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify(existingRealm), { status: 200 }),
        );

        await act(async () => {
            render(
                <RealmFormDrawer
                    open={true}
                    realm={existingRealm}
                    onClose={vi.fn()}
                    onSuccess={onSuccess}
                />,
            );
        });

        // Trigger a change so the form becomes dirty and Save is enabled.
        const sessionInput = screen.getByLabelText("Session Max Age (seconds)");
        await act(async () => {
            fireEvent.change(sessionInput, { target: { value: "7200" } });
        });

        const saveBtn = screen.getAllByRole("button", { name: "Save" });
        const submitBtn = saveBtn[saveBtn.length - 1];
        await waitFor(() => expect(submitBtn).not.toBeDisabled());

        await act(async () => {
            fireEvent.click(submitBtn);
        });

        await waitFor(() => expect(onSuccess).toHaveBeenCalled());

        // The request must have used the PUT method.
        expect(fetchSpy).toHaveBeenCalledWith(
            expect.stringContaining(existingRealm.id),
            expect.objectContaining({ method: "PUT" }),
        );
    });

    it("edit mode: button is disabled initially (form matches original)", async () => {
        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={existingRealm} onClose={vi.fn()} onSuccess={vi.fn()} />,
            );
        });

        const saveBtn = screen.getAllByRole("button", { name: "Save" });
        const submitBtn = saveBtn[saveBtn.length - 1];
        // Nothing has been changed — button must be disabled
        await waitFor(() => expect(submitBtn).toBeDisabled());
    });

    it("edit mode: button is enabled after changing a field", async () => {
        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={existingRealm} onClose={vi.fn()} onSuccess={vi.fn()} />,
            );
        });

        // Change the session lifetime field
        await act(async () => {
            fireEvent.change(screen.getByLabelText("Session Max Age (seconds)"), {
                target: { value: "7200" },
            });
        });

        const saveBtn = screen.getAllByRole("button", { name: "Save" });
        const submitBtn = saveBtn[saveBtn.length - 1];
        await waitFor(() => expect(submitBtn).not.toBeDisabled());
    });

    it("edit mode: button is disabled again after reverting change", async () => {
        await act(async () => {
            render(
                <RealmFormDrawer open={true} realm={existingRealm} onClose={vi.fn()} onSuccess={vi.fn()} />,
            );
        });

        const sessionInput = screen.getByLabelText("Session Max Age (seconds)");

        // Change
        await act(async () => {
            fireEvent.change(sessionInput, { target: { value: "7200" } });
        });
        const saveBtn = screen.getAllByRole("button", { name: "Save" });
        const submitBtn = saveBtn[saveBtn.length - 1];
        await waitFor(() => expect(submitBtn).not.toBeDisabled());

        // Revert to original
        await act(async () => {
            fireEvent.change(sessionInput, {
                target: { value: String(existingRealm.session_max_age_seconds) },
            });
        });
        await waitFor(() => expect(submitBtn).toBeDisabled());
    });
});
