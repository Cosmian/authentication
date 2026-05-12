import { render, screen, act, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ResetPasswordModal } from "../../../../src/components/credentials/ResetPasswordModal";

describe("ResetPasswordModal — submit button state", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it("button is disabled initially (empty form)", async () => {
        await act(async () => {
            render(
                <ResetPasswordModal
                    open={true}
                    username="alice"
                    onCancel={vi.fn()}
                    onSubmit={vi.fn()}
                />,
            );
        });

        const btn = screen.getByRole("button", { name: "Reset Password" });
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("button is disabled when only the new password is filled", async () => {
        await act(async () => {
            render(
                <ResetPasswordModal
                    open={true}
                    username="alice"
                    onCancel={vi.fn()}
                    onSubmit={vi.fn()}
                />,
            );
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("New Password"), {
                target: { value: "newsecret" },
            });
        });

        const btn = screen.getByRole("button", { name: "Reset Password" });
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("button is disabled when passwords don't match", async () => {
        await act(async () => {
            render(
                <ResetPasswordModal
                    open={true}
                    username="alice"
                    onCancel={vi.fn()}
                    onSubmit={vi.fn()}
                />,
            );
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("New Password"), {
                target: { value: "newsecret" },
            });
            fireEvent.change(screen.getByLabelText("Confirm Password"), {
                target: { value: "different" },
            });
        });

        const btn = screen.getByRole("button", { name: "Reset Password" });
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("button is enabled when both passwords are filled and match", async () => {
        await act(async () => {
            render(
                <ResetPasswordModal
                    open={true}
                    username="alice"
                    onCancel={vi.fn()}
                    onSubmit={vi.fn()}
                />,
            );
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("New Password"), {
                target: { value: "newsecret" },
            });
            fireEvent.change(screen.getByLabelText("Confirm Password"), {
                target: { value: "newsecret" },
            });
        });

        const btn = screen.getByRole("button", { name: "Reset Password" });
        await waitFor(() => expect(btn).not.toBeDisabled());
    });
});
