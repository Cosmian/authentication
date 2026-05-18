import { render, screen, act, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { CreateCredentialModal } from "../../../../src/components/credentials/CreateCredentialModal";

describe("CreateCredentialModal — submit button state", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it("button is disabled initially (empty form)", async () => {
        await act(async () => {
            render(<CreateCredentialModal open={true} onCancel={vi.fn()} onSubmit={vi.fn()} />);
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("button is disabled when only username is filled", async () => {
        await act(async () => {
            render(<CreateCredentialModal open={true} onCancel={vi.fn()} onSubmit={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("button is disabled when password and confirm are missing", async () => {
        await act(async () => {
            render(<CreateCredentialModal open={true} onCancel={vi.fn()} onSubmit={vi.fn()} />);
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
            render(<CreateCredentialModal open={true} onCancel={vi.fn()} onSubmit={vi.fn()} />);
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
            render(<CreateCredentialModal open={true} onCancel={vi.fn()} onSubmit={vi.fn()} />);
        });

        await act(async () => {
            fireEvent.change(screen.getByLabelText("Username"), { target: { value: "alice" } });
            fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret" } });
            fireEvent.change(screen.getByLabelText("Confirm Password"), { target: { value: "secret" } });
        });

        const btn = screen.getByRole("button", { name: "Create" });
        await waitFor(() => expect(btn).not.toBeDisabled());
    });
});
