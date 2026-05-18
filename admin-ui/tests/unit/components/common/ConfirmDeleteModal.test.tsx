import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { ConfirmDeleteModal } from "../../../../src/components/common/ConfirmDeleteModal";

describe("ConfirmDeleteModal", () => {
    it("should render the item name in the title", () => {
        render(<ConfirmDeleteModal open={true} itemName="my-realm" onConfirm={vi.fn()} onCancel={vi.fn()} />);
        expect(screen.getByText(/Delete "my-realm"/)).toBeInTheDocument();
    });

    it("should disable confirm button until name is typed", () => {
        render(<ConfirmDeleteModal open={true} itemName="my-realm" onConfirm={vi.fn()} onCancel={vi.fn()} />);
        const okButton = screen.getByRole("button", { name: "Delete" });
        expect(okButton).toBeDisabled();
    });

    it("should enable confirm button when name matches", () => {
        render(<ConfirmDeleteModal open={true} itemName="my-realm" onConfirm={vi.fn()} onCancel={vi.fn()} />);
        const input = screen.getByPlaceholderText("my-realm");
        fireEvent.change(input, { target: { value: "my-realm" } });
        const okButton = screen.getByRole("button", { name: "Delete" });
        expect(okButton).not.toBeDisabled();
    });

    it("should call onCancel when cancel button is clicked", () => {
        const onCancel = vi.fn();
        render(<ConfirmDeleteModal open={true} itemName="my-realm" onConfirm={vi.fn()} onCancel={onCancel} />);
        fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
        expect(onCancel).toHaveBeenCalled();
    });

    it("should not render when open is false", () => {
        render(<ConfirmDeleteModal open={false} itemName="my-realm" onConfirm={vi.fn()} onCancel={vi.fn()} />);
        expect(screen.queryByText(/Delete "my-realm"/)).not.toBeInTheDocument();
    });
});
