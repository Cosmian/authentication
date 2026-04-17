import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import PlaceholderPage from "../../../src/pages/PlaceholderPage";

describe("PlaceholderPage", () => {
    it("should render the title prop", () => {
        render(<PlaceholderPage title="Users" />);
        expect(screen.getByText("Users")).toBeInTheDocument();
    });

    it("should display a 'coming soon' message", () => {
        render(<PlaceholderPage title="Sessions" />);
        expect(screen.getByText(/coming soon/i)).toBeInTheDocument();
    });

    it("should handle empty title gracefully", () => {
        render(<PlaceholderPage title="" />);
        expect(screen.getByText(/coming soon/i)).toBeInTheDocument();
    });
});
