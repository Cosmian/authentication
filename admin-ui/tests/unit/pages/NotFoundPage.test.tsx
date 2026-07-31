import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { MemoryRouter } from "react-router";
import NotFoundPage from "../../../src/pages/NotFoundPage";

describe("NotFoundPage", () => {
    it("should render 404 content", () => {
        render(
            <MemoryRouter>
                <NotFoundPage />
            </MemoryRouter>,
        );
        expect(screen.getByText("404")).toBeInTheDocument();
    });

    it("should have a link back to the dashboard", () => {
        render(
            <MemoryRouter>
                <NotFoundPage />
            </MemoryRouter>,
        );
        const link = screen.getByRole("link", { name: /dashboard/i });
        expect(link).toBeInTheDocument();
        expect(link).toHaveAttribute("href", "/");
    });
});
