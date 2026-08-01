import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Footer } from "../../../src/components/layout/Footer";

describe("Footer", () => {
    it("should render the version string", () => {
        render(<Footer version="1.2.3" />);
        expect(screen.getByText(/1\.2\.3/)).toBeInTheDocument();
    });

    it("should render empty version gracefully", () => {
        render(<Footer version="" />);
        expect(screen.getByText(/Authentication Verifier/)).toBeInTheDocument();
    });
});
