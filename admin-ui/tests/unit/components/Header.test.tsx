import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Header } from "../../../src/components/layout/Header";

import { useRealm } from "../../../src/contexts/RealmContext";

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: vi.fn(() => ({
        realms: [
            { id: "_", label: "Admin" },
            { id: "my-service", label: "my-service" },
        ],
        selectedRealm: "_",
        setSelectedRealm: vi.fn(),
        realmLabel: (id: string) => (id === "_" ? "Admin" : id),
        loading: false,
        error: null,
    })),
}));

describe("Header", () => {
    it("should render the application title", () => {
        render(<Header isDarkMode={false} setIsDarkMode={() => {}} />);
        expect(screen.getByText("Auth Admin")).toBeInTheDocument();
    });

    it("should render the realm selector with Admin as default", () => {
        render(<Header isDarkMode={false} setIsDarkMode={() => {}} />);
        expect(screen.getByText("Admin")).toBeInTheDocument();
    });

    it("should render the dark mode toggle", () => {
        render(<Header isDarkMode={false} setIsDarkMode={() => {}} />);
        const toggle = screen.getByRole("switch");
        expect(toggle).toBeInTheDocument();
        expect(toggle).toHaveClass("w-20");
    });

    it("should pass the loading prop to the realm selector when realms are loading", () => {
        vi.mocked(useRealm).mockReturnValueOnce({
            realms: [],
            selectedRealm: "_",
            setSelectedRealm: vi.fn(),
            realmLabel: () => "Admin",
            loading: true,
            error: null,
        });
        const { container } = render(<Header isDarkMode={false} setIsDarkMode={() => {}} />);
        // Ant Design Select sets aria-busy="true" on the combobox when loading
        const combobox = container.querySelector(".ant-select-selector");
        expect(combobox).not.toBeNull();
        // The Select should be present; when loading=true Ant Design shows a spinner
        const loadingSpinner = container.querySelector(".ant-select-arrow .anticon-loading");
        expect(loadingSpinner).not.toBeNull();
    });
});
