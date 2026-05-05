import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import DashboardPage from "../../../src/pages/DashboardPage";
import { useRealm } from "../../../src/contexts/RealmContext";

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: vi.fn(),
}));

const defaultRealmContext = {
    realms: [
        { id: "_", label: "Super-Admin" },
        { id: "my-service", label: "my-service" },
    ],
    selectedRealm: "_",
    setSelectedRealm: vi.fn(),
    realmLabel: (id: string) => (id === "_" ? "Super-Admin" : id),
    isSuperAdmin: true,
    loading: false,
    error: null,
};

describe("DashboardPage", () => {
    beforeEach(() => {
        vi.mocked(useRealm).mockReturnValue(defaultRealmContext);
    });

    it("should render the welcome heading", () => {
        render(
            <MemoryRouter>
                <DashboardPage />
            </MemoryRouter>,
        );
        expect(screen.getByText(/Dashboard/i)).toBeInTheDocument();
    });

    it("should render navigation cards for each section", () => {
        render(
            <MemoryRouter>
                <DashboardPage />
            </MemoryRouter>,
        );
        expect(screen.getByText("Admins")).toBeInTheDocument();
        expect(screen.getByText("Credentials")).toBeInTheDocument();
        expect(screen.getByText("Sessions")).toBeInTheDocument();
        expect(screen.getByText("TOTP")).toBeInTheDocument();
    });

    it("should display the currently selected realm", () => {
        render(
            <MemoryRouter>
                <DashboardPage />
            </MemoryRouter>,
        );
        expect(screen.getByText(/Super-Admin/)).toBeInTheDocument();
    });

    it("should show error alert when realm context has an error", () => {
        vi.mocked(useRealm).mockReturnValue({
            ...defaultRealmContext,
            error: "Failed to load realms",
        });
        render(
            <MemoryRouter>
                <DashboardPage />
            </MemoryRouter>,
        );
        expect(screen.getByRole("alert")).toBeInTheDocument();
    });
});
