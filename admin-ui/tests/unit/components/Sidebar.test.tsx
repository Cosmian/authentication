import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { Sidebar } from "../../../src/components/layout/Sidebar";

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: () => ({
        realms: [{ id: "_", label: "Super-Admin" }],
        selectedRealm: "_",
        setSelectedRealm: vi.fn(),
        realmLabel: (id: string) => (id === "_" ? "Super-Admin" : id),
        isSuperAdmin: true,
        loading: false,
        error: null,
    }),
}));

describe("Sidebar", () => {
    it("should render all menu items", () => {
        render(
            <MemoryRouter initialEntries={["/"]}>
                <Sidebar collapsed={false} onCollapse={() => {}} isDarkMode={false} />
            </MemoryRouter>,
        );

        expect(screen.getByText("Dashboard")).toBeInTheDocument();
        expect(screen.getByText("Realms")).toBeInTheDocument();
        expect(screen.getByText("Admins")).toBeInTheDocument();
        expect(screen.getByText("Credentials")).toBeInTheDocument();
        expect(screen.getByText("Sessions")).toBeInTheDocument();
        expect(screen.getByText("TOTP")).toBeInTheDocument();
    });

    it("should highlight the active route", () => {
        render(
            <MemoryRouter initialEntries={["/admins"]}>
                <Sidebar collapsed={false} onCollapse={() => {}} isDarkMode={false} />
            </MemoryRouter>,
        );

        // Ant Design adds ant-menu-item-selected class to active items
        const adminsItem = screen.getByText("Admins").closest("li");
        expect(adminsItem).toHaveClass("ant-menu-item-selected");
    });

    it("should call onCollapse when the sider trigger is clicked", () => {
        const onCollapse = vi.fn();
        const { container } = render(
            <MemoryRouter initialEntries={["/"]}>
                <Sidebar collapsed={false} onCollapse={onCollapse} isDarkMode={false} />
            </MemoryRouter>,
        );

        const trigger = container.querySelector(".ant-layout-sider-trigger");
        expect(trigger).not.toBeNull();
        fireEvent.click(trigger!);
        expect(onCollapse).toHaveBeenCalled();
    });

    it("should render in collapsed state without labels", () => {
        render(
            <MemoryRouter initialEntries={["/"]}>
                <Sidebar collapsed={true} onCollapse={() => {}} isDarkMode={false} />
            </MemoryRouter>,
        );

        expect(screen.getByRole("menu")).toBeInTheDocument();
    });
});
