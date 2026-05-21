import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { Sidebar } from "../../../src/components/layout/Sidebar";

// Mutable context — individual tests override fields as needed.
const mockRealm = {
    realms: [
        {
            id: "_",
            auth_params: { username_password_params: null, jwt_params: null, totp_params: null },
            session_max_age_seconds: 0,
            session_max_stale_age_seconds: 0,
        },
    ],
    selectedRealm: "_",
    setSelectedRealm: vi.fn(),
    realmLabel: (id: string) => (id === "_" ? "Super-Admin" : id),
    isSuperAdmin: true,
    isGlobalAdmin: true,
    loading: false,
    error: null,
};

vi.mock("../../../src/contexts/useBranding", () => ({
    useBranding: vi.fn(() => ({
        title: "Auth Admin",
        logoAlt: "Auth Admin",
        logoLightUrl: "",
        logoDarkUrl: "",
        loginTitle: "Auth Admin",
        backgroundImageUrl: "",
    })),
}));

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: () => mockRealm,
}));

function renderSidebar(path = "/") {
    return render(
        <MemoryRouter initialEntries={[path]}>
            <Sidebar collapsed={false} onCollapse={() => {}} isDarkMode={false} />
        </MemoryRouter>,
    );
}

describe("Sidebar", () => {
    it("should render all menu items", () => {
        renderSidebar();

        expect(screen.getByText("Dashboard")).toBeInTheDocument();
        expect(screen.getByText("Realms")).toBeInTheDocument();
        expect(screen.getByText("Admins")).toBeInTheDocument();
        expect(screen.getByText("Credentials")).toBeInTheDocument();
        expect(screen.getByText("Sessions")).toBeInTheDocument();
    });

    it("should highlight the active route", () => {
        renderSidebar("/admins");

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

    it("super-admin with a specific realm selected still sees the Realms item", () => {
        // Simulate: global super-admin who switched to a concrete realm
        mockRealm.isSuperAdmin = false; // admin realm is NOT selected
        mockRealm.isGlobalAdmin = true; // but user IS a genuine super-admin
        mockRealm.selectedRealm = "realm-a";
        try {
            renderSidebar();
            expect(screen.getByText("Realms")).toBeInTheDocument();
        } finally {
            // restore defaults for subsequent tests
            mockRealm.isSuperAdmin = true;
            mockRealm.isGlobalAdmin = true;
            mockRealm.selectedRealm = "_";
        }
    });

    it("realm-admin does not see the Realms item", () => {
        mockRealm.isSuperAdmin = false;
        mockRealm.isGlobalAdmin = false;
        mockRealm.selectedRealm = "realm-a";
        try {
            renderSidebar();
            expect(screen.queryByText("Realms")).not.toBeInTheDocument();
        } finally {
            mockRealm.isSuperAdmin = true;
            mockRealm.isGlobalAdmin = true;
            mockRealm.selectedRealm = "_";
        }
    });
});
