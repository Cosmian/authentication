import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { MemoryRouter } from "react-router";
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
    isSuperAdminMode: true,
    isSuperAdmin: true,
    canManageRealm: (() => true) as (realmId: string) => boolean,
    loading: false,
    error: null,
};

vi.mock("../../../src/contexts/ThemeProvider", () => ({
    useTheme: vi.fn(() => ({
        isDarkMode: false,
        setIsDarkMode: vi.fn(),
        branding: {
            title: "Auth Admin",
            logoAlt: "Auth Admin",
            logoLightUrl: "",
            logoDarkUrl: "",
            loginTitle: "Auth Admin",
            backgroundImageUrl: "",
        },
        antTheme: {},
        superAdminBannerStyle: undefined,
    })),
}));

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: () => mockRealm,
}));

function renderSidebar(path = "/") {
    return render(
        <MemoryRouter initialEntries={[path]}>
            <Sidebar collapsed={false} onCollapse={() => {}} />
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
                <Sidebar collapsed={false} onCollapse={onCollapse} />
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
                <Sidebar collapsed={true} onCollapse={() => {}} />
            </MemoryRouter>,
        );

        expect(screen.getByRole("menu")).toBeInTheDocument();
    });

    it("super-admin with a specific realm selected still sees the Realms item", () => {
        // Simulate: global super-admin who switched to a concrete realm
        mockRealm.isSuperAdminMode = false; // admin realm is NOT selected
        mockRealm.isSuperAdmin = true; // but user IS a genuine super-admin
        mockRealm.selectedRealm = "realm-a";
        try {
            renderSidebar();
            expect(screen.getByText("Realms")).toBeInTheDocument();
        } finally {
            // restore defaults for subsequent tests
            mockRealm.isSuperAdminMode = true;
            mockRealm.isSuperAdmin = true;
            mockRealm.selectedRealm = "_";
        }
    });

    it("realm-admin sees the Realms item", () => {
        mockRealm.isSuperAdminMode = false;
        mockRealm.isSuperAdmin = false;
        mockRealm.selectedRealm = "realm-a";
        try {
            renderSidebar();
            expect(screen.getByText("Realms")).toBeInTheDocument();
        } finally {
            mockRealm.isSuperAdminMode = true;
            mockRealm.isSuperAdmin = true;
            mockRealm.selectedRealm = "_";
        }
    });

    it("realm-admin sees the Admins item for a realm it manages, not for one it does not", () => {
        mockRealm.isSuperAdminMode = false;
        mockRealm.isSuperAdmin = false;
        mockRealm.selectedRealm = "realm-a";
        try {
            mockRealm.canManageRealm = (realmId) => realmId === "realm-a";
            const { unmount } = renderSidebar();
            expect(screen.getByText("Admins")).toBeInTheDocument();
            unmount();

            mockRealm.canManageRealm = () => false;
            renderSidebar();
            expect(screen.queryByText("Admins")).not.toBeInTheDocument();
        } finally {
            mockRealm.isSuperAdminMode = true;
            mockRealm.isSuperAdmin = true;
            mockRealm.selectedRealm = "_";
            mockRealm.canManageRealm = () => true;
        }
    });

    it("super-admin still sees the Admins item on a claimed realm, to read its admins", () => {
        mockRealm.isSuperAdminMode = false;
        mockRealm.selectedRealm = "realm-a";
        mockRealm.canManageRealm = () => false;
        try {
            renderSidebar();
            expect(screen.getByText("Admins")).toBeInTheDocument();
        } finally {
            mockRealm.isSuperAdminMode = true;
            mockRealm.selectedRealm = "_";
            mockRealm.canManageRealm = () => true;
        }
    });
});
