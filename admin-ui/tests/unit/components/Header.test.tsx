import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { Header } from "../../../src/components/layout/Header";

import { useRealm } from "../../../src/contexts/RealmContext";

vi.mock("../../../src/contexts/AuthContext", () => ({
    useAuth: vi.fn(() => ({
        isAuthenticated: true,
        username: "admin",
        serverUrl: "",
        loading: false,
        sessionId: null,
        exp: null,
        login: vi.fn(),
        logout: vi.fn(),
    })),
}));

vi.mock("../../../src/contexts/RealmContext", () => ({
    useRealm: vi.fn(() => ({
        realms: [
            { id: "_", auth_params: { username_password_params: null, jwt_params: null, totp_params: null }, session_max_age_seconds: 0, session_max_stale_age_seconds: 0 },
            { id: "my-service", auth_params: { username_password_params: null, jwt_params: null, totp_params: null }, session_max_age_seconds: 3600, session_max_stale_age_seconds: 1800 },
        ],
        selectedRealm: "_",
        setSelectedRealm: vi.fn(),
        realmLabel: (id: string) => (id === "_" ? "Super-Admin" : id),
        isSuperAdmin: true,
        isGlobalAdmin: true,
        loading: false,
        error: null,
    })),
}));

describe("Header", () => {
    it("should render the application title", () => {
        render(<Header isDarkMode={false} setIsDarkMode={() => {}} />);
        expect(screen.getByText("Auth Admin")).toBeInTheDocument();
    });

    it("should render the realm selector with Super-Admin as default", () => {
        render(<Header isDarkMode={false} setIsDarkMode={() => {}} />);
        expect(screen.getByText("Super-Admin")).toBeInTheDocument();
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
            realmLabel: () => "Super-Admin",
            isSuperAdmin: true,
            isGlobalAdmin: true,
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
