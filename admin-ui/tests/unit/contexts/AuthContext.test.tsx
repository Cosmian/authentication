import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { AuthProvider, useAuth } from "../../../src/contexts/AuthContext";

const TestConsumer: React.FC = () => {
    const { isAuthenticated, username, serverUrl } = useAuth();
    return (
        <div>
            <span data-testid="authed">{String(isAuthenticated)}</span>
            <span data-testid="user">{username ?? ""}</span>
            <span data-testid="url">{serverUrl}</span>
        </div>
    );
};

describe("AuthContext", () => {
    it("should provide isAuthenticated as true (stub)", () => {
        render(
            <AuthProvider>
                <TestConsumer />
            </AuthProvider>,
        );

        expect(screen.getByTestId("authed")).toHaveTextContent("true");
    });

    it("should provide a default username", () => {
        render(
            <AuthProvider>
                <TestConsumer />
            </AuthProvider>,
        );

        expect(screen.getByTestId("user")).toHaveTextContent("admin");
    });

    it("should resolve serverUrl from default", () => {
        render(
            <AuthProvider>
                <TestConsumer />
            </AuthProvider>,
        );

        expect(screen.getByTestId("url")).toHaveTextContent("https://localhost:8443");
    });

    it("should throw when useAuth is used outside AuthProvider", () => {
        const spy = vi.spyOn(console, "error").mockImplementation(() => {});
        expect(() => render(<TestConsumer />)).toThrow("useAuth must be used within an AuthProvider");
        spy.mockRestore();
    });
});
