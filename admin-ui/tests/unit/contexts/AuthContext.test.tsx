import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuthProvider, useAuth } from "../../../src/contexts/AuthContext";

const TestConsumer: React.FC = () => {
    const { isAuthenticated, username, serverUrl, loading } = useAuth();
    return (
        <div>
            <span data-testid="authed">{String(isAuthenticated)}</span>
            <span data-testid="user">{username ?? ""}</span>
            <span data-testid="url">{serverUrl}</span>
            <span data-testid="loading">{String(loading)}</span>
        </div>
    );
};

describe("AuthContext", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it("should start unauthenticated and check session on mount", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response("Unauthorized", { status: 401 }));

        await act(async () => {
            render(
                <AuthProvider>
                    <TestConsumer />
                </AuthProvider>,
            );
        });

        expect(screen.getByTestId("authed")).toHaveTextContent("false");
        expect(screen.getByTestId("loading")).toHaveTextContent("false");
    });

    it("should authenticate when whoami returns valid claims", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(
                JSON.stringify({
                    iss: "auth-server",
                    sub: "alice",
                    aud: ["_"],
                    exp: Math.floor(Date.now() / 1000) + 3600,
                    iat: Math.floor(Date.now() / 1000),
                    as_as: "up",
                    as_rid: "_",
                }),
                { status: 200 },
            ),
        );

        await act(async () => {
            render(
                <AuthProvider>
                    <TestConsumer />
                </AuthProvider>,
            );
        });

        expect(screen.getByTestId("authed")).toHaveTextContent("true");
        expect(screen.getByTestId("user")).toHaveTextContent("alice");
    });

    it("should resolve serverUrl to empty string by default (same-origin mode)", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response("Unauthorized", { status: 401 }));

        await act(async () => {
            render(
                <AuthProvider>
                    <TestConsumer />
                </AuthProvider>,
            );
        });

        expect(screen.getByTestId("url")).toHaveTextContent("");
    });

    it("should throw when useAuth is used outside AuthProvider", () => {
        const spy = vi.spyOn(console, "error").mockImplementation(() => {});
        expect(() => render(<TestConsumer />)).toThrow("useAuth must be used within an AuthProvider");
        spy.mockRestore();
    });
});
