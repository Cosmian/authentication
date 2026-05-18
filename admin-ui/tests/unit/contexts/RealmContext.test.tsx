import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { RealmProvider, useRealm } from "../../../src/contexts/RealmContext";
import type { Realm } from "../../../src/types/api";

vi.mock("../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({ isAuthenticated: true, username: "admin", serverUrl: "", loading: false }),
}));

const makeRealm = (id: string): Realm => ({
    id,
    auth_params: { username_password_params: null, jwt_params: null, totp_params: null },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
});

const TestConsumer: React.FC = () => {
    const { realms, selectedRealm, realmLabel, setSelectedRealm, loading, error, refreshRealms } = useRealm();
    return (
        <div>
            <span data-testid="selected">{selectedRealm}</span>
            <span data-testid="label">{realmLabel(selectedRealm)}</span>
            <span data-testid="loading">{String(loading)}</span>
            <span data-testid="error">{error ?? ""}</span>
            <span data-testid="count">{realms.length}</span>
            <ul>
                {realms.map((r) => (
                    <li key={r.id} data-testid={`realm-${r.id}`}>
                        {r.id}
                    </li>
                ))}
            </ul>
            <button onClick={() => setSelectedRealm("test-realm")}>switch</button>
            <button onClick={() => refreshRealms()}>refresh</button>
        </div>
    );
};

describe("RealmContext", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
        localStorage.clear();
    });

    it("should default to the admin realm '_' displayed as 'Super-Admin'", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify([makeRealm("_"), makeRealm("my-service")]), { status: 200 }),
        );

        await act(async () => {
            render(
                <RealmProvider>
                    <TestConsumer />
                </RealmProvider>,
            );
        });

        expect(screen.getByTestId("selected")).toHaveTextContent("_");
        expect(screen.getByTestId("label")).toHaveTextContent("Super-Admin");
        expect(screen.getByTestId("realm-_")).toBeInTheDocument();
        expect(screen.getByTestId("realm-my-service")).toBeInTheDocument();
    });

    it("should update selectedRealm when setSelectedRealm is called", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify([makeRealm("_"), makeRealm("test-realm")]), { status: 200 }),
        );

        await act(async () => {
            render(
                <RealmProvider>
                    <TestConsumer />
                </RealmProvider>,
            );
        });

        await act(async () => {
            screen.getByText("switch").click();
        });

        expect(screen.getByTestId("selected")).toHaveTextContent("test-realm");
    });

    it("should fall back to admin realm on fetch failure", async () => {
        vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("Network error"));

        await act(async () => {
            render(
                <RealmProvider>
                    <TestConsumer />
                </RealmProvider>,
            );
        });

        expect(screen.getByTestId("selected")).toHaveTextContent("_");
        expect(screen.getByTestId("label")).toHaveTextContent("Super-Admin");
        expect(screen.getByTestId("count")).toHaveTextContent("1");
        expect(screen.getByTestId("error")).toHaveTextContent("Failed to load realms");
    });

    it("should fall back to admin realm on empty API response", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }));

        await act(async () => {
            render(
                <RealmProvider>
                    <TestConsumer />
                </RealmProvider>,
            );
        });

        expect(screen.getByTestId("selected")).toHaveTextContent("_");
        expect(screen.getByTestId("count")).toHaveTextContent("1");
    });

    it("should restore selected realm from localStorage", async () => {
        localStorage.setItem("admin-ui-selected-realm", "my-service");

        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify([makeRealm("_"), makeRealm("my-service")]), { status: 200 }),
        );

        await act(async () => {
            render(
                <RealmProvider>
                    <TestConsumer />
                </RealmProvider>,
            );
        });

        expect(screen.getByTestId("selected")).toHaveTextContent("my-service");
    });

    it("should throw when useRealm is used outside RealmProvider", () => {
        const spy = vi.spyOn(console, "error").mockImplementation(() => {});
        expect(() => render(<TestConsumer />)).toThrow("useRealm must be used within a RealmProvider");
        spy.mockRestore();
    });

    it("should re-fetch and update realms when refreshRealms is called", async () => {
        vi.spyOn(globalThis, "fetch")
            .mockResolvedValueOnce(new Response(JSON.stringify([makeRealm("_"), makeRealm("realm-a")]), { status: 200 }))
            .mockResolvedValueOnce(
                new Response(JSON.stringify([makeRealm("_"), makeRealm("realm-a"), makeRealm("realm-b")]), { status: 200 }),
            );

        await act(async () => {
            render(
                <RealmProvider>
                    <TestConsumer />
                </RealmProvider>,
            );
        });

        expect(screen.getByTestId("count")).toHaveTextContent("2");
        expect(screen.queryByTestId("realm-realm-b")).not.toBeInTheDocument();

        await act(async () => {
            screen.getByText("refresh").click();
        });

        expect(screen.getByTestId("count")).toHaveTextContent("3");
        expect(screen.getByTestId("realm-realm-b")).toBeInTheDocument();
    });
});
