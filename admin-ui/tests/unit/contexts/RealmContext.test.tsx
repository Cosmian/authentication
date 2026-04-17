import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { RealmProvider, useRealm } from "../../../src/contexts/RealmContext";

const TestConsumer: React.FC = () => {
    const { realms, selectedRealm, realmLabel, setSelectedRealm, loading, error } = useRealm();
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
                        {r.label}
                    </li>
                ))}
            </ul>
            <button onClick={() => setSelectedRealm("test-realm")}>switch</button>
        </div>
    );
};

describe("RealmContext", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
        localStorage.clear();
    });

    it("should default to the admin realm '_' displayed as 'Admin'", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify([{ id: "_" }, { id: "my-service" }]), { status: 200 }),
        );

        await act(async () => {
            render(
                <RealmProvider>
                    <TestConsumer />
                </RealmProvider>,
            );
        });

        expect(screen.getByTestId("selected")).toHaveTextContent("_");
        expect(screen.getByTestId("label")).toHaveTextContent("Admin");
        expect(screen.getByTestId("realm-_")).toHaveTextContent("Admin");
        expect(screen.getByTestId("realm-my-service")).toHaveTextContent("my-service");
    });

    it("should update selectedRealm when setSelectedRealm is called", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify([{ id: "_" }, { id: "test-realm" }]), { status: 200 }),
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
        expect(screen.getByTestId("label")).toHaveTextContent("Admin");
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
            new Response(JSON.stringify([{ id: "_" }, { id: "my-service" }]), { status: 200 }),
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
});
