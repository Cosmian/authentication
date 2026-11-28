import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { RealmProvider, useRealm } from "../../../src/contexts/RealmContext";
import type { Admin, Realm } from "../../../src/types/api";

vi.mock("../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({ isAuthenticated: true, username: "admin", serverUrl: "", loading: false }),
}));

const makeRealm = (id: string): Realm => ({
    id,
    auth_params: { username_password_params: null, jwt_params: null, totp_params: null },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
});

const makeAdmin = (id: string, realms: string[]): Admin => ({
    id,
    realms,
    userpass: null,
    jwt: null,
    fido2: null,
    digital_credentials: null,
    client_certificate: null,
});

interface ApiState {
    realms: Realm[];
    admins: Admin[] | "fail";
}

/** Serves `GET /admins/realms` and `GET /admins` from `state`, read on every call so a test can change it. */
const mockApi = (state: ApiState) =>
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
        const url = String(input);
        if (url.endsWith("/admins/realms")) return new Response(JSON.stringify(state.realms), { status: 200 });
        if (url.endsWith("/admins")) {
            if (state.admins === "fail") return new Response("boom", { status: 500 });
            return new Response(JSON.stringify(state.admins), { status: 200 });
        }
        throw new Error(`Unexpected request: ${url}`);
    });

const TestConsumer: React.FC = () => {
    const { realms, selectedRealm, isSuperAdminMode, realmLabel, setSelectedRealm, loading, error, refreshRealms, canManageRealm } =
        useRealm();
    return (
        <div>
            <span data-testid="selected">{selectedRealm}</span>
            <span data-testid="super-admin-mode">{String(isSuperAdminMode)}</span>
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
            <span data-testid="can-manage">
                {realms
                    .map((r) => r.id)
                    .filter(canManageRealm)
                    .join(",")}
            </span>
            <button onClick={() => setSelectedRealm("test-realm")}>switch</button>
            <button onClick={() => refreshRealms()}>refresh</button>
        </div>
    );
};

const renderProvider = async () => {
    await act(async () => {
        render(
            <RealmProvider>
                <TestConsumer />
            </RealmProvider>,
        );
    });
};

describe("RealmContext", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
        localStorage.clear();
    });

    it("should default to the admin realm '_' displayed as 'Super-Admin'", async () => {
        mockApi({ realms: [makeRealm("_"), makeRealm("my-service")], admins: [] });

        await renderProvider();

        expect(screen.getByTestId("selected")).toHaveTextContent("_");
        expect(screen.getByTestId("label")).toHaveTextContent("Super-Admin");
        expect(screen.getByTestId("realm-_")).toBeInTheDocument();
        expect(screen.getByTestId("realm-my-service")).toBeInTheDocument();
    });

    it("should update selectedRealm when setSelectedRealm is called", async () => {
        mockApi({ realms: [makeRealm("_"), makeRealm("test-realm")], admins: [] });

        await renderProvider();

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
        expect(screen.getByTestId("count")).toHaveTextContent("0");
        expect(screen.getByTestId("error")).toHaveTextContent("Failed to load realms");
    });

    it("should select no realm, not the admin realm, when the server returns none", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify([]), { status: 200 }));

        await act(async () => {
            render(
                <RealmProvider>
                    <TestConsumer />
                </RealmProvider>,
            );
        });

        expect(screen.getByTestId("selected")).toHaveTextContent(/^$/);
        expect(screen.getByTestId("super-admin-mode")).toHaveTextContent("false");
        expect(screen.getByTestId("count")).toHaveTextContent("0");
    });

    it("should not turn a realm admin into a super admin when it deletes its last realm", async () => {
        localStorage.setItem("admin-ui-selected-realm", "demo");
        const state: ApiState = { realms: [makeRealm("demo")], admins: "fail" };
        mockApi(state);
        await renderProvider();
        expect(screen.getByTestId("selected")).toHaveTextContent("demo");

        state.realms = [];
        await act(async () => {
            screen.getByText("refresh").click();
        });

        expect(screen.getByTestId("selected")).toHaveTextContent(/^$/);
        expect(screen.getByTestId("super-admin-mode")).toHaveTextContent("false");
    });

    it("should restore selected realm from localStorage", async () => {
        localStorage.setItem("admin-ui-selected-realm", "my-service");
        mockApi({ realms: [makeRealm("_"), makeRealm("my-service")], admins: [] });

        await renderProvider();

        expect(screen.getByTestId("selected")).toHaveTextContent("my-service");
    });

    it("should throw when useRealm is used outside RealmProvider", () => {
        const spy = vi.spyOn(console, "error").mockImplementation(() => {});
        expect(() => render(<TestConsumer />)).toThrow("useRealm must be used within a RealmProvider");
        spy.mockRestore();
    });

    it("should re-fetch and update realms when refreshRealms is called", async () => {
        const state: ApiState = { realms: [makeRealm("_"), makeRealm("realm-a")], admins: [] };
        mockApi(state);

        await renderProvider();

        expect(screen.getByTestId("count")).toHaveTextContent("2");
        expect(screen.queryByTestId("realm-realm-b")).not.toBeInTheDocument();

        state.realms = [makeRealm("_"), makeRealm("realm-a"), makeRealm("realm-b")];
        await act(async () => {
            screen.getByText("refresh").click();
        });

        expect(screen.getByTestId("count")).toHaveTextContent("3");
        expect(screen.getByTestId("realm-realm-b")).toBeInTheDocument();
    });

    describe("canManageRealm", () => {
        it("should refuse a super admin the realms that have admins of their own", async () => {
            mockApi({
                realms: [makeRealm("_"), makeRealm("demo"), makeRealm("free"), makeRealm("other")],
                admins: [makeAdmin("admin", ["_"]), makeAdmin("demo-admin", ["demo"]), makeAdmin("shared", ["demo", "other"])],
            });

            await renderProvider();

            expect(screen.getByTestId("can-manage")).toHaveTextContent(/^_,free$/);
        });

        it("should let a realm admin manage only its own realms, without listing admins", async () => {
            const fetchSpy = mockApi({ realms: [makeRealm("demo")], admins: "fail" });

            await renderProvider();

            expect(screen.getByTestId("can-manage")).toHaveTextContent(/^demo$/);
            expect(fetchSpy).toHaveBeenCalledTimes(1);
        });

        it("should treat realms as manageable when the admin list cannot be loaded", async () => {
            mockApi({ realms: [makeRealm("_"), makeRealm("demo"), makeRealm("free")], admins: "fail" });

            await renderProvider();

            expect(screen.getByTestId("count")).toHaveTextContent("3");
            expect(screen.getByTestId("error")).toHaveTextContent("");
            expect(screen.getByTestId("can-manage")).toHaveTextContent(/^_,demo,free$/);
        });

        it("should pick up a realm that became claimed after a refresh", async () => {
            const state: ApiState = { realms: [makeRealm("_"), makeRealm("demo")], admins: [makeAdmin("admin", ["_"])] };
            mockApi(state);
            await renderProvider();
            expect(screen.getByTestId("can-manage")).toHaveTextContent(/^_,demo$/);

            state.admins = [makeAdmin("admin", ["_"]), makeAdmin("demo-admin", ["demo"])];
            await act(async () => {
                screen.getByText("refresh").click();
            });

            expect(screen.getByTestId("can-manage")).toHaveTextContent(/^_$/);
        });
    });
});
