import { render, screen, act, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { AdminFormDrawer } from "../../../../src/components/admins/AdminFormDrawer";
import type { Admin } from "../../../../src/types/api";

vi.mock("../../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({
        isAuthenticated: true,
        username: "admin",
        serverUrl: "",
        loading: false,
        sessionId: null,
        exp: null,
        login: vi.fn(),
        logout: vi.fn(),
    }),
}));

const makeRealm = (id: string) => ({
    id,
    auth_params: { username_password_params: null, jwt_params: null, totp_params: null },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
});

const mockRealm = {
    realms: [makeRealm("realm-a"), makeRealm("realm-b")],
    selectedRealm: "realm-a",
    isSuperAdminMode: false,
    isSuperAdmin: false,
    canManageRealm: (() => true) as (realmId: string) => boolean,
    realmLabel: (id: string) => id,
};

vi.mock("../../../../src/contexts/RealmContext", () => ({
    useRealm: () => mockRealm,
}));

const existingAdmin: Admin = {
    id: "alice",
    realms: ["realm-a"],
    userpass: "alice",
    jwt: null,
    fido2: null,
    digital_credentials: null,
    client_certificate: null,
    totp_enabled: false,
};

/** Find the primary footer submit button (last in the DOM). */
function getSubmitButton(name: string | RegExp) {
    const buttons = screen.getAllByRole("button", { name });
    return buttons[buttons.length - 1];
}

/** Fill Admin ID and select a realm to satisfy required fields. */
async function fillRequiredFields() {
    await act(async () => {
        fireEvent.change(screen.getByLabelText("Admin ID"), { target: { value: "bob" } });
    });
    await act(async () => {
        const combobox = screen.getByRole("combobox");
        fireEvent.mouseDown(combobox);
    });
    const option = await screen.findByTitle("realm-a");
    await act(async () => {
        fireEvent.click(option);
    });
}

describe("AdminFormDrawer — submit button state", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
        mockRealm.canManageRealm = () => true;
    });

    it("realm picker: a realm that has its own admins is listed but cannot be picked", async () => {
        mockRealm.canManageRealm = (realmId) => realmId !== "realm-b";
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={null} onClose={vi.fn()} onSuccess={vi.fn()} />);
        });
        await act(async () => {
            fireEvent.mouseDown(screen.getByRole("combobox"));
        });

        expect(await screen.findByTitle("realm-a")).not.toHaveClass("ant-select-item-option-disabled");
        expect(await screen.findByTitle("realm-b (has its own admins)")).toHaveClass("ant-select-item-option-disabled");
    });

    // ── Create mode ──────────────────────────────────────────────────────────

    it("create mode: button is disabled initially (no values)", async () => {
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={null} onClose={vi.fn()} onSuccess={vi.fn()} />);
        });
        const btn = getSubmitButton("Create");
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("create mode: button is still disabled when only Admin ID is filled (realm required)", async () => {
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={null} onClose={vi.fn()} onSuccess={vi.fn()} />);
        });
        await act(async () => {
            fireEvent.change(screen.getByLabelText("Admin ID"), { target: { value: "bob" } });
        });
        const btn = getSubmitButton("Create");
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("create mode: button is enabled after Admin ID + realm are filled (no password toggle)", async () => {
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={null} onClose={vi.fn()} onSuccess={vi.fn()} />);
        });
        await fillRequiredFields();
        const btn = getSubmitButton("Create");
        await waitFor(() => expect(btn).not.toBeDisabled());
    });

    it("create mode: a preselected realm satisfies the realm requirement", async () => {
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={null} defaultRealm="realm-a" onClose={vi.fn()} onSuccess={vi.fn()} />);
        });
        await act(async () => {
            fireEvent.change(screen.getByLabelText("Admin ID"), { target: { value: "bob" } });
        });
        expect(screen.getByTitle("realm-a")).toBeInTheDocument();
        const btn = getSubmitButton("Create");
        await waitFor(() => expect(btn).not.toBeDisabled());
    });

    // ── Edit mode ─────────────────────────────────────────────────────────────

    it("edit mode: button is disabled initially (form matches original)", async () => {
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={existingAdmin} onClose={vi.fn()} onSuccess={vi.fn()} />);
        });
        const btn = getSubmitButton("Save");
        await waitFor(() => expect(btn).toBeDisabled());
    });

    it("edit mode: button is enabled after changing JWT field", async () => {
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={existingAdmin} onClose={vi.fn()} onSuccess={vi.fn()} />);
        });
        await act(async () => {
            fireEvent.change(screen.getByLabelText("JWT"), { target: { value: "new-jwt" } });
        });
        const btn = getSubmitButton("Save");
        await waitFor(() => expect(btn).not.toBeDisabled());
    });
});

describe("AdminFormDrawer — creating an admin with a password", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
        mockRealm.canManageRealm = () => true;
    });

    /** Fill the create form for `bob` in `realm-a` with a password, submit, and return the requests made. */
    async function createBob(): Promise<{ method: string; path: string; body: Record<string, unknown> }[]> {
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => new Response(JSON.stringify({}), { status: 201 }));
        const onSuccess = vi.fn();
        await act(async () => {
            render(<AdminFormDrawer open={true} admin={null} defaultRealm="realm-a" onClose={vi.fn()} onSuccess={onSuccess} />);
        });
        await act(async () => {
            fireEvent.change(screen.getByLabelText("Admin ID"), { target: { value: "bob" } });
            fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret-pw" } });
            fireEvent.change(screen.getByLabelText("Confirm Password"), { target: { value: "secret-pw" } });
        });
        const btn = getSubmitButton("Create");
        await waitFor(() => expect(btn).not.toBeDisabled());
        await act(async () => {
            fireEvent.click(btn);
        });
        await waitFor(() => expect(onSuccess).toHaveBeenCalled());
        return fetchSpy.mock.calls.map(([url, init]) => ({
            method: String(init?.method),
            path: String(url),
            body: JSON.parse(String(init?.body)) as Record<string, unknown>,
        }));
    }

    it("a super admin creates the login first, then the admin linked to it", async () => {
        mockRealm.isSuperAdmin = true;
        try {
            const calls = await createBob();
            expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(["POST /realms/_/userpass", "POST /admins"]);
            expect(calls[1].body).toMatchObject({ id: "bob", realms: ["realm-a"], userpass: "bob" });
        } finally {
            mockRealm.isSuperAdmin = false;
        }
    });

    it("a realm admin creates the admin first, then its login", async () => {
        const calls = await createBob();
        expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(["POST /admins", "POST /realms/_/userpass"]);
        expect(calls[0].body).toMatchObject({ id: "bob", userpass: null });
    });
});
