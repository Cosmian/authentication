import { test, expect, type Page } from "@playwright/test";
import type { AppRoleRoleConfig, K8sRoleConfig, TokenInfo } from "../../src/types/api";

// ── Fixture data ──────────────────────────────────────────────────────────────

const mockClaims = {
    iss: "https://localhost:8443",
    sub: "admin",
    aud: "_",
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000) - 60,
    as_as: "username_password",
    as_rid: "_",
};

const superAdminRealms = [
    {
        id: "_",
        auth_params: { username_password_params: { allow_expired_passwords: false }, jwt_params: null, totp_params: null },
        session_max_age_seconds: 86400,
        session_max_stale_age_seconds: 3600,
    },
];

const nonAdminRealms = [
    {
        id: "my-service",
        auth_params: { username_password_params: { allow_expired_passwords: false }, jwt_params: null, totp_params: null },
        session_max_age_seconds: 3600,
        session_max_stale_age_seconds: 1800,
    },
];

const ciRunnerConfig: AppRoleRoleConfig = {
    role_id: "rid-ci-runner",
    token_ttl: 3600,
    secret_id_ttl: 0,
    bind_secret_id: true,
    token_policies: ["CryptoOfficer"],
};

const spireK8sConfig: K8sRoleConfig = {
    jwks_url: "https://kubernetes.default.svc/openid/v1/jwks",
    bound_service_account_names: ["spire-agent"],
    bound_service_account_namespaces: ["spire"],
    token_ttl: 3600,
    expected_issuer: "https://kubernetes.default.svc",
    bound_audiences: ["cosmian-auth"],
};

const tokenInfo: TokenInfo = {
    id: "s.abcdef123456",
    entity_id: "spiffe://cluster/ns/spire/sa/spire-agent",
    policies: ["CryptoOfficer"],
    renewable: true,
    ttl: 3200,
    creation_time: 1_700_000_000,
};

// ── Route mocks ────────────────────────────────────────────────────────────────

interface MockOptions {
    realms?: typeof superAdminRealms;
    approle?: Record<string, AppRoleRoleConfig>;
    k8s?: Record<string, K8sRoleConfig>;
    tokenValid?: boolean;
}

/** Mocks auth + realm endpoints so the SPA renders as an authenticated (super-)admin. */
async function mockCommon(page: Page, realms: typeof superAdminRealms): Promise<void> {
    await page.route(
        (url) => url.pathname.startsWith("/whoami"),
        (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockClaims) }),
    );
    await page.route(
        (url) => url.pathname === "/admins/realms",
        (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(realms) }),
    );
    await page.route(
        (url) => url.pathname === "/public/version",
        (route) => route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ version: "test" }) }),
    );
}

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

/** Registers a mutable in-memory mock for the AppRole admin endpoints. */
async function mockAppRole(page: Page, initial: Record<string, AppRoleRoleConfig>): Promise<void> {
    const store = new Map<string, AppRoleRoleConfig>(Object.entries(initial));
    await page.route(
        (url) => url.pathname.startsWith("/auth/approle/"),
        async (route) => {
            const { pathname } = new URL(route.request().url());
            const method = route.request().method();
            const name = decodeURIComponent(pathname.split("/")[4] ?? "");

            if (pathname === "/auth/approle/role" && method === "GET") {
                return route.fulfill(json({ data: { keys: [...store.keys()] } }));
            }
            if (pathname.endsWith("/secret-id") && method === "POST") {
                return route.fulfill(json({ data: { secret_id: `secret-${name}-xyz`, secret_id_accessor: `acc-${name}` } }));
            }
            if (method === "GET") {
                const cfg = store.get(name);
                return cfg ? route.fulfill(json({ data: cfg })) : route.fulfill(json({ message: "not found" }, 400));
            }
            if (method === "POST") {
                const body = (await route.request().postDataJSON()) as Omit<AppRoleRoleConfig, "role_id">;
                store.set(name, { ...body, role_id: `rid-${name}` });
                return route.fulfill(json({ data: { role_id: `rid-${name}` } }));
            }
            if (method === "DELETE") {
                store.delete(name);
                return route.fulfill({ status: 204, body: "" });
            }
            return route.continue();
        },
    );
}

/** Registers a mutable in-memory mock for the Kubernetes role admin endpoints. */
async function mockK8s(page: Page, initial: Record<string, K8sRoleConfig>): Promise<void> {
    const store = new Map<string, K8sRoleConfig>(Object.entries(initial));
    await page.route(
        (url) => url.pathname.startsWith("/auth/kubernetes/"),
        async (route) => {
            const { pathname } = new URL(route.request().url());
            const method = route.request().method();
            const name = decodeURIComponent(pathname.split("/")[4] ?? "");

            if (pathname === "/auth/kubernetes/role" && method === "GET") {
                return route.fulfill(json({ data: { keys: [...store.keys()] } }));
            }
            if (method === "GET") {
                const cfg = store.get(name);
                return cfg ? route.fulfill(json({ data: cfg })) : route.fulfill(json({ message: "not found" }, 400));
            }
            if (method === "POST") {
                const body = (await route.request().postDataJSON()) as K8sRoleConfig;
                store.set(name, body);
                return route.fulfill(json({ data: {} }));
            }
            if (method === "DELETE") {
                store.delete(name);
                return route.fulfill({ status: 204, body: "" });
            }
            return route.continue();
        },
    );
}

/** Registers a mock for the token self-service endpoints (X-Vault-Token authed). */
async function mockToken(page: Page, valid: boolean): Promise<void> {
    let renewed = false;
    await page.route(
        (url) => url.pathname.startsWith("/auth/token/"),
        (route) => {
            const { pathname } = new URL(route.request().url());
            const hasToken = Boolean(route.request().headers()["x-vault-token"]);
            if (!hasToken || !valid) {
                return route.fulfill(json({ message: "invalid token" }, 403));
            }
            if (pathname.endsWith("/lookup-self")) {
                return route.fulfill(json({ data: { ...tokenInfo, ttl: renewed ? 7200 : 3200 } }));
            }
            if (pathname.endsWith("/renew-self")) {
                renewed = true;
                return route.fulfill(
                    json({
                        auth: {
                            client_token: "s.abcdef123456",
                            renewable: true,
                            lease_duration: 7200,
                            policies: tokenInfo.policies,
                            metadata: {},
                        },
                    }),
                );
            }
            if (pathname.endsWith("/revoke-self")) {
                return route.fulfill({ status: 204, body: "" });
            }
            return route.continue();
        },
    );
}

async function setup(page: Page, opts: MockOptions = {}): Promise<void> {
    await mockCommon(page, opts.realms ?? superAdminRealms);
    await mockAppRole(page, opts.approle ?? { "ci-runner": ciRunnerConfig });
    await mockK8s(page, opts.k8s ?? { "spire-agent-role": spireK8sConfig });
    await mockToken(page, opts.tokenValid ?? true);
}

// ── Tests ────────────────────────────────────────────────────────────────────

test.describe("Machine Credentials — navigation & access", () => {
    test("super-admin sees the sidebar entry and can open the page", async ({ page }) => {
        await setup(page);
        await page.goto("");
        await page.getByRole("menuitem", { name: "Machine Creds" }).click();
        await expect(page.getByRole("heading", { name: "Machine Credentials", level: 2 })).toBeVisible();
        await expect(page.getByRole("tab", { name: "AppRole" })).toBeVisible();
        await expect(page.getByRole("tab", { name: "Kubernetes" })).toBeVisible();
        await expect(page.getByRole("tab", { name: "Token" })).toBeVisible();
    });

    test("non-super-admin is blocked from the page content", async ({ page }) => {
        await setup(page, { realms: nonAdminRealms });
        await page.goto("/admin-ui/machine-credentials");
        await expect(page.getByText("Super-admin only")).toBeVisible();
        await expect(page.getByRole("menuitem", { name: "Machine Creds" })).toHaveCount(0);
    });
});

test.describe("Machine Credentials — AppRole tab", () => {
    test("lists existing roles with role id and policies", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await expect(page.getByRole("cell", { name: "ci-runner", exact: true })).toBeVisible();
        await expect(page.getByText("rid-ci-runner")).toBeVisible();
        await expect(page.getByText("CryptoOfficer")).toBeVisible();
    });

    test("creates a new AppRole role", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("button", { name: "New AppRole" }).click();
        await page.getByLabel("Role name").fill("new-role");
        await page.getByRole("button", { name: "Create" }).click();
        await expect(page.getByRole("cell", { name: "new-role", exact: true })).toBeVisible();
        await expect(page.getByText("rid-new-role")).toBeVisible();
    });

    test("generates a SecretID and shows it once", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("button", { name: "SecretID" }).click();
        const dialog = page.getByRole("dialog");
        await expect(dialog.getByText("secret-ci-runner-xyz")).toBeVisible();
        await expect(dialog.getByText("rid-ci-runner")).toBeVisible();
        await dialog.getByRole("button", { name: "Done" }).click();
        await expect(dialog).toBeHidden();
    });

    test("edits a role with the name locked", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("button", { name: "Edit" }).click();
        await expect(page.getByText("Edit AppRole — ci-runner")).toBeVisible();
        await expect(page.getByLabel("Role name")).toBeDisabled();
    });

    test("deletes a role", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("button", { name: "Delete" }).click();
        await page.getByRole("button", { name: "Delete" }).last().click();
        await expect(page.getByRole("cell", { name: "ci-runner" })).toHaveCount(0);
    });

    test("shows an empty state when there are no roles", async ({ page }) => {
        await setup(page, { approle: {} });
        await page.goto("/admin-ui/machine-credentials");
        await expect(page.getByText("No AppRole roles yet")).toBeVisible();
    });
});

test.describe("Machine Credentials — Kubernetes tab", () => {
    test("lists existing roles with service accounts and namespaces", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("tab", { name: "Kubernetes" }).click();
        await expect(page.getByRole("cell", { name: "spire-agent-role" })).toBeVisible();
        await expect(page.getByText("spire-agent", { exact: true })).toBeVisible();
        await expect(page.getByText("spire", { exact: true })).toBeVisible();
    });

    test("rejects a non-https JWKS URL", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("tab", { name: "Kubernetes" }).click();
        await page.getByRole("button", { name: "New Kubernetes role" }).click();
        await page.getByLabel("Role name").fill("bad-url-role");
        await page.getByLabel("JWKS URL").fill("http://insecure.example/jwks");
        await page.getByRole("button", { name: "Create" }).click();
        await expect(page.getByText("URL must use https://")).toBeVisible();
    });

    test("creates a new Kubernetes role", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("tab", { name: "Kubernetes" }).click();
        await page.getByRole("button", { name: "New Kubernetes role" }).click();
        await page.getByLabel("Role name").fill("api-role");
        await page.getByLabel("JWKS URL").fill("https://k8s.example/jwks");
        await page.getByRole("button", { name: "Create" }).click();
        await expect(page.getByRole("cell", { name: "api-role" })).toBeVisible();
    });

    test("deletes a Kubernetes role", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("tab", { name: "Kubernetes" }).click();
        await expect(page.getByRole("cell", { name: "spire-agent-role" })).toBeVisible();
        await page.getByRole("button", { name: "Delete" }).click();
        await page.getByRole("button", { name: "Delete" }).last().click();
        await expect(page.getByRole("cell", { name: "spire-agent-role" })).toHaveCount(0);
    });
});

test.describe("Machine Credentials — Token tab", () => {
    test("looks up a token and displays its metadata", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("tab", { name: "Token" }).click();
        await page.getByPlaceholder("Paste token…").fill("valid-token");
        await page.getByRole("button", { name: "Lookup" }).click();
        await expect(page.getByText("spiffe://cluster/ns/spire/sa/spire-agent")).toBeVisible();
        await expect(page.getByText("3200s")).toBeVisible();
    });

    test("shows an error for an invalid token", async ({ page }) => {
        await setup(page, { tokenValid: false });
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("tab", { name: "Token" }).click();
        await page.getByPlaceholder("Paste token…").fill("bad-token");
        await page.getByRole("button", { name: "Lookup" }).click();
        await expect(page.getByText(/Lookup failed/)).toBeVisible();
    });

    test("renews a token", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("tab", { name: "Token" }).click();
        await page.getByPlaceholder("Paste token…").fill("valid-token");
        await page.getByRole("button", { name: "Lookup" }).click();
        await expect(page.getByText("3200s")).toBeVisible();
        await page.getByRole("button", { name: "Renew" }).click();
        await expect(page.getByText("7200s", { exact: true })).toBeVisible();
    });

    test("revokes a token and clears the view", async ({ page }) => {
        await setup(page);
        await page.goto("/admin-ui/machine-credentials");
        await page.getByRole("tab", { name: "Token" }).click();
        await page.getByPlaceholder("Paste token…").fill("valid-token");
        await page.getByRole("button", { name: "Lookup" }).click();
        await expect(page.getByText("Entity ID")).toBeVisible();
        await page.getByRole("button", { name: "Revoke" }).click();
        await page.getByRole("button", { name: "Revoke" }).last().click();
        await expect(page.getByText("Entity ID")).toHaveCount(0);
    });
});
