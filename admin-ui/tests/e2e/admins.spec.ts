import { test, expect, type Page } from "@playwright/test";
import type { Admin, Realm } from "../../src/types/api";

const mockClaims = {
    iss: "https://localhost:8443",
    sub: "admin",
    aud: "_",
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000) - 60,
    as_as: "username_password",
    as_rid: "_",
};

const realm = (id: string): Realm => ({
    id,
    auth_params: { username_password_params: { allow_expired_passwords: false }, jwt_params: null, totp_params: null },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
});

const admin = (id: string, realms: string[]): Admin => ({
    id,
    realms,
    userpass: `${id}-login`,
    jwt: null,
    fido2: null,
    digital_credentials: null,
    client_certificate: null,
    totp_enabled: false,
});

const json = (body: unknown, status = 200) => ({ status, contentType: "application/json", body: JSON.stringify(body) });

/**
 * Mocks what the server returns to the logged-in admin: `realms` for `GET /admins/realms`, `admins` for
 * `GET /admins`. `DELETE /admins/:id` removes the admin from the list served afterwards.
 */
async function mockAdminsApi(page: Page, realms: Realm[], admins: Admin[]): Promise<void> {
    const store = [...admins];
    await page.route(
        (url) => url.pathname.startsWith("/whoami"),
        (route) => route.fulfill(json(mockClaims)),
    );
    await page.route(
        (url) => url.pathname === "/admins/realms",
        (route) => route.fulfill(json(realms)),
    );
    await page.route(
        (url) => url.pathname === "/public/version",
        (route) => route.fulfill(json({ version: "test" })),
    );
    await page.route(
        (url) => url.pathname === "/admins",
        (route) => route.fulfill(json(store)),
    );
    await page.route(
        (url) => url.pathname.startsWith("/admins/") && !url.pathname.startsWith("/admins/realms"),
        (route) => {
            if (route.request().method() !== "DELETE") return route.continue();
            const id = decodeURIComponent(new URL(route.request().url()).pathname.split("/").pop() ?? "");
            const index = store.findIndex((a) => a.id === id);
            if (index !== -1) store.splice(index, 1);
            return route.fulfill({ status: 204, body: "" });
        },
    );
}

const rowOf = (page: Page, adminId: string) => page.getByRole("row").filter({ hasText: adminId });

test.describe("Admins page", () => {
    test("a realm admin lists the admins of its realm and deletes one", async ({ page }) => {
        await mockAdminsApi(page, [realm("demo")], [admin("demo-admin", ["demo"]), admin("demo-colleague", ["demo"])]);
        await page.goto("/admin-ui/admins");

        await expect(rowOf(page, "demo-admin")).toBeVisible();
        await expect(rowOf(page, "demo-colleague").getByRole("button", { name: /Credential/ })).toBeVisible();
        await expect(page.getByRole("button", { name: "New Admin" })).toBeVisible();

        await rowOf(page, "demo-colleague")
            .getByRole("button", { name: /Delete/ })
            .click();
        await page.getByRole("button", { name: "Delete" }).last().click();

        await expect(rowOf(page, "demo-colleague")).toHaveCount(0);
        await expect(rowOf(page, "demo-admin")).toBeVisible();
    });

    test("a super admin sees the admins of a claimed realm read-only", async ({ page }) => {
        await mockAdminsApi(
            page,
            [realm("_"), realm("demo")],
            [admin("admin", ["_"]), admin("demo-admin", ["demo"]), admin("unclaimed-less", [])],
        );
        await page.goto("/admin-ui/admins");

        const claimed = rowOf(page, "demo-admin");
        await expect(claimed.getByText("Read-only")).toBeVisible();
        await expect(claimed.getByRole("button")).toHaveCount(0);
        await expect(rowOf(page, "unclaimed-less").getByRole("button", { name: /Edit/ })).toBeVisible();
        await expect(page.getByRole("button", { name: "New Admin" })).toBeVisible();
    });
});
