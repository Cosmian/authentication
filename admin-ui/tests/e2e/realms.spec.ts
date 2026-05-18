import { test, expect, type Page } from "@playwright/test";
import type { Realm } from "../../src/types/api";

// ── Fixture data ──────────────────────────────────────────────────────────────

const baseRealm: Realm = {
    id: "_",
    auth_params: {
        username_password_params: { allow_expired_passwords: false },
        jwt_params: null,
        totp_params: null,
    },
    session_max_age_seconds: 86400,
    session_max_stale_age_seconds: 3600,
};

const serviceRealm: Realm = {
    id: "my-service",
    auth_params: {
        username_password_params: { allow_expired_passwords: false },
        jwt_params: null,
        totp_params: null,
    },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Register page.route() handlers to mock all /admins/realms API calls.
 * `realmsStore` is mutated in-place by POST/PUT/DELETE handlers so that
 * the GET refetch after each operation reflects the change.
 */
async function mockRealmsApi(page: Page, initialRealms: Realm[]): Promise<void> {
    const store: Realm[] = [...initialRealms];

    // Also mock /public/version so the Footer doesn't hit a real server.
    await page.route("**/public/version", (route) =>
        route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ version: "test-version" }) }),
    );

    // LIST  GET /admins/realms
    await page.route("**/admins/realms", async (route) => {
        if (route.request().method() === "GET") {
            return route.fulfill({
                status: 200,
                contentType: "application/json",
                body: JSON.stringify(store),
            });
        }
        // CREATE  POST /admins/realms
        if (route.request().method() === "POST") {
            const body = (await route.request().postDataJSON()) as Realm;
            if (store.some((r) => r.id === body.id)) {
                return route.fulfill({
                    status: 409,
                    contentType: "application/json",
                    body: JSON.stringify({ message: `Realm '${body.id}' already exists` }),
                });
            }
            store.push(body);
            return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify(body) });
        }
        return route.continue();
    });

    // GET / PUT / DELETE  /admins/realms/:id
    await page.route("**/admins/realms/**", async (route) => {
        const url = new URL(route.request().url());
        const realmId = decodeURIComponent(url.pathname.split("/").pop() ?? "");
        const idx = store.findIndex((r) => r.id === realmId);

        if (route.request().method() === "GET") {
            if (idx === -1) {
                return route.fulfill({
                    status: 404,
                    contentType: "application/json",
                    body: JSON.stringify({ message: "Not found" }),
                });
            }
            return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(store[idx]) });
        }

        if (route.request().method() === "PUT") {
            const body = (await route.request().postDataJSON()) as Realm;
            if (idx === -1) {
                return route.fulfill({ status: 404, contentType: "application/json", body: JSON.stringify({ message: "Not found" }) });
            }
            store[idx] = { ...body, id: realmId };
            return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(store[idx]) });
        }

        if (route.request().method() === "DELETE") {
            if (idx !== -1) store.splice(idx, 1);
            return route.fulfill({ status: 204, body: "" });
        }

        return route.continue();
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe("Realms page", () => {
    test("should open the Create Realm drawer when clicking Create Realm", async ({ page }) => {
        await mockRealmsApi(page, [baseRealm]);
        await page.goto("/realms");

        // Wait for the table to finish loading.
        await expect(page.getByRole("button", { name: "Create Realm" })).toBeVisible();
        await page.getByRole("button", { name: "Create Realm" }).click();

        await expect(page.getByText("Create Realm").first()).toBeVisible();
        // The Realm ID input should be enabled in create mode.
        await expect(page.getByLabel("Realm ID")).toBeEnabled();
    });

    test("should create a new realm and display it in the table", async ({ page }) => {
        await mockRealmsApi(page, [baseRealm]);
        await page.goto("/realms");

        await expect(page.getByRole("button", { name: "Create Realm" })).toBeVisible();
        await page.getByRole("button", { name: "Create Realm" }).click();

        // Fill the Realm ID field.
        await page.getByLabel("Realm ID").fill("e2e-test-realm");

        // Submit the form.
        const createBtn = page.getByRole("button", { name: "Create" }).last();
        await createBtn.click();

        // The drawer should close and the new realm should appear in the table.
        await expect(page.getByText("e2e-test-realm")).toBeVisible();
    });

    test("should open the Edit Realm drawer for an existing realm", async ({ page }) => {
        await mockRealmsApi(page, [baseRealm, serviceRealm]);
        await page.goto("/realms");

        // Wait for the service realm row to appear.
        await expect(page.getByText("my-service")).toBeVisible();

        // Click the Edit button on the my-service row.
        await page
            .getByRole("row", { name: /my-service/ })
            .getByRole("button", { name: "Edit" })
            .click();

        // The drawer heading should reflect the realm being edited.
        await expect(page.getByText("Edit Realm: my-service")).toBeVisible();

        // The Realm ID field must be disabled in edit mode.
        await expect(page.getByLabel("Realm ID")).toBeDisabled();
    });

    test("should delete a realm after confirming in the delete modal", async ({ page }) => {
        await mockRealmsApi(page, [baseRealm, serviceRealm]);
        await page.goto("/realms");

        // Wait for the service realm row to appear.
        await expect(page.getByText("my-service")).toBeVisible();

        // Click the Delete button.
        await page
            .getByRole("row", { name: /my-service/ })
            .getByRole("button", { name: "Delete" })
            .click();

        // Confirm delete modal should appear.
        await expect(page.getByText(/Delete "my-service"/)).toBeVisible();

        // Type the realm name to confirm.
        await page.getByPlaceholder("my-service").fill("my-service");
        await page.getByRole("button", { name: "Delete" }).last().click();

        // The realm must no longer appear in the table.
        await expect(page.getByText("my-service")).not.toBeVisible();
    });
});
