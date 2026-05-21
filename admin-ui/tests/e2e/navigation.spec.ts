import { test, expect } from "@playwright/test";

const mockClaims = {
    iss: "https://localhost:8443",
    sub: "admin",
    aud: "_",
    exp: 9999999999,
    iat: 1000000000,
    as_as: "username_password",
    as_rid: "_",
};

const mockRealms = [
    {
        id: "_",
        auth_params: { username_password_params: { allow_expired_passwords: false }, jwt_params: null, totp_params: null },
        session_max_age_seconds: 86400,
        session_max_stale_age_seconds: 3600,
    },
];

test.describe("Navigation", () => {
    test.beforeEach(async ({ page }) => {
        await page.route("**/whoami**", (route) =>
            route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockClaims) }),
        );
        await page.route("**/admins/realms", (route) =>
            route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(mockRealms) }),
        );
        await page.route("**/admins", (route) =>
            route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) }),
        );
        await page.route("**/public/version", (route) =>
            route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ version: "test" }) }),
        );
    });

    test("should load the landing page", async ({ page }) => {
        await page.goto("/");
        await expect(page.getByText("Dashboard")).toBeVisible();
        await expect(page.getByText("Authentication Server")).toBeVisible();
    });

    test("should navigate to each section via sidebar", async ({ page }) => {
        await page.goto("/");

        const sectionHeadings: Record<string, string> = {
            Admins: "Admin Management",
            Credentials: "Credentials",
            Sessions: "Sessions",
        };

        for (const label of ["Admins", "Credentials", "Sessions"]) {
            await page.getByRole("menuitem", { name: label }).click();
            await expect(page.getByRole("heading", { name: sectionHeadings[label], level: 2 })).toBeVisible();
        }
    });

    test("should show 404 page for unknown route", async ({ page }) => {
        await page.goto("/admin-ui/nonexistent-page");
        await expect(page.getByText("404")).toBeVisible();
    });

    test("should navigate from 404 back to dashboard", async ({ page }) => {
        await page.goto("/admin-ui/nonexistent-page");
        await page.getByRole("link", { name: /dashboard/i }).click();
        await expect(page.getByText("Dashboard")).toBeVisible();
    });

    test("should show realm selector in header", async ({ page }) => {
        await page.goto("/");
        // The realm selector is an Ant Design Select; it shows the current realm label
        await expect(page.getByText("Super-Admin")).toBeVisible();
    });

    test("should toggle dark/light mode", async ({ page }) => {
        await page.goto("/");
        const toggle = page.getByRole("switch");
        await expect(toggle).toBeVisible();

        // Click to enable dark mode
        await toggle.click();
        // Verify the toggle changed state (Ant Design adds ant-switch-checked class)
        await expect(toggle).toHaveClass(/ant-switch-checked/);

        // Click again to disable
        await toggle.click();
        await expect(toggle).not.toHaveClass(/ant-switch-checked/);
    });
});
