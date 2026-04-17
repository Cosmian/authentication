import { test, expect } from "@playwright/test";

test.describe("Navigation", () => {
    test("should load the landing page", async ({ page }) => {
        await page.goto("/");
        await expect(page.getByText("Dashboard")).toBeVisible();
        await expect(page.getByText("Auth Admin")).toBeVisible();
    });

    test("should navigate to each section via sidebar", async ({ page }) => {
        await page.goto("/");

        for (const label of ["Users", "Credentials", "Sessions", "TOTP"]) {
            await page.getByRole("menuitem", { name: label }).click();
            await expect(page.getByText(label)).toBeVisible();
            await expect(page.getByText(/coming soon/i)).toBeVisible();
        }
    });

    test("should show 404 page for unknown route", async ({ page }) => {
        await page.goto("/nonexistent-page");
        await expect(page.getByText("404")).toBeVisible();
    });

    test("should navigate from 404 back to dashboard", async ({ page }) => {
        await page.goto("/nonexistent-page");
        await page.getByRole("link", { name: /dashboard/i }).click();
        await expect(page.getByText("Dashboard")).toBeVisible();
    });

    test("should show realm selector in header", async ({ page }) => {
        await page.goto("/");
        // The realm selector is an Ant Design Select; it shows the current realm label
        await expect(page.getByText("Admin")).toBeVisible();
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
