import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
    testDir: "./tests/e2e",
    timeout: 90_000,
    retries: process.env.CI ? 1 : 0,
    workers: 1,
    use: {
        baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:5173/admin-ui/",
        headless: true,
        screenshot: "only-on-failure",
        trace: "retain-on-failure",
        actionTimeout: 30_000,
        navigationTimeout: 30_000,
    },
    projects: [
        {
            name: "chromium",
            use: { ...devices["Desktop Chrome"] },
        },
    ],
    webServer: {
        command: "pnpm preview",
        url: "http://localhost:4173/admin-ui/",
        reuseExistingServer: !process.env.CI,
    },
});
