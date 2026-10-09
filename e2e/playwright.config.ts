import { defineConfig, devices } from "@playwright/test";
import { SP_ORIGIN } from "./tests/support";

// Runs against the stack started by .github/scripts/test/saml_e2e/stack.sh; no web server here.
export default defineConfig({
    testDir: "./tests",
    timeout: 60_000,
    retries: process.env.CI ? 1 : 0,
    // Tests share one server and one Keycloak and some change their settings.
    workers: 1,
    reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
    use: {
        baseURL: SP_ORIGIN,
        ignoreHTTPSErrors: true,
        headless: true,
        screenshot: "only-on-failure",
        trace: "retain-on-failure",
        actionTimeout: 15_000,
        navigationTimeout: 30_000,
    },
    projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
