import { expect, test } from "@playwright/test";
import { ADMIN, IDP_ENTITY_ID, IDP_METADATA_URL, SP_ORIGIN, UI_REALM, signInAsAlice } from "./support";

test.describe("Admin UI against the real server and IdP", () => {
    let idpMetadata = "";

    test.beforeAll(async ({ playwright }) => {
        const api = await playwright.request.newContext({ baseURL: SP_ORIGIN, ignoreHTTPSErrors: true });
        idpMetadata = await (await api.get(IDP_METADATA_URL)).text();
        // Make reruns against a kept-up stack (SAML_E2E_KEEP=1) start clean.
        const login = await api.post("/login?realm=_", {
            headers: { Authorization: `Basic ${Buffer.from(`${ADMIN.username}:${ADMIN.password}`).toString("base64")}` },
            data: {},
        });
        expect(login.status()).toBe(200);
        await api.delete(`/admins/realms/${UI_REALM}`);
        await api.dispose();
    });

    test("an admin configures a SAML realm from the IdP metadata and alice signs in through it", async ({ page, browser }) => {
        await page.goto("/admin-ui/");
        await page.getByPlaceholder("Username").fill(ADMIN.username);
        await page.getByPlaceholder("Password").fill(ADMIN.password);
        await page.getByRole("button", { name: "Login" }).click();
        await page.goto("/admin-ui/realms");

        await page.getByRole("button", { name: "Create Realm" }).click();
        await page.getByLabel("Realm ID").fill(UI_REALM);
        await page.getByRole("checkbox", { name: "SAML 2.0 (single sign-on)" }).check();
        await page.getByLabel("IdP metadata XML").fill(idpMetadata);
        await expect(page.getByLabel("Parsed IdP metadata").getByText(IDP_ENTITY_ID, { exact: true })).toBeVisible();
        await expect(page.getByLabel("SP entity ID", { exact: true })).toHaveValue(`${SP_ORIGIN}/saml/${UI_REALM}`);
        await expect(page.getByLabel("Assertion Consumer Service URL", { exact: true })).toHaveValue(`${SP_ORIGIN}/saml/${UI_REALM}/acs`);

        await page.getByLabel("Subject attribute").fill("username");
        await page.getByLabel("Role attribute").fill("groups");
        await page.getByRole("button", { name: "Add claim mapping" }).click();
        await page.getByLabel("SAML attribute").fill("email");
        await page.getByLabel("Claim name").fill("mail");
        const origins = page.getByLabel("Allowed return origins");
        await origins.fill(SP_ORIGIN);
        await origins.press("Enter");
        await page.getByLabel("Default return URL").fill(`${SP_ORIGIN}/whoami?realm=${UI_REALM}`);
        await page.getByRole("button", { name: "Create" }).last().click();

        const card = page.locator(".ant-card").filter({ hasText: UI_REALM });
        await expect(card.getByText("SAML", { exact: true })).toBeVisible();

        const context = await browser.newContext({ baseURL: SP_ORIGIN, ignoreHTTPSErrors: true });
        try {
            const claims = await signInAsAlice(await context.newPage(), UI_REALM);
            expect(claims).toMatchObject({ sub: "alice", as_as: "sa", as_rid: UI_REALM, mail: "alice@example.com" });
            expect(claims.roles).toEqual(expect.arrayContaining(["admins", "users"]));
        } finally {
            await context.close();
        }
    });
});
