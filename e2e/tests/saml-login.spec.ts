import { expect, test } from "@playwright/test";
import { ALICE, SEEDED_REALM, SP_ORIGIN, acsPath, isAcsPost, setAssertionSigning, signInAsAlice, submitKeycloakLogin } from "./support";

test.describe("SAML login through Keycloak", () => {
    test("alice signs in and gets a SAML session with her mapped claims", async ({ page }) => {
        const claims = await signInAsAlice(page, SEEDED_REALM);

        expect(page.url()).toBe(`${SP_ORIGIN}/whoami?realm=${SEEDED_REALM}`);
        expect(claims).toMatchObject({ sub: "alice", as_as: "sa", as_rid: SEEDED_REALM, mail: "alice@example.com" });
        expect(claims.roles).toEqual(expect.arrayContaining(["admins", "users"]));

        const session = (await page.context().cookies(SP_ORIGIN)).find((c) => c.name === "_ea_");
        expect(session).toMatchObject({ httpOnly: true, secure: true });
    });

    test("the browser lands on the requested return URL", async ({ page }) => {
        const returnTo = `${SP_ORIGIN}/public/version`;
        await page.goto(`/saml/${SEEDED_REALM}/login?return_to=${encodeURIComponent(returnTo)}`);
        await submitKeycloakLogin(page, ALICE.username, ALICE.password);

        await expect(page).toHaveURL(returnTo);
    });

    test("a wrong password at Keycloak creates no session", async ({ page }) => {
        await page.goto(`/saml/${SEEDED_REALM}/login`);
        await submitKeycloakLogin(page, ALICE.username, "wrong-password");

        await expect(page.getByText("Invalid username or password.")).toBeVisible();
        expect((await page.context().cookies(SP_ORIGIN)).some((c) => c.name === "_ea_")).toBe(false);
    });

    test("a captured SAML response cannot be used again", async ({ page, request }) => {
        const acsRequest = page.waitForRequest((r) => isAcsPost(r, SEEDED_REALM));
        await signInAsAlice(page, SEEDED_REALM);
        const form = new URLSearchParams((await acsRequest).postData() ?? "");
        const relayState = form.get("RelayState") ?? "";
        expect(form.get("SAMLResponse")).toBeTruthy();

        // Replay it with the login cookie the browser had, as an attacker who copied both would.
        const replay = await request.post(acsPath(SEEDED_REALM), {
            headers: { Cookie: `_ea_saml=${relayState}` },
            form: { SAMLResponse: form.get("SAMLResponse") ?? "", RelayState: relayState },
        });

        expect(replay.status()).toBe(401);
        expect(await replay.text()).toContain("unknown or expired sign-in request");
        expect(replay.headers()["set-cookie"] ?? "").not.toContain("_ea_=");
    });

    test.describe("when Keycloak stops signing assertions", () => {
        test.afterEach(() => setAssertionSigning(SEEDED_REALM, true));

        test("the login is refused", async ({ page }) => {
            setAssertionSigning(SEEDED_REALM, false);
            await page.goto(`/saml/${SEEDED_REALM}/login`);
            const acs = page.waitForResponse((r) => isAcsPost(r.request(), SEEDED_REALM));
            await submitKeycloakLogin(page, ALICE.username, ALICE.password);

            const response = await acs;
            expect(response.status()).toBe(401);
            expect(await response.text()).toContain("must be signed");
            expect((await page.context().cookies(SP_ORIGIN)).some((c) => c.name === "_ea_")).toBe(false);
        });
    });
});
