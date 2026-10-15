import { execFileSync } from "node:child_process";
import { expect, type Page, type Request } from "@playwright/test";

export const SP_ORIGIN = `https://127.0.0.1:${process.env.SP_PORT ?? "8443"}`;
export const IDP_ORIGIN = `https://127.0.0.1:${process.env.IDP_PORT ?? "9443"}`;
export const IDP_ENTITY_ID = `${IDP_ORIGIN}/realms/demo`;
export const IDP_METADATA_URL = `${IDP_ENTITY_ID}/protocol/saml/descriptor`;
const IDP_CONTAINER = process.env.SAML_E2E_IDP_CONTAINER ?? "saml-e2e-idp";

/** SAML realm created by stack.sh through the admin API. */
export const SEEDED_REALM = process.env.SP_REALM ?? "sso-demo";
/** SAML realm the admin UI test creates; Keycloak already has its client. */
export const UI_REALM = process.env.SP_UI_REALM ?? "sso-ui";

export const ALICE = { username: "alice", password: "alice-pw" };
export const ADMIN = { username: "admin", password: "change_me" };

export type Claims = Record<string, unknown> & { sub: string; as_as: string; as_rid: string; roles?: string[] };

export function acsPath(realm: string): string {
    return `/saml/${realm}/acs`;
}

export function isAcsPost(request: Request, realm: string): boolean {
    return request.method() === "POST" && new URL(request.url()).pathname === acsPath(realm);
}

export async function submitKeycloakLogin(page: Page, username: string, password: string): Promise<void> {
    await expect(page).toHaveURL((url) => url.href.startsWith(`${IDP_ENTITY_ID}/`));
    await page.locator("#username").fill(username);
    await page.locator("#password").fill(password);
    await page.locator("#kc-login").click();
}

/** Start an SP-initiated login on `realm`, sign in at Keycloak as alice, and return the `/whoami` claims. */
export async function signInAsAlice(page: Page, realm: string): Promise<Claims> {
    await page.goto(`/saml/${realm}/login`);
    const whoami = page.waitForResponse((r) => new URL(r.url()).pathname === "/whoami");
    await submitKeycloakLogin(page, ALICE.username, ALICE.password);
    const response = await whoami;
    expect(response.status()).toBe(200);
    return (await response.json()) as Claims;
}

function kcadm(...args: string[]): string {
    return execFileSync("docker", ["exec", IDP_CONTAINER, "/opt/keycloak/bin/kcadm.sh", ...args], { encoding: "utf8" });
}

/** Turn Keycloak's assertion signing on or off for the SAML client of `realm`. */
export function setAssertionSigning(realm: string, enabled: boolean): void {
    kcadm("config", "credentials", "--server", "http://localhost:8080", "--realm", "master", "--user", "admin", "--password", "admin");
    const clientId = `${SP_ORIGIN}/saml/${realm}`;
    const id = kcadm(
        "get",
        "clients",
        "-r",
        "demo",
        "-q",
        `clientId=${clientId}`,
        "--fields",
        "id",
        "--format",
        "csv",
        "--noquotes",
    ).trim();
    if (!id) throw new Error(`Keycloak has no client ${clientId}`);
    kcadm("update", `clients/${id}`, "-r", "demo", "-s", `attributes."saml.assertion.signature"=${enabled}`);
}
