import { http, HttpResponse } from "msw";
import { API_ADMINS, API_LOGIN, API_REALMS, API_SESSIONS, API_SESSIONS_EXPIRED, API_VERSION, API_WHOAMI } from "../constants/apiPaths";
import type { Admin, Realm, TotpGenerateRequest, TotpVerifyRequest, UserPass } from "../types/api";
import { mockAdmins, mockCredentials, mockLoginSuccess, mockRealms, mockTotpGenerate, mockVersion, mockWhoamiClaims } from "./fixtures";

// In-memory stores so CRUD is reflected immediately in dev mode
let realmsStore: Realm[] = [...mockRealms];
let adminsStore: Admin[] = [...mockAdmins];
let credentialsStore: Record<string, UserPass[]> = JSON.parse(JSON.stringify(mockCredentials));

export const resetRealmsStore = (): void => {
    realmsStore = [...mockRealms];
};

export const resetAdminsStore = (): void => {
    adminsStore = [...mockAdmins];
};

export const resetCredentialsStore = (): void => {
    credentialsStore = JSON.parse(JSON.stringify(mockCredentials));
};

export const handlers = [
    // ── Public ──────────────────────────────────────────────────
    http.get(API_VERSION, () => HttpResponse.json(mockVersion)),

    // ── Auth ────────────────────────────────────────────────────
    http.post(API_LOGIN, () => HttpResponse.json(mockLoginSuccess)),

    http.get(API_WHOAMI, () => {
        // Switch the mock user via: VITE_MOCK_USER=alice pnpm dev
        // Supported values: "admin" (super-admin, default), "alice" (realm-admin: my-service), "bob" (realm-admin: my-service + internal-app)
        const mockUserId = import.meta.env.VITE_MOCK_USER ?? "admin";
        const mockAdmin = adminsStore.find((a) => a.id === mockUserId) ?? adminsStore[0];
        const isSuperAdmin = mockAdmin.realms.includes("_");
        return HttpResponse.json({
            ...mockWhoamiClaims,
            sub: mockAdmin.id,
            aud: mockAdmin.realms,
            as_rid: isSuperAdmin ? "_" : mockAdmin.realms[0],
            exp: Math.floor(Date.now() / 1000) + 86400,
            iat: Math.floor(Date.now() / 1000),
        });
    }),

    // ── Sessions ────────────────────────────────────────────────
    http.delete(API_SESSIONS, () => new HttpResponse(null, { status: 204 })),

    http.delete(API_SESSIONS_EXPIRED, () => new HttpResponse(null, { status: 204 })),

    http.delete(`${API_SESSIONS}/realms/:realmId`, () => new HttpResponse(null, { status: 204 })),

    // ── Realms ──────────────────────────────────────────────────
    http.get(API_REALMS, () => HttpResponse.json(realmsStore)),

    http.get(`${API_REALMS}/:realmId`, ({ params }) => {
        const realm = realmsStore.find((r) => r.id === params.realmId);
        if (!realm) {
            return HttpResponse.json({ message: `Realm '${params.realmId}' not found` }, { status: 404 });
        }
        return HttpResponse.json(realm);
    }),

    http.post(API_REALMS, async ({ request }) => {
        const body = (await request.json()) as Realm;
        if (realmsStore.some((r) => r.id === body.id)) {
            return HttpResponse.json({ message: `Realm '${body.id}' already exists` }, { status: 409 });
        }
        realmsStore.push(body);
        return HttpResponse.json(body, { status: 201 });
    }),

    http.put(`${API_REALMS}/:realmId`, async ({ params, request }) => {
        const index = realmsStore.findIndex((r) => r.id === params.realmId);
        if (index === -1) {
            return HttpResponse.json({ message: `Realm '${params.realmId}' not found` }, { status: 404 });
        }
        const body = (await request.json()) as Realm;
        realmsStore[index] = { ...body, id: params.realmId as string };
        return HttpResponse.json(realmsStore[index]);
    }),

    http.delete(`${API_REALMS}/:realmId`, ({ params }) => {
        const index = realmsStore.findIndex((r) => r.id === params.realmId);
        if (index === -1) {
            return HttpResponse.json({ message: `Realm '${params.realmId}' not found` }, { status: 404 });
        }
        realmsStore.splice(index, 1);
        return new HttpResponse(null, { status: 204 });
    }),

    // ── Admins ──────────────────────────────────────────────────
    http.get(API_ADMINS, () => HttpResponse.json(adminsStore)),

    http.get(`${API_ADMINS}/:adminId`, ({ params }) => {
        const admin = adminsStore.find((a) => a.id === params.adminId);
        if (!admin) {
            return HttpResponse.json({ message: `Admin '${params.adminId}' not found` }, { status: 404 });
        }
        return HttpResponse.json(admin);
    }),

    http.post(API_ADMINS, async ({ request }) => {
        const body = (await request.json()) as Admin;
        if (adminsStore.some((a) => a.id === body.id)) {
            return HttpResponse.json({ message: `Admin '${body.id}' already exists` }, { status: 409 });
        }
        adminsStore.push(body);
        return HttpResponse.json(body, { status: 201 });
    }),

    http.put(`${API_ADMINS}/:adminId`, async ({ params, request }) => {
        const index = adminsStore.findIndex((a) => a.id === params.adminId);
        if (index === -1) {
            return HttpResponse.json({ message: `Admin '${params.adminId}' not found` }, { status: 404 });
        }
        const body = (await request.json()) as Admin;
        adminsStore[index] = { ...body, id: params.adminId as string };
        return HttpResponse.json(adminsStore[index]);
    }),

    http.delete(`${API_ADMINS}/:adminId`, ({ params }) => {
        const index = adminsStore.findIndex((a) => a.id === params.adminId);
        if (index === -1) {
            return HttpResponse.json({ message: `Admin '${params.adminId}' not found` }, { status: 404 });
        }
        adminsStore.splice(index, 1);
        return new HttpResponse(null, { status: 204 });
    }),

    http.put(`${API_ADMINS}/:adminId/realms/:realmId`, ({ params }) => {
        const admin = adminsStore.find((a) => a.id === params.adminId);
        if (!admin) {
            return HttpResponse.json({ message: `Admin '${params.adminId}' not found` }, { status: 404 });
        }
        const realmId = params.realmId as string;
        if (!admin.realms.includes(realmId)) {
            admin.realms.push(realmId);
        }
        return HttpResponse.json(admin);
    }),

    http.delete(`${API_ADMINS}/:adminId/realms/:realmId`, ({ params }) => {
        const admin = adminsStore.find((a) => a.id === params.adminId);
        if (!admin) {
            return HttpResponse.json({ message: `Admin '${params.adminId}' not found` }, { status: 404 });
        }
        admin.realms = admin.realms.filter((r) => r !== params.realmId);
        return HttpResponse.json(admin);
    }),

    // ── Credentials (UserPass) ──────────────────────────────────
    http.get("/realms/:realmId/userpass", ({ params }) => {
        const realmId = params.realmId as string;
        return HttpResponse.json(credentialsStore[realmId] ?? []);
    }),

    http.get("/realms/:realmId/userpass/:username", ({ params }) => {
        const realmId = params.realmId as string;
        const cred = (credentialsStore[realmId] ?? []).find((c) => c.username === params.username);
        if (!cred) {
            return HttpResponse.json({ message: `Credential '${params.username}' not found` }, { status: 404 });
        }
        return HttpResponse.json(cred);
    }),

    http.post("/realms/:realmId/userpass", async ({ params, request }) => {
        const realmId = params.realmId as string;
        const body = (await request.json()) as UserPass;
        if (!credentialsStore[realmId]) credentialsStore[realmId] = [];
        if (credentialsStore[realmId].some((c) => c.username === body.username)) {
            return HttpResponse.json({ message: `Credential '${body.username}' already exists` }, { status: 409 });
        }
        const entry: UserPass = { ...body, realm: realmId, password: [] };
        credentialsStore[realmId].push(entry);
        return HttpResponse.json(entry, { status: 201 });
    }),

    http.put("/realms/:realmId/userpass/:username", async ({ params, request }) => {
        const realmId = params.realmId as string;
        const store = credentialsStore[realmId] ?? [];
        const index = store.findIndex((c) => c.username === params.username);
        if (index === -1) {
            return HttpResponse.json({ message: `Credential '${params.username}' not found` }, { status: 404 });
        }
        const body = (await request.json()) as UserPass;
        store[index] = { ...body, realm: realmId, username: params.username as string, password: [] };
        return HttpResponse.json(store[index]);
    }),

    http.delete("/realms/:realmId/userpass/:username", ({ params }) => {
        const realmId = params.realmId as string;
        const store = credentialsStore[realmId] ?? [];
        const index = store.findIndex((c) => c.username === params.username);
        if (index === -1) {
            return HttpResponse.json({ message: `Credential '${params.username}' not found` }, { status: 404 });
        }
        store.splice(index, 1);
        return new HttpResponse(null, { status: 204 });
    }),

    // ── TOTP ────────────────────────────────────────────────────
    http.post("/realms/:realmId/totp/generate", async ({ request }) => {
        const body = (await request.json()) as TotpGenerateRequest;
        return HttpResponse.json({
            ...mockTotpGenerate,
            otpauth_url: mockTotpGenerate.otpauth_url.replace("user1", body.username),
        });
    }),

    http.post("/realms/:realmId/totp/verify", async ({ request }) => {
        const body = (await request.json()) as TotpVerifyRequest;
        // In mock mode, any 6-digit code succeeds
        if (body.code.length === 6) {
            // Toggle totp_enabled for the admin if found
            const admin = adminsStore.find((a) => a.id === body.username || a.userpass === body.username);
            if (admin) admin.totp_enabled = true;
            return new HttpResponse(null, { status: 200 });
        }
        return HttpResponse.json({ message: "Invalid TOTP code" }, { status: 400 });
    }),

    http.delete("/realms/:realmId/totp/:username", ({ params }) => {
        const admin = adminsStore.find(
            (a) => a.id === params.username || a.userpass === params.username,
        );
        if (admin) admin.totp_enabled = false;
        return new HttpResponse(null, { status: 200 });
    }),
];