import { http, HttpResponse } from "msw";
import { API_REALMS, API_VERSION } from "../constants/apiPaths";
import type { Realm } from "../types/api";
import { mockRealms, mockVersion } from "./fixtures";

// In-memory store so CRUD is reflected immediately in dev mode
let realmsStore: Realm[] = [...mockRealms];

export const resetRealmsStore = (): void => {
    realmsStore = [...mockRealms];
};

export const handlers = [
    // Version
    http.get(API_VERSION, () => HttpResponse.json(mockVersion)),

    // List realms
    http.get(API_REALMS, () => HttpResponse.json(realmsStore)),

    // Get realm by ID
    http.get(`${API_REALMS}/:realmId`, ({ params }) => {
        const realm = realmsStore.find((r) => r.id === params.realmId);
        if (!realm) {
            return HttpResponse.json({ message: `Realm '${params.realmId}' not found` }, { status: 404 });
        }
        return HttpResponse.json(realm);
    }),

    // Create realm
    http.post(API_REALMS, async ({ request }) => {
        const body = (await request.json()) as Realm;
        if (realmsStore.some((r) => r.id === body.id)) {
            return HttpResponse.json({ message: `Realm '${body.id}' already exists` }, { status: 409 });
        }
        realmsStore.push(body);
        return HttpResponse.json(body, { status: 201 });
    }),

    // Update realm
    http.put(`${API_REALMS}/:realmId`, async ({ params, request }) => {
        const index = realmsStore.findIndex((r) => r.id === params.realmId);
        if (index === -1) {
            return HttpResponse.json({ message: `Realm '${params.realmId}' not found` }, { status: 404 });
        }
        const body = (await request.json()) as Realm;
        realmsStore[index] = { ...body, id: params.realmId as string };
        return HttpResponse.json(realmsStore[index]);
    }),

    // Delete realm
    http.delete(`${API_REALMS}/:realmId`, ({ params }) => {
        const index = realmsStore.findIndex((r) => r.id === params.realmId);
        if (index === -1) {
            return HttpResponse.json({ message: `Realm '${params.realmId}' not found` }, { status: 404 });
        }
        realmsStore.splice(index, 1);
        return new HttpResponse(null, { status: 204 });
    }),
];