import { describe, it, expect, vi, beforeEach } from "vitest";
import { createRealmsApi } from "../../../src/services/realmsApi";
import type { Realm } from "../../../src/types/api";

const BASE_URL = "https://localhost:8443";

const sampleRealm: Realm = {
    id: "test-realm",
    auth_params: {
        username_password_params: { allow_expired_passwords: false },
        jwt_params: null,
        totp_params: null,
    },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
};

describe("realmsApi", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it("should list realms", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify([sampleRealm]), { status: 200 }),
        );

        const api = createRealmsApi(BASE_URL);
        const result = await api.list();

        expect(result).toEqual([sampleRealm]);
        expect(fetch).toHaveBeenCalledWith(
            `${BASE_URL}/admins/realms`,
            expect.objectContaining({ method: "GET", credentials: "include" }),
        );
    });

    it("should get a single realm", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify(sampleRealm), { status: 200 }),
        );

        const api = createRealmsApi(BASE_URL);
        const result = await api.get("test-realm");

        expect(result).toEqual(sampleRealm);
        expect(fetch).toHaveBeenCalledWith(
            `${BASE_URL}/admins/realms/test-realm`,
            expect.objectContaining({ method: "GET" }),
        );
    });

    it("should create a realm", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify(sampleRealm), { status: 201 }),
        );

        const api = createRealmsApi(BASE_URL);
        const result = await api.create(sampleRealm);

        expect(result).toEqual(sampleRealm);
        expect(fetch).toHaveBeenCalledWith(
            `${BASE_URL}/admins/realms`,
            expect.objectContaining({ method: "POST", body: JSON.stringify(sampleRealm) }),
        );
    });

    it("should update a realm", async () => {
        const updated = { ...sampleRealm, session_max_age_seconds: 7200 };
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify(updated), { status: 200 }),
        );

        const api = createRealmsApi(BASE_URL);
        const result = await api.update("test-realm", updated);

        expect(result.session_max_age_seconds).toBe(7200);
        expect(fetch).toHaveBeenCalledWith(
            `${BASE_URL}/admins/realms/test-realm`,
            expect.objectContaining({ method: "PUT" }),
        );
    });

    it("should delete a realm", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(null, { status: 204 }),
        );

        const api = createRealmsApi(BASE_URL);
        await api.delete("test-realm");

        expect(fetch).toHaveBeenCalledWith(
            `${BASE_URL}/admins/realms/test-realm`,
            expect.objectContaining({ method: "DELETE" }),
        );
    });

    it("should throw ApiError on 404", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify({ message: "Not found" }), { status: 404 }),
        );

        const api = createRealmsApi(BASE_URL);
        await expect(api.get("missing")).rejects.toThrow();
    });

    it("should throw ApiError on 409 conflict", async () => {
        vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
            new Response(JSON.stringify({ message: "Already exists" }), { status: 409 }),
        );

        const api = createRealmsApi(BASE_URL);
        await expect(api.create(sampleRealm)).rejects.toThrow();
    });
});
