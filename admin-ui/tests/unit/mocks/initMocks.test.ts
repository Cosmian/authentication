import { describe, expect, it, vi } from "vitest";
import { initializeMocking, shouldUseMocks } from "../../../src/mocks/initMocks";

describe("initMocks", () => {
    it("should enable mocks only in dev when explicitly requested", () => {
        expect(shouldUseMocks({ DEV: true, VITE_USE_MOCKS: "true" })).toBe(true);
        expect(shouldUseMocks({ DEV: true, VITE_USE_MOCKS: "false" })).toBe(false);
        expect(shouldUseMocks({ DEV: false, VITE_USE_MOCKS: "true" })).toBe(false);
    });

    it("should start the worker when mock mode is enabled", async () => {
        const startWorker = vi.fn().mockResolvedValue(undefined);

        await initializeMocking({ DEV: true, VITE_USE_MOCKS: "true" }, startWorker);

        expect(startWorker).toHaveBeenCalledOnce();
    });

    it("should skip the worker when mock mode is disabled", async () => {
        const startWorker = vi.fn().mockResolvedValue(undefined);

        await initializeMocking({ DEV: true, VITE_USE_MOCKS: undefined }, startWorker);

        expect(startWorker).not.toHaveBeenCalled();
    });
});