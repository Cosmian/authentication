import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(async () => {
    cleanup();
    // React 19 + scheduler@0.27 chains setImmediate callbacks:
    // performWorkUntilDeadline → schedulePerformWorkUntilDeadline → repeat.
    // A single flush is not enough after the antd v6 upgrade which queues more
    // async work; draining eight rounds covers all known cases (bumped from five
    // after a recurrence in RealmContext.test.tsx on CI).
    // If "window is not defined" returns, increase the loop count.
    for (let i = 0; i < 8; i++) {
        await new Promise<void>((resolve) => setImmediate(() => resolve()));
    }
    vi.restoreAllMocks();
});

vi.stubGlobal("localStorage", {
    store: {} as Record<string, string>,
    getItem: vi.fn(function (this: { store: Record<string, string> }, key: string) {
        return this.store[key] ?? null;
    }),
    setItem: vi.fn(function (this: { store: Record<string, string> }, key: string, value: string) {
        this.store[key] = value;
    }),
    removeItem: vi.fn(function (this: { store: Record<string, string> }, key: string) {
        delete this.store[key];
    }),
    clear: vi.fn(function (this: { store: Record<string, string> }) {
        this.store = {};
    }),
});

if (typeof window.matchMedia !== "function") {
    Object.defineProperty(window, "matchMedia", {
        writable: true,
        configurable: true,
        value: (query: string) => ({
            matches: false,
            media: query,
            onchange: null,
            addListener: () => {},
            removeListener: () => {},
            addEventListener: () => {},
            removeEventListener: () => {},
            dispatchEvent: () => false,
        }),
    });
}

if (typeof window.ResizeObserver === "undefined") {
    window.ResizeObserver = class ResizeObserver {
        observe() {}
        unobserve() {}
        disconnect() {}
    };
}

// jsdom doesn't implement getComputedStyle with pseudoElt; rc-util calls it with pseudo elements.
{
    const originalGetComputedStyle = window.getComputedStyle.bind(window);
    window.getComputedStyle = ((elt: Element, pseudoElt?: string | null) => {
        void pseudoElt;
        return originalGetComputedStyle(elt);
    }) as typeof window.getComputedStyle;
}
