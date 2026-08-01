import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(async () => {
    cleanup();
    // React 19's scheduler may queue setImmediate callbacks during unmount.
    // In CI environments those can fire after jsdom begins tearing down,
    // causing "window is not defined". Flushing the event loop here prevents it.
    await new Promise<void>((resolve) => setImmediate(() => resolve()));
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
