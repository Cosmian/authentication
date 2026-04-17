import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(() => {
    cleanup();
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
    window.getComputedStyle = ((elt: Element, _pseudoElt?: string | null) => { // eslint-disable-line @typescript-eslint/no-unused-vars
        return originalGetComputedStyle(elt);
    }) as typeof window.getComputedStyle;
}
