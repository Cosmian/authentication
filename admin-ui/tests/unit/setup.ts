import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { message } from "antd";
import { afterEach, vi } from "vitest";

// antd's static `message.*` mounts its own React root outside Testing Library's cleanup, so its
// commits and passive-effect flushes can fire after jsdom is torn down ("window is not defined").
// No test asserts on these toasts, so make them no-ops. Assigned directly because the tests'
// vi.restoreAllMocks() would undo a vi.spyOn.
{
    const noop = () => Object.assign(() => {}, { then: (resolve?: () => void) => Promise.resolve().then(resolve) });
    for (const method of ["success", "error", "warning", "info", "loading", "open"] as const) {
        (message as unknown as Record<string, unknown>)[method] = noop;
    }
}

afterEach(async () => {
    cleanup();
    // React 19 + scheduler@0.27 chains setImmediate callbacks:
    // performWorkUntilDeadline → schedulePerformWorkUntilDeadline → repeat.
    // A single flush is not enough after the antd v6 upgrade which queues more
    // async work; draining rounds covers all known cases (bumped from five to
    // eight after a recurrence in RealmContext.test.tsx, then to sixteen after
    // a recurrence in CredentialModal.test.tsx's Form.List-driven claim editor).
    // A fixed round count is load-dependent (it recurred on slow CI runners), so also keep
    // yielding for a minimum wall-clock time, which lets short timers (antd/rc-motion,
    // form validation) fire and the scheduler go idle before jsdom is torn down.
    const settleUntil = Date.now() + 50;
    for (let i = 0; i < 16 || Date.now() < settleUntil; i++) {
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
