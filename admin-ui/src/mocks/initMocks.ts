type MockEnvironment = Pick<ImportMetaEnv, "DEV" | "VITE_USE_MOCKS">;

export const shouldUseMocks = (env: MockEnvironment): boolean => env.DEV && env.VITE_USE_MOCKS === "true";

export const startMockWorker = async (): Promise<void> => {
    const { worker } = await import("./browser");

    await worker.start({
        onUnhandledRequest: "bypass",
        // The app uses root-relative API paths such as /admin/realms.
        // Register the worker at the origin root so it can intercept them in dev.
        serviceWorker: {
            url: "/mockServiceWorker.js",
        },
    });
};

export const initializeMocking = async (
    env: MockEnvironment = import.meta.env,
    startWorker: () => Promise<void> = startMockWorker,
): Promise<void> => {
    if (!shouldUseMocks(env)) {
        return;
    }

    await startWorker();
};