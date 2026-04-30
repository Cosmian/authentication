type MockEnvironment = Pick<ImportMetaEnv, "DEV" | "VITE_USE_MOCKS">;

export const shouldUseMocks = (env: MockEnvironment): boolean => env.DEV && env.VITE_USE_MOCKS === "true";

export const startMockWorker = async (): Promise<void> => {
    const { worker } = await import("./browser");

    await worker.start({
        onUnhandledRequest: "bypass",
        // Vite serves public/ assets under the base path (/admin-ui/).
        // The service worker must be registered there to intercept fetch requests.
        serviceWorker: {
            url: "/admin-ui/mockServiceWorker.js",
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