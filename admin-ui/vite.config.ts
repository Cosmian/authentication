import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vite";

const authTarget = process.env.VITE_AUTH_URL ?? "https://localhost:8443";

const proxyOpts = { target: authTarget, secure: false, changeOrigin: true };
const apiProxy: Record<string, { target: string; secure: boolean; changeOrigin: boolean }> = {
    "/login": proxyOpts,
    "/whoami": proxyOpts,
    "/sessions": proxyOpts,
    "/realms": proxyOpts,
    "/admins": proxyOpts,
    "/public": proxyOpts,
};

export default defineConfig(({ mode }) => ({
    base: "/admin-ui",
    plugins: [react(), tailwindcss()],
    build: {
        chunkSizeWarningLimit: 1600,
    },
    server: {
        // In mock mode the browser-side MSW worker intercepts all API requests,
        // so the Vite proxy must be disabled to prevent connection attempts to the
        // real auth server before MSW can handle them.
        proxy: mode === "mock" ? {} : apiProxy,
    },
    preview: {
        proxy: mode === "mock" ? {} : apiProxy,
    },
}));
