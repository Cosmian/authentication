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
    "/auth": proxyOpts,
    "/public": proxyOpts,
};

export default defineConfig(() => ({
    base: "/admin-ui",
    plugins: [react(), tailwindcss()],
    build: {
        chunkSizeWarningLimit: 1600,
    },
    server: {
        proxy: apiProxy,
    },
    preview: {
        proxy: apiProxy,
    },
}));
