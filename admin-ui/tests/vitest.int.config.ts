import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react-swc";
import { defineConfig } from "vitest/config";

export default defineConfig({
    plugins: [react(), tailwindcss()],
    test: {
        server: {
            deps: {
                inline: ["react-router", "react-router-dom"],
            },
        },
        environment: "node",
        include: ["./tests/integration/**/*.test.ts"],
        passWithNoTests: true,
        testTimeout: 120_000,
        hookTimeout: 300_000,
    },
});
