import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router";
import App from "./App";
import { ThemeProvider } from "./contexts/ThemeProvider";
import { applyBrandingToDocument, loadBranding } from "./utils/branding";

const bootstrap = async (): Promise<void> => {
    const branding = await loadBranding();
    applyBrandingToDocument(branding);

    ReactDOM.createRoot(document.getElementById("root")!).render(
        <React.StrictMode>
            <ThemeProvider branding={branding}>
                <BrowserRouter basename="/admin-ui">
                    <App />
                </BrowserRouter>
            </ThemeProvider>
        </React.StrictMode>,
    );
};

void bootstrap();
