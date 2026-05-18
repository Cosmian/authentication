import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { BrandingProvider } from "./contexts/BrandingProvider";
import { applyBrandingToDocument, loadBranding } from "./utils/branding";

const bootstrap = async (): Promise<void> => {
    const branding = await loadBranding();
    applyBrandingToDocument(branding);

    ReactDOM.createRoot(document.getElementById("root")!).render(
        <React.StrictMode>
            <BrandingProvider branding={branding}>
                <BrowserRouter basename="/admin-ui">
                    <App />
                </BrowserRouter>
            </BrandingProvider>
        </React.StrictMode>,
    );
};

void bootstrap();
