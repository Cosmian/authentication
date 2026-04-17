import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { initializeMocking } from "./mocks/initMocks";

const renderApp = (): void => {
    ReactDOM.createRoot(document.getElementById("root")!).render(
        <React.StrictMode>
            <BrowserRouter basename="/admin-ui">
                <App />
            </BrowserRouter>
        </React.StrictMode>,
    );
};

const bootstrap = async (): Promise<void> => {
    try {
        await initializeMocking();
    } finally {
        renderApp();
    }
};

void bootstrap();
