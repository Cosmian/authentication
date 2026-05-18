import type { ThemeConfig } from "antd";

export type MenuTheme = "light" | "dark";

export type Branding = {
    title: string;
    faviconUrl?: string;

    logoAlt: string;
    logoLightUrl: string;
    logoDarkUrl: string;

    loginTitle: string;
    loginSubtitle?: string;
    backgroundImageUrl: string;
    /** CSS color for the translucent card overlaid on the login background.
     *  Accepts any CSS color value, e.g. "rgba(126,34,206,0.3)" or "#7e22ce4d". */
    loginCardColor?: string;

    menuTheme?: MenuTheme;

    tokens?: {
        light?: ThemeConfig["token"];
        dark?: ThemeConfig["token"];
    };
};

const DEFAULT_BRANDING: Branding = {
    title: "Auth Admin",
    faviconUrl: "",

    logoAlt: "Authentication Server",
    logoLightUrl: "",
    logoDarkUrl: "",

    loginTitle: "Auth Admin",
    loginSubtitle: "",
    backgroundImageUrl: "",
    loginCardColor: "",

    menuTheme: "light",

    tokens: {
        light: {
            colorPrimary: "#e34319",
            colorText: "#292f52",
        },
        dark: {
            colorPrimary: "#9e6eff",
            colorText: "#e4dddd",
            colorBgBase: "#2a2d30",
        },
    },
};

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null;
}

function mergeBranding(defaults: Branding, overrides: Partial<Branding>): Branding {
    return {
        ...defaults,
        ...overrides,
        tokens: {
            light: {
                ...(defaults.tokens?.light ?? {}),
                ...(overrides.tokens?.light ?? {}),
            },
            dark: {
                ...(defaults.tokens?.dark ?? {}),
                ...(overrides.tokens?.dark ?? {}),
            },
        },
    };
}

export async function loadBranding(options?: { url?: string; cacheBust?: boolean }): Promise<Branding> {
    const url = options?.url ?? "/admin-ui/branding.json";
    const cacheBust = options?.cacheBust ?? true;

    const fetchUrl = cacheBust ? `${url}?v=${encodeURIComponent(String(Date.now()))}` : url;

    try {
        const response = await fetch(fetchUrl, { cache: "no-store" });
        if (!response.ok) {
            return DEFAULT_BRANDING;
        }
        const parsed: unknown = await response.json();
        if (!isRecord(parsed)) {
            return DEFAULT_BRANDING;
        }
        return mergeBranding(DEFAULT_BRANDING, parsed as Partial<Branding>);
    } catch {
        return DEFAULT_BRANDING;
    }
}

export function applyBrandingToDocument(branding: Branding): void {
    if (branding.title) {
        document.title = branding.title;
    }

    if (branding.faviconUrl) {
        const link =
            document.querySelector<HTMLLinkElement>("link[rel='icon']") ?? document.createElement("link");
        link.rel = "icon";
        link.href = branding.faviconUrl;
        document.head.appendChild(link);
    }
}
