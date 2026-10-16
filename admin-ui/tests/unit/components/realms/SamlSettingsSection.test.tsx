import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RealmFormDrawer } from "../../../../src/components/realms/RealmFormDrawer";
import type { Realm } from "../../../../src/types/api";
import { IDP_CERT_PEM, idpMetadata } from "../../fixtures/saml";

vi.mock("../../../../src/contexts/AuthContext", () => ({
    useAuth: () => ({
        isAuthenticated: true,
        username: "admin",
        serverUrl: "",
        loading: false,
        sessionId: null,
        exp: null,
        login: vi.fn(),
        logout: vi.fn(),
    }),
}));

const samlRealm: Realm = {
    id: "acme",
    auth_params: {
        username_password_params: null,
        jwt_params: null,
        totp_params: null,
        saml_params: {
            idp_entity_id: "https://idp.example.com/metadata",
            idp_sso_url: "https://idp.example.com/sso",
            idp_signing_certificates: [IDP_CERT_PEM],
            metadata_xml: idpMetadata(),
            sp_entity_id: "https://auth.example.com/saml/acme",
            sp_acs_url: "https://auth.example.com/saml/acme/acs",
            normalize_subject_case: false,
            attribute_claim_map: {},
            allowed_return_origins: ["https://app.example.com"],
            default_return_url: "https://app.example.com/home",
        },
    },
    session_max_age_seconds: 3600,
    session_max_stale_age_seconds: 1800,
};

async function openDrawer(realm: Realm | null): Promise<void> {
    await act(async () => {
        render(<RealmFormDrawer open={true} realm={realm} onClose={vi.fn()} onSuccess={vi.fn()} />);
    });
}

function saveButton(): HTMLElement {
    const buttons = screen.getAllByRole("button", { name: /^(Save|Create)$/ });
    return buttons[buttons.length - 1];
}

/** Whole-form validation re-parses the metadata on every change, which is slow under jsdom. */
const SLOW = { timeout: 5000 };

/** Make the saved realm dirty, save, and answer with `status` / `body`. */
async function saveWithResponse(status: number, body: string): Promise<void> {
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response(JSON.stringify(body), { status }));
    fireEvent.change(screen.getByLabelText("Role attribute"), { target: { value: "groups" } });
    await waitFor(() => expect(saveButton()).not.toBeDisabled(), SLOW);
    fireEvent.click(saveButton());
}

describe("RealmFormDrawer — SAML", () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    it("shows the saved settings with a preview of the IdP metadata", async () => {
        await openDrawer(samlRealm);

        expect(screen.getByRole("checkbox", { name: "SAML 2.0 (single sign-on)" })).toBeChecked();
        const preview = screen.getByLabelText("Parsed IdP metadata");
        expect(within(preview).getByText("https://idp.example.com/metadata")).toBeInTheDocument();
        expect(within(preview).getByText("user2.acme.com")).toBeInTheDocument();
        expect(within(preview).getByText(/Valid until 2027-04-11/)).toBeInTheDocument();
        expect(screen.getByRole("link", { name: /Download SP metadata/ })).toHaveAttribute("href", "/saml/acme/metadata");
    });

    it("prefills this server's SP URLs when SAML is turned on", async () => {
        await openDrawer(null);
        fireEvent.change(screen.getByLabelText("Realm ID"), { target: { value: "acme" } });
        fireEvent.click(screen.getByRole("checkbox", { name: "SAML 2.0 (single sign-on)" }));

        const origin = window.location.origin;
        await waitFor(() => expect(screen.getByLabelText("Assertion Consumer Service URL")).toHaveValue(`${origin}/saml/acme/acs`), SLOW);
        expect(screen.getByLabelText("SP entity ID")).toHaveValue(`${origin}/saml/acme`);
        expect(screen.getByText(/Save the realm to download/)).toBeInTheDocument();
    });

    it("copies the ACS URL", async () => {
        const writeText = vi.fn().mockResolvedValue(undefined);
        Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
        await openDrawer(samlRealm);

        fireEvent.click(screen.getByRole("button", { name: "Copy ACS URL" }));
        await waitFor(() => expect(writeText).toHaveBeenCalledWith("https://auth.example.com/saml/acme/acs"));
    });

    it("reports invalid metadata under the field and hides the preview", async () => {
        await openDrawer(samlRealm);
        fireEvent.change(screen.getByLabelText("IdP metadata XML"), { target: { value: "<not-xml" } });

        expect(await screen.findByText("the metadata is not well-formed XML", {}, SLOW)).toBeInTheDocument();
        expect(screen.queryByLabelText("Parsed IdP metadata")).not.toBeInTheDocument();
        expect(screen.getByLabelText("IdP metadata XML")).toHaveValue("<not-xml");
    });

    it("rejects a reserved claim name before saving", async () => {
        await openDrawer(samlRealm);
        fireEvent.click(screen.getByRole("button", { name: /Add claim mapping/ }));
        fireEvent.change(screen.getByLabelText("SAML attribute"), { target: { value: "uid" } });
        fireEvent.change(screen.getByLabelText("Claim name"), { target: { value: "sub" } });

        expect(await screen.findByText("'sub' is a reserved claim name", {}, SLOW)).toBeInTheDocument();
        await waitFor(() => expect(saveButton()).toBeDisabled(), SLOW);
    });

    it("rejects return origins that are not bare https origins", async () => {
        await openDrawer(samlRealm);
        const origins = screen.getByLabelText("Allowed return origins");
        fireEvent.change(origins, { target: { value: "http://app.example.com/path" } });
        fireEvent.keyDown(origins, { key: "Enter", code: "Enter" });

        expect(await screen.findByText(/must be an https origin/, {}, SLOW)).toBeInTheDocument();
    });

    it("shows a server validation error on the field it names", async () => {
        await openDrawer(samlRealm);
        await saveWithResponse(400, "Bad Request: saml_params.sp_acs_url: must end with /saml/acme/acs");

        expect(await screen.findByText("must end with /saml/acme/acs", {}, SLOW)).toBeInTheDocument();
        expect(screen.queryByText("The server refused these settings")).not.toBeInTheDocument();
    });

    it("shows other refusals inline, e.g. a server without SAML", async () => {
        await openDrawer(samlRealm);
        await saveWithResponse(400, "Bad Request: SAML is not enabled on this server (built without the `saml` feature)");

        expect(await screen.findByText("The server refused these settings", {}, SLOW)).toBeInTheDocument();
        expect(screen.getByText(/SAML is not enabled on this server/)).toBeInTheDocument();
    });

    it("sends the SAML settings, and null once SAML is turned off", async () => {
        const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify(samlRealm), { status: 200 }));
        await openDrawer(samlRealm);
        fireEvent.click(screen.getByRole("checkbox", { name: "SAML 2.0 (single sign-on)" }));
        await waitFor(() => expect(saveButton()).not.toBeDisabled(), SLOW);
        fireEvent.click(saveButton());

        await waitFor(() => expect(fetchSpy).toHaveBeenCalled(), SLOW);
        const body = JSON.parse(String(fetchSpy.mock.calls[0][1]?.body)) as Realm;
        expect(body.auth_params.saml_params).toBeNull();
    });
});
