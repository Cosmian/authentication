# admin-ui E2E tests (Playwright)

End-to-end tests for the authentication `admin-ui`. All backend calls are mocked
with `page.route(...)`, so these tests run against the built preview server
(`pnpm preview`) without a live authentication server.

## Running

```bash
pnpm test:e2e                 # all specs
pnpm exec playwright test <spec-name>
```

## Specs

| Spec                          | Coverage                                                                                                                                                                                                                                                       |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `navigation.spec.ts`          | Sidebar navigation, 404 handling, realm selector, dark-mode toggle.                                                                                                                                                                                            |
| `realms.spec.ts`              | Realms page: create / edit / delete flows.                                                                                                                                                                                                                     |
| `machine-credentials.spec.ts` | Machine Credentials page (super-admin): access gating, AppRole tab (list / create / edit / delete / generate SecretID / empty state), Kubernetes tab (list / create / delete / non-https JWKS rejection), Token tab (lookup / invalid token / renew / revoke). |

## Conventions

- Mock every backend route the page touches (`/whoami`, `/admins/realms`,
  `/public/version`, and the feature endpoints). Use a mutable in-memory store when a
  create/delete flow must be reflected by the subsequent list refetch.
- Prefer role-based locators (`getByRole("cell" | "tab" | "button", ...)`). Use
  `exact: true` or an anchored regex when a substring would match multiple elements
  (e.g. a role name that is also a substring of its `role_id` cell).
- Token self-service endpoints authenticate via the `X-Vault-Token` header, not the
  admin cookie — assert the header is present in their mocks.
