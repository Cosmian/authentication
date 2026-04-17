# Regression Testing Policy

## Test Pyramid

### Unit Tests (Vitest + Testing Library, jsdom)

Run: `pnpm test:unit`
Location: `tests/unit/**/*.test.{ts,tsx}`

**Per component, assert ALL of:**

| Category | What to test | Example |
|----------|-------------|---------|
| ✅ Happy path | Renders correctly with valid props | Component shows expected text/elements |
| ❌ Error state | Renders gracefully when API fails | Network error → `message.error()` toast; 403 → inline `<Alert>` |
| 🈳 Empty state | Renders with empty data | No realms → fallback to "Admin"; no users → empty table message |
| ⏳ Loading state | Shows spinner while data loads | `<Spin>` visible before fetch resolves |
| 🚫 Boundary | Handles edge cases | Very long realm names, special characters, unicode, max item counts |
| 🔄 State transition | Correct behavior on prop/context change | Realm switch triggers data refresh; dark mode toggle updates theme |

### Integration Tests (Vitest, node env)

Run: `pnpm test:integration`
Location: `tests/integration/**/*.test.ts`

**Per feature, assert:**

| Category | What to test |
|----------|-------------|
| CRUD round-trip | Create → Read → Update → Delete cycle against real server |
| Error propagation | Server 4xx/5xx → appropriate error surfaced |
| Session expiry | 401 response → redirect to login |
| Concurrent operations | Parallel requests don't corrupt state |

### E2E Tests (Playwright, chromium)

Run: `pnpm test:e2e`
Location: `tests/e2e/**/*.spec.ts`

**Per user journey, assert:**

| Category | What to test |
|----------|-------------|
| Navigation | Page loads, sidebar links work, realm selector changes context |
| Form submission | Fill → submit → success feedback → data persisted |
| Error recovery | Server down → error displayed → server back → recovery |
| Visual state | Dark/light mode toggle, sidebar collapse, responsive layout |

## Naming Convention

```typescript
describe("ComponentName", () => {
    it("should [expected behavior] when [condition]", () => {
        // ...
    });
});
```

## Coverage Targets

| Metric | Target |
|--------|--------|
| Statements | ≥ 80% |
| Branches | ≥ 75% |
| Functions | ≥ 80% |
| Lines | ≥ 80% |

Enforced in CI. New code must not decrease coverage.

## TDD Workflow

1. **Red**: Write test describing desired behavior (include error/edge cases)
2. **Green**: Implement minimal code to pass
3. **Refactor**: Clean up, re-run tests
4. **E2E**: Add after unit tests pass for page-level features
