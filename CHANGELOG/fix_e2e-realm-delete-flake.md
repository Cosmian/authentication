## Tests

- The admin UI E2E test that deletes a realm now checks the realm cards instead of any text on the page, because the confirm modal and the success toast also show the realm name, so on a slow runner the page-wide match found several elements and failed at once with a strict-mode violation.

## Docs

- The admin UI E2E conventions now require scoped locators (card, row or cell) for assertions after a create, update or delete, and `admin-ui/CLAUDE.md` points agents to those conventions when they add E2E tests.
