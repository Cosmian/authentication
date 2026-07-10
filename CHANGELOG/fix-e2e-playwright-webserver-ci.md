## Bug Fixes

- Fixed E2E tests failing in CI with `ERR_CONNECTION_REFUSED` on port 4173 by always including the Playwright `webServer` config (instead of excluding it when `CI=true`), so the preview server is started before tests run in the pipeline.
