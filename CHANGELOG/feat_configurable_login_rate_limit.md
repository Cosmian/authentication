## Features

- `POST /login`'s per-IP rate limiter is now configurable via `ServerParams::login_rate_limit_per_second` / `login_rate_limit_burst` (both optional, default to the previous hardcoded values: 5 req/s, burst of 10).
