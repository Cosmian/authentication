## Bug Fixes

- Make the first-start database seeding idempotent: several instances starting together on one empty MySQL/PostgreSQL database no longer fail with `realm '_' already exists`; an insert that loses the race is treated as success.
