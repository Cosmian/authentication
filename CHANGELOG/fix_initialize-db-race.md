## Bug Fixes

- Make the first-start database seeding idempotent: several instances starting together on one empty MySQL/PostgreSQL database no longer fail with `realm '_' already exists`. An insert that loses the race counts as success only when the row now exists; a `remove_me` login already taken by another admin still fails start-up.
