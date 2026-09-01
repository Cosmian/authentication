## Features

- `CredentialModal` (create mode): added a plaintext/pre-hashed password toggle (`PasswordFields`) so an admin can provision a credential from an already-computed Argon2 PHC string instead of a plaintext password, and a key/value extra-claims editor (`ExtraClaimsEditor`) for `UserPass.extra_claims`, matching the new server-side `hashed_password`/`extra_claims` fields.

## Bug Fixes

- `CredentialModal`'s roles-fetch effect had no unmount guard: if the `list()` call resolved after the modal/component was torn down, the resulting `setAvailableRoles` call could fire against a dead environment. Added the same `cancelled` guard already used by the form-validity effect right below it.
