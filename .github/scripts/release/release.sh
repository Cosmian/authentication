#!/usr/bin/env bash
# Bump the release version in every versioned file of the repository.
#
# Usage: release.sh <old_version> <new_version>
#
# Writing the CHANGELOG.md entry from CHANGELOG/*.md stays manual.
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "Usage: $0 <old_version> <new_version>" >&2
  exit 1
fi
OLD_VERSION="$1"
NEW_VERSION="$2"

for version in "$OLD_VERSION" "$NEW_VERSION"; do
  if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: '$version' is not an X.Y.Z version" >&2
    exit 1
  fi
done

REPO_ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$REPO_ROOT"

CURRENT_VERSION=$(bash .github/scripts/release/get_version.sh)
if [ "$CURRENT_VERSION" != "$OLD_VERSION" ]; then
  echo "Error: Cargo.toml is at $CURRENT_VERSION, not $OLD_VERSION" >&2
  exit 1
fi

OLD_RE="${OLD_VERSION//./\\.}"

# Fail when a file no longer changes, so this list cannot silently go stale.
replace() {
  local file="$1" expression="$2" tmp
  tmp=$(mktemp)
  sed -e "$expression" "$file" >"$tmp"
  if cmp -s "$file" "$tmp"; then
    rm -f "$tmp"
    echo "Error: no $OLD_VERSION to replace in $file; update $0" >&2
    exit 1
  fi
  cat "$tmp" >"$file"
  rm -f "$tmp"
  echo "  $file"
}

echo "Bumping $OLD_VERSION -> $NEW_VERSION"

# Anchored: third-party crates may share the version number.
replace Cargo.toml "s/^version = \"$OLD_RE\"/version = \"$NEW_VERSION\"/"
replace server/Cargo.toml "/^auth_client = /s/version = \"$OLD_RE\"/version = \"$NEW_VERSION\"/"

replace admin-ui/package.json "s/^\( *\"version\": \)\"$OLD_RE\"/\1\"$NEW_VERSION\"/"
replace e2e/package.json "s/^\( *\"version\": \)\"$OLD_RE\"/\1\"$NEW_VERSION\"/"

# Chart version, appVersion and the Artifact Hub image tags
replace charts/cosmian-auth-verifier/Chart.yaml "s/$OLD_RE/$NEW_VERSION/g"

# Only the workspace crates' entries; sed would also hit dependencies sharing the version.
cargo update --workspace --quiet
echo "  Cargo.lock"

LEFTOVERS=$(git grep -n -F "$OLD_VERSION" -- . \
  ':!CHANGELOG.md' ':!CHANGELOG/' ':!SECURITY.md' ':!Cargo.lock' ':!*pnpm-lock.yaml' \
  ':!admin-ui/tests/' || true)
if [ -n "$LEFTOVERS" ]; then
  echo "Warning: $OLD_VERSION still appears below; bump it by hand and add the file to $0 if needed:"
  echo "$LEFTOVERS"
fi

if ! grep -q "^## \[$NEW_VERSION\]" CHANGELOG.md; then
  echo "Warning: CHANGELOG.md has no '## [$NEW_VERSION]' entry: write it from CHANGELOG/*.md."
fi
if compgen -G "CHANGELOG/*.md" >/dev/null; then
  echo "Warning: CHANGELOG/ still holds entries: fold them into CHANGELOG.md and delete them."
fi
