# License overrides

`scripts/bundle-licenses.mjs` fails the build when a production dependency
ships no LICENSE file in its npm tarball. Some packages do that even though
their declared license requires reproducing a copyright notice (MIT, BSD,
Apache 2.0, etc.). For those, drop the upstream LICENSE text into this
directory and the bundler will use it.

## Filename convention

`<package-name-with-/-replaced-by-+>.txt`. Examples:

- `abstract-logging` → `abstract-logging.txt`
- `@cbor-extract/cbor-extract-darwin-arm64` → `@cbor-extract+cbor-extract-darwin-arm64.txt`

When several packages share one upstream LICENSE (e.g. platform-binary fan-outs
like `@cbor-extract/cbor-extract-<platform>`), store the text once in a
`_<group>.LICENSE.txt` file (leading underscore — no real package slugs to it)
and symlink each per-package filename at it. Keeps the bundler's exact-name
lookup intact while avoiding duplicated copies in the repo.

## Content convention

Verbatim upstream LICENSE text. No comments, no headers — the file's
contents are inlined directly into `THIRD_PARTY_LICENSES`. If upstream
ships **no** LICENSE file (declared license in `package.json` only, no
notice text exists), synthesize the standard SPDX template using the
`author` field from `package.json` as the copyright holder.

## Audit trail

When you add or update an override, drop a one-line note in this file
with the source URL so future maintainers can re-verify:

- `_cbor-extract.LICENSE.txt` — <https://github.com/kriszyp/cbor-extract/blob/master/LICENSE>. Shared by all `@cbor-extract/cbor-extract-<platform>` symlinks (darwin-arm64, darwin-x64, linux-arm, linux-arm64, linux-x64, win32-x64).
- `abstract-logging.txt` — synthesized; upstream <https://github.com/jsumners/abstract-logging> ships no LICENSE file. Author from npm `package.json`.
- `drizzle-orm.txt` — <https://github.com/drizzle-team/drizzle-orm/blob/main/LICENSE>
- `http_ece.txt` — <https://github.com/web-push-libs/encrypted-content-encoding/blob/master/LICENSE>
