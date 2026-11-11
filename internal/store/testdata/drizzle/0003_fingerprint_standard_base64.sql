-- Convert stored SHA256 fingerprints from base64url (`-`/`_`) to standard
-- base64 (`+`/`/`) so they match `ssh-keygen -lf` / `ssh-add -l` output.
UPDATE `ssh_keys` SET `fingerprint` = REPLACE(REPLACE(`fingerprint`, '_', '/'), '-', '+');
