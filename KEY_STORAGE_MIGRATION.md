# Key Storage Migration

## Overview
Signing keys are now stored directly in the SQLite database instead of as separate `.pem` files in the filesystem.

## Changes Made

### 1. Database Storage
Keys are now stored in the `provider_keys` table's `material_json` column:

**New format (PEM keys):**
```json
{
  "type": "pem",
  "pem_content": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
}
```

**Old format (deprecated but still supported for backward compatibility):**
```json
{
  "type": "pem",
  "pem": "/path/to/keyfile.pem"
}
```

**Ed25519 keys (unchanged):**
```json
{
  "type": "ed25519",
  "ed_secret": "base64url_encoded_secret",
  "ed_public": "base64url_encoded_public"
}
```

### 2. Modified Functions

#### `create_keypair()`
- Now returns `pem_content` instead of writing to a file and returning `pem` path
- No longer creates `.pem` files in `KEYS_DIR`

#### `import_private_key_auto()`
- Now returns `pem_content` instead of writing to a file and returning `pem` path
- No longer creates `.pem` files in `KEYS_DIR`

#### `jwk_from_key()`
- Updated to read from `pem_content` if available
- Falls back to reading from `pem` file path for backward compatibility

#### `sign_jwt_with_key()`
- Updated to read from `pem_content` if available
- Falls back to reading from `pem` file path for backward compatibility

#### Public Key API Endpoint
- Updated to read from `pem_content` if available
- Falls back to reading from `pem` file path for backward compatibility

### 3. Benefits

1. **Portability**: Signing keys live in the database, no separate key files to manage
2. **Atomicity**: Key creation and storage happen in a single database transaction
3. **Backup simplicity**: Signing keys need no extra files. A complete backup is still three
   files from the data directory, kept and restored together: the SQLite database
   (`providers.sqlite`), `scim_master.key` next to it and `users.txt`, plus the value of
   `OIDC_SCIM_ENCRYPTION_KEY` when it is set (see section 6).
4. **Security**: Keys are stored with the same permissions as the database file
5. **Consistency**: All configuration data in one place

### 4. Migration Path

The code supports both old and new formats:
- Existing keys stored as file paths will continue to work (backward compatibility)
- New keys will be stored with content directly in the database
- No manual migration required - old keys can be left as-is or will be replaced naturally during key rotation
- A key in the old format stores the absolute path of its `.pem` file. If you move that file
  (for example the old `<project>/keys/` folder, see section 6), add or rotate to a new key
  first, or keep the file at the same path, otherwise that key can no longer sign or be
  published.

### 5. Environment Variables

The `KEYS_DIR` environment variable is now deprecated but kept for backward compatibility. New installations don't need to set it.

`OIDC_SCIM_ENCRYPTION_KEY` holds the vault key outside the data directory. It is read only from
the environment, never from `config.php`; see section 6 and `config.example.php`.

### 6. Data directory, backups and upgrades

Runtime data lives only in the data directory: `OIDC_CONFIG_DIR` (legacy alias `CONFIG_DIR`),
else `config_dir` in `config.php`, else the sibling folder `<project-folder>_config`. It holds
`providers.sqlite`, `scim_master.key`, `users.txt` and `sessions/`, for old file-based keys
also `keys/`, and with the IP allowlist `blocked_requests.sqlite`.

- **Placement**: the data directory must be outside the web root. Bootstrap refuses to start
  (HTTP 500, reason in the error log) when the data directory, or a path set with
  `OIDC_USERS_FILE`, `OIDC_STORAGE_FILE`, `OIDC_KEYS_DIR` or `OIDC_APIKEYS_FILE`, is inside the
  project folder or the web server's document root.
- **Backups**: back up `providers.sqlite`, the `scim_master.key` from the same directory and
  `users.txt` together, and restore them together; keep the value of
  `OIDC_SCIM_ENCRYPTION_KEY`, when it is set, with them. The vault key decrypts the stored
  outbound SCIM connector tokens, the administrators' authenticator app secrets (table
  `admin_mfa_totp`) and the user password copies for password push, which exist only while
  password push is allowed (see **Password push** below). The vault key is `scim_master.key`,
  unless `OIDC_SCIM_ENCRYPTION_KEY` is set (the file is then still used to decrypt secrets
  stored before the variable was set). A database restored without its vault key cannot
  decrypt those secrets: the next secret that is saved creates a new, different key, the old
  secrets must be entered again, and administrators with an authenticator app cannot sign in
  until it is reset (see **Admin authenticator apps**). `users.txt` holds the admin console
  accounts. `sessions/` holds only short-lived sign-in state and can be left out of backups:
  after a restore, admins and users simply sign in again.
- **Admin accounts (`users.txt`)**: one `username:hash` line per administrator. Entries must be
  password hashes, best `password_hash()` digests; bcrypt (`$2y$`, `$2a$`, `$2b$`), argon2,
  SHA-crypt (`$5$`, `$6$`) and MD5-crypt (`$1$`) verify, Apache `$apr1$` does not. A plaintext entry works only with
  `OIDC_ALLOW_PLAINTEXT_ADMIN_PASSWORDS=1` (`allow_plaintext_admin_passwords` in `config.php`)
  and at least 12 characters, and every sign-in with one is logged. To write a line, run
  `php index.php hash-admin-password <user>` as the web server user: it reads the password (at
  least 12 characters) from standard input and prints `<user>:<hash>`. A bare hash:
  `php -r 'echo password_hash(rtrim(fgets(STDIN), "\r\n"), PASSWORD_DEFAULT), PHP_EOL;'`.
- **Admin authenticator apps**: the table `admin_mfa_totp` holds the administrators' TOTP
  secrets, encrypted with the vault key, so back up the vault key with the database. An
  operator resets a lost authenticator app with
  `DELETE FROM admin_mfa_totp WHERE username = '<admin>'`; the administrator then signs in with
  the password alone, or sets up a new app at the next sign-in while `admin_require_mfa` is on.
- **Password push (`scim_master.key` / `OIDC_SCIM_ENCRYPTION_KEY`)**: `scim_master.key` alone no
  longer protects synced passwords. A recoverable copy of a user's password (for outbound SCIM
  connectors with `push_passwords`) exists only while the user's owner has such a connector and
  either `OIDC_SCIM_ENCRYPTION_KEY` (kept outside the data directory) or
  `allow_password_push_with_key_file` is set. Only passwords set or changed while that holds
  are pushed.
  - Set one of them before upgrading. Otherwise the stored copies are deleted by the first web
    request, and each password is pushed again only after its user sets a new one.
  - Cron (`php index.php scim-sync`) needs the same settings as the web server; a mismatch is
    logged.
  - Changing `OIDC_SCIM_ENCRYPTION_KEY` to another value deletes the stored copies (copies under
    another environment key cannot be opened), while moving from `scim_master.key` to
    `OIDC_SCIM_ENCRYPTION_KEY` re-encrypts them. Turning `allow_password_push_with_key_file` off
    without the variable deletes them too.
- **Blocked requests (`blocked_requests.sqlite`)**: requests the IP allowlist refused
  (`ip_allowlist`, see `config.example.php`). It holds client addresses, user agents and paths,
  which are personal data: keep `ip_allowlist_log_retention_days` short. It can be deleted at
  any time and need not be backed up. Read it from the command line only as the web server
  user: `-wal` and `-shm` files that another user leaves next to it can stop the web server
  from recording.
- **Admin API clients (upgrade)**: existing Admin API clients lose `can_mint_tokens` (minting
  JWTs at `POST /api/token`, importing signing keys, managing OIDC clients that can use the
  `client_credentials` grant). Re-grant it per client in the console, or set
  `OIDC_LEGACY_API_CLIENT_TOKEN_MINTING=1` temporarily.
- **Signing key rotation**: a key stays in the JWKS until every token it signed has expired.
  Automatic rotation keeps at most 100 signing keys per provider and never removes a key that
  still verifies unexpired tokens. When all of them are still needed, it keeps the current key
  for another key TTL instead of adding one, and logs "Key rotation for provider ... stays in
  use until ...". Shorter token lifetimes or a longer key TTL let rotation resume.
- **Key file safety**: the application never regenerates or overwrites an existing
  `scim_master.key`. When the file is unreadable or does not hold a valid key, the operations
  that need it fail (fail closed) and the error log says so; restore the file from backup.
- **Upgrading an old layout**: installs that keep their data in `<project-folder>/.data`, or
  `users.txt`, `providers.sqlite`, `api_keys.sqlite`, `scim_master.key` or `keys/` in the
  project folder, must move it into the data directory (keep `scim_master.key` next to
  `providers.sqlite`) and then delete it from the web root. Until then that data is ignored,
  and bootstrap logs "legacy data found in the web root" at most once an hour and writes a
  deny-all `.htaccess` into the old `.data/` and `keys/` folders.
- **Temporary compatibility**: setting `allow_webroot_data_dir` in `config.php` (environment
  `OIDC_ALLOW_WEBROOT_DATA_DIR`) keeps the old fallback to `<project-folder>/.data` and the
  project-folder lookups while you move the data. Use it only for the move, then remove it:
  with it, the keys, the vault key and `users.txt` can be downloaded if the web server
  ignores `.htaccess`.

## Testing

After this change:
1. Existing providers with file-based keys should continue to work
2. New keys should be created with content stored in the database
3. JWT signing should work with both old and new key formats
4. Public key API should work with both old and new key formats
