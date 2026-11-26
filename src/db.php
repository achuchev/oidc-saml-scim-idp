<?php
declare(strict_types=1);

function storage_db(string $dbFile): PDO
{
    static $instances = [];
    if (!isset($instances[$dbFile])) {
        if (!extension_loaded("pdo_sqlite")) {
            throw new RuntimeException("PDO SQLite extension required");
        }
        $dir = dirname($dbFile);
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        $pdo = new PDO("sqlite:" . $dbFile);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec("PRAGMA foreign_keys = ON");
        $pdo->exec("PRAGMA busy_timeout = 5000");
        // Overwrite deleted content (consumed tokens, relayed SCIM payloads, cleared secrets)
        // instead of leaving it readable in free pages of the database file.
        @$pdo->exec("PRAGMA secure_delete = ON");
        @$pdo->exec("PRAGMA journal_mode = WAL");
        $instances[$dbFile] = $pdo;
        @chmod($dbFile, 0600);
        @chmod($dbFile . "-wal", 0600);
        @chmod($dbFile . "-shm", 0600);
    }
    return $instances[$dbFile];
}

/**
 * Binds $params by PHP type and executes $stmt: int and bool as INTEGER, null as NULL,
 * anything else as TEXT. PDOStatement::execute(array) binds every value as TEXT, and SQLite
 * orders any TEXT value after any number, so a comparison between a computed integer and a
 * TEXT parameter is wrong. Use this whenever SQL does arithmetic or MAX() with parameters.
 */
function storage_execute(PDOStatement $stmt, array $params = []): PDOStatement
{
    foreach ($params as $name => $value) {
        if (is_bool($value)) {
            $value = $value ? 1 : 0;
        }
        $type = is_int($value)
            ? PDO::PARAM_INT
            : ($value === null ? PDO::PARAM_NULL : PDO::PARAM_STR);
        $stmt->bindValue(is_int($name) ? $name + 1 : (string) $name, $value, $type);
    }
    $stmt->execute();
    return $stmt;
}

/**
 * Runs $fn($pdo) in one write transaction and returns its result. BEGIN IMMEDIATE takes the
 * write lock before the first statement, so busy_timeout applies; a deferred transaction that
 * reads first fails at once with "database is locked" when it upgrades to a write while another
 * connection writes. Commits when $fn returns, rolls back and rethrows when it throws. When a
 * transaction is already open on $pdo, $fn joins it. Never mix this with
 * PDO::beginTransaction() for the same unit of work. Finish or closeCursor() other SELECTs on
 * $pdo first: an unfinished statement holds a read snapshot, which BEGIN IMMEDIATE would then
 * have to upgrade, and an upgrade does not wait for busy_timeout either.
 */
function storage_write_transaction(PDO $pdo, callable $fn): mixed
{
    if ($pdo->inTransaction()) {
        return $fn($pdo);
    }
    try {
        $pdo->exec("BEGIN IMMEDIATE");
    } catch (PDOException $e) {
        // A transaction opened with a raw BEGIN is not always visible to inTransaction().
        if (str_contains(strtolower($e->getMessage()), "within a transaction")) {
            return $fn($pdo);
        }
        throw $e;
    }
    try {
        $result = $fn($pdo);
        $pdo->exec("COMMIT");
    } catch (Throwable $e) {
        try {
            $pdo->exec("ROLLBACK");
        } catch (Throwable $rollbackError) {
            // SQLite may already have rolled back; the original error is the one to report.
        }
        throw $e;
    }
    return $result;
}

function storage_initialize(string $dbFile): void
{
    // Every request and many helpers call this. The statements are idempotent but not free,
    // so run them once per process and database file.
    static $initialized = [];
    if (isset($initialized[$dbFile])) {
        return;
    }
    $pdo = storage_db($dbFile);

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS providers (" .
            "id TEXT PRIMARY KEY," .
            "owner TEXT NOT NULL," .
            "friendly TEXT NOT NULL," .
            "idp_id TEXT NOT NULL UNIQUE," .
            "alg TEXT," .
            "created_at TEXT," .
            "last_issued_at TEXT," .
            "key_ttl_seconds INTEGER," .
            "expired_key_retention_seconds INTEGER," .
            "key_rotation_lead_time_seconds INTEGER," .
            "active_kid TEXT," .
            "default_auth_policy TEXT NOT NULL DEFAULT 'flexible'" .
        ")"
    );

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS provider_keys (" .
            "provider_id TEXT NOT NULL," .
            "kid TEXT NOT NULL," .
            "alg TEXT," .
            "type TEXT," .
            "created_at TEXT," .
            "valid_from TEXT," .
            "expires_at TEXT," .
            "valid_for_seconds INTEGER," .
            "material_json TEXT NOT NULL," .
            "ordinal INTEGER NOT NULL DEFAULT 0," .
            "max_token_exp INTEGER," .
            "PRIMARY KEY (provider_id, kid)," .
            "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_provider_keys_provider ON provider_keys(provider_id)"
    );

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS api_keys (" .
            "username TEXT PRIMARY KEY," .
            "api_key TEXT NOT NULL" .
        ")"
    );

    // Shared Per-Admin Directory Users
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS idp_users (" .
            "id TEXT PRIMARY KEY," .
            "owner TEXT NOT NULL," .
            "username TEXT NOT NULL," .
            "email TEXT NOT NULL," .
            "password_hash TEXT," .
            "password_enc TEXT," .
            "given_name TEXT NOT NULL DEFAULT ''," .
            "family_name TEXT NOT NULL DEFAULT ''," .
            "display_name TEXT NOT NULL DEFAULT ''," .
            "mobile_phone TEXT NOT NULL DEFAULT ''," .
            "groups_json TEXT NOT NULL DEFAULT '[]'," .
            "attributes_json TEXT NOT NULL DEFAULT '{}'," .
            "status TEXT NOT NULL DEFAULT 'active'," .
            // SHA-256 (hex) of the pending enrollment link token; the token itself is never stored.
            "enrollment_token TEXT," .
            "enrollment_expires_at TEXT," .
            "external_id TEXT NOT NULL DEFAULT ''," .
            // Immutable OIDC subject. New users get their id; users created before the column
            // existed keep the address their RPs already know (storage_run_data_migrations).
            "subject TEXT," .
            // 1 for users created before the flag existed; new users start unverified.
            "email_verified INTEGER NOT NULL DEFAULT 1," .
            "created_at TEXT NOT NULL," .
            "updated_at TEXT," .
            "last_login_at TEXT," .
            "UNIQUE(owner, username)," .
            "UNIQUE(owner, email)" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_idp_users_owner ON idp_users(owner)"
    );

    // Shared Per-Admin Directory Groups (synced with idp_users.groups_json & SCIM 2.0 /Groups)
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS idp_groups (" .
            "id TEXT PRIMARY KEY," .
            "owner TEXT NOT NULL," .
            "display_name TEXT NOT NULL COLLATE NOCASE," .
            "external_id TEXT NOT NULL DEFAULT ''," .
            "created_at TEXT NOT NULL," .
            "updated_at TEXT NOT NULL," .
            "UNIQUE(owner, display_name)" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_idp_groups_owner ON idp_groups(owner)"
    );

    // macOS Touch ID / WebAuthn Credentials (bound to user + owner + rp_id)
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS webauthn_credentials (" .
            "id TEXT PRIMARY KEY," .
            "user_id TEXT NOT NULL," .
            "owner TEXT NOT NULL," .
            "rp_id TEXT NOT NULL," .
            "friendly_name TEXT NOT NULL DEFAULT 'macOS Touch ID'," .
            "public_key_pem TEXT NOT NULL," .
            "cose_alg INTEGER NOT NULL DEFAULT -7," .
            "sign_count INTEGER NOT NULL DEFAULT 0," .
            "transports_json TEXT NOT NULL DEFAULT '[\"internal\"]'," .
            "aaguid TEXT NOT NULL DEFAULT ''," .
            "created_at TEXT NOT NULL," .
            "last_used_at TEXT," .
            "FOREIGN KEY(user_id) REFERENCES idp_users(id) ON DELETE CASCADE" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id)"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_webauthn_owner_rp ON webauthn_credentials(owner, rp_id)"
    );

    // SAML 2.0 X.509 Signing Certificates per Provider
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS provider_saml_certs (" .
            "id TEXT PRIMARY KEY," .
            "provider_id TEXT NOT NULL," .
            "kid TEXT NOT NULL," .
            "private_key_pem TEXT NOT NULL," .
            "cert_pem TEXT NOT NULL," .
            "fingerprint_sha256 TEXT NOT NULL," .
            "is_active INTEGER NOT NULL DEFAULT 1," .
            "created_at TEXT NOT NULL," .
            "expires_at TEXT NOT NULL," .
            "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_saml_certs_provider ON provider_saml_certs(provider_id)"
    );

    // OIDC 1.0 Relying Party Clients per Provider
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS oidc_clients (" .
            "id TEXT PRIMARY KEY," .
            "provider_id TEXT NOT NULL," .
            "name TEXT NOT NULL," .
            "client_id TEXT NOT NULL," .
            "client_secret_hash TEXT," .
            "client_secret_preview TEXT," .
            "redirect_uris_json TEXT NOT NULL DEFAULT '[]'," .
            "post_logout_redirect_uris_json TEXT NOT NULL DEFAULT '[]'," .
            "grant_types_json TEXT NOT NULL DEFAULT '[\"authorization_code\",\"refresh_token\"]'," .
            "require_pkce INTEGER NOT NULL DEFAULT 0," .
            "auth_policy TEXT NOT NULL DEFAULT 'flexible'," .
            "login_uri TEXT NOT NULL DEFAULT ''," .
            "custom_claims_json TEXT NOT NULL DEFAULT '{}'," .
            "assigned_groups_json TEXT NOT NULL DEFAULT '[]'," .
            "access_token_ttl INTEGER NOT NULL DEFAULT 3600," .
            "created_at TEXT NOT NULL," .
            "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_oidc_clients_provider ON oidc_clients(provider_id)"
    );
    // client_id is unique per provider, not globally: every lookup is provider-scoped, and a
    // global constraint let one tenant reserve another tenant's client IDs. Older databases
    // lose the column-level UNIQUE in storage_migrate_oidc_clients_unique_per_provider().
    $pdo->exec(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_clients_provider_client ON oidc_clients(provider_id, client_id)"
    );

    // SAML 2.0 Service Provider Applications per Provider
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS saml_apps (" .
            "id TEXT PRIMARY KEY," .
            "provider_id TEXT NOT NULL," .
            "name TEXT NOT NULL," .
            "org_display_name TEXT NOT NULL DEFAULT ''," .
            "sp_entity_id TEXT NOT NULL," .
            "acs_url TEXT NOT NULL," .
            "acs_endpoints_json TEXT NOT NULL DEFAULT '[]'," .
            "slo_url TEXT NOT NULL DEFAULT ''," .
            "name_id_format TEXT NOT NULL DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'," .
            "name_id_source TEXT NOT NULL DEFAULT 'email'," .
            "supported_name_id_formats_json TEXT NOT NULL DEFAULT '[]'," .
            "sign_response INTEGER NOT NULL DEFAULT 1," .
            "sign_assertion INTEGER NOT NULL DEFAULT 1," .
            "verify_authn_request_sig INTEGER NOT NULL DEFAULT 0," .
            "allow_weak_sha1 INTEGER NOT NULL DEFAULT 0," .
            "encrypt_assertion INTEGER NOT NULL DEFAULT 0," .
            "encryption_alg TEXT NOT NULL DEFAULT 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'," .
            "sp_signing_cert_pem TEXT NOT NULL DEFAULT ''," .
            "sp_encryption_cert_pem TEXT NOT NULL DEFAULT ''," .
            "attribute_mapping_json TEXT NOT NULL DEFAULT '[]'," .
            "default_relay_state TEXT NOT NULL DEFAULT ''," .
            "auth_policy TEXT NOT NULL DEFAULT 'flexible'," .
            "assigned_groups_json TEXT NOT NULL DEFAULT '[]'," .
            "raw_sp_metadata_xml TEXT NOT NULL DEFAULT ''," .
            "created_at TEXT NOT NULL," .
            "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_saml_apps_provider ON saml_apps(provider_id)"
    );

    // End-User SSO Sessions per Provider
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS sso_sessions (" .
            "id TEXT PRIMARY KEY," .
            "provider_id TEXT NOT NULL," .
            "user_id TEXT NOT NULL," .
            "amr_json TEXT NOT NULL DEFAULT '[]'," .
            "authenticated_at TEXT NOT NULL," .
            "expires_at INTEGER NOT NULL," .
            "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE," .
            "FOREIGN KEY(user_id) REFERENCES idp_users(id) ON DELETE CASCADE" .
        ")"
    );
    // Expiry cleanups run on unauthenticated requests while holding SQLite's database-wide
    // write lock: index the columns they filter on, so they never scan the whole table.
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_sso_sessions_expires ON sso_sessions(expires_at)"
    );

    // Apps an SSO session signed the user in to (S02-05): one row per session and app, with the
    // NameID, its Format and the SessionIndex of the latest assertion, so single logout can
    // reach every participant (sso_session_participant_record()). Rows go with their session
    // (ON DELETE CASCADE: logout, expiry cleanup, revocation, user or provider deletion). The
    // primary key's index leads with sso_session_id, so it serves the cascade and the list.
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS sso_session_participants (" .
            "sso_session_id TEXT NOT NULL," .
            "provider_id TEXT NOT NULL," .
            "app_id TEXT NOT NULL," .
            "name_id TEXT NOT NULL DEFAULT ''," .
            "name_id_format TEXT NOT NULL DEFAULT ''," .
            "session_index TEXT NOT NULL DEFAULT ''," .
            "created_at TEXT NOT NULL," .
            "PRIMARY KEY (sso_session_id, app_id)," .
            "FOREIGN KEY(sso_session_id) REFERENCES sso_sessions(id) ON DELETE CASCADE" .
        ")"
    );

    // Short-lived Authentication / WebAuthn Ceremony Transactions
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS auth_transactions (" .
            "id TEXT PRIMARY KEY," .
            "provider_id TEXT," .
            "owner TEXT NOT NULL," .
            "protocol TEXT NOT NULL," .
            "payload_json TEXT NOT NULL DEFAULT '{}'," .
            "step_state_json TEXT NOT NULL DEFAULT '{}'," .
            "expires_at INTEGER NOT NULL" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_auth_tx_expires ON auth_transactions(expires_at)"
    );

    // OIDC Authorization Codes
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS oidc_auth_codes (" .
            "code TEXT PRIMARY KEY," .
            "provider_id TEXT NOT NULL," .
            "client_id TEXT NOT NULL," .
            "user_id TEXT NOT NULL," .
            "redirect_uri TEXT NOT NULL," .
            "scope TEXT NOT NULL," .
            "nonce TEXT," .
            "code_challenge TEXT," .
            "code_challenge_method TEXT," .
            "amr_json TEXT NOT NULL DEFAULT '[]'," .
            "auth_time INTEGER NOT NULL," .
            "expires_at INTEGER NOT NULL," .
            "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE," .
            "FOREIGN KEY(user_id) REFERENCES idp_users(id) ON DELETE CASCADE" .
        ")"
    );

    // OIDC Access & Refresh Tokens
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS oidc_tokens (" .
            "token_hash TEXT PRIMARY KEY," .
            "token_type TEXT NOT NULL," .
            "provider_id TEXT NOT NULL," .
            "client_id TEXT NOT NULL," .
            "user_id TEXT," .
            "scope TEXT NOT NULL," .
            "amr_json TEXT NOT NULL DEFAULT '[]'," .
            "expires_at INTEGER NOT NULL," .
            "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE," .
            "FOREIGN KEY(user_id) REFERENCES idp_users(id) ON DELETE CASCADE" .
        ")"
    );

    // SSO Audit Logs per Provider
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS sso_audit_logs (" .
            "id INTEGER PRIMARY KEY AUTOINCREMENT," .
            "provider_id TEXT NOT NULL," .
            "created_at TEXT NOT NULL," .
            "protocol TEXT NOT NULL," .
            "event_type TEXT NOT NULL," .
            "app_name TEXT NOT NULL DEFAULT ''," .
            "username TEXT NOT NULL DEFAULT ''," .
            "amr_json TEXT NOT NULL DEFAULT '[]'," .
            "status TEXT NOT NULL," .
            "details_json TEXT NOT NULL DEFAULT '{}'," .
            // 'security' or 'untrusted' (unauthenticated noise with its own cap); see audit_log_append().
            "audit_class TEXT NOT NULL DEFAULT 'security'," .
            "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_audit_provider ON sso_audit_logs(provider_id, id DESC)"
    );

    // SSO audit rows of deleted providers (G1a-01). delete_provider() copies a provider's rows
    // here, with its owner and idp_id, before the cascade above removes them. No foreign key, so
    // the record outlives the provider; rows are kept SSO_AUDIT_ARCHIVE_RETENTION_DAYS after
    // archiving. id is the archive's own; source_id is the row's sso_audit_logs id.
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS sso_audit_logs_archive (" .
            "id INTEGER PRIMARY KEY," .
            "source_id INTEGER NOT NULL," .
            "provider_id TEXT NOT NULL," .
            "owner TEXT NOT NULL DEFAULT ''," .
            "idp_id TEXT NOT NULL DEFAULT ''," .
            "created_at TEXT NOT NULL," .
            "protocol TEXT NOT NULL," .
            "event_type TEXT NOT NULL," .
            "app_name TEXT NOT NULL DEFAULT ''," .
            "username TEXT NOT NULL DEFAULT ''," .
            "amr_json TEXT NOT NULL DEFAULT '[]'," .
            "status TEXT NOT NULL," .
            "details_json TEXT NOT NULL DEFAULT '{}'," .
            "audit_class TEXT NOT NULL DEFAULT 'security'," .
            "archived_at TEXT NOT NULL" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_audit_archive_archived ON sso_audit_logs_archive(archived_at)"
    );

    // Brute-force / Auth Rate Limiting Table
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS auth_rate_limits (" .
            "bucket TEXT PRIMARY KEY," .
            "failures INTEGER NOT NULL DEFAULT 0," .
            "window_started_at INTEGER NOT NULL," .
            "locked_until INTEGER NOT NULL DEFAULT 0" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_auth_rl_window ON auth_rate_limits(window_started_at)"
    );

    // Programmatic Administration API Clients (Provider-Scoped & Full-Tenant)
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS admin_api_clients (" .
            "id TEXT PRIMARY KEY," .
            "owner TEXT NOT NULL," .
            "name TEXT NOT NULL," .
            "description TEXT NOT NULL DEFAULT ''," .
            "client_id TEXT NOT NULL UNIQUE," .
            "token_id TEXT NOT NULL UNIQUE," .
            "secret_hash TEXT NOT NULL," .
            "secret_preview TEXT NOT NULL," .
            "provider_scope TEXT NOT NULL DEFAULT 'selected'," .
            "allowed_provider_ids_json TEXT NOT NULL DEFAULT '[]'," .
            "can_create_providers INTEGER NOT NULL DEFAULT 0," .
            "provider_permission TEXT NOT NULL DEFAULT 'write'," .
            "user_scope TEXT NOT NULL DEFAULT 'none'," .
            "status TEXT NOT NULL DEFAULT 'active'," .
            "expires_at TEXT," .
            "created_at TEXT NOT NULL," .
            "last_used_at TEXT," .
            "last_used_ip TEXT" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_admin_api_clients_owner ON admin_api_clients(owner)"
    );

    // Short-lived OAuth 2.0 client_credentials Access Tokens for Admin API Clients
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS admin_api_access_tokens (" .
            "token_hash TEXT PRIMARY KEY," .
            "admin_client_id TEXT NOT NULL," .
            "expires_at INTEGER NOT NULL," .
            "created_at TEXT NOT NULL," .
            "FOREIGN KEY(admin_client_id) REFERENCES admin_api_clients(id) ON DELETE CASCADE" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_admin_at_expires ON admin_api_access_tokens(expires_at)"
    );

    // Inbound SCIM 2.0 Bearer Tokens per Provider
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS scim_tokens (" .
            "id TEXT PRIMARY KEY," .
            "provider_id TEXT NOT NULL," .
            "name TEXT NOT NULL," .
            "token_id TEXT NOT NULL UNIQUE," .
            "secret_hash TEXT NOT NULL," .
            "secret_preview TEXT NOT NULL," .
            "permission TEXT NOT NULL DEFAULT 'read'," .
            "filter_groups_json TEXT NOT NULL DEFAULT '[]'," .
            "status TEXT NOT NULL DEFAULT 'active'," .
            "expires_at TEXT," .
            "created_at TEXT NOT NULL," .
            "last_used_at TEXT," .
            "last_used_ip TEXT," .
            "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_scim_tokens_provider ON scim_tokens(provider_id)"
    );

    // Outbound SCIM 2.0 Push Provisioning Connectors per Provider
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS scim_connectors (" .
            "id TEXT PRIMARY KEY," .
            "provider_id TEXT NOT NULL," .
            "name TEXT NOT NULL," .
            "delivery_mode TEXT NOT NULL DEFAULT 'direct'," .
            "scim_base_url TEXT NOT NULL," .
            "bearer_token_enc TEXT NOT NULL," .
            "token_preview TEXT NOT NULL," .
            "agent_token_id TEXT," .
            "agent_secret_hash TEXT," .
            "agent_secret_preview TEXT," .
            "agent_last_seen_at TEXT," .
            "agent_hostname TEXT," .
            "agent_version TEXT," .
            "agent_last_ip TEXT," .
            "sync_groups INTEGER NOT NULL DEFAULT 1," .
            "push_passwords INTEGER NOT NULL DEFAULT 0," .
            "auto_sync INTEGER NOT NULL DEFAULT 1," .
            "deprovision_action TEXT NOT NULL DEFAULT 'deactivate'," .
            "assigned_groups_json TEXT NOT NULL DEFAULT '[]'," .
            "status TEXT NOT NULL DEFAULT 'active'," .
            "last_sync_at TEXT," .
            "last_sync_status TEXT," .
            "last_sync_summary TEXT," .
            "created_at TEXT NOT NULL," .
            "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_scim_connectors_provider ON scim_connectors(provider_id)"
    );

    // Remote SCIM Resource ID Mapping Table for Outbound Push Connectors
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS scim_remote_mappings (" .
            "connector_id TEXT NOT NULL," .
            "resource_type TEXT NOT NULL," .
            "local_id TEXT NOT NULL," .
            "remote_id TEXT NOT NULL," .
            "last_pushed_hash TEXT NOT NULL DEFAULT ''," .
            "synced_at TEXT NOT NULL," .
            "PRIMARY KEY (connector_id, resource_type, local_id)," .
            "FOREIGN KEY(connector_id) REFERENCES scim_connectors(id) ON DELETE CASCADE" .
        ")"
    );

    // Relay Job Queue for On-Premises Windows SCIM Proxy Agents
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS scim_agent_jobs (" .
            "id TEXT PRIMARY KEY," .
            "connector_id TEXT NOT NULL," .
            "method TEXT NOT NULL," .
            "endpoint_path TEXT NOT NULL," .
            "request_body_json TEXT," .
            "status TEXT NOT NULL DEFAULT 'pending'," .
            "response_status INTEGER," .
            "response_body_raw TEXT," .
            "error_message TEXT," .
            "created_at INTEGER NOT NULL," .
            "claimed_at INTEGER," .
            "completed_at INTEGER," .
            "FOREIGN KEY(connector_id) REFERENCES scim_connectors(id) ON DELETE CASCADE" .
        ")"
    );
    $pdo->exec(
        "CREATE INDEX IF NOT EXISTS idx_scim_agent_jobs_conn ON scim_agent_jobs(connector_id, status, created_at)"
    );

    // Backward-compatible schema migrations for older SQLite databases
    foreach (
        [
            "ALTER TABLE providers ADD COLUMN expired_key_retention_seconds INTEGER",
            "ALTER TABLE providers ADD COLUMN key_rotation_lead_time_seconds INTEGER",
            "ALTER TABLE providers ADD COLUMN active_kid TEXT",
            "ALTER TABLE providers ADD COLUMN default_auth_policy TEXT NOT NULL DEFAULT 'flexible'",
            "ALTER TABLE provider_keys ADD COLUMN ordinal INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE provider_keys ADD COLUMN max_token_exp INTEGER",
            "ALTER TABLE oidc_clients ADD COLUMN client_secret_preview TEXT",
            "ALTER TABLE saml_apps ADD COLUMN allow_weak_sha1 INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE idp_users ADD COLUMN external_id TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE idp_users ADD COLUMN updated_at TEXT",
            "ALTER TABLE idp_users ADD COLUMN password_enc TEXT",
            "ALTER TABLE scim_connectors ADD COLUMN push_passwords INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE scim_connectors ADD COLUMN delivery_mode TEXT NOT NULL DEFAULT 'direct'",
            "ALTER TABLE scim_connectors ADD COLUMN agent_token_id TEXT",
            "ALTER TABLE scim_connectors ADD COLUMN agent_secret_hash TEXT",
            "ALTER TABLE scim_connectors ADD COLUMN agent_secret_preview TEXT",
            "ALTER TABLE scim_connectors ADD COLUMN agent_last_seen_at TEXT",
            "ALTER TABLE scim_connectors ADD COLUMN agent_hostname TEXT",
            "ALTER TABLE scim_connectors ADD COLUMN agent_version TEXT",
            "ALTER TABLE scim_connectors ADD COLUMN agent_last_ip TEXT",
        ]
        as $sql
    ) {
        try {
            $pdo->exec($sql);
        } catch (Throwable $e) {
            continue;
        }
    }

    // Scrub any legacy plaintext OIDC client_secret_plain values if column exists. The preview
    // becomes the bare mask: a legacy secret never seeds a prefix preview (S03-10), even when
    // old data is restored after oidc.php's one-time preview migration has run.
    try {
        $pdo->exec(
            "UPDATE oidc_clients SET client_secret_preview = '••••••••', client_secret_plain = NULL WHERE client_secret_plain IS NOT NULL AND client_secret_plain != ''"
        );
    } catch (Throwable $e) {
        // Column does not exist on fresh databases; ignore.
    }

    // The schema above is complete. The rebuild below logs its own failures and is retried
    // on the next request, so a failed attempt must not repeat on every call in this one.
    $initialized[$dbFile] = true;
    storage_migrate_oidc_clients_unique_per_provider($pdo);
    storage_run_data_migrations($pdo);
    // S04-08: applies the password copy policy (crypto.php) once after the upgrade and again
    // whenever it changes: clears the recoverable password copies nothing may push and, with
    // $dbFile, re-encrypts key-file copies under OIDC_SCIM_ENCRYPTION_KEY. It needs the schema
    // above (scim_connectors.push_passwords) and must run outside any transaction, as it does
    // here; while the policy is unchanged it costs one SELECT per request. It logs and retries
    // its own failures and changes nothing on the command line.
    if (function_exists("vault_password_copies_migrate")) {
        try {
            vault_password_copies_migrate($pdo, $dbFile);
        } catch (Throwable $e) {
            error_log("storage: password copy policy not applied (will retry): " . $e->getMessage());
        }
    }
}

/**
 * Run-once migrations of the data layer (schema_ensure). Each one is atomic; a failure is
 * logged and retried on the next request, and does not stop the others.
 */
function storage_run_data_migrations(PDO $pdo): void
{
    $migrations = [
        // Immutable OIDC subject and per-user email_verified flag. Existing users keep the
        // address their RPs already know as sub, and stay verified (the old behavior).
        "data.idp_users_subject_v1" => [
            "ALTER TABLE idp_users ADD COLUMN subject TEXT",
            "ALTER TABLE idp_users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1",
            "UPDATE idp_users SET subject = COALESCE(NULLIF(email, ''), NULLIF(username, ''), id) " .
                "WHERE subject IS NULL OR subject = ''",
            static function (PDO $db): void {
                storage_create_unique_index_if_clean(
                    $db,
                    "idx_idp_users_owner_subject",
                    "idp_users(owner, subject)",
                    "SELECT 1 FROM idp_users WHERE subject IS NOT NULL GROUP BY owner, subject HAVING COUNT(*) > 1 LIMIT 1",
                    "two directory users of one owner share an OIDC subject"
                );
            },
        ],
        // Enrollment links: keep only the SHA-256 of each pending token, so outstanding links
        // keep working while a copy of the database no longer contains usable tokens.
        "data.enrollment_token_sha256_v1" => [
            static function (PDO $db): void {
                $rows = $db
                    ->query(
                        "SELECT id, enrollment_token FROM idp_users " .
                            "WHERE enrollment_token IS NOT NULL AND enrollment_token != ''"
                    )
                    ->fetchAll(PDO::FETCH_ASSOC);
                $upd = $db->prepare("UPDATE idp_users SET enrollment_token = :h WHERE id = :id");
                foreach ($rows as $row) {
                    $stored = (string) $row["enrollment_token"];
                    // A 64-hex value is already a digest (a raw token is 32 base64url characters).
                    if (preg_match('/^[0-9a-f]{64}$/D', $stored) === 1) {
                        continue;
                    }
                    $upd->execute([":h" => hash("sha256", $stored), ":id" => (string) $row["id"]]);
                }
            },
        ],
        // Audit classes: unauthenticated noise is capped on its own (audit_log_append).
        "data.audit_log_classes_v1" => [
            "ALTER TABLE sso_audit_logs ADD COLUMN audit_class TEXT NOT NULL DEFAULT 'security'",
            "UPDATE sso_audit_logs SET audit_class = 'untrusted' " .
                "WHERE event_type IN ('unknown_sp_issuer', 'password_login_failed', 'touchid_failed')",
            "CREATE INDEX IF NOT EXISTS idx_audit_provider_class ON sso_audit_logs(provider_id, audit_class, id)",
        ],
        // idp_id is resolved case-insensitively from URLs, so two providers must never differ
        // only by case.
        "data.providers_idp_id_nocase_v1" => [
            static function (PDO $db): void {
                storage_create_unique_index_if_clean(
                    $db,
                    "idx_providers_idp_id_nocase",
                    "providers(lower(idp_id))",
                    "SELECT 1 FROM providers GROUP BY lower(idp_id) HAVING COUNT(*) > 1 LIMIT 1",
                    "two providers have idp_ids that differ only by case; rename or delete one of them"
                );
            },
        ],
    ];
    foreach ($migrations as $migrationId => $steps) {
        try {
            schema_ensure($pdo, $migrationId, $steps);
        } catch (Throwable $e) {
            error_log("storage migration " . $migrationId . " failed (will retry): " . $e->getMessage());
        }
    }
}

/**
 * Creates a UNIQUE index unless rows already violate it ($duplicateSql returns a row), in
 * which case the problem is logged and the index is skipped rather than failing every request.
 * Runs inside schema_ensure()'s transaction.
 */
function storage_create_unique_index_if_clean(
    PDO $pdo,
    string $indexName,
    string $target,
    string $duplicateSql,
    string $problem
): void {
    $dup = $pdo->query($duplicateSql);
    $hasDuplicates = $dup->fetchColumn() !== false;
    $dup->closeCursor();
    if ($hasDuplicates) {
        error_log("storage: unique index " . $indexName . " not created: " . $problem);
        return;
    }
    $pdo->exec("CREATE UNIQUE INDEX IF NOT EXISTS " . $indexName . " ON " . $target);
}

/**
 * True while oidc_clients still carries the old column-level UNIQUE on client_id (an
 * automatic index created by a UNIQUE constraint that covers client_id alone).
 */
function storage_oidc_clients_client_id_globally_unique(PDO $pdo): bool
{
    $indexes = $pdo->query("PRAGMA index_list(oidc_clients)")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($indexes as $index) {
        if ((int) ($index["unique"] ?? 0) !== 1 || ($index["origin"] ?? "") !== "u") {
            continue;
        }
        $name = str_replace("'", "''", (string) ($index["name"] ?? ""));
        $columns = array_map(
            fn($c) => strtolower((string) ($c["name"] ?? "")),
            $pdo->query("PRAGMA index_info('" . $name . "')")->fetchAll(PDO::FETCH_ASSOC)
        );
        if ($columns === ["client_id"]) {
            return true;
        }
    }
    return false;
}

/**
 * One-time migration: drops the global UNIQUE on oidc_clients.client_id, leaving the
 * per-provider UNIQUE index (provider_id, client_id). SQLite cannot drop a column constraint,
 * so the table is rebuilt (storage_rebuild_oidc_clients_unique_per_provider). Foreign keys are
 * switched off around the transaction, as SQLite's table-rebuild procedure requires: dropping
 * the old table with foreign keys on would cascade into any table that references it. A failure
 * is logged and leaves the old table in place; it is retried on the next request.
 */
function storage_migrate_oidc_clients_unique_per_provider(PDO $pdo): void
{
    try {
        if (!storage_oidc_clients_client_id_globally_unique($pdo)) {
            return;
        }
        $foreignKeysWereOn = (int) $pdo->query("PRAGMA foreign_keys")->fetchColumn() === 1;
        if ($foreignKeysWereOn) {
            $pdo->exec("PRAGMA foreign_keys = OFF");
        }
        try {
            schema_ensure($pdo, "data.oidc_clients_unique_per_provider_v1", [
                static function (PDO $db): void {
                    storage_rebuild_oidc_clients_unique_per_provider($db);
                },
            ]);
        } finally {
            if ($foreignKeysWereOn) {
                $pdo->exec("PRAGMA foreign_keys = ON");
            }
        }
    } catch (Throwable $e) {
        error_log(
            "oidc_clients migration to per-provider client_id uniqueness failed (will retry): " .
                $e->getMessage()
        );
    }
}

/**
 * Rebuilds oidc_clients from its stored CREATE statement minus the UNIQUE on client_id, so
 * every column survives, including columns other modules added later. Indexes and triggers
 * are recreated from their stored SQL. Runs inside schema_ensure()'s transaction and refuses
 * to run while foreign keys are enforced.
 */
function storage_rebuild_oidc_clients_unique_per_provider(PDO $pdo): void
{
    if (!storage_oidc_clients_client_id_globally_unique($pdo)) {
        return; // Another process finished the rebuild first.
    }
    if ((int) $pdo->query("PRAGMA foreign_keys")->fetchColumn() !== 0) {
        throw new RuntimeException("foreign keys must be off while oidc_clients is rebuilt");
    }
    $createSql = (string) $pdo
        ->query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'oidc_clients'")
        ->fetchColumn();
    $newSql = preg_replace(
        '/((?:^|[(,])\s*["`\[]?client_id["`\]]?\s+TEXT\s+NOT\s+NULL)\s+UNIQUE(?=\s*[,)])/i',
        '$1',
        $createSql,
        -1,
        $replaced
    );
    if (!is_string($newSql) || $replaced !== 1) {
        throw new RuntimeException("unexpected oidc_clients definition; client_id UNIQUE not found");
    }
    $columns = [];
    foreach ($pdo->query("PRAGMA table_info(oidc_clients)")->fetchAll(PDO::FETCH_ASSOC) as $col) {
        $columns[] = '"' . str_replace('"', '""', (string) $col["name"]) . '"';
    }
    if (empty($columns)) {
        throw new RuntimeException("oidc_clients has no columns");
    }
    $columnList = implode(", ", $columns);
    // Automatic indexes have no SQL; the new table's constraints recreate them.
    $dependents = $pdo
        ->query(
            "SELECT sql FROM sqlite_master WHERE tbl_name = 'oidc_clients' " .
                "AND type IN ('index', 'trigger') AND sql IS NOT NULL " .
                "ORDER BY CASE type WHEN 'index' THEN 0 ELSE 1 END, name"
        )
        ->fetchAll(PDO::FETCH_COLUMN);

    // Copy out, recreate under the original name, copy back: no ALTER TABLE ... RENAME, whose
    // rewriting of references elsewhere in the schema is version-dependent.
    $pdo->exec("DROP TABLE IF EXISTS oidc_clients__rebuild_copy");
    $pdo->exec("CREATE TABLE oidc_clients__rebuild_copy AS SELECT * FROM oidc_clients");
    $pdo->exec("DROP TABLE oidc_clients");
    $pdo->exec($newSql);
    $pdo->exec(
        "INSERT INTO oidc_clients (" . $columnList . ") SELECT " . $columnList .
            " FROM oidc_clients__rebuild_copy"
    );
    $pdo->exec("DROP TABLE oidc_clients__rebuild_copy");
    foreach ($dependents as $sql) {
        $pdo->exec((string) $sql);
    }
    $pdo->exec(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_clients_provider_client ON oidc_clients(provider_id, client_id)"
    );
    if (storage_oidc_clients_client_id_globally_unique($pdo)) {
        throw new RuntimeException("oidc_clients rebuild kept the global client_id constraint");
    }
}

/**
 * Storage key for a rate-limit bucket. Keys from rate_limit_bucket() are short. Older callers
 * embed raw request values (the submitted username), so long keys are stored as a digest and
 * an attacker-sized identifier cannot bloat auth_rate_limits. Every rate_limit_* function maps
 * keys the same way, so callers see no difference.
 */
function rate_limit_storage_key(string $bucket): string
{
    return strlen($bucket) <= 128 ? $bucket : "sha256:" . hash("sha256", $bucket);
}

function rate_limit_is_blocked(string $storePath, string $bucket): bool
{
    $pdo = storage_db($storePath);
    $now = time();
    $stmt = $pdo->prepare(
        "SELECT locked_until FROM auth_rate_limits WHERE bucket = :b LIMIT 1"
    );
    $stmt->execute([":b" => rate_limit_storage_key($bucket)]);
    $lockedUntil = $stmt->fetchColumn();
    return $lockedUntil !== false && (int) $lockedUntil > $now;
}

/**
 * Counts one failed attempt in a single atomic UPSERT, so concurrent failures are never lost.
 * A window older than $windowSeconds restarts at 1, reaching $maxAttempts locks the bucket for
 * $lockoutSeconds, and an existing lock is never shortened. Prefer rate_limit_hit(), which
 * reserves the attempt before the expensive check instead of counting it afterwards.
 */
function rate_limit_record_failure(
    string $storePath,
    string $bucket,
    int $maxAttempts = 8,
    int $windowSeconds = 300,
    int $lockoutSeconds = 300
): void {
    $pdo = storage_db($storePath);
    $now = time();
    $windowSeconds = max(1, $windowSeconds);
    // In DO UPDATE every expression sees the row as it was before this statement.
    $expired = "auth_rate_limits.window_started_at + :win < :now";
    $failures = "CASE WHEN " . $expired . " THEN 1 ELSE auth_rate_limits.failures + 1 END";
    $stmt = $pdo->prepare(
        "INSERT INTO auth_rate_limits (bucket, failures, window_started_at, locked_until) " .
            "VALUES (:b, 1, :now, CASE WHEN 1 >= :max THEN :now + :lock ELSE 0 END) " .
            "ON CONFLICT(bucket) DO UPDATE SET " .
            "failures = " . $failures . ", " .
            "window_started_at = CASE WHEN " . $expired . " THEN :now ELSE auth_rate_limits.window_started_at END, " .
            "locked_until = MAX(auth_rate_limits.locked_until, " .
                "CASE WHEN (" . $failures . ") >= :max THEN :now + :lock ELSE 0 END)"
    );
    storage_execute($stmt, [
        ":b" => rate_limit_storage_key($bucket),
        ":now" => $now,
        ":max" => max(1, $maxAttempts),
        ":win" => $windowSeconds,
        ":lock" => max(0, $lockoutSeconds),
    ]);
    rate_limit_prune_expired($pdo, $now, $windowSeconds);
}

/**
 * Atomically reserves one attempt for $bucket before an expensive check (bcrypt, secret
 * verification). Returns true when the caller must reject the request without verifying:
 * the bucket is locked, or this is attempt $maxAttempts + 1 or later in the current window,
 * which also locks the bucket for $lockoutSeconds. A window older than $windowSeconds starts
 * over. A lock is never shortened, and attempts rejected during a lock do not extend it.
 * Call rate_limit_clear() after a success; do not also call rate_limit_record_failure() for
 * the same attempt. If the limiter cannot be updated the attempt is rejected (fail closed).
 */
function rate_limit_hit(
    string $storePath,
    string $bucket,
    int $maxAttempts,
    int $windowSeconds,
    int $lockoutSeconds
): bool {
    $key = rate_limit_storage_key($bucket);
    $maxAttempts = max(1, $maxAttempts);
    $windowSeconds = max(1, $windowSeconds);
    $lockoutSeconds = max(1, $lockoutSeconds);
    $now = time();
    try {
        $pdo = storage_db($storePath);
        // Read-only fast path: under attack most attempts hit a locked bucket, and these
        // should not queue for the write lock. The transaction below re-checks.
        if (rate_limit_is_blocked($storePath, $bucket)) {
            return true;
        }
        $limited = storage_write_transaction(
            $pdo,
            function (PDO $pdo) use ($key, $maxAttempts, $windowSeconds, $lockoutSeconds, $now): bool {
                $sel = $pdo->prepare(
                    "SELECT failures, window_started_at, locked_until FROM auth_rate_limits WHERE bucket = :b LIMIT 1"
                );
                storage_execute($sel, [":b" => $key]);
                $row = $sel->fetch(PDO::FETCH_ASSOC);
                $sel->closeCursor();
                $lockedUntil = is_array($row) ? (int) $row["locked_until"] : 0;
                if ($lockedUntil > $now) {
                    return true;
                }
                if (!is_array($row) || (int) $row["window_started_at"] + $windowSeconds < $now) {
                    $attempts = 1;
                    $windowStart = $now;
                } else {
                    $attempts = (int) $row["failures"] + 1;
                    $windowStart = (int) $row["window_started_at"];
                }
                $limited = $attempts > $maxAttempts;
                if ($limited) {
                    $lockedUntil = $now + $lockoutSeconds;
                }
                $up = $pdo->prepare(
                    "INSERT INTO auth_rate_limits (bucket, failures, window_started_at, locked_until) " .
                        "VALUES (:b, :f, :w, :l) ON CONFLICT(bucket) DO UPDATE SET " .
                        "failures = excluded.failures, window_started_at = excluded.window_started_at, " .
                        "locked_until = MAX(auth_rate_limits.locked_until, excluded.locked_until)"
                );
                storage_execute($up, [
                    ":b" => $key,
                    ":f" => $attempts,
                    ":w" => $windowStart,
                    ":l" => $lockedUntil,
                ]);
                return $limited;
            }
        );
    } catch (Throwable $e) {
        error_log("rate_limit_hit: limiter unavailable, attempt rejected: " . $e->getMessage());
        return true;
    }
    rate_limit_prune_expired($pdo, $now, $windowSeconds);
    return (bool) $limited;
}

/**
 * Best-effort removal of stale buckets. Runs on about 1 in 50 calls and deletes at most 200
 * rows (through the window_started_at index), so it never becomes a long scan under the write
 * lock on an unauthenticated request.
 */
function rate_limit_prune_expired(PDO $pdo, int $now, int $windowSeconds = 300): void
{
    if (mt_rand(1, 50) !== 1) {
        return;
    }
    try {
        $stmt = $pdo->prepare(
            "DELETE FROM auth_rate_limits WHERE rowid IN (" .
                "SELECT rowid FROM auth_rate_limits WHERE window_started_at < :cutoff AND locked_until < :now LIMIT 200" .
            ")"
        );
        storage_execute($stmt, [
            ":cutoff" => $now - max(3600, $windowSeconds),
            ":now" => $now,
        ]);
    } catch (Throwable $e) {
        // Cleanup is optional; a busy database must not fail the request that triggered it.
    }
}

function rate_limit_clear(string $storePath, string $bucket): void
{
    $pdo = storage_db($storePath);
    $pdo->prepare("DELETE FROM auth_rate_limits WHERE bucket = :b")->execute([
        ":b" => rate_limit_storage_key($bucket),
    ]);
}

function ensure_api_key(string $username, string $apiStore): string
{
    $pdo = storage_db($apiStore);
    $stmt = $pdo->prepare("SELECT api_key FROM api_keys WHERE username = :u");
    $stmt->execute([":u" => $username]);
    $existing = $stmt->fetchColumn();
    // An unfinished SELECT holds a read snapshot that the INSERT below would have to upgrade.
    $stmt->closeCursor();
    if (is_string($existing) && $existing !== "") {
        return $existing;
    }
    $newKey = base64url_encode(random_bytes(24));
    $ins = $pdo->prepare(
        "INSERT OR REPLACE INTO api_keys (username, api_key) VALUES (:u, :k)"
    );
    $ins->execute([":u" => $username, ":k" => $newKey]);
    return $newKey;
}

function get_user_by_apikey(string $apiKey, string $apiStore): ?string
{
    $pdo = storage_db($apiStore);
    $stmt = $pdo->prepare(
        "SELECT username FROM api_keys WHERE api_key = :k LIMIT 1"
    );
    $stmt->execute([":k" => $apiKey]);
    $user = $stmt->fetchColumn();
    if ($user === false || $user === null || $user === "") {
        return null;
    }
    return (string) $user;
}

/**
 * Upserts the given providers and replaces only their provider_keys rows, in one BEGIN
 * IMMEDIATE transaction. Providers missing from $providers are left untouched: delete_provider()
 * is the only way to delete one. An entry without a "keys" array keeps its stored keys. A key
 * keeps the larger of its stored and incoming max_token_exp. Whole rows are rewritten from the
 * caller's copy, so hot paths (token issuance, key rotation) must use provider_update_fields()
 * and provider_key_insert() instead.
 */
function save_providers(string $storePath, array $providers): void
{
    storage_initialize($storePath);
    $pdo = storage_db($storePath);
    storage_write_transaction($pdo, function (PDO $pdo) use ($providers): void {
        foreach ($providers as $prov) {
            if (!is_array($prov)) {
                throw new InvalidArgumentException("Invalid provider entry");
            }
            $providerId = storage_upsert_provider_row($pdo, $prov);
            if (isset($prov["keys"]) && is_array($prov["keys"])) {
                storage_replace_provider_keys($pdo, $providerId, $prov["keys"]);
            }
        }
    });
}

/** Inserts or updates one providers row from a load_providers()-shaped array; returns its id. */
function storage_upsert_provider_row(PDO $pdo, array $prov): string
{
    foreach (["id", "owner", "friendly", "idp_id"] as $required) {
        if (!isset($prov[$required]) || !is_scalar($prov[$required]) || (string) $prov[$required] === "") {
            throw new InvalidArgumentException("Provider field '$required' is required");
        }
    }
    $optionalString = static fn($v): ?string => is_scalar($v) ? (string) $v : null;
    $optionalInt = static fn($v): ?int => is_numeric($v) ? (int) $v : null;
    $stmt = $pdo->prepare(
        "INSERT INTO providers (" .
            "id, owner, friendly, idp_id, alg, created_at, last_issued_at, " .
            "key_ttl_seconds, expired_key_retention_seconds, key_rotation_lead_time_seconds, active_kid, default_auth_policy" .
        ") VALUES (" .
            ":id, :owner, :friendly, :idp_id, :alg, :created_at, :last_issued_at, " .
            ":key_ttl_seconds, :expired, :lead, :active_kid, :default_auth_policy" .
        ") ON CONFLICT(id) DO UPDATE SET " .
            "owner = excluded.owner," .
            "friendly = excluded.friendly," .
            "idp_id = excluded.idp_id," .
            "alg = excluded.alg," .
            "created_at = excluded.created_at," .
            "last_issued_at = excluded.last_issued_at," .
            "key_ttl_seconds = excluded.key_ttl_seconds," .
            "expired_key_retention_seconds = excluded.expired_key_retention_seconds," .
            "key_rotation_lead_time_seconds = excluded.key_rotation_lead_time_seconds," .
            "active_kid = excluded.active_kid," .
            "default_auth_policy = excluded.default_auth_policy"
    );
    storage_execute($stmt, [
        ":id" => (string) $prov["id"],
        ":owner" => (string) $prov["owner"],
        ":friendly" => (string) $prov["friendly"],
        ":idp_id" => (string) $prov["idp_id"],
        ":alg" => $optionalString($prov["alg"] ?? null),
        ":created_at" => $optionalString($prov["created_at"] ?? null),
        ":last_issued_at" => $optionalString($prov["last_issued_at"] ?? null),
        ":key_ttl_seconds" => $optionalInt($prov["key_ttl_seconds"] ?? null),
        ":expired" => $optionalInt($prov["expired_key_retention_seconds"] ?? null),
        ":lead" => $optionalInt($prov["key_rotation_lead_time_seconds"] ?? null),
        ":active_kid" => $optionalString($prov["active_kid"] ?? null),
        ":default_auth_policy" => $optionalString($prov["default_auth_policy"] ?? null) ?? "flexible",
    ]);
    return (string) $prov["id"];
}

/** Bound values for one provider_keys row; $ordinal orders the provider's keys. */
function storage_provider_key_params(string $providerId, array $key, int $ordinal): array
{
    $kid = isset($key["kid"]) && is_scalar($key["kid"]) ? (string) $key["kid"] : "";
    if ($kid === "") {
        throw new InvalidArgumentException("Provider key without kid");
    }
    $material = $key["material"] ?? [];
    $materialJson = json_encode($material, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($materialJson === false) {
        $materialJson = json_encode(new stdClass());
    }
    $type = $key["type"] ?? (is_array($material) ? ($material["type"] ?? null) : null);
    $optionalString = static fn($v): ?string => is_scalar($v) ? (string) $v : null;
    $optionalInt = static fn($v): ?int => is_numeric($v) ? (int) $v : null;
    return [
        ":provider_id" => $providerId,
        ":kid" => $kid,
        ":alg" => $optionalString($key["alg"] ?? null),
        ":type" => $optionalString($type),
        ":created_at" => $optionalString($key["created_at"] ?? null),
        ":valid_from" => $optionalString($key["valid_from"] ?? null),
        ":expires_at" => $optionalString($key["expires_at"] ?? null),
        ":valid_for_seconds" => $optionalInt($key["valid_for_seconds"] ?? null),
        ":material_json" => (string) $materialJson,
        ":ordinal" => $ordinal,
        ":max_token_exp" => $optionalInt($key["max_token_exp"] ?? null),
    ];
}

/**
 * Makes the provider's keys match $keys: upserts each entry (ordinal = its position) and
 * deletes stored keys that are not listed. Runs inside the caller's write transaction.
 */
function storage_replace_provider_keys(PDO $pdo, string $providerId, array $keys): void
{
    $sel = $pdo->prepare("SELECT kid FROM provider_keys WHERE provider_id = :pid");
    storage_execute($sel, [":pid" => $providerId]);
    $unlisted = [];
    foreach ($sel->fetchAll(PDO::FETCH_COLUMN) as $storedKid) {
        $unlisted[(string) $storedKid] = true;
    }

    $upsert = $pdo->prepare(
        "INSERT INTO provider_keys (" .
            "provider_id, kid, alg, type, created_at, valid_from, expires_at, valid_for_seconds, material_json, ordinal, max_token_exp" .
        ") VALUES (" .
            ":provider_id, :kid, :alg, :type, :created_at, :valid_from, :expires_at, :valid_for_seconds, :material_json, :ordinal, :max_token_exp" .
        ") ON CONFLICT(provider_id, kid) DO UPDATE SET " .
            "alg = excluded.alg, type = excluded.type, created_at = excluded.created_at, " .
            "valid_from = excluded.valid_from, expires_at = excluded.expires_at, " .
            "valid_for_seconds = excluded.valid_for_seconds, material_json = excluded.material_json, " .
            "ordinal = excluded.ordinal, " .
            "max_token_exp = CASE " .
                "WHEN provider_keys.max_token_exp IS NULL THEN excluded.max_token_exp " .
                "WHEN excluded.max_token_exp IS NULL THEN provider_keys.max_token_exp " .
                "ELSE MAX(provider_keys.max_token_exp, excluded.max_token_exp) END"
    );
    $listed = [];
    foreach (array_values($keys) as $ordinal => $key) {
        if (!is_array($key)) {
            throw new InvalidArgumentException("Invalid provider key entry");
        }
        $params = storage_provider_key_params($providerId, $key, $ordinal);
        $kid = $params[":kid"];
        if (isset($listed[$kid])) {
            throw new InvalidArgumentException("Duplicate key id on provider");
        }
        $listed[$kid] = true;
        unset($unlisted[$kid]);
        storage_execute($upsert, $params);
    }

    if (!empty($unlisted)) {
        $del = $pdo->prepare("DELETE FROM provider_keys WHERE provider_id = :pid AND kid = :kid");
        foreach (array_keys($unlisted) as $kid) {
            storage_execute($del, [":pid" => $providerId, ":kid" => (string) $kid]);
        }
    }
}

/**
 * Deletes one provider. Its clients, apps, certificates, keys, sessions, tokens and other
 * dependent rows go with it (ON DELETE CASCADE). In the same write transaction its SSO audit
 * rows are first copied to sso_audit_logs_archive (storage_archive_provider_audit_logs(),
 * G1a-01), so deleting a provider does not erase what happened at it, and afterwards the
 * owner's password copies that no connector pushes any more are cleared
 * (vault_purge_unused_password_copies(), S04-08): the cascade removed the provider's SCIM
 * connectors. A failed purge is logged and does not stop the deletion. Returns true when a
 * provider was deleted.
 */
function delete_provider(string $storePath, string $providerId): bool
{
    if ($providerId === "") {
        return false;
    }
    storage_initialize($storePath);
    return (bool) storage_write_transaction(
        storage_db($storePath),
        static function (PDO $pdo) use ($providerId): bool {
            $sel = $pdo->prepare("SELECT owner, idp_id FROM providers WHERE id = :id");
            storage_execute($sel, [":id" => $providerId]);
            $provider = $sel->fetch(PDO::FETCH_ASSOC);
            $sel->closeCursor();
            if (!is_array($provider)) {
                return false;
            }
            $owner = (string) $provider["owner"];
            storage_archive_provider_audit_logs($pdo, $providerId, $owner, (string) $provider["idp_id"]);
            $stmt = $pdo->prepare("DELETE FROM providers WHERE id = :id");
            storage_execute($stmt, [":id" => $providerId]);
            if ($stmt->rowCount() < 1) {
                return false;
            }
            if (function_exists("vault_purge_unused_password_copies")) {
                try {
                    vault_purge_unused_password_copies($pdo, $owner);
                } catch (Throwable $e) {
                    error_log("Provider deleted; clearing unused password copies failed: " . $e->getMessage());
                }
            }
            return true;
        }
    );
}

/** Days a deleted provider's SSO audit rows stay in sso_audit_logs_archive (G1a-01). */
const SSO_AUDIT_ARCHIVE_RETENTION_DAYS = 365;

/**
 * Copies every sso_audit_logs row of provider $providerId to sso_audit_logs_archive, with the
 * provider's $owner and $idpId and the time of archiving, then removes archived rows older than
 * SSO_AUDIT_ARCHIVE_RETENTION_DAYS (at most 5000 per call). Runs in the caller's write
 * transaction, before the provider row is deleted. Returns the number of rows archived.
 */
function storage_archive_provider_audit_logs(
    PDO $pdo,
    string $providerId,
    string $owner,
    string $idpId
): int {
    $copy = $pdo->prepare(
        "INSERT INTO sso_audit_logs_archive (" .
            "source_id, provider_id, owner, idp_id, created_at, protocol, event_type, app_name, " .
            "username, amr_json, status, details_json, audit_class, archived_at" .
        ") SELECT id, provider_id, :owner, :idp, created_at, protocol, event_type, app_name, " .
            "username, amr_json, status, details_json, audit_class, :at " .
            "FROM sso_audit_logs WHERE provider_id = :pid ORDER BY id ASC"
    );
    storage_execute($copy, [
        ":owner" => $owner,
        ":idp" => $idpId,
        ":at" => gmdate("Y-m-d\TH:i:s\Z"),
        ":pid" => $providerId,
    ]);
    $archived = $copy->rowCount();
    storage_execute(
        $pdo->prepare(
            "DELETE FROM sso_audit_logs_archive WHERE id IN (" .
                "SELECT id FROM sso_audit_logs_archive WHERE archived_at < :cutoff LIMIT 5000" .
            ")"
        ),
        [":cutoff" => gmdate("Y-m-d\TH:i:s\Z", time() - SSO_AUDIT_ARCHIVE_RETENTION_DAYS * 86400)]
    );
    return $archived;
}

/**
 * Targeted single-statement update of provider settings, for admin routes and hot paths that
 * must not rewrite every provider. Allowed fields: alg, key_ttl_seconds,
 * expired_key_retention_seconds (null allowed), key_rotation_lead_time_seconds, active_kid,
 * default_auth_policy and last_issued_at. Any other key, or a value of the wrong type, throws
 * InvalidArgumentException.
 */
function provider_update_fields(string $storePath, string $providerId, array $fields): void
{
    $sets = [];
    $params = [":id" => $providerId];
    foreach ($fields as $name => $value) {
        $name = (string) $name;
        switch ($name) {
            case "key_ttl_seconds":
            case "key_rotation_lead_time_seconds":
            case "expired_key_retention_seconds":
                if ($value === null && $name === "expired_key_retention_seconds") {
                    break;
                }
                if (is_string($value) && preg_match('/^\d{1,18}$/D', $value) === 1) {
                    $value = (int) $value;
                }
                if (!is_int($value) || $value < 0) {
                    throw new InvalidArgumentException("$name must be a non-negative integer");
                }
                break;
            case "alg":
            case "active_kid":
            case "last_issued_at":
                if ($value !== null && !is_string($value)) {
                    throw new InvalidArgumentException("$name must be a string or null");
                }
                break;
            case "default_auth_policy":
                if (!in_array($value, ["flexible", "touchid_only", "mfa"], true)) {
                    throw new InvalidArgumentException("Invalid default_auth_policy");
                }
                break;
            default:
                throw new InvalidArgumentException("Unknown provider field: " . $name);
        }
        $sets[] = $name . " = :f_" . $name;
        $params[":f_" . $name] = $value;
    }
    if (empty($sets)) {
        return;
    }
    storage_initialize($storePath);
    $stmt = storage_db($storePath)->prepare(
        "UPDATE providers SET " . implode(", ", $sets) . " WHERE id = :id"
    );
    storage_execute($stmt, $params);
}

/**
 * Adds one key (a wrap_key_entry()-shaped array) to a provider without rewriting the others:
 * ordinal = current maximum + 1, all under BEGIN IMMEDIATE. A kid that already exists throws
 * InvalidArgumentException("Key already exists on this provider"); an unknown provider throws
 * RuntimeException. With $activate the key also becomes active_kid and its alg the provider alg.
 */
function provider_key_insert(
    string $storePath,
    string $providerId,
    array $keyEntry,
    bool $activate = false
): void {
    storage_initialize($storePath);
    $pdo = storage_db($storePath);
    storage_write_transaction($pdo, function (PDO $pdo) use ($providerId, $keyEntry, $activate): void {
        $prov = $pdo->prepare("SELECT 1 FROM providers WHERE id = :id");
        storage_execute($prov, [":id" => $providerId]);
        $found = $prov->fetchColumn() !== false;
        $prov->closeCursor();
        if (!$found) {
            throw new RuntimeException("Provider not found");
        }
        $next = $pdo->prepare(
            "SELECT COALESCE(MAX(ordinal), -1) + 1 FROM provider_keys WHERE provider_id = :pid"
        );
        storage_execute($next, [":pid" => $providerId]);
        $ordinal = (int) $next->fetchColumn();
        $next->closeCursor();

        $params = storage_provider_key_params($providerId, $keyEntry, $ordinal);
        $dup = $pdo->prepare("SELECT 1 FROM provider_keys WHERE provider_id = :pid AND kid = :kid");
        storage_execute($dup, [":pid" => $providerId, ":kid" => $params[":kid"]]);
        $exists = $dup->fetchColumn() !== false;
        $dup->closeCursor();
        if ($exists) {
            throw new InvalidArgumentException("Key already exists on this provider");
        }
        storage_execute(
            $pdo->prepare(
                "INSERT INTO provider_keys (" .
                    "provider_id, kid, alg, type, created_at, valid_from, expires_at, valid_for_seconds, material_json, ordinal, max_token_exp" .
                ") VALUES (" .
                    ":provider_id, :kid, :alg, :type, :created_at, :valid_from, :expires_at, :valid_for_seconds, :material_json, :ordinal, :max_token_exp" .
                ")"
            ),
            $params
        );
        if ($activate) {
            storage_execute(
                $pdo->prepare(
                    "UPDATE providers SET active_kid = :kid, alg = COALESCE(:alg, alg) WHERE id = :id"
                ),
                [
                    ":kid" => $params[":kid"],
                    ":alg" => $params[":alg"] !== null && $params[":alg"] !== "" ? $params[":alg"] : null,
                    ":id" => $providerId,
                ]
            );
        }
    });
}

/**
 * Deletes one key of a provider. The provider's active key and its last remaining key are
 * never deleted (false is returned), so a concurrent change cannot leave it unable to sign.
 * Returns true when a row was deleted.
 */
function provider_key_delete(string $storePath, string $providerId, string $kid): bool
{
    storage_initialize($storePath);
    $stmt = storage_db($storePath)->prepare(
        "DELETE FROM provider_keys WHERE provider_id = :pid AND kid = :kid " .
            "AND kid IS NOT (SELECT active_kid FROM providers WHERE id = :pid) " .
            "AND (SELECT COUNT(*) FROM provider_keys WHERE provider_id = :pid) > 1"
    );
    storage_execute($stmt, [":pid" => $providerId, ":kid" => $kid]);
    return $stmt->rowCount() > 0;
}

/**
 * Loads providers with their keys, in the shape load_providers() returns: every provider, or
 * only the one whose id is $providerId.
 */
function storage_load_providers(PDO $pdo, ?string $providerId = null): array
{
    $where = $providerId !== null ? " WHERE id = :id" : "";
    $provStmt = $pdo->prepare(
        "SELECT rowid, id, owner, friendly, idp_id, alg, created_at, last_issued_at, " .
            "key_ttl_seconds, expired_key_retention_seconds, key_rotation_lead_time_seconds, active_kid, default_auth_policy " .
            "FROM providers" . $where . " ORDER BY rowid ASC"
    );
    storage_execute($provStmt, $providerId !== null ? [":id" => $providerId] : []);
    $providers = [];
    while ($prov = $provStmt->fetch(PDO::FETCH_ASSOC)) {
        $id = (string) $prov["id"];
        $providers[$id] = [
            "id" => $id,
            "owner" => $prov["owner"],
            "friendly" => $prov["friendly"],
            "idp_id" => $prov["idp_id"],
            "alg" => $prov["alg"],
            "created_at" => $prov["created_at"],
            "last_issued_at" => $prov["last_issued_at"],
            "key_ttl_seconds" => isset($prov["key_ttl_seconds"])
                ? (int) $prov["key_ttl_seconds"]
                : null,
            "expired_key_retention_seconds" => isset(
                $prov["expired_key_retention_seconds"]
            )
                ? (int) $prov["expired_key_retention_seconds"]
                : null,
            "key_rotation_lead_time_seconds" => isset(
                $prov["key_rotation_lead_time_seconds"]
            )
                ? (int) $prov["key_rotation_lead_time_seconds"]
                : null,
            "active_kid" => $prov["active_kid"],
            "default_auth_policy" =>
                $prov["default_auth_policy"] ?? "flexible",
            "keys" => [],
        ];
    }
    if (empty($providers)) {
        return [];
    }

    $keyWhere = $providerId !== null ? " WHERE provider_id = :pid" : "";
    $keyStmt = $pdo->prepare(
        "SELECT provider_id, kid, alg, type, created_at, valid_from, expires_at, valid_for_seconds, material_json, ordinal, max_token_exp " .
            "FROM provider_keys" . $keyWhere . " ORDER BY provider_id ASC, ordinal ASC, created_at ASC, kid ASC"
    );
    storage_execute($keyStmt, $providerId !== null ? [":pid" => $providerId] : []);
    while ($row = $keyStmt->fetch(PDO::FETCH_ASSOC)) {
        $rowProviderId = (string) $row["provider_id"];
        if (!isset($providers[$rowProviderId])) {
            continue;
        }
        $material = json_decode($row["material_json"] ?? "", true);
        if (!is_array($material)) {
            $material = [];
        }
        $providers[$rowProviderId]["keys"][] = [
            "kid" => $row["kid"],
            "alg" => $row["alg"],
            "type" => $row["type"],
            "created_at" => $row["created_at"],
            "valid_from" => $row["valid_from"],
            "expires_at" => $row["expires_at"],
            "valid_for_seconds" => isset($row["valid_for_seconds"])
                ? (int) $row["valid_for_seconds"]
                : null,
            "max_token_exp" => isset($row["max_token_exp"])
                ? (int) $row["max_token_exp"]
                : null,
            "material" => $material,
        ];
    }

    return array_values($providers);
}

function load_providers(string $storePath): array
{
    storage_initialize($storePath);
    return storage_load_providers(storage_db($storePath));
}

/** One provider in the load_providers() shape (keys included), or null. */
function load_provider_by_id(string $storePath, string $providerId): ?array
{
    if ($providerId === "") {
        return null;
    }
    storage_initialize($storePath);
    return storage_load_providers(storage_db($storePath), $providerId)[0] ?? null;
}

/**
 * One provider in the load_providers() shape, looked up by the idp_id from a URL with the
 * rules of find_provider_by_idpid(): the exact stored idp_id first, otherwise a case-insensitive
 * or rawurldecoded match only when exactly one provider matches.
 */
function load_provider_by_idp_id(string $storePath, string $idpId): ?array
{
    if ($idpId === "") {
        return null;
    }
    storage_initialize($storePath);
    $pdo = storage_db($storePath);
    $exact = $pdo->prepare("SELECT id FROM providers WHERE idp_id = :idp LIMIT 1");
    storage_execute($exact, [":idp" => $idpId]);
    $id = $exact->fetchColumn();
    $exact->closeCursor();
    if ($id === false) {
        $candidates = $pdo
            ->query("SELECT id, idp_id FROM providers ORDER BY rowid ASC")
            ->fetchAll(PDO::FETCH_ASSOC);
        $match = find_provider_by_idpid($candidates, $idpId);
        if ($match === null) {
            return null;
        }
        $id = $match["id"];
    }
    return load_provider_by_id($storePath, (string) $id);
}

/**
 * Finds a provider by the idp_id taken from a URL. The exact stored idp_id wins. Otherwise a
 * rawurldecoded match, then a case-insensitive one, is accepted only when exactly one provider
 * matches; an ambiguous match returns null, so "Acme-prod" never resolves to "acme-prod".
 */
function find_provider_by_idpid(array $providers, string $idpId): ?array
{
    if ($idpId === "") {
        return null;
    }
    foreach ($providers as $p) {
        if ((string) ($p["idp_id"] ?? "") === $idpId) {
            return $p;
        }
    }
    $decodedTarget = rawurldecode($idpId);
    $fallbacks = [
        static fn(string $stored): bool => rawurldecode($stored) === $decodedTarget,
        static fn(string $stored): bool => strcasecmp($stored, $idpId) === 0 ||
            strcasecmp(rawurldecode($stored), $decodedTarget) === 0,
    ];
    foreach ($fallbacks as $matches) {
        $found = [];
        foreach ($providers as $p) {
            if ($matches((string) ($p["idp_id"] ?? ""))) {
                $found[(string) ($p["id"] ?? "")] = $p;
            }
        }
        if (count($found) === 1) {
            return reset($found);
        }
        if (count($found) > 1) {
            return null;
        }
    }
    return null;
}

function find_provider_by_id(array $providers, string $id): ?array
{
    foreach ($providers as $p) {
        if ($p["id"] === $id) {
            return $p;
        }
    }
    return null;
}

function find_provider_by_name_owner(
    array $providers,
    string $owner,
    string $friendly
): ?array {
    foreach ($providers as $p) {
        if (
            $p["owner"] === $owner &&
            strcasecmp($p["friendly"], $friendly) === 0
        ) {
            return $p;
        }
    }
    return null;
}

/**
 * Appends one audit row. Events that anyone can trigger without authenticating (unknown SAML
 * issuers, failed password and passkey logins, or any call with $untrusted = true) go into the
 * 'untrusted' class, which keeps only the newest 250 rows per provider and never evicts other
 * rows. All other rows are kept for 180 days, with a ceiling of 5000 per provider, pruned in
 * batches. app_name, username and string detail values are clipped to 256 characters with
 * sanitize_label(), since they often carry request data. Never throws.
 */
function audit_log_append(
    string $storePath,
    string $providerId,
    string $protocol,
    string $eventType,
    string $status,
    string $appName = "",
    string $username = "",
    array $amr = [],
    array $details = [],
    bool $untrusted = false
): void {
    try {
        $class =
            $untrusted ||
            in_array($eventType, ["unknown_sp_issuer", "password_login_failed", "touchid_failed"], true)
                ? "untrusted"
                : "security";
        $jsonFlags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;
        $pdo = storage_db($storePath);
        $stmt = $pdo->prepare(
            "INSERT INTO sso_audit_logs (provider_id, created_at, protocol, event_type, app_name, username, amr_json, status, details_json, audit_class) " .
                "VALUES (:pid, :cat, :proto, :evt, :app, :usr, :amr, :st, :det, :cls)"
        );
        $stmt->execute([
            ":pid" => $providerId,
            ":cat" => gmdate("Y-m-d\TH:i:s\Z"),
            ":proto" => sanitize_label($protocol, 32),
            ":evt" => sanitize_label($eventType, 64),
            ":app" => sanitize_label($appName, 256),
            ":usr" => sanitize_label($username, 256),
            ":amr" => json_encode(audit_log_clip_values(array_values($amr)), $jsonFlags) ?: "[]",
            ":st" => sanitize_label($status, 32),
            ":det" => json_encode(audit_log_clip_values($details), $jsonFlags) ?: "{}",
            ":cls" => $class,
        ]);
        audit_log_prune($pdo, $providerId, $class);
    } catch (Throwable $e) {
        // Auditing must never break the request that triggered it.
        error_log("audit_log_append: audit row not written (" . get_class($e) . ")");
    }
}

/**
 * Bounds audit detail data: string values through sanitize_label(..., 256), string keys to 64
 * characters, at most 50 entries per level and 4 levels of nesting.
 */
function audit_log_clip_values(array $values, int $depth = 0): array
{
    $out = [];
    $count = 0;
    foreach ($values as $key => $value) {
        if (++$count > 50) {
            $out["_truncated"] = true;
            break;
        }
        if (is_string($key)) {
            $key = sanitize_label($key, 64);
            if ($key === "") {
                $key = "_";
            }
        }
        if (is_string($value)) {
            $out[$key] = sanitize_label($value, 256);
        } elseif (is_array($value)) {
            $out[$key] = $depth < 3 ? audit_log_clip_values($value, $depth + 1) : "[nested]";
        } elseif (is_scalar($value) || $value === null) {
            $out[$key] = $value;
        } else {
            $out[$key] = get_debug_type($value);
        }
    }
    return $out;
}

/**
 * Removes audit rows beyond the retention of $class for one provider, oldest first and at most
 * 200 (untrusted) or 500 (security) rows per call. The untrusted cap is enforced on every insert;
 * the age limit and ceiling of the security class are checked on about 1 in 20 inserts.
 */
function audit_log_prune(PDO $pdo, string $providerId, string $class): void
{
    // Deletes the class's rows older than its $keep newest ones (none while there are fewer).
    $beyondNewest =
        "DELETE FROM sso_audit_logs WHERE id IN (" .
            "SELECT id FROM sso_audit_logs WHERE provider_id = :pid AND audit_class = :cls AND id < (" .
                "SELECT id FROM sso_audit_logs WHERE provider_id = :pid AND audit_class = :cls " .
                "ORDER BY id DESC LIMIT 1 OFFSET :keep" .
            ") ORDER BY id ASC LIMIT :batch" .
        ")";
    if ($class === "untrusted") {
        storage_execute($pdo->prepare($beyondNewest), [
            ":pid" => $providerId,
            ":cls" => "untrusted",
            ":keep" => 249,
            ":batch" => 200,
        ]);
        return;
    }
    if (mt_rand(1, 20) !== 1) {
        return;
    }
    storage_execute(
        $pdo->prepare(
            "DELETE FROM sso_audit_logs WHERE id IN (" .
                "SELECT id FROM sso_audit_logs WHERE provider_id = :pid AND audit_class = :cls " .
                "AND created_at < :cutoff ORDER BY id ASC LIMIT :batch" .
            ")"
        ),
        [
            ":pid" => $providerId,
            ":cls" => $class,
            ":cutoff" => gmdate("Y-m-d\TH:i:s\Z", time() - 180 * 86400),
            ":batch" => 500,
        ]
    );
    storage_execute($pdo->prepare($beyondNewest), [
        ":pid" => $providerId,
        ":cls" => $class,
        ":keep" => 4999,
        ":batch" => 500,
    ]);
}

function audit_log_list(string $storePath, string $providerId, int $limit = 100): array
{
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT id, created_at, protocol, event_type, app_name, username, amr_json, status, details_json " .
            "FROM sso_audit_logs WHERE provider_id = :pid ORDER BY id DESC LIMIT :lim"
    );
    $stmt->bindValue(":pid", $providerId, PDO::PARAM_STR);
    $stmt->bindValue(":lim", max(1, min(500, $limit)), PDO::PARAM_INT);
    $stmt->execute();
    $rows = [];
    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $rows[] = [
            "id" => (int) $r["id"],
            "created_at" => $r["created_at"],
            "protocol" => $r["protocol"],
            "event_type" => $r["event_type"],
            "app_name" => $r["app_name"],
            "username" => $r["username"],
            "amr" => json_decode($r["amr_json"] ?? "[]", true) ?: [],
            "status" => $r["status"],
            "details" => json_decode($r["details_json"] ?? "{}", true) ?: [],
        ];
    }
    return $rows;
}

// ---------- SSO session participants (S02-05) ----------

/**
 * Records that SSO session $ssoSessionId of provider $providerId signed the user in to app
 * $appId, with the NameID, its Format and the SessionIndex the assertion carried, so single
 * logout can reach every app of the session (sso_session_participants). One row per session
 * and app: a later assertion to the same app replaces the NameID, Format and SessionIndex.
 * Nothing is written when the session does not exist (any more) for that provider, or when an
 * id is empty or a value is longer than such a value can be (ids 128 bytes, NameID 1024,
 * Format and SessionIndex 256). The row is deleted together with its session. Returns whether
 * a row was written. Never throws: a failure is logged and must not fail the sign-in.
 */
function sso_session_participant_record(
    string $storePath,
    string $ssoSessionId,
    string $providerId,
    string $appId,
    string $nameId,
    string $nameIdFormat = "",
    string $sessionIndex = ""
): bool {
    if (
        $ssoSessionId === "" || $providerId === "" || $appId === "" ||
        strlen($ssoSessionId) > 128 || strlen($providerId) > 128 || strlen($appId) > 128 ||
        strlen($nameId) > 1024 || strlen($nameIdFormat) > 256 || strlen($sessionIndex) > 256
    ) {
        return false;
    }
    try {
        // The WHERE clause also keeps the upsert unambiguous after INSERT ... SELECT.
        $stmt = storage_db($storePath)->prepare(
            "INSERT INTO sso_session_participants " .
                "(sso_session_id, provider_id, app_id, name_id, name_id_format, session_index, created_at) " .
                "SELECT :sid, :pid, :app, :nid, :fmt, :idx, :cat " .
                "WHERE EXISTS (SELECT 1 FROM sso_sessions WHERE id = :sid AND provider_id = :pid) " .
                "ON CONFLICT(sso_session_id, app_id) DO UPDATE SET " .
                "name_id = excluded.name_id, name_id_format = excluded.name_id_format, " .
                "session_index = excluded.session_index"
        );
        storage_execute($stmt, [
            ":sid" => $ssoSessionId,
            ":pid" => $providerId,
            ":app" => $appId,
            ":nid" => $nameId,
            ":fmt" => $nameIdFormat,
            ":idx" => $sessionIndex,
            ":cat" => gmdate("Y-m-d\TH:i:s\Z"),
        ]);
        return $stmt->rowCount() > 0;
    } catch (Throwable $e) {
        error_log("sso_session_participant_record: participant not recorded (" . get_class($e) . ")");
        return false;
    }
}

/**
 * The apps SSO session $ssoSessionId signed the user in to (sso_session_participant_record()),
 * oldest first, each as provider_id, app_id, name_id, name_id_format, session_index and
 * created_at. With $providerId, only that provider's rows. Apps deleted since are included, so
 * resolve app_id before sending anything to one.
 */
function sso_session_participants_list(
    string $storePath,
    string $ssoSessionId,
    ?string $providerId = null
): array {
    if ($ssoSessionId === "") {
        return [];
    }
    $sql =
        "SELECT provider_id, app_id, name_id, name_id_format, session_index, created_at " .
        "FROM sso_session_participants WHERE sso_session_id = :sid";
    $params = [":sid" => $ssoSessionId];
    if ($providerId !== null) {
        $sql .= " AND provider_id = :pid";
        $params[":pid"] = $providerId;
    }
    $stmt = storage_db($storePath)->prepare($sql . " ORDER BY created_at ASC, app_id ASC");
    storage_execute($stmt, $params);
    $out = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $out[] = [
            "provider_id" => (string) $r["provider_id"],
            "app_id" => (string) $r["app_id"],
            "name_id" => (string) $r["name_id"],
            "name_id_format" => (string) $r["name_id_format"],
            "session_index" => (string) $r["session_index"],
            "created_at" => (string) $r["created_at"],
        ];
    }
    return $out;
}
