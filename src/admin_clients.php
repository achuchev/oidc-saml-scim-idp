<?php
declare(strict_types=1);

/**
 * Programmatic Administration API Clients & Provider-Scoped RBAC.
 *
 * Supports external API clients authenticating via:
 *   1. Authorization: Bearer idp_adm_<tokenId>_<secret>  (or ApiKey / X-API-Key)
 *   2. Authorization: Basic base64(<client_id>:<client_secret>)
 *   3. OAuth 2.0 Client Credentials Grant (POST /api/oauth2/token -> Bearer idp_at_<token>)
 *
 * A client authenticates only while it is active and unexpired and its owner is still an
 * admin in users.txt (S10-04), and, when it has allowed_ips, only from those addresses
 * (admin_client_source_allowed()). Its secret is stored as machine_secret_hash() (X3-09).
 */

/**
 * storage_db() for the admin API tables, with this lane's run-once migrations applied
 * (schema_ensure(), never inside a transaction):
 *  - api.admin_audit_v1: admin_audit_logs, the admin audit trail (G1a-01). It has no foreign
 *    key to providers, so deleting a provider keeps the record of what was done to it.
 *  - api.admin_audit_v2: an index for the per-owner, per-class retention (admin_audit_prune()).
 *  - api.admin_client_can_mint_tokens_v2: admin_api_clients.can_mint_tokens (G1a-02). Clients
 *    that existed before the upgrade get 0, like new clients that are not granted it, so
 *    provider write alone no longer implies token minting; the operator flag
 *    legacy_api_client_token_minting restores that (auth_require_token_minting()).
 *  - api.admin_mfa_totp_v1: admin_mfa_totp, the administrators' authenticator apps (G2a-07).
 *  - api.admin_client_allowed_ips_v1: admin_api_clients.allowed_ips_json, the client's IP
 *    allowlist (normalized CIDR blocks). Existing clients get [] (any address).
 */
function admin_api_db(string $storePath): PDO
{
    storage_initialize($storePath);
    $pdo = storage_db($storePath);
    if ($pdo->inTransaction()) {
        return $pdo;
    }
    $migrations = [
        "api.admin_audit_v1" => [
            "CREATE TABLE IF NOT EXISTS admin_audit_logs (" .
                "id INTEGER PRIMARY KEY AUTOINCREMENT," .
                "created_at TEXT NOT NULL," .
                "owner TEXT NOT NULL DEFAULT ''," .
                "actor_type TEXT NOT NULL DEFAULT ''," .
                "actor_id TEXT NOT NULL DEFAULT ''," .
                "actor_name TEXT NOT NULL DEFAULT ''," .
                "source_ip TEXT NOT NULL DEFAULT ''," .
                "user_agent TEXT NOT NULL DEFAULT ''," .
                "action TEXT NOT NULL," .
                "outcome TEXT NOT NULL DEFAULT 'success'," .
                "provider_id TEXT," .
                "target TEXT NOT NULL DEFAULT ''," .
                "details_json TEXT NOT NULL DEFAULT '{}'," .
                // 'security', or 'untrusted' for unauthenticated events (see admin_audit_append()).
                "audit_class TEXT NOT NULL DEFAULT 'security'" .
            ")",
            "CREATE INDEX IF NOT EXISTS idx_admin_audit_owner ON admin_audit_logs(owner, id)",
            "CREATE INDEX IF NOT EXISTS idx_admin_audit_class ON admin_audit_logs(audit_class, id)",
            "CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_logs(created_at)",
        ],
        "api.admin_audit_v2" => [
            "CREATE INDEX IF NOT EXISTS idx_admin_audit_owner_class ON admin_audit_logs(owner, audit_class, id)",
        ],
        "api.admin_client_can_mint_tokens_v2" => [
            "ALTER TABLE admin_api_clients ADD COLUMN can_mint_tokens INTEGER NOT NULL DEFAULT 0",
        ],
        "api.admin_client_allowed_ips_v1" => [
            "ALTER TABLE admin_api_clients ADD COLUMN allowed_ips_json TEXT NOT NULL DEFAULT '[]'",
        ],
        "api.admin_mfa_totp_v1" => [
            "CREATE TABLE IF NOT EXISTS admin_mfa_totp (" .
                "username TEXT PRIMARY KEY," .
                // vault_encrypt_secret() of the base64 TOTP secret.
                "secret_enc TEXT NOT NULL," .
                // 'pending' until a code confirms it, then 'active'.
                "status TEXT NOT NULL DEFAULT 'pending'," .
                "created_at INTEGER NOT NULL," .
                "confirmed_at INTEGER," .
                // The newest time step accepted, so a code is never accepted twice.
                "last_step INTEGER NOT NULL DEFAULT 0" .
            ")",
        ],
    ];
    foreach ($migrations as $migrationId => $steps) {
        try {
            schema_ensure($pdo, $migrationId, $steps);
        } catch (Throwable $e) {
            error_log("admin API migration " . $migrationId . " failed (will retry): " . $e->getMessage());
        }
    }
    return $pdo;
}

function hydrate_admin_api_client_row(array $r): array
{
    $exp = isset($r["expires_at"]) && trim((string) $r["expires_at"]) !== ""
        ? (string) $r["expires_at"]
        : null;
    $isExpired = false;
    if ($exp !== null) {
        $ts = @strtotime($exp);
        if ($ts !== false && $ts <= time()) {
            $isExpired = true;
        }
    }
    return [
        "id" => (string) $r["id"],
        "owner" => (string) $r["owner"],
        "name" => (string) $r["name"],
        "description" => (string) ($r["description"] ?? ""),
        "client_id" => (string) $r["client_id"],
        "secret_preview" => (string) $r["secret_preview"],
        "provider_scope" => (string) ($r["provider_scope"] ?? "selected"),
        "allowed_provider_ids" =>
            json_decode((string) ($r["allowed_provider_ids_json"] ?? "[]"), true) ?:
            [],
        "can_create_providers" =>
            ((string) ($r["provider_scope"] ?? "selected") === "all") ||
            ((int) ($r["can_create_providers"] ?? 0) === 1),
        "provider_permission" => (string) ($r["provider_permission"] ?? "write"),
        "user_scope" => (string) ($r["user_scope"] ?? "none"),
        // May mint JWTs at POST /api/token and import private signing keys (G1a-02).
        "can_mint_tokens" => (int) ($r["can_mint_tokens"] ?? 0) === 1,
        // Normalized CIDR blocks the client may authenticate from; [] means any address.
        "allowed_ips" => admin_client_stored_allowed_ips($r["allowed_ips_json"] ?? null),
        "status" => (string) ($r["status"] ?? "active"),
        "expires_at" => $exp,
        "is_expired" => $isExpired,
        "created_at" => (string) $r["created_at"],
        "last_used_at" => $r["last_used_at"] ?? null,
        "last_used_ip" => $r["last_used_ip"] ?? null,
    ];
}

function admin_client_mint_secret(): array
{
    $tokenId = bin2hex(random_bytes(8)); // 16 hex chars
    $randomPart = base64url_encode(random_bytes(28));
    $plainSecret = "idp_adm_" . $tokenId . "_" . $randomPart;
    // A 224-bit random secret needs no slow hash (X3-09); the token id is its public lookup key.
    $secretHash = machine_secret_hash($plainSecret);
    $secretPreview = "idp_adm_" . substr($tokenId, 0, 6) . "••••••••";
    return [
        "token_id" => $tokenId,
        "plain_secret" => $plainSecret,
        "secret_hash" => $secretHash,
        "secret_preview" => $secretPreview,
    ];
}

/**
 * Resolves and validates a list of provider IDs (or idpId slugs) against providers owned by $owner.
 */
function admin_client_normalize_provider_ids(
    string $storePath,
    string $owner,
    mixed $rawIds
): array {
    if (!is_array($rawIds)) {
        $rawIds = normalize_string_list($rawIds);
    }
    // Only this owner's provider ids are read, not every tenant's providers and keys.
    $stmt = admin_api_db($storePath)->prepare(
        "SELECT id, idp_id FROM providers WHERE owner = :owner ORDER BY rowid ASC"
    );
    $stmt->execute([":owner" => $owner]);
    $ownedById = [];
    $ownedBySlug = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $p) {
        $pid = (string) $p["id"];
        $ownedById[$pid] = $pid;
        $ownedBySlug[strtolower((string) $p["idp_id"])] = $pid;
        $ownedBySlug[strtolower(rawurldecode((string) $p["idp_id"]))] = $pid;
    }

    $normalized = [];
    foreach ($rawIds as $item) {
        if (!is_scalar($item)) {
            throw new InvalidArgumentException("allowed_provider_ids must be a list of provider ids");
        }
        $val = trim((string) $item);
        if ($val === "") {
            continue;
        }
        if (isset($ownedById[$val])) {
            $normalized[] = $ownedById[$val];
        } elseif (isset($ownedBySlug[strtolower($val)])) {
            $normalized[] = $ownedBySlug[strtolower($val)];
        } else {
            throw new InvalidArgumentException(
                "Unknown or unauthorized provider identifier in allowed_provider_ids: " .
                    sanitize_label($val, 128)
            );
        }
    }
    return array_values(array_unique($normalized));
}

/**
 * Parses an expiry given as "never" (or empty, null, 0), a future ISO-8601 timestamp, or a
 * lifetime of at most 365 days in the parse_duration_seconds() grammar ("3600", "90min",
 * "1h", "2h30m", "1 day", "1w", "90d"). Returns the UTC expiry or null for never. Anything
 * else throws InvalidArgumentException instead of silently becoming one hour (S13-11).
 */
function admin_client_parse_expires_input(mixed $expiresSpec): ?string
{
    if (is_string($expiresSpec)) {
        $expiresSpec = trim($expiresSpec);
    }
    if (
        $expiresSpec === null ||
        $expiresSpec === "" ||
        $expiresSpec === 0 ||
        $expiresSpec === "0" ||
        (is_string($expiresSpec) && strtolower($expiresSpec) === "never")
    ) {
        return null;
    }
    // Accept an ISO-8601 date string directly
    if (is_string($expiresSpec) && preg_match('/^\d{4}-\d{2}-\d{2}T/', $expiresSpec)) {
        $ts = @strtotime($expiresSpec);
        if ($ts === false || $ts <= time()) {
            throw new InvalidArgumentException("expires_at must be a future ISO-8601 timestamp");
        }
        return gmdate("Y-m-d\TH:i:s\Z", $ts);
    }
    $secs = parse_duration_seconds($expiresSpec, 365 * 86400);
    if ($secs === null) {
        throw new InvalidArgumentException(
            "Invalid expiry: use 'never', a future ISO-8601 timestamp, or a lifetime of at most " .
                "365 days such as '3600', '90min', '1h', '2h30m', '1 day', '1w' or '90d'"
        );
    }
    if ($secs === 0) {
        return null;
    }
    return gmdate("Y-m-d\TH:i:s\Z", time() + $secs);
}

/**
 * The value of an enumerated input field: $default when the field is absent (or null), the
 * value when it is one of $allowed, otherwise InvalidArgumentException (G1e-02: an unknown
 * value is an error, never silently replaced by a default).
 */
function admin_client_enum_input(array $input, string $field, array $allowed, ?string $default): ?string
{
    if (!array_key_exists($field, $input) || $input[$field] === null) {
        return $default;
    }
    $value = $input[$field];
    if (!is_string($value) || !in_array($value, $allowed, true)) {
        throw new InvalidArgumentException(
            "$field must be one of: " . implode(", ", $allowed)
        );
    }
    return $value;
}

/**
 * The value of a boolean input field (G1e-02): $default when the field is absent or null, and
 * true or false for JSON true/false, 1/0 or the strings "true"/"false"/"1"/"0". Anything else
 * ("no", "off", 2, an array) throws InvalidArgumentException: a capability or activation flag
 * is never read loosely, as !empty() would read the string "false" as true.
 */
function admin_client_bool_input(array $input, string $field, bool $default): bool
{
    if (!array_key_exists($field, $input) || $input[$field] === null) {
        return $default;
    }
    $value = $input[$field];
    if (is_bool($value)) {
        return $value;
    }
    if ($value === 1 || $value === 0) {
        return $value === 1;
    }
    if (is_string($value)) {
        $normalized = strtolower(trim($value));
        if ($normalized === "true" || $normalized === "1") {
            return true;
        }
        if ($normalized === "false" || $normalized === "0") {
            return false;
        }
    }
    throw new InvalidArgumentException("$field must be true or false");
}

/**
 * A display label for a client name or description: sanitize_label() (no control or bidi
 * characters, whitespace collapsed, valid UTF-8) cut to $maxChars characters (S05-03).
 */
function admin_client_label_input(mixed $value, int $maxChars): string
{
    return is_scalar($value) ? sanitize_label((string) $value, $maxChars) : "";
}

/** Most entries an Admin API client's allowed_ips may hold (the whole list fits in an audit entry). */
const ADMIN_CLIENT_MAX_ALLOWED_IPS = 50;

/**
 * Parses allowed_ips for an Admin API client: a list of IPv4 or IPv6 addresses or CIDR
 * blocks, or one string split on whitespace and commas. Each entry goes through
 * ip_allowlist_parse_range() (no host names, wildcards or "a-b" ranges) and is stored in
 * its normalized form ("203.0.113.7/32", host bits cleared), without duplicates. Null, ""
 * and [] give [] (any address). Throws InvalidArgumentException for anything else and for
 * more than ADMIN_CLIENT_MAX_ALLOWED_IPS entries.
 */
function admin_client_allowed_ips_input(mixed $value): array
{
    if ($value === null || $value === "") {
        return [];
    }
    if (is_string($value)) {
        $value = preg_split('/[\s,]+/', $value, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }
    if (!is_array($value) || !array_is_list($value)) {
        throw new InvalidArgumentException("allowed_ips must be a list of IP addresses or CIDR blocks");
    }
    $normalized = [];
    foreach ($value as $entry) {
        if (!is_string($entry)) {
            throw new InvalidArgumentException("allowed_ips must be a list of IP addresses or CIDR blocks");
        }
        $entry = trim($entry);
        if ($entry === "") {
            continue;
        }
        $range = ip_allowlist_parse_range($entry);
        if ($range === null) {
            throw new InvalidArgumentException(
                "allowed_ips: '" . sanitize_label($entry, 64) . "' is not an IPv4 or IPv6 address or CIDR block"
            );
        }
        $normalized[$range["cidr"]] = true;
        if (count($normalized) > ADMIN_CLIENT_MAX_ALLOWED_IPS) {
            throw new InvalidArgumentException(
                "allowed_ips holds at most " . ADMIN_CLIENT_MAX_ALLOWED_IPS . " entries"
            );
        }
    }
    return array_keys($normalized);
}

/**
 * The stored allowed_ips_json of a client row as a list of CIDR strings. A missing column
 * (the migration has not run) or an empty list gives [] (any address). A value that is not
 * a JSON list of strings gives ["invalid"], which matches no address, so a damaged row
 * refuses every request instead of allowing every address.
 */
function admin_client_stored_allowed_ips(mixed $json): array
{
    if ($json === null || $json === "" || $json === "[]") {
        return [];
    }
    $decoded = json_decode((string) $json, true);
    if (!is_array($decoded) || !array_is_list($decoded)) {
        return ["invalid"];
    }
    $out = [];
    foreach ($decoded as $entry) {
        $out[] = is_string($entry) ? $entry : "invalid";
    }
    return $out;
}

function admin_client_list(string $storePath, string $owner): array
{
    $pdo = admin_api_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM admin_api_clients WHERE owner = :owner ORDER BY created_at DESC"
    );
    $stmt->execute([":owner" => $owner]);
    $out = [];
    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $out[] = hydrate_admin_api_client_row($r);
    }
    return $out;
}

function admin_client_get(
    string $storePath,
    string $owner,
    string $id
): ?array {
    $pdo = admin_api_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM admin_api_clients WHERE id = :id AND owner = :owner LIMIT 1"
    );
    $stmt->execute([":id" => $id, ":owner" => $owner]);
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    return $r ? hydrate_admin_api_client_row($r) : null;
}

function admin_client_create(
    string $storePath,
    string $owner,
    array $input
): array {
    $pdo = admin_api_db($storePath);
    $name = admin_client_label_input($input["name"] ?? "", 120);
    if ($name === "") {
        throw new InvalidArgumentException("API client name is required");
    }
    $description = admin_client_label_input($input["description"] ?? "", 280);

    $providerScope = admin_client_enum_input($input, "provider_scope", ["selected", "all"], "selected");
    $providerPermission = admin_client_enum_input($input, "provider_permission", ["read", "write"], "write");
    $userScope = admin_client_enum_input($input, "user_scope", ["none", "read", "write"], "none");

    $allowedProviderIds =
        $providerScope === "all"
            ? []
            : admin_client_normalize_provider_ids(
                $storePath,
                $owner,
                $input["allowed_provider_ids"] ?? []
            );

    $canCreateProviders =
        admin_client_bool_input($input, "can_create_providers", false) || $providerScope === "all";

    if (
        $providerScope === "selected" &&
        empty($allowedProviderIds) &&
        !$canCreateProviders
    ) {
        throw new InvalidArgumentException(
            "Select at least one provider for 'selected' scope, or enable can_create_providers"
        );
    }

    // Token minting (and private key import) is opt-in for new clients (G1a-02).
    $canMintTokens = admin_client_bool_input($input, "can_mint_tokens", false);
    $allowedIps = admin_client_allowed_ips_input($input["allowed_ips"] ?? null);

    $expiresAt = admin_client_parse_expires_input(
        $input["expires_in"] ?? ($input["expires_at"] ?? null)
    );

    $id = uuidv4();
    $clientId = "iac_" . bin2hex(random_bytes(8));
    $minted = admin_client_mint_secret();
    $now = gmdate("Y-m-d\TH:i:s\Z");

    $ins = $pdo->prepare(
        "INSERT INTO admin_api_clients (" .
            "id, owner, name, description, client_id, token_id, secret_hash, secret_preview, " .
            "provider_scope, allowed_provider_ids_json, can_create_providers, provider_permission, " .
            "user_scope, can_mint_tokens, allowed_ips_json, status, expires_at, created_at" .
        ") VALUES (" .
            ":id, :owner, :name, :desc, :cid, :tid, :sh, :sprev, :ps, :pids, :ccp, :pperm, :us, :mint, :ips, 'active', :exp, :cat" .
        ")"
    );
    $ins->execute([
        ":id" => $id,
        ":owner" => $owner,
        ":name" => $name,
        ":desc" => $description,
        ":cid" => $clientId,
        ":tid" => $minted["token_id"],
        ":sh" => $minted["secret_hash"],
        ":sprev" => $minted["secret_preview"],
        ":ps" => $providerScope,
        ":pids" => json_encode($allowedProviderIds, JSON_UNESCAPED_SLASHES),
        ":ccp" => $canCreateProviders ? 1 : 0,
        ":pperm" => $providerPermission,
        ":us" => $userScope,
        ":mint" => $canMintTokens ? 1 : 0,
        ":ips" => json_encode($allowedIps, JSON_UNESCAPED_SLASHES),
        ":exp" => $expiresAt,
        ":cat" => $now,
    ]);

    $created = admin_client_get($storePath, $owner, $id) ?? [];
    // Returned ONCE at creation!
    $created["api_token"] = $minted["plain_secret"];
    $created["client_secret"] = $minted["plain_secret"];
    return $created;
}

function admin_client_update(
    string $storePath,
    string $owner,
    string $id,
    array $input
): array {
    $existing = admin_client_get($storePath, $owner, $id);
    if (!$existing) {
        throw new RuntimeException("Admin API client not found");
    }

    $name = array_key_exists("name", $input)
        ? admin_client_label_input($input["name"], 120)
        : $existing["name"];
    if ($name === "") {
        throw new InvalidArgumentException("API client name cannot be empty");
    }
    $description = array_key_exists("description", $input)
        ? admin_client_label_input($input["description"], 280)
        : $existing["description"];

    // Unknown enum values are rejected instead of being ignored (G1e-02): a request such as
    // {"status": "disabled"} must not answer 200 while the client stays active.
    $providerScope = admin_client_enum_input(
        $input,
        "provider_scope",
        ["selected", "all"],
        (string) $existing["provider_scope"]
    );

    if ($providerScope === "all") {
        $allowedProviderIds = [];
    } elseif (array_key_exists("allowed_provider_ids", $input)) {
        $allowedProviderIds = admin_client_normalize_provider_ids(
            $storePath,
            $owner,
            $input["allowed_provider_ids"]
        );
    } else {
        $allowedProviderIds = $existing["allowed_provider_ids"];
    }

    // Booleans are parsed strictly (G1e-02); an explicit null still clears the capability.
    $canCreateProviders = array_key_exists("can_create_providers", $input)
        ? admin_client_bool_input($input, "can_create_providers", false)
        : (bool) $existing["can_create_providers"];
    if ($providerScope === "all") {
        $canCreateProviders = true;
    }

    if (
        $providerScope === "selected" &&
        empty($allowedProviderIds) &&
        !$canCreateProviders
    ) {
        throw new InvalidArgumentException(
            "Select at least one provider for 'selected' scope, or enable can_create_providers"
        );
    }

    $providerPermission = admin_client_enum_input(
        $input,
        "provider_permission",
        ["read", "write"],
        (string) $existing["provider_permission"]
    );
    $userScope = admin_client_enum_input(
        $input,
        "user_scope",
        ["none", "read", "write"],
        (string) $existing["user_scope"]
    );
    $status = admin_client_enum_input(
        $input,
        "status",
        ["active", "revoked"],
        (string) $existing["status"]
    );
    $canMintTokens = array_key_exists("can_mint_tokens", $input)
        ? admin_client_bool_input($input, "can_mint_tokens", false)
        : !empty($existing["can_mint_tokens"]);
    $allowedIps = array_key_exists("allowed_ips", $input)
        ? admin_client_allowed_ips_input($input["allowed_ips"])
        : (array) $existing["allowed_ips"];

    $expiresAt = $existing["expires_at"];
    if (array_key_exists("expires_in", $input) || array_key_exists("expires_at", $input)) {
        $expiresAt = admin_client_parse_expires_input(
            $input["expires_in"] ?? ($input["expires_at"] ?? null)
        );
    }

    $pdo = admin_api_db($storePath);
    $upd = $pdo->prepare(
        "UPDATE admin_api_clients SET " .
            "name = :name, description = :desc, provider_scope = :ps, allowed_provider_ids_json = :pids, " .
            "can_create_providers = :ccp, provider_permission = :pperm, user_scope = :us, " .
            "can_mint_tokens = :mint, allowed_ips_json = :ips, status = :st, expires_at = :exp " .
            "WHERE id = :id AND owner = :owner"
    );
    $upd->execute([
        ":name" => $name,
        ":desc" => $description,
        ":ps" => $providerScope,
        ":pids" => json_encode($allowedProviderIds, JSON_UNESCAPED_SLASHES),
        ":ccp" => $canCreateProviders ? 1 : 0,
        ":pperm" => $providerPermission,
        ":us" => $userScope,
        ":mint" => $canMintTokens ? 1 : 0,
        ":ips" => json_encode(array_values($allowedIps), JSON_UNESCAPED_SLASHES),
        ":st" => $status,
        ":exp" => $expiresAt,
        ":id" => $id,
        ":owner" => $owner,
    ]);

    if ($status === "revoked") {
        $pdo->prepare(
            "DELETE FROM admin_api_access_tokens WHERE admin_client_id = :id"
        )->execute([":id" => $id]);
    }

    return admin_client_get($storePath, $owner, $id) ?? [];
}

function admin_client_rotate_secret(
    string $storePath,
    string $owner,
    string $id
): array {
    $existing = admin_client_get($storePath, $owner, $id);
    if (!$existing) {
        throw new RuntimeException("Admin API client not found");
    }
    $minted = admin_client_mint_secret();
    $pdo = admin_api_db($storePath);
    $upd = $pdo->prepare(
        "UPDATE admin_api_clients SET token_id = :tid, secret_hash = :sh, secret_preview = :sprev WHERE id = :id AND owner = :owner"
    );
    $upd->execute([
        ":tid" => $minted["token_id"],
        ":sh" => $minted["secret_hash"],
        ":sprev" => $minted["secret_preview"],
        ":id" => $id,
        ":owner" => $owner,
    ]);
    // Revoke any previously minted short-lived OAuth2 access tokens
    $pdo->prepare(
        "DELETE FROM admin_api_access_tokens WHERE admin_client_id = :id"
    )->execute([":id" => $id]);

    $updated = admin_client_get($storePath, $owner, $id) ?? [];
    $updated["api_token"] = $minted["plain_secret"];
    $updated["client_secret"] = $minted["plain_secret"];
    return $updated;
}

function admin_client_delete(
    string $storePath,
    string $owner,
    string $id
): bool {
    $pdo = admin_api_db($storePath);
    $stmt = $pdo->prepare(
        "DELETE FROM admin_api_clients WHERE id = :id AND owner = :owner"
    );
    $stmt->execute([":id" => $id, ":owner" => $owner]);
    return $stmt->rowCount() > 0;
}

/**
 * Automatically grants a newly created provider to a 'selected'-scope API client.
 */
function admin_client_grant_provider(
    string $storePath,
    string $clientIdDb,
    string $providerId
): void {
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT provider_scope, allowed_provider_ids_json FROM admin_api_clients WHERE id = :id LIMIT 1"
    );
    $stmt->execute([":id" => $clientIdDb]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row || ($row["provider_scope"] ?? "") !== "selected") {
        return;
    }
    $ids = json_decode((string) ($row["allowed_provider_ids_json"] ?? "[]"), true) ?: [];
    if (!in_array($providerId, $ids, true)) {
        $ids[] = $providerId;
        $pdo->prepare(
            "UPDATE admin_api_clients SET allowed_provider_ids_json = :pids WHERE id = :id"
        )->execute([
            ":pids" => json_encode(array_values($ids), JSON_UNESCAPED_SLASHES),
            ":id" => $clientIdDb,
        ]);
    }
}

// ---------- Authentication & OAuth 2.0 Client Credentials ----------

function admin_client_touch_usage(string $storePath, string $id): void
{
    $pdo = storage_db($storePath);
    $pdo->prepare(
        "UPDATE admin_api_clients SET last_used_at = :ts, last_used_ip = :ip WHERE id = :id"
    )->execute([
        ":ts" => gmdate("Y-m-d\TH:i:s\Z"),
        ":ip" => client_ip_address(),
        ":id" => $id,
    ]);
}

/**
 * Whether a hydrated client may authenticate: active, not expired, and its owner is still an
 * admin in users.txt. Removing an admin from users.txt therefore also revokes their API
 * clients and OAuth access tokens (S10-04). An unreadable users.txt denies access.
 */
function admin_client_is_usable(array $client): bool
{
    return ($client["status"] ?? "") === "active" &&
        empty($client["is_expired"]) &&
        admin_account_exists((string) ($client["owner"] ?? ""));
}

/**
 * Whether this request may use $client: always when the client has no allowed_ips, otherwise
 * only when the request's client address lies in one of them. The address is resolved the way
 * the site-wide IP allowlist resolves it (ip_allowlist_client(): REMOTE_ADDR, or the
 * X-Forwarded-For client behind trusted_proxies, read strictly); an address that cannot be
 * resolved is refused, and so is every address when no stored entry parses.
 */
function admin_client_source_allowed(array $client): bool
{
    $allowed = (array) ($client["allowed_ips"] ?? []);
    if ($allowed === []) {
        return true;
    }
    $source = ip_allowlist_client();
    $bin = $source["bin"] ?? null;
    if (($source["problem"] ?? null) !== null || !is_string($bin)) {
        return false;
    }
    $items = [];
    foreach ($allowed as $entry) {
        $range = is_string($entry) ? ip_allowlist_parse_range($entry) : null;
        if ($range !== null) {
            $items[] = ["range" => $range];
        }
    }
    return ip_allowlist_match($bin, $items) !== null;
}

/**
 * admin_client_source_allowed() for a client whose credential has just been verified. The
 * caller treats a refusal like any failed authentication (the same 401, counted by the same
 * failure limiter), so the response does not tell whoever holds the credential that it is
 * valid. A refusal is recorded in the owner's admin audit log as admin_client.source_denied
 * (security class). The holder of a leaked credential can repeat the request at will, from
 * many addresses, so at most 5 rows per client and address are written in 10 minutes, and at
 * most 20 per client in an hour. The rate-limit and audit writes run after the response has
 * been sent (admin_client_after_response()), so an invalid credential and a valid one from
 * another address also take the same time to answer. Never throws; an error refuses.
 */
function admin_client_source_check(string $storePath, array $client): bool
{
    try {
        if (admin_client_source_allowed($client)) {
            return true;
        }
        $source = ip_allowlist_client();
    } catch (Throwable $e) {
        error_log("admin API client source check failed (" . get_class($e) . ")");
        return false;
    }
    if ($storePath === "") {
        return false;
    }
    $clientKey = (string) ($client["id"] ?? "");
    // Throttled per client and per the address the decision used (client_ip_bucket() of the
    // strictly resolved address; the connection's address when it has none), and per client.
    $addressBucket = client_ip_bucket(is_string($source["ip"] ?? null) ? $source["ip"] : null);
    $details = [
        "reason" => ($source["problem"] ?? null) !== null
            ? "client address not resolvable (" . (string) $source["problem"] . ")"
            : "client address not in allowed_ips",
        "address" => $source["ip"] ?? null,
    ];
    admin_client_after_response(static function () use ($storePath, $client, $clientKey, $addressBucket, $details): void {
        try {
            if (
                rate_limit_hit($storePath, rate_limit_bucket("admin_client_src_audit", $clientKey, $addressBucket), 5, 600, 600) ||
                rate_limit_hit($storePath, rate_limit_bucket("admin_client_src_audit_all", $clientKey), 20, 3600, 3600)
            ) {
                return;
            }
            admin_audit_append(
                $storePath,
                ["type" => "api_client", "owner" => (string) ($client["owner"] ?? ""), "client" => $client],
                "admin_client.source_denied",
                "failure",
                null,
                (string) ($client["client_id"] ?? ""),
                $details
            );
        } catch (Throwable $e) {
            error_log("admin API client source refusal not audited (" . get_class($e) . ")");
        }
    });
    return false;
}

/**
 * Runs $task once the response has been sent: at shutdown, after fastcgi_finish_request() or
 * litespeed_finish_request() where the SAPI has one (elsewhere, such as php -S, it still runs
 * at shutdown, before the output is flushed), with ignore_user_abort() on so a client that
 * disconnects does not cut it short. Use it for writes whose timing must not show in the
 * response. Errors are the task's to handle.
 */
function admin_client_after_response(callable $task): void
{
    register_shutdown_function(static function () use ($task): void {
        if (function_exists("ignore_user_abort")) {
            ignore_user_abort(true);
        }
        if (function_exists("fastcgi_finish_request")) {
            @fastcgi_finish_request();
        } elseif (function_exists("litespeed_finish_request")) {
            @litespeed_finish_request();
        }
        $task();
    });
}

/**
 * Verifies $secretToVerify against a client row looked up by its public id (token_id or
 * client_id) and returns the hydrated client if it may authenticate. Secrets are
 * machine_secret_hash() digests (X3-09); a legacy bcrypt digest that verifies is replaced
 * best-effort with a compare-and-swap UPDATE when $storePath is given. An unknown id needs
 * no dummy hash: the secret is a random credential, not a password.
 *
 * $legacyDigestBucket (with $storePath): a legacy digest is a bcrypt hash, slow by design, so
 * one attempt is reserved before checking it (rate_limit_hit(), 12 per 300 s, S06-09), in a
 * bucket derived from $legacyDigestBucket (the caller's per-address bucket) and this client
 * row. Concurrent guesses against a client not used since the upgrade then cannot run
 * unbounded bcrypt work, and guesses against one client never lock out another client on the
 * same address (G2a-02). A refused reservation fails the verification, and a secret that
 * verifies clears that bucket. SHA-256 digests never reserve.
 */
function admin_client_verify_active_row(
    ?array $row,
    string $secretToVerify,
    string $storePath = "",
    ?string $legacyDigestBucket = null
): ?array {
    if (!$row) {
        return null;
    }
    $storedHash = (string) ($row["secret_hash"] ?? "");
    $reserveBucket = null;
    if (
        $legacyDigestBucket !== null &&
        $storePath !== "" &&
        !str_starts_with($storedHash, 's256$') &&
        !empty(password_get_info($storedHash)["algo"])
    ) {
        $reserveBucket = rate_limit_bucket("admin_api_hdr_bcrypt", $legacyDigestBucket, (string) ($row["id"] ?? ""));
        if (rate_limit_hit($storePath, $reserveBucket, 12, 300, 300)) {
            return null;
        }
    }
    $upgradedHash = null;
    if (!machine_secret_verify($secretToVerify, $storedHash, $upgradedHash)) {
        return null;
    }
    if ($reserveBucket !== null) {
        try {
            rate_limit_clear($storePath, $reserveBucket);
        } catch (Throwable $e) {
            error_log("admin API client legacy digest limiter not cleared: " . $e->getMessage());
        }
    }
    if ($upgradedHash !== null && $storePath !== "") {
        try {
            storage_db($storePath)->prepare(
                "UPDATE admin_api_clients SET secret_hash = :new WHERE id = :id AND secret_hash = :old"
            )->execute([
                ":new" => $upgradedHash,
                ":id" => (string) $row["id"],
                ":old" => $storedHash,
            ]);
        } catch (Throwable $e) {
            error_log("admin API client secret digest upgrade failed: " . $e->getMessage());
        }
    }
    $hydrated = hydrate_admin_api_client_row($row);
    if (!admin_client_is_usable($hydrated) || !admin_client_source_check($storePath, $hydrated)) {
        return null;
    }
    return $hydrated;
}

/**
 * Authenticates an idp_adm_ token or an idp_at_ access token. $legacyDigestBucket: see
 * admin_client_verify_active_row().
 */
function admin_client_verify_by_token(string $storePath, string $rawToken, ?string $legacyDigestBucket = null): ?array
{
    $pdo = admin_api_db($storePath);

    // Case 1: Direct Admin API Token (idp_adm_<16hex>_<random>)
    if (preg_match('/^idp_adm_([0-9a-f]{16})_[A-Za-z0-9\-_]{20,}$/', $rawToken, $m)) {
        $stmt = $pdo->prepare(
            "SELECT * FROM admin_api_clients WHERE token_id = :tid LIMIT 1"
        );
        $stmt->execute([":tid" => $m[1]]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
        $stmt->closeCursor();
        $verified = admin_client_verify_active_row($row, $rawToken, $storePath, $legacyDigestBucket);
        if ($verified) {
            admin_client_touch_usage($storePath, $verified["id"]);
        }
        return $verified;
    }

    // Case 2: Short-lived OAuth 2.0 client_credentials Access Token (idp_at_<random>)
    if (preg_match('/^idp_at_[A-Za-z0-9\-_]{24,}$/', $rawToken)) {
        $pdo->prepare(
            "DELETE FROM admin_api_access_tokens WHERE expires_at <= :now"
        )->execute([":now" => time()]);
        $stmt = $pdo->prepare(
            "SELECT c.* FROM admin_api_access_tokens t " .
                "JOIN admin_api_clients c ON c.id = t.admin_client_id " .
                "WHERE t.token_hash = :th AND t.expires_at > :now LIMIT 1"
        );
        $stmt->execute([
            ":th" => hash("sha256", $rawToken),
            ":now" => time(),
        ]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();
        if (!$row) {
            return null;
        }
        $hydrated = hydrate_admin_api_client_row($row);
        if (!admin_client_is_usable($hydrated) || !admin_client_source_check($storePath, $hydrated)) {
            return null;
        }
        admin_client_touch_usage($storePath, $hydrated["id"]);
        return $hydrated;
    }

    return null;
}

/** $legacyDigestBucket: see admin_client_verify_active_row(). */
function admin_client_verify_basic_pair(
    string $storePath,
    string $clientId,
    string $clientSecret,
    ?string $legacyDigestBucket = null
): ?array {
    $pdo = admin_api_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM admin_api_clients WHERE client_id = :cid LIMIT 1"
    );
    $stmt->execute([":cid" => trim($clientId)]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    $stmt->closeCursor();
    $verified = admin_client_verify_active_row($row, $clientSecret, $storePath, $legacyDigestBucket);
    if ($verified) {
        admin_client_touch_usage($storePath, $verified["id"]);
    }
    return $verified;
}

/**
 * Exchanges client credentials for a short-lived idp_at_ access token. $verifiedClient
 * receives the authenticated client (for the caller's audit record), or null.
 * $legacyDigestBucket: see admin_client_verify_active_row().
 */
function admin_client_issue_oauth_token(
    string $storePath,
    string $clientId,
    string $clientSecret,
    int $ttlSeconds = 3600,
    ?array &$verifiedClient = null,
    ?string $legacyDigestBucket = null
): ?array {
    $verifiedClient = null;
    $client = admin_client_verify_basic_pair($storePath, $clientId, $clientSecret, $legacyDigestBucket);
    if (!$client) {
        return null;
    }
    $verifiedClient = $client;
    $ttl = max(60, min(86400, $ttlSeconds));
    $accessToken = "idp_at_" . base64url_encode(random_bytes(32));
    $now = time();

    $pdo = storage_db($storePath);
    $pdo->prepare(
        "DELETE FROM admin_api_access_tokens WHERE expires_at <= :now"
    )->execute([":now" => $now]);

    $ins = $pdo->prepare(
        "INSERT INTO admin_api_access_tokens (token_hash, admin_client_id, expires_at, created_at) " .
            "VALUES (:th, :cid, :exp, :cat)"
    );
    $ins->execute([
        ":th" => hash("sha256", $accessToken),
        ":cid" => $client["id"],
        ":exp" => $now + $ttl,
        ":cat" => gmdate("Y-m-d\TH:i:s\Z", $now),
    ]);

    return [
        "access_token" => $accessToken,
        "token_type" => "Bearer",
        "expires_in" => $ttl,
        "provider_scope" => $client["provider_scope"],
        "allowed_provider_ids" => $client["allowed_provider_ids"],
        "provider_permission" => $client["provider_permission"],
        "user_scope" => $client["user_scope"],
    ];
}

/**
 * Whether the request presents an Admin API client credential (G2a-02): an X-API-Key header,
 * an "Authorization: Bearer" or "ApiKey" value that starts with idp_adm_ or idp_at_, or HTTP
 * Basic credentials whose user name is a client_id (iac_...). Any other Authorization value,
 * such as the Basic credentials of an authentication gate in front of the console, is not one.
 */
function admin_api_request_has_client_credential(?string $authHeader = null, ?string $xApiKey = null): bool
{
    $authHeader = trim($authHeader ?? get_auth_header());
    $xApiKey = trim($xApiKey ?? (string) ($_SERVER["HTTP_X_API_KEY"] ?? ""));
    if ($xApiKey !== "") {
        return true;
    }
    if (preg_match('/^(?:Bearer|ApiKey)\s+(\S+)$/i', $authHeader, $m) === 1) {
        return str_starts_with($m[1], "idp_adm_") || str_starts_with($m[1], "idp_at_");
    }
    if (preg_match('/^Basic\s+([A-Za-z0-9+\/=]+)$/i', $authHeader, $m) === 1) {
        $decoded = base64_decode($m[1], true);
        return $decoded !== false && str_starts_with(ltrim($decoded), "iac_");
    }
    return false;
}

/**
 * Counts one failed Admin API authentication in $bucket and tells whether the caller must get
 * 429 instead of 401 (G2a-02, like scim_auth_failure()). Call it only after the presented
 * credential failed verification: a valid credential is never refused by this limiter, so
 * failures from a shared address can only lock out more failures. While the bucket is locked,
 * failures are not counted again, so retries cannot extend the lock. Never throws.
 */
function admin_api_auth_failure_locked(
    string $storePath,
    string $bucket,
    int $maxFailures,
    int $windowSeconds = 300,
    int $lockoutSeconds = 300
): bool {
    try {
        if (rate_limit_is_blocked($storePath, $bucket)) {
            return true;
        }
        // One atomic UPSERT per failure, so concurrent failures are never lost.
        rate_limit_record_failure($storePath, $bucket, $maxFailures, $windowSeconds, $lockoutSeconds);
        return rate_limit_is_blocked($storePath, $bucket);
    } catch (Throwable $e) {
        error_log("admin API authentication: failure not counted: " . $e->getMessage());
        return false;
    }
}

/**
 * Inspects request headers for Admin API Client credentials.
 * Returns null if no Authorization / X-API-Key header was supplied, and also when the request
 * carries a valid console session and its header is not an Admin API client credential
 * (admin_api_request_has_client_credential()), so require_admin_auth() uses the session.
 * Terminates with 401 (429 after repeated failures) if credentials were supplied but are
 * invalid, revoked or expired.
 */
function authenticate_admin_api_client_from_headers(string $storePath): ?array
{
    $authHeader = trim(get_auth_header());
    $xApiKey = trim((string) ($_SERVER["HTTP_X_API_KEY"] ?? ""));

    if ($authHeader === "" && $xApiKey === "") {
        return null;
    }
    $isClientCredential = admin_api_request_has_client_credential($authHeader, $xApiKey);
    if (!$isClientCredential) {
        if (current_user() !== null) {
            return null;
        }
        // Nothing to verify and nothing to count: such a value can never authenticate.
        json_response(401, [
            "error" => "Invalid, expired, or revoked Admin API client credentials",
        ]);
    }

    // The credential is verified first and only failures are counted, per client address
    // (G2a-02): a lock never refuses a valid credential, and a success never resets the
    // counter other callers on the same address share. Unknown ids cost one indexed lookup
    // and machine secrets are SHA-256 digests (X3-09). The one slow check left, a client row
    // still holding a legacy bcrypt digest (not used since the upgrade), reserves an attempt
    // in a separate per-address bucket first (admin_client_verify_active_row(), S06-09).
    $clientIpBucket = client_ip_bucket();
    $legacyDigestBucket = rate_limit_bucket("admin_api_hdr_bcrypt", $clientIpBucket);

    $client = null;
    if ($xApiKey !== "") {
        $client = admin_client_verify_by_token($storePath, $xApiKey, $legacyDigestBucket);
    } elseif (preg_match('/^(?:Bearer|ApiKey)\s+(\S+)$/i', $authHeader, $m)) {
        $client = admin_client_verify_by_token($storePath, trim($m[1]), $legacyDigestBucket);
    } elseif (preg_match('/^Basic\s+([A-Za-z0-9+\/=]+)$/i', $authHeader, $m)) {
        $decoded = base64_decode($m[1], true);
        if ($decoded !== false && str_contains($decoded, ":")) {
            [$cid, $csec] = explode(":", $decoded, 2);
            $client = admin_client_verify_basic_pair($storePath, $cid, $csec, $legacyDigestBucket);
        }
    }

    if ($client) {
        return $client;
    }
    // The 12th failure within 300 s locks further failures from this address out for 300 s.
    if (admin_api_auth_failure_locked($storePath, rate_limit_bucket("admin_api_hdr", $clientIpBucket), 12)) {
        if (!headers_sent()) {
            header("Retry-After: 300");
        }
        json_response(429, [
            "error" => "Too many failed API authentication attempts; please wait",
        ]);
    }
    json_response(401, [
        "error" => "Invalid, expired, or revoked Admin API client credentials",
    ]);
}

// ---------- Unified Admin Request Authorization ----------

/**
 * Authenticates either an external Admin API Client (header-based)
 * or an interactive Browser Admin Session (cookie + CSRF). An Authorization header that is not
 * an Admin API client credential does not override a valid session (G2a-02).
 *
 * @return array{type: string, owner: string, client: ?array}
 */
function require_admin_auth(string $storePath, string $csrfExpectedOrigin): array
{
    $apiClient = authenticate_admin_api_client_from_headers($storePath);
    if ($apiClient !== null) {
        return [
            "type" => "api_client",
            "owner" => $apiClient["owner"],
            "client" => $apiClient,
        ];
    }

    $user = require_login($csrfExpectedOrigin);
    return [
        "type" => "session",
        "owner" => $user,
        "client" => null,
    ];
}

function auth_require_session_only(array $auth): string
{
    if (($auth["type"] ?? "") !== "session") {
        json_response(403, [
            "error" => "This endpoint requires an interactive Administrator Console session",
        ]);
    }
    return (string) $auth["owner"];
}

function auth_can_access_provider(
    array $auth,
    string $providerId,
    bool $requireWrite = false
): bool {
    if (($auth["type"] ?? "") === "session") {
        return true;
    }
    $c = $auth["client"] ?? null;
    if (!is_array($c)) {
        return false;
    }
    if ($requireWrite && ($c["provider_permission"] ?? "write") !== "write") {
        return false;
    }
    if (($c["provider_scope"] ?? "selected") === "all") {
        return true;
    }
    return in_array($providerId, $c["allowed_provider_ids"] ?? [], true);
}

/**
 * Resolves a provider owned by $auth["owner"] by either UUID id or idpId slug,
 * and enforces provider-scoped read/write authorization for API clients.
 * An exact id or idp_id match wins; otherwise a case-insensitive or rawurldecoded idp_id
 * match is accepted only when exactly one of the owner's providers matches (S10-03).
 *
 * @return array{index: int, provider: array}
 */
function auth_resolve_provider_or_fail(
    array $auth,
    array $providers,
    string $idOrSlug,
    bool $requireWrite = false
): array {
    $owner = (string) $auth["owner"];
    $targetDecoded = rawurldecode($idOrSlug);
    $matchedIdx = null;
    $matchedProv = null;
    $looseMatches = [];

    foreach ($providers as $idx => $p) {
        if ((string) ($p["owner"] ?? "") !== $owner) {
            continue;
        }
        $pid = (string) ($p["id"] ?? "");
        $slug = (string) ($p["idp_id"] ?? "");
        if ($pid === $idOrSlug || $slug === $idOrSlug) {
            $matchedIdx = $idx;
            $matchedProv = $p;
            break;
        }
        if (
            strcasecmp($slug, $idOrSlug) === 0 ||
            strcasecmp(rawurldecode($slug), $targetDecoded) === 0
        ) {
            $looseMatches[$pid] = [$idx, $p];
        }
    }
    if ($matchedProv === null && count($looseMatches) === 1) {
        [$matchedIdx, $matchedProv] = reset($looseMatches);
    }

    if ($matchedProv === null || $matchedIdx === null) {
        json_response(404, ["error" => "Provider not found"]);
    }

    if (!auth_can_access_provider($auth, $matchedProv["id"], false)) {
        json_response(403, [
            "error" => "Forbidden: API client is not authorized for provider '" .
                $matchedProv["friendly"] .
                "'",
        ]);
    }

    if ($requireWrite && !auth_can_access_provider($auth, $matchedProv["id"], true)) {
        json_response(403, [
            "error" => "Forbidden: API client has read-only permission on providers",
        ]);
    }

    return ["index" => $matchedIdx, "provider" => $matchedProv];
}

function auth_require_create_provider(array $auth): void
{
    if (($auth["type"] ?? "") === "session") {
        return;
    }
    $c = $auth["client"] ?? [];
    if (($c["provider_permission"] ?? "write") !== "write") {
        json_response(403, [
            "error" => "Forbidden: API client has read-only permission",
        ]);
    }
    if (
        ($c["provider_scope"] ?? "selected") !== "all" &&
        empty($c["can_create_providers"])
    ) {
        json_response(403, [
            "error" => "Forbidden: API client is not permitted to create new providers",
        ]);
    }
}

/**
 * user_scope gate for everything that reads or changes the owner's shared directory: the
 * /api/users and /api/groups routes, and SCIM tokens and connectors, which give full access
 * to that directory (S10-01). Console sessions are unrestricted.
 */
function auth_require_user_directory(array $auth, bool $requireWrite = false): void
{
    if (($auth["type"] ?? "") === "session") {
        return;
    }
    $uScope = (string) ($auth["client"]["user_scope"] ?? "none");
    if ($requireWrite && $uScope !== "write") {
        json_response(403, [
            "error" => "Forbidden: API client requires user_scope='write' for this directory operation",
        ]);
    }
    if (!$requireWrite && !in_array($uScope, ["read", "write"], true)) {
        json_response(403, [
            "error" => "Forbidden: API client does not have directory user access",
        ]);
    }
}

/**
 * Token minting gate (G1a-02): an API client may mint JWTs at POST /api/token, import a
 * private signing key (whoever holds an imported key can mint tokens offline), or manage an
 * OIDC client that can use the client_credentials grant (its tokens carry the client_id it
 * chooses as their subject) only with the can_mint_tokens capability, which an administrator
 * grants per client; clients created before the capability existed do not have it. The
 * operator flag legacy_api_client_token_minting restores the old rule, under which provider
 * write permission alone allowed all of this. Console sessions are unrestricted. $purpose
 * completes the 403 message ("needed to ...").
 */
function auth_require_token_minting(array $auth, string $purpose = "mint tokens or import signing keys"): void
{
    if (($auth["type"] ?? "") !== "api_client") {
        return;
    }
    if (config_flag("legacy_api_client_token_minting", "OIDC_LEGACY_API_CLIENT_TOKEN_MINTING")) {
        return;
    }
    if (empty($auth["client"]["can_mint_tokens"])) {
        json_response(403, [
            "error" => "Forbidden: API client lacks the can_mint_tokens capability (needed to $purpose)",
        ]);
    }
}

/**
 * Who acted, for audit records: "admin:<user>" for a console session or legacy key owner,
 * "admin_client:<name>" for an Admin API client.
 */
function auth_actor_label(array $auth): string
{
    if (($auth["type"] ?? "") === "api_client") {
        return "admin_client:" . (string) ($auth["client"]["name"] ?? "");
    }
    return "admin:" . (string) ($auth["owner"] ?? "");
}

// ---------- Admin Audit Log (G1a-01) ----------

/**
 * A short keyed digest (16 hex characters) of an identifier that must not be stored as typed:
 * a failed login name that matches no administrator, or a malformed client_id, may be a
 * password or secret entered into the wrong field (G1a-01). Equal inputs give equal digests,
 * so repeated attempts can be correlated, but without the key a digest cannot be tested
 * against guesses. The key is an HMAC subkey of the vault master key. Empty when that key is
 * unavailable (the vault logs why).
 */
function admin_audit_name_digest(string $storePath, string $name): string
{
    static $keys = [];
    try {
        $keys[$storePath] ??= hash_hmac(
            "sha256",
            "admin audit name digest v1",
            vault_master_key($storePath),
            true
        );
    } catch (Throwable $e) {
        return "";
    }
    return substr(hash_hmac("sha256", $name, $keys[$storePath]), 0, 16);
}

/**
 * Successful actions that callers repeat routinely, recorded in the 'routine' audit class so
 * that their volume can never push security events out of the log (G1a-01): every
 * client_credentials exchange at /api/oauth2/token writes one.
 */
const ADMIN_AUDIT_ROUTINE_ACTIONS = [
    "admin_client.token_issued" => true,
];

/**
 * Retention of admin_audit_logs (G1a-01), applied by admin_audit_prune(). 'security' rows
 * (every administrative change, login, mint and alert) are kept for 365 days. Beyond the
 * newest ADMIN_AUDIT_SECURITY_SOFT_CAP rows of an owner, rows older than
 * ADMIN_AUDIT_MIN_RETENTION_DAYS are removed; younger rows are never removed by any cap, so
 * no actor can wipe the recent record of its own actions by generating events. 'routine' rows
 * keep the newest ADMIN_AUDIT_ROUTINE_CAP per owner and 'untrusted' rows (unauthenticated
 * failures) the newest ADMIN_AUDIT_UNTRUSTED_OWNER_CAP per administrator and
 * ADMIN_AUDIT_UNTRUSTED_ANON_CAP without one; both expire after the minimum retention and
 * never evict rows of another class or owner.
 */
const ADMIN_AUDIT_MIN_RETENTION_DAYS = 90;
const ADMIN_AUDIT_SECURITY_SOFT_CAP = 20000;
const ADMIN_AUDIT_ROUTINE_CAP = 2000;
const ADMIN_AUDIT_UNTRUSTED_OWNER_CAP = 500;
const ADMIN_AUDIT_UNTRUSTED_ANON_CAP = 2000;

/**
 * The value stored in and matched against admin_audit_logs.owner for administrator $owner:
 * the name itself, or "sha256:" plus its digest when it is longer than 256 bytes. Writing,
 * pruning and listing all use it, so an administrator with a long name still finds their own
 * rows, and two long names never share a value.
 */
function admin_audit_owner_key(string $owner): string
{
    return strlen($owner) <= 256 ? $owner : "sha256:" . hash("sha256", $owner);
}

/**
 * Appends one row to the admin audit log: who acted (session admin, API client or legacy
 * key owner), from where (client IP, user agent), the action, target ids, outcome and
 * details. Never pass secrets (passwords, client secrets, bearer tokens, keys, enrollment
 * tokens): log ids only. Unauthenticated events (failed logins) use $untrusted = true and go
 * into the 'untrusted' class; successful ADMIN_AUDIT_ROUTINE_ACTIONS into 'routine'; all other
 * rows into 'security'. Retention per class: see ADMIN_AUDIT_MIN_RETENTION_DAYS. Never throws.
 */
function admin_audit_append(
    string $storePath,
    array $auth,
    string $action,
    string $outcome = "success",
    ?string $providerId = null,
    string $target = "",
    array $details = [],
    bool $untrusted = false
): void {
    try {
        $pdo = admin_api_db($storePath);
        $client = is_array($auth["client"] ?? null) ? $auth["client"] : null;
        $owner = admin_audit_owner_key((string) ($auth["owner"] ?? ""));
        $class = $untrusted
            ? "untrusted"
            : (isset(ADMIN_AUDIT_ROUTINE_ACTIONS[$action]) && $outcome === "success" ? "routine" : "security");
        $jsonFlags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;
        $pdo->prepare(
            "INSERT INTO admin_audit_logs (" .
                "created_at, owner, actor_type, actor_id, actor_name, source_ip, user_agent, " .
                "action, outcome, provider_id, target, details_json, audit_class" .
            ") VALUES (:cat, :owner, :atype, :aid, :aname, :ip, :ua, :action, :outcome, :pid, :target, :details, :cls)"
        )->execute([
            ":cat" => gmdate("Y-m-d\TH:i:s\Z"),
            ":owner" => $owner,
            ":atype" => sanitize_label((string) ($auth["type"] ?? "anonymous"), 32),
            // A system event (an alert) has no actor; others name the client or the user.
            ":aid" => $client !== null
                ? sanitize_label((string) ($client["client_id"] ?? ""), 128)
                : (($auth["type"] ?? "") === "system" ? "" : sanitize_label((string) ($auth["owner"] ?? ""), 128)),
            ":aname" => $client !== null ? sanitize_label((string) ($client["name"] ?? ""), 128) : "",
            ":ip" => sanitize_label(client_ip_address(), 64),
            ":ua" => sanitize_label((string) ($_SERVER["HTTP_USER_AGENT"] ?? ""), 256),
            ":action" => sanitize_label($action, 64),
            ":outcome" => sanitize_label($outcome, 32),
            ":pid" => $providerId !== null && $providerId !== "" ? sanitize_label($providerId, 64) : null,
            ":target" => sanitize_label($target, 256),
            ":details" => json_encode(admin_audit_clip_values($details), $jsonFlags) ?: "{}",
            ":cls" => $class,
        ]);
        admin_audit_prune($pdo, $class, $owner);
    } catch (Throwable $e) {
        // Auditing must never break the request that triggered it.
        error_log("admin_audit_append: audit row not written (" . get_class($e) . ")");
    }
}

/**
 * Bounds audit details: strings through sanitize_label(..., 256), keys to 64 characters, at
 * most 50 entries per level and 4 levels.
 */
function admin_audit_clip_values(array $values, int $depth = 0): array
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
            $out[$key] = $depth < 3 ? admin_audit_clip_values($value, $depth + 1) : "[nested]";
        } elseif (is_scalar($value) || $value === null) {
            $out[$key] = $value;
        } else {
            $out[$key] = get_debug_type($value);
        }
    }
    return $out;
}

/**
 * Retention (see ADMIN_AUDIT_MIN_RETENTION_DAYS). On every 'untrusted' or 'routine' insert, the
 * rows of that class and owner beyond its cap are removed. On about 1 in 20 inserts, rows past
 * their age limit are removed, and $owner's 'security' rows beyond the soft cap that are older
 * than the minimum retention. At most 1000 rows per statement, oldest first. $owner is an
 * admin_audit_owner_key() value.
 */
function admin_audit_prune(PDO $pdo, string $class, string $owner): void
{
    // Deletes the rows of one class and owner older than the $keep newest ones (and, with
    // $olderThan, only those created before it).
    $trim = static function (string $class, string $owner, int $keep, ?string $olderThan = null) use ($pdo): void {
        storage_execute(
            $pdo->prepare(
                "DELETE FROM admin_audit_logs WHERE id IN (" .
                    "SELECT id FROM admin_audit_logs WHERE audit_class = :cls AND owner = :owner" .
                    ($olderThan !== null ? " AND created_at < :older" : "") . " AND id < (" .
                        "SELECT id FROM admin_audit_logs WHERE audit_class = :cls2 AND owner = :owner2 " .
                        "ORDER BY id DESC LIMIT 1 OFFSET :keep" .
                    ") ORDER BY id ASC LIMIT :batch" .
                ")"
            ),
            [
                ":cls" => $class,
                ":owner" => $owner,
                ":cls2" => $class,
                ":owner2" => $owner,
                ":keep" => max(0, $keep - 1),
                ":batch" => 1000,
            ] + ($olderThan !== null ? [":older" => $olderThan] : [])
        );
    };
    if ($class === "untrusted") {
        $trim(
            "untrusted",
            $owner,
            $owner === "" ? ADMIN_AUDIT_UNTRUSTED_ANON_CAP : ADMIN_AUDIT_UNTRUSTED_OWNER_CAP
        );
    } elseif ($class === "routine") {
        $trim("routine", $owner, ADMIN_AUDIT_ROUTINE_CAP);
    }
    if (mt_rand(1, 20) !== 1) {
        return;
    }
    $minAgeCutoff = gmdate("Y-m-d\TH:i:s\Z", time() - ADMIN_AUDIT_MIN_RETENTION_DAYS * 86400);
    foreach ([
        ["security", gmdate("Y-m-d\TH:i:s\Z", time() - 365 * 86400)],
        ["routine", $minAgeCutoff],
        ["untrusted", $minAgeCutoff],
    ] as [$expiringClass, $cutoff]) {
        storage_execute(
            $pdo->prepare(
                "DELETE FROM admin_audit_logs WHERE id IN (" .
                    "SELECT id FROM admin_audit_logs WHERE audit_class = :cls AND created_at < :cutoff " .
                    "ORDER BY id ASC LIMIT :batch" .
                ")"
            ),
            [":cls" => $expiringClass, ":cutoff" => $cutoff, ":batch" => 1000]
        );
    }
    if ($class === "security") {
        $trim("security", $owner, ADMIN_AUDIT_SECURITY_SOFT_CAP, $minAgeCutoff);
    }
}

/**
 * The newest admin audit rows of $owner (actions by the owner's session and API clients,
 * failed logins with the owner's username, and sign-in alerts), newest first.
 */
function admin_audit_list(string $storePath, string $owner, int $limit = 100): array
{
    $pdo = admin_api_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT id, created_at, actor_type, actor_id, actor_name, source_ip, user_agent, action, outcome, " .
            "provider_id, target, details_json, audit_class FROM admin_audit_logs WHERE owner = :owner " .
            "ORDER BY id DESC LIMIT :lim"
    );
    storage_execute($stmt, [
        ":owner" => admin_audit_owner_key($owner),
        ":lim" => max(1, min(500, $limit)),
    ]);
    $rows = [];
    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $details = json_decode((string) ($r["details_json"] ?? "{}"), true);
        $rows[] = [
            "id" => (int) $r["id"],
            "created_at" => (string) $r["created_at"],
            "actor_type" => (string) $r["actor_type"],
            "actor_id" => (string) $r["actor_id"],
            "actor_name" => (string) $r["actor_name"],
            "source_ip" => (string) $r["source_ip"],
            "user_agent" => (string) $r["user_agent"],
            "action" => (string) $r["action"],
            "outcome" => (string) $r["outcome"],
            "provider_id" => $r["provider_id"] !== null ? (string) $r["provider_id"] : null,
            "target" => (string) $r["target"],
            "details" => is_array($details) ? $details : [],
            "audit_class" => (string) ($r["audit_class"] ?? "security"),
        ];
    }
    return $rows;
}

// ---------- Admin Console Sign-in (G2a-01, G2a-07) ----------
// Passwords, known-device cookies, sign-in budgets and authenticator apps (TOTP), used by
// POST /api/login and the /api/admin-mfa routes.

/** Shortest plaintext users.txt password accepted while allow_plaintext_admin_passwords is on. */
const ADMIN_PLAINTEXT_PASSWORD_MIN_LENGTH = 12;

/** How an operator writes a password hash for users.txt (quoted in error_log lines). */
const ADMIN_PASSWORD_HASH_HINT =
    'php -r \'echo password_hash(rtrim(fgets(STDIN), "\r\n"), PASSWORD_DEFAULT), PHP_EOL;\' ' .
    "(type the password and press Enter; put \"<username>:<hash>\" in users.txt)";

/**
 * Sign-in budgets of POST /api/login (G2a-01), each counted over ADMIN_LOGIN_WINDOW_SECONDS
 * and locking for as long. Browsers without a known-device cookie are limited per account
 * (every address together), per address and typed name, per address across all names, and
 * globally. A browser with a known-device cookie for the account is limited only by the
 * failures made with that cookie. Codes from authenticator apps have their own budget per
 * account, which only someone who knows the password can use up.
 */
const ADMIN_LOGIN_WINDOW_SECONDS = 900;
const ADMIN_LOGIN_ACCOUNT_MAX_FAILURES = 10;
const ADMIN_LOGIN_IP_MAX_FAILURES = 20;
const ADMIN_LOGIN_GLOBAL_MAX_FAILURES = 200;
const ADMIN_LOGIN_DEVICE_MAX_FAILURES = 8;
const ADMIN_LOGIN_OTP_MAX_FAILURES = 5;

/** Lifetime of the known-device cookie POST /api/login sets after a successful sign-in. */
const ADMIN_DEVICE_COOKIE_TTL_SECONDS = 2592000;

/** Time step of authenticator app codes (RFC 6238 TOTP with HMAC-SHA-1 and 6 digits). */
const ADMIN_TOTP_PERIOD_SECONDS = 30;

/** How long a newly set up authenticator app can be confirmed with its first code. */
const ADMIN_TOTP_PENDING_SECONDS = 900;

/**
 * The hash family of a "$"-prefixed users.txt value that password_verify() can check on this
 * PHP: "bcrypt" ($2y$, $2a$, $2b$, $2x$), "argon2" ($argon2i$, $argon2id$, when PHP has
 * argon2), "sha-crypt" ($5$, $6$) or "md5-crypt" ($1$); password_verify() checks the crypt()
 * formats through crypt(). Null for anything else, such as Apache's $apr1$, which crypt()
 * cannot verify.
 */
function admin_password_hash_format(string $stored): ?string
{
    if (preg_match('#^\$2[abxy]\$\d\d\$[./A-Za-z0-9]{53}$#D', $stored) === 1) {
        return "bcrypt";
    }
    if (preg_match('#^\$argon2id?\$#', $stored) === 1) {
        return defined("PASSWORD_ARGON2I") ? "argon2" : null;
    }
    if (
        preg_match('#^\$5\$(?:rounds=\d{1,9}\$)?[^$]{0,16}\$[./A-Za-z0-9]{43}$#D', $stored) === 1 ||
        preg_match('#^\$6\$(?:rounds=\d{1,9}\$)?[^$]{0,16}\$[./A-Za-z0-9]{86}$#D', $stored) === 1
    ) {
        return "sha-crypt";
    }
    if (preg_match('#^\$1\$[^$]{0,8}\$[./A-Za-z0-9]{22}$#D', $stored) === 1) {
        return "md5-crypt";
    }
    return null;
}

/**
 * Verifies an administrator's console password against $users (parsed users.txt) (G2a-07).
 * A value that starts with "$" is always a password hash: password_verify() checks it when
 * PHP can (admin_password_hash_format()), otherwise the sign-in is refused with an error_log
 * line. It is never compared as plaintext, so the text of a hash PHP does not know no longer
 * works as the password. Any other value is a plaintext password, refused unless the operator
 * sets allow_plaintext_admin_passwords, and then accepted only with at least
 * ADMIN_PLAINTEXT_PASSWORD_MIN_LENGTH characters and a warning in the error log. Unknown users
 * and refused entries run a dummy_password_hash() check, so timing does not tell them apart.
 */
function admin_password_verify(array $users, string $username, string $password): bool
{
    $stored = $username !== "" && isset($users[$username]) ? (string) $users[$username] : null;
    if ($stored === null || $password === "" || strlen($password) > 4096) {
        password_verify($password, dummy_password_hash());
        return false;
    }
    $who = "'" . sanitize_label($username, 64) . "'";
    if (str_starts_with($stored, '$')) {
        if (admin_password_hash_format($stored) !== null) {
            return password_verify($password, $stored);
        }
        error_log(
            "Admin sign-in refused for $who: its users.txt entry is a password hash this PHP cannot verify " .
                '(for example Apache $apr1$). Replace it with a password_hash() digest: ' . ADMIN_PASSWORD_HASH_HINT
        );
        password_verify($password, dummy_password_hash());
        return false;
    }
    password_verify($password, dummy_password_hash());
    if (!config_flag("allow_plaintext_admin_passwords", "OIDC_ALLOW_PLAINTEXT_ADMIN_PASSWORDS")) {
        error_log(
            "Admin sign-in refused for $who: its users.txt entry is a plaintext password, not a password hash " .
                "(OIDC_ALLOW_PLAINTEXT_ADMIN_PASSWORDS=1 accepts it while migrating). Generate a hash with " .
                ADMIN_PASSWORD_HASH_HINT
        );
        return false;
    }
    if (strlen($stored) < ADMIN_PLAINTEXT_PASSWORD_MIN_LENGTH) {
        error_log(
            "Admin sign-in refused for $who: a plaintext users.txt password needs at least " .
                ADMIN_PLAINTEXT_PASSWORD_MIN_LENGTH . " characters. Better, replace it with a hash: " .
                ADMIN_PASSWORD_HASH_HINT
        );
        return false;
    }
    $ok = hash_equals($stored, $password);
    if ($ok) {
        error_log(
            "WARNING: administrator $who signed in with a plaintext users.txt password. Replace it with a hash: " .
                ADMIN_PASSWORD_HASH_HINT
        );
    }
    return $ok;
}

/**
 * The users.txt line "<username>:<password_hash()>" for an administrator, for a command-line
 * helper that writes admin password hashes (G2a-07). Throws InvalidArgumentException for a
 * name users.txt cannot hold (empty, surrounded by whitespace, containing ':' or control
 * characters, or starting with '#') and for a password shorter than
 * ADMIN_PLAINTEXT_PASSWORD_MIN_LENGTH or longer than 4096 bytes.
 */
function admin_password_hash_line(string $username, string $password): string
{
    if (
        $username === "" ||
        $username !== trim($username) ||
        str_contains($username, ":") ||
        str_starts_with($username, "#") ||
        preg_match('/[\x00-\x1f\x7f]/', $username) === 1
    ) {
        throw new InvalidArgumentException(
            "The username must not be empty, start with '#', contain ':' or control characters, or start or end with whitespace"
        );
    }
    if (strlen($password) < ADMIN_PLAINTEXT_PASSWORD_MIN_LENGTH || strlen($password) > 4096) {
        throw new InvalidArgumentException(
            "The password must have at least " . ADMIN_PLAINTEXT_PASSWORD_MIN_LENGTH . " characters"
        );
    }
    return $username . ":" . password_hash($password, PASSWORD_DEFAULT);
}

/** Name of the known-device cookie: __Host- prefixed whenever the session cookie is Secure. */
function admin_device_cookie_name(): string
{
    return admin_device_cookie_secure() ? "__Host-IDPADMDEV" : "IDPADMDEV";
}

/** Whether the known-device cookie is Secure: exactly when bootstrap made the session cookie so. */
function admin_device_cookie_secure(): bool
{
    return PHP_SAPI !== "cli" && !empty(session_get_cookie_params()["secure"]);
}

/** HMAC key of known-device cookies, a subkey of the vault master key; null when unavailable. */
function admin_device_cookie_key(string $storePath): ?string
{
    static $keys = [];
    if (!isset($keys[$storePath])) {
        try {
            $keys[$storePath] = hash_hmac("sha256", "admin known-device cookie v1", vault_master_key($storePath), true);
        } catch (Throwable $e) {
            return null;
        }
    }
    return $keys[$storePath];
}

/**
 * Binds a known-device cookie to $username and its current users.txt entry, so a changed
 * entry (a new password) retires the administrator's device cookies.
 */
function admin_device_user_binding(string $key, string $username, string $storedEntry): string
{
    return substr(hash_hmac("sha256", "user\0" . $username . "\0" . $storedEntry, $key), 0, 32);
}

/**
 * The device id in the request's known-device cookie when that cookie is valid for
 * $username: signed by this IdP, unexpired, and set by a successful sign-in of $username with
 * its current users.txt entry. Null otherwise. The cookie proves nothing about the password;
 * it only lets POST /api/login count this browser's failures on their own, so failures from
 * elsewhere never lock the administrator out of browsers they signed in with before (OWASP
 * device cookies, G2a-01).
 */
function admin_device_id_from_cookie(string $storePath, array $users, string $username): ?string
{
    $raw = $_COOKIE[admin_device_cookie_name()] ?? null;
    if (!is_string($raw) || strlen($raw) > 512 || $username === "" || !isset($users[$username])) {
        return null;
    }
    $parts = explode(".", $raw);
    $key = admin_device_cookie_key($storePath);
    if (count($parts) !== 3 || $parts[0] !== "v1" || $key === null) {
        return null;
    }
    $mac = base64url_encode(hash_hmac("sha256", $parts[0] . "." . $parts[1], $key, true));
    if (!hash_equals($mac, $parts[2])) {
        return null;
    }
    $payload = json_decode(base64url_decode($parts[1]), true);
    if (
        !is_array($payload) ||
        !is_string($payload["u"] ?? null) ||
        !is_string($payload["d"] ?? null) ||
        !is_int($payload["e"] ?? null) ||
        $payload["e"] <= time() ||
        preg_match('/^[A-Za-z0-9_-]{22}$/D', $payload["d"]) !== 1 ||
        !hash_equals(admin_device_user_binding($key, $username, (string) $users[$username]), $payload["u"])
    ) {
        return null;
    }
    return $payload["d"];
}

/**
 * Sets a new known-device cookie for $username after a successful sign-in: a fresh device id,
 * valid for ADMIN_DEVICE_COOKIE_TTL_SECONDS, HttpOnly and SameSite=Strict, __Host- prefixed and
 * Secure over https. Best effort: nothing is set when the vault key is unavailable.
 */
function admin_device_cookie_issue(string $storePath, array $users, string $username): void
{
    $key = admin_device_cookie_key($storePath);
    if ($key === null || headers_sent() || !isset($users[$username])) {
        return;
    }
    $expires = time() + ADMIN_DEVICE_COOKIE_TTL_SECONDS;
    $body = "v1." . base64url_encode((string) json_encode([
        "u" => admin_device_user_binding($key, $username, (string) $users[$username]),
        "d" => base64url_encode(random_bytes(16)),
        "e" => $expires,
    ]));
    setcookie(admin_device_cookie_name(), $body . "." . base64url_encode(hash_hmac("sha256", $body, $key, true)), [
        "expires" => $expires,
        "path" => "/",
        "domain" => "",
        "secure" => admin_device_cookie_secure(),
        "httponly" => true,
        "samesite" => "Strict",
    ]);
}

/**
 * Counts one failed console sign-in from a browser without a known-device cookie (G2a-01) in
 * $ipBucket (ADMIN_LOGIN_IP_MAX_FAILURES) and in $globalBucket
 * (ADMIN_LOGIN_GLOBAL_MAX_FAILURES). When the global ceiling is reached, such sign-ins are
 * refused from everywhere for ADMIN_LOGIN_WINDOW_SECONDS and an alert is raised, at most once
 * per window: an error_log line and a 'security' audit row for every administrator in $users.
 * Known-device sign-ins are never refused by these budgets. Never throws.
 */
function admin_login_count_untrusted_failure(
    string $storePath,
    string $ipBucket,
    string $globalBucket,
    array $users
): void {
    $window = ADMIN_LOGIN_WINDOW_SECONDS;
    try {
        rate_limit_record_failure($storePath, $ipBucket, ADMIN_LOGIN_IP_MAX_FAILURES, $window, $window);
        rate_limit_record_failure($storePath, $globalBucket, ADMIN_LOGIN_GLOBAL_MAX_FAILURES, $window, $window);
        if (
            !rate_limit_is_blocked($storePath, $globalBucket) ||
            rate_limit_hit($storePath, rate_limit_bucket("admin_login_alert", "global"), 1, $window, $window)
        ) {
            return;
        }
    } catch (Throwable $e) {
        error_log("admin sign-in: failure not counted: " . $e->getMessage());
        return;
    }
    error_log(
        "SECURITY ALERT: " . ADMIN_LOGIN_GLOBAL_MAX_FAILURES . " failed admin console sign-ins within " .
            intdiv($window, 60) . " minutes. Sign-ins from browsers without a known-device cookie are refused " .
            "for the next " . intdiv($window, 60) . " minutes; browsers that signed in before can still sign in."
    );
    foreach (array_keys($users) as $admin) {
        admin_audit_append(
            $storePath,
            ["type" => "system", "owner" => (string) $admin, "client" => null],
            "admin.login_alert",
            "alert",
            null,
            "",
            [
                "failed_sign_ins" => ADMIN_LOGIN_GLOBAL_MAX_FAILURES,
                "window_seconds" => $window,
                "new_device_sign_ins_paused_seconds" => $window,
            ]
        );
    }
}

/** Whether every administrator must use an authenticator app to sign in (admin_require_mfa). */
function admin_mfa_required(): bool
{
    return config_flag("admin_require_mfa", "OIDC_ADMIN_REQUIRE_MFA");
}

/** RFC 4648 base32 without padding, the form authenticator apps take secrets in. */
function admin_totp_base32(string $bin): string
{
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    $bits = "";
    for ($i = 0, $n = strlen($bin); $i < $n; $i++) {
        $bits .= str_pad(decbin(ord($bin[$i])), 8, "0", STR_PAD_LEFT);
    }
    $out = "";
    foreach ($bits === "" ? [] : str_split($bits, 5) as $chunk) {
        $out .= $alphabet[(int) bindec(str_pad($chunk, 5, "0", STR_PAD_RIGHT))];
    }
    return $out;
}

/** The 6-digit code of $secret for time step $step (RFC 6238 TOTP with HMAC-SHA-1). */
function admin_totp_code(string $secret, int $step): string
{
    $hash = hash_hmac("sha1", pack("J", $step), $secret, true);
    $offset = ord($hash[19]) & 0x0f;
    $value = ((ord($hash[$offset]) & 0x7f) << 24) |
        (ord($hash[$offset + 1]) << 16) |
        (ord($hash[$offset + 2]) << 8) |
        ord($hash[$offset + 3]);
    return str_pad((string) ($value % 1000000), 6, "0", STR_PAD_LEFT);
}

/**
 * The time step whose code is $code: the current step or the one before or after it (clock
 * drift), and only a step after $afterStep, so a code accepted once is never accepted again.
 * Null when none matches.
 */
function admin_totp_matching_step(string $secret, string $code, int $afterStep): ?int
{
    $code = preg_replace('/\s+/', "", $code) ?? "";
    if (preg_match('/^\d{6}$/D', $code) !== 1) {
        return null;
    }
    $now = intdiv(time(), ADMIN_TOTP_PERIOD_SECONDS);
    $match = null;
    foreach ([$now - 1, $now, $now + 1] as $step) {
        // Every candidate is compared, so the timing does not tell which one matched.
        if (hash_equals(admin_totp_code($secret, $step), $code) && $step > $afterStep) {
            $match = $step;
        }
    }
    return $match;
}

/**
 * The authenticator app record of $username: status ('pending' or 'active'), created_at and
 * confirmed_at (Unix times), last_step, secret_enc and the decrypted secret. The secret is null
 * when the vault cannot decrypt it; an active record then rejects every code, it never stops
 * being required. Null when $username has none.
 */
function admin_totp_record(string $storePath, string $username): ?array
{
    try {
        $stmt = admin_api_db($storePath)->prepare(
            "SELECT status, secret_enc, created_at, confirmed_at, last_step FROM admin_mfa_totp WHERE username = :u LIMIT 1"
        );
        $stmt->execute([":u" => $username]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();
    } catch (PDOException $e) {
        // Before the table exists nobody can have set up an app; any other error is raised.
        if (str_contains(strtolower($e->getMessage()), "no such table")) {
            return null;
        }
        throw $e;
    }
    if (!is_array($row)) {
        return null;
    }
    $plain = vault_decrypt_secret($storePath, (string) $row["secret_enc"]);
    $secret = is_string($plain) ? base64_decode($plain, true) : false;
    return [
        "status" => (string) $row["status"],
        "secret_enc" => (string) $row["secret_enc"],
        "secret" => is_string($secret) && strlen($secret) >= 16 ? $secret : null,
        "created_at" => (int) $row["created_at"],
        "confirmed_at" => $row["confirmed_at"] !== null ? (int) $row["confirmed_at"] : null,
        "last_step" => (int) $row["last_step"],
    ];
}

/** Whether $username has a confirmed authenticator app, so every sign-in needs its code. */
function admin_totp_enrolled(string $storePath, string $username): bool
{
    $record = admin_totp_record($storePath, $username);
    return $record !== null && $record["status"] === "active";
}

/**
 * Starts setting up an authenticator app for $username: a new random 160-bit secret is stored
 * as 'pending', replacing an earlier pending one, and returned in base32 with its otpauth://
 * URI ($issuer names this IdP in the app). Throws RuntimeException when $username already has
 * an active app.
 *
 * @return array{secret: string, otpauth_uri: string, expires_in: int}
 */
function admin_totp_begin(string $storePath, string $username, string $issuer): array
{
    $secret = random_bytes(20);
    $envelope = vault_encrypt_secret($storePath, base64_encode($secret));
    $pdo = admin_api_db($storePath);
    storage_write_transaction($pdo, function (PDO $pdo) use ($username, $envelope): void {
        $sel = $pdo->prepare("SELECT status FROM admin_mfa_totp WHERE username = :u LIMIT 1");
        $sel->execute([":u" => $username]);
        $status = $sel->fetchColumn();
        $sel->closeCursor();
        if ($status === "active") {
            throw new RuntimeException("An authenticator app is already set up; remove it first");
        }
        storage_execute(
            $pdo->prepare(
                "INSERT OR REPLACE INTO admin_mfa_totp (username, secret_enc, status, created_at, confirmed_at, last_step) " .
                    "VALUES (:u, :s, 'pending', :now, NULL, 0)"
            ),
            [":u" => $username, ":s" => $envelope, ":now" => time()]
        );
    });
    $b32 = admin_totp_base32($secret);
    $issuer = str_replace(":", " ", sanitize_label($issuer, 64));
    if ($issuer === "") {
        $issuer = "Identity Cloud Console";
    }
    return [
        "secret" => $b32,
        "otpauth_uri" => "otpauth://totp/" . rawurlencode($issuer) . ":" . rawurlencode($username) .
            "?secret=" . $b32 . "&issuer=" . rawurlencode($issuer) .
            "&algorithm=SHA1&digits=6&period=" . ADMIN_TOTP_PERIOD_SECONDS,
        "expires_in" => ADMIN_TOTP_PENDING_SECONDS,
    ];
}

/**
 * Confirms $username's pending authenticator app with a current $code, at most
 * ADMIN_TOTP_PENDING_SECONDS after it was set up. True once it is active.
 */
function admin_totp_confirm(string $storePath, string $username, string $code): bool
{
    $record = admin_totp_record($storePath, $username);
    if (
        $record === null ||
        $record["status"] !== "pending" ||
        $record["secret"] === null ||
        $record["created_at"] + ADMIN_TOTP_PENDING_SECONDS < time()
    ) {
        return false;
    }
    $step = admin_totp_matching_step($record["secret"], $code, 0);
    if ($step === null) {
        return false;
    }
    // Only the pending secret the code was checked against becomes active.
    $upd = admin_api_db($storePath)->prepare(
        "UPDATE admin_mfa_totp SET status = 'active', confirmed_at = :now, last_step = :step " .
            "WHERE username = :u AND status = 'pending' AND secret_enc = :enc"
    );
    storage_execute($upd, [
        ":now" => time(),
        ":step" => $step,
        ":u" => $username,
        ":enc" => $record["secret_enc"],
    ]);
    return $upd->rowCount() === 1;
}

/**
 * Checks $code against $username's active authenticator app. Each code works once: the
 * accepted time step is stored with a compare-and-swap, so a replayed or concurrent second use
 * of the same code fails.
 */
function admin_totp_verify(string $storePath, string $username, string $code): bool
{
    $record = admin_totp_record($storePath, $username);
    if ($record === null || $record["status"] !== "active" || $record["secret"] === null) {
        return false;
    }
    $step = admin_totp_matching_step($record["secret"], $code, $record["last_step"]);
    if ($step === null) {
        return false;
    }
    $upd = admin_api_db($storePath)->prepare(
        "UPDATE admin_mfa_totp SET last_step = :step WHERE username = :u AND status = 'active' AND last_step < :floor"
    );
    storage_execute($upd, [":step" => $step, ":u" => $username, ":floor" => $step]);
    return $upd->rowCount() === 1;
}

/** Removes $username's authenticator app, pending or active. True when one was removed. */
function admin_totp_delete(string $storePath, string $username): bool
{
    $stmt = admin_api_db($storePath)->prepare("DELETE FROM admin_mfa_totp WHERE username = :u");
    $stmt->execute([":u" => $username]);
    return $stmt->rowCount() > 0;
}

/** Status of $username's authenticator app for the console; never includes the secret. */
function admin_totp_status(string $storePath, string $username): array
{
    $record = admin_totp_record($storePath, $username);
    $active = $record !== null && $record["status"] === "active";
    return [
        "enrolled" => $active,
        "pending" => $record !== null && !$active && $record["created_at"] + ADMIN_TOTP_PENDING_SECONDS >= time(),
        "confirmed_at" => $active && $record["confirmed_at"] !== null
            ? gmdate("Y-m-d\TH:i:s\Z", $record["confirmed_at"])
            : null,
    ];
}
