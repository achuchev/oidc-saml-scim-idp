<?php
declare(strict_types=1);

/** Shortest signing-key lifetime the API accepts (S10-07). */
const API_KEY_MIN_TTL_SECONDS = 300;

/**
 * Shortest interval automatic rotation may leave between two keys (S10-07). Rotation replaces
 * the active key once it is within the lead time of its expiry, so a provider generates a new
 * key every TTL minus lead time seconds; a non-zero lead time must stay at least this much
 * shorter than the TTL.
 */
const API_KEY_MIN_ROTATION_INTERVAL_SECONDS = 300;

/**
 * Most signing keys a provider may publish (keys still in its JWKS) before POST .../keys
 * answers 409 (S10-07). Expired keys that have left the JWKS do not count.
 */
const API_MAX_KEYS_PER_PROVIDER = 20;

/** Most keys that have left the JWKS one POST .../keys call removes (S10-07). */
const API_KEY_PRUNE_BATCH = 100;

/**
 * JOSE "typ" of the workload tokens POST /api/token mints (G1a-02, RFC 8725 section 3.11),
 * so verifiers can tell them from the provider's ID tokens ("JWT") and access tokens
 * ("at+jwt"), which share its issuer and keys. legacy_workload_tokens restores "JWT".
 */
const API_TOKEN_JWT_TYP = "workload+jwt";

/** Longest lifetime of a workload token (G1a-02); legacy_workload_tokens allows 365 days. */
const API_TOKEN_MAX_TTL_SECONDS = 86400;

/**
 * End-user identity claims, and the client_id and scope of access tokens, that POST
 * /api/token does not copy from "extra" either (G1a-02), so a workload token cannot pose as
 * a user's ID or access token (the claims OIDC_PROTECTED_CLAIMS keeps from custom_claims).
 * legacy_workload_tokens allows them again.
 */
const API_TOKEN_IDENTITY_CLAIMS = [
    "client_id" => true,
    "scope" => true,
    "name" => true,
    "given_name" => true,
    "family_name" => true,
    "preferred_username" => true,
    "email" => true,
    "email_verified" => true,
    "phone_number" => true,
    "groups" => true,
];

/**
 * Claims POST /api/token never copies from "extra": the registered claims it sets itself and
 * the end-user authentication and session claims a workload token must not assert (G1a-02).
 */
const API_TOKEN_RESERVED_CLAIMS = [
    "iss" => true,
    "aud" => true,
    "sub" => true,
    "iat" => true,
    "nbf" => true,
    "exp" => true,
    "jti" => true,
    "nonce" => true,
    "auth_time" => true,
    "amr" => true,
    "acr" => true,
    "azp" => true,
    "at_hash" => true,
    "c_hash" => true,
    "s_hash" => true,
    "sid" => true,
    "cnf" => true,
    "act" => true,
];

function format_provider_api_payload(
    array $p,
    string $baseUrl,
    string $PROVIDERS_FILE,
    PDO $pdo
): array {
    $issuer = $baseUrl . "/" . $p["idp_id"];
    // One provider whose certificate cannot be created must not break the whole list (S10-06).
    try {
        ensure_provider_saml_cert($PROVIDERS_FILE, $p);
    } catch (Throwable $e) {
        error_log(
            "format_provider_api_payload: SAML certificate unavailable for provider " .
                (string) $p["id"] . ": " . $e->getMessage()
        );
    }

    $cStmt = $pdo->prepare(
        "SELECT COUNT(*) FROM oidc_clients WHERE provider_id = :pid"
    );
    $cStmt->execute([":pid" => $p["id"]]);
    $oidcCount = (int) $cStmt->fetchColumn();

    $sStmt = $pdo->prepare(
        "SELECT COUNT(*) FROM saml_apps WHERE provider_id = :pid"
    );
    $sStmt->execute([":pid" => $p["id"]]);
    $samlCount = (int) $sStmt->fetchColumn();

    $scimTokStmt = $pdo->prepare(
        "SELECT COUNT(*) FROM scim_tokens WHERE provider_id = :pid"
    );
    $scimTokStmt->execute([":pid" => $p["id"]]);
    $scimTokenCount = (int) $scimTokStmt->fetchColumn();

    $scimConnStmt = $pdo->prepare(
        "SELECT COUNT(*) FROM scim_connectors WHERE provider_id = :pid"
    );
    $scimConnStmt->execute([":pid" => $p["id"]]);
    $scimConnCount = (int) $scimConnStmt->fetchColumn();

    // "alg" is the algorithm the provider signs with: its active key's (S10-09). The stored
    // provider alg is only the fallback, so a provider saved before activation synced it is
    // not shown with a stale algorithm.
    $alg = (string) ($p["alg"] ?? "RS256");
    foreach ($p["keys"] ?? [] as $k) {
        if (
            (string) ($k["kid"] ?? "") === (string) ($p["active_kid"] ?? "") &&
            is_string($k["alg"] ?? null) &&
            $k["alg"] !== ""
        ) {
            $alg = $k["alg"];
            break;
        }
    }

    return [
        "id" => $p["id"],
        "friendly" => $p["friendly"],
        "idpId" => $p["idp_id"],
        "alg" => $alg,
        "default_auth_policy" => $p["default_auth_policy"] ?? "flexible",
        "issuer" => $issuer,
        "discovery" => $issuer . "/.well-known/openid-configuration",
        "jwks" => $issuer . "/jwks",
        "authorize_endpoint" => $issuer . "/oauth2/authorize",
        "token_endpoint" => $issuer . "/oauth2/token",
        "userinfo_endpoint" => $issuer . "/oauth2/userinfo",
        "saml_metadata" => $issuer . "/saml/metadata",
        "saml_metadata_download" => $issuer . "/saml/metadata?download=1",
        "saml_sso" => $issuer . "/saml/sso",
        "saml_slo" => $issuer . "/saml/slo",
        "saml_cert" => $issuer . "/saml/cert.pem",
        "scim_base_url" => $issuer . "/scim/v2",
        "portal_url" => $issuer . "/portal",
        "oidc_app_count" => $oidcCount,
        "saml_app_count" => $samlCount,
        "scim_token_count" => $scimTokenCount,
        "scim_connector_count" => $scimConnCount,
        "created_at" => $p["created_at"] ?? null,
        "last_issued_at" => $p["last_issued_at"] ?? null,
        "active_kid" => $p["active_kid"] ?? null,
        "key_count" => isset($p["keys"]) ? count($p["keys"]) : 0,
        "key_ttl_seconds" => $p["key_ttl_seconds"] ?? null,
        // The key TTL automatic rotation actually uses: the provider's value, else
        // SIGNING_KEY_TTL (or SIGNING_KEY_VALIDITY), else one hour. The console shows it for
        // providers without a stored TTL.
        "effective_key_ttl_seconds" => provider_ttl_seconds($p),
        "expired_key_retention_seconds" =>
            $p["expired_key_retention_seconds"] ?? null,
        // The retention actually applied: the provider's value, else EXPIRED_KEY_RETENTION
        // or one hour (S04-03).
        "effective_expired_key_retention_seconds" => provider_retention_seconds($p),
        "key_rotation_lead_time_seconds" =>
            $p["key_rotation_lead_time_seconds"] ?? null,
    ];
}

/**
 * Parses a user-supplied duration with parse_duration_seconds() (S13-11) and ends the request
 * with 400 when it is not valid or outside [$min, $max] seconds; nothing is clamped or
 * replaced by a default.
 */
function api_duration_or_400(mixed $spec, string $field, int $min = 0, int $max = 31536000): int
{
    $seconds = parse_duration_seconds(is_string($spec) ? trim($spec) : $spec, $max);
    if ($seconds === null) {
        if ($max >= 2 * 86400) {
            $limit = intdiv($max, 86400) . " days";
        } elseif ($max % 3600 === 0) {
            $limit = intdiv($max, 3600) . " hours";
        } else {
            $limit = $max . " seconds";
        }
        json_response(400, [
            "error" => "$field must be a number of seconds ('3600') or a duration such as " .
                "'90min', '1h', '2h30m', '1 day' or '1w', at most " . $limit,
        ]);
    }
    if ($seconds < $min) {
        json_response(400, ["error" => "$field must be at least $min seconds"]);
    }
    return $seconds;
}

/** True when a duration field is absent: missing, null or an empty string. */
function api_duration_absent(mixed $spec): bool
{
    return $spec === null || (is_string($spec) && trim($spec) === "");
}

/**
 * A boolean request field, false when absent or null. Only true/false, 1/0 and the strings
 * "true"/"false"/"1"/"0" are accepted (admin_client_bool_input()); anything else answers 400
 * instead of being read as true the way !empty() reads "false" (G1e-02).
 */
function api_bool_or_400(array $input, string $field): bool
{
    try {
        return admin_client_bool_input($input, $field, false);
    } catch (InvalidArgumentException $e) {
        json_response(400, ["error" => $e->getMessage()]);
    }
}

/**
 * Key timing rules for every path that sets the provider key TTL (S10-07): a TTL of at least
 * API_KEY_MIN_TTL_SECONDS, and the rotation interval rule of
 * api_validate_rotation_interval_or_400() for the resulting TTL and lead time.
 */
function api_validate_key_timing_or_400(int $ttlSeconds, int $leadSeconds): void
{
    if ($ttlSeconds < API_KEY_MIN_TTL_SECONDS) {
        json_response(400, [
            "error" => "Key TTL must be at least " . API_KEY_MIN_TTL_SECONDS . " seconds",
        ]);
    }
    api_validate_rotation_interval_or_400($ttlSeconds, $leadSeconds);
}

/**
 * Automatic rotation replaces the active key once time() reaches its expiry minus the lead
 * time, so a provider generates a new key every TTL minus lead time seconds (S10-07). A
 * non-zero lead time must leave at least API_KEY_MIN_ROTATION_INTERVAL_SECONDS between
 * rotations: "shorter than the TTL" alone would accept TTL 300 s with lead time 299 s, a new
 * key on nearly every signing call. A zero lead time never shortens the interval, so it is
 * always accepted, also on a provider whose stored TTL predates the minimum. $error replaces
 * the default message.
 */
function api_validate_rotation_interval_or_400(int $ttlSeconds, int $leadSeconds, ?string $error = null): void
{
    if ($leadSeconds > 0 && $ttlSeconds - $leadSeconds < API_KEY_MIN_ROTATION_INTERVAL_SECONDS) {
        json_response(400, [
            "error" => $error ?? (
                "Key rotation lead time ($leadSeconds s) must be 0 or at least " .
                API_KEY_MIN_ROTATION_INTERVAL_SECONDS . " seconds shorter than the key TTL ($ttlSeconds s): " .
                "automatic rotation generates a new key every TTL minus lead time"
            ),
        ]);
    }
}

/**
 * The kids of a provider's keys that are in its JWKS, as [kid => true]: exactly the keys
 * filter_publishable_keys_for_provider() publishes, computed in one pass over the keys.
 */
function api_published_kids(array $prov): array
{
    $kids = [];
    foreach (filter_publishable_keys_for_provider($prov) as $k) {
        $kids[(string) ($k["kid"] ?? "")] = true;
    }
    return $kids;
}

/**
 * The kids of a provider's keys that have left its JWKS (past their expiry plus retention and
 * past every token they signed), oldest first: the keys that can be pruned. The active key is
 * never among them.
 */
function api_unpublished_kids(array $prov, ?array $publishedKids = null): array
{
    $publishedKids ??= api_published_kids($prov);
    $activeKid = (string) ($prov["active_kid"] ?? "");
    $kids = [];
    foreach ($prov["keys"] ?? [] as $k) {
        $kid = is_array($k) ? (string) ($k["kid"] ?? "") : "";
        if ($kid !== "" && $kid !== $activeKid && !isset($publishedKids[$kid])) {
            $kids[] = $kid;
        }
    }
    return $kids;
}

/** id, owner, friendly and idp_id of every provider of $owner, oldest first (no keys). */
function api_owner_provider_rows(string $storePath, string $owner): array
{
    storage_initialize($storePath);
    $stmt = storage_db($storePath)->prepare(
        "SELECT id, owner, friendly, idp_id FROM providers WHERE owner = :owner ORDER BY rowid ASC"
    );
    $stmt->execute([":owner" => $owner]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Resolves one of the caller's providers by UUID or idpId (auth_resolve_provider_or_fail():
 * 404 when unknown, 403 when out of scope) and returns it freshly loaded with its keys.
 * Only this owner's provider rows are read, never every tenant's keys (S10-07).
 */
function api_resolve_provider(
    array $auth,
    string $storePath,
    string $idOrSlug,
    bool $requireWrite = false
): array {
    $res = auth_resolve_provider_or_fail(
        $auth,
        api_owner_provider_rows($storePath, (string) $auth["owner"]),
        $idOrSlug,
        $requireWrite
    );
    $provider = load_provider_by_id($storePath, (string) $res["provider"]["id"]);
    if ($provider === null) {
        json_response(404, ["error" => "Provider not found"]);
    }
    return $provider;
}

/**
 * A directory user body from the admin API: "subject" (immutable, assigned by the directory)
 * and internal "_"-prefixed flags are never taken from the request (S03-06).
 */
function api_directory_user_input(array $body): array
{
    unset($body["subject"]);
    foreach (array_keys($body) as $key) {
        if (is_string($key) && str_starts_with($key, "_")) {
            unset($body[$key]);
        }
    }
    return $body;
}

/**
 * API clients need can_mint_tokens to create, change or rotate the secret of an OIDC client
 * that can use the client_credentials grant (G1a-02): such a client obtains provider-signed
 * access tokens without any user, with sub = its client_id and its custom claims, values the
 * API client chooses. That is a confidential client registered for the grant, or any
 * confidential client while legacy_oauth_flows is on. $client is the client as it would be
 * stored; as in oidc_save_client(), any non-empty is_public means public, and an empty grant
 * list means the defaults, which do not include client_credentials.
 */
function api_require_minting_for_client_credentials(array $auth, array $client): void
{
    if (($auth["type"] ?? "") !== "api_client" || !empty($client["is_public"])) {
        return;
    }
    $grantTypes = $client["grant_types"] ?? null;
    if (is_string($grantTypes)) {
        $grantTypes = preg_split('/[\s,]+/', $grantTypes, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }
    if (
        in_array("client_credentials", normalize_string_list($grantTypes), true) ||
        oidc_legacy_oauth_flows()
    ) {
        auth_require_token_minting(
            $auth,
            "manage OIDC clients that can use the client_credentials grant, whose tokens carry the client_id as their subject"
        );
    }
}

/** provider_update_fields() (one UPDATE of one provider); failures end the request safely. */
function api_update_provider_or_fail(string $storePath, string $providerId, array $fields): void
{
    try {
        provider_update_fields($storePath, $providerId, $fields);
    } catch (Throwable $e) {
        api_fail_from_exception($e);
    }
}

/**
 * Whether any provider of any owner already uses $idpId, compared case-insensitively, raw and
 * rawurldecoded. Public URLs resolve idp_ids that loosely, so two such providers could shadow
 * or squat each other's URLs (S10-03).
 */
function api_idp_id_taken(string $storePath, string $idpId): bool
{
    storage_initialize($storePath);
    $decoded = rawurldecode($idpId);
    $rows = storage_db($storePath)->query("SELECT idp_id FROM providers")->fetchAll(PDO::FETCH_COLUMN);
    foreach ($rows as $stored) {
        $stored = (string) $stored;
        $storedDecoded = rawurldecode($stored);
        foreach ([$idpId, $decoded] as $candidate) {
            if (strcasecmp($stored, $candidate) === 0 || strcasecmp($storedDecoded, $candidate) === 0) {
                return true;
            }
        }
    }
    return false;
}

/** True for a PDOException caused by a UNIQUE or other integrity constraint (SQLSTATE 23000). */
function api_is_constraint_violation(Throwable $e): bool
{
    if (!($e instanceof PDOException)) {
        return false;
    }
    $state = (string) ($e->errorInfo[0] ?? $e->getCode());
    return $state === "23000" || str_contains($e->getMessage(), "constraint failed");
}

/**
 * Answers a failed create or update without leaking internals (S03-14): integrity violations,
 * and conflicts a save function detected itself and raised with exception code 409 (a
 * duplicate client_id, oidc_assert_client_id_available()), become 409 with $conflictMessage;
 * other storage errors a logged generic 500, "not found" errors 404, and validation
 * exceptions 400 with their message.
 */
function api_fail_from_exception(Throwable $e, string $conflictMessage = "This item already exists"): never
{
    if (api_is_constraint_violation($e)) {
        json_response(409, ["error" => $conflictMessage]);
    }
    if ($e instanceof Exception && !($e instanceof PDOException) && $e->getCode() === 409) {
        json_response(409, ["error" => $conflictMessage]);
    }
    if ($e instanceof PDOException) {
        error_log("admin API storage error: " . $e->getMessage());
        json_response(500, ["error" => "The request could not be completed"]);
    }
    if (!($e instanceof Exception)) {
        // TypeError and other engine errors: the input had an unexpected shape.
        error_log("admin API request failed: " . get_class($e) . ": " . $e->getMessage());
        json_response(400, ["error" => "Invalid request"]);
    }
    $message = $e->getMessage();
    $code = str_contains(strtolower($message), "not found") ? 404 : 400;
    json_response($code, ["error" => $message]);
}

/**
 * Safe error text for SCIM connector save, test and sync (G1a-07): DNS answers and blocked
 * target addresses are reduced to one generic message, IP literals are removed from other
 * messages, and storage errors are not passed through.
 */
function api_scim_fail_from_exception(Throwable $e): never
{
    if ($e instanceof PDOException) {
        error_log("admin API SCIM storage error: " . $e->getMessage());
        json_response(500, ["error" => "The request could not be completed"]);
    }
    if (!($e instanceof Exception)) {
        error_log("admin API SCIM request failed: " . get_class($e) . ": " . $e->getMessage());
        json_response(400, ["error" => "Invalid request"]);
    }
    $message = $e->getMessage();
    if (str_contains(strtolower($message), "not found")) {
        json_response(404, ["error" => $message]);
    }
    if (preg_match('/could not resolve|resolves? to|link-local|ssrf|\bdns\b/i', $message) === 1) {
        error_log("admin API SCIM target rejected: " . $message);
        json_response(400, ["error" => "The SCIM target host is not allowed or could not be resolved"]);
    }
    // IPv4 literals, then IPv6 literals (full form, or compressed with "::").
    $message = (string) preg_replace('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', "[address]", $message);
    $message = (string) preg_replace(
        '/(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?/i',
        "[address]",
        $message
    );
    json_response(400, ["error" => sanitize_label($message, 300)]);
}

/**
 * Where GET /api/https-ca reads a TLS chain from (S10-10): this IdP's own public endpoint,
 * never SERVER_NAME or another name a client chooses. The host is that of public_base_url,
 * else that of the base URL, whose host bootstrap accepts only from allowed_hosts. Only a
 * configured public_base_url may name a port other than 443. "configured" tells whether the
 * host came from public_base_url (chosen by the operator) rather than from the request. Null
 * when the public scheme is not https or the host is a local name.
 *
 * @return array{host: string, port: int, configured: bool}|null
 */
function api_https_ca_target(string $baseUrl): ?array
{
    $configured = config_value("public_base_url", ["OIDC_PUBLIC_BASE_URL", "PUBLIC_BASE_URL"]);
    $isConfigured = is_string($configured) && trim($configured) !== "";
    $parts = parse_url($isConfigured ? trim($configured) : $baseUrl);
    if (!is_array($parts) || strtolower((string) ($parts["scheme"] ?? "")) !== "https") {
        return null;
    }
    $host = rtrim(strtolower(trim((string) ($parts["host"] ?? ""), "[]")), ".");
    if ($host === "" || $host === "localhost" || str_ends_with($host, ".localhost")) {
        return null;
    }
    $port = $isConfigured && isset($parts["port"]) ? (int) $parts["port"] : 443;
    if ($port < 1 || $port > 65535) {
        return null;
    }
    return ["host" => $host, "port" => $port, "configured" => $isConfigured];
}

/**
 * The certificate chain $host presents on $port, read over a connection pinned to an address
 * that was resolved and checked first (S10-10). With $requirePublic, every A and AAAA record,
 * and every address the system resolver returns, must be a public unicast address
 * (ip_is_public_unicast()). Callers pass false only for the host of the operator's
 * public_base_url, which the client cannot choose and which may resolve to a private address
 * from the server (split-horizon DNS, on-premises installs). A name that does not resolve
 * fails closed. The TLS connection goes to a resolved IP literal with SNI set to $host, so a
 * second DNS answer cannot send it elsewhere. The matching trust-store root
 * (find_trust_anchor_for()) is appended when the server does not send it. Throws on failure; the
 * messages name addresses, so they belong in the log, not in responses.
 */
function api_fetch_public_tls_chain(string $host, int $port, bool $requirePublic = true): array
{
    $host = rtrim(strtolower(trim($host, "[] \t")), ".");
    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        $ips[] = $host;
    } else {
        if (
            strlen($host) > 253 ||
            preg_match(
                '/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D',
                $host
            ) !== 1
        ) {
            throw new InvalidArgumentException("Invalid host name for TLS inspection");
        }
        foreach ([[DNS_A, "ip"], [DNS_AAAA, "ipv6"]] as [$type, $field]) {
            $records = @dns_get_record($host, $type);
            foreach (is_array($records) ? $records : [] as $record) {
                if (is_string($record[$field] ?? null) && $record[$field] !== "") {
                    $ips[] = $record[$field];
                }
            }
        }
        $systemIps = @gethostbynamel($host);
        foreach (is_array($systemIps) ? $systemIps : [] as $ip) {
            $ips[] = (string) $ip;
        }
    }
    $ips = array_values(array_filter(
        array_unique($ips),
        fn($ip) => filter_var($ip, FILTER_VALIDATE_IP) !== false
    ));
    if (empty($ips)) {
        throw new RuntimeException("$host does not resolve");
    }
    if ($requirePublic) {
        foreach ($ips as $ip) {
            if (!ip_is_public_unicast($ip)) {
                throw new RuntimeException("$host resolves to the non-public address $ip; not connecting");
            }
        }
    }

    $lastError = "TLS connection failed";
    foreach (array_slice($ips, 0, 3) as $ip) {
        $literal = str_contains($ip, ":") ? "[" . $ip . "]" : $ip;
        $ctx = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "capture_peer_cert_chain" => true,
                "SNI_enabled" => true,
                "peer_name" => $host,
                "verify_peer" => false,
                "verify_peer_name" => false,
                "allow_self_signed" => true,
            ],
        ]);
        $errno = 0;
        $errstr = "";
        $fp = @stream_socket_client(
            "ssl://" . $literal . ":" . $port,
            $errno,
            $errstr,
            5,
            STREAM_CLIENT_CONNECT,
            $ctx
        );
        if ($fp === false) {
            $lastError = "TLS connection to $literal:$port failed: $errstr ($errno)";
            continue;
        }
        $opts = stream_context_get_options($fp);
        fclose($fp);
        $chain = $opts["ssl"]["peer_certificate_chain"] ?? null;
        if (!is_array($chain) || $chain === []) {
            $single = $opts["ssl"]["peer_certificate"] ?? null;
            $chain = $single ? [$single] : [];
        }
        if ($chain === []) {
            $lastError = "No certificate received from $literal:$port";
            continue;
        }
        $chain = array_values($chain);
        $top = $chain[count($chain) - 1];
        $trustedRoot = find_trust_anchor_for($top);
        if ($trustedRoot && !certs_equal($top, $trustedRoot)) {
            $chain[] = $trustedRoot;
        }
        return $chain;
    }
    throw new RuntimeException($lastError);
}

/**
 * Whether the caller may create or change password-pushing SCIM connectors. Such a connector
 * sends every user's plaintext password to the URL it names, which is more than user_scope
 * grants, so API clients may do this only with allow_api_client_password_push (S10-01).
 */
function api_may_manage_password_push(array $auth): bool
{
    return ($auth["type"] ?? "") === "session" ||
        config_flag("allow_api_client_password_push", "OIDC_ALLOW_API_CLIENT_PASSWORD_PUSH");
}

/**
 * The idp_id of a new provider of $owner named $friendly (S10-03). idp_ids are global and
 * both owner names and provider names may contain '-', so idp_id_for() alone lets owner
 * "acme" create "eu-prod" and take "acme-eu-prod", the id that owner "acme-eu" would get for
 * "prod". New providers therefore get '_' wherever their name has '-': their id then holds no
 * '-' after the owner, so the owner is everything before its last '-', and no owner can take
 * an id another owner's provider names would produce. Existing providers keep their stored
 * idp_id. The operator flag legacy_provider_id_format restores the old derivation.
 */
function api_new_provider_idp_id(string $owner, string $friendly): string
{
    if (config_flag("legacy_provider_id_format", "OIDC_LEGACY_PROVIDER_ID_FORMAT")) {
        return idp_id_for($owner, $friendly);
    }
    return idp_id_for($owner, str_replace("-", "_", $friendly));
}

/**
 * Audiences POST /api/token refuses (G1a-02): the provider's issuer (the audience of its RFC
 * 9068 access tokens) and the client_id of any of its OIDC clients (the audience of their ID
 * tokens), compared case-insensitively and ignoring a trailing '/'. A workload token with such
 * an audience would pass as one of the provider's own end-user tokens at a relying party or
 * resource server that does not check "typ". Returns the refused entries of $audList.
 */
function api_workload_refused_audiences(string $storePath, array $provider, string $issuer, array $audList): array
{
    $stmt = storage_db($storePath)->prepare("SELECT client_id FROM oidc_clients WHERE provider_id = :pid");
    $stmt->execute([":pid" => (string) $provider["id"]]);
    $taken = [strtolower(rtrim($issuer, "/")) => true];
    foreach ($stmt->fetchAll(PDO::FETCH_COLUMN) as $clientId) {
        $taken[strtolower(rtrim((string) $clientId, "/"))] = true;
    }
    $refused = [];
    foreach ($audList as $aud) {
        if (isset($taken[strtolower(rtrim((string) $aud, "/"))])) {
            $refused[] = (string) $aud;
        }
    }
    return $refused;
}

/** The issuer name authenticator apps show for this console's accounts (G2a-07). */
function api_admin_totp_issuer(string $baseUrl): string
{
    $host = parse_url($baseUrl, PHP_URL_HOST);
    return "Identity Cloud Console" . (is_string($host) && $host !== "" ? " " . $host : "");
}

/**
 * Ends the request unless $input["password"] is the current console password of $owner: 403
 * when it is wrong, 429 after 5 wrong passwords within 15 minutes. Required to set up or
 * remove an administrator's authenticator app (G2a-07), so a borrowed console session cannot
 * change how the administrator signs in.
 */
function api_admin_reauthenticate_or_fail(string $storePath, string $usersFile, array $auth, array $input): void
{
    $owner = (string) $auth["owner"];
    $bucket = rate_limit_bucket("admin_reauth", strtolower($owner));
    $window = ADMIN_LOGIN_WINDOW_SECONDS;
    if (rate_limit_hit($storePath, $bucket, 5, $window, $window)) {
        json_response(429, ["error" => "Too many wrong passwords. Please wait a few minutes."]);
    }
    $password = is_scalar($input["password"] ?? null) ? (string) $input["password"] : "";
    if (!admin_password_verify(read_users($usersFile), $owner, $password)) {
        admin_audit_append($storePath, $auth, "admin.reauthentication", "failure");
        json_response(403, ["error" => "Your current password is required and was not correct"]);
    }
    rate_limit_clear($storePath, $bucket);
}

/**
 * Ends the request unless $code is a current code of $owner's authenticator app (403; 429
 * after ADMIN_LOGIN_OTP_MAX_FAILURES wrong codes, the budget POST /api/login uses). With
 * $pending, $code confirms the app being set up instead.
 */
function api_admin_totp_code_or_fail(string $storePath, string $owner, string $code, bool $pending = false): void
{
    $bucket = rate_limit_bucket("admin_login_otp", strtolower($owner));
    if (rate_limit_is_blocked($storePath, $bucket)) {
        json_response(429, ["error" => "Too many invalid authentication codes. Please wait a few minutes."]);
    }
    $ok = $pending
        ? admin_totp_confirm($storePath, $owner, $code)
        : admin_totp_verify($storePath, $owner, $code);
    if (!$ok) {
        $window = ADMIN_LOGIN_WINDOW_SECONDS;
        rate_limit_record_failure($storePath, $bucket, ADMIN_LOGIN_OTP_MAX_FAILURES, $window, $window);
        json_response(403, [
            "error" => $pending
                ? "Invalid code, or the setup has expired; start the setup again"
                : "Invalid or already used authentication code",
        ]);
    }
    rate_limit_clear($storePath, $bucket);
}

/**
 * Handles all /api/* Admin Console, Programmatic Management API, & OpenAPI endpoints.
 * Returns void if unmatched so the router can continue to protocol/SPA routes.
 */
function handle_api_routes(
    string $method,
    string $path,
    string $CONFIG_DIR,
    string $USERS_FILE,
    string $PROVIDERS_FILE,
    string $APIKEYS_FILE,
    string $KEYS_DIR,
    string $scriptDir,
    string $origin,
    string $baseUrl,
    string $rpId
): void {
    // Public OpenAPI JSON alias at root /openapi.json as well as /api/openapi.json
    if (
        ($path === "/openapi.json" || $path === "/api/openapi.json") &&
        in_array($method, ["GET", "OPTIONS"], true)
    ) {
        send_security_headers(false);
        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Methods: GET, OPTIONS");
        header("Access-Control-Allow-Headers: Authorization, X-API-Key, Content-Type, Accept");
        if ($method === "OPTIONS") {
            http_response_code(204);
            exit();
        }
        $download = isset($_GET["download"]) && $_GET["download"] !== "0";
        header("Content-Type: application/json; charset=utf-8");
        if ($download) {
            header('Content-Disposition: attachment; filename="openapi.json"');
        }
        echo json_encode(
            build_openapi_spec($baseUrl),
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
        );
        exit();
    }

    if (!str_starts_with($path, "/api/")) {
        return;
    }

    // Handle CORS preflight for external header-authenticated API clients & OpenAPI tools
    if ($method === "OPTIONS") {
        send_security_headers(false);
        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");
        header("Access-Control-Allow-Headers: Authorization, X-API-Key, Content-Type, Accept");
        http_response_code(204);
        exit();
    }

    // Emit CORS response header ONLY when caller is using stateless Authorization / X-API-Key headers (never for cookie sessions)
    if (trim(get_auth_header()) !== "" || !empty($_SERVER["HTTP_X_API_KEY"])) {
        header("Access-Control-Allow-Origin: *");
    }

    // ---------- Interactive OpenAPI Documentation Portal ----------
    if ($path === "/api/docs" && $method === "GET") {
        render_openapi_docs_ui($baseUrl);
    }

    // ---------- OAuth 2.0 Client Credentials Grant for Admin API Clients ----------
    if ($path === "/api/oauth2/token" && $method === "POST") {
        $ct = strtolower((string) ($_SERVER["CONTENT_TYPE"] ?? ($_SERVER["HTTP_CONTENT_TYPE"] ?? "")));
        $params = str_contains($ct, "application/json")
            ? read_json_body(true)
            : $_POST;

        $grantType = trim((string) ($params["grant_type"] ?? "client_credentials"));
        if ($grantType !== "client_credentials") {
            json_response(400, [
                "error" => "unsupported_grant_type",
                "error_description" => "Only grant_type=client_credentials is supported on /api/oauth2/token",
            ]);
        }

        $clientId = trim((string) ($params["client_id"] ?? ""));
        $clientSecret = (string) ($params["client_secret"] ?? "");
        $authHdr = trim(get_auth_header());
        if (preg_match('/^Basic\s+([A-Za-z0-9+\/=]+)$/i', $authHdr, $bm)) {
            $dec = base64_decode($bm[1], true);
            if ($dec !== false && str_contains($dec, ":")) {
                [$bCid, $bSec] = explode(":", $dec, 2);
                $clientId = rawurldecode($bCid);
                $clientSecret = rawurldecode($bSec);
            }
        }

        if ($clientId === "" || $clientSecret === "") {
            json_response(401, [
                "error" => "invalid_client",
                "error_description" => "Missing client_id or client_secret",
            ]);
        }

        // A user-supplied lifetime is parsed strictly (S13-11): no silent one-hour fallback.
        $ttl = 3600;
        if (!api_duration_absent($params["ttl"] ?? null)) {
            $ttlSpec = $params["ttl"];
            $ttlParsed = parse_duration_seconds(is_string($ttlSpec) ? trim($ttlSpec) : $ttlSpec, 86400);
            if ($ttlParsed === null || $ttlParsed < 60) {
                json_response(400, [
                    "error" => "invalid_request",
                    "error_description" => "ttl must be between 60 and 86400 seconds, as seconds ('3600') " .
                        "or a duration such as '90min', '1h' or '2h30m'",
                ]);
            }
            $ttl = $ttlParsed;
        }

        // The credential is verified first and only failures are counted, per client address
        // (G2a-02): a lock never refuses a valid client, and a success never resets the
        // counter that other callers on the same address share. A client row that still holds
        // a legacy bcrypt digest reserves an attempt in the per-address bcrypt bucket before
        // that slow check (S06-09); SHA-256 digests need no reservation (X3-09).
        $clientIpBucket = client_ip_bucket();
        $verifiedClient = null;
        $issued = admin_client_issue_oauth_token(
            $PROVIDERS_FILE,
            $clientId,
            $clientSecret,
            $ttl,
            $verifiedClient,
            rate_limit_bucket("admin_api_hdr_bcrypt", $clientIpBucket)
        );
        if (!$issued || $verifiedClient === null) {
            // The 10th failure within 300 s locks further failures from this address out for
            // 300 s; while locked, failures are neither counted nor audited.
            if (admin_api_auth_failure_locked($PROVIDERS_FILE, rate_limit_bucket("admin_oauth_tok", $clientIpBucket), 10)) {
                if (!headers_sent()) {
                    header("Retry-After: 300");
                }
                json_response(429, [
                    "error" => "too_many_requests",
                    "error_description" => "Too many failed client authentication attempts; please wait",
                ]);
            }
            // A value that is not shaped like a client_id may be a secret sent in the wrong
            // field, so only its keyed digest is recorded (G1a-01).
            $wellFormedId = preg_match('/^iac_[0-9a-f]{16}$/D', $clientId) === 1;
            admin_audit_append(
                $PROVIDERS_FILE,
                ["type" => "anonymous", "owner" => "", "client" => null],
                "admin_client.token_denied",
                "failure",
                null,
                $wellFormedId ? $clientId : "",
                $wellFormedId
                    ? []
                    : ["client_id" => "malformed", "client_id_digest" => admin_audit_name_digest($PROVIDERS_FILE, $clientId)],
                true
            );
            json_response(401, [
                "error" => "invalid_client",
                "error_description" => "Invalid, expired, or revoked Admin API client credentials",
            ]);
        }

        // A routine event: its own capped audit class, so frequent exchanges can never push
        // security events out of the owner's log (G1a-01).
        admin_audit_append(
            $PROVIDERS_FILE,
            ["type" => "api_client", "owner" => $verifiedClient["owner"], "client" => $verifiedClient],
            "admin_client.token_issued",
            "success",
            null,
            (string) $verifiedClient["client_id"],
            ["expires_in" => $issued["expires_in"] ?? $ttl]
        );
        json_response(200, $issued);
    }

    // ---------- Caller Scope Introspection ----------
    if ($path === "/api/auth/whoami" && $method === "GET") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        json_response(200, [
            "auth_type" => $auth["type"],
            "owner" => $auth["owner"],
            "client" => $auth["client"],
        ]);
    }

    // ---------- Debug ----------
    if ($path === "/api/debug-status" && $method === "GET") {
        json_response(200, ["debug" => debug_enabled($CONFIG_DIR)]);
    }
    if ($path === "/api/debug" && $method === "GET") {
        if (!debug_enabled($CONFIG_DIR)) {
            json_response(404, ["error" => "debug disabled"]);
        }
        require_login($origin);
        $users_ok = is_readable($USERS_FILE);
        $users = $users_ok ? read_users($USERS_FILE) : [];
        json_response(200, [
            "router" => [
                "resolved_path" => $path,
                "origin" => $origin,
                "baseUrl" => $baseUrl,
                "rpId" => $rpId,
                "php_sapi" => php_sapi_name(),
            ],
            "config" => [
                "users_readable" => $users_ok,
                "users_count" => count($users),
            ],
            "session" => [
                "user" => current_user(),
            ],
        ]);
    }

    // ---------- HTTPS CA Export ----------
    if ($path === "/api/https-ca" && $method === "GET") {
        require_admin_auth($PROVIDERS_FILE, $origin);
        // Only this IdP's own public https endpoint is read, over a connection pinned to a
        // resolved address (S10-10); SERVER_NAME follows the client's Host header. A host taken
        // from the request must resolve to public addresses only; the host of a configured
        // public_base_url may also resolve to a private one (split-horizon DNS).
        $target = api_https_ca_target($baseUrl);
        if ($target === null) {
            json_response(400, [
                "error" => "App is not behind public HTTPS or server hostname unknown",
            ]);
        }
        $mode = is_string($_GET["mode"] ?? null) ? strtolower($_GET["mode"]) : "ca";
        $download = isset($_GET["download"]) && $_GET["download"] !== "0";
        try {
            $chain = api_fetch_public_tls_chain($target["host"], $target["port"], !$target["configured"]);
        } catch (Throwable $e) {
            // Resolution and connection details stay in the log: they reveal internal addresses
            // and reachability.
            error_log("GET /api/https-ca: " . $e->getMessage());
            json_response(502, [
                "error" => "The TLS certificate chain of this server could not be read",
            ]);
        }
        try {
            if ($mode === "meta") {
                $last = !empty($chain) ? end($chain) : null;
                json_response(200, [
                    "meta" => [
                        "served_depth" => count($chain),
                        "has_self_signed_root" =>
                            $last && is_self_signed_cert($last),
                    ],
                ]);
            }
            $pems = array_map("x509_resource_to_pem", $chain);
            $caPems = array_slice($pems, 1);
            $rootPem = "";
            if (!empty($pems)) {
                $last = end($chain);
                if ($last && is_self_signed_cert($last)) {
                    $rootPem = x509_resource_to_pem($last);
                } else {
                    $rootPem = end($caPems) ?: "";
                }
            }
            $content = $mode === "root" ? $rootPem ?: "" : implode("", $caPems);
            if ($content === "") {
                json_response(404, [
                    "error" => "No CA certificates available from server",
                ]);
            }
            header("Content-Type: application/x-pem-file");
            if ($download) {
                $fname = $mode === "root" ? "root.pem" : "ca-chain.pem";
                header(
                    'Content-Disposition: attachment; filename="' . $fname . '"'
                );
            }
            echo $content;
            exit();
        } catch (Throwable $e) {
            error_log("GET /api/https-ca: certificate export failed: " . $e->getMessage());
            json_response(500, ["error" => "The TLS certificate chain could not be exported"]);
        }
    }

    // ---------- Browser Admin Auth ----------
    // POST /api/login (G2a-01, G2a-07). A browser that signed in as this administrator before
    // presents a signed known-device cookie (OWASP device cookies): its attempts count only
    // against that cookie, so failures made anywhere else, even from the same address, never
    // lock the administrator out of the browsers they use. Other attempts are limited per
    // address and typed name, per account (all addresses together), per address across all
    // names, and by a global ceiling that also raises an alert (ADMIN_LOGIN_* budgets). The
    // password is checked against users.txt by admin_password_verify(). An administrator with
    // an authenticator app, or every administrator while admin_require_mfa is on, must also
    // send its current code as "otp"; the session starts only after that.
    if ($path === "/api/login" && $method === "POST") {
        verify_request_csrf($origin, false);
        $input = read_json_body();
        $u = is_scalar($input["username"] ?? null) ? trim((string) $input["username"]) : "";
        $p = is_scalar($input["password"] ?? null) ? (string) $input["password"] : "";
        $otp = is_scalar($input["otp"] ?? null) ? trim((string) $input["otp"]) : "";
        $tooMany = ["error" => "Too many failed login attempts. Please wait a few minutes."];

        $users = read_users($USERS_FILE);
        $acct = strtolower($u);
        $window = ADMIN_LOGIN_WINDOW_SECONDS;
        $ipBucketId = client_ip_bucket();
        $ipBucket = rate_limit_bucket("admin_login_ip", $ipBucketId);
        $globalBucket = rate_limit_bucket("admin_login_global", "all");
        $deviceId = admin_device_id_from_cookie($PROVIDERS_FILE, $users, $u);
        // Attempts are reserved before the password is checked (S06-09) and cleared after a
        // successful sign-in. Bucket keys are digests, so a raw (possibly huge) username never
        // becomes a key.
        $reserved = $deviceId !== null
            ? [[rate_limit_bucket("admin_login_dev", $deviceId), ADMIN_LOGIN_DEVICE_MAX_FAILURES, $window]]
            : [
                [rate_limit_bucket("admin_login", $ipBucketId, $acct), 8, 300],
                [rate_limit_bucket("admin_login_acct", $acct), ADMIN_LOGIN_ACCOUNT_MAX_FAILURES, $window],
            ];
        if (
            $deviceId === null &&
            (rate_limit_is_blocked($PROVIDERS_FILE, $globalBucket) || rate_limit_is_blocked($PROVIDERS_FILE, $ipBucket))
        ) {
            json_response(429, $tooMany);
        }
        foreach ($reserved as [$bucket, $max, $seconds]) {
            if (rate_limit_hit($PROVIDERS_FILE, $bucket, $max, $seconds, $seconds)) {
                json_response(429, $tooMany);
            }
        }
        $deviceDetail = $deviceId !== null ? "known" : "new";

        if (!admin_password_verify($users, $u, $p)) {
            if ($deviceId === null) {
                admin_login_count_untrusted_failure($PROVIDERS_FILE, $ipBucket, $globalBucket, $users);
            }
            // Only an existing administrator's name is recorded, so that administrator sees the
            // attempt. Any other name may be a password typed into the wrong field and is never
            // stored (G1a-01): the row has no owner and a keyed digest for correlation only. The
            // digest is computed either way, so both branches cost the same.
            $isAdmin = $u !== "" && isset($users[$u]);
            $nameDigest = admin_audit_name_digest($PROVIDERS_FILE, $u);
            admin_audit_append(
                $PROVIDERS_FILE,
                ["type" => "anonymous", "owner" => $isAdmin ? $u : "", "client" => null],
                "admin.login",
                "failure",
                null,
                "",
                ($isAdmin ? [] : ["username" => "unknown", "username_digest" => $nameDigest]) +
                    ["device" => $deviceDetail],
                true
            );
            json_response(401, ["error" => "Invalid credentials"]);
        }

        // Second factor (G2a-07): a code from the administrator's authenticator app. With
        // admin_require_mfa, an administrator without one sets it up here: the answer carries
        // a new secret, and the next attempt with a code from it confirms the app.
        $mfa = "none";
        $enrolled = admin_totp_enrolled($PROVIDERS_FILE, $u);
        if ($enrolled || admin_mfa_required()) {
            $mfa = "totp";
            $otpBucket = rate_limit_bucket("admin_login_otp", $acct);
            if (rate_limit_is_blocked($PROVIDERS_FILE, $otpBucket)) {
                json_response(429, ["error" => "Too many invalid authentication codes. Please wait a few minutes."]);
            }
            $mfaAnswer = ["mfa_required" => true, "mfa_methods" => ["totp"]];
            if ($otp === "") {
                if ($enrolled) {
                    json_response(401, ["error" => "Enter the 6-digit code from your authenticator app."] + $mfaAnswer);
                }
                try {
                    $setup = admin_totp_begin($PROVIDERS_FILE, $u, api_admin_totp_issuer($baseUrl));
                } catch (Throwable $e) {
                    error_log("POST /api/login: authenticator app setup failed: " . $e->getMessage());
                    json_response(500, ["error" => "The authenticator app setup could not be started"]);
                }
                json_response(401, [
                    "error" => "This console requires an authenticator app. Add the account shown to your app, " .
                        "then sign in again with the 6-digit code it displays.",
                    "mfa_enrollment_required" => true,
                    "totp" => $setup,
                ] + $mfaAnswer);
            }
            $otpOk = $enrolled
                ? admin_totp_verify($PROVIDERS_FILE, $u, $otp)
                : admin_totp_confirm($PROVIDERS_FILE, $u, $otp);
            if (!$otpOk) {
                rate_limit_record_failure($PROVIDERS_FILE, $otpBucket, ADMIN_LOGIN_OTP_MAX_FAILURES, $window, $window);
                // The password was right: a security event the administrator must see.
                admin_audit_append(
                    $PROVIDERS_FILE,
                    ["type" => "anonymous", "owner" => $u, "client" => null],
                    "admin.login",
                    "failure",
                    null,
                    "",
                    ["reason" => "invalid_authentication_code", "device" => $deviceDetail]
                );
                json_response(401, $enrolled
                    ? ["error" => "Invalid or already used authentication code."] + $mfaAnswer
                    : [
                        "error" => "Invalid code, or the setup has expired. Sign in again without a code to get a new secret.",
                        "mfa_enrollment_required" => true,
                    ] + $mfaAnswer);
            }
            rate_limit_clear($PROVIDERS_FILE, $otpBucket);
            if (!$enrolled) {
                admin_audit_append(
                    $PROVIDERS_FILE,
                    ["type" => "session", "owner" => $u, "client" => null],
                    "admin.mfa_enrolled",
                    "success",
                    null,
                    "",
                    ["method" => "totp", "during_sign_in" => true]
                );
            }
        }

        foreach ($reserved as [$bucket]) {
            rate_limit_clear($PROVIDERS_FILE, $bucket);
        }
        // Starts the session on demand (sessions are lazy, S15-08), issues a new session id and
        // binds the login to the current users.txt entry and a 12-hour lifetime (S10-04).
        $csrfToken = admin_session_login($u);
        admin_device_cookie_issue($PROVIDERS_FILE, $users, $u);
        admin_audit_append(
            $PROVIDERS_FILE,
            ["type" => "session", "owner" => $u, "client" => null],
            "admin.login",
            "success",
            null,
            "",
            ["device" => $deviceDetail, "mfa" => $mfa]
        );
        $response = ["user" => $u, "csrfToken" => $csrfToken];
        // The legacy per-admin API key is retired (S10-04); legacy_admin_api_key restores it.
        if (config_flag("legacy_admin_api_key", "OIDC_LEGACY_ADMIN_API_KEY")) {
            $response["apiKey"] = ensure_api_key($u, $APIKEYS_FILE);
        }
        json_response(200, $response);
    }

    if ($path === "/api/logout" && $method === "POST") {
        verify_request_csrf($origin, true);
        $loggedOut = current_user();
        if ($loggedOut !== null) {
            admin_audit_append(
                $PROVIDERS_FILE,
                ["type" => "session", "owner" => $loggedOut, "client" => null],
                "admin.logout"
            );
        }
        // Also drops tokens the API docs page may have persisted in this origin's storage.
        if (!headers_sent()) {
            header('Clear-Site-Data: "storage"');
        }
        $_SESSION = [];
        if (ini_get("session.use_cookies") && !headers_sent()) {
            $params = session_get_cookie_params();
            setcookie(session_name(), "", [
                "expires" => time() - 3600,
                "path" => $params["path"] ?: "/",
                "domain" => $params["domain"] ?: "",
                "secure" => (bool) $params["secure"],
                "httponly" => (bool) $params["httponly"],
                "samesite" => $params["samesite"] ?: "Lax",
            ]);
        }
        if (session_status() === PHP_SESSION_ACTIVE) {
            @session_destroy();
        }
        json_response(200, ["ok" => true]);
    }

    // "Sign out everywhere" for administrators (G2a-04): replaces the administrator's session
    // key (admin_sessions_revoke_all()), so every other console session of this administrator
    // ends at its next request; the calling session stays signed in. Admin API clients are not
    // sessions and keep working.
    if ($path === "/api/sessions/revoke" && $method === "POST") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $owner = auth_require_session_only($auth);
        if (!admin_sessions_revoke_all($owner, true)) {
            json_response(500, ["error" => "Other sessions could not be signed out"]);
        }
        admin_audit_append($PROVIDERS_FILE, $auth, "admin.sessions_revoked");
        json_response(200, ["ok" => true]);
    }

    if ($path === "/api/me" && $method === "GET") {
        $u = current_user();
        if (!$u) {
            // No session is started for an anonymous caller (G1c-06): csrf_token() would create
            // and persist one on every request, and /api/login needs no token (it returns one).
            json_response(200, ["user" => null, "csrfToken" => ""]);
        }
        $me = [
            "user" => $u,
            "csrfToken" => csrf_token(),
            "rpId" => $rpId,
            "baseUrl" => $baseUrl,
            // Whether the console shows Blocked Requests (ip_allowlist_admins); the routes check again.
            "can_view_blocked_requests" => ip_allowlist_admin_allowed($u),
        ];
        // apiKey is returned only while legacy_admin_api_key is enabled (S10-04).
        if (config_flag("legacy_admin_api_key", "OIDC_LEGACY_ADMIN_API_KEY")) {
            $me["apiKey"] = ensure_api_key($u, $APIKEYS_FILE);
        }
        json_response(200, $me);
    }

    // ---------- Admin API Clients CRUD (/api/admin-clients*) [Session Admin Only] ----------
    if ($path === "/api/admin-clients") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $owner = auth_require_session_only($auth);

        if ($method === "GET") {
            json_response(200, [
                "clients" => admin_client_list($PROVIDERS_FILE, $owner),
            ]);
        }
        if ($method === "POST") {
            try {
                $created = admin_client_create(
                    $PROVIDERS_FILE,
                    $owner,
                    read_json_body()
                );
            } catch (Throwable $e) {
                api_fail_from_exception($e, "An API client with these identifiers already exists");
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "admin_client.created",
                "success",
                null,
                (string) ($created["client_id"] ?? ""),
                [
                    "id" => $created["id"] ?? null,
                    "name" => $created["name"] ?? null,
                    "provider_scope" => $created["provider_scope"] ?? null,
                    "allowed_provider_ids" => $created["allowed_provider_ids"] ?? [],
                    "can_create_providers" => $created["can_create_providers"] ?? null,
                    "provider_permission" => $created["provider_permission"] ?? null,
                    "user_scope" => $created["user_scope"] ?? null,
                    "can_mint_tokens" => $created["can_mint_tokens"] ?? null,
                    "expires_at" => $created["expires_at"] ?? null,
                ]
            );
            json_response(201, ["client" => $created]);
        }
    }

    if (
        preg_match(
            '#^/api/admin-clients/([a-f0-9\-]+)/rotate-secret$#i',
            $path,
            $m
        ) &&
        $method === "POST"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $owner = auth_require_session_only($auth);
        try {
            $rotated = admin_client_rotate_secret(
                $PROVIDERS_FILE,
                $owner,
                $m[1]
            );
        } catch (Throwable $e) {
            api_fail_from_exception($e);
        }
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "admin_client.secret_rotated",
            "success",
            null,
            (string) ($rotated["client_id"] ?? ""),
            ["id" => $rotated["id"] ?? null]
        );
        json_response(200, ["client" => $rotated]);
    }

    if (preg_match('#^/api/admin-clients/([a-f0-9\-]+)$#i', $path, $m)) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $owner = auth_require_session_only($auth);
        $cid = $m[1];

        if ($method === "GET") {
            $found = admin_client_get($PROVIDERS_FILE, $owner, $cid);
            if (!$found) {
                json_response(404, ["error" => "Admin API client not found"]);
            }
            json_response(200, ["client" => $found]);
        }
        if (in_array($method, ["PUT", "PATCH"], true)) {
            $body = read_json_body();
            try {
                $updated = admin_client_update(
                    $PROVIDERS_FILE,
                    $owner,
                    $cid,
                    $body
                );
            } catch (Throwable $e) {
                api_fail_from_exception($e);
            }
            $changed = array_values(array_intersect(
                array_keys($body),
                [
                    "name", "description", "provider_scope", "allowed_provider_ids",
                    "can_create_providers", "provider_permission", "user_scope",
                    "can_mint_tokens", "status", "expires_in", "expires_at",
                ]
            ));
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                ($updated["status"] ?? "") === "revoked" ? "admin_client.revoked" : "admin_client.updated",
                "success",
                null,
                (string) ($updated["client_id"] ?? ""),
                [
                    "id" => $updated["id"] ?? null,
                    "fields" => $changed,
                    "provider_scope" => $updated["provider_scope"] ?? null,
                    "allowed_provider_ids" => $updated["allowed_provider_ids"] ?? [],
                    "provider_permission" => $updated["provider_permission"] ?? null,
                    "user_scope" => $updated["user_scope"] ?? null,
                    "can_mint_tokens" => $updated["can_mint_tokens"] ?? null,
                    "status" => $updated["status"] ?? null,
                ]
            );
            json_response(200, ["client" => $updated]);
        }
        if ($method === "DELETE") {
            $existing = admin_client_get($PROVIDERS_FILE, $owner, $cid);
            $ok = admin_client_delete($PROVIDERS_FILE, $owner, $cid);
            if (!$ok) {
                json_response(404, ["error" => "Admin API client not found"]);
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "admin_client.deleted",
                "success",
                null,
                (string) ($existing["client_id"] ?? ""),
                ["id" => $cid, "name" => $existing["name"] ?? null]
            );
            json_response(200, ["ok" => true]);
        }
    }

    // ---------- Admin Audit Log (G1a-01) [Session Admin Only] ----------
    if ($path === "/api/admin-audit-logs" && $method === "GET") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $owner = auth_require_session_only($auth);
        $lim = isset($_GET["limit"]) && is_string($_GET["limit"])
            ? max(1, min(500, (int) $_GET["limit"]))
            : 100;
        json_response(200, [
            "logs" => admin_audit_list($PROVIDERS_FILE, $owner, $lim),
        ]);
    }

    // ---------- IP Allowlist & Blocked Requests [Session Admin Only] ----------
    // The operator's IP allowlist (ip_allowlist in config.php or OIDC_IP_ALLOWLIST; read-only here)
    // and the requests it refused (src/ip_allowlist.php, src/blocked_requests.php). Console sessions
    // of the administrators in ip_allowlist_admins (default: all) only.
    if ($path === "/api/ip-allowlist" && $method === "GET") {
        ip_allowlist_require_viewer(require_admin_auth($PROVIDERS_FILE, $origin));
        json_response(200, ip_allowlist_status($CONFIG_DIR));
    }

    if ($path === "/api/ip-allowlist/blocked-requests" && in_array($method, ["GET", "DELETE"], true)) {
        // DELETE: require_login() checks Origin and X-CSRF-Token.
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        ip_allowlist_require_viewer($auth);
        $unavailable = static function (Throwable $e) use ($method): never {
            // Paths and SQLite messages stay in the log.
            error_log($method . " /api/ip-allowlist/blocked-requests: " . $e->getMessage());
            if (headers_sent()) {
                // A CSV download that failed after it started ends short; a JSON error appended
                // to it would only corrupt the file.
                exit();
            }
            header_remove("Content-Disposition"); // the error is not a download
            json_response(503, ["error" => "The blocked-request log is unavailable"]);
        };
        if ($method === "GET") {
            try {
                $filters = blocked_requests_filters($_GET);
            } catch (InvalidArgumentException $e) {
                json_response(400, ["error" => $e->getMessage()]);
            }
            $format = is_string($_GET["format"] ?? null) ? strtolower(trim($_GET["format"])) : "json";
            if ($format !== "json" && $format !== "csv") {
                json_response(400, ["error" => "format must be json or csv"]);
            }
            if ($format === "csv") {
                // The export is audited below even when the browser cancels the download, and the
                // session lock is released first, so a long download does not hold up the console.
                ignore_user_abort(true);
                if (session_status() === PHP_SESSION_ACTIVE) {
                    session_write_close();
                }
                try {
                    $rows = blocked_requests_send_csv($CONFIG_DIR, $filters);
                } catch (RuntimeException $e) {
                    $unavailable($e);
                }
                admin_audit_append($PROVIDERS_FILE, $auth, "ip_allowlist.log_exported", "success", null, "",
                    ["rows" => $rows, "filters" => blocked_requests_filters_public($filters)]);
                exit();
            }
            // limit and cursor: absent or empty (as for the filters) means unset; otherwise digits.
            $rawLimit = $_GET["limit"] ?? "";
            $limit = $rawLimit === ""
                ? 100
                : (is_string($rawLimit) && preg_match('/^\d{1,9}$/D', $rawLimit) === 1 ? (int) $rawLimit : 0);
            if ($limit < 1 || $limit > BLOCKED_REQUESTS_LIST_MAX) {
                json_response(400, ["error" => "limit must be a whole number from 1 to " . BLOCKED_REQUESTS_LIST_MAX]);
            }
            $rawCursor = $_GET["cursor"] ?? "";
            $cursor = null;
            if ($rawCursor !== "") {
                if (!is_string($rawCursor) || preg_match('/^\d{1,18}$/D', $rawCursor) !== 1) {
                    json_response(400, ["error" => "cursor must be the next_cursor of a previous page"]);
                }
                $cursor = (int) $rawCursor;
            }
            try {
                json_response(200, blocked_requests_list($CONFIG_DIR, $filters, $limit, $cursor));
            } catch (RuntimeException $e) {
                $unavailable($e);
            }
        }
        // DELETE {"password": "...", "all": true} or {"password": "...", <at least one filter>}
        $input = read_json_body();
        $all = ($input["all"] ?? false) === true;
        try {
            $filters = blocked_requests_filters($input);
        } catch (InvalidArgumentException $e) {
            json_response(400, ["error" => $e->getMessage()]);
        }
        $hasFilter = !blocked_requests_filters_empty($filters);
        if ($all === $hasFilter) {
            json_response(400, ["error" => "Send \"all\": true or at least one filter (ip, since, until, reason, enforced), not both"]);
        }
        // A borrowed session cannot wipe the record: 403 wrong password, 429 after 5 within 15 minutes.
        api_admin_reauthenticate_or_fail($PROVIDERS_FILE, $USERS_FILE, $auth, $input);
        try {
            $deleted = blocked_requests_purge($CONFIG_DIR, $all ? [] : $filters);
        } catch (RuntimeException $e) {
            $unavailable($e);
        }
        admin_audit_append($PROVIDERS_FILE, $auth, "ip_allowlist.log_purged", "success", null, "", [
            "scope" => $all ? "all" : "filtered",
            "filters" => $all ? [] : blocked_requests_filters_public($filters),
            "deleted" => $deleted,
        ]);
        json_response(200, ["deleted" => $deleted]);
    }

    // ---------- Administrator Authenticator App (TOTP, G2a-07) [Session Admin Only] ----------
    // Once an app is confirmed, every console sign-in of the administrator needs its code
    // (POST /api/login "otp"). Setting one up or removing it needs the current password, and
    // removing an active app also a current code. An operator resets a lost app by deleting
    // the administrator's row from the admin_mfa_totp table.
    if ($path === "/api/admin-mfa" && $method === "GET") {
        $owner = auth_require_session_only(require_admin_auth($PROVIDERS_FILE, $origin));
        json_response(200, [
            "totp" => admin_totp_status($PROVIDERS_FILE, $owner),
            "required" => admin_mfa_required(),
        ]);
    }

    if ($path === "/api/admin-mfa/totp" && in_array($method, ["POST", "DELETE"], true)) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $owner = auth_require_session_only($auth);
        $input = read_json_body();
        api_admin_reauthenticate_or_fail($PROVIDERS_FILE, $USERS_FILE, $auth, $input);
        if ($method === "POST") {
            if (admin_totp_enrolled($PROVIDERS_FILE, $owner)) {
                json_response(409, ["error" => "An authenticator app is already set up; remove it first"]);
            }
            try {
                $setup = admin_totp_begin($PROVIDERS_FILE, $owner, api_admin_totp_issuer($baseUrl));
            } catch (Throwable $e) {
                error_log("POST /api/admin-mfa/totp: setup failed: " . $e->getMessage());
                json_response(500, ["error" => "The authenticator app setup could not be started"]);
            }
            admin_audit_append($PROVIDERS_FILE, $auth, "admin.mfa_setup_started", "success", null, "", ["method" => "totp"]);
            json_response(200, ["totp" => $setup]);
        }
        if (admin_totp_enrolled($PROVIDERS_FILE, $owner)) {
            api_admin_totp_code_or_fail(
                $PROVIDERS_FILE,
                $owner,
                is_scalar($input["otp"] ?? null) ? (string) $input["otp"] : ""
            );
        }
        if (!admin_totp_delete($PROVIDERS_FILE, $owner)) {
            json_response(404, ["error" => "No authenticator app is set up"]);
        }
        admin_audit_append($PROVIDERS_FILE, $auth, "admin.mfa_removed", "success", null, "", ["method" => "totp"]);
        json_response(200, ["ok" => true, "required" => admin_mfa_required()]);
    }

    if ($path === "/api/admin-mfa/totp/confirm" && $method === "POST") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $owner = auth_require_session_only($auth);
        $input = read_json_body();
        api_admin_totp_code_or_fail(
            $PROVIDERS_FILE,
            $owner,
            is_scalar($input["otp"] ?? null) ? (string) $input["otp"] : "",
            true
        );
        admin_audit_append($PROVIDERS_FILE, $auth, "admin.mfa_enrolled", "success", null, "", ["method" => "totp"]);
        json_response(200, ["totp" => admin_totp_status($PROVIDERS_FILE, $owner)]);
    }

    // ---------- Automation Workload JWT Endpoint: POST /api/token ----------
    if ($path === "/api/token" && $method === "POST") {
        // Callers: a console session (cookie + CSRF) or an Admin API client with write access to
        // the provider and the can_mint_tokens capability (G1a-02). The retired per-admin legacy
        // key is accepted only while legacy_admin_api_key is enabled, and only while its owner is
        // still an admin in users.txt (S10-04).
        $legacyEnabled = config_flag("legacy_admin_api_key", "OIDC_LEGACY_ADMIN_API_KEY");
        $legacyKey = get_api_key();
        $isLegacyKey =
            $legacyKey !== null &&
            !str_starts_with($legacyKey, "idp_adm_") &&
            !str_starts_with($legacyKey, "idp_at_");
        $auth = null;
        if ($isLegacyKey && !$legacyEnabled) {
            json_response(401, [
                "error" => "Legacy admin API keys are disabled. Use an Admin API client (idp_adm_...) " .
                    "or a console session; an operator can re-enable legacy keys temporarily with " .
                    "OIDC_LEGACY_ADMIN_API_KEY=1.",
            ]);
        }
        if ($isLegacyKey) {
            $legacyOwner = get_user_by_apikey((string) $legacyKey, $APIKEYS_FILE);
            if ($legacyOwner !== null) {
                if (!admin_account_exists($legacyOwner)) {
                    json_response(401, ["error" => "Missing or invalid API credentials"]);
                }
                $auth = ["type" => "legacy_api_key", "owner" => $legacyOwner, "client" => null];
            }
        }
        if ($auth === null) {
            $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        }
        auth_require_token_minting($auth);
        // Workload tokens are typed "workload+jwt", live at most 24 hours, carry no end-user
        // identity claims and never name the provider's issuer or OIDC clients as audience
        // (G1a-02); legacy_workload_tokens restores the old, looser tokens.
        $legacyWorkload = config_flag("legacy_workload_tokens", "OIDC_LEGACY_WORKLOAD_TOKENS");

        $input = read_json_body();
        $idpId = is_scalar($input["idpId"] ?? null) ? trim((string) $input["idpId"]) : "";
        if ($idpId === "") {
            json_response(400, ["error" => "idpId is required"]);
        }
        $ttlSpec = $input["ttl"] ?? "3600";
        $ttl = api_duration_absent($ttlSpec)
            ? 3600
            : api_duration_or_400($ttlSpec, "ttl", 1, $legacyWorkload ? 365 * 86400 : API_TOKEN_MAX_TTL_SECONDS);

        $audList = normalize_string_list($input["aud"] ?? "");
        $sub = is_scalar($input["sub"] ?? null) ? trim((string) $input["sub"]) : "";
        if (empty($audList) || $sub === "") {
            json_response(400, ["error" => "aud and sub are required"]);
        }

        // The legacy key acts for its owner like a console session; other owners' providers
        // are simply not found.
        $resolveAuth = $auth["type"] === "legacy_api_key"
            ? ["type" => "session", "owner" => $auth["owner"], "client" => null]
            : $auth;
        $provider = api_resolve_provider($resolveAuth, $PROVIDERS_FILE, $idpId, true);

        $iss = $baseUrl . "/" . $provider["idp_id"];
        if (!$legacyWorkload) {
            $refusedAud = api_workload_refused_audiences($PROVIDERS_FILE, $provider, $iss, $audList);
            if ($refusedAud !== []) {
                json_response(400, [
                    "error" => "aud must not be this provider's issuer or the client_id of one of its OIDC clients, " .
                        "so the token cannot pass as one of its ID or access tokens: " .
                        sanitize_label(implode(", ", $refusedAud), 300),
                ]);
            }
        }
        $now = time();
        $claims = [
            "iss" => $iss,
            "aud" => $audList,
            "sub" => $sub,
            "iat" => $now,
            "nbf" => $now,
            "exp" => $now + $ttl,
            "jti" => uuidv4(),
        ];

        // Extra claims never override registered claims or assert an end-user authentication
        // or session (nonce, auth_time, amr, acr, azp, *_hash, sid, cnf, act) or, unless
        // legacy_workload_tokens, an end-user identity or access token (API_TOKEN_IDENTITY_CLAIMS):
        // such names are dropped and reported back (G1a-02).
        $extra = $input["extra"] ?? [];
        $extraNames = [];
        $ignoredClaims = [];
        if (is_array($extra)) {
            foreach ($extra as $k => $v) {
                if (!is_string($k)) {
                    continue;
                }
                if (
                    array_key_exists($k, API_TOKEN_RESERVED_CLAIMS) ||
                    (!$legacyWorkload && array_key_exists($k, API_TOKEN_IDENTITY_CLAIMS))
                ) {
                    $ignoredClaims[] = $k;
                    continue;
                }
                if (is_scalar($v) || is_array($v) || is_null($v)) {
                    $claims[$k] = $v;
                    $extraNames[] = $k;
                }
            }
        }

        if (isset($input["k8s"]) && is_array($input["k8s"])) {
            $ns = is_scalar($input["k8s"]["namespace"] ?? null) ? trim((string) $input["k8s"]["namespace"]) : "";
            $sa = is_scalar($input["k8s"]["serviceAccount"] ?? null) ? trim((string) $input["k8s"]["serviceAccount"]) : "";
            if ($ns !== "" && $sa !== "") {
                $claims["kubernetes.io"] = [
                    "namespace" => $ns,
                    "serviceaccount" => [
                        "name" => $sa,
                        "uid" => uuidv4(),
                    ],
                ];
            }
        }

        // Only this provider is passed, so a rotation never rewrites other providers.
        $providersForSigning = [$provider];
        try {
            $keyToUse = resolve_signing_key_for_provider(
                $PROVIDERS_FILE,
                $providersForSigning,
                $provider,
                $KEYS_DIR
            );
            $jwt = sign_jwt_with_key($keyToUse, $claims, $legacyWorkload ? "JWT" : API_TOKEN_JWT_TYP);
        } catch (Throwable $e) {
            error_log("POST /api/token: signing failed for provider " . (string) $provider["id"] . ": " . $e->getMessage());
            json_response(500, ["error" => "Token signing failed"]);
        }

        // Keeps the signing key in the JWKS until this token expires (S04-03).
        provider_key_record_token_exp(
            $PROVIDERS_FILE,
            (string) $provider["id"],
            (string) ($keyToUse["kid"] ?? ""),
            (int) $claims["exp"]
        );
        // One column of one provider, best effort: never a rewrite of every provider (X4-02).
        try {
            provider_update_fields($PROVIDERS_FILE, (string) $provider["id"], [
                "last_issued_at" => date("c"),
            ]);
        } catch (Throwable $e) {
            error_log("POST /api/token: last_issued_at not updated: " . $e->getMessage());
        }
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "token.minted",
            "success",
            (string) $provider["id"],
            (string) $claims["jti"],
            [
                "jti" => $claims["jti"],
                "sub" => $sub,
                "aud" => $audList,
                "exp" => $claims["exp"],
                "kid" => (string) ($keyToUse["kid"] ?? ""),
                "typ" => $legacyWorkload ? "JWT" : API_TOKEN_JWT_TYP,
                "extra_claims" => $extraNames,
                "ignored_claims" => $ignoredClaims,
                "k8s" => isset($claims["kubernetes.io"]),
            ]
        );

        $accept = $_SERVER["HTTP_ACCEPT"] ?? "";
        $wantPlain =
            (isset($_GET["raw"]) && $_GET["raw"] !== "0") ||
            str_contains($accept, "text/plain") ||
            str_contains($accept, "application/jwt");
        if ($wantPlain) {
            header("Content-Type: text/plain");
            header("Cache-Control: no-store");
            echo $jwt;
            exit();
        }
        $response = [
            "token" => $jwt,
            "iat" => $now,
            "exp" => $now + $ttl,
        ];
        if (!empty($ignoredClaims)) {
            $response["ignored_claims"] = $ignoredClaims;
        }
        json_response(200, $response);
    }

    // ---------- Providers CRUD & Configuration ----------
    // Provider routes read only the caller's own providers (api_resolve_provider()) and write
    // with targeted statements (provider_update_fields(), provider_key_insert(),
    // provider_key_delete(), delete_provider()), never by saving every tenant's providers back
    // (S10-07, X4-02, S06-02).
    if ($path === "/api/providers" && $method === "GET") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $pdo = storage_db($PROVIDERS_FILE);
        $out = [];
        foreach (api_owner_provider_rows($PROVIDERS_FILE, (string) $auth["owner"]) as $row) {
            if (!auth_can_access_provider($auth, (string) $row["id"], false)) {
                continue;
            }
            $p = load_provider_by_id($PROVIDERS_FILE, (string) $row["id"]);
            if ($p !== null) {
                $out[] = format_provider_api_payload($p, $baseUrl, $PROVIDERS_FILE, $pdo);
            }
        }
        json_response(200, ["providers" => $out]);
    }

    if ($path === "/api/providers/check-name" && $method === "GET") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $owner = (string) $auth["owner"];
        $name = isset($_GET["name"]) && is_string($_GET["name"]) ? trim($_GET["name"]) : "";
        // Also true when the provider URL this name produces is taken by any tenant (S10-03).
        // "idpId" is the id a provider created with this name would get.
        $idpId = $name !== "" ? api_new_provider_idp_id($owner, $name) : "";
        $exists = $name !== "" && (
            find_provider_by_name_owner(api_owner_provider_rows($PROVIDERS_FILE, $owner), $owner, $name) !== null ||
            api_idp_id_taken($PROVIDERS_FILE, $idpId)
        );
        json_response(200, ["exists" => $exists, "idpId" => $idpId]);
    }

    if ($path === "/api/providers" && $method === "POST") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        auth_require_create_provider($auth);
        $u = (string) $auth["owner"];

        $input = read_json_body();
        $friendly = is_string($input["friendly"] ?? null) ? trim($input["friendly"]) : "";
        $keyMode = is_string($input["keyMode"] ?? null) ? trim($input["keyMode"]) : "";
        if ($keyMode === "") {
            $keyMode = "generate";
        }
        $alg = is_string($input["alg"] ?? null) ? trim($input["alg"]) : "RS256";
        $keyText = is_string($input["keyText"] ?? null) ? $input["keyText"] : "";

        if ($friendly === "") {
            json_response(400, ["error" => "Friendly name required"]);
        }
        // The name becomes part of the issuer, entity ID and certificate subject (S10-06).
        if (sanitize_label($friendly, 64) !== $friendly) {
            json_response(400, [
                "error" => "Friendly name must be 1 to 64 characters of valid text without control " .
                    "characters, invisible formatting marks or repeated spaces",
            ]);
        }
        if (!in_array($keyMode, ["generate", "paste"], true)) {
            json_response(400, ["error" => "keyMode must be 'generate' or 'paste'"]);
        }
        // An unknown policy is an error, not "flexible" (G1e-02).
        $defaultPolicy = $input["default_auth_policy"] ?? "flexible";
        if (
            !is_string($defaultPolicy) ||
            !in_array($defaultPolicy, ["flexible", "touchid_only", "mfa"], true)
        ) {
            json_response(400, [
                "error" => "default_auth_policy must be one of: flexible, touchid_only, mfa",
            ]);
        }
        $keyTtlSeconds = api_duration_absent($input["keyTtl"] ?? null)
            ? 3600
            : api_duration_or_400($input["keyTtl"], "keyTtl", API_KEY_MIN_TTL_SECONDS);
        $keyRotationLeadTimeSeconds = api_duration_absent($input["keyRotationLeadTime"] ?? null)
            ? 0
            : api_duration_or_400($input["keyRotationLeadTime"], "keyRotationLeadTime");
        api_validate_key_timing_or_400($keyTtlSeconds, $keyRotationLeadTimeSeconds);
        // Unset retention (null) means EXPIRED_KEY_RETENTION or one hour (S04-03).
        $retentionSpec = $input["expiredKeyRetention"] ?? ($input["expired_key_retention"] ?? null);
        $retentionSeconds = api_duration_absent($retentionSpec)
            ? null
            : api_duration_or_400($retentionSpec, "expiredKeyRetention");
        if ($keyMode === "paste") {
            // Whoever holds an imported private key can mint tokens offline (G1a-02).
            auth_require_token_minting($auth);
        }

        if (find_provider_by_name_owner(api_owner_provider_rows($PROVIDERS_FILE, $u), $u, $friendly)) {
            json_response(409, ["error" => "Provider name already exists"]);
        }
        // idp_ids are global and resolved case-insensitively from URLs, so a new one must not
        // equal any tenant's, ignoring case and percent-encoding, and must say unambiguously
        // which owner it belongs to (S10-03, api_new_provider_idp_id()).
        $idpId = api_new_provider_idp_id($u, $friendly);
        if (api_idp_id_taken($PROVIDERS_FILE, $idpId)) {
            json_response(409, ["error" => "A provider with this ID already exists"]);
        }

        try {
            if ($keyMode === "paste") {
                $key = import_private_key_auto($keyText, $KEYS_DIR);
                $alg = $key["alg"];
            } else {
                if ($alg === "") {
                    json_response(400, [
                        "error" => "Algorithm required for key generation",
                    ]);
                }
                $alg = normalize_jwa_alg($alg);
                $key = create_keypair($alg, $KEYS_DIR);
            }
        } catch (Throwable $e) {
            json_response(400, ["error" => "Key error: " . $e->getMessage()]);
        }

        $now = time();
        $k1 = wrap_key_entry($key, $alg, date("c", $now));
        $k1["valid_for_seconds"] = $keyTtlSeconds;
        $k1["expires_at"] = date("c", $now + $keyTtlSeconds);

        $prov = [
            "id" => uuidv4(),
            "owner" => $u,
            "friendly" => $friendly,
            "idp_id" => $idpId,
            "alg" => $alg,
            "default_auth_policy" => $defaultPolicy,
            "created_at" => date("c"),
            "last_issued_at" => null,
            "key_ttl_seconds" => $keyTtlSeconds,
            "expired_key_retention_seconds" => $retentionSeconds,
            "key_rotation_lead_time_seconds" => $keyRotationLeadTimeSeconds,
            "keys" => [$k1],
            "active_kid" => $k1["kid"],
        ];
        // Only the new provider is written; other tenants' rows are never touched (X4-02).
        try {
            save_providers($PROVIDERS_FILE, [$prov]);
        } catch (Throwable $e) {
            api_fail_from_exception($e, "A provider with this ID already exists");
        }
        // A provider without a SAML certificate would break listings and SAML: undo it (S10-06).
        try {
            ensure_provider_saml_cert($PROVIDERS_FILE, $prov);
        } catch (Throwable $e) {
            error_log("POST /api/providers: SAML certificate creation failed: " . $e->getMessage());
            try {
                delete_provider($PROVIDERS_FILE, (string) $prov["id"]);
            } catch (Throwable $cleanupError) {
                error_log("POST /api/providers: cleanup failed: " . $cleanupError->getMessage());
            }
            json_response(500, [
                "error" => "The provider's SAML signing certificate could not be created; the provider was not created",
            ]);
        }

        // If created by a 'selected'-scope API client, automatically grant access to this new provider
        if (($auth["type"] ?? "") === "api_client" && !empty($auth["client"]["id"])) {
            admin_client_grant_provider(
                $PROVIDERS_FILE,
                (string) $auth["client"]["id"],
                $prov["id"]
            );
        }
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "provider.created",
            "success",
            (string) $prov["id"],
            $idpId,
            [
                "friendly" => $friendly,
                "key_mode" => $keyMode,
                "alg" => $alg,
                "kid" => (string) $k1["kid"],
                "default_auth_policy" => $defaultPolicy,
                "key_ttl_seconds" => $keyTtlSeconds,
                "key_rotation_lead_time_seconds" => $keyRotationLeadTimeSeconds,
                "expired_key_retention_seconds" => $retentionSeconds,
            ]
        );

        $pdo = storage_db($PROVIDERS_FILE);
        json_response(
            201,
            format_provider_api_payload(
                load_provider_by_id($PROVIDERS_FILE, (string) $prov["id"]) ?? $prov,
                $baseUrl,
                $PROVIDERS_FILE,
                $pdo
            )
        );
    }

    // Granular & Unified Provider Settings Routes
    if (
        preg_match('#^/api/providers/([^/]+)/policy$#i', $path, $m) &&
        $method === "PATCH"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        $input = read_json_body();
        // A missing or unknown policy is an error; {} no longer saves "flexible" (G1e-02).
        $pol = $input["default_auth_policy"] ?? null;
        if (!is_string($pol) || !in_array($pol, ["flexible", "touchid_only", "mfa"], true)) {
            json_response(400, [
                "error" => "default_auth_policy is required and must be one of: flexible, touchid_only, mfa",
            ]);
        }
        api_update_provider_or_fail($PROVIDERS_FILE, (string) $prov["id"], ["default_auth_policy" => $pol]);
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "provider.policy_changed",
            "success",
            (string) $prov["id"],
            (string) $prov["idp_id"],
            ["from" => $prov["default_auth_policy"] ?? null, "to" => $pol]
        );
        json_response(200, ["ok" => true, "default_auth_policy" => $pol]);
    }

    if (
        preg_match('#^/api/providers/([^/]+)/ttl$#i', $path, $m) &&
        $method === "PATCH"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        $input = read_json_body();
        if (api_duration_absent($input["ttl"] ?? null)) {
            json_response(400, ["error" => "ttl required"]);
        }
        $sec = api_duration_or_400($input["ttl"], "ttl", API_KEY_MIN_TTL_SECONDS);
        api_validate_key_timing_or_400($sec, (int) ($prov["key_rotation_lead_time_seconds"] ?? 0));
        api_update_provider_or_fail($PROVIDERS_FILE, (string) $prov["id"], ["key_ttl_seconds" => $sec]);
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "provider.key_ttl_changed",
            "success",
            (string) $prov["id"],
            (string) $prov["idp_id"],
            ["from" => $prov["key_ttl_seconds"] ?? null, "to" => $sec]
        );
        json_response(200, ["ok" => true, "key_ttl_seconds" => $sec]);
    }

    if (
        preg_match('#^/api/providers/([^/]+)/expired-retention$#i', $path, $m) &&
        $method === "PATCH"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        $input = read_json_body();
        if (api_duration_absent($input["retention"] ?? null)) {
            json_response(400, ["error" => "retention required"]);
        }
        $sec = api_duration_or_400($input["retention"], "retention");
        api_update_provider_or_fail(
            $PROVIDERS_FILE,
            (string) $prov["id"],
            ["expired_key_retention_seconds" => $sec]
        );
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "provider.key_retention_changed",
            "success",
            (string) $prov["id"],
            (string) $prov["idp_id"],
            ["from" => $prov["expired_key_retention_seconds"] ?? null, "to" => $sec]
        );
        json_response(200, [
            "ok" => true,
            "expired_key_retention_seconds" => $sec,
        ]);
    }

    if (
        preg_match('#^/api/providers/([^/]+)/rotation-lead-time$#i', $path, $m) &&
        $method === "PATCH"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        $input = read_json_body();
        if (api_duration_absent($input["leadTime"] ?? null)) {
            json_response(400, ["error" => "leadTime required"]);
        }
        $sec = api_duration_or_400($input["leadTime"], "leadTime");
        // Rotation generates a key every TTL minus lead time; a lead time close to the TTL would
        // generate one on nearly every signing call (S10-07).
        api_validate_rotation_interval_or_400(provider_ttl_seconds($prov), $sec);
        api_update_provider_or_fail(
            $PROVIDERS_FILE,
            (string) $prov["id"],
            ["key_rotation_lead_time_seconds" => $sec]
        );
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "provider.key_lead_time_changed",
            "success",
            (string) $prov["id"],
            (string) $prov["idp_id"],
            ["from" => $prov["key_rotation_lead_time_seconds"] ?? null, "to" => $sec]
        );
        json_response(200, [
            "ok" => true,
            "key_rotation_lead_time_seconds" => $sec,
        ]);
    }

    // Single Provider GET / Unified PUT|PATCH / DELETE
    if (
        preg_match('#^/api/providers/([^/]+)$#i', $path, $m) &&
        strtolower($m[1]) !== "check-name"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $targetKey = rawurldecode($m[1]);

        if ($method === "GET") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $targetKey, false);
            $pdo = storage_db($PROVIDERS_FILE);
            json_response(200, [
                "provider" => format_provider_api_payload(
                    $prov,
                    $baseUrl,
                    $PROVIDERS_FILE,
                    $pdo
                ),
            ]);
        }

        if (in_array($method, ["PUT", "PATCH"], true)) {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $targetKey, true);
            $input = read_json_body();
            $fields = [];

            if (isset($input["default_auth_policy"])) {
                $pol = $input["default_auth_policy"];
                if (!is_string($pol) || !in_array($pol, ["flexible", "touchid_only", "mfa"], true)) {
                    json_response(400, ["error" => "Invalid default_auth_policy"]);
                }
                $fields["default_auth_policy"] = $pol;
            }
            $ttlSpec = $input["key_ttl"] ?? ($input["ttl"] ?? null);
            if (!api_duration_absent($ttlSpec)) {
                $fields["key_ttl_seconds"] = api_duration_or_400($ttlSpec, "key_ttl", API_KEY_MIN_TTL_SECONDS);
            }
            $retSpec =
                $input["expired_key_retention"] ?? ($input["retention"] ?? null);
            if (!api_duration_absent($retSpec)) {
                $fields["expired_key_retention_seconds"] = api_duration_or_400($retSpec, "expired_key_retention");
            }
            $leadSpec =
                $input["key_rotation_lead_time"] ?? ($input["leadTime"] ?? null);
            if (!api_duration_absent($leadSpec)) {
                $fields["key_rotation_lead_time_seconds"] = api_duration_or_400($leadSpec, "key_rotation_lead_time");
            }
            // The TTL and lead time as they will be stored must keep the rotation interval (TTL
            // minus lead time) at API_KEY_MIN_ROTATION_INTERVAL_SECONDS or more (S10-07).
            if (isset($fields["key_ttl_seconds"]) || isset($fields["key_rotation_lead_time_seconds"])) {
                api_validate_rotation_interval_or_400(
                    $fields["key_ttl_seconds"] ?? provider_ttl_seconds($prov),
                    $fields["key_rotation_lead_time_seconds"] ??
                        (int) ($prov["key_rotation_lead_time_seconds"] ?? 0)
                );
            }
            if (
                isset($input["active_kid"]) &&
                is_scalar($input["active_kid"]) &&
                trim((string) $input["active_kid"]) !== ""
            ) {
                $wantKid = trim((string) $input["active_kid"]);
                $wantKey = null;
                foreach ($prov["keys"] ?? [] as $k) {
                    if ((string) ($k["kid"] ?? "") === $wantKid) {
                        $wantKey = $k;
                        break;
                    }
                }
                if ($wantKey === null) {
                    json_response(400, ["error" => "Unknown active_kid: " . sanitize_label($wantKid, 128)]);
                }
                $fields["active_kid"] = $wantKid;
                // The provider alg follows the active key, so the next automatic rotation
                // keeps the algorithm the admin chose (S10-09).
                $fields["alg"] = normalize_jwa_alg((string) ($wantKey["alg"] ?? ($prov["alg"] ?? "RS256")));
            }

            if (!empty($fields)) {
                api_update_provider_or_fail($PROVIDERS_FILE, (string) $prov["id"], $fields);
                admin_audit_append(
                    $PROVIDERS_FILE,
                    $auth,
                    "provider.updated",
                    "success",
                    (string) $prov["id"],
                    (string) $prov["idp_id"],
                    ["changes" => $fields]
                );
            }
            $pdo = storage_db($PROVIDERS_FILE);
            json_response(200, [
                "provider" => format_provider_api_payload(
                    load_provider_by_id($PROVIDERS_FILE, (string) $prov["id"]) ?? $prov,
                    $baseUrl,
                    $PROVIDERS_FILE,
                    $pdo
                ),
            ]);
        }

        if ($method === "DELETE") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $targetKey, true);
            // The provider's SSO audit rows are deleted with it (db.php), so the admin audit row
            // records how many there were (G1a-01).
            $ssoAuditRows = null;
            try {
                $countStmt = storage_db($PROVIDERS_FILE)->prepare(
                    "SELECT COUNT(*) FROM sso_audit_logs WHERE provider_id = :pid"
                );
                $countStmt->execute([":pid" => (string) $prov["id"]]);
                $ssoAuditRows = (int) $countStmt->fetchColumn();
                $countStmt->closeCursor();
            } catch (Throwable $e) {
                error_log("DELETE provider: SSO audit rows not counted: " . $e->getMessage());
            }
            // delete_provider() is the only way to delete a provider (save_providers() never
            // deletes); its dependent rows go with it (X4-02).
            if (!delete_provider($PROVIDERS_FILE, (string) $prov["id"])) {
                json_response(404, ["error" => "Provider not found"]);
            }
            // The provider's SCIM connectors went with it (ON DELETE CASCADE), so the owner may
            // no longer have a password-pushing connector: the recoverable password copies that
            // the policy no longer allows are cleared (S04-08). The provider is already deleted,
            // so a failure here is only logged.
            try {
                vault_purge_unused_password_copies(storage_db($PROVIDERS_FILE), (string) $prov["owner"]);
            } catch (Throwable $e) {
                error_log("DELETE provider: password copies not purged: " . get_class($e) . ": " . $e->getMessage());
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "provider.deleted",
                "success",
                (string) $prov["id"],
                (string) $prov["idp_id"],
                ["friendly" => (string) $prov["friendly"], "sso_audit_rows_deleted" => $ssoAuditRows]
            );
            json_response(200, ["ok" => true]);
        }
    }

    // ---------- Provider Keys (JWKS) Management ----------
    if (preg_match('#^/api/providers/([^/]+)/keys$#i', $path, $m)) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $targetKey = rawurldecode($m[1]);

        if ($method === "GET") {
            $p = api_resolve_provider($auth, $PROVIDERS_FILE, $targetKey, false);
            $keys = array_map(
                fn($k) => [
                    "kid" => $k["kid"],
                    "alg" => $k["alg"],
                    "created_at" => $k["created_at"] ?? null,
                    "expires_at" => $k["expires_at"] ?? null,
                    "valid_for_seconds" => $k["valid_for_seconds"] ?? null,
                ],
                $p["keys"] ?? []
            );
            json_response(200, [
                "keys" => $keys,
                "active_kid" => $p["active_kid"] ?? null,
            ]);
        }

        if ($method === "POST") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $targetKey, true);
            $input = read_json_body();
            $mode = is_string($input["keyMode"] ?? null) ? trim($input["keyMode"]) : "";
            if ($mode === "") {
                $mode = "generate";
            }
            if (!in_array($mode, ["generate", "paste"], true)) {
                json_response(400, ["error" => "keyMode must be 'generate' or 'paste'"]);
            }
            if ($mode === "paste") {
                // Whoever holds an imported private key can mint tokens offline (G1a-02).
                auth_require_token_minting($auth);
            }
            $alg = normalize_jwa_alg(is_string($input["alg"] ?? null) ? $input["alg"] : "RS256");
            $text = is_string($input["keyText"] ?? null) ? $input["keyText"] : "";
            // keyTtl is the lifetime of this key only. The provider TTL, which drives automatic
            // rotation, changes only through the provider settings or when the caller sets
            // applyTtlToProvider (G1e-03).
            $ttlSec = api_duration_absent($input["keyTtl"] ?? null)
                ? max(API_KEY_MIN_TTL_SECONDS, provider_ttl_seconds($prov))
                : api_duration_or_400($input["keyTtl"], "keyTtl", API_KEY_MIN_TTL_SECONDS);
            $applyTtlToProvider = api_bool_or_400($input, "applyTtlToProvider");
            $activate = api_bool_or_400($input, "activate");
            $providerLead = (int) ($prov["key_rotation_lead_time_seconds"] ?? 0);
            if ($applyTtlToProvider) {
                api_validate_key_timing_or_400($ttlSec, $providerLead);
            }
            // Rotation replaces the active key once it is within the lead time of its expiry, so
            // a key activated with a TTL close to the lead time would be replaced by the next
            // signing call (S10-07).
            if ($activate) {
                api_validate_rotation_interval_or_400(
                    $ttlSec,
                    $providerLead,
                    "keyTtl ($ttlSec s) must exceed the provider's key rotation lead time ($providerLead s) by at least " .
                        API_KEY_MIN_ROTATION_INTERVAL_SECONDS . " seconds when activate is true; otherwise automatic " .
                        "rotation would replace the key right after activation"
                );
            }
            // The limit counts the keys still in the JWKS (S10-07): the active key, unexpired
            // keys, and expired keys within their retention or still covering a token they
            // signed. Keys automatic rotation left behind once they have expired do not count,
            // so the limit never blocks a provider in normal use.
            $existingKeys = $prov["keys"] ?? [];
            $publishedKids = api_published_kids($prov);
            $publishedCount = count($publishedKids);
            if ($publishedCount >= API_MAX_KEYS_PER_PROVIDER) {
                json_response(409, [
                    "error" => "This provider already publishes " . $publishedCount . " signing keys (the limit is " .
                        API_MAX_KEYS_PER_PROVIDER . "); delete keys that are no longer needed first",
                ]);
            }
            try {
                if ($mode === "paste") {
                    $mat = import_private_key_auto($text, $KEYS_DIR);
                    $alg = $mat["alg"];
                } else {
                    $mat = create_keypair($alg, $KEYS_DIR);
                }
            } catch (Throwable $e) {
                json_response(400, ["error" => "Key error: " . $e->getMessage()]);
            }
            foreach ($existingKeys as $k) {
                if ((string) ($k["kid"] ?? "") === (string) ($mat["kid"] ?? "")) {
                    json_response(409, ["error" => "This key already exists on the provider"]);
                }
            }
            $entry = wrap_key_entry($mat, $alg, date("c"));
            $entry["valid_for_seconds"] = $ttlSec;
            $entry["expires_at"] = date(
                "c",
                strtotime($entry["valid_from"]) + $ttlSec
            );
            // Keys that have left the JWKS verify nothing any more; they are removed here, as
            // prune-expired would remove them, so keys added through this route cannot pile up
            // in storage once they expire (S10-07). The active key is never removed, and at
            // most API_KEY_PRUNE_BATCH keys go per call, in one transaction. Best effort: a
            // failure is logged and the new key is still added.
            $prunable = array_slice(
                api_unpublished_kids($prov, $publishedKids),
                0,
                API_KEY_PRUNE_BATCH
            );
            $pruned = [];
            if (!empty($prunable)) {
                try {
                    $pruned = storage_write_transaction(
                        storage_db($PROVIDERS_FILE),
                        function (PDO $pdo) use ($PROVIDERS_FILE, $prov, $prunable): array {
                            $done = [];
                            foreach ($prunable as $kid) {
                                if (provider_key_delete($PROVIDERS_FILE, (string) $prov["id"], $kid)) {
                                    $done[] = $kid;
                                }
                            }
                            return $done;
                        }
                    );
                } catch (Throwable $e) {
                    error_log("Adding a provider key: pruning expired keys failed: " . $e->getMessage());
                    $pruned = [];
                }
            }
            if (!empty($pruned)) {
                admin_audit_append(
                    $PROVIDERS_FILE,
                    $auth,
                    "key.pruned",
                    "success",
                    (string) $prov["id"],
                    implode(",", $pruned),
                    ["kids" => $pruned, "automatic" => true]
                );
            }
            try {
                provider_key_insert($PROVIDERS_FILE, (string) $prov["id"], $entry, $activate);
            } catch (Throwable $e) {
                if ($e instanceof InvalidArgumentException && str_contains($e->getMessage(), "already exists")) {
                    json_response(409, ["error" => "This key already exists on the provider"]);
                }
                api_fail_from_exception($e, "This key already exists on the provider");
            }
            if ($applyTtlToProvider) {
                api_update_provider_or_fail($PROVIDERS_FILE, (string) $prov["id"], ["key_ttl_seconds" => $ttlSec]);
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "key.added",
                "success",
                (string) $prov["id"],
                (string) $entry["kid"],
                [
                    "mode" => $mode,
                    "alg" => (string) $entry["alg"],
                    "activated" => $activate,
                    "valid_for_seconds" => $ttlSec,
                    "applied_ttl_to_provider" => $applyTtlToProvider,
                ]
            );
            json_response(201, [
                "kid" => $entry["kid"],
                "alg" => $entry["alg"],
                "active_kid" => $activate ? $entry["kid"] : ($prov["active_kid"] ?? null),
                "created_at" => $entry["created_at"],
                "expires_at" => $entry["expires_at"],
                "valid_for_seconds" => $entry["valid_for_seconds"],
                // kids of keys that had left the JWKS and were removed by this call
                "pruned" => $pruned,
            ]);
        }
    }

    if (
        preg_match(
            '#^/api/providers/([^/]+)/keys/([^/]+)/public$#i',
            $path,
            $m
        ) &&
        $method === "GET"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $p = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), false);
        $kid = rawurldecode($m[2]);

        foreach ($p["keys"] ?? [] as $k) {
            if ((string) ($k["kid"] ?? "") !== $kid) {
                continue;
            }
            $mat = is_array($k["material"] ?? null) ? $k["material"] : [];
            $pub = "";
            if (($mat["type"] ?? "") === "ed25519") {
                $pub = is_string($mat["ed_public"] ?? null) ? $mat["ed_public"] : "";
            } elseif ($mat !== []) {
                // Only stored PEM text ever reaches OpenSSL (S10-08).
                try {
                    $pub = (string) (signing_key_pkey_details($mat)["key"] ?? "");
                } catch (Throwable $e) {
                    $pub = "";
                }
            }
            if ($pub !== "") {
                json_response(200, ["public_key" => $pub]);
            }
            json_response(404, ["error" => "Public key not found"]);
        }
        json_response(404, ["error" => "Key not found"]);
    }

    if (
        preg_match('#^/api/providers/([^/]+)/active-key$#i', $path, $m) &&
        $method === "PATCH"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        $input = read_json_body();
        $kid = is_scalar($input["kid"] ?? null) ? (string) $input["kid"] : "";
        if ($kid === "") {
            json_response(400, ["error" => "kid required"]);
        }
        $newKey = null;
        foreach ($prov["keys"] ?? [] as $k) {
            if ((string) ($k["kid"] ?? "") === $kid) {
                $newKey = $k;
                break;
            }
        }
        if ($newKey === null) {
            json_response(400, ["error" => "unknown kid"]);
        }
        // The provider alg follows the active key (S10-09).
        $newAlg = normalize_jwa_alg((string) ($newKey["alg"] ?? ($prov["alg"] ?? "RS256")));
        api_update_provider_or_fail(
            $PROVIDERS_FILE,
            (string) $prov["id"],
            ["active_kid" => $kid, "alg" => $newAlg]
        );
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "key.activated",
            "success",
            (string) $prov["id"],
            $kid,
            ["previous_kid" => $prov["active_kid"] ?? null, "alg" => $newAlg]
        );
        json_response(200, ["ok" => true, "active_kid" => $kid, "alg" => $newAlg]);
    }

    if (
        preg_match(
            '#^/api/providers/([^/]+)/keys/bulk-delete$#i',
            $path,
            $m
        ) &&
        $method === "POST"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);

        $body = read_json_body();
        if (!isset($body["kids"]) || !is_array($body["kids"])) {
            json_response(400, ["error" => "Missing kids"]);
        }
        $kids = array_values(
            array_unique(
                array_filter(
                    array_map(fn($s) => is_scalar($s) ? (string) $s : "", $body["kids"]),
                    fn($s) => $s !== ""
                )
            )
        );
        if (empty($kids)) {
            json_response(400, ["error" => "No kids provided"]);
        }
        $active = (string) ($prov["active_kid"] ?? "");
        if (in_array($active, $kids, true)) {
            json_response(400, ["error" => "Cannot delete the active key"]);
        }
        $keys = $prov["keys"] ?? [];
        $known = [];
        foreach ($keys as $k) {
            $kid = (string) ($k["kid"] ?? "");
            if (in_array($kid, $kids, true)) {
                $known[] = $kid;
            }
        }
        if (count($keys) - count($known) < 1) {
            json_response(400, ["error" => "Cannot delete the last key"]);
        }
        // provider_key_delete() re-checks the active key and key count in the same statement.
        $deleted = [];
        foreach ($known as $kid) {
            if (provider_key_delete($PROVIDERS_FILE, (string) $prov["id"], $kid)) {
                $deleted[] = $kid;
            }
        }
        if (!empty($deleted)) {
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "key.deleted",
                "success",
                (string) $prov["id"],
                implode(",", $deleted),
                ["kids" => $deleted]
            );
        }
        json_response(200, [
            "ok" => true,
            "deleted" => $deleted,
            "remaining_count" => count($keys) - count($deleted),
        ]);
    }

    if (
        preg_match(
            '#^/api/providers/([^/]+)/keys/prune-expired$#i',
            $path,
            $m
        ) &&
        $method === "POST"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);

        // A key is pruned only once it has left the JWKS: past its expiry plus retention and
        // past the expiry of every token it signed (max_token_exp, S04-03). The JWKS is
        // computed once, so a provider with many leftover keys is not scanned once per key.
        $keys = $prov["keys"] ?? [];
        $toDelete = api_unpublished_kids($prov);
        $deleted = [];
        foreach ($toDelete as $kid) {
            if (provider_key_delete($PROVIDERS_FILE, (string) $prov["id"], $kid)) {
                $deleted[] = $kid;
            }
        }
        if (!empty($deleted)) {
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "key.pruned",
                "success",
                (string) $prov["id"],
                implode(",", $deleted),
                ["kids" => $deleted]
            );
        }
        json_response(200, [
            "ok" => true,
            "deleted" => $deleted,
            "remaining_count" => count($keys) - count($deleted),
        ]);
    }

    if (
        preg_match('#^/api/providers/([^/]+)/keys/([^/]+)$#i', $path, $m) &&
        $method === "DELETE"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        $kid = rawurldecode($m[2]);

        if ((string) ($prov["active_kid"] ?? "") === $kid) {
            json_response(400, ["error" => "Cannot delete the active key"]);
        }
        $keys = $prov["keys"] ?? [];
        $found = false;
        foreach ($keys as $k) {
            if ((string) ($k["kid"] ?? "") === $kid) {
                $found = true;
                break;
            }
        }
        if (!$found) {
            json_response(404, ["error" => "Key not found"]);
        }
        if (count($keys) <= 1) {
            json_response(400, ["error" => "Cannot delete the last key"]);
        }
        if (!provider_key_delete($PROVIDERS_FILE, (string) $prov["id"], $kid)) {
            json_response(409, [
                "error" => "The key was not deleted: it is now the provider's active or last key",
            ]);
        }
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "key.deleted",
            "success",
            (string) $prov["id"],
            $kid,
            ["kids" => [$kid]]
        );
        json_response(200, [
            "ok" => true,
            "deleted" => [$kid],
            "remaining_count" => count($keys) - 1,
        ]);
    }

    // ---------- Shared Per-Admin Directory Users & Touch ID Management ----------
    if ($path === "/api/users" && $method === "GET") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        auth_require_user_directory($auth, false);
        $u = $auth["owner"];
        json_response(200, [
            "users" => directory_list_users($PROVIDERS_FILE, $u),
            "custom_attribute_schema" => directory_discover_custom_attribute_schema(
                $PROVIDERS_FILE,
                $u
            ),
        ]);
    }

    if ($path === "/api/users" && $method === "POST") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        auth_require_user_directory($auth, true);
        $body = api_directory_user_input(read_json_body());
        // An address entered by an administrator counts as verified unless the request says
        // otherwise (S03-06).
        if (!array_key_exists("email_verified", $body)) {
            $body["email_verified"] = true;
        }
        try {
            $created = directory_create_user(
                $PROVIDERS_FILE,
                $auth["owner"],
                $body
            );
        } catch (Throwable $e) {
            api_fail_from_exception($e, "A user with this username or email already exists");
        }
        unset($created["_password_hash"]);
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "user.created",
            "success",
            null,
            (string) ($created["id"] ?? ""),
            ["username" => $created["username"] ?? null, "status" => $created["status"] ?? null]
        );
        json_response(201, ["user" => $created]);
    }

    if (preg_match('#^/api/users/([a-f0-9\-]+)$#i', $path, $m)) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $uid = $m[1];

        if ($method === "GET") {
            auth_require_user_directory($auth, false);
            $user = directory_get_user_by_id($PROVIDERS_FILE, $uid, $auth["owner"]);
            if (!$user) {
                json_response(404, ["error" => "User not found"]);
            }
            unset($user["_password_hash"]);
            json_response(200, ["user" => $user]);
        }
        if (in_array($method, ["PUT", "PATCH"], true)) {
            auth_require_user_directory($auth, true);
            $body = api_directory_user_input(read_json_body());
            // An administrator's change of address counts as verified unless the request says
            // otherwise (S03-06); directory_update_user() alone would reset it to unverified.
            if (array_key_exists("email", $body) && !array_key_exists("email_verified", $body)) {
                $current = directory_get_user_by_id($PROVIDERS_FILE, $uid, $auth["owner"]);
                if (
                    $current !== null &&
                    is_scalar($body["email"]) &&
                    strtolower(trim((string) $body["email"])) !== strtolower((string) ($current["email"] ?? ""))
                ) {
                    $body["email_verified"] = true;
                }
            }
            try {
                $updated = directory_update_user(
                    $PROVIDERS_FILE,
                    $auth["owner"],
                    $uid,
                    $body
                );
            } catch (Throwable $e) {
                api_fail_from_exception($e, "Another user already uses this username or email");
            }
            unset($updated["_password_hash"]);
            // groups_base and attributes_base only tell what "groups" and "attributes" were
            // derived from (S12-14); they are not field changes.
            $changed = array_values(array_filter(
                array_keys($body),
                fn($k) => is_string($k) && !in_array($k, ["password", "groups_base", "attributes_base"], true)
            ));
            if (array_key_exists("password", $body) || !empty($body["clear_password"])) {
                $changed[] = "password";
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "user.updated",
                "success",
                null,
                $uid,
                ["fields" => array_values(array_unique($changed))]
            );
            json_response(200, ["user" => $updated]);
        }
        if ($method === "DELETE") {
            auth_require_user_directory($auth, true);
            $ok = directory_delete_user($PROVIDERS_FILE, $auth["owner"], $uid);
            if (!$ok) {
                json_response(404, ["error" => "User not found"]);
            }
            admin_audit_append($PROVIDERS_FILE, $auth, "user.deleted", "success", null, $uid);
            json_response(200, ["ok" => true]);
        }
    }

    if (
        preg_match(
            '#^/api/users/([a-f0-9\-]+)/enrollment-link$#i',
            $path,
            $m
        ) &&
        $method === "POST"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        auth_require_user_directory($auth, true);
        try {
            $tok = directory_create_enrollment_token(
                $PROVIDERS_FILE,
                $auth["owner"],
                $m[1],
                86400
            );
        } catch (Throwable $e) {
            api_fail_from_exception($e);
        }
        // The token itself is a credential and is never logged.
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "user.enrollment_link_created",
            "success",
            null,
            $m[1],
            ["valid_for_seconds" => 86400]
        );
        json_response(200, [
            "token" => $tok,
            "enrollment_url" =>
                $baseUrl . "/enroll?token=" . rawurlencode($tok),
        ]);
    }

    // 1-Click Browser Admin Touch ID Enrollment for any Test User on This Mac (Interactive Session)
    if (
        preg_match(
            '#^/api/users/([a-f0-9\-]+)/webauthn/register-options$#i',
            $path,
            $m
        ) &&
        $method === "POST"
    ) {
        $u = require_login($origin);
        $targetUser = directory_get_user_by_id($PROVIDERS_FILE, $m[1], $u);
        if (!$targetUser) {
            json_response(404, ["error" => "User not found"]);
        }
        try {
            $reg = webauthn_build_registration_options(
                $PROVIDERS_FILE,
                $targetUser,
                $rpId,
                "Identity Cloud (" . $u . ")"
            );
            $_SESSION["admin_webauthn_reg"] = [
                "user_id" => $targetUser["id"],
                "challenge" => $reg["challenge"],
                "expires_at" => time() + 300,
            ];
            json_response(200, ["publicKey" => $reg["publicKey"]]);
        } catch (Throwable $e) {
            api_fail_from_exception($e);
        }
    }

    if (
        preg_match(
            '#^/api/users/([a-f0-9\-]+)/webauthn/register-verify$#i',
            $path,
            $m
        ) &&
        $method === "POST"
    ) {
        $u = require_login($origin);
        $targetUser = directory_get_user_by_id($PROVIDERS_FILE, $m[1], $u);
        if (!$targetUser) {
            json_response(404, ["error" => "User not found"]);
        }
        $pending = $_SESSION["admin_webauthn_reg"] ?? null;
        unset($_SESSION["admin_webauthn_reg"]);
        if (
            !is_array($pending) ||
            ($pending["user_id"] ?? "") !== $targetUser["id"] ||
            (int) ($pending["expires_at"] ?? 0) < time()
        ) {
            json_response(400, [
                "error" => "Registration challenge expired; please try again",
            ]);
        }
        $body = read_json_body();
        try {
            $stored = webauthn_verify_and_store_registration(
                $PROVIDERS_FILE,
                $targetUser,
                (string) $pending["challenge"],
                $origin,
                $rpId,
                $body["credential"] ?? [],
                is_scalar($body["friendlyName"] ?? null) ? (string) $body["friendlyName"] : "MacBook Touch ID"
            );
        } catch (Throwable $e) {
            api_fail_from_exception($e, "This passkey is already registered");
        }
        admin_audit_append(
            $PROVIDERS_FILE,
            ["type" => "session", "owner" => $u, "client" => null],
            "user.passkey_registered",
            "success",
            null,
            (string) $targetUser["id"],
            ["credential_id" => is_array($stored) ? ($stored["id"] ?? null) : null, "rp_id" => $rpId]
        );
        json_response(201, ["credential" => $stored]);
    }

    // Signs a directory user out everywhere without suspending or deleting the user (G2a-06):
    // every SSO session with all providers of the owner, the user's OIDC access and refresh
    // tokens (offline_access grants included) and unredeemed authorization codes end in one
    // write transaction (directory_revoke_user_access()).
    if (preg_match('#^/api/users/([a-f0-9\-]+)/sessions/revoke$#i', $path, $m) && $method === "POST") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        auth_require_user_directory($auth, true);
        $target = directory_get_user_by_id($PROVIDERS_FILE, $m[1], $auth["owner"]);
        if (!$target) {
            json_response(404, ["error" => "User not found"]);
        }
        $targetId = (string) $target["id"];
        try {
            storage_write_transaction(
                storage_db($PROVIDERS_FILE),
                static function (PDO $pdo) use ($targetId): void {
                    directory_revoke_user_access($pdo, $targetId);
                }
            );
        } catch (Throwable $e) {
            api_fail_from_exception($e);
        }
        admin_audit_append($PROVIDERS_FILE, $auth, "user.sessions_revoked", "success", null, $targetId);
        json_response(200, ["ok" => true]);
    }

    if (
        preg_match('#^/api/webauthn/credentials/([^/]+)$#', $path, $m) &&
        $method === "DELETE"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        auth_require_user_directory($auth, true);
        $credId = rawurldecode($m[1]);
        $ok = webauthn_delete_credential($PROVIDERS_FILE, $auth["owner"], $credId);
        if (!$ok) {
            json_response(404, ["error" => "Credential not found"]);
        }
        admin_audit_append($PROVIDERS_FILE, $auth, "user.passkey_deleted", "success", null, $credId);
        json_response(200, ["ok" => true]);
    }

    // ---------- OIDC Clients CRUD ----------
    // Storage errors are never echoed: a duplicate client_id answers 409 (S03-14). Secrets
    // are never written to the audit log, only client ids.
    if (preg_match('#^/api/providers/([^/]+)/oidc-clients$#i', $path, $m)) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $provKey = rawurldecode($m[1]);

        if ($method === "GET") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $provKey, false);
            json_response(200, [
                "clients" => oidc_list_clients(
                    $PROVIDERS_FILE,
                    $prov["id"]
                ),
            ]);
        }
        if ($method === "POST") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $provKey, true);
            $body = read_json_body();
            api_require_minting_for_client_credentials($auth, $body);
            try {
                $client = oidc_save_client(
                    $PROVIDERS_FILE,
                    $prov["id"],
                    $body
                );
            } catch (Throwable $e) {
                api_fail_from_exception($e, "client_id already in use on this provider");
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "oidc_client.created",
                "success",
                (string) $prov["id"],
                (string) ($client["client_id"] ?? ""),
                ["id" => $client["id"] ?? null, "name" => $client["name"] ?? null]
            );
            json_response(201, ["client" => $client]);
        }
    }

    if (
        preg_match(
            '#^/api/providers/([^/]+)/oidc-clients/([^/]+)/rotate-secret$#i',
            $path,
            $m
        ) &&
        $method === "POST"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        $existingClient = oidc_resolve_client(
            $PROVIDERS_FILE,
            $prov["id"],
            rawurldecode($m[2])
        );
        if (!$existingClient) {
            json_response(404, ["error" => "OIDC client not found"]);
        }
        api_require_minting_for_client_credentials($auth, $existingClient);
        try {
            $rotated = oidc_save_client(
                $PROVIDERS_FILE,
                $prov["id"],
                ["rotate_secret" => true],
                $existingClient["id"]
            );
        } catch (Throwable $e) {
            api_fail_from_exception($e, "client_id already in use on this provider");
        }
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "oidc_client.secret_rotated",
            "success",
            (string) $prov["id"],
            (string) ($existingClient["client_id"] ?? ""),
            ["id" => $existingClient["id"] ?? null]
        );
        json_response(200, ["client" => $rotated]);
    }

    if (
        preg_match(
            '#^/api/providers/([^/]+)/oidc-clients/([^/]+)$#i',
            $path,
            $m
        )
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $provKey = rawurldecode($m[1]);
        $clientKey = rawurldecode($m[2]);

        if ($method === "GET") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $provKey, false);
            $found = oidc_resolve_client(
                $PROVIDERS_FILE,
                $prov["id"],
                $clientKey
            );
            if (!$found) {
                json_response(404, ["error" => "OIDC client not found"]);
            }
            json_response(200, ["client" => $found]);
        }

        if (in_array($method, ["PUT", "PATCH"], true)) {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $provKey, true);
            $found = oidc_resolve_client(
                $PROVIDERS_FILE,
                $prov["id"],
                $clientKey
            );
            if (!$found) {
                json_response(404, ["error" => "OIDC client not found"]);
            }
            $body = read_json_body();
            // Checked on the client as the update would store it (oidc_save_client() merges
            // the request over the stored client the same way).
            api_require_minting_for_client_credentials($auth, array_merge($found, $body));
            try {
                $client = oidc_save_client(
                    $PROVIDERS_FILE,
                    $prov["id"],
                    $body,
                    $found["id"]
                );
            } catch (Throwable $e) {
                api_fail_from_exception($e, "client_id already in use on this provider");
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                !empty($body["rotate_secret"]) ? "oidc_client.secret_rotated" : "oidc_client.updated",
                "success",
                (string) $prov["id"],
                (string) ($client["client_id"] ?? ""),
                [
                    "id" => $found["id"] ?? null,
                    "fields" => array_values(array_filter(
                        array_keys($body),
                        fn($k) => is_string($k) && $k !== "client_secret"
                    )),
                ]
            );
            json_response(200, ["client" => $client]);
        }

        if ($method === "DELETE") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $provKey, true);
            $found = oidc_resolve_client(
                $PROVIDERS_FILE,
                $prov["id"],
                $clientKey
            );
            if (!$found) {
                json_response(404, ["error" => "OIDC client not found"]);
            }
            oidc_delete_client(
                $PROVIDERS_FILE,
                $prov["id"],
                $found["id"]
            );
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "oidc_client.deleted",
                "success",
                (string) $prov["id"],
                (string) ($found["client_id"] ?? ""),
                ["id" => $found["id"] ?? null, "name" => $found["name"] ?? null]
            );
            json_response(200, ["ok" => true]);
        }
    }

    // ---------- SAML 2.0 Apps & Metadata Import/Export APIs ----------
    if ($path === "/api/saml/parse-sp-metadata" && $method === "POST") {
        require_admin_auth($PROVIDERS_FILE, $origin);
        $body = read_json_body();
        $xml = is_string($body["xml"] ?? null) ? $body["xml"] : "";
        try {
            $parsed = saml_parse_sp_metadata($xml);
        } catch (Throwable $e) {
            api_fail_from_exception($e);
        }
        json_response(200, ["parsed" => $parsed]);
    }

    if (preg_match('#^/api/providers/([^/]+)/saml-apps$#i', $path, $m)) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $provKey = rawurldecode($m[1]);

        if ($method === "GET") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $provKey, false);
            json_response(200, [
                "apps" => saml_list_apps(
                    $PROVIDERS_FILE,
                    $prov["id"]
                ),
            ]);
        }
        if ($method === "POST") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $provKey, true);
            try {
                $app = saml_save_app(
                    $PROVIDERS_FILE,
                    $prov["id"],
                    read_json_body()
                );
            } catch (Throwable $e) {
                api_fail_from_exception($e, "A SAML application with this entity ID already exists on this provider");
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "saml_app.created",
                "success",
                (string) $prov["id"],
                (string) ($app["id"] ?? ""),
                ["name" => $app["name"] ?? null, "sp_entity_id" => $app["sp_entity_id"] ?? null]
            );
            json_response(201, ["app" => $app]);
        }
    }

    if (
        preg_match(
            '#^/api/providers/([^/]+)/saml-apps/([a-f0-9\-]+)$#i',
            $path,
            $m
        )
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $provKey = rawurldecode($m[1]);
        $appId = $m[2];

        if ($method === "GET") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $provKey, false);
            $app = saml_get_app(
                $PROVIDERS_FILE,
                $prov["id"],
                $appId
            );
            if (!$app) {
                json_response(404, ["error" => "SAML app not found"]);
            }
            json_response(200, ["app" => $app]);
        }
        if (in_array($method, ["PUT", "PATCH"], true)) {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $provKey, true);
            $body = read_json_body();
            try {
                $app = saml_save_app(
                    $PROVIDERS_FILE,
                    $prov["id"],
                    $body,
                    $appId
                );
            } catch (Throwable $e) {
                api_fail_from_exception($e, "A SAML application with this entity ID already exists on this provider");
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "saml_app.updated",
                "success",
                (string) $prov["id"],
                $appId,
                [
                    "sp_entity_id" => $app["sp_entity_id"] ?? null,
                    "fields" => array_values(array_filter(array_keys($body), "is_string")),
                ]
            );
            json_response(200, ["app" => $app]);
        }
        if ($method === "DELETE") {
            $prov = api_resolve_provider($auth, $PROVIDERS_FILE, $provKey, true);
            $ok = saml_delete_app(
                $PROVIDERS_FILE,
                $prov["id"],
                $appId
            );
            if (!$ok) {
                json_response(404, ["error" => "SAML app not found"]);
            }
            admin_audit_append($PROVIDERS_FILE, $auth, "saml_app.deleted", "success", (string) $prov["id"], $appId);
            json_response(200, ["ok" => true]);
        }
    }

    if (
        preg_match('#^/api/providers/([^/]+)/saml-certs$#i', $path, $m) &&
        $method === "GET"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), false);
        try {
            $activeCert = ensure_provider_saml_cert($PROVIDERS_FILE, $prov);
        } catch (Throwable $e) {
            error_log("GET saml-certs: SAML certificate unavailable: " . $e->getMessage());
            json_response(500, ["error" => "The provider's SAML signing certificate is unavailable"]);
        }
        // The metadata publishes the staged and recently retired certificates too, like the
        // public metadata endpoint, so SPs can roll over (G1a-04).
        $metadataXml = saml_build_idp_metadata(
            $prov,
            $baseUrl,
            $activeCert,
            false,
            list_published_provider_saml_certs($PROVIDERS_FILE, (string) $prov["id"])
        );
        $issuer = $baseUrl . "/" . $prov["idp_id"];
        json_response(200, [
            "active_cert" => [
                "id" => $activeCert["id"],
                "kid" => $activeCert["kid"],
                "cert_pem" => $activeCert["cert_pem"],
                "fingerprint_sha256" => $activeCert["fingerprint_sha256"],
                "created_at" => $activeCert["created_at"],
                "expires_at" => $activeCert["expires_at"],
                // Expiry status, as in certs[] (G1a-04): an expired active certificate keeps
                // signing, so the console warns about it instead.
                "expired" => $activeCert["expired"] ?? false,
                "expires_in_days" => $activeCert["expires_in_days"] ?? null,
                "expires_soon" => $activeCert["expires_soon"] ?? false,
            ],
            // Every certificate, each with its state (active, next or retired) and retired_at.
            "certs" => list_provider_saml_certs($PROVIDERS_FILE, $prov["id"]),
            "entity_id" => $issuer,
            "metadata_url" => $issuer . "/saml/metadata",
            "metadata_download_url" => $issuer . "/saml/metadata?download=1",
            "sso_url" => $issuer . "/saml/sso",
            "slo_url" => $issuer . "/saml/slo",
            "cert_download_url" => $issuer . "/saml/cert.pem?download=1",
            "metadata_xml" => $metadataXml,
        ]);
    }

    if (
        preg_match('#^/api/providers/([^/]+)/saml-certs/rotate$#i', $path, $m) &&
        $method === "POST"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        $body = read_json_body(false);
        $days = 3650;
        if (array_key_exists("valid_days", $body) && $body["valid_days"] !== null) {
            $rawDays = $body["valid_days"];
            if (
                !(is_int($rawDays) || (is_string($rawDays) && preg_match('/^\d{1,5}$/D', $rawDays) === 1)) ||
                (int) $rawDays < 30 ||
                (int) $rawDays > 3650
            ) {
                json_response(400, ["error" => "valid_days must be a whole number from 30 to 3650"]);
            }
            $days = (int) $rawDays;
        }
        // By default the new certificate is staged as "next": it is published in the metadata
        // but signs nothing until it is activated, so SPs can pick it up first. "activate": true
        // switches at once (the previous certificate stays published while retired) (G1a-04).
        // Only a real boolean activates; a value such as "false" answers 400 (G1e-02).
        $activate = api_bool_or_400($body, "activate");
        try {
            $newCert = rotate_provider_saml_cert(
                $PROVIDERS_FILE,
                $prov,
                $days,
                $activate
            );
        } catch (Throwable $e) {
            error_log("SAML certificate rotation failed: " . $e->getMessage());
            json_response(500, ["error" => "The SAML certificate could not be created"]);
        }
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "saml_cert.rotated",
            "success",
            (string) $prov["id"],
            (string) ($newCert["id"] ?? ""),
            [
                "kid" => $newCert["kid"] ?? null,
                "fingerprint_sha256" => $newCert["fingerprint_sha256"] ?? null,
                "state" => $newCert["state"] ?? null,
                "valid_days" => $days,
            ]
        );
        json_response(201, ["cert" => $newCert]);
    }

    if (
        preg_match('#^/api/providers/([^/]+)/saml-certs/([a-f0-9\-]+)/activate$#i', $path, $m) &&
        $method === "POST"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        $certId = strtolower($m[2]);
        try {
            $activated = activate_provider_saml_cert($PROVIDERS_FILE, $prov, $certId);
        } catch (InvalidArgumentException $e) {
            $code = $e->getMessage() === "SAML certificate not found" ? 404 : 400;
            json_response($code, ["error" => $e->getMessage()]);
        } catch (Throwable $e) {
            api_fail_from_exception($e);
        }
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "saml_cert.activated",
            "success",
            (string) $prov["id"],
            $certId,
            ["kid" => $activated["kid"] ?? null, "fingerprint_sha256" => $activated["fingerprint_sha256"] ?? null]
        );
        json_response(200, ["cert" => $activated]);
    }

    if (
        preg_match('#^/api/providers/([^/]+)/saml-certs/([a-f0-9\-]+)$#i', $path, $m) &&
        $method === "DELETE"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        $certId = strtolower($m[2]);
        // Removes a staged or retired certificate from the metadata at once, for example after
        // a key compromise (G1a-04). The active certificate cannot be deleted.
        try {
            $deleted = delete_provider_saml_cert($PROVIDERS_FILE, $prov, $certId);
        } catch (InvalidArgumentException $e) {
            json_response(400, ["error" => $e->getMessage()]);
        } catch (Throwable $e) {
            api_fail_from_exception($e);
        }
        if (!$deleted) {
            json_response(404, ["error" => "SAML certificate not found"]);
        }
        admin_audit_append($PROVIDERS_FILE, $auth, "saml_cert.deleted", "success", (string) $prov["id"], $certId);
        json_response(200, ["ok" => true]);
    }

    // ---------- Shared Directory Groups (/api/groups) ----------
    if ($path === "/api/groups" && $method === "GET") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        auth_require_user_directory($auth, false);
        json_response(200, [
            "groups" => directory_list_groups($PROVIDERS_FILE, $auth["owner"]),
        ]);
    }

    if ($path === "/api/groups" && $method === "POST") {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        auth_require_user_directory($auth, true);
        $body = read_json_body();
        try {
            $group = directory_create_group(
                $PROVIDERS_FILE,
                $auth["owner"],
                (string) ($body["display_name"] ?? ($body["displayName"] ?? "")),
                (string) ($body["external_id"] ?? ($body["externalId"] ?? "")),
                is_array($body["member_ids"] ?? null) ? $body["member_ids"] : []
            );
        } catch (Throwable $e) {
            api_fail_from_exception($e, "A group with this name already exists");
        }
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "group.created",
            "success",
            null,
            (string) ($group["id"] ?? ""),
            ["display_name" => $group["display_name"] ?? ($group["displayName"] ?? null)]
        );
        json_response(201, ["group" => $group]);
    }

    if (preg_match('#^/api/groups/([a-f0-9\-]+)$#i', $path, $m)) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $gid = $m[1];
        if ($method === "GET") {
            auth_require_user_directory($auth, false);
            $group = directory_get_group_by_id($PROVIDERS_FILE, $auth["owner"], $gid);
            if (!$group) {
                json_response(404, ["error" => "Group not found"]);
            }
            json_response(200, ["group" => $group]);
        }
        if (in_array($method, ["PUT", "PATCH"], true)) {
            auth_require_user_directory($auth, true);
            $body = read_json_body();
            // base_member_ids: the member list that member_ids was derived from (a loaded copy
            // of the group that the client edited). Then only the members added or removed
            // relative to it are applied, so membership changes made meanwhile by others are
            // kept (S12-14); without it, member_ids replaces the members.
            $baseMids = $body["base_member_ids"] ?? null;
            if ($baseMids !== null && !is_array($baseMids)) {
                json_response(400, ["error" => "base_member_ids must be an array of user ids"]);
            }
            try {
                $dn = array_key_exists("display_name", $body)
                    ? (string) $body["display_name"]
                    : (array_key_exists("displayName", $body)
                        ? (string) $body["displayName"]
                        : null);
                $ext = array_key_exists("external_id", $body)
                    ? (string) $body["external_id"]
                    : (array_key_exists("externalId", $body)
                        ? (string) $body["externalId"]
                        : null);
                $mids = is_array($body["member_ids"] ?? null) ? $body["member_ids"] : null;
                $updated = directory_update_group(
                    $PROVIDERS_FILE,
                    $auth["owner"],
                    $gid,
                    $dn,
                    $ext,
                    $mids,
                    false,
                    $baseMids
                );
            } catch (Throwable $e) {
                api_fail_from_exception($e, "A group with this name already exists");
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "group.updated",
                "success",
                null,
                $gid,
                [
                    "fields" => array_values(array_filter(
                        array_keys($body),
                        fn($k) => is_string($k) && $k !== "base_member_ids"
                    )),
                ]
            );
            json_response(200, ["group" => $updated]);
        }
        if ($method === "DELETE") {
            auth_require_user_directory($auth, true);
            if (!directory_delete_group($PROVIDERS_FILE, $auth["owner"], $gid)) {
                json_response(404, ["error" => "Group not found"]);
            }
            admin_audit_append($PROVIDERS_FILE, $auth, "group.deleted", "success", null, $gid);
            json_response(200, ["ok" => true]);
        }
    }

    // ---------- SCIM 2.0 Server Tokens & Outbound Push Connectors ----------
    // A SCIM token or connector reads or writes the owner's whole directory, so API clients
    // need user_scope (read to list, write to create, change, delete, test or sync), on top of
    // provider access (S10-01). Console sessions are unrestricted.
    if (
        preg_match('#^/api/providers/([^/]+)/scim$#i', $path, $m) &&
        $method === "GET"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), false);
        auth_require_user_directory($auth, false);
        $scimBase = $baseUrl . "/" . $prov["idp_id"] . "/scim/v2";
        json_response(200, [
            "scim_base_url" => $scimBase,
            "users_endpoint" => $scimBase . "/Users",
            "groups_endpoint" => $scimBase . "/Groups",
            "service_provider_config_url" => $scimBase . "/ServiceProviderConfig",
            "schemas_url" => $scimBase . "/Schemas",
            "tokens" => scim_token_list($PROVIDERS_FILE, $prov["id"]),
            "connectors" => scim_connector_list($PROVIDERS_FILE, $prov["id"]),
        ]);
    }

    if (preg_match('#^/api/providers/([^/]+)/scim/tokens$#i', $path, $m)) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), $method !== "GET");
        if ($method === "GET") {
            auth_require_user_directory($auth, false);
            json_response(200, [
                "tokens" => scim_token_list($PROVIDERS_FILE, $prov["id"]),
            ]);
        }
        if ($method === "POST") {
            auth_require_user_directory($auth, true);
            $body = read_json_body();
            // A minted token may never carry more directory access than its creator has.
            $requested = $body["permission"] ?? "read";
            if (
                ($auth["type"] ?? "") === "api_client" &&
                $requested === "write" &&
                ($auth["client"]["user_scope"] ?? "none") !== "write"
            ) {
                json_response(403, [
                    "error" => "Forbidden: a SCIM token cannot have more access than the API client's user_scope",
                ]);
            }
            try {
                $tok = scim_token_create(
                    $PROVIDERS_FILE,
                    $prov["id"],
                    $body
                );
            } catch (Throwable $e) {
                api_fail_from_exception($e);
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "scim_token.created",
                "success",
                (string) $prov["id"],
                (string) ($tok["id"] ?? ""),
                [
                    "name" => $tok["name"] ?? null,
                    "permission" => $tok["permission"] ?? null,
                    "filter_groups" => $tok["filter_groups"] ?? [],
                    "expires_at" => $tok["expires_at"] ?? null,
                ]
            );
            json_response(201, ["token" => $tok]);
        }
    }

    if (
        preg_match(
            '#^/api/providers/([^/]+)/scim/tokens/([a-f0-9\-]+)$#i',
            $path,
            $m
        ) &&
        $method === "DELETE"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        auth_require_user_directory($auth, true);
        if (!scim_token_delete($PROVIDERS_FILE, $prov["id"], $m[2])) {
            json_response(404, ["error" => "SCIM token not found"]);
        }
        admin_audit_append($PROVIDERS_FILE, $auth, "scim_token.deleted", "success", (string) $prov["id"], $m[2]);
        json_response(200, ["ok" => true]);
    }

    if (preg_match('#^/api/providers/([^/]+)/scim/connectors$#i', $path, $m)) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), $method !== "GET");
        if ($method === "GET") {
            auth_require_user_directory($auth, false);
            json_response(200, [
                "connectors" => scim_connector_list($PROVIDERS_FILE, $prov["id"]),
            ]);
        }
        if ($method === "POST") {
            auth_require_user_directory($auth, true);
            $body = read_json_body();
            // A password-pushing connector sends every user's plaintext password to the URL it
            // names: console sessions only, unless allow_api_client_password_push is set.
            if (!empty($body["push_passwords"]) && !api_may_manage_password_push($auth)) {
                json_response(403, [
                    "error" => "Forbidden: password-pushing SCIM connectors can only be set up from the admin console",
                ]);
            }
            try {
                $conn = scim_connector_save(
                    $PROVIDERS_FILE,
                    $prov["id"],
                    $body,
                    null,
                    auth_actor_label($auth)
                );
            } catch (Throwable $e) {
                api_scim_fail_from_exception($e);
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "scim_connector.created",
                "success",
                (string) $prov["id"],
                (string) ($conn["id"] ?? ""),
                [
                    "name" => $conn["name"] ?? null,
                    "delivery_mode" => $conn["delivery_mode"] ?? null,
                    "scim_base_url" => $conn["scim_base_url"] ?? null,
                    "push_passwords" => $conn["push_passwords"] ?? null,
                ]
            );
            json_response(201, ["connector" => $conn]);
        }
    }

    if (
        preg_match(
            '#^/api/providers/([^/]+)/scim/connectors/([a-f0-9\-]+)$#i',
            $path,
            $m
        )
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), $method !== "GET");
        $cid = $m[2];

        if ($method === "GET") {
            auth_require_user_directory($auth, false);
            $conn = scim_connector_get($PROVIDERS_FILE, $prov["id"], $cid);
            if (!$conn) {
                json_response(404, ["error" => "SCIM connector not found"]);
            }
            json_response(200, ["connector" => $conn]);
        }
        if (in_array($method, ["PUT", "PATCH"], true)) {
            auth_require_user_directory($auth, true);
            $body = read_json_body();
            if (!api_may_manage_password_push($auth)) {
                // Changing a password-pushing connector (its URL, token or agent) could redirect
                // the passwords; enabling the push is the same as creating one.
                $existing = scim_connector_get($PROVIDERS_FILE, $prov["id"], $cid);
                if (!$existing) {
                    json_response(404, ["error" => "SCIM connector not found"]);
                }
                if (!empty($existing["push_passwords"]) || !empty($body["push_passwords"])) {
                    json_response(403, [
                        "error" => "Forbidden: password-pushing SCIM connectors can only be changed from the admin console",
                    ]);
                }
            }
            try {
                $conn = scim_connector_save(
                    $PROVIDERS_FILE,
                    $prov["id"],
                    $body,
                    $cid,
                    auth_actor_label($auth)
                );
            } catch (Throwable $e) {
                api_scim_fail_from_exception($e);
            }
            admin_audit_append(
                $PROVIDERS_FILE,
                $auth,
                "scim_connector.updated",
                "success",
                (string) $prov["id"],
                $cid,
                [
                    "fields" => array_values(array_filter(
                        array_keys($body),
                        fn($k) => is_string($k) && $k !== "bearer_token"
                    )),
                    "bearer_token_changed" => is_string($body["bearer_token"] ?? null) && trim($body["bearer_token"]) !== "",
                    "scim_base_url" => $conn["scim_base_url"] ?? null,
                    "push_passwords" => $conn["push_passwords"] ?? null,
                ]
            );
            json_response(200, ["connector" => $conn]);
        }
        if ($method === "DELETE") {
            auth_require_user_directory($auth, true);
            if (!scim_connector_delete($PROVIDERS_FILE, $prov["id"], $cid, auth_actor_label($auth))) {
                json_response(404, ["error" => "SCIM connector not found"]);
            }
            admin_audit_append($PROVIDERS_FILE, $auth, "scim_connector.deleted", "success", (string) $prov["id"], $cid);
            json_response(200, ["ok" => true]);
        }
    }

    if (
        preg_match(
            '#^/api/providers/([^/]+)/scim/connectors/([a-f0-9\-]+)/test$#i',
            $path,
            $m
        ) &&
        $method === "POST"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        auth_require_user_directory($auth, true);
        // The test makes outbound calls (up to 15 s) and nothing after this point uses the
        // session, so its lock is released first: the administrator's other console requests
        // are not blocked meanwhile (G1c-06).
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        try {
            $result = scim_connector_test(
                $PROVIDERS_FILE,
                $prov,
                $m[2]
            );
        } catch (Throwable $e) {
            api_scim_fail_from_exception($e);
        }
        json_response(200, $result);
    }

    if (
        preg_match(
            '#^/api/providers/([^/]+)/scim/connectors/([a-f0-9\-]+)/sync$#i',
            $path,
            $m
        ) &&
        $method === "POST"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), true);
        auth_require_user_directory($auth, true);
        $body = read_json_body(false);
        // A sync makes outbound calls for up to its time budget; as for the test above, the
        // session lock is released first (G1c-06).
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
        $forceFull = !empty($body["force"]);
        try {
            $result = scim_connector_sync(
                $PROVIDERS_FILE,
                $prov,
                $m[2],
                $forceFull
            );
        } catch (Throwable $e) {
            api_scim_fail_from_exception($e);
        }
        admin_audit_append(
            $PROVIDERS_FILE,
            $auth,
            "scim_connector.synced",
            "success",
            (string) $prov["id"],
            $m[2],
            ["force" => $forceFull]
        );
        json_response(200, $result);
    }

    // ---------- Audit Logs ----------
    if (
        preg_match('#^/api/providers/([^/]+)/audit-logs$#i', $path, $m) &&
        $method === "GET"
    ) {
        $auth = require_admin_auth($PROVIDERS_FILE, $origin);
        $prov = api_resolve_provider($auth, $PROVIDERS_FILE, rawurldecode($m[1]), false);
        $lim = isset($_GET["limit"]) && is_string($_GET["limit"])
            ? max(1, min(500, (int) $_GET["limit"]))
            : 100;
        json_response(200, [
            "logs" => audit_log_list(
                $PROVIDERS_FILE,
                $prov["id"],
                $lim
            ),
        ]);
    }

    json_response(404, ["error" => "Unknown API endpoint: $path"]);
}
