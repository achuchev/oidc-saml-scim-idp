<?php
declare(strict_types=1);

/**
 * SCIM 2.0 (RFC 7643 Core Schema & RFC 7644 Protocol) Identity Provisioning Engine.
 *
 * Provides:
 *   1. Hosted Inbound SCIM 2.0 Server per Provider (/{idpId}/scim/v2/*)
 *      - /ServiceProviderConfig, /Schemas, /ResourceTypes
 *      - /Users, /Users/.search, /Users/{id}  (GET, POST, PUT, PATCH, DELETE + RFC 7644 filter & pagination)
 *      - /Groups, /Groups/.search, /Groups/{id} (GET, POST, PUT, PATCH, DELETE + membership sync)
 *      - PUT replaces the resource; If-Match / If-None-Match are checked against its version
 *   2. Outbound SCIM 2.0 Push Provisioning Connectors
 *      - Pushes Users & Groups from the Shared Directory to external SCIM 2.0 SPs
 *        (e.g., Palo Alto Cloud Identity Engine, Nextcloud, Slack, AWS, Cloudflare)
 *      - Optional encrypted password push (`push_passwords`, disabled by default)
 *      - SSRF-hardened HTTP client with DNS-pinned resolution & redirect blocking
 */

const SCIM_SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_SCHEMA_ENTERPRISE_USER = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const SCIM_SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCIM_SCHEMA_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_SCHEMA_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCIM_SCHEMA_SEARCH = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
const SCIM_SCHEMA_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error";
const SCIM_SCHEMA_SP_CONFIG = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
const SCIM_SCHEMA_RESOURCE_TYPE = "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
const SCIM_SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema";

// Inbound filter and search limits. A filter is parsed once per request into an AST.
const SCIM_FILTER_MAX_LENGTH = 2048;
const SCIM_FILTER_MAX_DEPTH = 16;
const SCIM_FILTER_MAX_LOGICAL_OPS = 32;
const SCIM_ATTR_LIST_MAX_LENGTH = 2048;
const SCIM_ATTR_LIST_MAX_ENTRIES = 64;

// Credential failure throttling, per provider and client network (or agent token id).
const SCIM_AUTH_MAX_FAILURES = 12;
const SCIM_AUTH_WINDOW_SECONDS = 300;
const SCIM_AUTH_LOCKOUT_SECONDS = 300;

// Outbound sync limits. The lease outlasts the longest sync: its time budget, plus the
// pickup wait and the longest answer wait (120 s + 15 s) of a relay job the agent claimed
// just before the budget ran out.
const SCIM_SYNC_TIME_BUDGET_SECONDS = 60;
const SCIM_SYNC_LEASE_SECONDS = 240;
const SCIM_SYNC_MAX_RERUNS = 2;
const SCIM_SYNC_CIRCUIT_SECONDS = 300;
const SCIM_OUTBOUND_TIMEOUT_SECONDS = 15;
const SCIM_OUTBOUND_CONNECT_TIMEOUT_SECONDS = 6;
const SCIM_AGENT_RELAY_TIMEOUT_SECONDS = 20;
const SCIM_OUTBOUND_MAX_RESPONSE_BYTES = 1048576;

// On-premises agent liveness: an agent is online when it polled within
// SCIM_AGENT_ONLINE_SECONDS and answers the jobs it claims; an agent that leaves claimed
// jobs unanswered gets one automatic retry per SCIM_AGENT_STALL_RETRY_SECONDS.
const SCIM_AGENT_ONLINE_SECONDS = 90;
const SCIM_AGENT_STALL_RETRY_SECONDS = 900;
const SCIM_AGENT_POLL_MAX_WAIT_SECONDS = 15;

// On-premises agent relay queue. A job waits SCIM_AGENT_RELAY_TIMEOUT_SECONDS for the agent
// to claim it; a claimed job is awaited for the agent's reported local timeout (at most
// SCIM_AGENT_MAX_LOCAL_TIMEOUT_SECONDS, which also applies when the agent reports none)
// plus SCIM_AGENT_ANSWER_GRACE_SECONDS. A poll answer stays below SCIM_AGENT_POLL_MAX_BYTES
// because older agents read at most 1 MiB of it; SCIM_AGENT_JOB_MAX_BYTES leaves room for
// the answer's envelope, so a job that is accepted always fits into one poll answer.
const SCIM_AGENT_MAX_LOCAL_TIMEOUT_SECONDS = 120;
const SCIM_AGENT_ANSWER_GRACE_SECONDS = 15;
const SCIM_AGENT_QUEUE_MARGIN_SECONDS = 10;
const SCIM_AGENT_FINISHED_JOB_KEEP_SECONDS = 60;
const SCIM_AGENT_JOB_MAX_AGE_SECONDS = 300;
const SCIM_AGENT_MAX_JOBS_PER_POLL = 10;
const SCIM_AGENT_POLL_MAX_BYTES = 921600;
const SCIM_AGENT_JOB_MAX_BYTES = 917504;
const SCIM_AGENT_POLL_REQUEST_MAX_BYTES = 65536;
// Older agents post the results of a whole poll (up to ten relayed responses of 512 KiB
// each, JSON-escaped) in one request.
const SCIM_AGENT_RESULT_REQUEST_MAX_BYTES = 8388608;
const SCIM_AGENT_MAX_RESULTS_PER_REQUEST = 50;
// Agents relay at most 512 KiB of a local response. Newer agents flag a body they cut
// ("truncated": true); older ones cut it silently, so a body of that size counts as cut.
const SCIM_AGENT_RESULT_BODY_MAX_BYTES = 524288;

// Rejected outbound target URLs on connector save, per provider and client network.
const SCIM_TARGET_CHECK_MAX_FAILURES = 20;
const SCIM_TARGET_CHECK_WINDOW_SECONDS = 600;
const SCIM_TARGET_CHECK_LOCKOUT_SECONDS = 600;

/** An outbound SCIM call failed below HTTP (no status was received). */
final class ScimTransportException extends RuntimeException
{
    public function __construct(string $message, public readonly bool $timedOut = false)
    {
        parent::__construct($message);
    }
}

/** Stops the current outbound sync run, for example when its time budget is used up. */
final class ScimSyncAbortException extends RuntimeException
{
}

// ---------- SCIM HTTP Response & Body Helpers ----------

function scim_json_response(
    int $status,
    ?array $payload = null,
    ?string $etag = null,
    ?string $location = null
): never {
    http_response_code($status);
    if (!headers_sent()) {
        send_security_headers(false);
        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Headers: Authorization, Content-Type, Accept, If-Match, If-None-Match");
        header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");
        if ($etag !== null && $etag !== "") {
            header("ETag: " . $etag);
        }
        if ($location !== null && $location !== "") {
            header("Location: " . $location);
        }
        if ($status !== 204 && $payload !== null) {
            header("Content-Type: application/scim+json; charset=utf-8");
            header("Cache-Control: no-store, no-cache, must-revalidate");
        }
    }
    if ($status === 204 || $payload === null) {
        exit();
    }
    // Stored text from older releases or remote systems may hold invalid UTF-8: it is
    // substituted instead of failing the whole response.
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    echo $json !== false ? $json : "{}";
    exit();
}

function scim_error_response(
    int $status,
    string $detail,
    ?string $scimType = null
): never {
    $err = [
        "schemas" => [SCIM_SCHEMA_ERROR],
        "status" => (string) $status,
        "detail" => $detail,
    ];
    if ($scimType !== null && $scimType !== "") {
        $err["scimType"] = $scimType;
    }
    scim_json_response($status, $err);
}

function scim_read_json_body(): array
{
    $ct = strtolower((string) ($_SERVER["CONTENT_TYPE"] ?? ($_SERVER["HTTP_CONTENT_TYPE"] ?? "")));
    if (
        $ct !== "" &&
        !str_contains($ct, "application/scim+json") &&
        !str_contains($ct, "application/json")
    ) {
        scim_error_response(
            415,
            "Content-Type must be application/scim+json or application/json"
        );
    }
    $raw = file_get_contents("php://input", false, null, 0, 524289);
    if ($raw === false || trim($raw) === "") {
        return [];
    }
    if (strlen($raw) > 524288) {
        scim_error_response(413, "SCIM JSON payload exceeds maximum allowed size");
    }
    $decoded = json_decode($raw, true, 32);
    if (!is_array($decoded)) {
        scim_error_response(400, "Malformed JSON payload", "invalidSyntax");
    }
    return $decoded;
}

// ---------- Inbound SCIM 2.0 Bearer Tokens Management ----------

function hydrate_scim_token_row(array $r): array
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
        "provider_id" => (string) $r["provider_id"],
        "name" => (string) $r["name"],
        "secret_preview" => (string) $r["secret_preview"],
        "permission" => (string) ($r["permission"] ?? "read"),
        "filter_groups" =>
            json_decode((string) ($r["filter_groups_json"] ?? "[]"), true) ?: [],
        "status" => (string) ($r["status"] ?? "active"),
        "expires_at" => $exp,
        "is_expired" => $isExpired,
        "created_at" => (string) $r["created_at"],
        "last_used_at" => $r["last_used_at"] ?? null,
        "last_used_ip" => $r["last_used_ip"] ?? null,
    ];
}

function scim_token_list(string $storePath, string $providerId): array
{
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM scim_tokens WHERE provider_id = :pid ORDER BY created_at DESC"
    );
    $stmt->execute([":pid" => $providerId]);
    $out = [];
    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $out[] = hydrate_scim_token_row($r);
    }
    return $out;
}

function scim_token_create(
    string $storePath,
    string $providerId,
    array $input
): array {
    $name = trim((string) ($input["name"] ?? ""));
    if ($name === "") {
        throw new InvalidArgumentException("SCIM token name is required");
    }
    $perm = (string) ($input["permission"] ?? "read");
    $permission = in_array($perm, ["read", "write"], true) ? $perm : "read";
    $filterGroups = normalize_string_list($input["filter_groups"] ?? []);
    $expiresAt = admin_client_parse_expires_input(
        $input["expires_in"] ?? ($input["expires_at"] ?? null)
    );

    $id = uuidv4();
    $tokenId = bin2hex(random_bytes(8));
    $plainToken = "idp_scim_" . $tokenId . "_" . base64url_encode(random_bytes(28));
    // High-entropy machine credential: fast digest, verified with machine_secret_verify().
    $secretHash = machine_secret_hash($plainToken);
    $secretPreview = "idp_scim_" . substr($tokenId, 0, 6) . "••••••••";
    $now = gmdate("Y-m-d\TH:i:s\Z");

    $pdo = storage_db($storePath);
    $ins = $pdo->prepare(
        "INSERT INTO scim_tokens (" .
            "id, provider_id, name, token_id, secret_hash, secret_preview, permission, " .
            "filter_groups_json, status, expires_at, created_at" .
        ") VALUES (:id, :pid, :name, :tid, :sh, :sprev, :perm, :fg, 'active', :exp, :cat)"
    );
    $ins->execute([
        ":id" => $id,
        ":pid" => $providerId,
        ":name" => $name,
        ":tid" => $tokenId,
        ":sh" => $secretHash,
        ":sprev" => $secretPreview,
        ":perm" => $permission,
        ":fg" => json_encode($filterGroups, JSON_UNESCAPED_SLASHES),
        ":exp" => $expiresAt,
        ":cat" => $now,
    ]);

    $stmt = $pdo->prepare("SELECT * FROM scim_tokens WHERE id = :id LIMIT 1");
    $stmt->execute([":id" => $id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    $hydrated = hydrate_scim_token_row($row);
    $hydrated["bearer_token"] = $plainToken;
    return $hydrated;
}

function scim_token_delete(
    string $storePath,
    string $providerId,
    string $id
): bool {
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "DELETE FROM scim_tokens WHERE id = :id AND provider_id = :pid"
    );
    $stmt->execute([":id" => $id, ":pid" => $providerId]);
    return $stmt->rowCount() > 0;
}

/**
 * Answers a failed SCIM or agent credential. The lockout is consulted only on this
 * failure path, so a credential that verifies is never refused: an attacker can only
 * exhaust the failure budget of its own bucket. While the bucket is locked, failures
 * are not counted again, so retries cannot extend an active lockout.
 */
function scim_auth_failure(
    string $storePath,
    string $bucket,
    string $detail,
    bool $agentJson = false
): never {
    if (rate_limit_is_blocked($storePath, $bucket)) {
        if (!headers_sent()) {
            header("Retry-After: " . SCIM_AUTH_LOCKOUT_SECONDS);
        }
        if ($agentJson) {
            json_response(429, ["error" => "Too many failed SCIM agent authentication attempts"]);
        }
        scim_error_response(429, "Too many failed SCIM authentication attempts");
    }
    rate_limit_record_failure(
        $storePath,
        $bucket,
        SCIM_AUTH_MAX_FAILURES,
        SCIM_AUTH_WINDOW_SECONDS,
        SCIM_AUTH_LOCKOUT_SECONDS
    );
    if ($agentJson) {
        json_response(401, ["error" => $detail]);
    }
    if (!headers_sent()) {
        header('WWW-Authenticate: Bearer realm="SCIM 2.0", error="invalid_token"');
    }
    scim_error_response(401, $detail);
}

/**
 * Best-effort compare-and-swap of a legacy password_hash() digest to its
 * machine_secret_hash() form after the secret verified.
 */
function scim_store_upgraded_secret_hash(
    PDO $pdo,
    string $table,
    string $id,
    string $oldHash,
    string $newHash
): void {
    $sql = match ($table) {
        "scim_tokens" =>
            "UPDATE scim_tokens SET secret_hash = :new WHERE id = :id AND secret_hash = :old",
        "scim_connectors" =>
            "UPDATE scim_connectors SET agent_secret_hash = :new WHERE id = :id AND agent_secret_hash = :old",
        default => "",
    };
    if ($sql === "") {
        return;
    }
    try {
        $pdo->prepare($sql)->execute([":new" => $newHash, ":id" => $id, ":old" => $oldHash]);
    } catch (Throwable $e) {
        error_log("SCIM: could not upgrade a stored credential digest (" . get_class($e) . ")");
    }
}

function scim_authenticate_inbound_request(
    string $storePath,
    array $provider,
    bool $requireWrite
): array {
    $providerId = (string) $provider["id"];
    // Failures are counted per provider and client network, and only after the presented
    // credential failed verification, so failed attempts against one tenant (or from
    // another network) can never lock out a valid token.
    $failBucket = rate_limit_bucket("scim_auth", $providerId, client_ip_bucket());

    $authHeader = trim(get_auth_header());
    $rawToken = "";
    if (preg_match('/^Bearer\s+(\S+)$/i', $authHeader, $m)) {
        $rawToken = trim($m[1]);
    } elseif (!empty($_SERVER["HTTP_X_API_KEY"])) {
        $rawToken = trim((string) $_SERVER["HTTP_X_API_KEY"]);
    }

    if ($rawToken === "") {
        header('WWW-Authenticate: Bearer realm="SCIM 2.0"');
        scim_error_response(401, "Missing Bearer token in Authorization header");
    }

    // 1. Dedicated provider SCIM token (idp_scim_<16hex>_<secret>), looked up by its public id.
    //    Unknown ids cost no hashing at all; secrets are verified with a fast digest.
    if (preg_match('/^idp_scim_([a-f0-9]{16})_[A-Za-z0-9\-_]+$/D', $rawToken, $tm)) {
        $pdo = storage_db($storePath);
        $stmt = $pdo->prepare(
            "SELECT * FROM scim_tokens WHERE token_id = :tid AND provider_id = :pid LIMIT 1"
        );
        $stmt->execute([":tid" => $tm[1], ":pid" => $providerId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        // Ends the read snapshot before the writes below. A write on a connection that still
        // reads an older snapshot fails at once with "database is locked" (no busy wait) when
        // a concurrent request committed in between, which refused valid tokens with a 500.
        $stmt->closeCursor();

        $upgradedHash = null;
        if (
            !is_array($row) ||
            !machine_secret_verify($rawToken, (string) ($row["secret_hash"] ?? ""), $upgradedHash)
        ) {
            scim_auth_failure($storePath, $failBucket, "Invalid SCIM Bearer token");
        }

        $hydrated = hydrate_scim_token_row($row);
        if ($hydrated["status"] !== "active" || $hydrated["is_expired"]) {
            scim_auth_failure($storePath, $failBucket, "SCIM Bearer token is revoked or expired");
        }
        if ($upgradedHash !== null) {
            scim_store_upgraded_secret_hash(
                $pdo,
                "scim_tokens",
                (string) $row["id"],
                (string) $row["secret_hash"],
                $upgradedHash
            );
        }

        if ($requireWrite && $hydrated["permission"] !== "write") {
            scim_error_response(
                403,
                "SCIM token has read-only permission; write operations are forbidden"
            );
        }

        try {
            // Usage bookkeeping only: it never fails a request whose token verified.
            $pdo->prepare(
                "UPDATE scim_tokens SET last_used_at = :ts, last_used_ip = :ip WHERE id = :id"
            )->execute([
                ":ts" => gmdate("Y-m-d\TH:i:s\Z"),
                ":ip" => client_ip_address(),
                ":id" => $hydrated["id"],
            ]);
        } catch (Throwable $e) {
            error_log("SCIM: could not record the use of a token (" . get_class($e) . ")");
        }
        rate_limit_clear($storePath, $failBucket);

        return [
            "actor" => "scim_token:" . $hydrated["name"],
            "permission" => $hydrated["permission"],
            "filter_groups" => normalize_string_list($hydrated["filter_groups"]),
        ];
    }

    // 2. Also accept scoped Admin API Client tokens (idp_adm_... / idp_at_...). A client row
    //    still holding a legacy bcrypt digest reserves an attempt in the per-address bucket
    //    the admin API uses before that slow check (S06-09, X3-09).
    if (function_exists("admin_client_verify_by_token")) {
        $admClient = admin_client_verify_by_token(
            $storePath,
            $rawToken,
            rate_limit_bucket("admin_api_hdr_bcrypt", client_ip_bucket())
        );
        if (is_array($admClient) && ($admClient["owner"] ?? null) === $provider["owner"]) {
            $provOk =
                ($admClient["provider_scope"] ?? "selected") === "all" ||
                in_array($provider["id"], $admClient["allowed_provider_ids"] ?? [], true);
            $uScope = (string) ($admClient["user_scope"] ?? "none");
            if (!$provOk || !in_array($uScope, ["read", "write"], true)) {
                scim_error_response(
                    403,
                    "Admin API client lacks provider scope or user_scope access for SCIM"
                );
            }
            if ($requireWrite && $uScope !== "write") {
                scim_error_response(
                    403,
                    "Admin API client has read-only user_scope; SCIM write operations are forbidden"
                );
            }
            rate_limit_clear($storePath, $failBucket);
            return [
                "actor" => "admin_client:" . $admClient["name"],
                "permission" => $uScope,
                "filter_groups" => [],
            ];
        }
    }

    scim_auth_failure($storePath, $failBucket, "Invalid or unauthorized SCIM Bearer token");
}

// ---------- SCIM 2.0 Resource Versions & Conditional Requests (RFC 7644 3.14) ----------

/** Weak entity tag of a resource state. Any change of the state gives a new tag. */
function scim_weak_etag(array $state): string
{
    return 'W/"' . substr(hash("sha256", serialize($state)), 0, 32) . '"';
}

/**
 * Version (ETag and meta.version) of a SCIM User: a digest of everything the resource shows
 * or a SCIM write changes (identifiers, names, phone, status, password presence, groups and
 * every stored attribute) plus updated_at. Two changes within the same second therefore get
 * different versions; updated_at alone has one-second resolution (G3b-02).
 */
function scim_user_version(array $user): string
{
    return scim_weak_etag([
        "id" => (string) ($user["id"] ?? ""),
        "userName" => (string) ($user["username"] ?? ""),
        "email" => (string) ($user["email"] ?? ""),
        "givenName" => (string) ($user["given_name"] ?? ""),
        "familyName" => (string) ($user["family_name"] ?? ""),
        "displayName" => (string) ($user["display_name"] ?? ""),
        "phone" => (string) ($user["mobile_phone"] ?? ""),
        "externalId" => (string) ($user["external_id"] ?? ""),
        "status" => (string) ($user["status"] ?? "active"),
        "hasPassword" => !empty($user["has_password"]),
        "groups" => is_array($user["groups"] ?? null) ? array_values($user["groups"]) : [],
        "attributes" => is_array($user["attributes"] ?? null) ? $user["attributes"] : [],
        "updated" => (string) ($user["updated_at"] ?? ""),
    ]);
}

/** Version of a SCIM Group: its name, externalId, member ids (as a set) and updated_at. */
function scim_group_version(array $group): string
{
    $memberIds = [];
    foreach ($group["members"] ?? [] as $m) {
        if (is_array($m) && isset($m["id"]) && is_scalar($m["id"])) {
            $memberIds[] = (string) $m["id"];
        }
    }
    $memberIds = array_values(array_unique($memberIds));
    sort($memberIds, SORT_STRING);
    return scim_weak_etag([
        "id" => (string) ($group["id"] ?? ""),
        "displayName" => (string) ($group["display_name"] ?? ""),
        "externalId" => (string) ($group["external_id"] ?? ""),
        "members" => $memberIds,
        "updated" => (string) ($group["updated_at"] ?? ""),
    ]);
}

/**
 * If-Match (PUT, PATCH and DELETE of /Users/{id} and /Groups/{id}) and If-None-Match (GET of
 * them) are evaluated against the resource version. OIDC_SCIM_IGNORE_IF_MATCH=1 restores
 * ignoring both headers; /ServiceProviderConfig then reports etag as unsupported.
 */
function scim_preconditions_enabled(): bool
{
    return !config_flag("scim_ignore_if_match", "OIDC_SCIM_IGNORE_IF_MATCH");
}

/**
 * Entity tags of a conditional request header ($serverKey: HTTP_IF_MATCH or
 * HTTP_IF_NONE_MATCH): ["*"], or the opaque tags of its comma-separated list, weak "W/"
 * prefixes dropped. Unquoted tags are accepted leniently; a header without any usable tag
 * gives an empty list, which matches nothing. Null when the header is absent or empty, or
 * when preconditions are ignored.
 */
function scim_precondition_tags(string $serverKey): ?array
{
    if (!scim_preconditions_enabled()) {
        return null;
    }
    $raw = $_SERVER[$serverKey] ?? null;
    if (!is_string($raw) || trim($raw) === "") {
        return null;
    }
    $raw = trim($raw);
    if ($raw === "*") {
        return ["*"];
    }
    if (preg_match_all('/"([^"]*)"/', $raw, $m) > 0) {
        return $m[1];
    }
    $tags = [];
    foreach (explode(",", $raw) as $part) {
        $part = trim($part);
        if (strncasecmp($part, "W/", 2) === 0) {
            $part = substr($part, 2);
        }
        $part = trim($part);
        if ($part !== "") {
            $tags[] = $part;
        }
    }
    return $tags;
}

/**
 * Weak comparison (RFC 7232 2.3.2, as RFC 7644 3.14 uses for SCIM versions) of a version with
 * the tags from scim_precondition_tags(): true when one of them is "*" or has the same
 * opaque tag.
 */
function scim_version_matches(array $tags, string $version): bool
{
    $opaque = preg_match('/^(?:W\/)?"([^"]*)"$/D', $version, $vm) === 1 ? $vm[1] : $version;
    foreach ($tags as $tag) {
        if ($tag === "*" || $tag === $opaque) {
            return true;
        }
    }
    return false;
}

function scim_precondition_failed(): never
{
    scim_error_response(412, "Failed to update: the resource has changed on the server; read it again and retry");
}

/**
 * Evaluates If-Match against $version, the version of the resource as this request read it:
 * 412 Precondition Failed when no listed tag matches. Returns $version when the request is
 * conditional, null otherwise. The write checks the condition again, atomically, on the
 * resource as stored at that moment (scim_write_precondition()).
 */
function scim_check_if_match(string $version): ?string
{
    $tags = scim_precondition_tags("HTTP_IF_MATCH");
    if ($tags === null) {
        return null;
    }
    if (!scim_version_matches($tags, $version)) {
        scim_precondition_failed();
    }
    return $version;
}

/** Answers 304 Not Modified to a GET whose If-None-Match lists $version, or "*". */
function scim_answer_not_modified_if_current(string $version): void
{
    $tags = scim_precondition_tags("HTTP_IF_NONE_MATCH");
    if ($tags !== null && scim_version_matches($tags, $version)) {
        if (!headers_sent()) {
            // A 304 carries the Cache-Control of the 200 it stands for (RFC 7232 4.1).
            header("Cache-Control: no-store, no-cache, must-revalidate");
        }
        scim_json_response(304, null, $version);
    }
}

/**
 * The $precondition of the directory write of /Users/{id} or /Groups/{id}
 * (directory_update_user(), directory_delete_user(), directory_update_group() and
 * directory_delete_group()). The directory layer calls it inside its write transaction
 * (BEGIN IMMEDIATE), after slow work such as password hashing, with the resource as stored
 * at that moment, so no other writer can change the resource between the check and the
 * write. It is false when the request's If-Match does not match that resource's version
 * ($versionOf: scim_user_version() or scim_group_version(); "*" matches any resource that
 * still exists), or when the resource no longer passes $inScope (the token's group
 * restriction, which the request checked on the copy it read). The write is then rolled back
 * with DirectoryPreconditionFailed (answer it with scim_write_refused()). Null, so the write
 * costs no extra read, when the request has no If-Match and $inScope is null.
 */
function scim_write_precondition(Closure $versionOf, ?Closure $inScope = null): ?Closure
{
    $tags = scim_precondition_tags("HTTP_IF_MATCH");
    if ($tags === null && $inScope === null) {
        return null;
    }
    return static function (array $stored) use ($tags, $versionOf, $inScope): bool {
        if ($inScope !== null && !$inScope($stored)) {
            return false;
        }
        return $tags === null || scim_version_matches($tags, (string) $versionOf($stored));
    };
}

/**
 * Answers a write of /Users/{id} or /Groups/{id} that its precondition refused
 * (DirectoryPreconditionFailed), or that found the resource deleted after the request read
 * it: 412 Precondition Failed for a conditional request (If-Match), else 404 with $notFound,
 * the answer for a resource that is gone or outside the token's group restriction.
 */
function scim_write_refused(string $notFound): never
{
    if (scim_precondition_tags("HTTP_IF_MATCH") !== null) {
        scim_precondition_failed();
    }
    scim_error_response(404, $notFound);
}

// ---------- SCIM 2.0 Resource Formatting (Users & Groups) ----------

/**
 * Outbound user payloads carry explicit clears for empty optional attributes (roles: [],
 * phoneNumbers: [], title: null and every enterprise extension field as null), so a target
 * that merges on PUT drops values removed here instead of keeping them.
 * OIDC_SCIM_OUTBOUND_OMIT_EMPTY_ATTRIBUTES=1 restores leaving empty attributes out, for
 * targets that reject null or empty values.
 */
function scim_outbound_sends_explicit_clears(): bool
{
    return !config_flag("scim_outbound_omit_empty_attributes", "OIDC_SCIM_OUTBOUND_OMIT_EMPTY_ATTRIBUTES");
}

function scim_format_user_resource(
    array $user,
    string $scimBaseUrl,
    array $groupMapByNameLower = [],
    ?string $outboundPlainPassword = null,
    bool $isOutbound = false
): array {
    $attrs = is_array($user["attributes"] ?? null) ? $user["attributes"] : [];
    // Outbound payloads name every optional attribute, empty ones as null or [], so a target
    // that merges on PUT clears what was removed here (G3b-01). Inbound responses leave
    // empty attributes out, as before.
    $explicitClears = $isOutbound && scim_outbound_sends_explicit_clears();
    $enterprise = [];
    foreach (["employeeNumber", "costCenter", "organization", "division", "department"] as $ek) {
        if (isset($attrs[$ek]) && is_scalar($attrs[$ek]) && trim((string) $attrs[$ek]) !== "") {
            $enterprise[$ek] = trim((string) $attrs[$ek]);
        } elseif ($explicitClears) {
            $enterprise[$ek] = null;
        }
    }
    if (isset($attrs["manager"]) && is_scalar($attrs["manager"]) && trim((string) $attrs["manager"]) !== "") {
        $enterprise["manager"] = ["value" => trim((string) $attrs["manager"])];
    } elseif ($explicitClears) {
        $enterprise["manager"] = null;
    }

    $schemas = [SCIM_SCHEMA_USER];
    if (!empty($enterprise)) {
        $schemas[] = SCIM_SCHEMA_ENTERPRISE_USER;
    }

    $given = (string) ($user["given_name"] ?? "");
    $family = (string) ($user["family_name"] ?? "");
    $formatted = trim($given . " " . $family);
    if ($formatted === "") {
        $formatted = (string) ($user["display_name"] ?? $user["username"]);
    }

    $res = [
        "schemas" => $schemas,
        "userName" => (string) $user["username"],
        "name" => [
            "formatted" => $formatted,
            "givenName" => $given,
            "familyName" => $family,
        ],
        "displayName" => (string) ($user["display_name"] ?? $user["username"]),
        "active" => ($user["status"] ?? "active") === "active",
        "emails" => [
            [
                "value" => (string) $user["email"],
                "type" => "work",
                "primary" => true,
            ],
        ],
    ];

    if (!$isOutbound) {
        $res = ["schemas" => $schemas, "id" => (string) $user["id"]] + $res;
    }

    $extId = trim((string) ($user["external_id"] ?? ""));
    if ($isOutbound && $extId === "") {
        $extId = (string) $user["id"];
    }
    if ($extId !== "") {
        $res["externalId"] = $extId;
    }

    if (!empty($user["mobile_phone"])) {
        $res["phoneNumbers"] = [
            [
                "value" => (string) $user["mobile_phone"],
                "type" => "mobile",
                "primary" => true,
            ],
        ];
    } elseif ($explicitClears) {
        $res["phoneNumbers"] = [];
    }

    if (isset($attrs["title"]) && is_scalar($attrs["title"]) && trim((string) $attrs["title"]) !== "") {
        $res["title"] = trim((string) $attrs["title"]);
    } elseif ($explicitClears) {
        $res["title"] = null;
    }

    $roleList = isset($attrs["roles"]) ? normalize_string_list($attrs["roles"]) : [];
    if (!empty($roleList)) {
        $res["roles"] = array_map(fn($r) => ["value" => $r], $roleList);
    } elseif ($explicitClears) {
        $res["roles"] = [];
    }

    if (!$isOutbound) {
        $groupRefs = [];
        foreach ($user["groups"] ?? [] as $gn) {
            $gl = strtolower(trim((string) $gn));
            $gObj = $groupMapByNameLower[$gl] ?? null;
            $gid = $gObj ? (string) $gObj["id"] : "";
            $entry = [
                "value" => $gid !== "" ? $gid : (string) $gn,
                "display" => (string) $gn,
                "type" => "direct",
            ];
            if ($gid !== "" && $scimBaseUrl !== "") {
                $entry['$ref'] = rtrim($scimBaseUrl, "/") . "/Groups/" . rawurlencode($gid);
            }
            $groupRefs[] = $entry;
        }
        $res["groups"] = $groupRefs;
    }

    if (!empty($enterprise)) {
        $res[SCIM_SCHEMA_ENTERPRISE_USER] = $enterprise;
    }

    // Optional password push for Outbound SCIM Connectors ONLY (never returned on Inbound GET)
    if ($isOutbound && $outboundPlainPassword !== null && $outboundPlainPassword !== "") {
        $res["password"] = $outboundPlainPassword;
    }

    if (!$isOutbound) {
        $created = (string) ($user["created_at"] ?? gmdate("Y-m-d\TH:i:s\Z"));
        $updated = (string) ($user["updated_at"] ?? $created);
        $res["meta"] = [
            "resourceType" => "User",
            "created" => $created,
            "lastModified" => $updated,
            "location" => rtrim($scimBaseUrl, "/") . "/Users/" . rawurlencode((string) $user["id"]),
            "version" => scim_user_version($user),
        ];
    }

    return $res;
}

function scim_format_group_resource(
    array $group,
    string $scimBaseUrl,
    bool $excludeMembers = false
): array {
    $created = (string) ($group["created_at"] ?? gmdate("Y-m-d\TH:i:s\Z"));
    $updated = (string) ($group["updated_at"] ?? $created);
    $version = scim_group_version($group);

    $res = [
        "schemas" => [SCIM_SCHEMA_GROUP],
        "id" => (string) $group["id"],
        "displayName" => (string) $group["display_name"],
    ];
    if (!empty($group["external_id"])) {
        $res["externalId"] = (string) $group["external_id"];
    }
    if (!$excludeMembers) {
        $members = [];
        foreach ($group["members"] ?? [] as $m) {
            $uid = (string) $m["id"];
            $members[] = [
                "value" => $uid,
                "display" => (string) ($m["username"] ?? ($m["email"] ?? $uid)),
                '$ref' => rtrim($scimBaseUrl, "/") . "/Users/" . rawurlencode($uid),
            ];
        }
        $res["members"] = $members;
    }
    $res["meta"] = [
        "resourceType" => "Group",
        "created" => $created,
        "lastModified" => $updated,
        "location" => rtrim($scimBaseUrl, "/") . "/Groups/" . rawurlencode((string) $group["id"]),
        "version" => $version,
    ];
    return $res;
}

// ---------- SCIM Input Parsing & RFC 7644 PatchOp Engine ----------

function scim_extract_primary_value(mixed $items): string
{
    if (is_string($items)) {
        return trim($items);
    }
    if (!is_array($items)) {
        return "";
    }
    foreach ($items as $item) {
        if (is_array($item) && !empty($item["primary"]) && isset($item["value"])) {
            return trim((string) $item["value"]);
        }
    }
    foreach ($items as $item) {
        if (is_array($item) && isset($item["value"]) && trim((string) $item["value"]) !== "") {
            return trim((string) $item["value"]);
        }
        if (is_string($item) && trim($item) !== "") {
            return trim($item);
        }
    }
    return "";
}

/**
 * The key of $arr that names attribute $name: the exact key, else the first key that matches
 * case-insensitively (attribute names are case-insensitive, RFC 7643 2.1). Null when absent.
 */
function scim_attribute_key(array $arr, string $name): int|string|null
{
    if (array_key_exists($name, $arr)) {
        return $name;
    }
    foreach (array_keys($arr) as $key) {
        if (strcasecmp((string) $key, $name) === 0) {
            return $key;
        }
    }
    return null;
}

/**
 * PUT replaces a resource (RFC 7644 3.5.1): by default the optional attributes that a
 * PUT /Users leaves out (title, phoneNumbers and the enterprise extension fields) are
 * cleared, and a PUT /Groups without members empties the group.
 * OIDC_SCIM_PUT_KEEPS_OMITTED_ATTRIBUTES=1 restores the old merge, where they keep their
 * stored values; an explicit null still clears. Roles follow scim_put_keeps_omitted_roles.
 */
function scim_put_keeps_omitted_attributes(): bool
{
    return config_flag("scim_put_keeps_omitted_attributes", "OIDC_SCIM_PUT_KEEPS_OMITTED_ATTRIBUTES");
}

/**
 * Directory input from a SCIM User resource: POST (create) without $existingUser, PUT with
 * the stored user. A PUT replaces the resource (RFC 7644 3.5.1): title, phoneNumbers, roles
 * and the enterprise extension fields that it leaves out, or sends as null or empty, are
 * cleared, and an omitted or null enterprise extension clears all of its fields (G3b-01).
 * scim_put_keeps_omitted_attributes() and scim_put_keeps_omitted_roles restore the old
 * merge for attributes left out. Left out of a PUT, these keep their stored values: password
 * (write-only), active, userName, emails, name, displayName, externalId and the stored
 * attributes that SCIM does not show (custom attributes set by an admin). Wrong types for
 * roles, title, the enterprise extension and its fields answer 400 invalidValue instead of
 * being ignored.
 */
function scim_extract_user_input_from_resource(
    array $body,
    ?array $existingUser = null
): array {
    $out = [];
    $isReplace = $existingUser !== null;
    $clearOmitted = $isReplace && !scim_put_keeps_omitted_attributes();

    if (array_key_exists("userName", $body)) {
        $out["username"] = trim((string) $body["userName"]);
    } elseif ($existingUser === null && isset($body["username"])) {
        $out["username"] = trim((string) $body["username"]);
    }

    if (array_key_exists("emails", $body)) {
        $email = scim_extract_primary_value($body["emails"]);
        if ($email !== "") {
            $out["email"] = $email;
        }
    }
    // On create an email-shaped userName doubles as the email. A PUT without emails keeps the
    // stored address instead of overwriting it with the userName.
    if (!$isReplace && !isset($out["email"]) && isset($out["username"]) && str_contains($out["username"], "@")) {
        $out["email"] = $out["username"];
    }

    if (isset($body["name"]) && is_array($body["name"])) {
        if (array_key_exists("givenName", $body["name"])) {
            $out["given_name"] = trim((string) $body["name"]["givenName"]);
        }
        if (array_key_exists("familyName", $body["name"])) {
            $out["family_name"] = trim((string) $body["name"]["familyName"]);
        }
        if (
            !isset($body["displayName"]) &&
            isset($body["name"]["formatted"]) &&
            trim((string) $body["name"]["formatted"]) !== ""
        ) {
            $out["display_name"] = trim((string) $body["name"]["formatted"]);
        }
    }

    if (array_key_exists("displayName", $body)) {
        $out["display_name"] = trim((string) $body["displayName"]);
    }

    $phoneKey = scim_attribute_key($body, "phoneNumbers");
    if ($phoneKey !== null) {
        $out["mobile_phone"] = scim_extract_primary_value($body[$phoneKey]);
    } elseif ($clearOmitted) {
        $out["mobile_phone"] = "";
    }

    if (array_key_exists("externalId", $body)) {
        $out["external_id"] = trim((string) $body["externalId"]);
    }

    if (array_key_exists("active", $body)) {
        $activeVal = $body["active"];
        if (is_string($activeVal)) {
            $activeVal = !in_array(strtolower(trim($activeVal)), ["false", "0", "no"], true);
        }
        $out["status"] = $activeVal ? "active" : "suspended";
    }

    if (isset($body["password"]) && is_string($body["password"]) && $body["password"] !== "") {
        $out["password"] = $body["password"];
    }

    // Stored attributes that SCIM does not show (custom attributes) are always kept.
    $attrs = $existingUser !== null && is_array($existingUser["attributes"] ?? null)
        ? $existingUser["attributes"]
        : [];
    $attrsChanged = false;
    // Sets a single-valued text attribute; null, "" and whitespace clear it (RFC 7643 2.5).
    $putText = static function (string $key, mixed $value) use (&$attrs, &$attrsChanged): void {
        if ($value !== null && !is_scalar($value)) {
            scim_error_response(400, "$key must be a string", "invalidValue");
        }
        $text = $value === null ? "" : trim((string) $value);
        if ($text === "") {
            unset($attrs[$key]);
        } else {
            $attrs[$key] = $text;
        }
        $attrsChanged = true;
    };

    $titleKey = scim_attribute_key($body, "title");
    if ($titleKey !== null) {
        $putText("title", $body[$titleKey]);
    } elseif ($clearOmitted) {
        $putText("title", null);
    }

    $rolesKey = scim_attribute_key($body, "roles");
    if ($rolesKey !== null) {
        $rolesValue = $body[$rolesKey];
        if ($rolesValue !== null && !is_array($rolesValue)) {
            // A scalar such as "roles": "admin" used to be ignored with a 200.
            scim_error_response(400, "roles must be a list of role objects with a value", "invalidValue");
        }
        // null and [] are the same state (RFC 7643 2.5): both clear the roles. Items without
        // a usable value answer 400, as in PATCH, so a role change is never dropped silently.
        $roles = scim_patch_role_values($rolesValue);
        if ($roles === []) {
            unset($attrs["roles"]);
        } else {
            $attrs["roles"] = $roles;
        }
        $attrsChanged = true;
    } elseif (
        $isReplace &&
        array_key_exists("roles", $attrs) &&
        !config_flag("scim_put_keeps_omitted_roles", "OIDC_SCIM_PUT_KEEPS_OMITTED_ROLES")
    ) {
        // PUT replaces the resource (RFC 7644 3.5.1): roles it leaves out (clients such as
        // Okta omit an attribute that became empty) are revoked instead of staying in the
        // OIDC/SAML roles claim. OIDC_SCIM_PUT_KEEPS_OMITTED_ROLES=1 keeps stored roles that a
        // PUT leaves out (roles managed outside SCIM); null still clears.
        unset($attrs["roles"]);
        $attrsChanged = true;
    }

    // Enterprise User extension. A PUT that leaves it out, or a field of it, clears what it
    // left out; an explicit null extension clears every field, even with the old merge.
    $extKey = scim_attribute_key($body, SCIM_SCHEMA_ENTERPRISE_USER);
    $ext = $extKey !== null ? $body[$extKey] : null;
    if ($ext !== null && (!is_array($ext) || ($ext !== [] && array_is_list($ext)))) {
        scim_error_response(400, "The enterprise user extension must be an object", "invalidValue");
    }
    $clearOmittedFields = $clearOmitted || ($isReplace && $extKey !== null && $ext === null);
    foreach (["employeeNumber", "costCenter", "organization", "division", "department", "manager"] as $ek) {
        $fieldKey = is_array($ext) ? scim_attribute_key($ext, $ek) : null;
        if ($fieldKey === null) {
            if ($clearOmittedFields) {
                $putText($ek, null);
            }
            continue;
        }
        $fieldValue = $ext[$fieldKey];
        if ($ek === "manager" && is_array($fieldValue)) {
            // manager is complex: its "value" sub-attribute is the manager's id.
            $valueKey = scim_attribute_key($fieldValue, "value");
            $fieldValue = $valueKey !== null ? $fieldValue[$valueKey] : null;
        }
        $putText($ek, $fieldValue);
    }

    if ($attrsChanged) {
        $out["attributes"] = $attrs;
    }

    return $out;
}

/**
 * Reads one PatchOp operation: returns [op, path, value]. Exits with 400 on malformed input.
 */
function scim_patch_read_operation(mixed $opItem): array
{
    if (!is_array($opItem)) {
        scim_error_response(400, "Each PatchOp operation must be an object", "invalidSyntax");
    }
    $opRaw = $opItem["op"] ?? "replace";
    $op = is_string($opRaw) ? strtolower(trim($opRaw)) : "";
    if (!in_array($op, ["add", "replace", "remove"], true)) {
        scim_error_response(400, "Unsupported PatchOp operation", "invalidSyntax");
    }
    $pathRaw = $opItem["path"] ?? "";
    if (!is_string($pathRaw)) {
        scim_error_response(400, "PatchOp path must be a string", "invalidPath");
    }
    return [$op, trim($pathRaw), $opItem["value"] ?? null];
}

/**
 * The value of a PatchOp without a path must be an object of attributes (RFC 7644 3.5.2).
 */
function scim_patch_pathless_value(mixed $value): array
{
    if (is_array($value) && ($value === [] || !array_is_list($value))) {
        return $value;
    }
    scim_error_response(400, "A PatchOp operation without a path needs an object value", "invalidSyntax");
}

/**
 * Parses an RFC 7644 PATCH path: an attribute path, or a value path with an optional
 * sub-attribute (for example emails[type eq "work"].value). Returns
 * ["uri" => ?string, "attr" => string, "sub" => ?string, "filter" => ?array (filter AST)].
 * Throws InvalidArgumentException for any other form.
 */
function scim_patch_parse_path(string $path): array
{
    if (strlen($path) > SCIM_FILTER_MAX_LENGTH) {
        throw new InvalidArgumentException("path is too long");
    }
    $st = ["tokens" => scim_filter_tokenize($path), "pos" => 0, "logical" => 0];
    $first = scim_filter_peek($st);
    if ($first === null || $first["t"] !== "word") {
        throw new InvalidArgumentException("path must start with an attribute name");
    }
    $st["pos"]++;
    $parsed = scim_filter_parse_attr_path((string) $first["v"]);
    if (scim_filter_peek_type($st) === "[") {
        if ($parsed["sub"] !== null) {
            throw new InvalidArgumentException("a value filter must follow a top-level attribute");
        }
        $st["pos"]++;
        $parsed["filter"] = scim_filter_parse_or($st, 1, true);
        if (scim_filter_peek_type($st) !== "]") {
            throw new InvalidArgumentException("missing ']'");
        }
        $st["pos"]++;
        if (scim_filter_peek_type($st) === "sub") {
            $parsed["sub"] = (string) $st["tokens"][$st["pos"]]["v"];
            $st["pos"]++;
        }
    }
    if ($st["pos"] !== count($st["tokens"])) {
        throw new InvalidArgumentException("unexpected text after the attribute path");
    }
    return $parsed;
}

/**
 * Strict boolean for authorization-relevant PATCH values. Accepts JSON booleans, 0/1 and
 * the strings true/false/1/0/yes/no (Entra ID sends "True"/"False"); null otherwise.
 */
function scim_patch_bool(mixed $value): ?bool
{
    if (is_bool($value)) {
        return $value;
    }
    if ($value === 0 || $value === 1) {
        return $value === 1;
    }
    if (is_string($value)) {
        $v = strtolower(trim($value));
        if (in_array($v, ["true", "1", "yes"], true)) {
            return true;
        }
        if (in_array($v, ["false", "0", "no"], true)) {
            return false;
        }
    }
    return null;
}

/**
 * Role values from a PATCH value: a string, a role object ({"value": ...}) or a list of
 * either. Any other shape answers 400, so a role change is never silently dropped.
 */
function scim_patch_role_values(mixed $value): array
{
    if ($value === null) {
        return [];
    }
    if (is_string($value) || is_int($value) || is_float($value)) {
        return normalize_string_list([(string) $value]);
    }
    if (!is_array($value)) {
        scim_error_response(400, "roles values must be strings or objects with a value", "invalidValue");
    }
    $items = array_is_list($value) ? $value : [$value];
    $out = [];
    foreach ($items as $item) {
        $v = is_array($item) ? ($item["value"] ?? null) : $item;
        if (!is_string($v) && !is_int($v) && !is_float($v)) {
            scim_error_response(400, "roles values must be strings or objects with a value", "invalidValue");
        }
        $out[] = trim((string) $v);
    }
    return normalize_string_list($out);
}

/**
 * PATCH of roles (stored as attributes.roles, released as the OIDC/SAML "roles" claim).
 * Supports add, replace and remove on "roles", "roles.value", "roles[filter]" and
 * "roles[filter].value". Only role values are stored, so a filter that tests anything
 * else (primary, type) cannot be evaluated and selects every stored role: a removal then
 * revokes them all (fail closed) and a replacement leaves only the new value, which is
 * what single-role clients such as Entra ID's SingleAppRoleAssignment intend.
 */
function scim_patch_user_roles(
    array &$attrs,
    bool &$attrsChanged,
    string $op,
    array $path,
    mixed $value
): void {
    $sub = $path["sub"] !== null ? strtolower($path["sub"]) : null;
    if ($sub !== null && !in_array($sub, ["value", "display", "type", "primary"], true)) {
        scim_error_response(400, "Unsupported roles sub-attribute in PATCH path", "invalidPath");
    }
    if ($sub !== null && $sub !== "value") {
        return; // display, type and primary are not stored for roles
    }
    if ($value === null && $op !== "remove") {
        scim_error_response(400, "roles $op needs a value", "invalidValue");
    }
    $current = normalize_string_list($attrs["roles"] ?? []);
    $incoming = scim_patch_role_values($value);

    if ($path["filter"] === null) {
        if ($op === "add") {
            $new = normalize_string_list(array_merge($current, $incoming));
        } elseif ($op === "replace") {
            $new = $incoming;
        } else {
            $new = $value === null ? [] : array_values(array_diff($current, $incoming));
        }
    } else {
        if ($op === "add") {
            scim_error_response(400, "add does not accept a value filter in the path", "invalidPath");
        }
        $precise = array_diff(scim_filter_referenced_attrs($path["filter"]), ["value", "display"]) === [];
        $kept = [];
        $matched = 0;
        foreach ($current as $role) {
            if (!$precise || scim_filter_eval($path["filter"], ["value" => $role, "display" => $role])) {
                $matched++;
                continue;
            }
            $kept[] = $role;
        }
        if ($op === "remove") {
            $new = $kept;
        } else {
            if ($current !== [] && $matched === 0) {
                scim_error_response(400, "No stored role matches the PATCH path filter", "noTarget");
            }
            $new = normalize_string_list(array_merge($kept, $incoming));
        }
    }

    if ($new === []) {
        unset($attrs["roles"]);
    } else {
        $attrs["roles"] = array_values($new);
    }
    $attrsChanged = true;
}

/**
 * PATCH of emails. The directory stores one address, presented as the primary work
 * email, so a value filter is evaluated against that slot: a filter for another type
 * (home, other) addresses nothing that is stored and is ignored, while a value-based
 * filter that matches nothing is a noTarget error. Removing the stored address empties
 * it, which the directory then rejects because the email is required.
 */
function scim_patch_user_emails(
    array &$patchInput,
    string $op,
    array $path,
    mixed $value,
    array $existingUser
): void {
    $sub = $path["sub"] !== null ? strtolower($path["sub"]) : null;
    if ($sub !== null && !in_array($sub, ["value", "type", "primary", "display"], true)) {
        scim_error_response(400, "Unsupported emails sub-attribute in PATCH path", "invalidPath");
    }
    if ($sub !== null && $sub !== "value") {
        return; // type, primary and display of the single stored address are fixed
    }
    $current = (string) ($patchInput["email"] ?? ($existingUser["email"] ?? ""));
    if ($path["filter"] !== null) {
        $slot = ["value" => $current, "type" => "work", "primary" => true];
        if (!scim_filter_eval($path["filter"], $slot)) {
            $slotOnly = array_diff(
                scim_filter_referenced_attrs($path["filter"]),
                ["type", "primary", "display"]
            ) === [];
            if ($op === "remove" || $slotOnly) {
                return;
            }
            scim_error_response(400, "No stored email matches the PATCH path filter", "noTarget");
        }
    }
    if ($op === "remove") {
        if ($path["filter"] === null && $sub === null && $value !== null) {
            $items = is_array($value) && array_is_list($value) ? $value : [$value];
            $listed = [];
            foreach ($items as $item) {
                $v = is_array($item) ? ($item["value"] ?? null) : $item;
                if (is_string($v)) {
                    $listed[] = strtolower(trim($v));
                }
            }
            if (!in_array(strtolower($current), $listed, true)) {
                return; // removing an address that is not stored changes nothing
            }
        }
        $patchInput["email"] = "";
        return;
    }
    if (is_string($value)) {
        $email = trim($value);
    } elseif (is_array($value) && !array_is_list($value)) {
        $email = is_string($value["value"] ?? null) ? trim($value["value"]) : "";
    } elseif (is_array($value)) {
        $email = scim_extract_primary_value($value);
    } else {
        $email = "";
    }
    if ($email === "") {
        scim_error_response(400, "emails needs a non-empty address value", "invalidValue");
    }
    $patchInput["email"] = $email;
}

function scim_apply_single_user_path_mutation(
    array &$patchInput,
    array &$attrs,
    bool &$attrsChanged,
    string $op,
    string $rawPath,
    mixed $value,
    array $existingUser = []
): void {
    $rawPath = trim($rawPath);
    $enterpriseKeys = ["employeeNumber", "costCenter", "organization", "division", "department", "manager"];

    // A path naming the enterprise extension itself carries an object of its attributes.
    if (strcasecmp($rawPath, SCIM_SCHEMA_ENTERPRISE_USER) === 0) {
        if (is_array($value) && !array_is_list($value)) {
            foreach ($value as $ek => $ev) {
                scim_apply_single_user_path_mutation(
                    $patchInput,
                    $attrs,
                    $attrsChanged,
                    $op,
                    SCIM_SCHEMA_ENTERPRISE_USER . ":" . $ek,
                    $ev,
                    $existingUser
                );
            }
        } elseif ($op === "remove" && $value === null) {
            foreach ($enterpriseKeys as $ek) {
                if (array_key_exists($ek, $attrs)) {
                    unset($attrs[$ek]);
                    $attrsChanged = true;
                }
            }
        }
        return;
    }

    try {
        $p = scim_patch_parse_path($rawPath);
    } catch (InvalidArgumentException $e) {
        scim_error_response(400, "Invalid PATCH path: " . $e->getMessage(), "invalidPath");
    }
    $sub = $p["sub"] !== null ? strtolower($p["sub"]) : null;
    $hasFilter = $p["filter"] !== null;

    if ($p["uri"] !== null) {
        // Enterprise User extension; other extension schemas are not stored by this server.
        if (strcasecmp($p["uri"], SCIM_SCHEMA_ENTERPRISE_USER) !== 0 || $hasFilter) {
            return;
        }
        $k = null;
        foreach ($enterpriseKeys as $ek) {
            if (strcasecmp($ek, $p["attr"]) === 0) {
                $k = $ek;
                break;
            }
        }
        if ($k === null || ($sub !== null && !($k === "manager" && $sub === "value"))) {
            return;
        }
        if ($op === "remove") {
            unset($attrs[$k]);
        } elseif (is_array($value) && isset($value["value"]) && is_scalar($value["value"])) {
            $attrs[$k] = trim((string) $value["value"]);
        } else {
            $attrs[$k] = is_scalar($value) ? trim((string) $value) : "";
        }
        $attrsChanged = true;
        return;
    }

    $attr = strtolower($p["attr"]);

    // Attributes that decide who can sign in, or with which rights, fail closed: an
    // unsupported path or value answers 400 instead of being dropped with a 200.
    if ($attr === "active") {
        if ($hasFilter || $sub !== null) {
            scim_error_response(400, "Unsupported PATCH path for active", "invalidPath");
        }
        if ($op === "remove") {
            $patchInput["status"] = "suspended";
            return;
        }
        $active = scim_patch_bool($value);
        if ($active === null) {
            scim_error_response(400, "active must be a boolean", "invalidValue");
        }
        $patchInput["status"] = $active ? "active" : "suspended";
        return;
    }
    if ($attr === "username") {
        if ($hasFilter || $sub !== null) {
            scim_error_response(400, "Unsupported PATCH path for userName", "invalidPath");
        }
        if ($op === "remove") {
            // userName is required: directory_update_user() rejects the empty value.
            $patchInput["username"] = "";
            return;
        }
        if (!is_string($value) && !is_int($value)) {
            scim_error_response(400, "userName must be a string", "invalidValue");
        }
        $userName = trim((string) $value);
        if ($userName === "") {
            scim_error_response(400, "userName must not be empty", "invalidValue");
        }
        $patchInput["username"] = $userName;
        return;
    }
    if ($attr === "password") {
        if ($hasFilter || $sub !== null) {
            scim_error_response(400, "Unsupported PATCH path for password", "invalidPath");
        }
        if ($op === "remove") {
            unset($patchInput["password"]);
            $patchInput["clear_password"] = true;
            return;
        }
        if (!is_string($value) || $value === "") {
            scim_error_response(400, "password must be a non-empty string", "invalidValue");
        }
        unset($patchInput["clear_password"]);
        $patchInput["password"] = $value;
        return;
    }
    if ($attr === "emails") {
        scim_patch_user_emails($patchInput, $op, $p, $value, $existingUser);
        return;
    }
    if ($attr === "roles") {
        scim_patch_user_roles($attrs, $attrsChanged, $op, $p, $value);
        return;
    }
    if ($attr === "groups") {
        scim_error_response(
            400,
            "groups is read-only on User resources; change membership through /Groups",
            "mutability"
        );
    }
    if ($attr === "members") {
        scim_error_response(400, "members is not a User attribute", "invalidPath");
    }

    // Profile attributes keep the lenient handling Microsoft Entra ID and Okta rely on.
    $text = is_scalar($value) ? trim((string) $value) : "";
    if ($attr === "displayname") {
        if (!$hasFilter && $sub === null) {
            $patchInput["display_name"] = $op === "remove" ? "" : $text;
        }
        return;
    }
    if ($attr === "name") {
        if ($hasFilter) {
            return;
        }
        if ($sub === "formatted") {
            $patchInput["display_name"] = $op === "remove" ? "" : $text;
        } elseif ($sub === "givenname") {
            $patchInput["given_name"] = $op === "remove" ? "" : $text;
        } elseif ($sub === "familyname") {
            $patchInput["family_name"] = $op === "remove" ? "" : $text;
        } elseif ($sub === null && is_array($value)) {
            if (array_key_exists("givenName", $value)) {
                $patchInput["given_name"] = is_scalar($value["givenName"]) ? trim((string) $value["givenName"]) : "";
            }
            if (array_key_exists("familyName", $value)) {
                $patchInput["family_name"] = is_scalar($value["familyName"]) ? trim((string) $value["familyName"]) : "";
            }
            if (array_key_exists("formatted", $value) && !isset($patchInput["display_name"])) {
                $patchInput["display_name"] = is_scalar($value["formatted"]) ? trim((string) $value["formatted"]) : "";
            }
        }
        return;
    }
    if ($attr === "externalid") {
        if (!$hasFilter && $sub === null) {
            $patchInput["external_id"] = $op === "remove" ? "" : $text;
        }
        return;
    }
    if ($attr === "title") {
        if (!$hasFilter && $sub === null) {
            if ($op === "remove") {
                unset($attrs["title"]);
            } else {
                $attrs["title"] = $text;
            }
            $attrsChanged = true;
        }
        return;
    }
    if ($attr === "phonenumbers") {
        if ($op === "remove") {
            $patchInput["mobile_phone"] = "";
        } else {
            $patchInput["mobile_phone"] = is_scalar($value)
                ? trim((string) $value)
                : scim_extract_primary_value($value);
        }
        return;
    }
    // Anything else (addresses, preferredLanguage, locale, entitlements, ...) is not stored here.
}

function scim_apply_user_patch_operations(
    array $existingUser,
    array $operations
): array {
    $patchInput = [];
    $attrs = is_array($existingUser["attributes"] ?? null)
        ? $existingUser["attributes"]
        : [];
    $attrsChanged = false;

    foreach ($operations as $opItem) {
        [$op, $path, $value] = scim_patch_read_operation($opItem);

        if ($path === "" || strcasecmp($path, SCIM_SCHEMA_USER) === 0) {
            // Pathless object map (used heavily by Microsoft Entra ID & Okta)
            foreach (scim_patch_pathless_value($value) as $k => $v) {
                $k = (string) $k;
                if (strcasecmp($k, SCIM_SCHEMA_ENTERPRISE_USER) === 0 && is_array($v)) {
                    foreach ($v as $ek => $ev) {
                        scim_apply_single_user_path_mutation(
                            $patchInput,
                            $attrs,
                            $attrsChanged,
                            $op,
                            SCIM_SCHEMA_ENTERPRISE_USER . ":" . $ek,
                            $ev,
                            $existingUser
                        );
                    }
                } else {
                    scim_apply_single_user_path_mutation(
                        $patchInput,
                        $attrs,
                        $attrsChanged,
                        $op,
                        $k,
                        $v,
                        $existingUser
                    );
                }
            }
            continue;
        }
        scim_apply_single_user_path_mutation(
            $patchInput,
            $attrs,
            $attrsChanged,
            $op,
            $path,
            $value,
            $existingUser
        );
    }

    if ($attrsChanged) {
        $patchInput["attributes"] = $attrs;
    }
    return $patchInput;
}

/**
 * True when directory_update_user($input) would change the stored user. A PATCH or PUT
 * that changes nothing is answered without a write, so updated_at is not bumped and no
 * outbound sync is triggered.
 */
function scim_user_input_changes_anything(array $existing, array $input): bool
{
    if (array_key_exists("groups", $input)) {
        return true;
    }
    if (isset($input["password"]) && (string) $input["password"] !== "") {
        return true;
    }
    if (!empty($input["clear_password"]) && !empty($existing["has_password"])) {
        return true;
    }
    $username = isset($input["username"]) ? trim((string) $input["username"]) : (string) $existing["username"];
    $email = isset($input["email"]) ? trim((string) $input["email"]) : (string) $existing["email"];
    if ($username !== (string) $existing["username"] || $email !== (string) $existing["email"]) {
        return true;
    }
    foreach (["given_name", "family_name", "mobile_phone", "external_id"] as $k) {
        if (array_key_exists($k, $input) && trim((string) $input[$k]) !== (string) ($existing[$k] ?? "")) {
            return true;
        }
    }
    if (array_key_exists("display_name", $input)) {
        $given = array_key_exists("given_name", $input) ? trim((string) $input["given_name"]) : (string) ($existing["given_name"] ?? "");
        $family = array_key_exists("family_name", $input) ? trim((string) $input["family_name"]) : (string) ($existing["family_name"] ?? "");
        $displayName = trim((string) $input["display_name"]);
        if ($displayName === "") {
            $full = trim($given . " " . $family);
            $displayName = $full !== "" ? $full : $username;
        }
        if ($displayName !== (string) ($existing["display_name"] ?? "")) {
            return true;
        }
    }
    if (
        isset($input["status"]) &&
        in_array($input["status"], ["active", "suspended"], true) &&
        $input["status"] !== (string) ($existing["status"] ?? "active")
    ) {
        return true;
    }
    if (
        array_key_exists("attributes", $input) &&
        is_array($input["attributes"]) &&
        $input["attributes"] !== (is_array($existing["attributes"] ?? null) ? $existing["attributes"] : [])
    ) {
        return true;
    }
    return false;
}

/**
 * True when a group-restricted SCIM token may use this group name (always true for an
 * unrestricted token).
 */
function scim_group_name_in_scope(string $name, array $filterGroups): bool
{
    if (empty($filterGroups)) {
        return true;
    }
    $n = strtolower(trim($name));
    foreach ($filterGroups as $g) {
        if (is_scalar($g) && strtolower(trim((string) $g)) === $n) {
            return true;
        }
    }
    return false;
}

/**
 * Resolves member references (ids, or legacy username/email values) to user ids of the
 * owner's directory. For a group-restricted token ($filterGroups) only users already in
 * its scope can be referenced; others are skipped exactly like unknown ids, so a group
 * write can never pull an outside user into scope, or reveal that the user exists.
 */
function scim_extract_member_ids_from_value(
    string $storePath,
    string $owner,
    mixed $membersVal,
    array $filterGroups = []
): array {
    if (!is_array($membersVal)) {
        return [];
    }
    // Single member object {"value": "..."} vs list [{"value": "..."}]
    if (isset($membersVal["value"])) {
        $membersVal = [$membersVal];
    }
    $ids = [];
    foreach ($membersVal as $m) {
        $raw = "";
        if (is_array($m) && isset($m["value"]) && is_scalar($m["value"])) {
            $raw = trim((string) $m["value"]);
        } elseif (is_string($m)) {
            $raw = trim($m);
        }
        if ($raw === "") {
            continue;
        }
        $u = directory_get_user_by_id($storePath, $raw, $owner);
        if (!$u) {
            $u = directory_find_user_by_identifier($storePath, $owner, $raw);
        }
        if ($u && (empty($filterGroups) || directory_user_matches_assigned_groups($u, $filterGroups))) {
            $ids[] = (string) $u["id"];
        }
    }
    return array_values(array_unique($ids));
}

/** Sorted, de-duplicated id list, for comparing membership sets. */
function scim_id_set(array $ids): array
{
    $set = array_values(array_unique(array_map("strval", $ids)));
    sort($set, SORT_STRING);
    return $set;
}

function scim_apply_group_patch_operations(
    string $storePath,
    string $owner,
    array $existingGroup,
    array $operations,
    array $filterGroups = []
): array {
    $displayName = (string) $existingGroup["display_name"];
    $externalId = (string) ($existingGroup["external_id"] ?? "");
    $memberIds = array_map(fn($m) => (string) $m["id"], $existingGroup["members"] ?? []);
    $memberDisplay = [];
    foreach ($existingGroup["members"] ?? [] as $m) {
        $memberDisplay[(string) $m["id"]] = (string) ($m["username"] ?? "");
    }

    $readDisplayName = static function (string $op, mixed $v): string {
        if ($op === "remove") {
            return ""; // displayName is required: rejected below
        }
        if (!is_string($v) && !is_int($v)) {
            scim_error_response(400, "displayName must be a string", "invalidValue");
        }
        return trim((string) $v);
    };
    $applyMembers = static function (string $op, mixed $v) use (&$memberIds, $storePath, $owner, $filterGroups): void {
        if ($v === null) {
            if ($op === "add") {
                scim_error_response(400, "members add needs a value", "invalidValue");
            }
            $memberIds = [];
            return;
        }
        if (!is_array($v)) {
            scim_error_response(400, "members must be a list of objects with a value", "invalidValue");
        }
        $incoming = scim_extract_member_ids_from_value($storePath, $owner, $v, $filterGroups);
        if ($op === "add") {
            $memberIds = array_values(array_unique(array_merge($memberIds, $incoming)));
        } elseif ($op === "replace") {
            $memberIds = $incoming;
        } else {
            $memberIds = array_values(array_diff($memberIds, $incoming));
        }
    };

    foreach ($operations as $opItem) {
        [$op, $path, $value] = scim_patch_read_operation($opItem);

        if ($path === "" || strcasecmp($path, SCIM_SCHEMA_GROUP) === 0) {
            foreach (scim_patch_pathless_value($value) as $k => $v) {
                $kl = strtolower((string) $k);
                if ($kl === "displayname") {
                    $displayName = $readDisplayName($op, $v);
                } elseif ($kl === "externalid") {
                    $externalId = $op === "remove" ? "" : (is_scalar($v) ? trim((string) $v) : "");
                } elseif ($kl === "members") {
                    $applyMembers($op, $v);
                }
                // Other attributes are not stored for groups.
            }
            continue;
        }

        try {
            $p = scim_patch_parse_path($path);
        } catch (InvalidArgumentException $e) {
            scim_error_response(400, "Invalid PATCH path: " . $e->getMessage(), "invalidPath");
        }
        if ($p["uri"] !== null) {
            continue; // extension attributes are not stored for groups
        }
        $attr = strtolower($p["attr"]);
        if ($attr === "displayname") {
            if ($p["filter"] !== null || $p["sub"] !== null) {
                scim_error_response(400, "Unsupported PATCH path for displayName", "invalidPath");
            }
            $displayName = $readDisplayName($op, $value);
        } elseif ($attr === "externalid") {
            if ($p["filter"] === null && $p["sub"] === null) {
                $externalId = $op === "remove" ? "" : (is_scalar($value) ? trim((string) $value) : "");
            }
        } elseif ($attr === "members") {
            if ($p["sub"] !== null) {
                scim_error_response(400, "Unsupported PATCH path for members", "invalidPath");
            }
            if ($p["filter"] === null) {
                $applyMembers($op, $value);
                continue;
            }
            if ($op !== "remove") {
                scim_error_response(400, "Only remove accepts a members value filter", "invalidPath");
            }
            // Any valid filter over the member objects, e.g. members[value eq "a" or value eq "b"].
            $filterAst = $p["filter"];
            $kept = [];
            foreach ($memberIds as $mid) {
                if (!array_key_exists($mid, $memberDisplay)) {
                    $mu = directory_get_user_by_id($storePath, $mid, $owner);
                    $memberDisplay[$mid] = $mu ? (string) $mu["username"] : "";
                }
                $memberObj = ["value" => $mid, "display" => $memberDisplay[$mid], "type" => "User"];
                if (!scim_filter_eval($filterAst, $memberObj)) {
                    $kept[] = $mid;
                }
            }
            $memberIds = $kept;
        }
        // Other attributes are not stored for groups.
    }

    return [
        "display_name" => $displayName,
        "external_id" => $externalId,
        "member_ids" => $memberIds,
    ];
}

// ---------- RFC 7644 SCIM Filter Engine & Attribute Projection ----------
// A filter is tokenized in one pass and parsed once per request into an AST by a
// recursive-descent parser with length, nesting and operator limits; each resource is then
// evaluated against the AST. Anything outside the supported grammar is a 400 invalidFilter.
//
//   FILTER    = OR
//   OR        = AND *("or" AND)
//   AND       = NOT *("and" NOT)
//   NOT       = "not" NOT / PRIMARY
//   PRIMARY   = "(" FILTER ")" / attrPath ["[" valFilter "]" [subAttr]] (op value / "pr")
//               / valuePath
//   value     = JSON string / number / true / false / null

/**
 * Splits a filter or PATCH path into tokens in one linear pass. Token types: "(", ")",
 * "[", "]", "word" (attribute paths and keywords), "sub" (".name" after "]"), "str" (JSON
 * string; single-quoted strings are accepted for compatibility) and "num".
 * Throws InvalidArgumentException on anything else.
 */
function scim_filter_tokenize(string $s): array
{
    $tokens = [];
    $len = strlen($s);
    $i = 0;
    while ($i < $len) {
        $c = $s[$i];
        if ($c === " " || $c === "\t" || $c === "\r" || $c === "\n") {
            $i++;
            continue;
        }
        if ($c === "(" || $c === ")" || $c === "[" || $c === "]") {
            $tokens[] = ["t" => $c, "v" => $c];
            $i++;
            continue;
        }
        if ($c === '"') {
            if (preg_match('/\G"(?:[^"\\\\\x00-\x1F]++|\\\\(?:["\\\\\/bfnrt]|u[0-9A-Fa-f]{4}))*+"/', $s, $m, 0, $i) !== 1) {
                throw new InvalidArgumentException("invalid string literal");
            }
            $decoded = json_decode($m[0]);
            if (!is_string($decoded)) {
                throw new InvalidArgumentException("invalid string literal");
            }
            $tokens[] = ["t" => "str", "v" => $decoded];
            $i += strlen($m[0]);
            continue;
        }
        if ($c === "'") {
            if (preg_match('/\G\'((?:[^\'\\\\]++|\\\\.)*+)\'/s', $s, $m, 0, $i) !== 1) {
                throw new InvalidArgumentException("invalid string literal");
            }
            $tokens[] = ["t" => "str", "v" => (string) preg_replace('/\\\\(.)/s', '$1', $m[1])];
            $i += strlen($m[0]);
            continue;
        }
        if ($c === ".") {
            if (preg_match('/\G\.([A-Za-z][A-Za-z0-9_\-]*|\$ref)/', $s, $m, 0, $i) !== 1) {
                throw new InvalidArgumentException("invalid sub-attribute");
            }
            $tokens[] = ["t" => "sub", "v" => $m[1]];
            $i += strlen($m[0]);
            continue;
        }
        if (preg_match('/\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?(?![A-Za-z0-9_.:$\-])/', $s, $m, 0, $i) === 1) {
            $tokens[] = [
                "t" => "num",
                "v" => preg_match('/[.eE]/', $m[0]) === 1 ? (float) $m[0] : (int) $m[0],
            ];
            $i += strlen($m[0]);
            continue;
        }
        if (preg_match('/\G[A-Za-z][A-Za-z0-9_.:$\-]*/', $s, $m, 0, $i) === 1) {
            $tokens[] = ["t" => "word", "v" => $m[0]];
            $i += strlen($m[0]);
            continue;
        }
        throw new InvalidArgumentException("unexpected character at offset $i");
    }
    return $tokens;
}

function scim_filter_peek(array $st, int $ahead = 0): ?array
{
    return $st["tokens"][$st["pos"] + $ahead] ?? null;
}

function scim_filter_peek_type(array $st, int $ahead = 0): string
{
    $tok = $st["tokens"][$st["pos"] + $ahead] ?? null;
    return $tok === null ? "" : (string) $tok["t"];
}

function scim_filter_is_keyword(?array $tok, string $keyword): bool
{
    return $tok !== null && $tok["t"] === "word" && strcasecmp((string) $tok["v"], $keyword) === 0;
}

function scim_filter_is_operator_word(string $word): bool
{
    return in_array(
        strtolower($word),
        ["eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le", "pr", "and", "or"],
        true
    );
}

function scim_filter_check_depth(int $depth): void
{
    if ($depth > SCIM_FILTER_MAX_DEPTH) {
        throw new InvalidArgumentException("nesting exceeds " . SCIM_FILTER_MAX_DEPTH . " levels");
    }
}

function scim_filter_count_logical(array &$st): void
{
    $st["logical"]++;
    if ($st["logical"] > SCIM_FILTER_MAX_LOGICAL_OPS) {
        throw new InvalidArgumentException(
            "more than " . SCIM_FILTER_MAX_LOGICAL_OPS . " and/or operators"
        );
    }
}

/**
 * Parses an attribute path ([schema URI ":"] name ["." subAttr]). The core User and Group
 * schema URIs are dropped; other URIs select an extension object.
 */
function scim_filter_parse_attr_path(string $word): array
{
    $uri = null;
    $rest = $word;
    $colon = strrpos($word, ":");
    if ($colon !== false) {
        $uri = substr($word, 0, $colon);
        $rest = substr($word, $colon + 1);
        if (preg_match('/^urn:[A-Za-z0-9][A-Za-z0-9.:_\-]*$/iD', $uri) !== 1) {
            throw new InvalidArgumentException("invalid schema URI in attribute path");
        }
        if (strcasecmp($uri, SCIM_SCHEMA_USER) === 0 || strcasecmp($uri, SCIM_SCHEMA_GROUP) === 0) {
            $uri = null;
        }
    }
    if (preg_match('/^([A-Za-z][A-Za-z0-9_\-]*)(?:\.([A-Za-z][A-Za-z0-9_\-]*|\$ref))?$/D', $rest, $m) !== 1) {
        throw new InvalidArgumentException("invalid attribute path");
    }
    return [
        "uri" => $uri,
        "attr" => $m[1],
        "sub" => isset($m[2]) && $m[2] !== "" ? $m[2] : null,
        "filter" => null,
    ];
}

/**
 * Parses a filter once into an AST. Throws InvalidArgumentException for filters longer
 * than SCIM_FILTER_MAX_LENGTH bytes, nested deeper than SCIM_FILTER_MAX_DEPTH, with more
 * than SCIM_FILTER_MAX_LOGICAL_OPS and/or operators, or outside the supported grammar.
 */
function scim_filter_parse(string $filter): array
{
    if (strlen($filter) > SCIM_FILTER_MAX_LENGTH) {
        throw new InvalidArgumentException("filter exceeds " . SCIM_FILTER_MAX_LENGTH . " bytes");
    }
    $st = ["tokens" => scim_filter_tokenize($filter), "pos" => 0, "logical" => 0];
    if ($st["tokens"] === []) {
        throw new InvalidArgumentException("filter is empty");
    }
    $ast = scim_filter_parse_or($st, 0, false);
    if ($st["pos"] < count($st["tokens"])) {
        throw new InvalidArgumentException("unexpected token");
    }
    return $ast;
}

function scim_filter_parse_or(array &$st, int $depth, bool $inValuePath): array
{
    $args = [scim_filter_parse_and($st, $depth, $inValuePath)];
    while (scim_filter_is_keyword(scim_filter_peek($st), "or")) {
        $st["pos"]++;
        scim_filter_count_logical($st);
        $args[] = scim_filter_parse_and($st, $depth, $inValuePath);
    }
    return count($args) === 1 ? $args[0] : ["op" => "or", "args" => $args];
}

function scim_filter_parse_and(array &$st, int $depth, bool $inValuePath): array
{
    $args = [scim_filter_parse_not($st, $depth, $inValuePath)];
    while (scim_filter_is_keyword(scim_filter_peek($st), "and")) {
        $st["pos"]++;
        scim_filter_count_logical($st);
        $args[] = scim_filter_parse_not($st, $depth, $inValuePath);
    }
    return count($args) === 1 ? $args[0] : ["op" => "and", "args" => $args];
}

function scim_filter_parse_not(array &$st, int $depth, bool $inValuePath): array
{
    $next = scim_filter_peek($st, 1);
    if (
        scim_filter_is_keyword(scim_filter_peek($st), "not") &&
        $next !== null &&
        ($next["t"] === "(" || ($next["t"] === "word" && !scim_filter_is_operator_word((string) $next["v"])))
    ) {
        scim_filter_check_depth($depth + 1);
        $st["pos"]++;
        return ["op" => "not", "x" => scim_filter_parse_not($st, $depth + 1, $inValuePath)];
    }
    return scim_filter_parse_primary($st, $depth, $inValuePath);
}

function scim_filter_parse_primary(array &$st, int $depth, bool $inValuePath): array
{
    $tok = scim_filter_peek($st);
    if ($tok === null) {
        throw new InvalidArgumentException("filter ends unexpectedly");
    }
    if ($tok["t"] === "(") {
        scim_filter_check_depth($depth + 1);
        $st["pos"]++;
        $inner = scim_filter_parse_or($st, $depth + 1, $inValuePath);
        if (scim_filter_peek_type($st) !== ")") {
            throw new InvalidArgumentException("missing ')'");
        }
        $st["pos"]++;
        return $inner;
    }
    if ($tok["t"] !== "word") {
        throw new InvalidArgumentException("expected an attribute name");
    }
    $st["pos"]++;
    $path = scim_filter_parse_attr_path((string) $tok["v"]);

    if (scim_filter_peek_type($st) === "[") {
        if ($inValuePath) {
            throw new InvalidArgumentException("nested value filters are not supported");
        }
        if ($path["sub"] !== null) {
            throw new InvalidArgumentException("a value filter must follow a top-level attribute");
        }
        scim_filter_check_depth($depth + 1);
        $st["pos"]++;
        $path["filter"] = scim_filter_parse_or($st, $depth + 1, true);
        if (scim_filter_peek_type($st) !== "]") {
            throw new InvalidArgumentException("missing ']'");
        }
        $st["pos"]++;
        if (scim_filter_peek_type($st) === "sub") {
            $path["sub"] = (string) $st["tokens"][$st["pos"]]["v"];
            $st["pos"]++;
        }
        $after = scim_filter_peek($st);
        $comparisonFollows = $after !== null && $after["t"] === "word" &&
            in_array(strtolower((string) $after["v"]), ["eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le", "pr"], true);
        if ($path["sub"] === null && !$comparisonFollows) {
            return ["op" => "vp", "path" => $path];
        }
    }

    $opTok = scim_filter_peek($st);
    if ($opTok === null || $opTok["t"] !== "word") {
        throw new InvalidArgumentException("expected an operator after an attribute");
    }
    $op = strtolower((string) $opTok["v"]);
    $st["pos"]++;
    if ($op === "pr") {
        return ["op" => "pr", "path" => $path];
    }
    if (!in_array($op, ["eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le"], true)) {
        throw new InvalidArgumentException("unsupported operator");
    }
    $valTok = scim_filter_peek($st);
    if ($valTok !== null && ($valTok["t"] === "str" || $valTok["t"] === "num")) {
        $value = $valTok["v"];
    } elseif ($valTok !== null && $valTok["t"] === "word" && in_array(strtolower((string) $valTok["v"]), ["true", "false", "null"], true)) {
        $word = strtolower((string) $valTok["v"]);
        $value = $word === "null" ? null : $word === "true";
    } else {
        throw new InvalidArgumentException("comparison values must be JSON strings, numbers, true, false or null");
    }
    $st["pos"]++;
    if ((is_bool($value) || $value === null) && $op !== "eq" && $op !== "ne") {
        throw new InvalidArgumentException("$op cannot compare with true, false or null");
    }
    return [
        "op" => "cmp",
        "cmp" => $op,
        "path" => $path,
        "value" => $value,
        // RFC 7643: id and externalId are caseExact; other supported attributes are not.
        "exact" => $path["uri"] === null && $path["sub"] === null && $path["filter"] === null &&
            in_array(strtolower($path["attr"]), ["id", "externalid"], true),
    ];
}

/** Lowercase names of the attributes a filter AST tests (used for valuePath semantics). */
function scim_filter_referenced_attrs(array $node): array
{
    $op = $node["op"];
    if ($op === "and" || $op === "or") {
        $out = [];
        foreach ($node["args"] as $arg) {
            foreach (scim_filter_referenced_attrs($arg) as $name) {
                $out[$name] = true;
            }
        }
        return array_map("strval", array_keys($out));
    }
    if ($op === "not") {
        return scim_filter_referenced_attrs($node["x"]);
    }
    $p = $node["path"];
    return [strtolower(
        ($p["uri"] !== null ? $p["uri"] . ":" : "") .
            $p["attr"] .
            ($p["sub"] !== null ? "." . $p["sub"] : "")
    )];
}

function scim_case_insensitive_get(array $arr, string $key): mixed
{
    if (array_key_exists($key, $arr)) {
        return $arr[$key];
    }
    foreach ($arr as $k => $v) {
        if (strcasecmp((string) $k, $key) === 0) {
            return $v;
        }
    }
    return null;
}

/**
 * Values an attribute path selects in a resource (a list; empty when absent). Multi-valued
 * complex attributes yield their "value" sub-attributes; a value filter keeps only the
 * matching elements.
 */
function scim_filter_resolve_path(array $path, array $resource): array
{
    $base = $resource;
    if ($path["uri"] !== null) {
        $ext = scim_case_insensitive_get($resource, (string) $path["uri"]);
        if (!is_array($ext)) {
            return [];
        }
        $base = $ext;
    }
    $val = scim_case_insensitive_get($base, (string) $path["attr"]);
    if ($val === null) {
        return [];
    }
    $sub = $path["sub"];
    if ($path["filter"] !== null || $sub !== null) {
        $items = is_array($val) && array_is_list($val) ? $val : [$val];
        if ($path["filter"] !== null) {
            $items = array_values(array_filter(
                $items,
                static fn($it) => is_array($it) && scim_filter_eval($path["filter"], $it)
            ));
            if ($sub === null) {
                return $items;
            }
        }
        $out = [];
        foreach ($items as $it) {
            if (!is_array($it)) {
                continue;
            }
            $sv = scim_case_insensitive_get($it, (string) $sub);
            if ($sv === null) {
                continue;
            }
            if (is_array($sv) && array_is_list($sv)) {
                foreach ($sv as $x) {
                    $out[] = $x;
                }
            } else {
                $out[] = $sv;
            }
        }
        return $out;
    }
    if (is_array($val) && array_is_list($val)) {
        $flat = [];
        foreach ($val as $item) {
            $flat[] = is_array($item) && isset($item["value"]) ? $item["value"] : $item;
        }
        return $flat;
    }
    return [$val];
}

/**
 * Compares one resource value with a filter literal ($op is never "ne"; the caller
 * negates "eq" across all values).
 */
function scim_filter_compare(mixed $actual, string $op, mixed $expected, bool $caseExact): bool
{
    if ($expected === null) {
        return $op === "eq" && $actual === null;
    }
    if (is_bool($expected)) {
        if (is_bool($actual)) {
            return $actual === $expected;
        }
        if (is_string($actual)) {
            $a = strtolower(trim($actual));
            if ($a === "true" || $a === "false") {
                return ($a === "true") === $expected;
            }
        }
        return false;
    }
    if ($actual === null || is_array($actual) || is_object($actual)) {
        return false;
    }
    if (
        (is_int($expected) || is_float($expected)) &&
        (is_int($actual) || is_float($actual) || (is_string($actual) && is_numeric($actual)))
    ) {
        $a = (float) $actual;
        $e = (float) $expected;
        return match ($op) {
            "eq" => $a == $e,
            "gt" => $a > $e,
            "ge" => $a >= $e,
            "lt" => $a < $e,
            "le" => $a <= $e,
            "co" => str_contains((string) $actual, (string) $expected),
            "sw" => str_starts_with((string) $actual, (string) $expected),
            "ew" => str_ends_with((string) $actual, (string) $expected),
            default => false,
        };
    }
    $aStr = is_bool($actual) ? ($actual ? "true" : "false") : (string) $actual;
    $eStr = (string) $expected;
    if (!$caseExact) {
        $aStr = strtolower($aStr);
        $eStr = strtolower($eStr);
    }
    return match ($op) {
        "eq" => $aStr === $eStr,
        "co" => str_contains($aStr, $eStr),
        "sw" => str_starts_with($aStr, $eStr),
        "ew" => str_ends_with($aStr, $eStr),
        "gt" => strcmp($aStr, $eStr) > 0,
        "ge" => strcmp($aStr, $eStr) >= 0,
        "lt" => strcmp($aStr, $eStr) < 0,
        "le" => strcmp($aStr, $eStr) <= 0,
        default => false,
    };
}

/** Evaluates a parsed filter against one resource (or one value-path element). */
function scim_filter_eval(array $node, array $resource): bool
{
    switch ($node["op"]) {
        case "or":
            foreach ($node["args"] as $arg) {
                if (scim_filter_eval($arg, $resource)) {
                    return true;
                }
            }
            return false;
        case "and":
            foreach ($node["args"] as $arg) {
                if (!scim_filter_eval($arg, $resource)) {
                    return false;
                }
            }
            return true;
        case "not":
            return !scim_filter_eval($node["x"], $resource);
        case "vp":
            return scim_filter_resolve_path($node["path"], $resource) !== [];
        case "pr":
            foreach (scim_filter_resolve_path($node["path"], $resource) as $v) {
                if ($v !== null && $v !== "" && $v !== []) {
                    return true;
                }
            }
            return false;
        case "cmp":
            $vals = scim_filter_resolve_path($node["path"], $resource);
            $expected = $node["value"];
            if ($vals === []) {
                return $node["cmp"] === "ne" && $expected !== null;
            }
            if ($node["cmp"] === "ne") {
                foreach ($vals as $v) {
                    if (scim_filter_compare($v, "eq", $expected, $node["exact"])) {
                        return false;
                    }
                }
                return true;
            }
            foreach ($vals as $v) {
                if (scim_filter_compare($v, $node["cmp"], $expected, $node["exact"])) {
                    return true;
                }
            }
            return false;
    }
    return false;
}

/**
 * Parses an "attributes" or "excludedAttributes" parameter: a comma-separated string
 * (query parameter) or a list of strings (SearchRequest body). Exits with 400 for
 * oversized lists or malformed attribute names.
 */
function scim_parse_attribute_list(mixed $raw): array
{
    if ($raw === null || $raw === "") {
        return [];
    }
    if (is_string($raw)) {
        if (strlen($raw) > SCIM_ATTR_LIST_MAX_LENGTH) {
            scim_error_response(400, "Attribute list is too long", "invalidValue");
        }
        $items = preg_split('/[\s,]+/', $raw) ?: [];
    } elseif (is_array($raw) && array_is_list($raw)) {
        $items = [];
        $total = 0;
        foreach ($raw as $item) {
            if (!is_string($item)) {
                scim_error_response(400, "Attribute lists must contain strings", "invalidValue");
            }
            $total += strlen($item);
            $items[] = $item;
        }
        if ($total > SCIM_ATTR_LIST_MAX_LENGTH) {
            scim_error_response(400, "Attribute list is too long", "invalidValue");
        }
    } else {
        scim_error_response(400, "Attribute lists must be strings", "invalidValue");
    }
    $out = [];
    foreach ($items as $item) {
        $item = trim($item);
        if ($item === "") {
            continue;
        }
        if (strlen($item) > 256 || preg_match('/^[A-Za-z][A-Za-z0-9_.:$\-]*$/D', $item) !== 1) {
            scim_error_response(400, "Invalid attribute name in attribute list", "invalidValue");
        }
        $out[] = $item;
        if (count($out) > SCIM_ATTR_LIST_MAX_ENTRIES) {
            scim_error_response(400, "Attribute list has too many entries", "invalidValue");
        }
    }
    return $out;
}

/**
 * Validates list and search parameters (GET query or POST /.search SearchRequest) and
 * parses the filter once. Exits with 400 on invalid input.
 */
function scim_parse_list_query(array $params): array
{
    $filterRaw = $params["filter"] ?? "";
    if (!is_string($filterRaw)) {
        scim_error_response(400, "filter must be a string", "invalidFilter");
    }
    $ast = null;
    if (trim($filterRaw) !== "") {
        try {
            $ast = scim_filter_parse(trim($filterRaw));
        } catch (InvalidArgumentException $e) {
            scim_error_response(400, "Invalid filter: " . $e->getMessage(), "invalidFilter");
        }
    }

    $sortBy = null;
    $sortRaw = $params["sortBy"] ?? "";
    if (!is_string($sortRaw)) {
        scim_error_response(400, "sortBy must be a string", "invalidValue");
    }
    $sortRaw = trim($sortRaw);
    if ($sortRaw !== "") {
        if (strlen($sortRaw) > 256 || preg_match('/^[A-Za-z][A-Za-z0-9_.:$\-]*$/D', $sortRaw) !== 1) {
            scim_error_response(400, "Unsupported sortBy attribute", "invalidValue");
        }
        try {
            $sortBy = scim_filter_parse_attr_path($sortRaw);
        } catch (InvalidArgumentException $e) {
            scim_error_response(400, "Unsupported sortBy attribute", "invalidValue");
        }
    }
    $sortOrderRaw = $params["sortOrder"] ?? "ascending";
    $sortOrder = is_string($sortOrderRaw) ? strtolower(trim($sortOrderRaw)) : "ascending";

    $startRaw = $params["startIndex"] ?? 1;
    $countRaw = $params["count"] ?? null;
    return [
        "ast" => $ast,
        "startIndex" => max(1, is_scalar($startRaw) ? (int) $startRaw : 1),
        "count" => is_scalar($countRaw) ? max(0, min(500, (int) $countRaw)) : 100,
        "sortBy" => $sortBy,
        "descending" => $sortOrder === "descending",
        "attributes" => scim_parse_attribute_list($params["attributes"] ?? null),
        "excludedAttributes" => scim_parse_attribute_list($params["excludedAttributes"] ?? null),
    ];
}

/**
 * Sorts formatted resources by one attribute path. Sort keys are resolved once per
 * resource; ties keep their original order.
 */
function scim_sort_resources(array $resources, ?array $sortBy, bool $descending): array
{
    if ($sortBy === null) {
        return $resources;
    }
    $keyed = [];
    foreach (array_values($resources) as $idx => $res) {
        $first = scim_filter_resolve_path($sortBy, $res)[0] ?? "";
        $key = is_bool($first) ? ($first ? "true" : "false") : (is_scalar($first) ? (string) $first : "");
        $keyed[] = [$key, $idx, $res];
    }
    usort($keyed, static function (array $a, array $b) use ($descending): int {
        $cmp = strcasecmp($a[0], $b[0]);
        if ($cmp !== 0) {
            return $descending ? -$cmp : $cmp;
        }
        return $a[1] <=> $b[1];
    });
    return array_column($keyed, 2);
}

/** Lowercase top-level resource key an attributes entry selects, and whether it names a sub-attribute. */
function scim_projection_key(string $attr): array
{
    $a = $attr;
    foreach ([SCIM_SCHEMA_USER, SCIM_SCHEMA_GROUP] as $coreUri) {
        if (stripos($a, $coreUri . ":") === 0) {
            $a = substr($a, strlen($coreUri) + 1);
            break;
        }
    }
    if (stripos($a, "urn:") === 0) {
        if (strcasecmp($a, SCIM_SCHEMA_ENTERPRISE_USER) === 0) {
            return [strtolower(SCIM_SCHEMA_ENTERPRISE_USER), false];
        }
        if (stripos($a, SCIM_SCHEMA_ENTERPRISE_USER . ":") === 0) {
            return [strtolower(SCIM_SCHEMA_ENTERPRISE_USER), true];
        }
        return [strtolower($a), false];
    }
    $dot = strpos($a, ".");
    return $dot === false ? [strtolower($a), false] : [strtolower(substr($a, 0, $dot)), true];
}

function scim_project_resource_attributes(
    array $resource,
    array $attributes,
    array $excludedAttributes
): array {
    if (!empty($attributes)) {
        $keep = ["schemas" => true, "id" => true, "meta" => true, "username" => true, "displayname" => true];
        foreach ($attributes as $a) {
            $keep[scim_projection_key((string) $a)[0]] = true;
        }
        $filtered = [];
        foreach ($resource as $k => $v) {
            if (isset($keep[strtolower((string) $k)])) {
                $filtered[$k] = $v;
            }
        }
        return $filtered;
    }
    if (!empty($excludedAttributes)) {
        $drop = [];
        foreach ($excludedAttributes as $a) {
            [$key, $isSub] = scim_projection_key((string) $a);
            if (!$isSub) {
                $drop[$key] = true;
            }
        }
        foreach (array_keys($resource) as $k) {
            $kl = strtolower((string) $k);
            if (!in_array($kl, ["schemas", "id", "meta"], true) && isset($drop[$kl])) {
                unset($resource[$k]);
            }
        }
    }
    return $resource;
}

/** True when the excluded attributes list removes a group's members. */
function scim_excludes_members(array $excludedAttributes): bool
{
    foreach ($excludedAttributes as $a) {
        if (scim_projection_key((string) $a) === ["members", false]) {
            return true;
        }
    }
    return false;
}

// ---------- SCIM 2.0 Discovery Endpoints (/ServiceProviderConfig, /ResourceTypes, /Schemas) ----------

function scim_build_service_provider_config(string $scimBaseUrl): array
{
    return [
        "schemas" => [SCIM_SCHEMA_SP_CONFIG],
        "documentationUri" => "https://datatracker.ietf.org/doc/html/rfc7644",
        "patch" => ["supported" => true],
        "bulk" => ["supported" => false, "maxOperations" => 0, "maxPayloadSize" => 0],
        "filter" => ["supported" => true, "maxResults" => 500],
        "changePassword" => ["supported" => true],
        "sort" => ["supported" => true],
        // If-Match and If-None-Match are enforced unless OIDC_SCIM_IGNORE_IF_MATCH is set.
        "etag" => ["supported" => scim_preconditions_enabled()],
        "authenticationSchemes" => [
            [
                "type" => "oauthbearertoken",
                "name" => "OAuth Bearer Token",
                "description" => "Authentication scheme using the OAuth Bearer Token Standard (RFC 6750)",
                "specUri" => "https://datatracker.ietf.org/doc/html/rfc6750",
                "primary" => true,
            ],
        ],
        "meta" => [
            "resourceType" => "ServiceProviderConfig",
            "location" => rtrim($scimBaseUrl, "/") . "/ServiceProviderConfig",
        ],
    ];
}

function scim_build_resource_types(string $scimBaseUrl): array
{
    $base = rtrim($scimBaseUrl, "/");
    return [
        [
            "schemas" => [SCIM_SCHEMA_RESOURCE_TYPE],
            "id" => "User",
            "name" => "User",
            "endpoint" => "/Users",
            "description" => "User Account",
            "schema" => SCIM_SCHEMA_USER,
            "schemaExtensions" => [
                [
                    "schema" => SCIM_SCHEMA_ENTERPRISE_USER,
                    "required" => false,
                ],
            ],
            "meta" => [
                "resourceType" => "ResourceType",
                "location" => $base . "/ResourceTypes/User",
            ],
        ],
        [
            "schemas" => [SCIM_SCHEMA_RESOURCE_TYPE],
            "id" => "Group",
            "name" => "Group",
            "endpoint" => "/Groups",
            "description" => "Directory Group",
            "schema" => SCIM_SCHEMA_GROUP,
            "meta" => [
                "resourceType" => "ResourceType",
                "location" => $base . "/ResourceTypes/Group",
            ],
        ],
    ];
}

function scim_build_schemas(string $scimBaseUrl): array
{
    $base = rtrim($scimBaseUrl, "/");
    return [
        [
            "schemas" => [SCIM_SCHEMA_SCHEMA],
            "id" => SCIM_SCHEMA_USER,
            "name" => "User",
            "description" => "SCIM 2.0 User Account",
            "attributes" => [
                ["name" => "userName", "type" => "string", "multiValued" => false, "required" => true, "caseExact" => false, "mutability" => "readWrite", "returned" => "default", "uniqueness" => "server"],
                ["name" => "name", "type" => "complex", "multiValued" => false, "required" => false, "mutability" => "readWrite", "returned" => "default", "subAttributes" => [
                    ["name" => "formatted", "type" => "string", "multiValued" => false, "mutability" => "readWrite", "returned" => "default"],
                    ["name" => "givenName", "type" => "string", "multiValued" => false, "mutability" => "readWrite", "returned" => "default"],
                    ["name" => "familyName", "type" => "string", "multiValued" => false, "mutability" => "readWrite", "returned" => "default"],
                ]],
                ["name" => "displayName", "type" => "string", "multiValued" => false, "required" => false, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "title", "type" => "string", "multiValued" => false, "required" => false, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "active", "type" => "boolean", "multiValued" => false, "required" => false, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "password", "type" => "string", "multiValued" => false, "required" => false, "mutability" => "writeOnly", "returned" => "never"],
                ["name" => "emails", "type" => "complex", "multiValued" => true, "required" => false, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "phoneNumbers", "type" => "complex", "multiValued" => true, "required" => false, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "roles", "type" => "complex", "multiValued" => true, "required" => false, "mutability" => "readWrite", "returned" => "default", "subAttributes" => [
                    ["name" => "value", "type" => "string", "multiValued" => false, "mutability" => "readWrite", "returned" => "default"],
                ]],
                ["name" => "groups", "type" => "complex", "multiValued" => true, "required" => false, "mutability" => "readOnly", "returned" => "default"],
            ],
            "meta" => ["resourceType" => "Schema", "location" => $base . "/Schemas/" . rawurlencode(SCIM_SCHEMA_USER)],
        ],
        [
            "schemas" => [SCIM_SCHEMA_SCHEMA],
            "id" => SCIM_SCHEMA_ENTERPRISE_USER,
            "name" => "EnterpriseUser",
            "description" => "Enterprise User Schema Extension",
            "attributes" => [
                ["name" => "employeeNumber", "type" => "string", "multiValued" => false, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "costCenter", "type" => "string", "multiValued" => false, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "organization", "type" => "string", "multiValued" => false, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "division", "type" => "string", "multiValued" => false, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "department", "type" => "string", "multiValued" => false, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "manager", "type" => "complex", "multiValued" => false, "mutability" => "readWrite", "returned" => "default"],
            ],
            "meta" => ["resourceType" => "Schema", "location" => $base . "/Schemas/" . rawurlencode(SCIM_SCHEMA_ENTERPRISE_USER)],
        ],
        [
            "schemas" => [SCIM_SCHEMA_SCHEMA],
            "id" => SCIM_SCHEMA_GROUP,
            "name" => "Group",
            "description" => "SCIM 2.0 Group",
            "attributes" => [
                ["name" => "displayName", "type" => "string", "multiValued" => false, "required" => true, "mutability" => "readWrite", "returned" => "default"],
                ["name" => "members", "type" => "complex", "multiValued" => true, "required" => false, "mutability" => "readWrite", "returned" => "default"],
            ],
            "meta" => ["resourceType" => "Schema", "location" => $base . "/Schemas/" . rawurlencode(SCIM_SCHEMA_GROUP)],
        ],
    ];
}

// ---------- Inbound SCIM 2.0 Router (/{idpId}/scim/v2/*) ----------

function handle_scim_inbound_routes(
    string $method,
    string $subPath,
    string $storePath,
    array $provider,
    string $issuer
): void {
    if (!preg_match('#^/scim/v2(/.*)?$#i', $subPath, $m)) {
        return;
    }

    if ($method === "OPTIONS") {
        scim_json_response(204);
    }

    $scimRoute = rtrim($m[1] ?? "/", "/");
    if ($scimRoute === "") {
        $scimRoute = "/";
    }
    $scimBaseUrl = $issuer . "/scim/v2";
    $owner = (string) $provider["owner"];

    $isWriteMethod = in_array($method, ["POST", "PUT", "PATCH", "DELETE"], true) &&
        !preg_match('#/\.search$#i', $scimRoute);

    $scimAuth = scim_authenticate_inbound_request($storePath, $provider, $isWriteMethod);
    $tokenFilterGroups = $scimAuth["filter_groups"] ?? [];

    // 1. /ServiceProviderConfig
    if (strcasecmp($scimRoute, "/ServiceProviderConfig") === 0 && $method === "GET") {
        scim_json_response(200, scim_build_service_provider_config($scimBaseUrl));
    }

    // 2. /ResourceTypes
    if (strcasecmp($scimRoute, "/ResourceTypes") === 0 && $method === "GET") {
        $rts = scim_build_resource_types($scimBaseUrl);
        scim_json_response(200, [
            "schemas" => [SCIM_SCHEMA_LIST],
            "totalResults" => count($rts),
            "startIndex" => 1,
            "itemsPerPage" => count($rts),
            "Resources" => $rts,
        ]);
    }
    if (preg_match('#^/ResourceTypes/([^/]+)$#i', $scimRoute, $rm) && $method === "GET") {
        foreach (scim_build_resource_types($scimBaseUrl) as $rt) {
            if (strcasecmp($rt["id"], rawurldecode($rm[1])) === 0) {
                scim_json_response(200, $rt);
            }
        }
        scim_error_response(404, "ResourceType not found");
    }

    // 3. /Schemas
    if (strcasecmp($scimRoute, "/Schemas") === 0 && $method === "GET") {
        $schemas = scim_build_schemas($scimBaseUrl);
        scim_json_response(200, [
            "schemas" => [SCIM_SCHEMA_LIST],
            "totalResults" => count($schemas),
            "startIndex" => 1,
            "itemsPerPage" => count($schemas),
            "Resources" => $schemas,
        ]);
    }
    if (preg_match('#^/Schemas/(.+)$#i', $scimRoute, $sm) && $method === "GET") {
        $targetSchema = rawurldecode($sm[1]);
        foreach (scim_build_schemas($scimBaseUrl) as $sch) {
            if (strcasecmp($sch["id"], $targetSchema) === 0) {
                scim_json_response(200, $sch);
            }
        }
        scim_error_response(404, "Schema not found");
    }

    // Build group map for user group references
    $allGroups = directory_list_groups($storePath, $owner);
    $groupMapByNameLower = [];
    foreach ($allGroups as $g) {
        $groupMapByNameLower[strtolower($g["display_name"])] = $g;
    }

    // 4. /Users & /Users/.search
    if (
        (strcasecmp($scimRoute, "/Users") === 0 && $method === "GET") ||
        (strcasecmp($scimRoute, "/Users/.search") === 0 && $method === "POST")
    ) {
        // The filter is validated and parsed once, then evaluated per resource.
        $query = scim_parse_list_query($method === "POST" ? scim_read_json_body() : $_GET);

        $formatted = [];
        foreach (directory_list_users($storePath, $owner) as $u) {
            if (
                !empty($tokenFilterGroups) &&
                !directory_user_matches_assigned_groups($u, $tokenFilterGroups)
            ) {
                continue;
            }
            $res = scim_format_user_resource($u, $scimBaseUrl, $groupMapByNameLower);
            if ($query["ast"] === null || scim_filter_eval($query["ast"], $res)) {
                $formatted[] = $res;
            }
        }
        $formatted = scim_sort_resources($formatted, $query["sortBy"], $query["descending"]);

        $total = count($formatted);
        $sliced = $query["count"] === 0
            ? []
            : array_slice($formatted, $query["startIndex"] - 1, $query["count"]);
        $projected = array_map(
            fn($r) => scim_project_resource_attributes($r, $query["attributes"], $query["excludedAttributes"]),
            $sliced
        );

        scim_json_response(200, [
            "schemas" => [SCIM_SCHEMA_LIST],
            "totalResults" => $total,
            "startIndex" => $query["startIndex"],
            "itemsPerPage" => count($projected),
            "Resources" => array_values($projected),
        ]);
    }

    if (strcasecmp($scimRoute, "/Users") === 0 && $method === "POST") {
        $body = scim_read_json_body();
        $input = scim_extract_user_input_from_resource($body);
        if (!empty($tokenFilterGroups)) {
            // A group-restricted token only sees users of its groups: the new user joins the
            // first one, so it stays inside (and manageable by) the token's scope. The marker
            // that replaces a deleted group's name is skipped: it is no group anyone can join.
            $joinGroup = null;
            foreach ($tokenFilterGroups as $filterGroup) {
                if (is_scalar($filterGroup) && !directory_is_reserved_group_name((string) $filterGroup)) {
                    $joinGroup = (string) $filterGroup;
                    break;
                }
            }
            if ($joinGroup === null) {
                scim_error_response(
                    403,
                    "This SCIM token is restricted to groups that no longer exist; it cannot create users"
                );
            }
            $input["groups"] = [$joinGroup];
        }
        try {
            $created = directory_create_user($storePath, $owner, $input);
            audit_log_append(
                $storePath,
                $provider["id"],
                "scim",
                "scim_user_created",
                "success",
                $scimAuth["actor"],
                $created["username"] ?? ""
            );
            $res = scim_format_user_resource($created, $scimBaseUrl, $groupMapByNameLower);
            scim_json_response(
                201,
                $res,
                $res["meta"]["version"] ?? null,
                $res["meta"]["location"] ?? null
            );
        } catch (RuntimeException $e) {
            if (str_contains(strtolower($e->getMessage()), "already exists")) {
                scim_error_response(409, $e->getMessage(), "uniqueness");
            }
            scim_error_response(400, $e->getMessage(), "invalidValue");
        } catch (Throwable $e) {
            scim_error_response(400, $e->getMessage(), "invalidValue");
        }
    }

    if (preg_match('#^/Users/([a-f0-9\-]+)$#i', $scimRoute, $um)) {
        $uid = $um[1];
        $existing = directory_get_user_by_id($storePath, $uid, $owner);
        if (
            !$existing ||
            (!empty($tokenFilterGroups) &&
                !directory_user_matches_assigned_groups($existing, $tokenFilterGroups))
        ) {
            scim_error_response(404, "User $uid not found");
        }

        // Conditional requests (RFC 7644 3.14) are checked against this version, and the write
        // checks If-Match and the token's group restriction again on the user as stored under
        // the write lock (scim_write_precondition()).
        $existingVersion = scim_user_version($existing);
        $writePrecondition = scim_write_precondition(
            static fn(array $u): string => scim_user_version($u),
            empty($tokenFilterGroups)
                ? null
                : static fn(array $u): bool => directory_user_matches_assigned_groups($u, $tokenFilterGroups)
        );

        if ($method === "GET") {
            scim_answer_not_modified_if_current($existingVersion);
            $res = scim_format_user_resource($existing, $scimBaseUrl, $groupMapByNameLower);
            $projected = scim_project_resource_attributes(
                $res,
                scim_parse_attribute_list($_GET["attributes"] ?? null),
                scim_parse_attribute_list($_GET["excludedAttributes"] ?? null)
            );
            scim_json_response(200, $projected, $res["meta"]["version"] ?? null);
        }

        if ($method === "PUT") {
            $body = scim_read_json_body();
            $input = scim_extract_user_input_from_resource($body, $existing);
            if (array_key_exists("attributes", $input)) {
                // The attributes were derived from this copy: only what this request changes is
                // applied to the attributes stored at write time (directory_merge_attributes()),
                // so a concurrent change to another attribute, or to other roles, is kept.
                $input["attributes_base"] = is_array($existing["attributes"] ?? null)
                    ? $existing["attributes"]
                    : [];
            }
            scim_check_if_match($existingVersion);
            if (!scim_user_input_changes_anything($existing, $input)) {
                // Nothing changes: no write, so updated_at and outbound sync stay untouched.
                $res = scim_format_user_resource($existing, $scimBaseUrl, $groupMapByNameLower);
                scim_json_response(200, $res, $res["meta"]["version"] ?? null);
            }
            try {
                $updated = directory_update_user($storePath, $owner, $uid, $input, $writePrecondition);
                audit_log_append(
                    $storePath,
                    $provider["id"],
                    "scim",
                    "scim_user_replaced",
                    "success",
                    $scimAuth["actor"],
                    $updated["username"] ?? ""
                );
                $res = scim_format_user_resource($updated, $scimBaseUrl, $groupMapByNameLower);
                scim_json_response(200, $res, $res["meta"]["version"] ?? null);
            } catch (DirectoryPreconditionFailed $e) {
                scim_write_refused("User $uid not found");
            } catch (RuntimeException $e) {
                if (str_contains(strtolower($e->getMessage()), "not found")) {
                    // Deleted by another request after this one read it.
                    scim_write_refused("User $uid not found");
                }
                if (str_contains(strtolower($e->getMessage()), "already uses")) {
                    scim_error_response(409, $e->getMessage(), "uniqueness");
                }
                scim_error_response(400, $e->getMessage(), "invalidValue");
            } catch (Throwable $e) {
                scim_error_response(400, $e->getMessage(), "invalidValue");
            }
        }

        if ($method === "PATCH") {
            $body = scim_read_json_body();
            $ops = $body["Operations"] ?? ($body["operations"] ?? null);
            if (!is_array($ops) || !array_is_list($ops)) {
                scim_error_response(400, "PatchOp requires an Operations array", "invalidSyntax");
            }
            // Unsupported paths for authorization attributes answer 400 inside this call.
            $patchInput = scim_apply_user_patch_operations($existing, $ops);
            if (array_key_exists("attributes", $patchInput)) {
                // As for PUT: only the attributes this PATCH changes are applied.
                $patchInput["attributes_base"] = is_array($existing["attributes"] ?? null)
                    ? $existing["attributes"]
                    : [];
            }
            scim_check_if_match($existingVersion);
            if (!scim_user_input_changes_anything($existing, $patchInput)) {
                // Nothing changes: no write, so updated_at and outbound sync stay untouched.
                $res = scim_format_user_resource($existing, $scimBaseUrl, $groupMapByNameLower);
                scim_json_response(200, $res, $res["meta"]["version"] ?? null);
            }
            try {
                $updated = directory_update_user($storePath, $owner, $uid, $patchInput, $writePrecondition);
                audit_log_append(
                    $storePath,
                    $provider["id"],
                    "scim",
                    "scim_user_patched",
                    "success",
                    $scimAuth["actor"],
                    $updated["username"] ?? ""
                );
                $res = scim_format_user_resource($updated, $scimBaseUrl, $groupMapByNameLower);
                scim_json_response(200, $res, $res["meta"]["version"] ?? null);
            } catch (DirectoryPreconditionFailed $e) {
                scim_write_refused("User $uid not found");
            } catch (RuntimeException $e) {
                if (str_contains(strtolower($e->getMessage()), "not found")) {
                    // Deleted by another request after this one read it.
                    scim_write_refused("User $uid not found");
                }
                if (str_contains(strtolower($e->getMessage()), "already uses")) {
                    scim_error_response(409, $e->getMessage(), "uniqueness");
                }
                scim_error_response(400, $e->getMessage(), "invalidValue");
            } catch (Throwable $e) {
                scim_error_response(400, $e->getMessage(), "invalidValue");
            }
        }

        if ($method === "DELETE") {
            scim_check_if_match($existingVersion);
            try {
                $deleted = directory_delete_user($storePath, $owner, $uid, false, $writePrecondition);
            } catch (DirectoryPreconditionFailed $e) {
                scim_write_refused("User $uid not found");
            }
            if (!$deleted && scim_precondition_tags("HTTP_IF_MATCH") !== null) {
                // Deleted by another request after this one read it: no version can match.
                scim_precondition_failed();
            }
            audit_log_append(
                $storePath,
                $provider["id"],
                "scim",
                "scim_user_deleted",
                "success",
                $scimAuth["actor"],
                $existing["username"] ?? $uid
            );
            scim_json_response(204);
        }
    }

    // 5. /Groups & /Groups/.search
    if (
        (strcasecmp($scimRoute, "/Groups") === 0 && $method === "GET") ||
        (strcasecmp($scimRoute, "/Groups/.search") === 0 && $method === "POST")
    ) {
        $query = scim_parse_list_query($method === "POST" ? scim_read_json_body() : $_GET);
        $excludeMembers = scim_excludes_members($query["excludedAttributes"]);

        $formatted = [];
        foreach ($allGroups as $g) {
            if (!scim_group_name_in_scope((string) $g["display_name"], $tokenFilterGroups)) {
                continue;
            }
            $fullRes = scim_format_group_resource($g, $scimBaseUrl, false);
            if ($query["ast"] === null || scim_filter_eval($query["ast"], $fullRes)) {
                $formatted[] = $excludeMembers
                    ? scim_format_group_resource($g, $scimBaseUrl, true)
                    : $fullRes;
            }
        }
        $formatted = scim_sort_resources($formatted, $query["sortBy"], $query["descending"]);

        $total = count($formatted);
        $sliced = $query["count"] === 0
            ? []
            : array_slice($formatted, $query["startIndex"] - 1, $query["count"]);
        $projected = array_map(
            fn($r) => scim_project_resource_attributes($r, $query["attributes"], $query["excludedAttributes"]),
            $sliced
        );

        scim_json_response(200, [
            "schemas" => [SCIM_SCHEMA_LIST],
            "totalResults" => $total,
            "startIndex" => $query["startIndex"],
            "itemsPerPage" => count($projected),
            "Resources" => array_values($projected),
        ]);
    }

    if (strcasecmp($scimRoute, "/Groups") === 0 && $method === "POST") {
        $body = scim_read_json_body();
        $dnRaw = $body["displayName"] ?? "";
        $extRaw = $body["externalId"] ?? "";
        if (!is_scalar($dnRaw) || !is_scalar($extRaw)) {
            scim_error_response(400, "displayName and externalId must be strings", "invalidValue");
        }
        $dn = trim((string) $dnRaw);
        $ext = trim((string) $extRaw);
        if ($dn !== "" && !scim_group_name_in_scope($dn, $tokenFilterGroups)) {
            scim_error_response(403, "This SCIM token may only create groups named in its group restriction");
        }
        $membersKey = scim_attribute_key($body, "members");
        $membersValue = $membersKey !== null ? $body[$membersKey] : null;
        if ($membersValue !== null && !is_array($membersValue)) {
            scim_error_response(400, "members must be a list of objects with a value", "invalidValue");
        }
        $memberIds = scim_extract_member_ids_from_value(
            $storePath,
            $owner,
            $membersValue ?? [],
            $tokenFilterGroups
        );
        try {
            $created = directory_create_group($storePath, $owner, $dn, $ext, $memberIds);
            audit_log_append(
                $storePath,
                $provider["id"],
                "scim",
                "scim_group_created",
                "success",
                $scimAuth["actor"],
                $created["display_name"] ?? ""
            );
            $res = scim_format_group_resource($created, $scimBaseUrl);
            scim_json_response(
                201,
                $res,
                $res["meta"]["version"] ?? null,
                $res["meta"]["location"] ?? null
            );
        } catch (RuntimeException $e) {
            if (str_contains(strtolower($e->getMessage()), "already exists")) {
                scim_error_response(409, $e->getMessage(), "uniqueness");
            }
            scim_error_response(400, $e->getMessage(), "invalidValue");
        } catch (Throwable $e) {
            scim_error_response(400, $e->getMessage(), "invalidValue");
        }
    }

    if (preg_match('#^/Groups/([a-f0-9\-]+)$#i', $scimRoute, $gm)) {
        $gid = $gm[1];
        $existing = directory_get_group_by_id($storePath, $owner, $gid);
        if (
            !$existing ||
            !scim_group_name_in_scope((string) $existing["display_name"], $tokenFilterGroups)
        ) {
            scim_error_response(404, "Group $gid not found");
        }
        $currentMemberIds = array_map(fn($m) => (string) $m["id"], $existing["members"] ?? []);
        // Conditional requests (RFC 7644 3.14) are checked against this version, and the write
        // checks If-Match and the token's group restriction again on the group as stored under
        // the write lock (scim_write_precondition()).
        $existingVersion = scim_group_version($existing);
        $writePrecondition = scim_write_precondition(
            static fn(array $g): string => scim_group_version($g),
            empty($tokenFilterGroups)
                ? null
                : static fn(array $g): bool =>
                    scim_group_name_in_scope((string) ($g["display_name"] ?? ""), $tokenFilterGroups)
        );

        if ($method === "GET") {
            scim_answer_not_modified_if_current($existingVersion);
            $excluded = scim_parse_attribute_list($_GET["excludedAttributes"] ?? null);
            $res = scim_format_group_resource($existing, $scimBaseUrl, scim_excludes_members($excluded));
            $projected = scim_project_resource_attributes(
                $res,
                scim_parse_attribute_list($_GET["attributes"] ?? null),
                $excluded
            );
            scim_json_response(200, $projected, $res["meta"]["version"] ?? null);
        }

        if ($method === "PUT") {
            $body = scim_read_json_body();
            $dnRaw = $body["displayName"] ?? $existing["display_name"];
            $extRaw = array_key_exists("externalId", $body)
                ? ($body["externalId"] ?? "")
                : (string) ($existing["external_id"] ?? "");
            if (!is_scalar($dnRaw) || !is_scalar($extRaw)) {
                scim_error_response(400, "displayName and externalId must be strings", "invalidValue");
            }
            $dn = trim((string) $dnRaw);
            $ext = trim((string) $extRaw);
            if ($dn !== "" && !scim_group_name_in_scope($dn, $tokenFilterGroups)) {
                scim_error_response(403, "This SCIM token may only use group names listed in its group restriction");
            }
            $membersKey = scim_attribute_key($body, "members");
            $membersValue = $membersKey !== null ? $body[$membersKey] : null;
            if ($membersValue !== null && !is_array($membersValue)) {
                // A scalar used to empty the group silently.
                scim_error_response(400, "members must be a list of objects with a value", "invalidValue");
            }
            if ($membersKey !== null) {
                // null and [] both empty the group (RFC 7643 2.5).
                $memberIds = scim_extract_member_ids_from_value($storePath, $owner, $membersValue, $tokenFilterGroups);
            } elseif (scim_put_keeps_omitted_attributes()) {
                $memberIds = null; // old merge: the stored members are kept
            } else {
                // PUT replaces the group (RFC 7644 3.5.1): without members it has none, so a
                // client that leaves out an emptied member list still revokes the access.
                $memberIds = [];
            }
            scim_check_if_match($existingVersion);
            if (
                $dn === (string) $existing["display_name"] &&
                $ext === (string) ($existing["external_id"] ?? "") &&
                ($memberIds === null || scim_id_set($memberIds) === scim_id_set($currentMemberIds))
            ) {
                // Nothing changes: no write, so updated_at and outbound sync stay untouched.
                $res = scim_format_group_resource($existing, $scimBaseUrl);
                scim_json_response(200, $res, $res["meta"]["version"] ?? null);
            }
            try {
                $updated = directory_update_group(
                    $storePath,
                    $owner,
                    $gid,
                    $dn,
                    $ext,
                    $memberIds,
                    false,
                    null,
                    $writePrecondition
                );
                audit_log_append(
                    $storePath,
                    $provider["id"],
                    "scim",
                    "scim_group_replaced",
                    "success",
                    $scimAuth["actor"],
                    $updated["display_name"] ?? ""
                );
                $res = scim_format_group_resource($updated, $scimBaseUrl);
                scim_json_response(200, $res, $res["meta"]["version"] ?? null);
            } catch (DirectoryPreconditionFailed $e) {
                scim_write_refused("Group $gid not found");
            } catch (RuntimeException $e) {
                if (str_contains(strtolower($e->getMessage()), "not found")) {
                    // Deleted by another request after this one read it.
                    scim_write_refused("Group $gid not found");
                }
                if (str_contains(strtolower($e->getMessage()), "already uses")) {
                    scim_error_response(409, $e->getMessage(), "uniqueness");
                }
                scim_error_response(400, $e->getMessage(), "invalidValue");
            } catch (Throwable $e) {
                scim_error_response(400, $e->getMessage(), "invalidValue");
            }
        }

        if ($method === "PATCH") {
            $body = scim_read_json_body();
            $ops = $body["Operations"] ?? ($body["operations"] ?? null);
            if (!is_array($ops) || !array_is_list($ops)) {
                scim_error_response(400, "PatchOp requires an Operations array", "invalidSyntax");
            }
            $patched = scim_apply_group_patch_operations($storePath, $owner, $existing, $ops, $tokenFilterGroups);
            $newName = trim((string) $patched["display_name"]);
            if ($newName !== "" && !scim_group_name_in_scope($newName, $tokenFilterGroups)) {
                scim_error_response(403, "This SCIM token may only use group names listed in its group restriction");
            }
            $newExternalId = trim((string) $patched["external_id"]);
            $nameChanged = $newName !== (string) $existing["display_name"];
            $externalIdChanged = $newExternalId !== (string) ($existing["external_id"] ?? "");
            scim_check_if_match($existingVersion);
            if (
                !$nameChanged &&
                !$externalIdChanged &&
                scim_id_set($patched["member_ids"]) === scim_id_set($currentMemberIds)
            ) {
                // Nothing changes: no write, so updated_at and outbound sync stay untouched.
                $res = scim_format_group_resource($existing, $scimBaseUrl);
                scim_json_response(200, $res, $res["meta"]["version"] ?? null);
            }
            try {
                // Only what this PATCH changes is written: the membership difference against the
                // group as read above (the base), and displayName and externalId only when it
                // changes them (null keeps the stored value). A concurrent change to other members,
                // or a concurrent rename, is therefore kept instead of being reverted.
                $updated = directory_update_group(
                    $storePath,
                    $owner,
                    $gid,
                    $nameChanged ? $newName : null,
                    $externalIdChanged ? $newExternalId : null,
                    $patched["member_ids"],
                    false,
                    $currentMemberIds,
                    $writePrecondition
                );
                audit_log_append(
                    $storePath,
                    $provider["id"],
                    "scim",
                    "scim_group_patched",
                    "success",
                    $scimAuth["actor"],
                    $updated["display_name"] ?? ""
                );
                $res = scim_format_group_resource($updated, $scimBaseUrl);
                scim_json_response(200, $res, $res["meta"]["version"] ?? null);
            } catch (DirectoryPreconditionFailed $e) {
                scim_write_refused("Group $gid not found");
            } catch (RuntimeException $e) {
                if (str_contains(strtolower($e->getMessage()), "not found")) {
                    // Deleted by another request after this one read it.
                    scim_write_refused("Group $gid not found");
                }
                if (str_contains(strtolower($e->getMessage()), "already uses")) {
                    scim_error_response(409, $e->getMessage(), "uniqueness");
                }
                scim_error_response(400, $e->getMessage(), "invalidValue");
            } catch (Throwable $e) {
                scim_error_response(400, $e->getMessage(), "invalidValue");
            }
        }

        if ($method === "DELETE") {
            scim_check_if_match($existingVersion);
            try {
                $deleted = directory_delete_group($storePath, $owner, $gid, false, $writePrecondition);
            } catch (DirectoryPreconditionFailed $e) {
                scim_write_refused("Group $gid not found");
            }
            if (!$deleted && scim_precondition_tags("HTTP_IF_MATCH") !== null) {
                // Deleted by another request after this one read it: no version can match.
                scim_precondition_failed();
            }
            audit_log_append(
                $storePath,
                $provider["id"],
                "scim",
                "scim_group_deleted",
                "success",
                $scimAuth["actor"],
                $existing["display_name"] ?? $gid
            );
            scim_json_response(204);
        }
    }

    scim_error_response(404, "Unknown SCIM 2.0 endpoint: $scimRoute");
}

// ---------- Outbound SCIM 2.0 Push Provisioning Connectors ----------

function hydrate_scim_connector_row(array $r): array
{
    $lastSeen = $r["agent_last_seen_at"] ?? null;
    // Agent-reported labels are cleaned again on output: rows written by older releases
    // may hold byte-truncated (invalid) UTF-8 that would break the JSON response.
    $agentHostname = is_string($r["agent_hostname"] ?? null) ? sanitize_label($r["agent_hostname"], 120) : "";
    $agentVersion = is_string($r["agent_version"] ?? null) ? sanitize_label($r["agent_version"], 40) : "";
    return [
        "id" => (string) $r["id"],
        "provider_id" => (string) $r["provider_id"],
        "name" => (string) $r["name"],
        "delivery_mode" => (string) ($r["delivery_mode"] ?? "direct"),
        "scim_base_url" => (string) $r["scim_base_url"],
        "token_preview" => (string) $r["token_preview"],
        "agent_secret_preview" => $r["agent_secret_preview"] ?? null,
        "agent_last_seen_at" => $lastSeen,
        "agent_hostname" => $agentHostname !== "" ? $agentHostname : null,
        "agent_version" => $agentVersion !== "" ? $agentVersion : null,
        "agent_last_ip" => $r["agent_last_ip"] ?? null,
        "agent_online" => ($r["delivery_mode"] ?? "direct") === "agent" && scim_agent_is_online($r),
        "sync_groups" => (int) ($r["sync_groups"] ?? 1) === 1,
        "push_passwords" => (int) ($r["push_passwords"] ?? 0) === 1,
        // Whether this installation lets connectors push passwords at all (S04-08); while it
        // does not, push_passwords cannot be turned on and a connector with it pushes none.
        "password_push_available" => vault_password_push_allowed(),
        "auto_sync" => (int) ($r["auto_sync"] ?? 1) === 1,
        "deprovision_action" => (string) ($r["deprovision_action"] ?? "deactivate"),
        "assigned_groups" =>
            json_decode((string) ($r["assigned_groups_json"] ?? "[]"), true) ?: [],
        "status" => (string) ($r["status"] ?? "active"),
        "last_sync_at" => $r["last_sync_at"] ?? null,
        "last_sync_status" => $r["last_sync_status"] ?? null,
        "last_sync_summary" => $r["last_sync_summary"] ?? null,
        // Changes queued for the next sync (a sync stopped early, or automatic syncs were
        // skipped while the target or agent was unavailable), and whether a sync is running.
        "sync_queued" => (int) ($r["sync_pending"] ?? 0) > 0,
        "sync_running" => (int) ($r["sync_lock_until"] ?? 0) >= time(),
        "created_at" => (string) $r["created_at"],
    ];
}

function scim_connector_list(string $storePath, string $providerId): array
{
    // scim_db(): stored token previews are re-masked once before any is served.
    $pdo = scim_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM scim_connectors WHERE provider_id = :pid ORDER BY created_at DESC"
    );
    $stmt->execute([":pid" => $providerId]);
    $out = [];
    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $out[] = hydrate_scim_connector_row($r);
    }
    return $out;
}

function scim_connector_get(
    string $storePath,
    string $providerId,
    string $connectorId
): ?array {
    $pdo = scim_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM scim_connectors WHERE id = :id AND provider_id = :pid LIMIT 1"
    );
    $stmt->execute([":id" => $connectorId, ":pid" => $providerId]);
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    return $r ? hydrate_scim_connector_row($r) : null;
}

/**
 * storage_db() plus this lane's additive schema: the outbound sync lease, pending flag,
 * circuit breaker and agent timeout columns. Call it outside any transaction.
 */
function scim_db(string $storePath): PDO
{
    $pdo = storage_db($storePath);
    schema_ensure($pdo, "scim.connector_sync_v1", [
        "ALTER TABLE scim_connectors ADD COLUMN sync_lock_until INTEGER",
        "ALTER TABLE scim_connectors ADD COLUMN sync_pending INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE scim_connectors ADD COLUMN circuit_open_until INTEGER",
        "ALTER TABLE scim_connectors ADD COLUMN agent_local_timeout INTEGER",
    ]);
    // Agent poll lease (one open long-poll per connector) and the claim/result times that
    // tell an answering agent from one that only polls.
    schema_ensure($pdo, "scim.agent_liveness_v1", [
        "ALTER TABLE scim_connectors ADD COLUMN agent_poll_until INTEGER",
        "ALTER TABLE scim_connectors ADD COLUMN agent_last_claim_at INTEGER",
        "ALTER TABLE scim_connectors ADD COLUMN agent_last_result_at INTEGER",
    ]);
    // remote_name: the userName or displayName a mapping was last pushed with, so a user
    // re-created under the same userName can take over the remote account of its stale
    // mapping without any request. Plus a one-time repair of mappings older releases wrote:
    // - Lookups used to adopt the first resource of any answer, so several local users (or
    //   groups) could be linked to one remote resource that every push then overwrote.
    //   Such shared links are dropped; the next sync re-links each resource only on a
    //   unique, exact userName/displayName match.
    // - A create answer without an id used to store the local id as the remote id. Those
    //   mappings are pushed once more: a PUT that answers 404 then re-links the resource by
    //   name instead of leaving a mapping whose updates and deprovisioning only hit 404.
    // - remote_name is filled from the directory for resources that still exist.
    schema_ensure($pdo, "scim.remote_mappings_v1", [
        "ALTER TABLE scim_remote_mappings ADD COLUMN remote_name TEXT",
        static function (PDO $db): void {
            $db->exec(
                "DELETE FROM scim_remote_mappings WHERE remote_id <> '' AND EXISTS (" .
                    "SELECT 1 FROM scim_remote_mappings AS o WHERE o.connector_id = scim_remote_mappings.connector_id " .
                    "AND o.resource_type = scim_remote_mappings.resource_type " .
                    "AND o.remote_id = scim_remote_mappings.remote_id " .
                    "AND o.local_id <> scim_remote_mappings.local_id)"
            );
            $db->exec("UPDATE scim_remote_mappings SET last_pushed_hash = '' WHERE remote_id = local_id");
            $db->exec(
                "UPDATE scim_remote_mappings SET remote_name = (SELECT u.username FROM idp_users AS u " .
                    "WHERE u.id = scim_remote_mappings.local_id) WHERE resource_type = 'user' AND remote_name IS NULL"
            );
            $db->exec(
                "UPDATE scim_remote_mappings SET remote_name = (SELECT g.display_name FROM idp_groups AS g " .
                    "WHERE g.id = scim_remote_mappings.local_id) WHERE resource_type = 'group' AND remote_name IS NULL"
            );
        },
    ]);
    // Relay queue: whether the agent cut a relayed response body (the result then carries
    // "truncated": true). A cut body is never parsed.
    schema_ensure($pdo, "scim.agent_relay_v1", [
        "ALTER TABLE scim_agent_jobs ADD COLUMN response_truncated INTEGER NOT NULL DEFAULT 0",
    ]);
    // User change-detection hashes used to cover the pushed plaintext password: an unkeyed
    // SHA-256 over directory data plus the password, testable at GPU speed by anyone with a
    // copy of the database. They are blanked once; the next sync pushes each user once more
    // and stores scim_user_change_hash(), which never includes the password.
    schema_ensure($pdo, "scim.user_change_hash_v1", [
        "UPDATE scim_remote_mappings SET last_pushed_hash = '' WHERE resource_type = 'user'",
    ]);
    // Downstream bearer token previews used to show the first 6 and last 3 characters of the
    // token. They are re-masked once with secret_preview_mask() (only the last 4 characters,
    // and only of tokens of 32 characters or more); the agent-mode label stays. A token that
    // cannot be decrypted gets the bare mask.
    schema_ensure($pdo, "scim.token_preview_mask_v1", [
        static function (PDO $db) use ($storePath): void {
            $rows = $db->query(
                "SELECT id, bearer_token_enc FROM scim_connectors WHERE token_preview <> 'on-prem local'"
            )->fetchAll(PDO::FETCH_ASSOC);
            $upd = $db->prepare("UPDATE scim_connectors SET token_preview = :prev WHERE id = :id");
            foreach ($rows as $r) {
                $enc = (string) ($r["bearer_token_enc"] ?? "");
                $plain = null;
                if ($enc !== "") {
                    try {
                        $plain = vault_decrypt_secret($storePath, $enc);
                    } catch (Throwable $e) {
                        $plain = null;
                    }
                }
                $upd->execute([":prev" => secret_preview_mask($plain ?? ""), ":id" => (string) $r["id"]]);
            }
        },
    ]);
    return $pdo;
}

/** True when the connector's on-premises agent polled within SCIM_AGENT_ONLINE_SECONDS. */
function scim_agent_polled_recently(array $row, ?int $now = null): bool
{
    $now ??= time();
    $lastSeen = $row["agent_last_seen_at"] ?? null;
    $ts = is_string($lastSeen) && $lastSeen !== "" ? strtotime($lastSeen) : false;
    return $ts !== false && ($now - $ts) <= SCIM_AGENT_ONLINE_SECONDS;
}

/**
 * How long the result of a claimed relay job is awaited, counted from the claim: the
 * agent's reported local SCIM timeout (agent_local_timeout, 1-120 s) plus
 * SCIM_AGENT_ANSWER_GRACE_SECONDS. An agent that never reported its timeout gets the
 * longest one an agent allows (120 s).
 */
function scim_agent_answer_grace_seconds(mixed $localTimeout): int
{
    $seconds = is_numeric($localTimeout) ? (int) $localTimeout : 0;
    if ($seconds < 1 || $seconds > SCIM_AGENT_MAX_LOCAL_TIMEOUT_SECONDS) {
        $seconds = SCIM_AGENT_MAX_LOCAL_TIMEOUT_SECONDS;
    }
    return $seconds + SCIM_AGENT_ANSWER_GRACE_SECONDS;
}

/**
 * True while an agent that keeps polling leaves relay jobs it claimed unanswered: its
 * oldest claim since its last posted result is older than the answer grace
 * (scim_agent_answer_grace_seconds()). Polling alone therefore does not make an agent
 * online. The verdict lasts until the agent posts a result, or for at most
 * SCIM_AGENT_STALL_RETRY_SECONDS after that claim, so an agent that restarted in the
 * middle of a job recovers without an administrator.
 */
function scim_agent_is_stalled(array $row, ?int $now = null): bool
{
    $now ??= time();
    $claimedAt = (int) ($row["agent_last_claim_at"] ?? 0);
    if ($claimedAt <= 0 || $claimedAt <= (int) ($row["agent_last_result_at"] ?? 0)) {
        return false;
    }
    $grace = scim_agent_answer_grace_seconds($row["agent_local_timeout"] ?? null);
    $age = $now - $claimedAt;
    return $age > $grace && $age < SCIM_AGENT_STALL_RETRY_SECONDS;
}

/** An agent is online when it polled recently and answers the jobs it claims. */
function scim_agent_is_online(array $row, ?int $now = null): bool
{
    return scim_agent_polled_recently($row, $now) && !scim_agent_is_stalled($row, $now);
}

/**
 * Lab-only switch (env OIDC_SCIM_ALLOW_PRIVATE_NETS, config.php "scim_allow_private_nets"):
 * allows http:// targets, private or reserved addresses and this IdP's own host name.
 */
function scim_allow_private_networks(): bool
{
    return config_flag("scim_allow_private_nets", "OIDC_SCIM_ALLOW_PRIVATE_NETS");
}

/**
 * Compatibility switch (env OIDC_SCIM_ALLOW_IDP_HOST_TARGETS, config.php
 * "scim_allow_idp_host_targets", default off): allows outbound connectors whose target
 * host is this IdP's own host name, for single-domain installs that serve another SCIM
 * application next to the IdP. The lab switch above implies it.
 */
function scim_allow_idp_host_targets(): bool
{
    return scim_allow_private_networks() ||
        config_flag("scim_allow_idp_host_targets", "OIDC_SCIM_ALLOW_IDP_HOST_TARGETS");
}

/**
 * Lowercase host names (or IP literals) this IdP answers on: its public base URL and the
 * current request's host and server name.
 */
function scim_idp_own_hosts(): array
{
    $hosts = [];
    $urls = [
        $GLOBALS["baseUrl"] ?? null,
        config_value("public_base_url", ["OIDC_PUBLIC_BASE_URL", "PUBLIC_BASE_URL"]),
    ];
    foreach ($urls as $u) {
        if (is_string($u) && $u !== "") {
            $h = parse_url($u, PHP_URL_HOST);
            if (is_string($h) && $h !== "") {
                $hosts[] = strtolower(trim($h, "[]"));
            }
        }
    }
    foreach (["HTTP_HOST", "SERVER_NAME"] as $key) {
        $v = $_SERVER[$key] ?? null;
        if (is_string($v) && trim($v) !== "") {
            $hosts[] = strtolower(trim((string) preg_replace('/:\d+$/', "", trim($v)), "[]"));
        }
    }
    return array_values(array_unique(array_filter($hosts, static fn($h) => $h !== "")));
}

/** A and AAAA answers for a host name (system resolver IPv4 answers as a fallback). */
function scim_resolve_host_addresses(string $host): array
{
    $ips = [];
    foreach ([[DNS_A, "ip"], [DNS_AAAA, "ipv6"]] as [$type, $field]) {
        $records = @dns_get_record($host, $type);
        if (!is_array($records)) {
            continue;
        }
        foreach ($records as $rec) {
            $ip = is_array($rec) ? ($rec[$field] ?? null) : null;
            if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                $ips[] = strtolower($ip);
            }
        }
    }
    if ($ips === []) {
        $v4 = @gethostbynamel($host);
        if (is_array($v4)) {
            foreach ($v4 as $ip) {
                if (is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                    $ips[] = $ip;
                }
            }
        }
    }
    return array_values(array_unique($ips));
}

/**
 * Validates an outbound SCIM base URL and resolves the address every request must connect
 * to (SSRF and DNS-rebinding protection). The host must be an ASCII DNS name (punycode for
 * IDN) or an IP literal: percent-encoding, user info, a query, a fragment, backslashes and
 * non-ASCII characters are rejected, so libcurl cannot derive another host name than the
 * one validated here. Every A/AAAA answer must be a public unicast address, and the IdP's
 * own host is refused. Errors stay generic; details go to the server log.
 * OIDC_SCIM_ALLOW_PRIVATE_NETS=1 relaxes the address rules for controlled labs only.
 *
 * @return array{url: string, host: string, port: int, pinned_ip: string, scheme: string}
 */
function scim_validate_outbound_url(string $rawUrl): array
{
    $allowPrivate = scim_allow_private_networks();
    $clean = rtrim(validate_safe_url($rawUrl, false, "SCIM Base URL"), "/");
    if (strlen($clean) > 2048) {
        throw new InvalidArgumentException("SCIM Base URL is too long");
    }
    if (preg_match('/[^\x21-\x7E]/', $clean) === 1) {
        throw new InvalidArgumentException(
            "SCIM Base URL must be plain ASCII without spaces (use punycode for international domain names)"
        );
    }
    if (strpbrk($clean, "\\#?") !== false) {
        throw new InvalidArgumentException("SCIM Base URL must not contain a query string, fragment or backslash");
    }
    $parts = parse_url($clean);
    if (
        !is_array($parts) ||
        isset($parts["user"]) ||
        isset($parts["pass"]) ||
        isset($parts["query"]) ||
        isset($parts["fragment"])
    ) {
        throw new InvalidArgumentException("SCIM Base URL must not contain credentials, a query string or a fragment");
    }
    $scheme = strtolower((string) ($parts["scheme"] ?? ""));
    if ($scheme !== "https" && !($scheme === "http" && $allowPrivate)) {
        throw new InvalidArgumentException(
            "Outbound SCIM Base URL must use https:// (set OIDC_SCIM_ALLOW_PRIVATE_NETS=1 for local http lab testing)"
        );
    }

    $hostPart = strtolower((string) ($parts["host"] ?? ""));
    $isIp = false;
    if (str_starts_with($hostPart, "[")) {
        $host = substr($hostPart, 1, -1);
        if (!str_ends_with($hostPart, "]") || filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
            throw new InvalidArgumentException("SCIM Base URL has an invalid IPv6 address");
        }
        $isIp = true;
    } elseif (filter_var($hostPart, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        $host = $hostPart;
        $isIp = true;
    } else {
        $host = $hostPart;
        $labels = explode(".", $host);
        $lastLabel = (string) end($labels);
        if (
            preg_match('/^(?=.{1,253}$)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$/D', $host) !== 1 ||
            preg_match('/^(?:[0-9]+|0x[0-9a-f]*)$/D', $lastLabel) === 1
        ) {
            throw new InvalidArgumentException(
                "SCIM Base URL host must be an ASCII DNS name (punycode for IDN) or an IP address"
            );
        }
    }
    $port = isset($parts["port"]) ? (int) $parts["port"] : ($scheme === "https" ? 443 : 80);
    if ($port < 1 || $port > 65535) {
        throw new InvalidArgumentException("SCIM Base URL has an invalid port");
    }
    $path = (string) ($parts["path"] ?? "");
    if ($path !== "" && preg_match('/^(?:\/(?:[A-Za-z0-9\-._~!$&\'()*+,;=:@]|%[0-9A-Fa-f]{2})*)+$/D', $path) !== 1) {
        throw new InvalidArgumentException("SCIM Base URL has an invalid path");
    }
    if (!scim_allow_idp_host_targets() && in_array($host, scim_idp_own_hosts(), true)) {
        throw new InvalidArgumentException(
            "SCIM Base URL must not point at this identity provider's host (see OIDC_SCIM_ALLOW_IDP_HOST_TARGETS)"
        );
    }

    $ips = $isIp ? [$host] : scim_resolve_host_addresses($host);
    $rejectReason = null;
    if ($ips === []) {
        $rejectReason = "no A/AAAA answer";
    } elseif (!$allowPrivate) {
        foreach ($ips as $ip) {
            if (!ip_is_public_unicast($ip)) {
                $rejectReason = "non-public address " . $ip;
                break;
            }
        }
    }
    if ($rejectReason !== null) {
        error_log("SCIM outbound URL rejected for host " . $host . ": " . $rejectReason);
        throw new InvalidArgumentException("SCIM Base URL host must resolve to public internet addresses only");
    }

    $authority = ($isIp && str_contains($host, ":") ? "[" . $host . "]" : $host) .
        (isset($parts["port"]) ? ":" . $port : "");
    return [
        "url" => $scheme . "://" . $authority . rtrim($path, "/"),
        "host" => $host,
        "port" => $port,
        "pinned_ip" => $ips[0],
        "scheme" => $scheme,
    ];
}

/**
 * Comparable form of a stored connector URL: scheme and host lowercased, default port
 * explicit, trailing slash removed. Anything that does not parse compares as "".
 */
function scim_url_compare_key(string $url): string
{
    $parts = parse_url(trim($url));
    if (!is_array($parts) || !isset($parts["scheme"], $parts["host"])) {
        return "";
    }
    $scheme = strtolower((string) $parts["scheme"]);
    $port = isset($parts["port"])
        ? (int) $parts["port"]
        : ($scheme === "https" ? 443 : ($scheme === "http" ? 80 : 0));
    $userInfo = isset($parts["user"])
        ? $parts["user"] . (isset($parts["pass"]) ? ":" . $parts["pass"] : "") . "@"
        : "";
    return $scheme . "://" . $userInfo .
        strtolower(trim((string) $parts["host"], "[]")) . ":" . $port .
        rtrim((string) ($parts["path"] ?? ""), "/") .
        (isset($parts["query"]) ? "?" . $parts["query"] : "") .
        (isset($parts["fragment"]) ? "#" . $parts["fragment"] : "");
}

/**
 * scim_validate_outbound_url() for a target URL an administrator or API client submits.
 * Its rejections are already generic (resolved addresses and the reason only reach the
 * server log); in addition they are counted per provider and client network, and past
 * SCIM_TARGET_CHECK_MAX_FAILURES within the window further URLs are refused before any DNS
 * lookup, so connector saves cannot be used to probe the IdP host's internal DNS.
 *
 * @return array{url: string, host: string, port: int, pinned_ip: string, scheme: string}
 */
function scim_connector_validate_target(string $storePath, string $providerId, string $rawUrl): array
{
    $bucket = rate_limit_bucket("scim_target_check", $providerId, client_ip_bucket());
    if (rate_limit_is_blocked($storePath, $bucket)) {
        throw new InvalidArgumentException("Too many rejected SCIM Base URLs; try again in a few minutes");
    }
    try {
        return scim_validate_outbound_url($rawUrl);
    } catch (InvalidArgumentException $e) {
        rate_limit_record_failure(
            $storePath,
            $bucket,
            SCIM_TARGET_CHECK_MAX_FAILURES,
            SCIM_TARGET_CHECK_WINDOW_SECONDS,
            SCIM_TARGET_CHECK_LOCKOUT_SECONDS
        );
        throw $e;
    }
}

function scim_connector_save(
    string $storePath,
    string $providerId,
    array $input,
    ?string $existingId = null,
    string $actor = ""
): array {
    $pdo = scim_db($storePath);
    $existingRow = null;
    if ($existingId !== null) {
        $st = $pdo->prepare(
            "SELECT * FROM scim_connectors WHERE id = :id AND provider_id = :pid LIMIT 1"
        );
        $st->execute([":id" => $existingId, ":pid" => $providerId]);
        $existingRow = $st->fetch(PDO::FETCH_ASSOC);
        $st->closeCursor();
        if (!$existingRow) {
            throw new RuntimeException("SCIM connector not found");
        }
    }
    foreach (["name", "delivery_mode", "scim_base_url", "bearer_token", "deprovision_action", "status"] as $field) {
        if (isset($input[$field]) && !is_string($input[$field])) {
            throw new InvalidArgumentException("$field must be a string");
        }
    }
    // Enumerated settings that are sent must be valid: a typo must not silently turn into
    // another mode, keep a connector meant to be paused active, or change deprovisioning.
    $enumFields = [
        "delivery_mode" => ["direct", "agent"],
        "status" => ["active", "paused"],
        "deprovision_action" => ["deactivate", "delete"],
    ];
    foreach ($enumFields as $field => $allowed) {
        if (isset($input[$field])) {
            $input[$field] = strtolower(trim($input[$field]));
            if (!in_array($input[$field], $allowed, true)) {
                throw new InvalidArgumentException("$field must be one of: " . implode(", ", $allowed));
            }
        }
    }

    // Password push keeps a recoverable copy of every password it sends (S04-08), so it cannot
    // be turned on (a new connector with it, or a connector going from off to on) while the
    // only vault key is the key file next to the database. A connector that already pushes
    // stays editable: it sends no password until push is allowed (scim_connector_sync_run()).
    // Checked before the target URL is resolved or anything is written.
    $pushPasswords = array_key_exists("push_passwords", $input)
        ? (!empty($input["push_passwords"]) ? 1 : 0)
        : (int) ($existingRow["push_passwords"] ?? 0);
    if (
        $pushPasswords === 1 &&
        (int) ($existingRow["push_passwords"] ?? 0) !== 1 &&
        !vault_password_push_allowed()
    ) {
        throw new InvalidArgumentException(vault_password_push_blocked_reason());
    }

    $name = trim((string) ($input["name"] ?? ($existingRow["name"] ?? "")));
    if ($name === "") {
        throw new InvalidArgumentException("Connector name is required");
    }

    $reqMode = (string) ($input["delivery_mode"] ?? ($existingRow["delivery_mode"] ?? "direct"));
    $deliveryMode = in_array($reqMode, ["direct", "agent"], true) ? $reqMode : "direct";
    $existingMode = $existingRow !== null ? (string) ($existingRow["delivery_mode"] ?? "direct") : null;
    $modeChanged = $existingMode !== null && $existingMode !== $deliveryMode;

    $rawBaseUrl = trim(
        (string) ($input["scim_base_url"] ?? ($existingRow["scim_base_url"] ?? ""))
    );
    $urlChanged = false;
    if ($deliveryMode === "agent") {
        // In agent mode, the target URL lives on the on-premises network (configured in Windows config.json)
        $scimBaseUrl = $rawBaseUrl !== "" ? rtrim($rawBaseUrl, "/") : "agent://on-premises";
    } else {
        // A cheap textual comparison first: the input checks below run before the target
        // host is resolved, so a request that fails them never triggers a DNS lookup.
        $scimBaseUrl = rtrim($rawBaseUrl, "/");
        $urlChanged = $existingRow !== null &&
            scim_url_compare_key((string) ($existingRow["scim_base_url"] ?? "")) !== scim_url_compare_key($scimBaseUrl);
    }

    // The downstream bearer token is write-only and is only ever sent to the URL it was
    // saved with: changing the target URL or the delivery mode needs the token again in the
    // same request, and agent mode (whose relay never uses it) drops the stored token.
    $rawToken = trim((string) ($input["bearer_token"] ?? ""));
    $tokenReplaced = false;
    if ($deliveryMode === "agent") {
        $tokenEnc = "";
        $tokenPreview = "on-prem local";
    } elseif ($rawToken !== "") {
        $tokenEnc = vault_encrypt_secret($storePath, $rawToken);
        // Third-party secret: the preview never shows its start, and its end only for long tokens.
        $tokenPreview = secret_preview_mask($rawToken);
        $tokenReplaced = true;
    } elseif ($existingRow === null || (string) ($existingRow["bearer_token_enc"] ?? "") === "") {
        throw new InvalidArgumentException("SCIM Bearer token is required for direct connectors");
    } elseif ($modeChanged || $urlChanged) {
        throw new InvalidArgumentException(
            "Re-enter the SCIM Bearer token when changing the target URL or delivery mode"
        );
    } else {
        $tokenEnc = (string) $existingRow["bearer_token_enc"];
        $tokenPreview = (string) $existingRow["token_preview"];
    }

    if ($deliveryMode === "direct") {
        $scimBaseUrl = scim_connector_validate_target($storePath, $providerId, $rawBaseUrl)["url"];
        $validatedChanged = $existingRow !== null &&
            scim_url_compare_key((string) ($existingRow["scim_base_url"] ?? "")) !== scim_url_compare_key($scimBaseUrl);
        if ($validatedChanged && !$tokenReplaced) {
            // Never reached when both comparisons agree; kept so a normalization difference
            // can never send the stored token to another target.
            throw new InvalidArgumentException(
                "Re-enter the SCIM Bearer token when changing the target URL or delivery mode"
            );
        }
        $urlChanged = $validatedChanged;
    }

    // The agent token lives only while the connector is in agent mode: leaving agent mode
    // revokes it and entering agent mode always mints a new one.
    $mintedAgentPlain = null;
    $agentTokenId = $existingRow["agent_token_id"] ?? null;
    $agentSecretHash = $existingRow["agent_secret_hash"] ?? null;
    $agentSecretPreview = $existingRow["agent_secret_preview"] ?? null;
    $agentTokenRevoked = false;
    if ($deliveryMode !== "agent") {
        $agentTokenRevoked = !empty($agentTokenId);
        $agentTokenId = null;
        $agentSecretHash = null;
        $agentSecretPreview = null;
    } elseif ($existingMode !== "agent" || empty($agentTokenId) || !empty($input["rotate_agent_token"])) {
        $agentTokenRevoked = !empty($agentTokenId);
        $agentTokenId = bin2hex(random_bytes(8));
        $mintedAgentPlain =
            "idp_sagt_" . $agentTokenId . "_" . base64url_encode(random_bytes(28));
        $agentSecretHash = machine_secret_hash($mintedAgentPlain);
        $agentSecretPreview = "idp_sagt_" . substr($agentTokenId, 0, 6) . "••••••••";
    }
    // A revoked or new agent token starts without the previous agent's liveness: heartbeat,
    // labels, open poll lease, claim/result times and reported timeout. The assignments are
    // chosen here, not with a bound flag in SQL: PDO binds execute() values as text, and
    // SQLite never finds the text '1' equal to the integer 1.
    $agentStateResetSql = ($agentTokenRevoked || $mintedAgentPlain !== null)
        ? "agent_last_seen_at = NULL, agent_hostname = NULL, agent_version = NULL, agent_last_ip = NULL, " .
            "agent_poll_until = NULL, agent_last_claim_at = NULL, agent_last_result_at = NULL, " .
            "agent_local_timeout = NULL, "
        : "";

    // Remote ids issued by the previous target mean nothing to a new one.
    $resetMappings = $existingRow !== null &&
        ($modeChanged || $urlChanged || !empty($input["reset_remote_mappings"]));

    $syncGroups = array_key_exists("sync_groups", $input)
        ? (!empty($input["sync_groups"]) ? 1 : 0)
        : (int) ($existingRow["sync_groups"] ?? 1);

    $autoSync = array_key_exists("auto_sync", $input)
        ? (!empty($input["auto_sync"]) ? 1 : 0)
        : (int) ($existingRow["auto_sync"] ?? 1);

    // Sent values were validated above; a stored value from an older release that is not
    // valid falls back to the default.
    $reqDeprov = (string) ($input["deprovision_action"] ?? ($existingRow["deprovision_action"] ?? "deactivate"));
    $deprovisionAction = in_array($reqDeprov, ["deactivate", "delete"], true)
        ? $reqDeprov
        : "deactivate";

    $assignedGroups = array_key_exists("assigned_groups", $input)
        ? normalize_string_list($input["assigned_groups"])
        : (json_decode((string) ($existingRow["assigned_groups_json"] ?? "[]"), true) ?: []);

    $reqStatus = (string) ($input["status"] ?? ($existingRow["status"] ?? "active"));
    $status = in_array($reqStatus, ["active", "paused"], true) ? $reqStatus : "active";

    $auditDetails = [
        "delivery_mode" => $deliveryMode,
        "target_host" => $deliveryMode === "direct" ? (string) parse_url($scimBaseUrl, PHP_URL_HOST) : "",
        "bearer_token_replaced" => $tokenReplaced,
        "agent_token_minted" => $mintedAgentPlain !== null,
        "agent_token_revoked" => $agentTokenRevoked,
    ];

    if ($existingId !== null) {
        $upd = $pdo->prepare(
            "UPDATE scim_connectors SET name = :name, delivery_mode = :dm, scim_base_url = :url, bearer_token_enc = :enc, " .
                "token_preview = :prev, agent_token_id = :atid, agent_secret_hash = :ash, agent_secret_preview = :asprev, " .
                $agentStateResetSql .
                "sync_groups = :sg, push_passwords = :ppw, auto_sync = :as, " .
                "deprovision_action = :dep, assigned_groups_json = :ag, status = :st, circuit_open_until = NULL " .
                "WHERE id = :id AND provider_id = :pid"
        );
        // A sync that is still running would write mappings of the previous target after
        // the reset, so the reset takes the connector's sync lease (or waits for the sync).
        // The lease is taken without clearing sync_pending: a sync requested meanwhile is
        // run after the save (see below) instead of being dropped.
        $resetLease = null;
        if ($resetMappings) {
            $resetLease = scim_sync_acquire_lease($pdo, $providerId, $existingId, false);
            if ($resetLease === null) {
                throw new RuntimeException(
                    "A sync of this connector is running; save the new target again when it has finished"
                );
            }
        }
        $updParams = [
            ":name" => $name,
            ":dm" => $deliveryMode,
            ":url" => $scimBaseUrl,
            ":enc" => $tokenEnc,
            ":prev" => $tokenPreview,
            ":atid" => $agentTokenId,
            ":ash" => $agentSecretHash,
            ":asprev" => $agentSecretPreview,
            ":sg" => $syncGroups,
            ":ppw" => $pushPasswords,
            ":as" => $autoSync,
            ":dep" => $deprovisionAction,
            ":ag" => json_encode($assignedGroups, JSON_UNESCAPED_SLASHES),
            ":st" => $status,
            ":id" => $existingId,
            ":pid" => $providerId,
        ];
        try {
            // One BEGIN IMMEDIATE write transaction (storage_write_transaction()): the update,
            // the mapping reset and the relay job cleanup commit or roll back together.
            storage_write_transaction(
                $pdo,
                function (PDO $pdo) use (
                    $upd,
                    $updParams,
                    $resetMappings,
                    $existingId,
                    $existingMode,
                    $deliveryMode,
                    $mintedAgentPlain
                ): void {
                    $upd->execute($updParams);
                    if ($resetMappings) {
                        $pdo->prepare("DELETE FROM scim_remote_mappings WHERE connector_id = :cid")
                            ->execute([":cid" => $existingId]);
                    }
                    if ($existingMode === "agent" && $deliveryMode !== "agent") {
                        // No agent serves this connector any more: its queued relay jobs (whose
                        // encrypted bodies may carry passwords) are dropped.
                        $pdo->prepare("DELETE FROM scim_agent_jobs WHERE connector_id = :cid")
                            ->execute([":cid" => $existingId]);
                    } elseif ($existingMode === "agent" && $mintedAgentPlain !== null) {
                        // The previous token can no longer post results, so jobs claimed with it
                        // are given up now instead of holding their waiters until the answer
                        // deadline. Pending jobs stay for the agent that uses the new token.
                        $pdo->prepare(
                            "UPDATE scim_agent_jobs SET status = 'abandoned', request_body_json = NULL, completed_at = :now " .
                                "WHERE connector_id = :cid AND status = 'claimed'"
                        )->execute([":now" => time(), ":cid" => $existingId]);
                    }
                }
            );
        } finally {
            if ($resetLease !== null) {
                scim_sync_release_lease($pdo, $existingId, $resetLease);
            }
        }
        if ($pushPasswords === 0) {
            // This may have been the owner's last connector that pushes passwords.
            scim_purge_unused_password_copies($pdo, $providerId);
        }
        if ($resetLease !== null && scim_sync_pending_value($pdo, $existingId) > 0) {
            // A sync requested while the save held the lease (or queued before it) runs
            // after this response, against the saved target, under the usual auto-sync rules.
            scim_schedule_connector_sync($storePath, $providerId, $existingId);
        }
        audit_log_append(
            $storePath,
            $providerId,
            "scim",
            "scim_connector_updated",
            "success",
            $name,
            $actor,
            [],
            $auditDetails + [
                "previous_target_host" => $existingMode === "direct"
                    ? (string) parse_url((string) ($existingRow["scim_base_url"] ?? ""), PHP_URL_HOST)
                    : "",
                "target_changed" => $modeChanged || $urlChanged,
                "remote_mappings_reset" => $resetMappings,
            ]
        );
        $saved = scim_connector_get($storePath, $providerId, $existingId) ?? [];
        if ($mintedAgentPlain !== null) {
            $saved["agent_token"] = $mintedAgentPlain;
        }
        return $saved;
    }

    $id = uuidv4();
    $now = gmdate("Y-m-d\TH:i:s\Z");
    $ins = $pdo->prepare(
        "INSERT INTO scim_connectors (" .
            "id, provider_id, name, delivery_mode, scim_base_url, bearer_token_enc, token_preview, " .
            "agent_token_id, agent_secret_hash, agent_secret_preview, " .
            "sync_groups, push_passwords, auto_sync, deprovision_action, assigned_groups_json, status, created_at" .
        ") VALUES (:id, :pid, :name, :dm, :url, :enc, :prev, :atid, :ash, :asprev, :sg, :ppw, :as, :dep, :ag, :st, :cat)"
    );
    $ins->execute([
        ":id" => $id,
        ":pid" => $providerId,
        ":name" => $name,
        ":dm" => $deliveryMode,
        ":url" => $scimBaseUrl,
        ":enc" => $tokenEnc,
        ":prev" => $tokenPreview,
        ":atid" => $agentTokenId,
        ":ash" => $agentSecretHash,
        ":asprev" => $agentSecretPreview,
        ":sg" => $syncGroups,
        ":ppw" => $pushPasswords,
        ":as" => $autoSync,
        ":dep" => $deprovisionAction,
        ":ag" => json_encode($assignedGroups, JSON_UNESCAPED_SLASHES),
        ":st" => $status,
        ":cat" => $now,
    ]);
    audit_log_append($storePath, $providerId, "scim", "scim_connector_created", "success", $name, $actor, [], $auditDetails);
    $saved = scim_connector_get($storePath, $providerId, $id) ?? [];
    if ($mintedAgentPlain !== null) {
        $saved["agent_token"] = $mintedAgentPlain;
    }
    return $saved;
}

/**
 * After a connector of $providerId was saved with push_passwords off, or deleted: clears the
 * password copies of the provider's owner that no connector may push any more
 * (vault_purge_unused_password_copies(), S04-08). Call it after the connector change has
 * committed, with no unfinished SELECT on $pdo. A failure is logged and does not fail the
 * save or delete; the copies are then cleared by the owner's next connector save or delete,
 * or when the password copy policy changes.
 */
function scim_purge_unused_password_copies(PDO $pdo, string $providerId): void
{
    try {
        $stmt = $pdo->prepare("SELECT owner FROM providers WHERE id = :pid LIMIT 1");
        $stmt->execute([":pid" => $providerId]);
        $owner = $stmt->fetchColumn();
        $stmt->closeCursor();
        if (is_string($owner) && $owner !== "") {
            vault_purge_unused_password_copies($pdo, $owner);
        }
    } catch (Throwable $e) {
        error_log("SCIM connector change: clearing unused password copies failed: " . $e->getMessage());
    }
}

function scim_connector_delete(
    string $storePath,
    string $providerId,
    string $connectorId,
    string $actor = ""
): bool {
    $pdo = storage_db($storePath);
    $sel = $pdo->prepare(
        "SELECT name, delivery_mode, scim_base_url FROM scim_connectors WHERE id = :id AND provider_id = :pid LIMIT 1"
    );
    $sel->execute([":id" => $connectorId, ":pid" => $providerId]);
    $row = $sel->fetch(PDO::FETCH_ASSOC);
    // Ends the read snapshot before the writes below (see storage_write_transaction()).
    $sel->closeCursor();
    $stmt = $pdo->prepare(
        "DELETE FROM scim_connectors WHERE id = :id AND provider_id = :pid"
    );
    $stmt->execute([":id" => $connectorId, ":pid" => $providerId]);
    $deleted = $stmt->rowCount() > 0;
    if ($deleted) {
        // This may have been the owner's last connector that pushes passwords.
        scim_purge_unused_password_copies($pdo, $providerId);
    }
    if ($deleted && is_array($row)) {
        audit_log_append(
            $storePath,
            $providerId,
            "scim",
            "scim_connector_deleted",
            "success",
            (string) $row["name"],
            $actor,
            [],
            [
                "delivery_mode" => (string) ($row["delivery_mode"] ?? "direct"),
                "target_host" => ($row["delivery_mode"] ?? "direct") === "direct"
                    ? (string) parse_url((string) $row["scim_base_url"], PHP_URL_HOST)
                    : "",
            ]
        );
    }
    return $deleted;
}

/** Generic description of a libcurl failure; the full error goes to the server log. */
function scim_curl_error_summary(int $errno): string
{
    // libcurl error numbers are a stable ABI.
    if ($errno === 28) {
        return "the request timed out";
    }
    if ($errno === 6 || $errno === 7) {
        return "could not connect to the target";
    }
    if ($errno === 23 || $errno === 63) {
        return "the response exceeded " . intdiv(SCIM_OUTBOUND_MAX_RESPONSE_BYTES, 1048576) . " MiB";
    }
    if (in_array($errno, [35, 51, 53, 54, 58, 59, 60, 64, 66, 77, 80, 82, 83, 90, 91], true)) {
        return "TLS handshake or certificate verification failed";
    }
    return "transport error";
}

/**
 * Executes an SSRF-hardened outbound SCIM 2.0 HTTP request. libcurl must connect to the
 * address scim_validate_outbound_url() resolved: CURLOPT_CONNECT_TO with an empty host
 * matches whatever host name libcurl derives from the URL, the peer is re-checked before
 * the request is sent (CURLOPT_PREREQFUNCTION, PHP 8.4 with libcurl 7.80+) and after the
 * transfer (CURLINFO_PRIMARY_IP). Proxies and redirects are disabled and the response is
 * capped at SCIM_OUTBOUND_MAX_RESPONSE_BYTES. ext-curl is required; there is no unpinned
 * fallback transport.
 *
 * A response larger than the cap is not a transport failure: the request was delivered and
 * its HTTP status is known (compliant targets echo the whole resource on PUT and POST, so a
 * large group easily exceeds the cap). It is returned like an agent relay answer the agent
 * had to cut: "truncated" set, the status and the start of the raw body kept, the body not
 * parsed. Callers that need the body (lookups, the id of a created resource) handle that.
 *
 * @return array{status: int, body: ?array, raw: string, truncated: bool}
 */
function scim_outbound_http_request(
    array $validatedBase,
    string $bearerToken,
    string $method,
    string $endpointPath,
    ?array $jsonPayload = null,
    int $timeoutSeconds = SCIM_OUTBOUND_TIMEOUT_SECONDS
): array {
    if (!function_exists("curl_init") || !defined("CURLOPT_CONNECT_TO")) {
        throw new ScimTransportException("Outbound SCIM requires the PHP curl extension");
    }
    $pinnedIp = (string) ($validatedBase["pinned_ip"] ?? "");
    $pinnedBin = filter_var($pinnedIp, FILTER_VALIDATE_IP) !== false ? inet_pton($pinnedIp) : false;
    $port = (int) ($validatedBase["port"] ?? 0);
    if (!is_string($pinnedBin) || $port < 1 || $port > 65535) {
        throw new ScimTransportException("Outbound SCIM target address was not validated");
    }
    $hostLabel = (string) ($validatedBase["host"] ?? "");
    $fullUrl = $validatedBase["url"] . "/" . ltrim($endpointPath, "/");
    $headers = [
        "Authorization: Bearer " . $bearerToken,
        "Accept: application/scim+json, application/json",
        "User-Agent: IdentityCloud-SCIM/2.0",
    ];
    $encodedBody = null;
    if ($jsonPayload !== null) {
        $encodedBody = json_encode($jsonPayload, JSON_UNESCAPED_SLASHES);
        if ($encodedBody === false) {
            throw new RuntimeException("Could not encode the outbound SCIM payload");
        }
        $headers[] = "Content-Type: application/scim+json; charset=utf-8";
    }

    $ch = curl_init();
    if ($ch === false) {
        throw new ScimTransportException("Failed to initialize cURL for SCIM push");
    }
    $timeout = max(1, $timeoutSeconds);
    $connectHost = str_contains($pinnedIp, ":") ? "[" . $pinnedIp . "]" : $pinnedIp;
    $body = "";
    $overflow = false;
    $opts = [
        CURLOPT_URL => $fullUrl,
        CURLOPT_CUSTOMREQUEST => strtoupper($method),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS => 0,
        CURLOPT_CONNECTTIMEOUT => min(SCIM_OUTBOUND_CONNECT_TIMEOUT_SECONDS, $timeout),
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_NOSIGNAL => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        // An empty proxy disables any proxy from the environment: the pin must hold end to end.
        CURLOPT_PROXY => "",
        // "HOST:PORT:CONNECT-TO-HOST:CONNECT-TO-PORT" with empty HOST and PORT matches every
        // connection, whatever host name libcurl derives (it percent-decodes and IDN-converts).
        CURLOPT_CONNECT_TO => ["::" . $connectHost . ":" . $port],
        CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use (&$body, &$overflow): int {
            if (strlen($body) + strlen($chunk) > SCIM_OUTBOUND_MAX_RESPONSE_BYTES) {
                $overflow = true;
                return 0; // aborts the transfer (CURLE_WRITE_ERROR)
            }
            $body .= $chunk;
            return strlen($chunk);
        },
    ];
    if (defined("CURLOPT_MAXFILESIZE_LARGE")) {
        $opts[CURLOPT_MAXFILESIZE_LARGE] = SCIM_OUTBOUND_MAX_RESPONSE_BYTES;
    }
    if (defined("CURLPROTO_HTTP") && defined("CURLPROTO_HTTPS")) {
        $opts[CURLOPT_PROTOCOLS] = ($validatedBase["scheme"] ?? "https") === "http"
            ? CURLPROTO_HTTP
            : CURLPROTO_HTTPS;
    }
    if (defined("CURLOPT_PREREQFUNCTION") && defined("CURL_PREREQFUNC_OK") && defined("CURL_PREREQFUNC_ABORT")) {
        $opts[CURLOPT_PREREQFUNCTION] = static function (
            $handle,
            string $primaryIp,
            string $localIp,
            int $primaryPort,
            int $localPort
        ) use ($pinnedBin, $port): int {
            $reached = filter_var($primaryIp, FILTER_VALIDATE_IP) !== false &&
                inet_pton($primaryIp) === $pinnedBin &&
                $primaryPort === $port;
            return $reached ? CURL_PREREQFUNC_OK : CURL_PREREQFUNC_ABORT;
        };
    }
    if ($encodedBody !== null) {
        $opts[CURLOPT_POSTFIELDS] = $encodedBody;
    }
    if (!curl_setopt_array($ch, $opts)) {
        throw new ScimTransportException("Could not configure the pinned outbound SCIM connection");
    }
    $ok = curl_exec($ch);
    $errno = curl_errno($ch);
    $curlErr = curl_error($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $primaryIp = (string) curl_getinfo($ch, CURLINFO_PRIMARY_IP);
    unset($ch);

    if (
        $primaryIp !== "" &&
        (filter_var($primaryIp, FILTER_VALIDATE_IP) === false || inet_pton($primaryIp) !== $pinnedBin)
    ) {
        error_log(
            "SCIM outbound request to " . $hostLabel . " reached " . $primaryIp .
                " instead of " . $pinnedIp . "; response discarded"
        );
        throw new ScimTransportException("Outbound SCIM connection did not reach the validated address");
    }
    // Stopped by the response cap (the write counter, or CURLOPT_MAXFILESIZE_LARGE on the
    // announced length) after the status line arrived: a truncated answer, not a failure.
    $capped = $ok === false && ($overflow || $errno === 63) && $httpCode >= 100;
    if ($ok === false && !$capped) {
        error_log(
            "SCIM outbound request to " . $hostLabel . " (" . $pinnedIp . ") failed: curl error " .
                $errno . ": " . $curlErr
        );
        throw new ScimTransportException(
            "Outbound SCIM request failed: " . scim_curl_error_summary($errno),
            $errno === 28
        );
    }
    if ($primaryIp === "") {
        throw new ScimTransportException("Outbound SCIM connection did not report its peer address");
    }
    if ($capped) {
        error_log(
            "SCIM outbound " . strtoupper($method) . " to " . $hostLabel . " answered HTTP " . $httpCode .
                " with more than " . SCIM_OUTBOUND_MAX_RESPONSE_BYTES . " bytes; only its status was used"
        );
        return [
            "status" => $httpCode,
            "body" => null,
            "raw" => substr($body, 0, 1000),
            "truncated" => true,
        ];
    }
    $decoded = $body !== "" ? json_decode($body, true) : null;
    return [
        "status" => $httpCode,
        "body" => is_array($decoded) ? $decoded : null,
        "raw" => substr($body, 0, 1000),
        "truncated" => false,
    ];
}

function scim_connector_load_secret_row(
    string $storePath,
    string $providerId,
    string $connectorId
): array {
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM scim_connectors WHERE id = :id AND provider_id = :pid LIMIT 1"
    );
    $stmt->execute([":id" => $connectorId, ":pid" => $providerId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        throw new RuntimeException("SCIM connector not found");
    }
    $mode = (string) ($row["delivery_mode"] ?? "direct");
    $enc = (string) ($row["bearer_token_enc"] ?? "");
    $token = $enc !== "" ? vault_decrypt_secret($storePath, $enc) : "";
    if ($mode === "direct" && ($token === null || $token === "")) {
        throw new RuntimeException("Unable to decrypt connector Bearer token; please re-save token");
    }
    $row["_plain_token"] = $token ?? "";
    return $row;
}

/** Size of a relay job (or poll answer envelope) as json_response() encodes it. */
function scim_agent_json_bytes(array $value): int
{
    $json = json_encode($value, JSON_UNESCAPED_SLASHES);
    return is_string($json) ? strlen($json) : PHP_INT_MAX;
}

/** A queued relay job as the agent receives it, its body decrypted; null when that fails. */
function scim_agent_job_entry(string $storePath, array $job): ?array
{
    $stored = $job["request_body_json"] ?? null;
    $body = null;
    if (is_string($stored) && $stored !== "") {
        $body = vault_decrypt_secret($storePath, $stored);
        if ($body === null) {
            return null;
        }
    }
    return [
        "id" => (string) $job["id"],
        "method" => (string) $job["method"],
        "endpoint_path" => (string) $job["endpoint_path"],
        "body_raw" => $body,
    ];
}

/**
 * Relays one outbound SCIM request through the connector's on-premises agent and waits for
 * its result.
 * - The request body is stored encrypted with the vault key (it can carry a password with
 *   push_passwords) and is decrypted only into the authenticated agent's poll answer.
 * - A request that cannot fit into one poll answer is refused before it is queued, with a
 *   RuntimeException that fails only this resource.
 * - The job may wait $timeoutSeconds for the agent to claim it. Once claimed, its result is
 *   awaited until the agent's local timeout plus a grace has passed since the claim
 *   (scim_agent_answer_grace_seconds()), whatever $timeoutSeconds is, so a slow but working
 *   target is not reported as failed while the operation is being applied.
 * - A job the waiter gives up on is marked 'abandoned', never deleted while an agent may
 *   still answer it, and its late result is discarded.
 *
 * @return array{status: int, body: ?array, raw: string, truncated: bool}
 */
function scim_relay_via_agent_queue(
    string $storePath,
    string $connectorId,
    string $method,
    string $endpointPath,
    ?array $jsonPayload = null,
    int $timeoutSeconds = SCIM_AGENT_RELAY_TIMEOUT_SECONDS
): array {
    if (session_status() === PHP_SESSION_ACTIVE) {
        @session_write_close();
    }
    $pdo = scim_db($storePath);
    $now = time();
    // No job older than this has a waiter left, whatever its state.
    $pdo->prepare("DELETE FROM scim_agent_jobs WHERE created_at < :cut")->execute([
        ":cut" => $now - SCIM_AGENT_JOB_MAX_AGE_SECONDS,
    ]);

    $jobId = uuidv4();
    $method = strtoupper($method);
    $endpoint = ltrim($endpointPath, "/");
    $bodyJson = null;
    if ($jsonPayload !== null) {
        $bodyJson = json_encode($jsonPayload, JSON_UNESCAPED_SLASHES);
        if (!is_string($bodyJson)) {
            throw new RuntimeException("Could not encode the outbound SCIM payload");
        }
    }
    $entryBytes = scim_agent_json_bytes([
        "id" => $jobId,
        "method" => $method,
        "endpoint_path" => $endpoint,
        "body_raw" => $bodyJson,
    ]);
    if ($entryBytes > SCIM_AGENT_JOB_MAX_BYTES) {
        throw new RuntimeException(sprintf(
            "the request (%d KiB) is larger than the %d KiB the on-premises agent relay can deliver",
            (int) ceil($entryBytes / 1024),
            intdiv(SCIM_AGENT_JOB_MAX_BYTES, 1024)
        ));
    }

    $ins = $pdo->prepare(
        "INSERT INTO scim_agent_jobs (id, connector_id, method, endpoint_path, request_body_json, status, created_at) " .
            "VALUES (:id, :cid, :m, :ep, :b, 'pending', :cat)"
    );
    $ins->execute([
        ":id" => $jobId,
        ":cid" => $connectorId,
        ":m" => $method,
        ":ep" => $endpoint,
        ":b" => $bodyJson !== null ? vault_encrypt_secret($storePath, $bodyJson) : null,
        ":cat" => $now,
    ]);

    $pollStmt = $pdo->prepare(
        "SELECT j.status, j.claimed_at, j.response_status, j.response_body_raw, j.response_truncated, " .
            "j.error_message, c.agent_local_timeout FROM scim_agent_jobs AS j " .
            "LEFT JOIN scim_connectors AS c ON c.id = j.connector_id WHERE j.id = :id LIMIT 1"
    );
    $delStmt = $pdo->prepare("DELETE FROM scim_agent_jobs WHERE id = :id");
    $abandonStmt = $pdo->prepare(
        "UPDATE scim_agent_jobs SET status = 'abandoned', request_body_json = NULL, completed_at = :now " .
            "WHERE id = :id AND status = :expected"
    );

    // Never longer than the window in which polls still hand a pending job out.
    $pickupSeconds = max(2, min(SCIM_AGENT_RELAY_TIMEOUT_SECONDS, $timeoutSeconds));
    $pickupDeadline = microtime(true) + $pickupSeconds;
    $answerDeadline = null;
    $claimSeenAt = null;
    $answerSeconds = 0;
    while (true) {
        // Results usually arrive within a second; a long-running job is checked less often.
        usleep($claimSeenAt !== null && microtime(true) - $claimSeenAt > 5.0 ? 200000 : 60000);
        $pollStmt->execute([":id" => $jobId]);
        $jr = $pollStmt->fetch(PDO::FETCH_ASSOC);
        $pollStmt->closeCursor();
        if (!is_array($jr)) {
            throw new ScimTransportException("SCIM agent relay job unexpectedly disappeared");
        }
        $state = (string) $jr["status"];
        if ($state === "completed") {
            $delStmt->execute([":id" => $jobId]);
            // A body the agent had to cut is not parsed: callers see the status only.
            $truncated = (int) ($jr["response_truncated"] ?? 0) === 1;
            $rawStr = (string) ($jr["response_body_raw"] ?? "");
            $decoded = !$truncated && $rawStr !== "" ? json_decode($rawStr, true) : null;
            return [
                "status" => (int) ($jr["response_status"] ?? 0),
                "body" => is_array($decoded) ? $decoded : null,
                "raw" => substr($rawStr, 0, 1000),
                "truncated" => $truncated,
            ];
        }
        if ($state === "failed") {
            $delStmt->execute([":id" => $jobId]);
            $agentError = sanitize_label((string) ($jr["error_message"] ?? ""), 300);
            throw new ScimTransportException(
                "On-premises SCIM Agent transport error: " . ($agentError !== "" ? $agentError : "Unknown error")
            );
        }
        if ($state === "abandoned") {
            // Given up by the queue housekeeping or by an agent token rotation.
            throw new ScimTransportException("The on-premises SCIM agent relay job was abandoned before its result arrived");
        }
        $nowF = microtime(true);
        if ($state === "claimed") {
            if ($answerDeadline === null) {
                $claimSeenAt = $nowF;
                $answerSeconds = scim_agent_answer_grace_seconds($jr["agent_local_timeout"] ?? null);
                $claimedAt = (int) ($jr["claimed_at"] ?? 0);
                $answerDeadline = min(
                    (float) ($claimedAt > 0 ? $claimedAt : time()) + $answerSeconds,
                    $nowF + $answerSeconds
                );
            }
            if ($nowF < $answerDeadline) {
                continue;
            }
        } elseif ($nowF < $pickupDeadline) {
            continue;
        }
        // Past the deadline of its current state: the job is given up unless it just moved on.
        $abandonStmt->execute([":now" => time(), ":id" => $jobId, ":expected" => $state]);
        if ($abandonStmt->rowCount() !== 1) {
            continue;
        }
        if ($state === "claimed") {
            throw new ScimTransportException(
                "The on-premises SCIM agent took the request but reported no result within {$answerSeconds} s; " .
                    "the change may still have been applied on-premises",
                true
            );
        }
        if ($pickupSeconds < SCIM_AGENT_RELAY_TIMEOUT_SECONDS) {
            // The sync's time budget had shortened the pickup wait: the budget is used up,
            // which says nothing about the agent (no circuit; the next sync continues).
            throw new ScimSyncAbortException(
                "the " . SCIM_SYNC_TIME_BUDGET_SECONDS . " s time budget of this sync ran out before the " .
                    "on-premises agent picked up the request"
            );
        }
        throw new ScimTransportException(
            "The on-premises SCIM agent did not pick up the request within {$pickupSeconds} s; " .
                "check that scim-agent.exe is running and connected",
            true
        );
    }
}

/**
 * Sends one outbound SCIM request through the connector's transport. With a $deadline
 * (the sync time budget), the request's own timeout never runs past it, and a used-up
 * budget stops the sync run (ScimSyncAbortException). For agent connectors the budget
 * bounds the wait for the agent to pick the job up; a job the agent has already claimed is
 * awaited until its answer deadline, so the result of a change being applied on-premises
 * is not thrown away. A wait that only timed out because the budget had shortened it also
 * stops the run (ScimSyncAbortException), so the end of a budget never opens the circuit.
 */
function scim_execute_connector_request(
    string $storePath,
    array $connectorRow,
    ?array $validatedBase,
    string $method,
    string $endpointPath,
    ?array $jsonPayload = null,
    ?float $deadline = null
): array {
    $isAgent = ($connectorRow["delivery_mode"] ?? "direct") === "agent";
    $timeout = $isAgent ? SCIM_AGENT_RELAY_TIMEOUT_SECONDS : SCIM_OUTBOUND_TIMEOUT_SECONDS;
    if ($deadline !== null) {
        $remaining = $deadline - microtime(true);
        if ($remaining < 1.0) {
            throw new ScimSyncAbortException(
                "the " . SCIM_SYNC_TIME_BUDGET_SECONDS . " s time budget of this sync is used up"
            );
        }
        $timeout = max(1, min($timeout, (int) floor($remaining)));
    }
    if ($isAgent) {
        return scim_relay_via_agent_queue(
            $storePath,
            (string) $connectorRow["id"],
            $method,
            $endpointPath,
            $jsonPayload,
            $timeout
        );
    }
    if ($validatedBase === null) {
        throw new RuntimeException("Missing validated SCIM base URL");
    }
    try {
        return scim_outbound_http_request(
            $validatedBase,
            (string) $connectorRow["_plain_token"],
            $method,
            $endpointPath,
            $jsonPayload,
            $timeout
        );
    } catch (ScimTransportException $e) {
        if ($e->timedOut && $timeout < SCIM_OUTBOUND_TIMEOUT_SECONDS) {
            throw new ScimSyncAbortException(
                "the " . SCIM_SYNC_TIME_BUDGET_SECONDS . " s time budget of this sync ran out while waiting for the target",
                0,
                $e
            );
        }
        throw $e;
    }
}

function scim_connector_test(
    string $storePath,
    array $provider,
    string $connectorId
): array {
    $row = scim_connector_load_secret_row($storePath, $provider["id"], $connectorId);
    $isAgent = ($row["delivery_mode"] ?? "direct") === "agent";
    if ($isAgent && !scim_agent_polled_recently($row)) {
        // Nobody would pick the job up: answer at once instead of holding the request for
        // the relay timeout. (An agent that polls but stalls is still tried: a test is how
        // an administrator checks that it answers again.)
        throw new RuntimeException(scim_agent_offline_message());
    }
    $validated = $isAgent
        ? null
        : scim_validate_outbound_url((string) $row["scim_base_url"]);
    $t0 = microtime(true);
    $resp = scim_execute_connector_request(
        $storePath,
        $row,
        $validated,
        "GET",
        "Users?startIndex=1&count=1"
    );
    $latencyMs = (int) round((microtime(true) - $t0) * 1000);

    if ($resp["status"] >= 200 && $resp["status"] < 300) {
        $agentHost = sanitize_label((string) ($row["agent_hostname"] ?? ""), 120);
        $via = $isAgent
            ? " via On-Premises Windows Agent" . ($agentHost !== "" ? " ({$agentHost})" : "")
            : "";
        $remoteTotal = $resp["body"]["totalResults"] ?? null;
        return [
            "ok" => true,
            "http_status" => $resp["status"],
            "latency_ms" => $latencyMs,
            "remote_total_users" => is_int($remoteTotal) ? $remoteTotal : null,
            "message" => "Connected to SCIM 2.0 target{$via} ({$latencyMs} ms)",
        ];
    }

    throw new RuntimeException(scim_remote_failure_message("Remote SCIM request", $resp));
}

function scim_agent_offline_message(): string
{
    return "The on-premises SCIM agent has not polled in the last " . SCIM_AGENT_ONLINE_SECONDS .
        " seconds; check that scim-agent.exe is running and connected";
}

/** Valid-UTF-8, bounded text for sync error lists, summaries and audit details. */
function scim_sync_error_text(string $text): string
{
    $clean = sanitize_label($text, 500);
    return $clean !== "" ? $clean : "Unknown error";
}

/** Error message for a non-success HTTP answer of the downstream SCIM server. */
function scim_remote_failure_message(string $what, array $resp): string
{
    $status = (int) ($resp["status"] ?? 0);
    $detail = $resp["body"]["detail"] ?? null;
    $detailText = sanitize_label(is_scalar($detail) ? (string) $detail : (string) ($resp["raw"] ?? ""), 240);
    return "$what failed (HTTP $status)" . ($detailText !== "" ? ": " . $detailText : "");
}

/**
 * A value for an outbound SCIM filter comparison, encoded as a JSON string (RFC 7644
 * compValue), so quotes, backslashes and control characters are escaped correctly.
 */
function scim_filter_string_literal(string $value): string
{
    $json = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (!is_string($json)) {
        throw new RuntimeException("the value is not valid UTF-8 and cannot be used in a SCIM filter");
    }
    return $json;
}

/** Comparison key for userName and displayName values, which are not case-exact (RFC 7643). */
function scim_match_key(string $value): string
{
    return function_exists("mb_strtolower") ? mb_strtolower($value, "UTF-8") : strtolower($value);
}

/**
 * The remote id of the one resource in a lookup answer whose $attr equals $want (case
 * insensitively). Resources that do not match are ignored, so a target that ignores the
 * filter (RFC 7644 makes filtering optional) or applies it loosely cannot make the sync
 * adopt an unrelated account or group. Returns "" when nothing matches; two different
 * matching resources are an error, and nothing is adopted.
 */
function scim_remote_unique_match(mixed $body, string $attr, string $want): string
{
    $resources = is_array($body) ? scim_case_insensitive_get($body, "Resources") : null;
    if (!is_array($resources) || $want === "") {
        return "";
    }
    $wantKey = scim_match_key($want);
    $found = "";
    foreach ($resources as $res) {
        if (!is_array($res)) {
            continue;
        }
        $idRaw = $res["id"] ?? null;
        $id = is_string($idRaw) || is_int($idRaw) ? trim((string) $idRaw) : "";
        $value = scim_case_insensitive_get($res, $attr);
        if ($id === "" || !is_string($value) || scim_match_key($value) !== $wantKey) {
            continue;
        }
        if ($found !== "" && $found !== $id) {
            throw new RuntimeException(
                "the target returned more than one resource with this $attr; nothing was linked"
            );
        }
        $found = $id;
    }
    return $found;
}

/**
 * Change-detection hash of an outbound user payload (scim_remote_mappings.last_pushed_hash).
 * The password is never part of it: an unkeyed SHA-256 over directory data plus the
 * password would let anyone holding a copy of the database test password guesses at GPU
 * speed. With push_passwords on, $passwordMarker (scim_password_change_marker()) makes a
 * newly set password trigger a push all the same.
 */
function scim_user_change_hash(array $payload, ?string $passwordMarker = null): string
{
    unset($payload["password"]);
    $digest = hash(
        "sha256",
        (string) json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)
    );
    return $passwordMarker === null ? $digest : hash("sha256", $digest . "|password:" . $passwordMarker);
}

/**
 * Password part of a user's change-detection hash: a digest of the vault ciphertext of the
 * password, which changes whenever a password is set (each encryption has a fresh IV) and
 * reveals nothing about the password. A ciphertext that could not be decrypted is marked,
 * so the user is pushed again once decryption works.
 */
function scim_password_change_marker(string $passwordEnvelope, ?string $plainPassword): string
{
    if ($passwordEnvelope === "") {
        return "none";
    }
    return hash("sha256", $passwordEnvelope) . ($plainPassword === null ? ":undecryptable" : "");
}

/** Vault ciphertext of each directory user's password (user id => envelope, "" when none). */
function scim_user_password_envelopes(PDO $pdo, string $owner): array
{
    $stmt = $pdo->prepare("SELECT id, password_enc FROM idp_users WHERE owner = :owner");
    $stmt->execute([":owner" => $owner]);
    $out = [];
    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $enc = $r["password_enc"] ?? null;
        $out[(string) $r["id"]] = is_string($enc) ? $enc : "";
    }
    return $out;
}

function scim_sync_empty_stats(): array
{
    return [
        "users_created" => 0,
        "users_updated" => 0,
        "users_unchanged" => 0,
        "users_deprovisioned" => 0,
        "groups_synced" => 0,
        "groups_deprovisioned" => 0,
        "errors" => [],
    ];
}

/**
 * Takes the per-connector sync lease with one conditional UPDATE. Returns the lease value
 * (its expiry, used as the ownership token) or null when another request holds it. With
 * $clearPending (the default) the queued-sync flag is cleared as well; scim_connector_sync()
 * keeps it and takes it with scim_sync_take_pending() once it is about to run.
 */
function scim_sync_acquire_lease(
    PDO $pdo,
    string $providerId,
    string $connectorId,
    bool $clearPending = true
): ?int {
    $now = time();
    $until = $now + SCIM_SYNC_LEASE_SECONDS;
    $st = $pdo->prepare(
        "UPDATE scim_connectors SET sync_lock_until = :until" . ($clearPending ? ", sync_pending = 0" : "") . " " .
            "WHERE id = :id AND provider_id = :pid AND (sync_lock_until IS NULL OR sync_lock_until < :now)"
    );
    $st->execute([":until" => $until, ":id" => $connectorId, ":pid" => $providerId, ":now" => $now]);
    if ($st->rowCount() === 1) {
        return $until;
    }
    $exists = $pdo->prepare("SELECT 1 FROM scim_connectors WHERE id = :id AND provider_id = :pid");
    $exists->execute([":id" => $connectorId, ":pid" => $providerId]);
    if ($exists->fetchColumn() === false) {
        throw new RuntimeException("SCIM connector not found");
    }
    return null;
}

/**
 * The connector's sync_pending value (0 when it does not exist): 0 = nothing queued,
 * 1 = changes queued for the next sync, 2 = a forced (full) sync was requested.
 */
function scim_sync_pending_value(PDO $pdo, string $connectorId): int
{
    $st = $pdo->prepare("SELECT sync_pending FROM scim_connectors WHERE id = :id");
    $st->execute([":id" => $connectorId]);
    $value = $st->fetchColumn();
    $st->closeCursor();
    return $value === false ? 0 : (int) $value;
}

/**
 * Asks the current lease holder for one more run (a forced one with $force). The flag is
 * set in the same statement that checks for a live lease, so it is never left behind by a
 * holder that released the lease in between: false means there is no holder, and the
 * caller takes the lease itself.
 */
function scim_sync_request_rerun(PDO $pdo, string $providerId, string $connectorId, bool $force): bool
{
    $st = $pdo->prepare(
        "UPDATE scim_connectors SET sync_pending = " . ($force ? "2" : "MAX(sync_pending, 1)") . " " .
            "WHERE id = :id AND provider_id = :pid AND sync_lock_until IS NOT NULL AND sync_lock_until >= :now"
    );
    $st->execute([":id" => $connectorId, ":pid" => $providerId, ":now" => time()]);
    return $st->rowCount() === 1;
}

/** Keeps the connector's remaining changes queued for its next sync (a forced request stays). */
function scim_sync_mark_pending(PDO $pdo, string $connectorId): void
{
    try {
        $pdo->prepare("UPDATE scim_connectors SET sync_pending = MAX(sync_pending, 1) WHERE id = :id")
            ->execute([":id" => $connectorId]);
    } catch (Throwable $e) {
        error_log("SCIM: could not queue the next sync of connector " . $connectorId . " (" . get_class($e) . ")");
    }
}

/**
 * Takes the queued-sync flag while holding the lease (compare-and-swap, so a forced request
 * that arrives meanwhile is not lost) and renews the lease when a request was taken.
 * Returns [taken value: 0, 1 or 2 = forced, current lease].
 */
function scim_sync_take_pending(PDO $pdo, string $connectorId, int $lease): array
{
    $sel = $pdo->prepare("SELECT sync_pending FROM scim_connectors WHERE id = :id AND sync_lock_until = :mine");
    $upd = $pdo->prepare(
        "UPDATE scim_connectors SET sync_pending = 0, sync_lock_until = :until " .
            "WHERE id = :id AND sync_lock_until = :mine AND sync_pending = :was"
    );
    for ($attempt = 0; $attempt < 3; $attempt++) {
        $sel->execute([":id" => $connectorId, ":mine" => $lease]);
        $was = $sel->fetchColumn();
        $sel->closeCursor();
        if ($was === false || (int) $was <= 0) {
            return [0, $lease];
        }
        $until = time() + SCIM_SYNC_LEASE_SECONDS;
        $upd->execute([":until" => $until, ":id" => $connectorId, ":mine" => $lease, ":was" => (int) $was]);
        if ($upd->rowCount() === 1) {
            return [(int) $was, $until];
        }
        // The value changed in between (a forced request arrived): read it again.
    }
    return [0, $lease];
}

function scim_sync_release_lease(PDO $pdo, string $connectorId, int $lease): void
{
    try {
        $pdo->prepare(
            "UPDATE scim_connectors SET sync_lock_until = NULL WHERE id = :id AND sync_lock_until = :mine"
        )->execute([":id" => $connectorId, ":mine" => $lease]);
    } catch (Throwable $e) {
        error_log("SCIM: could not release the sync lease of connector " . $connectorId . " (" . get_class($e) . ")");
    }
}

/** Circuit and agent liveness columns of a connector ([] when it no longer exists). */
function scim_sync_connector_state(PDO $pdo, string $connectorId): array
{
    $st = $pdo->prepare(
        "SELECT delivery_mode, circuit_open_until, agent_last_seen_at, agent_last_claim_at, " .
            "agent_last_result_at, agent_local_timeout FROM scim_connectors WHERE id = :id"
    );
    $st->execute([":id" => $connectorId]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    return is_array($row) ? $row : [];
}

/** Summary text: where the changes a stopped sync left queued are picked up. */
function scim_sync_resume_hint(bool $isAgent): string
{
    $agentPoll = $isAgent && scim_can_detach_from_client() ? "the agent's next poll, " : "";
    return "the remaining changes stay queued for the next sync (" . $agentPoll .
        "the next directory change or Sync Now)";
}

/**
 * Runs an outbound sync of one connector. Only one sync per connector runs at a time (a
 * lease taken with a conditional UPDATE). sync_pending queues work for the next sync:
 * - a sync requested while another one runs asks the lease holder for one more run
 *   (2 = forced, for a manual Sync Now), so syncs never overlap and no change is dropped;
 * - a run that stops with changes left (time budget, transport timeout), and an automatic
 *   sync that is skipped, keep the changes queued.
 * Queued work is taken by the next sync of the connector: after the next directory change,
 * on the agent's next poll (scim_agent_resume_pending_sync()), with a manual sync, or from a
 * scheduled job (scim_run_pending_syncs()). Each call has a time budget of
 * SCIM_SYNC_TIME_BUDGET_SECONDS, shared by its re-runs. Automatic syncs ($isAutoSync) are
 * skipped while the connector's circuit is open after a transport timeout, and while its
 * on-premises agent is offline or polls without answering its jobs; a manual sync of a
 * connector whose agent is offline fails at once instead of waiting for relay timeouts.
 */
function scim_connector_sync(
    string $storePath,
    array $provider,
    string $connectorId,
    bool $forceFull = false,
    bool $isAutoSync = false
): array {
    $pdo = scim_db($storePath);
    $providerId = (string) $provider["id"];
    $lease = null;
    for ($attempt = 0; $attempt < 3 && $lease === null; $attempt++) {
        $lease = scim_sync_acquire_lease($pdo, $providerId, $connectorId, false);
        if ($lease === null && scim_sync_request_rerun($pdo, $providerId, $connectorId, $forceFull)) {
            break;
        }
        // No holder any more (it released the lease in between): try to take it again.
    }
    if ($lease === null) {
        return [
            "ok" => true,
            "status" => "deferred",
            "summary" => "A sync is already running for this connector; it runs again as soon as it finishes",
            "synced_at" => null,
            "stats" => scim_sync_empty_stats(),
        ];
    }
    $released = false;
    try {
        $state = scim_sync_connector_state($pdo, $connectorId);
        $skipReason = null;
        if ($isAutoSync && (int) ($state["circuit_open_until"] ?? 0) > time()) {
            $skipReason = "Automatic sync is paused after a transport timeout";
        } elseif (($state["delivery_mode"] ?? "direct") === "agent") {
            // Relay jobs would only wait for their timeout. Checked while holding the lease,
            // so an agent that is busy with the jobs of a running sync is not misjudged.
            if (!scim_agent_polled_recently($state)) {
                if (!$isAutoSync) {
                    throw new RuntimeException(scim_agent_offline_message());
                }
                $skipReason = "The on-premises SCIM agent is offline";
            } elseif ($isAutoSync && scim_agent_is_stalled($state)) {
                $skipReason = "The on-premises SCIM agent polls but has not answered its last jobs";
            }
        }
        if ($skipReason !== null) {
            // Not now: the changes stay queued for the first sync after the recovery.
            scim_sync_mark_pending($pdo, $connectorId);
            return [
                "ok" => false,
                "status" => "skipped",
                "summary" => $skipReason,
                "synced_at" => null,
                "stats" => scim_sync_empty_stats(),
            ];
        }
        // Requests queued before this run started are served by it (a forced one forces it).
        [$taken, $lease] = scim_sync_take_pending($pdo, $connectorId, $lease);
        $force = $forceFull || $taken >= 2;
        $deadline = microtime(true) + SCIM_SYNC_TIME_BUDGET_SECONDS;
        $runs = 0;
        while (true) {
            $runs++;
            $result = scim_connector_sync_run($storePath, $provider, $connectorId, $force, $deadline);
            if (!empty($result["resume"])) {
                // Stopped with changes left: they stay queued for the next sync.
                scim_sync_mark_pending($pdo, $connectorId);
            }
            if (!empty($result["aborted"]) || $runs > SCIM_SYNC_MAX_RERUNS || microtime(true) >= $deadline - 1) {
                // A request that arrived during this run stays queued for the next sync.
                break;
            }
            // Release only while nothing is queued, so a change that arrived during this run
            // is never left behind; otherwise take the request and run once more.
            $rel = $pdo->prepare(
                "UPDATE scim_connectors SET sync_lock_until = NULL WHERE id = :id AND sync_lock_until = :mine AND sync_pending = 0"
            );
            $rel->execute([":id" => $connectorId, ":mine" => $lease]);
            if ($rel->rowCount() === 1) {
                $released = true;
                break;
            }
            [$taken, $lease] = scim_sync_take_pending($pdo, $connectorId, $lease);
            if ($taken === 0) {
                break;
            }
            $force = $taken >= 2;
        }
        unset($result["aborted"], $result["resume"]);
        return $result;
    } finally {
        if (!$released) {
            scim_sync_release_lease($pdo, $connectorId, $lease);
        }
    }
}

/**
 * One sync pass. Order: deprovision users that left the scope (revocation first), push new
 * and changed users, push groups and deprovision orphaned remote groups, then (forced sync
 * only) re-push unchanged users and groups. A deprovision answer other than 2xx or 404 is
 * an error and the mapping is kept for the next run. A used-up time budget or a transport
 * failure stops the pass; a transport timeout also opens the connector's circuit. After a
 * used-up budget or a timeout the result carries "resume", and the caller keeps the rest
 * queued. An answer larger than the response cap ("truncated") only fails what needs its
 * body: a lookup, or the id of a created resource, which is then found by a lookup.
 * Remote resources are linked only by ids the target issued: an unlinked user or group
 * adopts an existing remote resource only on a unique, exact userName/displayName match
 * that no other local resource holds, and a create answer without an id is an error.
 */
function scim_connector_sync_run(
    string $storePath,
    array $provider,
    string $connectorId,
    bool $forceFull,
    float $deadline
): array {
    $row = scim_connector_load_secret_row($storePath, (string) $provider["id"], $connectorId);
    $isAgent = ($row["delivery_mode"] ?? "direct") === "agent";
    $validated = $isAgent
        ? null
        : scim_validate_outbound_url((string) $row["scim_base_url"]);
    $owner = (string) $provider["owner"];
    $syncGroups = (int) ($row["sync_groups"] ?? 1) === 1;
    // Passwords are pushed only while the password copy policy allows it (S04-08): never while
    // the only vault key is the key file next to the database, whatever the connector says.
    $pushPasswords = (int) ($row["push_passwords"] ?? 0) === 1;
    if ($pushPasswords && !vault_password_push_allowed()) {
        $pushPasswords = false;
        error_log("SCIM connector " . $connectorId . ": passwords not pushed. " . vault_password_push_blocked_reason());
    }
    $deprovAction = (string) ($row["deprovision_action"] ?? "deactivate");
    $assignedGroups = json_decode((string) ($row["assigned_groups_json"] ?? "[]"), true);
    $assignedGroups = is_array($assignedGroups) ? normalize_string_list($assignedGroups) : [];

    $pdo = storage_db($storePath);
    $mapStmt = $pdo->prepare(
        "SELECT resource_type, local_id, remote_id, last_pushed_hash, remote_name FROM scim_remote_mappings WHERE connector_id = :cid"
    );
    $mapStmt->execute([":cid" => $connectorId]);
    $existingMappings = ["user" => [], "group" => []];
    while ($mr = $mapStmt->fetch(PDO::FETCH_ASSOC)) {
        $rt = (string) $mr["resource_type"];
        if ($rt !== "user" && $rt !== "group") {
            continue;
        }
        $existingMappings[$rt][(string) $mr["local_id"]] = [
            "remote_id" => (string) $mr["remote_id"],
            "hash" => (string) $mr["last_pushed_hash"],
            "name" => (string) ($mr["remote_name"] ?? ""),
        ];
    }

    $upsertMap = $pdo->prepare(
        "INSERT INTO scim_remote_mappings (connector_id, resource_type, local_id, remote_id, last_pushed_hash, synced_at, remote_name) " .
            "VALUES (:cid, :rt, :lid, :rid, :h, :ts, :rn) " .
            "ON CONFLICT(connector_id, resource_type, local_id) DO UPDATE SET " .
            "remote_id = excluded.remote_id, last_pushed_hash = excluded.last_pushed_hash, synced_at = excluded.synced_at, " .
            "remote_name = excluded.remote_name"
    );
    $delMap = $pdo->prepare(
        "DELETE FROM scim_remote_mappings WHERE connector_id = :cid AND resource_type = :rt AND local_id = :lid"
    );

    $stats = scim_sync_empty_stats();
    $nowIso = gmdate("Y-m-d\TH:i:s\Z");
    // Remote id per linked in-scope local user (group member values) and the reverse index,
    // so one remote account is never linked to two local users; the same index for groups.
    $remoteUserIdsByLocalId = [];
    $userOwnerByRemoteId = [];
    $groupOwnerByRemoteId = [];
    $liveGroupRemoteIds = [];
    // Remote accounts that a re-created user takes over from a stale mapping:
    // local user id => [remote id, local id of the stale mapping].
    $userTransfers = [];
    $aborted = false;
    $timedOut = false;
    // Set when the run stops with changes left (time budget, transport timeout): the
    // caller then keeps them queued (sync_pending) for the next sync.
    $resume = false;

    $send = static function (string $method, string $endpoint, ?array $payload = null) use ($storePath, $row, $validated, $deadline): array {
        return scim_execute_connector_request($storePath, $row, $validated, $method, $endpoint, $payload, $deadline);
    };
    $saveMap = static function (string $type, string $localId, string $remoteId, string $hash, string $name) use ($upsertMap, $connectorId, $nowIso): void {
        $upsertMap->execute([
            ":cid" => $connectorId,
            ":rt" => $type,
            ":lid" => $localId,
            ":rid" => $remoteId,
            ":h" => $hash,
            ":ts" => $nowIso,
            ":rn" => $name,
        ]);
    };
    $dropMap = static function (string $type, string $localId) use ($delMap, $connectorId): void {
        $delMap->execute([":cid" => $connectorId, ":rt" => $type, ":lid" => $localId]);
    };
    $remoteIdOf = static function (mixed $resp): string {
        $id = is_array($resp) ? ($resp["id"] ?? null) : null;
        return is_string($id) || is_int($id) ? trim((string) $id) : "";
    };

    // Links a local user to a remote account, in memory and in the mapping table.
    $linkUser = static function (string $localUid, string $remoteId, string $hash, string $username) use ($saveMap, &$remoteUserIdsByLocalId, &$userOwnerByRemoteId): void {
        $previous = $remoteUserIdsByLocalId[$localUid] ?? null;
        if ($previous !== null && $previous !== $remoteId && ($userOwnerByRemoteId[$previous] ?? null) === $localUid) {
            unset($userOwnerByRemoteId[$previous]);
        }
        $remoteUserIdsByLocalId[$localUid] = $remoteId;
        $userOwnerByRemoteId[$remoteId] = $localUid;
        $saveMap("user", $localUid, $remoteId, $hash, $username);
    };
    // Forgets the in-memory link of a local user whose remote account answered 404.
    $unlinkUser = static function (string $localUid) use (&$remoteUserIdsByLocalId, &$userOwnerByRemoteId): void {
        $previous = $remoteUserIdsByLocalId[$localUid] ?? null;
        if ($previous !== null && ($userOwnerByRemoteId[$previous] ?? null) === $localUid) {
            unset($userOwnerByRemoteId[$previous]);
        }
        unset($remoteUserIdsByLocalId[$localUid]);
    };
    // Finds a user's remote account by userName (the value is sent as a JSON string). Only a
    // unique exact match is adopted, and never an account linked to another local user, so a
    // target that ignores or only partly applies the filter cannot redirect the PUT.
    $lookupUser = static function (string $localUid, string $username) use ($send, &$userOwnerByRemoteId): string {
        $resp = $send("GET", "Users?filter=" . rawurlencode("userName eq " . scim_filter_string_literal($username)));
        if ($resp["status"] < 200 || $resp["status"] >= 300) {
            return "";
        }
        if (!empty($resp["truncated"])) {
            // Part of the answer is missing: neither "no match" nor a match can be trusted.
            throw new RuntimeException("the userName lookup answer was too large to read; nothing was linked");
        }
        $found = scim_remote_unique_match($resp["body"], "userName", $username);
        $owner = $found !== "" ? ($userOwnerByRemoteId[$found] ?? null) : null;
        if ($owner !== null && $owner !== $localUid) {
            throw new RuntimeException("the remote account with this userName is already linked to another local user");
        }
        return $found;
    };

    // Pushes one user: PUT to its linked remote account (or one taken over from a stale
    // mapping, or found by userName), POST when there is none. After a PUT to a linked id
    // answers 404 the user is looked up again before any POST, so an account that exists
    // under another id (for example on a re-pointed target) is linked instead of failing
    // with 409 on every sync. The addressed id stays the link; a create answer without an id
    // is an error, never a mapping to the local id.
    $pushUser = static function (string $localUid, array $u, array $payload, string $payloadHash) use ($send, $lookupUser, $linkUser, $unlinkUser, $dropMap, $remoteIdOf, $existingMappings, &$userTransfers, &$userOwnerByRemoteId, &$stats): void {
        $username = (string) $u["username"];
        $remoteId = (string) ($existingMappings["user"][$localUid]["remote_id"] ?? "");
        $transfer = $remoteId === "" ? ($userTransfers[$localUid] ?? null) : null;
        $fromLookup = false;
        if ($transfer !== null) {
            $remoteId = (string) $transfer[0];
        } elseif ($remoteId === "") {
            $remoteId = $lookupUser($localUid, $username);
            $fromLookup = true;
        }
        $attempts = 0;
        while ($remoteId !== "" && $attempts < 2) {
            $attempts++;
            $putResp = $send("PUT", "Users/" . rawurlencode($remoteId), ["id" => $remoteId] + $payload);
            if ($putResp["status"] >= 200 && $putResp["status"] < 300) {
                $linkUser($localUid, $remoteId, $payloadHash, $username);
                if ($transfer !== null && (string) $transfer[0] === $remoteId) {
                    $dropMap("user", (string) $transfer[1]);
                }
                $stats["users_updated"]++;
                return;
            }
            if ($putResp["status"] !== 404) {
                throw new RuntimeException(scim_remote_failure_message("PUT /Users/$remoteId", $putResp));
            }
            // The remote account no longer exists.
            $unlinkUser($localUid);
            $gone = $remoteId;
            $remoteId = $fromLookup ? "" : $lookupUser($localUid, $username);
            $fromLookup = true;
            if ($remoteId === $gone) {
                $remoteId = "";
            }
        }
        $postResp = $send("POST", "Users", $payload);
        if ($postResp["status"] < 200 || $postResp["status"] >= 300) {
            throw new RuntimeException(scim_remote_failure_message("POST /Users ($username)", $postResp));
        }
        $newRemoteId = $remoteIdOf($postResp["body"]);
        if ($newRemoteId === "" && !empty($postResp["truncated"])) {
            // The account was created, but its answer was too large to read the new id
            // from: it is linked by its unique, exact userName instead.
            $newRemoteId = $lookupUser($localUid, $username);
        }
        if ($newRemoteId === "") {
            throw new RuntimeException(
                "POST /Users ($username) answered without a resource id; the account is linked by userName on a later sync"
            );
        }
        $owner = $userOwnerByRemoteId[$newRemoteId] ?? null;
        if ($owner !== null && $owner !== $localUid) {
            throw new RuntimeException("POST /Users ($username) returned the id of an account linked to another local user");
        }
        $linkUser($localUid, $newRemoteId, $payloadHash, $username);
        $stats["users_created"]++;
    };

    $groupPayload = static function (array $g) use (&$remoteUserIdsByLocalId): array {
        $remoteMembers = [];
        foreach ($g["members"] ?? [] as $m) {
            $luid = (string) $m["id"];
            if (isset($remoteUserIdsByLocalId[$luid])) {
                $remoteMembers[] = [
                    "value" => $remoteUserIdsByLocalId[$luid],
                    "display" => (string) $m["username"],
                ];
            }
        }
        return [
            "schemas" => [SCIM_SCHEMA_GROUP],
            "displayName" => (string) $g["display_name"],
            "externalId" => (string) ($g["external_id"] !== "" ? $g["external_id"] : $g["id"]),
            "members" => $remoteMembers,
        ];
    };

    $linkGroup = static function (string $gid, string $remGid, string $hash, string $displayName) use ($saveMap, &$groupOwnerByRemoteId, &$liveGroupRemoteIds): void {
        $groupOwnerByRemoteId[$remGid] = $gid;
        $liveGroupRemoteIds[$remGid] = true;
        $saveMap("group", $gid, $remGid, $hash, $displayName);
    };
    // Finds a group's remote group by displayName, with the same unique-match rules. The
    // membership is excluded from the answer (RFC 7644 3.4.2.5, as Microsoft Entra ID asks
    // for it), so the lookup of a large group stays far below the response cap.
    $lookupGroup = static function (string $gid, string $displayName) use ($send, &$groupOwnerByRemoteId): string {
        $resp = $send(
            "GET",
            "Groups?filter=" . rawurlencode("displayName eq " . scim_filter_string_literal($displayName)) .
                "&excludedAttributes=members"
        );
        if ($resp["status"] < 200 || $resp["status"] >= 300) {
            return "";
        }
        if (!empty($resp["truncated"])) {
            throw new RuntimeException("the displayName lookup answer was too large to read; nothing was linked");
        }
        $found = scim_remote_unique_match($resp["body"], "displayName", $displayName);
        $owner = $found !== "" ? ($groupOwnerByRemoteId[$found] ?? null) : null;
        if ($owner !== null && $owner !== $gid) {
            throw new RuntimeException("the remote group with this displayName is already linked to another local group");
        }
        return $found;
    };

    // Pushes one group the same way. Every remote group it lands on is recorded as live, so
    // the orphan pass below never deprovisions a group that a local group (re)claimed.
    $pushGroup = static function (string $gid, array $g, array $gPayload, string $gHash) use ($send, $lookupGroup, $linkGroup, $remoteIdOf, $existingMappings, &$liveGroupRemoteIds, &$groupOwnerByRemoteId, &$stats): void {
        $displayName = (string) $g["display_name"];
        $remGid = (string) ($existingMappings["group"][$gid]["remote_id"] ?? "");
        $fromLookup = false;
        if ($remGid === "") {
            $remGid = $lookupGroup($gid, $displayName);
            $fromLookup = true;
        }
        $attempts = 0;
        while ($remGid !== "" && $attempts < 2) {
            $attempts++;
            $liveGroupRemoteIds[$remGid] = true;
            $putG = $send("PUT", "Groups/" . rawurlencode($remGid), ["id" => $remGid] + $gPayload);
            if ($putG["status"] >= 200 && $putG["status"] < 300) {
                $linkGroup($gid, $remGid, $gHash, $displayName);
                $stats["groups_synced"]++;
                return;
            }
            if ($putG["status"] !== 404) {
                throw new RuntimeException(scim_remote_failure_message("PUT /Groups/$remGid", $putG));
            }
            $gone = $remGid;
            $remGid = $fromLookup ? "" : $lookupGroup($gid, $displayName);
            $fromLookup = true;
            if ($remGid === $gone) {
                $remGid = "";
            }
        }
        $postG = $send("POST", "Groups", $gPayload);
        if ($postG["status"] < 200 || $postG["status"] >= 300) {
            throw new RuntimeException(scim_remote_failure_message("POST /Groups ($displayName)", $postG));
        }
        $newRemGid = $remoteIdOf($postG["body"]);
        if ($newRemGid === "" && !empty($postG["truncated"])) {
            // The group was created, but it was echoed back with its members, larger than
            // the response cap: its id comes from a displayName lookup without the members.
            $newRemGid = $lookupGroup($gid, $displayName);
        }
        if ($newRemGid === "") {
            throw new RuntimeException(
                "POST /Groups ($displayName) answered without a resource id; the group is linked by displayName on a later sync"
            );
        }
        $owner = $groupOwnerByRemoteId[$newRemGid] ?? null;
        if ($owner !== null && $owner !== $gid) {
            throw new RuntimeException("POST /Groups ($displayName) returned the id of a group linked to another local group");
        }
        $linkGroup($gid, $newRemGid, $gHash, $displayName);
        $stats["groups_synced"]++;
    };

    try {
        // 1. In-scope users and their outbound payloads (local work only).
        $inScopeUsersById = [];
        foreach (directory_list_users($storePath, $owner) as $u) {
            if (directory_user_matches_assigned_groups($u, $assignedGroups)) {
                $inScopeUsersById[(string) $u["id"]] = $u;
            }
        }
        $userWork = [];
        $userForced = [];
        foreach ($inScopeUsersById as $localUid => $u) {
            $mappedRemoteId = (string) ($existingMappings["user"][(string) $localUid]["remote_id"] ?? "");
            if ($mappedRemoteId !== "") {
                // Group payloads keep a mapped member even if this run cannot update the user,
                // and its remote account is never adopted by another local user.
                $remoteUserIdsByLocalId[(string) $localUid] = $mappedRemoteId;
                $userOwnerByRemoteId[$mappedRemoteId] = (string) $localUid;
            }
        }
        // Password ciphertexts are read before any password: a password set in between then
        // costs one extra push on the next sync, never a missed one.
        $passwordEnvelopes = $pushPasswords ? scim_user_password_envelopes($pdo, $owner) : [];
        foreach ($inScopeUsersById as $localUid => $u) {
            $localUid = (string) $localUid;
            try {
                $plainPw = null;
                $passwordMarker = null;
                if ($pushPasswords) {
                    $plainPw = directory_get_user_password_for_scim($storePath, $owner, $localUid);
                    $passwordMarker = scim_password_change_marker($passwordEnvelopes[$localUid] ?? "", $plainPw);
                }
                $payload = scim_format_user_resource($u, "", [], $plainPw, true);
                $payloadHash = scim_user_change_hash($payload, $passwordMarker);
            } catch (Throwable $e) {
                $stats["errors"][] = scim_sync_error_text("User " . (string) $u["username"] . ": " . $e->getMessage());
                continue;
            }
            $mapped = $existingMappings["user"][$localUid] ?? null;
            $mappedRemoteId = (string) ($mapped["remote_id"] ?? "");
            if ($mapped !== null && $mappedRemoteId !== "" && $mapped["hash"] === $payloadHash) {
                if ($forceFull) {
                    $userForced[$localUid] = [$u, $payload, $payloadHash];
                } else {
                    $stats["users_unchanged"]++;
                }
                continue;
            }
            $userWork[$localUid] = [$u, $payload, $payloadHash];
        }

        // 2. Deprovision previously pushed users that were deleted or left the scope. This
        //    runs before any push, so a large push never starves revocation. Only a 2xx or
        //    404 answer drops the mapping; anything else (including status 0) is an error and
        //    the mapping stays, so the next sync retries. A remote account that an in-scope
        //    user is mapped to is never deprovisioned: only the stale mapping row is dropped.
        //    A stale mapping last pushed with the userName of an in-scope user that is not
        //    linked yet (a deleted user re-created before its deprovision went through) is
        //    not deprovisioned: the remote account moves to that user, and the stale mapping
        //    row is dropped once its PUT succeeds. This needs no request, so it never slows
        //    revocation down, and an interrupted run simply finds the same match again.
        $liveUserRemoteIds = [];
        foreach ($existingMappings["user"] as $lid => $mi) {
            if (isset($inScopeUsersById[(string) $lid]) && $mi["remote_id"] !== "") {
                $liveUserRemoteIds[$mi["remote_id"]] = true;
            }
        }
        $unlinkedByName = [];
        foreach ($userWork as $lid => $work) {
            if ((string) ($existingMappings["user"][(string) $lid]["remote_id"] ?? "") !== "") {
                continue;
            }
            $nameKey = scim_match_key((string) $work[0]["username"]);
            // A name two local users share (differing only in case) transfers nothing.
            $unlinkedByName[$nameKey] = isset($unlinkedByName[$nameKey]) ? "" : (string) $lid;
        }
        foreach ($existingMappings["user"] as $mappedLocalUid => $mapInfo) {
            $mappedLocalUid = (string) $mappedLocalUid;
            if (isset($inScopeUsersById[$mappedLocalUid])) {
                continue;
            }
            $remId = $mapInfo["remote_id"];
            if ($remId === "") {
                continue;
            }
            if (isset($liveUserRemoteIds[$remId])) {
                $dropMap("user", $mappedLocalUid);
                continue;
            }
            $claimant = $mapInfo["name"] !== "" ? ($unlinkedByName[scim_match_key($mapInfo["name"])] ?? "") : "";
            if ($claimant !== "" && !isset($userTransfers[$claimant])) {
                $userTransfers[$claimant] = [$remId, $mappedLocalUid];
                $liveUserRemoteIds[$remId] = true;
                continue;
            }
            try {
                if ($deprovAction === "delete") {
                    $what = "DELETE /Users/$remId";
                    $resp = $send("DELETE", "Users/" . rawurlencode($remId));
                } else {
                    // Deactivate via RFC 7644 PatchOp active=false
                    $what = "PATCH /Users/$remId (active=false)";
                    $resp = $send("PATCH", "Users/" . rawurlencode($remId), [
                        "schemas" => [SCIM_SCHEMA_PATCH],
                        "Operations" => [
                            ["op" => "replace", "path" => "active", "value" => false],
                        ],
                    ]);
                }
                $status = (int) $resp["status"];
                if (($status >= 200 && $status < 300) || $status === 404) {
                    $dropMap("user", $mappedLocalUid);
                    $stats["users_deprovisioned"]++;
                } else {
                    throw new RuntimeException(scim_remote_failure_message($what, $resp));
                }
            } catch (ScimSyncAbortException | ScimTransportException $e) {
                throw $e;
            } catch (Throwable $e) {
                $stats["errors"][] = scim_sync_error_text("Deprovision $mappedLocalUid: " . $e->getMessage());
            }
        }

        // 3. Push new and changed users.
        foreach ($userWork as $localUid => [$u, $payload, $payloadHash]) {
            try {
                $pushUser((string) $localUid, $u, $payload, $payloadHash);
            } catch (ScimSyncAbortException | ScimTransportException $e) {
                throw $e;
            } catch (Throwable $e) {
                $stats["errors"][] = scim_sync_error_text("User " . (string) $u["username"] . ": " . $e->getMessage());
            }
        }

        // 4. Push groups and memberships, then deprovision remote groups whose local group was
        //    deleted or left the connector scope: DELETE them, or (deprovision_action other
        //    than "delete") empty their membership so nobody keeps the downstream rights tied
        //    to them. With sync_groups off, pushed groups are left as they are.
        $groupForced = [];
        if ($syncGroups) {
            $assignedLower = array_map("strtolower", $assignedGroups);
            $inScopeGroups = [];
            foreach (directory_list_groups($storePath, $owner) as $g) {
                if (
                    !empty($assignedLower) &&
                    !in_array(strtolower((string) $g["display_name"]), $assignedLower, true)
                ) {
                    continue;
                }
                $inScopeGroups[(string) $g["id"]] = $g;
            }
            // Remote groups of in-scope local groups, recorded before any push, so a failed
            // push never makes a live group look orphaned and no other group adopts them.
            foreach ($existingMappings["group"] as $lid => $mi) {
                if (isset($inScopeGroups[(string) $lid]) && $mi["remote_id"] !== "") {
                    $liveGroupRemoteIds[$mi["remote_id"]] = true;
                    $groupOwnerByRemoteId[$mi["remote_id"]] = (string) $lid;
                }
            }
            foreach ($inScopeGroups as $gid => $g) {
                $gid = (string) $gid;
                $gPayload = $groupPayload($g);
                $gHash = hash("sha256", (string) json_encode($gPayload, JSON_UNESCAPED_SLASHES));
                $gMapped = $existingMappings["group"][$gid] ?? null;
                if ($gMapped !== null && $gMapped["remote_id"] !== "" && $gMapped["hash"] === $gHash) {
                    if ($forceFull) {
                        $groupForced[$gid] = $g;
                    }
                    continue;
                }
                try {
                    $pushGroup($gid, $g, $gPayload, $gHash);
                } catch (ScimSyncAbortException | ScimTransportException $e) {
                    throw $e;
                } catch (Throwable $e) {
                    $stats["errors"][] = scim_sync_error_text("Group " . (string) $g["display_name"] . ": " . $e->getMessage());
                }
            }

            foreach ($existingMappings["group"] as $lid => $mi) {
                $lid = (string) $lid;
                if (isset($inScopeGroups[$lid])) {
                    continue;
                }
                $remGid = $mi["remote_id"];
                if ($remGid === "" || isset($liveGroupRemoteIds[$remGid])) {
                    // A live group uses this remote group (for example a re-created group that
                    // adopted it by name): only the stale mapping row is dropped.
                    $dropMap("group", $lid);
                    continue;
                }
                try {
                    if ($deprovAction === "delete") {
                        $what = "DELETE /Groups/$remGid";
                        $resp = $send("DELETE", "Groups/" . rawurlencode($remGid));
                    } else {
                        // RFC 7644 3.5.2.2: "remove" on members without a value filter removes
                        // every member. Targets that insist on a value for "remove" get an
                        // empty replacement instead.
                        $what = "PATCH /Groups/$remGid (remove members)";
                        $resp = $send("PATCH", "Groups/" . rawurlencode($remGid), [
                            "schemas" => [SCIM_SCHEMA_PATCH],
                            "Operations" => [
                                ["op" => "remove", "path" => "members"],
                            ],
                        ]);
                        if (in_array((int) $resp["status"], [400, 405, 422, 501], true)) {
                            $what = "PATCH /Groups/$remGid (members=[])";
                            $resp = $send("PATCH", "Groups/" . rawurlencode($remGid), [
                                "schemas" => [SCIM_SCHEMA_PATCH],
                                "Operations" => [
                                    ["op" => "replace", "path" => "members", "value" => []],
                                ],
                            ]);
                        }
                    }
                    $status = (int) $resp["status"];
                    if (($status >= 200 && $status < 300) || $status === 404) {
                        $dropMap("group", $lid);
                        $stats["groups_deprovisioned"]++;
                    } else {
                        throw new RuntimeException(scim_remote_failure_message($what, $resp));
                    }
                } catch (ScimSyncAbortException | ScimTransportException $e) {
                    throw $e;
                } catch (Throwable $e) {
                    $stats["errors"][] = scim_sync_error_text("Deprovision group $lid: " . $e->getMessage());
                }
            }
        }

        // 5. Forced full sync: re-push unchanged users and groups last, so new work and
        //    revocations always go first within the time budget.
        foreach ($userForced as $localUid => [$u, $payload, $payloadHash]) {
            try {
                $pushUser((string) $localUid, $u, $payload, $payloadHash);
            } catch (ScimSyncAbortException | ScimTransportException $e) {
                throw $e;
            } catch (Throwable $e) {
                $stats["errors"][] = scim_sync_error_text("User " . (string) $u["username"] . ": " . $e->getMessage());
            }
        }
        foreach ($groupForced as $gid => $g) {
            $gPayload = $groupPayload($g);
            $gHash = hash("sha256", (string) json_encode($gPayload, JSON_UNESCAPED_SLASHES));
            try {
                $pushGroup((string) $gid, $g, $gPayload, $gHash);
            } catch (ScimSyncAbortException | ScimTransportException $e) {
                throw $e;
            } catch (Throwable $e) {
                $stats["errors"][] = scim_sync_error_text("Group " . (string) $g["display_name"] . ": " . $e->getMessage());
            }
        }
    } catch (ScimTransportException $e) {
        $aborted = true;
        $timedOut = $e->timedOut;
        // After a timeout, the changes not pushed yet stay queued for the first sync after
        // the pause. Other transport failures are retried by the next directory change.
        $resume = $e->timedOut;
        $stats["errors"][] = scim_sync_error_text(
            "Sync stopped: " . $e->getMessage() .
                ($e->timedOut ? "; automatic syncs pause for " . SCIM_SYNC_CIRCUIT_SECONDS . " s" : "")
        );
    } catch (ScimSyncAbortException $e) {
        $aborted = true;
        $resume = true;
        $stats["errors"][] = scim_sync_error_text("Sync stopped early: " . $e->getMessage());
    }

    $statusStr = empty($stats["errors"]) ? "success" : "partial_error";
    $summaryStr = sprintf(
        "Created %d, updated %d, unchanged %d, deprovisioned %d users; synced %d, deprovisioned %d groups%s",
        $stats["users_created"],
        $stats["users_updated"],
        $stats["users_unchanged"],
        $stats["users_deprovisioned"],
        $stats["groups_synced"],
        $stats["groups_deprovisioned"],
        empty($stats["errors"]) ? "" : (" (" . count($stats["errors"]) . " errors)")
    ) . ($resume ? "; stopped early: " . scim_sync_resume_hint($isAgent) : "");

    $pdo->prepare(
        "UPDATE scim_connectors SET last_sync_at = :ts, last_sync_status = :st, last_sync_summary = :sum, " .
            "circuit_open_until = :circ WHERE id = :id"
    )->execute([
        ":ts" => $nowIso,
        ":st" => $statusStr,
        ":sum" => $summaryStr,
        // A transport timeout pauses automatic syncs; any run without one closes the circuit.
        ":circ" => $timedOut ? time() + SCIM_SYNC_CIRCUIT_SECONDS : null,
        ":id" => $connectorId,
    ]);

    audit_log_append(
        $storePath,
        (string) $provider["id"],
        "scim",
        "scim_outbound_sync",
        $statusStr === "success" ? "success" : "failed",
        (string) $row["name"],
        "",
        [],
        [
            "summary" => $summaryStr,
            "push_passwords" => $pushPasswords,
            "errors" => array_slice($stats["errors"], 0, 5),
        ]
    );

    return [
        "ok" => empty($stats["errors"]),
        "status" => $statusStr,
        "summary" => $summaryStr,
        "synced_at" => $nowIso,
        "stats" => $stats,
        "aborted" => $aborted,
        "resume" => $resume,
    ];
}

/**
 * Schedules an outbound auto-sync for the owner's connectors after the current response:
 * at most once per owner per request, run from a shutdown function that first detaches
 * from the client (php-fpm and LiteSpeed complete the response; other SAPIs send it with
 * its exact length first, see scim_flush_response_before_sync()). Directory writes
 * therefore do not wait for downstream servers, and a connector that points back at this
 * IdP cannot chain requests through the worker pool (each connector also syncs under its
 * own lease, within its time budget).
 */
function scim_trigger_auto_sync_for_owner(string $storePath, string $owner): void
{
    static $scheduled = [];
    $key = $storePath . "\n" . $owner;
    if (isset($scheduled[$key])) {
        return;
    }
    $scheduled[$key] = true;
    scim_buffer_response_for_sync();
    register_shutdown_function(static function () use ($storePath, $owner): void {
        scim_run_deferred_auto_sync($storePath, $owner);
    });
}

/**
 * Runs an automatic sync of one connector after the current response (at most once per
 * connector per request), detached from the client like scim_trigger_auto_sync_for_owner(),
 * and only while the connector is active with auto-sync on. Never throws.
 */
function scim_schedule_connector_sync(
    string $storePath,
    string $providerId,
    string $connectorId,
    ?array $provider = null
): void {
    static $scheduled = [];
    $key = $storePath . "\n" . $connectorId;
    if (isset($scheduled[$key])) {
        return;
    }
    $scheduled[$key] = true;
    scim_buffer_response_for_sync();
    register_shutdown_function(static function () use ($storePath, $providerId, $connectorId, $provider): void {
        try {
            scim_detach_from_client();
            $pdo = scim_db($storePath);
            if ($pdo->inTransaction()) {
                error_log("SCIM deferred sync skipped: a database transaction was still open at shutdown");
                return;
            }
            $st = $pdo->prepare(
                "SELECT 1 FROM scim_connectors WHERE id = :id AND provider_id = :pid AND status = 'active' AND auto_sync = 1"
            );
            $st->execute([":id" => $connectorId, ":pid" => $providerId]);
            $active = $st->fetchColumn() !== false;
            $st->closeCursor();
            $prov = $provider ?? scim_load_provider($storePath, $providerId);
            if ($active && is_array($prov)) {
                scim_connector_sync($storePath, $prov, $connectorId, false, true);
            }
        } catch (Throwable $e) {
            error_log(
                "SCIM deferred sync of connector " . $connectorId . " failed: " . get_class($e) . ": " . $e->getMessage()
            );
        }
    });
}

/**
 * One provider as load_providers() returns it, or null. Only that provider is read, never
 * every tenant's providers and keys (S10-07).
 */
function scim_load_provider(string $storePath, string $providerId): ?array
{
    return load_provider_by_id($storePath, $providerId);
}

/** True when this SAPI can complete the response and keep running (php-fpm, LiteSpeed). */
function scim_can_detach_from_client(): bool
{
    return PHP_SAPI !== "cli" &&
        (function_exists("fastcgi_finish_request") || function_exists("litespeed_finish_request"));
}

/**
 * Starts buffering the rest of the response when a sync is scheduled for after it on a SAPI
 * that cannot complete the response first (php-cgi/mod_fcgid, mod_php), so that
 * scim_flush_response_before_sync() can send it with an exact Content-Length.
 */
function scim_buffer_response_for_sync(): void
{
    static $started = false;
    if ($started || PHP_SAPI === "cli" || scim_can_detach_from_client() || headers_sent()) {
        return;
    }
    $started = true;
    ob_start();
}

/** True when buffered output reaches the client byte for byte (no compressing handler). */
function scim_output_length_is_exact(): bool
{
    $zlib = strtolower(trim((string) ini_get("zlib.output_compression")));
    if (!in_array($zlib, ["", "0", "off", "false", "no"], true) || trim((string) ini_get("output_handler")) !== "") {
        return false;
    }
    foreach (ob_get_status(true) as $status) {
        if (($status["name"] ?? "") !== "default output handler") {
            return false;
        }
    }
    return true;
}

/**
 * For SAPIs without a finish-request call: sends the buffered response with its exact
 * Content-Length and "Connection: close" before the sync starts, so the client can stop
 * waiting once it has the response. Best effort: a web server that buffers CGI output
 * itself (for example mod_fcgid with its default FcgidOutputBufferSize) still completes the
 * response only when the script ends; the sync stays bounded by its time budget either way.
 */
function scim_flush_response_before_sync(): void
{
    if (!headers_sent() && ob_get_level() > 0 && scim_output_length_is_exact()) {
        // Nothing reached the client yet, so the whole response is in the buffers. They are
        // measured before any is flushed: flushing first could send the headers early.
        $length = 0;
        foreach (ob_get_status(true) as $status) {
            $length += (int) ($status["buffer_used"] ?? 0);
        }
        $code = http_response_code();
        $code = is_int($code) ? $code : 200;
        if ($code >= 200 && $code !== 204 && $code !== 304) {
            header("Content-Length: " . $length);
            header("Connection: close");
        }
    }
    while (ob_get_level() > 0) {
        if (!@ob_end_flush()) {
            break;
        }
    }
    @flush();
}

/** Sends the response to the client and keeps running (once per request). */
function scim_detach_from_client(): void
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;
    ignore_user_abort(true);
    if (session_status() === PHP_SESSION_ACTIVE) {
        @session_write_close();
    }
    if (function_exists("fastcgi_finish_request")) {
        @fastcgi_finish_request();
    } elseif (function_exists("litespeed_finish_request")) {
        @litespeed_finish_request();
    } elseif (PHP_SAPI !== "cli") {
        scim_flush_response_before_sync();
    }
}

/**
 * Shutdown-time auto-sync of every active auto-sync connector of an owner. A connector whose
 * circuit is open, or whose agent is offline or stalled, is not synced now: its changes stay
 * queued (sync_pending) for the first sync after the recovery. Never throws.
 */
function scim_run_deferred_auto_sync(string $storePath, string $owner): void
{
    try {
        scim_detach_from_client();
        $pdo = scim_db($storePath);
        if ($pdo->inTransaction()) {
            error_log("SCIM auto-sync skipped: a database transaction was still open at shutdown");
            return;
        }
        // Only this owner's connectors are read, and only the providers that have one are
        // loaded: a directory write never loads every tenant's providers and keys (S10-07).
        $stmt = $pdo->prepare(
            "SELECT c.id, c.provider_id, c.delivery_mode, c.agent_last_seen_at, c.agent_last_claim_at, " .
                "c.agent_last_result_at, c.agent_local_timeout, c.circuit_open_until " .
                "FROM scim_connectors c JOIN providers p ON p.id = c.provider_id " .
                "WHERE p.owner = :owner AND c.status = 'active' AND c.auto_sync = 1 " .
                "ORDER BY p.rowid ASC, c.created_at ASC"
        );
        $stmt->execute([":owner" => $owner]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $providers = [];
        foreach ($rows as $r) {
            // Skip a connector whose circuit is open, and an on-prem agent that is offline
            // or polls without answering the jobs it claims (polling alone does not make
            // an agent online).
            if (
                (int) ($r["circuit_open_until"] ?? 0) > time() ||
                (($r["delivery_mode"] ?? "direct") === "agent" && !scim_agent_is_online($r))
            ) {
                scim_sync_mark_pending($pdo, (string) $r["id"]);
                continue;
            }
            $providerId = (string) $r["provider_id"];
            if (!array_key_exists($providerId, $providers)) {
                $providers[$providerId] = scim_load_provider($storePath, $providerId);
            }
            $prov = $providers[$providerId];
            if (!is_array($prov)) {
                continue;
            }
            try {
                scim_connector_sync($storePath, $prov, (string) $r["id"], false, true);
            } catch (Throwable $e) {
                error_log(
                    "SCIM auto-sync of connector " . (string) $r["id"] . " failed: " .
                        get_class($e) . ": " . $e->getMessage()
                );
            }
        }
    } catch (Throwable $e) {
        error_log("SCIM auto-sync failed: " . get_class($e) . ": " . $e->getMessage());
    }
}

/**
 * Runs the queued syncs (sync_pending) of every active auto-sync connector, for a scheduled
 * job or CLI worker, so that work a sync left queued (time budget, timeout, agent offline)
 * also continues without further directory changes. Each connector syncs under its lease
 * with the usual time budget and auto-sync rules. Returns connector id => sync status
 * ("success", "partial_error", "deferred", "skipped" or "error").
 */
function scim_run_pending_syncs(string $storePath): array
{
    $pdo = scim_db($storePath);
    $rows = $pdo->query(
        "SELECT id, provider_id FROM scim_connectors WHERE sync_pending > 0 AND status = 'active' AND auto_sync = 1"
    )->fetchAll(PDO::FETCH_ASSOC);
    // Only providers that have a queued connector are loaded (S10-07).
    $providers = [];
    $out = [];
    foreach ($rows as $r) {
        $connectorId = (string) $r["id"];
        $providerId = (string) $r["provider_id"];
        if (!array_key_exists($providerId, $providers)) {
            $providers[$providerId] = scim_load_provider($storePath, $providerId);
        }
        $prov = $providers[$providerId];
        if (!is_array($prov)) {
            continue;
        }
        try {
            $result = scim_connector_sync($storePath, $prov, $connectorId, false, true);
            $out[$connectorId] = (string) ($result["status"] ?? "");
        } catch (Throwable $e) {
            error_log(
                "SCIM queued sync of connector " . $connectorId . " failed: " . get_class($e) . ": " . $e->getMessage()
            );
            $out[$connectorId] = "error";
        }
    }
    return $out;
}

/**
 * On an agent's poll: when its connector has queued changes (a sync stopped at its time
 * budget or after a timeout, or automatic syncs were skipped while the agent was offline or
 * stalled), the next sync runs after this poll is answered, so they reach the target without
 * waiting for another directory change. Only on SAPIs that complete the response first:
 * elsewhere the agent would wait for its poll answer while the sync waits for the agent.
 * The auto-sync rules apply: active connector with auto-sync on, no sync running, circuit
 * closed, agent answering its jobs. Never throws.
 */
function scim_agent_resume_pending_sync(string $storePath, array $provider, string $connectorId): void
{
    if (!scim_can_detach_from_client()) {
        return;
    }
    try {
        $pdo = scim_db($storePath);
        $st = $pdo->prepare(
            "SELECT sync_pending, sync_lock_until, circuit_open_until, status, auto_sync, delivery_mode, " .
                "agent_last_seen_at, agent_last_claim_at, agent_last_result_at, agent_local_timeout " .
                "FROM scim_connectors WHERE id = :id AND provider_id = :pid"
        );
        $st->execute([":id" => $connectorId, ":pid" => (string) $provider["id"]]);
        $r = $st->fetch(PDO::FETCH_ASSOC);
        $st->closeCursor();
        $now = time();
        if (
            !is_array($r) ||
            (int) ($r["sync_pending"] ?? 0) <= 0 ||
            (string) ($r["status"] ?? "") !== "active" ||
            (int) ($r["auto_sync"] ?? 0) !== 1 ||
            (string) ($r["delivery_mode"] ?? "") !== "agent" ||
            (int) ($r["sync_lock_until"] ?? 0) >= $now ||
            (int) ($r["circuit_open_until"] ?? 0) > $now ||
            !scim_agent_is_online($r, $now)
        ) {
            return;
        }
        scim_schedule_connector_sync($storePath, (string) $provider["id"], $connectorId, $provider);
    } catch (Throwable $e) {
        error_log("SCIM: could not resume the queued sync of connector " . $connectorId . " (" . get_class($e) . ")");
    }
}

// ---------- On-Premises Windows SCIM Proxy Agent Endpoints (/{idpId}/scim/agent/*) ----------

function scim_authenticate_agent_request(
    string $storePath,
    array $provider
): array {
    $providerId = (string) $provider["id"];
    $authHeader = trim(get_auth_header());
    $rawToken = "";
    if (preg_match('/^Bearer\s+(\S+)$/i', $authHeader, $m)) {
        $rawToken = trim($m[1]);
    }

    // The credential is verified first and a valid agent token is never refused. Failures
    // are counted per provider and agent token id when the id exists, otherwise per client
    // network, so a co-located client cannot lock out a legitimate agent.
    $tokenId = null;
    if (preg_match('/^idp_sagt_([a-f0-9]{16})_[A-Za-z0-9\-_]+$/D', $rawToken, $tm)) {
        $tokenId = $tm[1];
        $pdo = storage_db($storePath);
        $stmt = $pdo->prepare(
            "SELECT * FROM scim_connectors WHERE agent_token_id = :tid AND provider_id = :pid AND delivery_mode = 'agent' LIMIT 1"
        );
        $stmt->execute([":tid" => $tokenId, ":pid" => $providerId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        // Ends the read snapshot before any write (see scim_authenticate_inbound_request()).
        $stmt->closeCursor();
        if (is_array($row)) {
            $tokenBucket = rate_limit_bucket("scim_agent_auth", $providerId, "token", $tokenId);
            $storedHash = (string) ($row["agent_secret_hash"] ?? "");
            $upgradedHash = null;
            if (machine_secret_verify($rawToken, $storedHash, $upgradedHash)) {
                if ($upgradedHash !== null) {
                    scim_store_upgraded_secret_hash($pdo, "scim_connectors", (string) $row["id"], $storedHash, $upgradedHash);
                }
                rate_limit_clear($storePath, $tokenBucket);
                return $row;
            }
            scim_auth_failure($storePath, $tokenBucket, "Invalid or rotated SCIM Agent Bearer token", true);
        }
    }

    scim_auth_failure(
        $storePath,
        rate_limit_bucket("scim_agent_auth", $providerId, "ip", client_ip_bucket()),
        $tokenId === null
            ? "Missing or invalid SCIM Agent Bearer token"
            : "Invalid or rotated SCIM Agent Bearer token",
        true
    );
}

/**
 * Reads an authenticated agent's JSON request body of at most $maxBytes (413 above it).
 * The result endpoint allows SCIM_AGENT_RESULT_REQUEST_MAX_BYTES, so older agents that post
 * the results of a whole poll in one request are not refused (read_json_body() stops at
 * 512 KiB, less than one relayed response once JSON-escaped).
 */
function scim_agent_read_json_body(int $maxBytes): array
{
    $declared = $_SERVER["CONTENT_LENGTH"] ?? null;
    if (is_string($declared) && preg_match('/^\d{1,18}$/D', $declared) === 1 && (int) $declared > $maxBytes) {
        json_response(413, ["error" => "Request JSON payload too large"]);
    }
    $raw = file_get_contents("php://input", false, null, 0, $maxBytes + 1);
    if ($raw === false || trim($raw) === "") {
        return [];
    }
    if (strlen($raw) > $maxBytes) {
        json_response(413, ["error" => "Request JSON payload too large"]);
    }
    $decoded = json_decode($raw, true, 32);
    return is_array($decoded) ? $decoded : [];
}

/**
 * Housekeeping of a connector's relay queue, run on every poll. Jobs nobody waits for any
 * more are abandoned (and so never handed out): pending jobs past the pickup window, and
 * claimed jobs past the longest answer grace. Finished rows a waiter did not collect, and
 * any row older than SCIM_AGENT_JOB_MAX_AGE_SECONDS, are deleted.
 */
function scim_agent_prune_jobs(PDO $pdo, string $connectorId): void
{
    $now = time();
    $pdo->prepare(
        "UPDATE scim_agent_jobs SET status = 'abandoned', request_body_json = NULL, completed_at = :now " .
            "WHERE connector_id = :cid AND ((status = 'pending' AND created_at < :pcut) " .
            "OR (status = 'claimed' AND claimed_at < :ccut))"
    )->execute([
        ":now" => $now,
        ":cid" => $connectorId,
        ":pcut" => $now - SCIM_AGENT_RELAY_TIMEOUT_SECONDS - SCIM_AGENT_QUEUE_MARGIN_SECONDS,
        ":ccut" => $now - scim_agent_answer_grace_seconds(null) - SCIM_AGENT_QUEUE_MARGIN_SECONDS,
    ]);
    $pdo->prepare(
        "DELETE FROM scim_agent_jobs WHERE connector_id = :cid AND (created_at < :maxage " .
            "OR (status IN ('completed', 'failed') AND completed_at < :fcut))"
    )->execute([
        ":cid" => $connectorId,
        ":maxage" => $now - SCIM_AGENT_JOB_MAX_AGE_SECONDS,
        ":fcut" => $now - SCIM_AGENT_FINISHED_JOB_KEEP_SECONDS,
    ]);
}

function handle_scim_agent_routes(
    string $method,
    string $subPath,
    string $storePath,
    array $provider
): void {
    if (!preg_match('#^/scim/agent/(poll|result)$#i', $subPath, $m)) {
        return;
    }
    if ($method !== "POST") {
        json_response(405, ["error" => "Method Not Allowed"]);
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        @session_write_close();
    }

    $action = strtolower($m[1]);
    $connRow = scim_authenticate_agent_request($storePath, $provider);
    $connectorId = (string) $connRow["id"];
    $body = scim_agent_read_json_body(
        $action === "result" ? SCIM_AGENT_RESULT_REQUEST_MAX_BYTES : SCIM_AGENT_POLL_REQUEST_MAX_BYTES
    );
    $pdo = scim_db($storePath);

    if ($action === "poll") {
        // Agent-supplied labels are stored as valid UTF-8 without control characters, cut
        // by characters (a byte cut can split a character and break the console's JSON).
        $hostname = is_string($body["hostname"] ?? null) ? sanitize_label($body["hostname"], 120) : "";
        $version = is_string($body["version"] ?? null) ? sanitize_label($body["version"], 40) : "";
        $waitRaw = $body["wait_seconds"] ?? null;
        $waitSecs = is_numeric($waitRaw)
            ? max(0, min(SCIM_AGENT_POLL_MAX_WAIT_SECONDS, (int) $waitRaw))
            : 12;
        // Optional fields of newer agents: how many jobs they take per poll, and their local
        // SCIM timeout, which sets how long the result of a claimed job is awaited. Older
        // agents send neither: they get up to ten jobs and the longest answer grace.
        $maxJobsRaw = $body["max_jobs"] ?? null;
        $maxJobs = is_numeric($maxJobsRaw)
            ? max(1, min(SCIM_AGENT_MAX_JOBS_PER_POLL, (int) $maxJobsRaw))
            : SCIM_AGENT_MAX_JOBS_PER_POLL;
        $localTimeoutRaw = $body["local_timeout_seconds"] ?? null;
        $localTimeout = is_numeric($localTimeoutRaw) && (int) $localTimeoutRaw >= 1
            ? min(SCIM_AGENT_MAX_LOCAL_TIMEOUT_SECONDS, (int) $localTimeoutRaw)
            : null;

        // Liveness is only recorded while the token this request authenticated with is still
        // the connector's agent token: a poll that raced a rotation cannot write the previous
        // agent's heartbeat, labels or poll lease over the reset state.
        $agentTokenId = (string) ($connRow["agent_token_id"] ?? "");

        // One open long-poll per connector. Further concurrent polls (a token used in
        // parallel, or a retry while the server still holds the previous poll) are answered
        // at once, so they cannot pin PHP workers; agents retry after their error backoff.
        $pollUntil = time() + $waitSecs + 5;
        $takePoll = $pdo->prepare(
            "UPDATE scim_connectors SET agent_poll_until = :until " .
                "WHERE id = :id AND agent_token_id = :tid AND (agent_poll_until IS NULL OR agent_poll_until < :now)"
        );
        $takePoll->execute([":until" => $pollUntil, ":id" => $connectorId, ":tid" => $agentTokenId, ":now" => time()]);
        if ($takePoll->rowCount() !== 1) {
            if (!headers_sent()) {
                header("Retry-After: 2");
            }
            json_response(429, ["error" => "Another poll of this SCIM agent connector is still open; retry shortly"]);
        }

        $pdo->prepare(
            "UPDATE scim_connectors SET agent_last_seen_at = :ts, agent_hostname = :hn, agent_version = :ver, " .
                "agent_last_ip = :ip, agent_local_timeout = :lt WHERE id = :id AND agent_token_id = :tid"
        )->execute([
            ":ts" => gmdate("Y-m-d\TH:i:s\Z"),
            ":hn" => $hostname !== "" ? $hostname : ($connRow["agent_hostname"] ?? null),
            ":ver" => $version !== "" ? $version : ($connRow["agent_version"] ?? null),
            ":ip" => client_ip_address(),
            ":lt" => $localTimeout,
            ":id" => $connectorId,
            ":tid" => $agentTokenId,
        ]);

        // A claimed job is never handed out again (a second run could create a duplicate
        // while the first is still in progress): the waiter's answer deadline and this
        // housekeeping give it up instead.
        scim_agent_prune_jobs($pdo, $connectorId);

        $selStmt = $pdo->prepare(
            "SELECT id, method, endpoint_path, request_body_json FROM scim_agent_jobs " .
                "WHERE connector_id = :cid AND status = 'pending' AND created_at >= :fresh " .
                "ORDER BY created_at ASC, rowid ASC LIMIT " . $maxJobs
        );
        // A job is claimed only while the token this poll authenticated with is still the
        // connector's agent token, so a rotation (or a switch to direct mode) also cuts off a
        // long-poll that is already waiting. The encrypted body leaves the queue with the claim.
        $claimStmt = $pdo->prepare(
            "UPDATE scim_agent_jobs SET status = 'claimed', claimed_at = :now, request_body_json = NULL " .
                "WHERE id = :id AND connector_id = :cid AND status = 'pending' AND EXISTS (" .
                "SELECT 1 FROM scim_connectors WHERE id = :cid2 AND agent_token_id = :tid AND delivery_mode = 'agent')"
        );
        $tokenStmt = $pdo->prepare(
            "SELECT 1 FROM scim_connectors WHERE id = :id AND agent_token_id = :tid AND delivery_mode = 'agent'"
        );
        $failStmt = $pdo->prepare(
            "UPDATE scim_agent_jobs SET status = 'failed', error_message = :err, request_body_json = NULL, " .
                "completed_at = :now WHERE id = :id AND connector_id = :cid AND status = 'pending'"
        );

        // The answer stays below SCIM_AGENT_POLL_MAX_BYTES (older agents read at most 1 MiB);
        // jobs that do not fit any more wait for the next poll.
        $connectorName = utf8_truncate((string) $connRow["name"], 200);
        $answerBytes = scim_agent_json_bytes([
            "connector_id" => $connectorId,
            "connector_name" => $connectorName,
            "jobs" => [],
        ]);
        $deadline = microtime(true) + $waitSecs;
        $claimedJobs = [];
        $tokenRevoked = false;

        do {
            $selStmt->execute([
                ":cid" => $connectorId,
                ":fresh" => time() - SCIM_AGENT_RELAY_TIMEOUT_SECONDS - SCIM_AGENT_QUEUE_MARGIN_SECONDS,
            ]);
            $candidates = $selStmt->fetchAll(PDO::FETCH_ASSOC);
            $answerFull = false;
            foreach ($candidates as $cand) {
                $entry = scim_agent_job_entry($storePath, $cand);
                $entryBytes = $entry !== null ? scim_agent_json_bytes($entry) : 0;
                $failure = null;
                if ($entry === null) {
                    // Also a job an older release queued with a clear-text body.
                    $failure = "The IdP could not decrypt this relay job";
                } elseif ($entryBytes > SCIM_AGENT_JOB_MAX_BYTES) {
                    // Refused when it was queued already; checked again before it is sent.
                    $failure = "The relay job is larger than one poll answer may be";
                }
                if ($failure !== null) {
                    $failStmt->execute([
                        ":err" => $failure,
                        ":now" => time(),
                        ":id" => (string) $cand["id"],
                        ":cid" => $connectorId,
                    ]);
                    continue;
                }
                $entryBytes++; // the separating comma
                if ($answerBytes + $entryBytes > SCIM_AGENT_POLL_MAX_BYTES) {
                    $answerFull = true;
                    break;
                }
                $claimStmt->execute([
                    ":now" => time(),
                    ":id" => (string) $cand["id"],
                    ":cid" => $connectorId,
                    ":cid2" => $connectorId,
                    ":tid" => $agentTokenId,
                ]);
                if ($claimStmt->rowCount() === 1) {
                    $claimedJobs[] = $entry;
                    $answerBytes += $entryBytes;
                    continue;
                }
                // Not claimed: the waiter gave up meanwhile, or the token was revoked.
                $tokenStmt->execute([":id" => $connectorId, ":tid" => $agentTokenId]);
                $tokenRevoked = $tokenStmt->fetchColumn() === false;
                $tokenStmt->closeCursor();
                if ($tokenRevoked) {
                    break;
                }
            }
            if ($tokenRevoked || $claimedJobs !== [] || $answerFull || microtime(true) >= $deadline) {
                break;
            }
            usleep(80000); // 80ms
        } while (true);

        if ($tokenRevoked) {
            // Jobs claimed earlier in this poll were abandoned (rotation) or deleted (switch to
            // direct mode) together with the token, so nothing is handed out.
            json_response(401, ["error" => "Invalid or rotated SCIM Agent Bearer token"]);
        }

        if ($claimedJobs !== []) {
            // The oldest claim since the agent's last result: an agent that only polls and
            // never answers is told apart from one that works (scim_agent_is_stalled()).
            $claimNow = time();
            $pdo->prepare(
                "UPDATE scim_connectors SET agent_last_claim_at = CASE " .
                    "WHEN agent_last_claim_at IS NULL OR agent_last_claim_at <= COALESCE(agent_last_result_at, 0) " .
                    "OR agent_last_claim_at < :retry THEN :now ELSE agent_last_claim_at END " .
                    "WHERE id = :id AND agent_token_id = :tid"
            )->execute([
                ":retry" => $claimNow - SCIM_AGENT_STALL_RETRY_SECONDS,
                ":now" => $claimNow,
                ":id" => $connectorId,
                ":tid" => $agentTokenId,
            ]);
        }
        $pdo->prepare(
            "UPDATE scim_connectors SET agent_poll_until = NULL WHERE id = :id AND agent_poll_until = :mine"
        )->execute([":id" => $connectorId, ":mine" => $pollUntil]);

        // Changes queued while this agent was offline, or left by a sync that stopped early,
        // continue after this answer.
        scim_agent_resume_pending_sync($storePath, $provider, $connectorId);

        json_response(200, [
            "connector_id" => $connectorId,
            "connector_name" => $connectorName,
            "jobs" => $claimedJobs,
        ]);
    }

    if ($action === "result") {
        $items = isset($body["results"]) && is_array($body["results"])
            ? $body["results"]
            : [$body];
        // Only a job of this connector that is still claimed takes a result. A late result
        // (its waiter gave up and abandoned the job) or one for an unknown job is accepted
        // and discarded; "acknowledged" counts the results that were stored.
        $updOk = $pdo->prepare(
            "UPDATE scim_agent_jobs SET status = 'completed', response_status = :rs, response_body_raw = :rb, " .
                "response_truncated = :tr, request_body_json = NULL, completed_at = :now " .
                "WHERE id = :id AND connector_id = :cid AND status = 'claimed'"
        );
        $updErr = $pdo->prepare(
            "UPDATE scim_agent_jobs SET status = 'failed', error_message = :err, request_body_json = NULL, " .
                "completed_at = :now WHERE id = :id AND connector_id = :cid AND status = 'claimed'"
        );
        // A late answer to a job this connector's agent did claim (its waiter gave up and
        // abandoned it) is discarded too, but still shows that the agent answers its jobs.
        // It is marked, so each job counts once; ids of unknown or never-claimed jobs do not
        // count, so posting made-up results cannot hide an agent that leaves its jobs open.
        $updLate = $pdo->prepare(
            "UPDATE scim_agent_jobs SET response_status = :rs WHERE id = :id AND connector_id = :cid " .
                "AND status = 'abandoned' AND claimed_at IS NOT NULL AND response_status IS NULL"
        );
        $nowTs = time();
        $acknowledged = 0;
        $answeredLate = 0;
        $reported = 0;
        foreach ($items as $it) {
            if ($reported >= SCIM_AGENT_MAX_RESULTS_PER_REQUEST) {
                break;
            }
            if (!is_array($it)) {
                continue;
            }
            $jidRaw = $it["job_id"] ?? null;
            $jid = is_string($jidRaw) || is_int($jidRaw) ? trim((string) $jidRaw) : "";
            if ($jid === "" || strlen($jid) > 64) {
                continue;
            }
            $reported++;
            // Agent error text is stored as valid, bounded UTF-8 without control characters.
            $errRaw = $it["error"] ?? null;
            $errMsg = is_scalar($errRaw)
                ? sanitize_label((string) $errRaw, 500)
                : ($errRaw === null ? "" : "Malformed agent error report");
            if ($errMsg !== "") {
                $updErr->execute([
                    ":err" => $errMsg,
                    ":now" => $nowTs,
                    ":id" => $jid,
                    ":cid" => $connectorId,
                ]);
                $stored = $updErr->rowCount();
                $acknowledged += $stored;
                if ($stored === 0) {
                    $updLate->execute([":rs" => 0, ":id" => $jid, ":cid" => $connectorId]);
                    $answeredLate += $updLate->rowCount();
                }
                continue;
            }
            $statusRaw = $it["status"] ?? 200;
            $httpStatus = is_numeric($statusRaw) ? (int) $statusRaw : 0;
            $httpStatus = $httpStatus >= 100 && $httpStatus <= 599 ? $httpStatus : 0;
            $bodyRaw = is_string($it["body_raw"] ?? null) ? $it["body_raw"] : "";
            // A response body the agent cut is kept only for error messages and never parsed:
            // a lookup must not read "no match" from part of an answer.
            $truncated = ($it["truncated"] ?? false) === true || strlen($bodyRaw) >= SCIM_AGENT_RESULT_BODY_MAX_BYTES;
            $updOk->execute([
                ":rs" => $httpStatus,
                ":rb" => $truncated ? substr($bodyRaw, 0, 1000) : $bodyRaw,
                ":tr" => $truncated ? 1 : 0,
                ":now" => $nowTs,
                ":id" => $jid,
                ":cid" => $connectorId,
            ]);
            $stored = $updOk->rowCount();
            $acknowledged += $stored;
            if ($stored === 0) {
                $updLate->execute([":rs" => $httpStatus, ":id" => $jid, ":cid" => $connectorId]);
                $answeredLate += $updLate->rowCount();
            }
        }
        if ($acknowledged > 0 || $answeredLate > 0) {
            // The agent answers jobs it claimed (even late or with an error): it is not stalled.
            $pdo->prepare("UPDATE scim_connectors SET agent_last_result_at = :now WHERE id = :id AND agent_token_id = :tid")
                ->execute([":now" => $nowTs, ":id" => $connectorId, ":tid" => (string) ($connRow["agent_token_id"] ?? "")]);
        }
        $discarded = $reported - $acknowledged;
        if ($discarded > 0) {
            error_log(
                "SCIM agent relay: discarded " . $discarded . " result(s) for connector " . $connectorId .
                    " that no request awaits any more (late or unknown job)"
            );
        }
        json_response(200, ["ok" => true, "acknowledged" => $acknowledged, "discarded" => $discarded]);
    }
}
