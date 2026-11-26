<?php
declare(strict_types=1);

// Largest JSON payload one auth transaction may store (tx_create()). Unauthenticated
// requests create transactions, so the size is bounded (S12-11).
const TX_PAYLOAD_MAX_BYTES = 16384;

// Largest JSON payload of a completion transaction (oidc_finalize, saml_finalize). It wraps
// the payload of the sign-in it completes (up to TX_PAYLOAD_MAX_BYTES) with about 250 bytes
// of session details, and only a completed sign-in creates one, so a request that was
// accepted at the start is not refused after the password or passkey step.
const TX_FINALIZE_PAYLOAD_MAX_BYTES = TX_PAYLOAD_MAX_BYTES + 4096;

// Lifetime of an SSO session started by auth_complete_transaction().
const SSO_SESSION_TTL_SECONDS = 28800;

// ---------- SSO Session Management (Per-Provider Cookie) ----------

/**
 * Name of the SSO session cookie for $providerId. Over https it carries the __Host- prefix
 * (G2a-05): browsers then accept it only with Secure, Path=/ and no Domain, so a sibling
 * subdomain or a plain-http response cannot plant or shadow it. Renaming it ended the SSO
 * sessions that existed under the old name once.
 */
function sso_cookie_name(string $providerId): string
{
    $name = sso_legacy_cookie_name($providerId);
    return !empty($GLOBALS["isHttps"]) ? "__Host-" . $name : $name;
}

/** The SSO cookie name without prefix: the name over plain http, and the name used before. */
function sso_legacy_cookie_name(string $providerId): string
{
    return "idp_sso_" . substr(hash("sha256", $providerId), 0, 12);
}

/**
 * The cookies of this request that PHP files under $name in $_COOKIE, in header order, as
 * ["name" => raw name, "value" => value decoded as PHP decodes it]. PHP keeps only the first
 * of several such cookies, strips leading whitespace from names and turns " ", "." and an
 * unclosed "[" into "_", so "idp.sso_x", or a second "idp_sso_x" with a longer Path, would
 * shadow the cookie the IdP set (G2a-05). Like PHP 8.1.11+, a name that only this mangling
 * gives a __Host- or __Secure- prefix is skipped (PHP drops it). Without the raw Cookie
 * header, $_COOKIE[$name] is reported as is.
 */
function sso_request_cookies(string $name): array
{
    $header = $_SERVER["HTTP_COOKIE"] ?? null;
    if (!is_string($header) || $header === "") {
        $value = $_COOKIE[$name] ?? null;
        return is_string($value) ? [["name" => $name, "value" => $value]] : [];
    }
    $found = [];
    foreach (explode(";", $header) as $pair) {
        $eq = strpos($pair, "=");
        $rawName = ltrim($eq === false ? $pair : substr($pair, 0, $eq), " \t\n\r\v\f");
        if ($rawName === "") {
            continue;
        }
        $mangled = "";
        $length = strlen($rawName);
        for ($i = 0; $i < $length; $i++) {
            $ch = $rawName[$i];
            if ($ch === "[") {
                if (strpos($rawName, "]", $i + 1) !== false) {
                    break; // "name[...]" is an array element of "name"
                }
                $ch = "_";
            }
            $mangled .= ($ch === " " || $ch === ".") ? "_" : $ch;
        }
        if ($mangled !== $name) {
            continue;
        }
        if ($mangled !== $rawName) {
            foreach (["__Host-", "__Secure-"] as $prefix) {
                if (str_starts_with($mangled, $prefix) && !str_starts_with($rawName, $prefix)) {
                    continue 2;
                }
            }
        }
        $found[] = [
            "name" => $rawName,
            "value" => $eq === false ? "" : rawurldecode(substr($pair, $eq + 1)),
        ];
    }
    return $found;
}

/**
 * This request's SSO session id for $providerId: the value of the one cookie named exactly
 * sso_cookie_name(). Null when there is none, when it is not a session id, and when more than
 * one cookie maps to that name or the one that does is a look-alike (G2a-05): one of them may
 * have been planted to sign this browser in as someone else, and which one PHP picked cannot
 * be trusted, so the request is treated as having no session.
 */
function sso_request_session_id(string $providerId): ?string
{
    static $logged = [];
    $name = sso_cookie_name($providerId);
    $cookies = sso_request_cookies($name);
    if ($cookies === []) {
        return null;
    }
    if (count($cookies) !== 1 || $cookies[0]["name"] !== $name) {
        if (!isset($logged[$name])) {
            $logged[$name] = true;
            error_log(sprintf(
                "sso: ignored the SSO cookie of provider %s: %d cookie(s) map to its name, not exactly one named %s (possible cookie injection)",
                sanitize_label($providerId, 64),
                count($cookies),
                $name
            ));
        }
        return null;
    }
    $sid = trim($cookies[0]["value"]);
    return preg_match('/^[A-Za-z0-9_-]{43}$/D', $sid) === 1 ? $sid : null;
}

/**
 * Every SSO session id this request carried for $providerId, under the current cookie name,
 * the legacy unprefixed name or a look-alike of either. Used to end all of them at sign-in
 * and sign-out, including a session that was planted next to the real one.
 */
function sso_request_session_ids(string $providerId): array
{
    $names = array_unique([sso_cookie_name($providerId), sso_legacy_cookie_name($providerId)]);
    $ids = [];
    foreach ($names as $name) {
        foreach (sso_request_cookies($name) as $cookie) {
            $sid = trim($cookie["value"]);
            if ($sid !== "" && strlen($sid) <= 128 && !in_array($sid, $ids, true)) {
                $ids[] = $sid;
            }
        }
    }
    return $ids;
}

/** Sends a Set-Cookie that deletes the host-only, Path=/ cookie $name. */
function sso_expire_cookie(string $name, bool $isHttps): void
{
    if (headers_sent()) {
        return;
    }
    setcookie($name, "", [
        "expires" => time() - 3600,
        "path" => "/",
        "secure" => $isHttps || str_starts_with($name, "__Host-"),
        "httponly" => true,
        "samesite" => "Lax",
    ]);
}

function sso_get_session(string $storePath, array $provider): ?array
{
    $sid = sso_request_session_id((string) $provider["id"]);
    if ($sid === null) {
        return null;
    }
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM sso_sessions WHERE id = :id AND provider_id = :pid LIMIT 1"
    );
    $stmt->execute([":id" => $sid, ":pid" => $provider["id"]]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt->closeCursor();
    if (!$row || (int) $row["expires_at"] <= time()) {
        return null;
    }
    // A sign-in time that does not parse is a corrupted session, never a sign-in that just
    // happened (S06-03).
    $authTime = strtotime((string) $row["authenticated_at"]);
    if ($authTime === false) {
        return null;
    }
    $user = directory_get_user_by_id(
        $storePath,
        (string) $row["user_id"],
        $provider["owner"]
    );
    if (!$user || ($user["status"] ?? "active") !== "active") {
        return null;
    }
    $amr = json_decode((string) ($row["amr_json"] ?? "[]"), true);
    return [
        "id" => (string) $row["id"],
        "user" => $user,
        "amr" => is_array($amr) ? $amr : [],
        "authenticated_at" => (string) $row["authenticated_at"],
        "auth_time" => $authTime,
        "expires_at" => (int) $row["expires_at"],
    ];
}

/**
 * Starts an SSO session for $userId and sets its cookie; returns the session id.
 * $authenticatedAt is the sign-in time to record (default: now); the session ends
 * $ttlSeconds after it. Every session this browser presented for the provider ends, and
 * the OIDC codes and tokens bound to them move to the new session (same user) or are
 * revoked (another user) through oidc_rebind_session_tokens() (X3-08).
 */
function sso_set_session(
    string $storePath,
    array $provider,
    string $userId,
    array $amr,
    bool $isHttps,
    int $ttlSeconds = 28800,
    ?int $authenticatedAt = null
): string {
    $pdo = storage_db($storePath);
    $providerId = (string) $provider["id"];
    $cookieName = sso_cookie_name($providerId);
    // The sessions this browser had with the provider end: the previous one, one under the
    // legacy cookie name, and a look-alike planted next to them (G2a-05).
    $prevSids = sso_request_session_ids($providerId);
    $delPrev = $pdo->prepare("DELETE FROM sso_sessions WHERE id = :id AND provider_id = :pid");
    foreach ($prevSids as $prevSid) {
        $delPrev->execute([":id" => $prevSid, ":pid" => $providerId]);
    }

    $sid = base64url_encode(random_bytes(32));
    $authenticatedAt ??= time();
    $nowIso = gmdate("Y-m-d\TH:i:s\Z", $authenticatedAt);
    $exp = $authenticatedAt + $ttlSeconds;

    // Expired sessions are removed now and then, in bounded batches, so a sign-in never
    // pays for a large cleanup while holding the database write lock (S12-11).
    if (random_int(1, 20) === 1) {
        $pdo->prepare(
            "DELETE FROM sso_sessions WHERE rowid IN " .
                "(SELECT rowid FROM sso_sessions WHERE expires_at <= :now LIMIT 500)"
        )->execute([":now" => time()]);
    }

    $ins = $pdo->prepare(
        "INSERT INTO sso_sessions (id, provider_id, user_id, amr_json, authenticated_at, expires_at) " .
            "VALUES (:id, :pid, :uid, :amr, :cat, :exp)"
    );
    $ins->execute([
        ":id" => $sid,
        ":pid" => $provider["id"],
        ":uid" => $userId,
        ":amr" => json_encode(array_values(array_unique($amr)), JSON_UNESCAPED_SLASHES),
        ":cat" => $nowIso,
        ":exp" => $exp,
    ]);

    // OIDC codes and tokens bound to a replaced session (X3-08; a new sign-in in the same
    // browser after prompt=login, max_age, a step-up or another user) would otherwise stay
    // bound to a session no logout matches. Those of $userId move to the new session, so
    // logging out of it ends them too; those of another user, whose session this sign-in
    // ended, are revoked as on logout (offline_access grants are kept). Called after the new
    // row exists, as the helper requires; it deletes the replaced row again in its own write
    // transaction, logs its own errors and never throws.
    if (function_exists("oidc_rebind_session_tokens")) {
        foreach ($prevSids as $prevSid) {
            oidc_rebind_session_tokens($storePath, $providerId, $prevSid, $sid, $userId);
        }
    }

    if (!headers_sent()) {
        // Host-only (no Domain) and Path=/, as the __Host- prefix requires.
        setcookie($cookieName, $sid, [
            "expires" => $exp,
            "path" => "/",
            "secure" => $isHttps || str_starts_with($cookieName, "__Host-"),
            "httponly" => true,
            "samesite" => "Lax",
        ]);
    }
    $legacyName = sso_legacy_cookie_name($providerId);
    if ($legacyName !== $cookieName && sso_request_cookies($legacyName) !== []) {
        sso_expire_cookie($legacyName, $isHttps);
    }
    return $sid;
}

/**
 * Ends this browser's SSO session with $provider: every session id the request carried
 * (sso_request_session_ids(): also one under the legacy cookie name or a planted look-alike,
 * G2a-05) is deleted together with the codes and tokens bound to it, and both the current
 * and the legacy cookie are expired.
 */
function sso_destroy_session(
    string $storePath,
    array $provider,
    bool $isHttps
): void {
    $providerId = (string) $provider["id"];
    $sids = sso_request_session_ids($providerId);
    if ($sids !== []) {
        $pdo = storage_db($storePath);
        $del = $pdo->prepare("DELETE FROM sso_sessions WHERE id = :id AND provider_id = :pid");
        foreach ($sids as $sid) {
            // Codes and tokens bound to this session end with it (offline_access grants stay).
            // Best-effort: the helper logs its own errors and never stops the logout.
            if (function_exists("oidc_revoke_tokens_for_session")) {
                oidc_revoke_tokens_for_session($storePath, $providerId, $sid);
            }
            $del->execute([":id" => $sid, ":pid" => $providerId]);
        }
    }
    $cookieName = sso_cookie_name($providerId);
    sso_expire_cookie($cookieName, $isHttps);
    $legacyName = sso_legacy_cookie_name($providerId);
    if ($legacyName !== $cookieName) {
        sso_expire_cookie($legacyName, $isHttps);
    }
}

/**
 * "Sign out everywhere" for the user of this browser's SSO session with $provider (G2a-06):
 * every SSO session of the user (with all providers of the directory), the user's OIDC
 * tokens, offline_access grants included, and unredeemed authorization codes end in one
 * write transaction (directory_revoke_user_access()), and this browser's SSO cookies are
 * expired. Returns the session the request presented, for the caller's audit entry, or
 * null when there was none (this browser's cookies are still expired).
 */
function sso_sign_out_everywhere(
    string $storePath,
    array $provider,
    bool $isHttps
): ?array {
    $session = sso_get_session($storePath, $provider);
    if ($session !== null) {
        $userId = (string) $session["user"]["id"];
        storage_write_transaction(
            storage_db($storePath),
            static function (PDO $pdo) use ($userId): void {
                directory_revoke_user_access($pdo, $userId);
            }
        );
    }
    sso_destroy_session($storePath, $provider, $isHttps);
    return $session;
}

/**
 * Does a sign-in with $amr meet $policy? Pass a resolved policy (effective_auth_policy()).
 * Fails closed (X1-10): any value other than flexible or touchid_only, such as a raw
 * "inherit", an empty string or a typo, is treated as mfa.
 */
function auth_policy_satisfied(string $policy, array $amr): bool
{
    $hasPwd = in_array("pwd", $amr, true);
    $hasHwk = in_array("hwk", $amr, true);
    if ($policy === "flexible") {
        return $hasPwd || $hasHwk;
    }
    if ($policy === "touchid_only") {
        return $hasHwk;
    }
    return $hasPwd && $hasHwk;
}

// ---------- Auth Transactions ----------

/**
 * Returns the storage PDO after this lane's run-once migrations: the
 * auth_transactions.browser_binding column, plus the passkey label repair done by
 * webauthn_db(). Call it outside any transaction.
 */
function auth_flow_db(string $storePath): PDO
{
    $pdo = webauthn_db($storePath);
    schema_ensure($pdo, "login.tx_binding_v1", [
        "ALTER TABLE auth_transactions ADD COLUMN browser_binding TEXT",
    ]);
    return $pdo;
}

// A transaction id is not a secret: it travels in /login?tx= URLs, Location headers and
// page config. Each transaction is therefore bound to the browser that started it.
// tx_create() stores the SHA-256 of a random per-browser cookie, and tx_load() and
// tx_consume_atomic() return only rows whose binding matches the caller's cookie, so a
// /login?tx= or /login/complete?fin= link cannot be completed or watched from another browser.

function tx_binding_cookie_name(): string
{
    // The __Host- prefix makes browsers refuse the cookie unless it is Secure, has Path=/
    // and no Domain, so a sibling subdomain or a plain-HTTP response cannot plant it.
    return !empty($GLOBALS["isHttps"]) ? "__Host-idp_txb" : "idp_txb";
}

/**
 * Returns the SHA-256 (hex) of this browser's transaction-binding cookie. With $mint, a
 * missing or malformed cookie is replaced by a fresh random 32-byte value, sent as a
 * session cookie (HttpOnly, Path=/; over HTTPS Secure and SameSite=None, over plain HTTP
 * SameSite=Lax). Without $mint, "" is returned when the browser has no valid cookie.
 *
 * SameSite=None: sign-ins also start with a cross-site POST (SAML HTTP-POST AuthnRequest,
 * POST /oauth2/authorize, SAML SLO), which carries no Lax cookie. That request would mint a
 * new value, and the browser stores a cookie set on a top-level navigation, so the new value
 * replaced the existing one and every other sign-in in progress in the browser (another tab,
 * a pending completion link, concurrent POST starts) stopped matching; any site could reset
 * a sign-in that way. Sent along with cross-site POSTs, the existing value is reused. The
 * cookie authorizes nothing by itself: it only binds transactions to this browser. Browsers
 * refuse SameSite=None without Secure, so plain HTTP (development only) keeps Lax.
 */
function tx_browser_binding(bool $mint = false): string
{
    $name = tx_binding_cookie_name();
    $value = $_COOKIE[$name] ?? "";
    if (!is_string($value) || preg_match('/^[A-Za-z0-9_-]{43}$/D', $value) !== 1) {
        if (!$mint) {
            return "";
        }
        $value = base64url_encode(random_bytes(32));
        if (!headers_sent()) {
            $https = !empty($GLOBALS["isHttps"]);
            setcookie($name, $value, [
                "expires" => 0,
                "path" => "/",
                "secure" => $https,
                "httponly" => true,
                "samesite" => $https ? "None" : "Lax",
            ]);
        }
        $_COOKIE[$name] = $value;
    }
    return hash("sha256", $value);
}

/**
 * True when an auth_transactions row is bound to the calling browser. Rows without a
 * binding (created before the binding existed) never match.
 */
function tx_row_bound_to_browser(array $row): bool
{
    $stored = $row["browser_binding"] ?? null;
    $current = tx_browser_binding(false);
    return is_string($stored) &&
        $stored !== "" &&
        $current !== "" &&
        hash_equals($stored, $current);
}

/**
 * Stores a new auth transaction that expires after $ttlSeconds and returns its id. It is
 * bound to this browser: tx_browser_binding(true) mints and sets the binding cookie when
 * the request carries none. A payload whose JSON exceeds $maxPayloadBytes, or that cannot
 * be encoded, is refused with an InvalidArgumentException. Keep the default
 * TX_PAYLOAD_MAX_BYTES for anything a request can start without signing in; completion
 * transactions, which wrap such a payload, pass TX_FINALIZE_PAYLOAD_MAX_BYTES.
 *
 * A handler of a cross-site POST (SAML HTTP-POST AuthnRequest or LogoutRequest, POST
 * /oauth2/authorize, an RP's logout form) must not call it directly. Such a request can
 * arrive without the binding cookie (over plain HTTP the cookie is SameSite=Lax, and a
 * browser may withhold cookies from cross-site requests), and the cookie minted here would
 * then replace the one every other sign-in in progress in that browser is bound to.
 * routes_idp.php stores such requests with idp_route_tx_create_handoff() and binds them to
 * the browser at the same-site GET that follows.
 */
function tx_create(
    string $storePath,
    ?string $providerId,
    string $owner,
    string $protocol,
    array $payload,
    array $stepState = [],
    int $ttlSeconds = 900,
    int $maxPayloadBytes = TX_PAYLOAD_MAX_BYTES
): string {
    // Anonymous requests create transactions, so their size is capped (S12-11). A payload
    // that cannot be encoded (invalid UTF-8) is refused instead of being stored empty.
    $payloadJson = json_encode($payload, JSON_UNESCAPED_SLASHES);
    if (!is_string($payloadJson)) {
        throw new InvalidArgumentException("The sign-in request contains data that cannot be stored");
    }
    if (strlen($payloadJson) > $maxPayloadBytes) {
        throw new InvalidArgumentException("The sign-in request is too large");
    }

    $pdo = auth_flow_db($storePath);
    // Expired transactions are removed now and then, in bounded batches, so a flood of
    // abandoned sign-ins cannot make every request scan the table under the write lock.
    if (random_int(1, 20) === 1) {
        $pdo->prepare(
            "DELETE FROM auth_transactions WHERE rowid IN " .
                "(SELECT rowid FROM auth_transactions WHERE expires_at <= :now LIMIT 500)"
        )->execute([":now" => time()]);
    }

    $id = base64url_encode(random_bytes(24));
    $ins = $pdo->prepare(
        "INSERT INTO auth_transactions (id, provider_id, owner, protocol, payload_json, step_state_json, expires_at, browser_binding) " .
            "VALUES (:id, :pid, :owner, :proto, :pay, :st, :exp, :bind)"
    );
    $ins->execute([
        ":id" => $id,
        ":pid" => $providerId,
        ":owner" => $owner,
        ":proto" => $protocol,
        ":pay" => $payloadJson,
        ":st" => json_encode($stepState, JSON_UNESCAPED_SLASHES),
        ":exp" => time() + $ttlSeconds,
        // Login transactions bind to the browser here; finalize (fin) transactions,
        // created while completing a bound login, reuse the same cookie.
        ":bind" => tx_browser_binding(true),
    ]);
    return $id;
}

/**
 * Loads a live transaction, or null when it is unknown, expired or bound to another
 * browser (see tx_browser_binding()).
 */
function tx_load(string $storePath, string $txId): ?array
{
    if (trim($txId) === "") {
        return null;
    }
    $pdo = auth_flow_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM auth_transactions WHERE id = :id LIMIT 1"
    );
    $stmt->execute([":id" => trim($txId)]);
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    if (
        !$r ||
        (int) $r["expires_at"] <= time() ||
        !tx_row_bound_to_browser($r)
    ) {
        return null;
    }
    return [
        "id" => (string) $r["id"],
        "provider_id" => $r["provider_id"],
        "owner" => (string) $r["owner"],
        "protocol" => (string) $r["protocol"],
        "payload" =>
            json_decode((string) ($r["payload_json"] ?? "{}"), true) ?: [],
        "step_state" =>
            json_decode((string) ($r["step_state_json"] ?? "{}"), true) ?: [],
        "expires_at" => (int) $r["expires_at"],
        "browser_bound" => true,
    ];
}

function tx_update_step(
    string $storePath,
    string $txId,
    array $stepState
): void {
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "UPDATE auth_transactions SET step_state_json = :st WHERE id = :id"
    );
    $stmt->execute([
        ":st" => json_encode($stepState, JSON_UNESCAPED_SLASHES),
        ":id" => $txId,
    ]);
}

function tx_delete(string $storePath, string $txId): void
{
    $pdo = storage_db($storePath);
    $pdo->prepare("DELETE FROM auth_transactions WHERE id = :id")->execute([
        ":id" => $txId,
    ]);
}

/**
 * Atomically loads and deletes a transaction (used for single-use fin tokens). Returns
 * null when it is unknown or expired. A transaction bound to another browser is neither
 * returned nor deleted, so a leaked fin link cannot be redeemed or burned elsewhere.
 * A finalize transaction (oidc_finalize, saml_finalize) is also consumed but null is
 * returned when the SSO session its sign-in started has ended meanwhile (G2a-06, see
 * tx_finalize_session_live()).
 */
function tx_consume_atomic(string $storePath, string $txId): ?array
{
    if (trim($txId) === "") {
        return null;
    }
    // Before BEGIN: the migration check must run outside a transaction.
    $pdo = auth_flow_db($storePath);
    $pdo->exec("BEGIN IMMEDIATE");
    try {
        $stmt = $pdo->prepare(
            "SELECT * FROM auth_transactions WHERE id = :id LIMIT 1"
        );
        $stmt->execute([":id" => trim($txId)]);
        $r = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();
        if ($r && !tx_row_bound_to_browser($r)) {
            $r = false;
        }
        $sessionLive = true;
        if ($r) {
            $pdo->prepare(
                "DELETE FROM auth_transactions WHERE id = :id"
            )->execute([":id" => trim($txId)]);
            // Checked under the same write lock that directory_revoke_user_access() takes.
            $sessionLive = tx_finalize_session_live($pdo, $r);
        }
        $pdo->exec("COMMIT");
        if (!$r || (int) $r["expires_at"] <= time() || !$sessionLive) {
            return null;
        }
        return [
            "id" => (string) $r["id"],
            "provider_id" => $r["provider_id"],
            "owner" => (string) $r["owner"],
            "protocol" => (string) $r["protocol"],
            "payload" =>
                json_decode((string) ($r["payload_json"] ?? "{}"), true) ?: [],
            "step_state" =>
                json_decode((string) ($r["step_state_json"] ?? "{}"), true) ?:
                [],
            "expires_at" => (int) $r["expires_at"],
            "browser_bound" => true,
        ];
    } catch (Throwable $e) {
        @$pdo->exec("ROLLBACK");
        throw $e;
    }
}

/**
 * For a finalize transaction row (oidc_finalize, saml_finalize): true while the SSO session
 * its sign-in started (payload sso_session_id, set by auth_complete_transaction()) still
 * exists for the same provider and user and has not expired. A password change, suspension,
 * passkey removal or "sign out everywhere" deletes the user's sessions, so a completion link
 * minted before that (it lives 120 seconds) no longer yields a code or assertion (G2a-06).
 * A finalize row without a session id is refused. Other transactions: always true.
 */
function tx_finalize_session_live(PDO $pdo, array $row): bool
{
    if (!in_array((string) ($row["protocol"] ?? ""), ["oidc_finalize", "saml_finalize"], true)) {
        return true;
    }
    $payload = json_decode((string) ($row["payload_json"] ?? ""), true);
    $sid = is_array($payload) ? ($payload["sso_session_id"] ?? null) : null;
    $userId = is_array($payload) ? ($payload["user_id"] ?? null) : null;
    if (!is_string($sid) || $sid === "" || !is_scalar($userId) || (string) $userId === "") {
        return false;
    }
    $stmt = $pdo->prepare(
        "SELECT 1 FROM sso_sessions WHERE id = :id AND provider_id = :pid AND user_id = :uid " .
            "AND expires_at > :now LIMIT 1"
    );
    storage_execute($stmt, [
        ":id" => $sid,
        ":pid" => (string) ($row["provider_id"] ?? ""),
        ":uid" => (string) $userId,
        ":now" => time(),
    ]);
    $live = $stmt->fetchColumn() !== false;
    $stmt->closeCursor();
    return $live;
}

/**
 * Minimum sign-on policy a transaction asks for (the $minimum of effective_auth_policy()):
 * the payload's min_auth_policy when its creator set one (also when set to null), else the
 * step-up that a RequestedAuthnContext in the stored SAML AuthnRequest needs (S02-02).
 * null when nothing stricter than the app's policy is requested.
 */
function tx_min_auth_policy(array $payload): ?string
{
    if (array_key_exists("min_auth_policy", $payload)) {
        return is_string($payload["min_auth_policy"]) ? $payload["min_auth_policy"] : null;
    }
    $authnReq = $payload["authn_req"] ?? null;
    if (is_array($authnReq) && function_exists("saml_requested_min_auth_policy")) {
        return saml_requested_min_auth_policy($authnReq);
    }
    return null;
}

/**
 * Resolves metadata about the target application & effective Sign-On Policy for a transaction.
 * "auth_policy" is always flexible, touchid_only or mfa: an app or client stored as "inherit"
 * (or with no policy) follows the provider's default_auth_policy, an unknown value fails
 * closed to mfa, and a stricter minimum requested for this sign-in wins (effective_auth_policy()).
 */
function tx_resolve_context(
    string $storePath,
    array $provider,
    array $tx
): array {
    $proto = $tx["protocol"];
    $payload = is_array($tx["payload"] ?? null) ? $tx["payload"] : [];
    $minimum = tx_min_auth_policy($payload);

    if ($proto === "oidc" || $proto === "test_oidc") {
        $client = oidc_find_client_by_client_id(
            $storePath,
            $provider["id"],
            (string) ($payload["client_id"] ?? "")
        );
        return [
            "app_name" => $client["name"] ?? ($payload["app_name"] ?? "OIDC Client"),
            "protocol_label" => "OpenID Connect",
            "auth_policy" => effective_auth_policy($provider, $client, $minimum),
            "assigned_groups" => $client["assigned_groups"] ?? [],
            "client" => $client,
        ];
    }

    if ($proto === "saml" || $proto === "test_saml") {
        $app = !empty($payload["app_id"])
            ? saml_get_app($storePath, $provider["id"], (string) $payload["app_id"])
            : null;
        return [
            "app_name" => $app["name"] ?? ($payload["app_name"] ?? "SAML 2.0 Service Provider"),
            "protocol_label" => "SAML 2.0",
            "auth_policy" => effective_auth_policy($provider, $app, $minimum),
            "assigned_groups" => $app["assigned_groups"] ?? [],
            "saml_app" => $app,
        ];
    }

    return [
        "app_name" => $provider["friendly"] . " App Portal",
        "protocol_label" => "IdP Portal",
        "auth_policy" => effective_auth_policy($provider, null, $minimum),
        "assigned_groups" => [],
    ];
}

/**
 * Completes an authenticated SSO transaction and returns a JSON redirect/post descriptor.
 * The oidc_finalize and saml_finalize payloads it creates carry auth_time (the sign-in time
 * recorded for the new SSO session), session_expires_at (when that session ends) and
 * sso_session_id, so /login/complete can bind codes and tokens to the session and SAML
 * AuthnInstant and SessionNotOnOrAfter follow it.
 *
 * The transaction is single-use (G1c-05): after the account and group checks, and before
 * the SSO session is created, it is claimed with tx_consume_atomic(), which removes it for
 * exactly one request. A failed claim (another request completed it first, or it expired
 * or was removed) throws, so concurrent requests cannot complete one sign-in twice. A
 * refused sign-in throws before the claim and leaves the transaction in place. A caller
 * that has already claimed $tx with tx_consume_atomic() passes $txClaimed = true (as
 * routes_idp.php does); the claim is then skipped.
 */
function auth_complete_transaction(
    string $storePath,
    array &$providers,
    array &$provider,
    string $baseUrl,
    bool $isHttps,
    array $tx,
    array $user,
    array $amr,
    string $keysDir = "",
    bool $txClaimed = false
): array {
    // Defense in depth (S06-11): whatever the caller checked earlier in the sign-in, the
    // account must still exist and be active now, before a session is created for it.
    $current = directory_get_user_by_id(
        $storePath,
        (string) ($user["id"] ?? ""),
        (string) $provider["owner"]
    );
    if (!$current || ($current["status"] ?? "") !== "active") {
        throw new RuntimeException("This account is not active");
    }
    $user = $current;

    $ctx = tx_resolve_context($storePath, $provider, $tx);
    if (
        !directory_user_matches_assigned_groups(
            $user,
            $ctx["assigned_groups"] ?? []
        )
    ) {
        audit_log_append(
            $storePath,
            $provider["id"],
            $tx["protocol"],
            "access_denied_group",
            "error",
            $ctx["app_name"],
            $user["username"],
            $amr,
            ["required_groups" => $ctx["assigned_groups"]]
        );
        throw new RuntimeException(
            "Access denied: user '" .
                $user["username"] .
                "' is not a member of the groups assigned to " .
                $ctx["app_name"]
        );
    }

    // Claimed only after the checks above (G1c-05). The claim removes the row, so nothing is
    // left to delete once the session exists.
    if (!$txClaimed) {
        $claimed = tx_consume_atomic($storePath, (string) ($tx["id"] ?? ""));
        if (
            $claimed === null ||
            (string) ($claimed["provider_id"] ?? "") !== (string) $provider["id"]
        ) {
            throw new RuntimeException("Login session expired; please reload");
        }
    }

    directory_touch_last_login($storePath, $user["id"]);
    $authTime = time();
    $sessionExpiresAt = $authTime + SSO_SESSION_TTL_SECONDS;
    $sid = sso_set_session(
        $storePath,
        $provider,
        $user["id"],
        $amr,
        $isHttps,
        SSO_SESSION_TTL_SECONDS,
        $authTime
    );

    $issuer = $baseUrl . "/" . $provider["idp_id"];
    $proto = $tx["protocol"];
    $payload = $tx["payload"];

    if ($proto === "portal") {
        audit_log_append(
            $storePath,
            $provider["id"],
            "portal",
            "portal_login",
            "success",
            $ctx["app_name"],
            $user["username"],
            $amr
        );
        return [
            "action" => "redirect",
            "url" => $issuer . "/portal",
        ];
    }

    if ($proto === "oidc" || $proto === "test_oidc") {
        $client = $ctx["client"];
        if (!$client) {
            throw new RuntimeException("OIDC client no longer exists");
        }
        $finId = tx_create(
            $storePath,
            $provider["id"],
            $provider["owner"],
            "oidc_finalize",
            [
                "auth_req" => $payload,
                "user_id" => $user["id"],
                "amr" => $amr,
                "auth_time" => $authTime,
                "session_expires_at" => $sessionExpiresAt,
                "sso_session_id" => $sid,
            ],
            [],
            120,
            TX_FINALIZE_PAYLOAD_MAX_BYTES
        );
        return [
            "action" => "redirect",
            "url" => $issuer . "/login/complete?fin=" . rawurlencode($finId),
        ];
    }

    if ($proto === "saml" || $proto === "test_saml") {
        $finId = tx_create(
            $storePath,
            $provider["id"],
            $provider["owner"],
            "saml_finalize",
            [
                "saml_req" => $payload,
                "is_test" => $proto === "test_saml",
                "user_id" => $user["id"],
                "amr" => $amr,
                "auth_time" => $authTime,
                "session_expires_at" => $sessionExpiresAt,
                "sso_session_id" => $sid,
            ],
            [],
            120,
            TX_FINALIZE_PAYLOAD_MAX_BYTES
        );
        return [
            "action" => "redirect",
            "url" => $issuer . "/login/complete?fin=" . rawurlencode($finId),
        ];
    }

    return [
        "action" => "redirect",
        "url" => $issuer . "/portal",
    ];
}

// ---------- Shared Modern CSS Tokens & Fonts ----------

function idp_ui_head_assets(): string
{
    return <<<'ASSETS'
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap" />
  <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" />
  <style>
    :root {
      --bg-canvas: #f6f8fb;
      --bg-card: #ffffff;
      --bg-subtle: #f1f5f9;
      --text-primary: #0f172a;
      --text-secondary: #64748b;
      --border-hairline: #e2e8f0;
      --accent: #4f46e5;
      --accent-hover: #4338ca;
      --accent-soft: rgba(79, 70, 229, 0.1);
      --card-shadow: 0 24px 60px -15px rgba(15, 23, 42, 0.1), 0 1px 3px rgba(15, 23, 42, 0.04);
      --ambient-bg: radial-gradient(circle at 15% 12%, rgba(79, 70, 229, 0.12) 0%, transparent 45%), radial-gradient(circle at 85% 82%, rgba(236, 72, 153, 0.1) 0%, transparent 45%), #f6f8fb;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg-canvas: #090d16;
        --bg-card: #101726;
        --bg-subtle: rgba(148, 163, 184, 0.08);
        --text-primary: #f8fafc;
        --text-secondary: #94a3b8;
        --border-hairline: rgba(148, 163, 184, 0.15);
        --accent: #6366f1;
        --accent-hover: #818cf8;
        --accent-soft: rgba(99, 102, 241, 0.16);
        --card-shadow: 0 28px 65px -12px rgba(0, 0, 0, 0.65);
        --ambient-bg: radial-gradient(circle at 15% 12%, rgba(79, 70, 229, 0.22) 0%, transparent 45%), radial-gradient(circle at 85% 82%, rgba(236, 72, 153, 0.14) 0%, transparent 45%), #090d16;
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--ambient-bg);
      color: var(--text-primary);
      -webkit-font-smoothing: antialiased;
    }
    h1, h2, h3 { font-family: 'Plus Jakarta Sans', 'Inter', sans-serif; letter-spacing: -0.02em; }
    code, pre, .mono { font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace; }
    .mi {
      font-family: 'Material Icons Round';
      font-weight: normal; font-style: normal; font-size: 20px; line-height: 1;
      display: inline-flex; align-items: center; justify-content: center;
      user-select: none; -webkit-font-smoothing: antialiased;
    }
    .brand-shield {
      width: 40px; height: 40px; border-radius: 12px;
      background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 55%, #ec4899 100%);
      display: inline-flex; align-items: center; justify-content: center;
      color: #fff; box-shadow: 0 8px 20px -4px rgba(79, 70, 229, 0.55); flex-shrink: 0;
    }
    @keyframes fadeUp {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .anim-up { animation: fadeUp 0.25s cubic-bezier(0.16, 1, 0.3, 1) both; }
  </style>
ASSETS;
}

// ---------- Modern Status / Confirmation / Error Card ----------

function render_modern_status_page(
    int $httpCode,
    string $title,
    string $message,
    array $opts = []
): never {
    $assets = idp_ui_head_assets();
    $escTitle = html_escape($title);
    $escMsg = html_escape($message);
    $variant = (string) ($opts["variant"] ?? ($httpCode >= 400 ? "error" : "info"));
    $iconName = match ($variant) {
        "error" => "error_outline",
        "confirm" => "logout",
        "success" => "check_circle",
        default => "info",
    };
    $iconBg = match ($variant) {
        "error" => "rgba(239, 68, 68, 0.14)",
        "confirm" => "rgba(245, 158, 11, 0.15)",
        "success" => "rgba(16, 185, 129, 0.15)",
        default => "var(--accent-soft)",
    };
    $iconColor = match ($variant) {
        "error" => "#ef4444",
        "confirm" => "#f59e0b",
        "success" => "#10b981",
        default => "var(--accent)",
    };

    $actionsHtml = "";
    if (!empty($opts["post_action"])) {
        $escPost = html_escape((string) $opts["post_action"]);
        $escBtn = html_escape((string) ($opts["post_label"] ?? "Confirm"));
        // Confirmation pages (sign-out) post the session's CSRF token, so the POST is verified
        // by token rather than by the Origin header alone (S15-02, S02-06). They are shown on
        // top-level GETs, where csrf_token() may start the session.
        $escCsrf = html_escape(csrf_token());
        $actionsHtml .=
            "<form method='post' action='{$escPost}' style='margin-top:22px;'>" .
            "<input type='hidden' name='csrf_token' value='{$escCsrf}'>" .
            "<button type='submit' style='width:100%;padding:12px 20px;border-radius:11px;border:none;background:#dc2626;color:#fff;font-weight:700;font-size:14.5px;cursor:pointer;'>{$escBtn}</button>" .
            "</form>";
    }
    if (!empty($opts["link_url"])) {
        $escUrl = html_escape((string) $opts["link_url"]);
        $escLbl = html_escape((string) ($opts["link_label"] ?? "Continue"));
        $actionsHtml .=
            "<a href='{$escUrl}' style='display:inline-flex;align-items:center;justify-content:center;gap:6px;width:100%;margin-top:14px;padding:11px 18px;border-radius:11px;border:1px solid var(--border-hairline);background:var(--bg-subtle);color:var(--text-primary);text-decoration:none;font-weight:600;font-size:14px;'>{$escLbl}</a>";
    }

    $html = <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{$escTitle}</title>
  {$assets}
</head>
<body style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;">
  <div class="anim-up" style="width:100%;max-width:440px;background:var(--bg-card);border:1px solid var(--border-hairline);border-radius:20px;box-shadow:var(--card-shadow);padding:36px 32px;text-align:center;">
    <div style="width:52px;height:52px;border-radius:16px;background:{$iconBg};color:{$iconColor};display:inline-flex;align-items:center;justify-content:center;margin-bottom:16px;">
      <span class="mi" style="font-size:28px;">{$iconName}</span>
    </div>
    <h1 style="margin:0 0 8px;font-size:21px;font-weight:800;">{$escTitle}</h1>
    <p style="margin:0;color:var(--text-secondary);font-size:14.5px;line-height:1.55;">{$escMsg}</p>
    {$actionsHtml}
  </div>
</body>
</html>
HTML;

    html_response($httpCode, $html);
}

// ---------- Hosted Sign-In Page HTML (Touch ID + Password + MFA) ----------

/**
 * Renders the hosted sign-in page for a transaction loaded with tx_load(). $rpId is the
 * WebAuthn RP ID of this request ("" uses the global $rpId); passkeys are counted for it
 * only, as /login/password and the assertion options do.
 */
function render_hosted_login_page(
    string $storePath,
    array $provider,
    string $baseUrl,
    array $tx,
    string $rpId = ""
): never {
    if ($rpId === "") {
        $rpId = (string) ($GLOBALS["rpId"] ?? "");
    }
    $ctx = tx_resolve_context($storePath, $provider, $tx);
    $issuer = $baseUrl . "/" . $provider["idp_id"];
    $appName = html_escape($ctx["app_name"]);
    $protoLabel = html_escape($ctx["protocol_label"]);
    $provFriendly = html_escape($provider["friendly"]);
    $policy = $ctx["auth_policy"];
    $assets = idp_ui_head_assets();

    $stepState = $tx["step_state"] ?? [];
    $mfaUser = null;
    $mfaCredentialCount = 0;
    // Who is signing in is shown only to the browser the transaction is bound to.
    if (
        !empty($stepState["pwd_verified_user_id"]) &&
        ($tx["browser_bound"] ?? false) === true
    ) {
        $mfaUser = directory_get_user_by_id(
            $storePath,
            (string) $stepState["pwd_verified_user_id"],
            $provider["owner"]
        );
        if ($mfaUser) {
            $mfaCredentialCount = webauthn_count_user_credentials(
                $storePath,
                (string) $mfaUser["id"],
                $rpId
            );
        }
    }

    $initConfig = safe_json_for_script([
        "txId" => $tx["id"],
        "csrfToken" => csrf_token(),
        "issuerUrl" => $issuer,
        "providerName" => $provider["friendly"],
        "appName" => $ctx["app_name"],
        "protocolLabel" => $ctx["protocol_label"],
        "policy" => $policy,
        // Inline enrollment of a first passkey at MFA step 2 is refused by the server unless
        // allow_first_use_passkey_enrollment is on (S06-01), so the page does not offer it.
        "allowInlineEnrollment" => config_flag(
            "allow_first_use_passkey_enrollment",
            "OIDC_ALLOW_FIRST_USE_PASSKEY_ENROLLMENT"
        ),
        "mfaStep2User" => $mfaUser
            ? [
                "id" => $mfaUser["id"],
                "username" => $mfaUser["username"],
                "email" => $mfaUser["email"],
                "touchid_count" => $mfaCredentialCount,
            ]
            : null,
    ]);

    $html = <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sign in to {$appName} — {$provFriendly}</title>
  {$assets}
  <style>
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .login-card {
      width: 100%;
      max-width: 438px;
      background: var(--bg-card);
      border-radius: 22px;
      box-shadow: var(--card-shadow);
      border: 1px solid var(--border-hairline);
      padding: 38px 34px 32px;
    }
    .brand-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 22px;
      gap: 10px;
    }
    .idp-badge {
      display: inline-flex;
      align-items: center;
      gap: 9px;
      font-weight: 700;
      font-size: 13.5px;
      color: var(--text-primary);
    }
    .proto-pill {
      font-size: 11px;
      font-weight: 700;
      color: var(--accent);
      background: var(--accent-soft);
      padding: 4px 10px;
      border-radius: 999px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    h1 {
      font-size: 23px;
      font-weight: 800;
      margin: 0 0 6px;
      color: var(--text-primary);
    }
    .subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 24px;
      line-height: 1.45;
    }
    .touchid-btn {
      width: 100%;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      padding: 13px 18px;
      border-radius: 13px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      background: linear-gradient(135deg, #111827 0%, #1e293b 100%);
      color: #ffffff;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.14s ease, box-shadow 0.16s ease;
      box-shadow: 0 10px 24px -8px rgba(15, 23, 42, 0.45);
    }
    @media (prefers-color-scheme: dark) {
      .touchid-btn {
        background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 60%, #db2777 100%);
        box-shadow: 0 10px 28px -8px rgba(99, 102, 241, 0.55);
      }
    }
    .touchid-btn:hover:not(:disabled) {
      transform: translateY(-1px);
    }
    .touchid-btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .fp-ring {
      width: 30px; height: 30px; border-radius: 9px;
      background: rgba(244, 63, 94, 0.18);
      display: inline-flex; align-items: center; justify-content: center;
      color: #fb7185;
    }
    @media (prefers-color-scheme: dark) {
      .fp-ring { background: rgba(255, 255, 255, 0.18); color: #fff; }
    }
    .divider {
      display: flex; align-items: center; margin: 22px 0;
      color: var(--text-secondary); font-size: 11.5px; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.06em;
    }
    .divider::before, .divider::after {
      content: ""; flex: 1; border-bottom: 1px solid var(--border-hairline);
    }
    .divider span { padding: 0 12px; }
    .field { margin-bottom: 15px; }
    label {
      display: block; font-size: 13px; font-weight: 600;
      color: var(--text-primary); margin-bottom: 6px;
    }
    .inp-wrap { position: relative; }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 11.5px 14px;
      font-size: 14.5px;
      font-family: inherit;
      color: var(--text-primary);
      background: var(--bg-subtle);
      border: 1px solid var(--border-hairline);
      border-radius: 11px;
      outline: none;
      transition: border-color 0.15s, box-shadow 0.15s, background 0.15s;
    }
    input:focus {
      background: var(--bg-card);
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-soft);
    }
    .pw-toggle {
      position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
      border: none; background: transparent; color: var(--text-secondary);
      cursor: pointer; padding: 4px; display: inline-flex;
    }
    .primary-btn {
      width: 100%;
      padding: 12.5px 18px;
      border-radius: 11px;
      border: none;
      background: var(--accent);
      color: #fff;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      margin-top: 6px;
      transition: background 0.15s, transform 0.12s;
    }
    .primary-btn:hover:not(:disabled) { background: var(--accent-hover); transform: translateY(-1px); }
    .alert {
      padding: 12px 14px; border-radius: 11px; font-size: 13px;
      margin-top: 16px; line-height: 1.5;
    }
    .alert-error { background: rgba(239, 68, 68, 0.12); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.28); }
    .alert-warn { background: rgba(245, 158, 11, 0.12); color: #d97706; border: 1px solid rgba(245, 158, 11, 0.28); }
    .alert-info { background: var(--accent-soft); color: var(--accent); border: 1px solid rgba(99, 102, 241, 0.25); }
    .footer-meta {
      margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--border-hairline);
      display: flex; align-items: center; justify-content: center; gap: 6px;
      font-size: 12px; color: var(--text-secondary);
    }
  </style>
</head>
<body>
  <div class="login-card anim-up">
    <div class="brand-row">
      <div class="idp-badge">
        <span class="brand-shield" style="width:30px;height:30px;border-radius:9px;">
          <span class="mi" style="font-size:17px;">shield</span>
        </span>
        <span>{$provFriendly}</span>
      </div>
      <span class="proto-pill">{$protoLabel}</span>
    </div>

    <h1>Sign in to {$appName}</h1>
    <p class="subtitle" id="subtitle-text">Verify your identity to continue</p>

    <div id="secure-warning" class="alert alert-warn" style="display:none; margin-bottom:18px; margin-top:0;">
      <strong>Secure Origin Required:</strong> macOS browsers require <code>https://</code> or <code>http://localhost</code> for Touch ID Passkeys.
    </div>

    <div id="step-main"></div>
    <div id="error-box" class="alert alert-error" style="display:none;"></div>

    <div class="footer-meta">
      <span class="mi" style="font-size:15px;">verified_user</span>
      <span>Protected by WebAuthn &amp; Zero-Trust SSO</span>
    </div>
  </div>

  <script>
    const CONFIG = {$initConfig};

    function b64uToBytes(b64u) {
      let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      const bin = atob(b64);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return arr;
    }

    function bytesToB64u(buf) {
      const bytes = new Uint8Array(buf);
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function setError(msg) {
      const box = document.getElementById('error-box');
      if (!msg) { box.style.display = 'none'; box.textContent = ''; }
      else { box.style.display = 'block'; box.textContent = msg; }
    }

    let stateMfaUser = CONFIG.mfaStep2User;

    // Passkey sign-in sends no username: the browser offers its discoverable passkeys.
    // In MFA step 2 the server already knows the user from the password step.
    async function triggerTouchIdLogin() {
      setError('');
      if (!window.PublicKeyCredential) {
        setError('WebAuthn / Touch ID is not supported in this browser context.');
        return;
      }
      try {
        const optRes = await fetch(CONFIG.issuerUrl + '/login/webauthn/options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CONFIG.csrfToken },
          body: JSON.stringify({ txId: CONFIG.txId })
        });
        const optJson = await optRes.json();
        if (!optRes.ok) throw new Error(optJson.error || 'Could not start Touch ID');

        const pk = optJson.publicKey;
        pk.challenge = b64uToBytes(pk.challenge);
        if (Array.isArray(pk.allowCredentials)) {
          pk.allowCredentials = pk.allowCredentials.map(c => ({
            ...c,
            id: b64uToBytes(c.id)
          }));
        }

        const assertion = await navigator.credentials.get({ publicKey: pk });
        const verifyRes = await fetch(CONFIG.issuerUrl + '/login/webauthn/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CONFIG.csrfToken },
          body: JSON.stringify({
            txId: CONFIG.txId,
            credential: {
              id: assertion.id,
              rawId: bytesToB64u(assertion.rawId),
              type: assertion.type,
              response: {
                clientDataJSON: bytesToB64u(assertion.response.clientDataJSON),
                authenticatorData: bytesToB64u(assertion.response.authenticatorData),
                signature: bytesToB64u(assertion.response.signature),
                userHandle: assertion.response.userHandle ? bytesToB64u(assertion.response.userHandle) : null
              }
            }
          })
        });
        const verifyJson = await verifyRes.json();
        if (!verifyRes.ok) throw new Error(verifyJson.error || 'Touch ID verification failed');
        if (verifyJson.url) window.location.href = verifyJson.url;
      } catch (err) {
        if (err && err.name === 'NotAllowedError') {
          setError('Touch ID prompt was cancelled, timed out, or no matching Passkey is enrolled on this Mac.');
        } else {
          setError(err.message || String(err));
        }
      }
    }

    async function enrollInlineMfaTouchId() {
      setError('');
      try {
        const optRes = await fetch(CONFIG.issuerUrl + '/login/webauthn/register-options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CONFIG.csrfToken },
          body: JSON.stringify({ txId: CONFIG.txId })
        });
        const optJson = await optRes.json();
        if (!optRes.ok) throw new Error(optJson.error || 'Failed to start Touch ID enrollment');

        const pk = optJson.publicKey;
        pk.challenge = b64uToBytes(pk.challenge);
        pk.user.id = b64uToBytes(pk.user.id);
        if (Array.isArray(pk.excludeCredentials)) {
          pk.excludeCredentials = pk.excludeCredentials.map(c => ({ ...c, id: b64uToBytes(c.id) }));
        }

        const cred = await navigator.credentials.create({ publicKey: pk });
        const regRes = await fetch(CONFIG.issuerUrl + '/login/webauthn/register-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CONFIG.csrfToken },
          body: JSON.stringify({
            txId: CONFIG.txId,
            friendlyName: 'macOS Touch ID',
            credential: {
              id: cred.id,
              rawId: bytesToB64u(cred.rawId),
              type: cred.type,
              response: {
                clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
                attestationObject: bytesToB64u(cred.response.attestationObject),
                transports: cred.response.getTransports ? cred.response.getTransports() : ['internal']
              }
            }
          })
        });
        const regJson = await regRes.json();
        if (!regRes.ok) throw new Error(regJson.error || 'Enrollment failed');
        if (regJson.url) window.location.href = regJson.url;
      } catch (err) {
        setError(err.message || String(err));
      }
    }

    async function submitPasswordForm(e) {
      e.preventDefault();
      setError('');
      const username = document.getElementById('inp-username').value.trim();
      const password = document.getElementById('inp-password').value;
      if (!username || !password) {
        setError('Please enter both username/email and password.');
        return;
      }
      try {
        const res = await fetch(CONFIG.issuerUrl + '/login/password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CONFIG.csrfToken },
          body: JSON.stringify({ txId: CONFIG.txId, username, password })
        });
        const j = await res.json();
        if (!res.ok) throw new Error(j.error || 'Sign-in failed');
        if (j.action === 'mfa_step2') {
          stateMfaUser = j.user;
          render();
          if (stateMfaUser.touchid_count > 0) {
            triggerTouchIdLogin();
          }
          return;
        }
        if (j.url) window.location.href = j.url;
      } catch (err) {
        setError(err.message || String(err));
      }
    }

    function wirePasswordVisibility() {
      const btn = document.getElementById('btn-pw-vis');
      const inp = document.getElementById('inp-password');
      if (!btn || !inp) return;
      btn.onclick = () => {
        const show = inp.type === 'password';
        inp.type = show ? 'text' : 'password';
        btn.querySelector('.mi').textContent = show ? 'visibility_off' : 'visibility';
      };
    }

    function render() {
      const container = document.getElementById('step-main');
      const subtitle = document.getElementById('subtitle-text');

      if (!window.isSecureContext) {
        document.getElementById('secure-warning').style.display = 'block';
      }

      if (stateMfaUser) {
        subtitle.textContent = 'Step 2 of 2 — Biometric verification for ' + stateMfaUser.email;
        if (stateMfaUser.touchid_count > 0) {
          container.innerHTML = `
            <div class="alert alert-info" style="margin-top:0; margin-bottom:18px;">
              <strong>Password verified.</strong> Place your finger on your Mac's Touch ID sensor to finish signing in.
            </div>
            <button type="button" class="touchid-btn" id="btn-mfa-touchid">
              <span class="fp-ring"><span class="mi" style="font-size:19px;">fingerprint</span></span>
              <span>Verify with macOS Touch ID</span>
            </button>
          `;
          document.getElementById('btn-mfa-touchid').onclick = () => triggerTouchIdLogin();
        } else if (!CONFIG.allowInlineEnrollment) {
          container.innerHTML = `
            <div class="alert alert-info" style="margin-top:0; margin-bottom:18px;">
              <strong>Password verified.</strong> This application also requires a passkey (Touch ID), and your account has none for this site yet. Ask your administrator for a passkey enrollment link, enroll your passkey with it, then sign in again.
            </div>
          `;
        } else {
          container.innerHTML = `
            <div class="alert alert-info" style="margin-top:0; margin-bottom:18px;">
              This application requires Step-Up MFA. Enroll your Mac's Touch ID sensor now to complete sign-in.
            </div>
            <button type="button" class="touchid-btn" id="btn-mfa-enroll">
              <span class="fp-ring"><span class="mi" style="font-size:19px;">fingerprint</span></span>
              <span>Enroll Touch ID &amp; Continue</span>
            </button>
          `;
          document.getElementById('btn-mfa-enroll').onclick = enrollInlineMfaTouchId;
        }
        return;
      }

      if (CONFIG.policy === 'touchid_only') {
        subtitle.textContent = 'Phishing-resistant biometric sign-in required';
        container.innerHTML = `
          <button type="button" class="touchid-btn" id="btn-touchid">
            <span class="fp-ring"><span class="mi" style="font-size:19px;">fingerprint</span></span>
            <span>Continue with macOS Touch ID</span>
          </button>
        `;
        document.getElementById('btn-touchid').onclick = () => triggerTouchIdLogin();
        return;
      }

      if (CONFIG.policy === 'mfa') {
        subtitle.textContent = 'Step 1 of 2 — Enter your directory password';
        container.innerHTML = `
          <form id="pw-form">
            <div class="field">
              <label for="inp-username">Username or Email</label>
              <input id="inp-username" type="text" placeholder="alice@company.example" autocomplete="username" autofocus required />
            </div>
            <div class="field">
              <label for="inp-password">Password</label>
              <div class="inp-wrap">
                <input id="inp-password" type="password" autocomplete="current-password" style="padding-right:40px;" required />
                <button type="button" class="pw-toggle" id="btn-pw-vis" tabindex="-1"><span class="mi" style="font-size:19px;">visibility</span></button>
              </div>
            </div>
            <button type="submit" class="primary-btn">Continue to Touch ID</button>
          </form>
        `;
        wirePasswordVisibility();
        document.getElementById('pw-form').onsubmit = submitPasswordForm;
        return;
      }

      // Default: 'flexible' (Touch ID or Password)
      subtitle.textContent = 'Sign in instantly with Touch ID or your password';
      container.innerHTML = `
        <button type="button" class="touchid-btn" id="btn-touchid">
          <span class="fp-ring"><span class="mi" style="font-size:19px;">fingerprint</span></span>
          <span>Sign in with macOS Touch ID</span>
        </button>
        <div class="divider"><span>or continue with password</span></div>
        <form id="pw-form">
          <div class="field">
            <label for="inp-username">Username or Email</label>
            <input id="inp-username" type="text" autocomplete="username webauthn" placeholder="alice@company.example" />
          </div>
          <div class="field">
            <label for="inp-password">Password</label>
            <div class="inp-wrap">
              <input id="inp-password" type="password" autocomplete="current-password" style="padding-right:40px;" />
              <button type="button" class="pw-toggle" id="btn-pw-vis" tabindex="-1"><span class="mi" style="font-size:19px;">visibility</span></button>
            </div>
          </div>
          <button type="submit" class="primary-btn">Sign In</button>
        </form>
      `;
      wirePasswordVisibility();
      document.getElementById('btn-touchid').onclick = () => triggerTouchIdLogin();
      document.getElementById('pw-form').onsubmit = submitPasswordForm;
    }

    render();
  </script>
</body>
</html>
HTML;

    html_response(200, $html);
}

// ---------- Self-Service Touch ID Enrollment Page ----------

function render_enrollment_page(
    array $user,
    string $token,
    string $baseUrl
): never {
    $uName = html_escape($user["display_name"] ?: $user["username"]);
    $uEmail = html_escape($user["email"]);
    $assets = idp_ui_head_assets();
    $cfgJson = safe_json_for_script([
        "token" => $token,
        "csrfToken" => csrf_token(),
        "baseUrl" => $baseUrl,
        "existingCount" => $user["touchid_count"] ?? 0,
    ]);

    $html = <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Enroll macOS Touch ID — {$uName}</title>
  {$assets}
  <style>
    body { min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
    .card {
      width:100%; max-width:445px; background:var(--bg-card); border-radius:22px;
      border:1px solid var(--border-hairline); box-shadow:var(--card-shadow); padding:36px 32px;
    }
    .hero-fp {
      width:56px; height:56px; border-radius:17px;
      background:linear-gradient(135deg, #e11d48 0%, #db2777 55%, #7c3aed 100%);
      color:#fff; display:inline-flex; align-items:center; justify-content:center;
      box-shadow:0 12px 26px -6px rgba(225, 29, 72, 0.45); margin-bottom:18px;
    }
    h1 { margin:0 0 8px; font-size:22px; font-weight:800; }
    p { margin:0 0 20px; color:var(--text-secondary); font-size:14px; line-height:1.55; }
    .user-pill {
      display:flex; align-items:center; gap:10px; padding:10px 13px; border-radius:12px;
      background:var(--bg-subtle); border:1px solid var(--border-hairline); margin-bottom:18px; font-size:13.5px;
    }
    label { display:block; font-size:13px; font-weight:600; margin-bottom:6px; }
    input {
      width:100%; padding:11.5px 14px; border-radius:11px; border:1px solid var(--border-hairline);
      background:var(--bg-subtle); color:var(--text-primary); font-family:inherit; font-size:14.5px; margin-bottom:18px; outline:none;
    }
    input:focus { border-color:var(--accent); box-shadow:0 0 0 3px var(--accent-soft); background:var(--bg-card); }
    .btn {
      width:100%; display:flex; align-items:center; justify-content:center; gap:10px;
      padding:13px 18px; border:none; border-radius:12px;
      background:linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
      color:#fff; font-size:15px; font-weight:700; cursor:pointer;
      box-shadow:0 10px 24px -6px rgba(79, 70, 229, 0.45);
    }
    .msg { margin-top:16px; padding:12px 14px; border-radius:11px; font-size:13.5px; line-height:1.45; }
    .ok { background:rgba(16, 185, 129, 0.14); color:#10b981; border:1px solid rgba(16, 185, 129, 0.3); }
    .err { background:rgba(239, 68, 68, 0.12); color:#ef4444; border:1px solid rgba(239, 68, 68, 0.28); }
  </style>
</head>
<body>
  <div class="card anim-up">
    <div class="hero-fp"><span class="mi" style="font-size:30px;">fingerprint</span></div>
    <h1>Enroll macOS Touch ID</h1>
    <p>Register a hardware-backed platform Passkey on this Mac for passwordless SAML 2.0 &amp; OIDC sign-in.</p>
    <div class="user-pill">
      <span class="mi" style="color:var(--accent);">account_circle</span>
      <div>
        <div style="font-weight:700;">{$uName}</div>
        <div class="mono" style="font-size:12px;color:var(--text-secondary);">{$uEmail}</div>
      </div>
    </div>
    <label for="dev-name">Authenticator Label</label>
    <input id="dev-name" type="text" value="MacBook Touch ID" maxlength="80" />
    <button class="btn" id="btn-enroll">
      <span class="mi">fingerprint</span>
      <span>Register Touch ID Sensor</span>
    </button>
    <div id="status-box"></div>
  </div>
  <script>
    const CFG = {$cfgJson};
    function b64uToBytes(b64u) {
      let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      const bin = atob(b64);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return arr;
    }
    function bytesToB64u(buf) {
      const bytes = new Uint8Array(buf);
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    document.getElementById('btn-enroll').onclick = async () => {
      const box = document.getElementById('status-box');
      box.textContent = '';
      const showBoxMsg = (cls, text) => {
        const d = document.createElement('div');
        d.className = 'msg ' + cls;
        d.textContent = text;
        box.replaceChildren(d);
      };
      try {
        const r1 = await fetch(CFG.baseUrl + '/enroll/options', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': CFG.csrfToken},
          body: JSON.stringify({ token: CFG.token })
        });
        const j1 = await r1.json();
        if (!r1.ok) throw new Error(j1.error || 'Failed to start enrollment');
        const pk = j1.publicKey;
        pk.challenge = b64uToBytes(pk.challenge);
        pk.user.id = b64uToBytes(pk.user.id);
        if (Array.isArray(pk.excludeCredentials)) {
          pk.excludeCredentials = pk.excludeCredentials.map(c => ({ ...c, id: b64uToBytes(c.id) }));
        }
        const cred = await navigator.credentials.create({ publicKey: pk });
        const r2 = await fetch(CFG.baseUrl + '/enroll/verify', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': CFG.csrfToken},
          body: JSON.stringify({
            token: CFG.token,
            friendlyName: document.getElementById('dev-name').value.trim() || 'MacBook Touch ID',
            credential: {
              id: cred.id,
              rawId: bytesToB64u(cred.rawId),
              type: cred.type,
              response: {
                clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
                attestationObject: bytesToB64u(cred.response.attestationObject),
                transports: cred.response.getTransports ? cred.response.getTransports() : ['internal']
              }
            }
          })
        });
        const j2 = await r2.json();
        if (!r2.ok) throw new Error(j2.error || 'Verification failed');
        document.getElementById('btn-enroll').disabled = true;
        showBoxMsg('ok', 'Touch ID Passkey enrolled! You can now sign into any assigned SAML 2.0 or OIDC application with your fingerprint.');
      } catch (e) {
        showBoxMsg('err', e.message || String(e));
      }
    };
  </script>
</body>
</html>
HTML;

    html_response(200, $html);
}

// ---------- Okta / WorkOS-Style End-User App Launchpad (/{idpId}/portal) ----------

/**
 * Launch URL for an OIDC client tile: the client's Initiate Login URI with the REQUIRED
 * iss parameter of third-party-initiated login (OIDC Core section 4). Returns null when the
 * client has no usable login_uri or is the built-in test playground: such clients get no
 * tile, instead of a link to the developer test harness.
 */
function portal_oidc_launch_url(array $client, string $issuer): ?string
{
    if (str_starts_with((string) ($client["client_id"] ?? ""), "builtin-oidc-playground-")) {
        return null;
    }
    $loginUri = trim((string) ($client["login_uri"] ?? ""));
    if ($loginUri === "") {
        return null;
    }
    try {
        // Same rules as at save time: http(s) only, no fragment, https unless loopback.
        $loginUri = validate_endpoint_url($loginUri, false, "Initiate Login URI");
    } catch (Throwable $e) {
        return null;
    }
    parse_str((string) parse_url($loginUri, PHP_URL_QUERY), $query);
    if (array_key_exists("iss", $query)) {
        return $loginUri;
    }
    if (!str_contains($loginUri, "?")) {
        $sep = "?";
    } elseif (str_ends_with($loginUri, "?") || str_ends_with($loginUri, "&")) {
        $sep = "";
    } else {
        $sep = "&";
    }
    return $loginUri . $sep . "iss=" . rawurlencode($issuer);
}

/**
 * Renders the end-user portal for $session. With $signOutEverywhereUrl (a POST route on this
 * IdP that calls sso_sign_out_everywhere()), a "Sign Out Everywhere" button posts the
 * session's CSRF token there (G2a-06); without it the button is not shown.
 */
function render_end_user_portal(
    string $storePath,
    array $provider,
    string $baseUrl,
    array $session,
    string $signOutEverywhereUrl = ""
): never {
    $user = $session["user"];
    $issuer = $baseUrl . "/" . $provider["idp_id"];
    $assets = idp_ui_head_assets();

    $samlApps = array_values(
        array_filter(
            saml_list_apps($storePath, $provider["id"]),
            fn($a) => directory_user_matches_assigned_groups(
                $user,
                $a["assigned_groups"] ?? []
            )
        )
    );
    $oidcClients = array_values(
        array_filter(
            oidc_list_clients($storePath, $provider["id"]),
            fn($c) => directory_user_matches_assigned_groups(
                $user,
                $c["assigned_groups"] ?? []
            )
        )
    );

    $provFriendly = html_escape($provider["friendly"]);
    $dispName = html_escape($user["display_name"]);
    $emailEsc = html_escape($user["email"]);
    $escLogoutUrl = html_escape($issuer . "/oauth2/logout");
    // The Sign Out form posts the session's CSRF token (S15-02).
    $escCsrfToken = html_escape(csrf_token());
    $signOutEverywhereHtml = "";
    if ($signOutEverywhereUrl !== "") {
        $escEverywhereUrl = html_escape($signOutEverywhereUrl);
        $signOutEverywhereHtml =
            '<form method="post" action="' . $escEverywhereUrl . '" id="form-signout-everywhere" style="margin:0;">' .
            '<input type="hidden" name="csrf_token" value="' . $escCsrfToken . '">' .
            '<button type="submit" class="btn btn-ghost" title="Ends your sessions in every browser and revokes the access you granted to applications">' .
            '<span class="mi" style="font-size:16px;">devices</span>' .
            "<span>Sign Out Everywhere</span>" .
            "</button>" .
            "</form>";
    }

    $amrBadges = implode(
        "",
        array_map(
            fn($m) => '<span class="amr-chip">' .
                ($m === "hwk" ? '<span class="mi" style="font-size:13px;">fingerprint</span>' : "") .
                html_escape((string) $m) .
                "</span>",
            $session["amr"]
        )
    );

    $cardsHtml = "";
    foreach ($samlApps as $sa) {
        $launchUrl = $issuer . "/saml/sso?app_id=" . rawurlencode($sa["id"]);
        $escName = html_escape($sa["name"]);
        $escSub = html_escape($sa["sp_entity_id"]);
        $searchAttr = html_escape(strtolower($sa["name"] . " " . $sa["sp_entity_id"] . " saml"));
        $cardsHtml .=
            '<a class="app-tile" data-search="' . $searchAttr . '" href="' . html_escape($launchUrl) . '" target="_blank" rel="noreferrer">' .
            '<div class="tile-top">' .
            '<span class="app-proto saml">SAML 2.0</span>' .
            '<span class="mi launch-arrow">north_east</span>' .
            "</div>" .
            '<div class="app-title">' . $escName . "</div>" .
            '<div class="app-sub mono">' . $escSub . "</div>" .
            "</a>";
    }
    foreach ($oidcClients as $oc) {
        $launchUrl = portal_oidc_launch_url($oc, $issuer);
        if ($launchUrl === null) {
            continue;
        }
        $escName = html_escape($oc["name"]);
        $escSub = html_escape($oc["client_id"]);
        $searchAttr = html_escape(strtolower($oc["name"] . " " . $oc["client_id"] . " oidc"));
        $cardsHtml .=
            '<a class="app-tile" data-search="' . $searchAttr . '" href="' . html_escape($launchUrl) . '" target="_blank" rel="noreferrer">' .
            '<div class="tile-top">' .
            '<span class="app-proto oidc">OIDC 1.0</span>' .
            '<span class="mi launch-arrow">north_east</span>' .
            "</div>" .
            '<div class="app-title">' . $escName . "</div>" .
            '<div class="app-sub mono">' . $escSub . "</div>" .
            "</a>";
    }
    if ($cardsHtml === "") {
        $cardsHtml =
            '<div style="grid-column:1/-1;padding:36px 20px;text-align:center;color:var(--text-secondary);font-size:14px;">' .
            '<span class="mi" style="font-size:36px;opacity:0.4;display:block;margin-bottom:8px;">apps</span>' .
            "No SAML 2.0 or OIDC applications are currently assigned to your account." .
            "</div>";
    }

    // Labels are re-sanitized here so one malformed stored label cannot make the whole
    // config fail to encode (safe_json_for_script() would then return "{}").
    $portalCredentials = [];
    foreach ($user["credentials"] ?? [] as $cred) {
        if (is_array($cred)) {
            $cred["friendly_name"] = sanitize_label((string) ($cred["friendly_name"] ?? ""), 80);
            $portalCredentials[] = $cred;
        }
    }
    $portalCfg = safe_json_for_script([
        "issuerUrl" => $issuer,
        "csrfToken" => csrf_token(),
        "credentials" => $portalCredentials,
    ]);

    $html = <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{$provFriendly} — Application Launchpad</title>
  {$assets}
  <style>
    .topbar {
      position: sticky; top: 0; z-index: 20;
      backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
      background: color-mix(in srgb, var(--bg-card) 82%, transparent);
      border-bottom: 1px solid var(--border-hairline);
      padding: 14px 28px; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap;
    }
    .container { max-width: 1040px; margin: 36px auto 64px; padding: 0 22px; }
    .hero { display: flex; justify-content: space-between; align-items: flex-end; flex-wrap: wrap; gap: 16px; margin-bottom: 24px; }
    .search-box {
      position: relative; min-width: 260px;
    }
    .search-box input {
      width: 100%; padding: 10px 14px 10px 36px; border-radius: 11px;
      border: 1px solid var(--border-hairline); background: var(--bg-card);
      color: var(--text-primary); font-family: inherit; font-size: 13.5px; outline: none;
    }
    .search-box input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
    .search-box .mi { position: absolute; left: 11px; top: 50%; transform: translateY(-50%); font-size: 18px; color: var(--text-secondary); }
    .section {
      background: var(--bg-card); border-radius: 20px; border: 1px solid var(--border-hairline);
      padding: 26px; margin-bottom: 24px; box-shadow: var(--card-shadow);
    }
    h2 { margin: 0 0 18px; font-size: 17px; font-weight: 800; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(255px, 1fr)); gap: 16px; }
    .app-tile {
      display: block; text-decoration: none; color: inherit;
      border: 1px solid var(--border-hairline); border-radius: 15px; padding: 20px;
      background: var(--bg-subtle); transition: transform 0.15s ease, border-color 0.15s ease, background 0.15s ease;
    }
    .app-tile:hover { transform: translateY(-2px); border-color: var(--accent); background: var(--bg-card); }
    .tile-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
    .launch-arrow { font-size: 18px; color: var(--text-secondary); transition: transform 0.15s, color 0.15s; }
    .app-tile:hover .launch-arrow { transform: translate(2px, -2px); color: var(--accent); }
    .app-proto { display: inline-block; font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 999px; }
    .app-proto.saml { background: rgba(245, 158, 11, 0.16); color: #d97706; }
    .app-proto.oidc { background: rgba(59, 130, 246, 0.16); color: #2563eb; }
    .app-title { font-weight: 700; font-size: 15.5px; margin-bottom: 5px; }
    .app-sub { font-size: 12px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .amr-chip {
      display: inline-flex; align-items: center; gap: 4px;
      background: var(--accent-soft); color: var(--accent);
      font-size: 11px; font-weight: 700; padding: 3px 9px; border-radius: 999px; margin-left: 5px;
    }
    .btn {
      display: inline-flex; align-items: center; gap: 7px; padding: 9.5px 15px;
      border-radius: 10px; border: none; background: var(--accent); color: #fff;
      font-weight: 600; font-size: 13px; cursor: pointer; text-decoration: none; font-family: inherit;
    }
    .btn-ghost {
      background: transparent; border: 1px solid var(--border-hairline); color: var(--text-primary);
    }
    .btn-ghost:hover { background: var(--bg-subtle); }
  </style>
</head>
<body>
  <header class="topbar">
    <div style="display:flex;align-items:center;gap:12px;">
      <span class="brand-shield" style="width:34px;height:34px;border-radius:10px;">
        <span class="mi" style="font-size:19px;">shield</span>
      </span>
      <div>
        <div style="font-weight:800;font-size:15px;">{$provFriendly}</div>
        <div style="font-size:11.5px;color:var(--text-secondary);">End-User SSO Launchpad</div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;font-size:13px;">
      <div>
        <strong>{$dispName}</strong> <span style="color:var(--text-secondary);">({$emailEsc})</span>
        {$amrBadges}
      </div>
      <form method="post" action="{$escLogoutUrl}" style="margin:0;">
        <input type="hidden" name="csrf_token" value="{$escCsrfToken}">
        <button type="submit" class="btn btn-ghost">
          <span class="mi" style="font-size:16px;">logout</span>
          <span>Sign Out</span>
        </button>
      </form>
      {$signOutEverywhereHtml}
    </div>
  </header>

  <div class="container anim-up">
    <div class="hero">
      <div>
        <h1 style="margin:0 0 4px;font-size:24px;font-weight:800;">Welcome, {$dispName}</h1>
        <div style="color:var(--text-secondary);font-size:14px;">Launch your assigned SAML 2.0 and OpenID Connect applications in one click.</div>
      </div>
      <div class="search-box">
        <span class="mi">search</span>
        <input id="app-search" type="text" placeholder="Filter applications…" />
      </div>
    </div>

    <div class="section">
      <h2>Assigned Applications</h2>
      <div class="grid" id="apps-grid">{$cardsHtml}</div>
    </div>

    <div class="section">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:14px;">
        <div>
          <h2 style="margin:0 0 3px;">macOS Touch ID &amp; Passkeys</h2>
          <div style="font-size:13px;color:var(--text-secondary);">Biometric hardware credentials bound to your directory profile</div>
        </div>
        <button class="btn" id="btn-add-passkey">
          <span class="mi" style="font-size:18px;">fingerprint</span>
          <span>Enroll Touch ID on This Mac</span>
        </button>
      </div>
      <div id="passkey-msg"></div>
      <div id="passkey-list"></div>
    </div>
  </div>

  <script>
    const PORTAL = {$portalCfg};
    document.getElementById('app-search').oninput = (e) => {
      const q = e.target.value.trim().toLowerCase();
      document.querySelectorAll('#apps-grid .app-tile').forEach(tile => {
        const hay = tile.getAttribute('data-search') || '';
        tile.style.display = (!q || hay.includes(q)) ? 'block' : 'none';
      });
    };
    const signOutEverywhere = document.getElementById('form-signout-everywhere');
    if (signOutEverywhere) {
      signOutEverywhere.onsubmit = (e) => {
        if (!confirm('Sign out of every browser and device, and revoke the access you granted to applications?')) {
          e.preventDefault();
        }
      };
    }

    function b64uToBytes(b64u) {
      let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      const bin = atob(b64);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      return arr;
    }
    function bytesToB64u(buf) {
      const bytes = new Uint8Array(buf);
      let bin = '';
      for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function renderCreds() {
      const el = document.getElementById('passkey-list');
      el.textContent = '';
      if (!PORTAL.credentials.length) {
        const empty = document.createElement('div');
        empty.style.cssText = 'color:var(--text-secondary);font-size:13.5px;padding:10px 0;';
        empty.textContent = 'No Touch ID Passkeys enrolled yet.';
        el.appendChild(empty);
        return;
      }
      PORTAL.credentials.forEach(c => {
        const row = document.createElement('div');
        row.style.cssText = 'padding:12px 15px;border:1px solid var(--border-hairline);background:var(--bg-subtle);border-radius:12px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;font-size:13.5px;';
        const left = document.createElement('div');
        left.style.cssText = 'display:flex;align-items:center;gap:9px;';
        const ico = document.createElement('span');
        ico.className = 'mi';
        ico.style.cssText = 'font-size:19px;color:#ec4899;';
        ico.textContent = 'fingerprint';
        const strong = document.createElement('strong');
        strong.textContent = c.friendly_name || 'macOS Touch ID';
        const rpSpan = document.createElement('span');
        rpSpan.className = 'mono';
        rpSpan.style.cssText = 'color:var(--text-secondary);font-size:12px;';
        rpSpan.textContent = '(' + (c.rp_id || '') + ')';
        left.appendChild(ico);
        left.appendChild(strong);
        left.appendChild(rpSpan);
        const right = document.createElement('div');
        right.style.cssText = 'color:var(--text-secondary);font-size:12px;';
        right.textContent = 'Enrolled ' + (c.created_at || '');
        row.appendChild(left);
        row.appendChild(right);
        el.appendChild(row);
      });
    }
    renderCreds();

    // Adding a passkey may require a recent sign-in: the server then answers 403 with a
    // reauth_url (on this IdP) that starts a fresh sign-in.
    function portalRequestError(j, fallback) {
      const err = new Error((j && j.error) || fallback);
      if (j && typeof j.reauth_url === 'string' && j.reauth_url.indexOf(PORTAL.issuerUrl + '/') === 0) {
        err.reauthUrl = j.reauth_url;
      }
      return err;
    }

    document.getElementById('btn-add-passkey').onclick = async () => {
      const msg = document.getElementById('passkey-msg');
      msg.textContent = '';
      try {
        const r1 = await fetch(PORTAL.issuerUrl + '/portal/webauthn/options', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': PORTAL.csrfToken},
          body: '{}'
        });
        const j1 = await r1.json();
        if (!r1.ok) throw portalRequestError(j1, 'Failed');
        const pk = j1.publicKey;
        pk.challenge = b64uToBytes(pk.challenge);
        pk.user.id = b64uToBytes(pk.user.id);
        if (Array.isArray(pk.excludeCredentials)) {
          pk.excludeCredentials = pk.excludeCredentials.map(c => ({ ...c, id: b64uToBytes(c.id) }));
        }
        const cred = await navigator.credentials.create({ publicKey: pk });
        const r2 = await fetch(PORTAL.issuerUrl + '/portal/webauthn/verify', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': PORTAL.csrfToken},
          body: JSON.stringify({
            friendlyName: 'macOS Touch ID',
            credential: {
              id: cred.id,
              rawId: bytesToB64u(cred.rawId),
              type: cred.type,
              response: {
                clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
                attestationObject: bytesToB64u(cred.response.attestationObject),
                transports: cred.response.getTransports ? cred.response.getTransports() : ['internal']
              }
            }
          })
        });
        const j2 = await r2.json();
        if (!r2.ok) throw portalRequestError(j2, 'Failed');
        location.reload();
      } catch (e) {
        const errDiv = document.createElement('div');
        errDiv.style.cssText = 'color:#ef4444;font-size:13px;margin-bottom:12px;';
        errDiv.textContent = e.message || String(e);
        if (e && e.reauthUrl) {
          errDiv.appendChild(document.createTextNode(' '));
          const link = document.createElement('a');
          link.href = e.reauthUrl;
          link.textContent = 'Sign in again';
          link.style.cssText = 'color:var(--accent);font-weight:600;';
          errDiv.appendChild(link);
        }
        msg.replaceChildren(errDiv);
      }
    };
  </script>
</body>
</html>
HTML;

    html_response(200, $html);
}

// ---------- Built-In SAML & OIDC Test Result Inspector Page ----------

function render_sso_inspector_result(
    string $title,
    string $subtitle,
    bool $ok,
    array $sections,
    string $portalUrl
): never {
    $assets = idp_ui_head_assets();
    $badgeBg = $ok ? "rgba(16, 185, 129, 0.16)" : "rgba(239, 68, 68, 0.16)";
    $badgeColor = $ok ? "#10b981" : "#ef4444";
    $badgeIcon = $ok ? "verified" : "error_outline";
    $badgeText = $ok ? "CRYPTOGRAPHICALLY VERIFIED" : "VERIFICATION FAILED";
    $escTitle = html_escape($title);
    $escSub = html_escape($subtitle);
    $escPortal = html_escape($portalUrl);

    $secHtml = "";
    foreach ($sections as $idx => $sec) {
        $secLabel = html_escape((string) ($sec["label"] ?? ""));
        $secContent = html_escape((string) ($sec["content"] ?? ""));
        $blockId = "code-sec-" . (int) $idx;
        $secHtml .= <<<SEC
        <div style="margin-bottom:22px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <div style="font-size:12.5px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-secondary);">{$secLabel}</div>
            <button type="button" class="copy-btn" data-target="{$blockId}" style="display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:7px;border:1px solid var(--border-hairline);background:var(--bg-subtle);color:var(--text-primary);font-size:12px;font-weight:600;cursor:pointer;">
              <span class="mi" style="font-size:14px;">content_copy</span><span>Copy</span>
            </button>
          </div>
          <pre style="margin:0;padding:16px;border-radius:13px;background:#0b1120;border:1px solid #1e293b;color:#e2e8f0;font-size:12.5px;line-height:1.55;overflow:auto;max-height:380px;white-space:pre-wrap;word-break:break-all;"><code id="{$blockId}">{$secContent}</code></pre>
        </div>
SEC;
    }

    $html = <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{$escTitle}</title>
  {$assets}
  <style>
    body { padding: 36px 20px 64px; }
    .wrap {
      max-width: 960px; margin: 0 auto; background: var(--bg-card);
      border-radius: 22px; border: 1px solid var(--border-hairline);
      padding: 32px 34px; box-shadow: var(--card-shadow);
    }
    .pill {
      display: inline-flex; align-items: center; gap: 6px;
      background: {$badgeBg}; color: {$badgeColor};
      font-weight: 800; font-size: 11px; padding: 5px 11px; border-radius: 999px; letter-spacing: 0.05em;
    }
  </style>
</head>
<body>
  <div class="wrap anim-up">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:16px;margin-bottom:26px;padding-bottom:20px;border-bottom:1px solid var(--border-hairline);">
      <div>
        <span class="pill"><span class="mi" style="font-size:15px;">{$badgeIcon}</span>{$badgeText}</span>
        <h1 style="margin:10px 0 4px;font-size:24px;font-weight:800;">{$escTitle}</h1>
        <div style="color:var(--text-secondary);font-size:14px;">{$escSub}</div>
      </div>
      <a href="{$escPortal}" style="display:inline-flex;align-items:center;gap:7px;padding:10px 16px;border-radius:10px;background:var(--accent);color:#fff;text-decoration:none;font-size:13.5px;font-weight:700;">
        <span class="mi" style="font-size:17px;">apps</span>
        <span>Open App Launchpad</span>
      </a>
    </div>
    {$secHtml}
  </div>
  <script>
    document.querySelectorAll('.copy-btn').forEach(btn => {
      btn.onclick = () => {
        const el = document.getElementById(btn.getAttribute('data-target'));
        if (!el) return;
        navigator.clipboard.writeText(el.textContent || '').then(() => {
          const span = btn.querySelector('span:last-child');
          span.textContent = 'Copied!';
          setTimeout(() => { span.textContent = 'Copy'; }, 1600);
        });
      };
    });
  </script>
</body>
</html>
HTML;

    html_response(200, $html);
}
