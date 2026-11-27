<?php
declare(strict_types=1);

// Protocol claims the IdP sets itself; directory attributes and client custom_claims
// can never supply them (this is the only protection legacy_token_claims keeps).
const OIDC_RESERVED_CLAIMS = [
    "iss" => true,
    "sub" => true,
    "aud" => true,
    "exp" => true,
    "nbf" => true,
    "iat" => true,
    "jti" => true,
    "amr" => true,
    "acr" => true,
    "azp" => true,
    "nonce" => true,
    "auth_time" => true,
    "client_id" => true,
    "at_hash" => true,
    "c_hash" => true,
    "s_hash" => true,
    "sid" => true,
];

// Reserved claims plus the standard claims released through scopes and the access
// token's scope: client custom_claims cannot override any of them (the secure
// default; see oidc_build_user_profile_claims()).
const OIDC_PROTECTED_CLAIMS = [
    "iss" => true,
    "sub" => true,
    "aud" => true,
    "exp" => true,
    "nbf" => true,
    "iat" => true,
    "jti" => true,
    "amr" => true,
    "acr" => true,
    "azp" => true,
    "nonce" => true,
    "auth_time" => true,
    "client_id" => true,
    "at_hash" => true,
    "c_hash" => true,
    "s_hash" => true,
    "sid" => true,
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

// Grant types a client can be registered for. "implicit" covers every response_type
// that returns tokens from the authorization endpoint (implicit and hybrid flows).
const OIDC_GRANT_TYPES = [
    "authorization_code",
    "implicit",
    "refresh_token",
    "client_credentials",
];
const OIDC_DEFAULT_GRANT_TYPES = ["authorization_code", "refresh_token"];

// Refresh tokens: each one is valid for 30 days after it was issued, and a token
// family (one authorization plus every rotation of its refresh token) ends 90 days
// after the user signed in, however often it is refreshed.
const OIDC_REFRESH_TOKEN_TTL = 30 * 86400;
const OIDC_REFRESH_FAMILY_MAX_LIFETIME = 90 * 86400;

// Client secrets are stored as a fast digest (machine_secret_hash()), so a secret
// chosen by an administrator must be long enough to resist guessing. Longer
// secrets than the maximum could never be verified (machine_secret_verify()).
const OIDC_CLIENT_SECRET_MIN_LENGTH = 32;
const OIDC_CLIENT_SECRET_MAX_LENGTH = 4096;

// A client secret still stored as a legacy password_hash() digest (bcrypt, slow by
// design) is checked only after one attempt was reserved in each of two budgets
// (rate_limit_hit(), see oidc_reserve_legacy_secret_check()). Both are keyed by the
// caller's network (client_ip_bucket()), never by the client alone: client_ids are
// public, so wrong secrets use up only the budgets of the networks they come from,
// and a correct secret sent from any other network is still checked.
//  - Per client and network, 10 checks per 5 minutes (then none for 5 minutes):
//    bounds online guessing of a weak legacy secret from one network.
//  - Per network across every provider and client, 20 checks per minute (then none
//    for a minute): bounds the bcrypt work one network can cause (X3-09).
// A correct secret clears its client's budget for its network but only gives back its
// own attempt in the per-network budget, so knowing one client's secret never resets
// what wrong secrets for other clients used up there. A refused request keeps no
// attempt in either budget.
const OIDC_LEGACY_SECRET_CLIENT_MAX_CHECKS = 10;
const OIDC_LEGACY_SECRET_CLIENT_WINDOW_SECONDS = 300;
const OIDC_LEGACY_SECRET_NETWORK_MAX_CHECKS = 20;
const OIDC_LEGACY_SECRET_NETWORK_WINDOW_SECONDS = 60;

// Expired codes and tokens deleted per table by one oidc_purge_expired() run, so a large
// backlog never holds the database write lock for long (as for sso_sessions, S12-11).
const OIDC_PURGE_BATCH_SIZE = 500;

// Accepted auth_policy values for a client. "inherit" applies the provider's
// default_auth_policy (resolved by effective_auth_policy()).
const OIDC_AUTH_POLICIES = ["inherit", "flexible", "touchid_only", "mfa"];

// Largest authorization request parameters accepted (bytes). They are stored in the sign-in
// transaction an unauthenticated request creates (S12-11). A valid code_challenge has at
// most 128 characters (RFC 7636 section 4.2).
const OIDC_AUTHORIZE_PARAM_MAX_BYTES = [
    "state" => 2048,
    "nonce" => 1024,
    "scope" => 1024,
    "prompt" => 64,
    "code_challenge" => 128,
    "code_challenge_method" => 16,
    "response_type" => 64,
    "response_mode" => 32,
    "max_age" => 16,
];

function send_oidc_cors_headers(): void
{
    if (!headers_sent()) {
        send_security_headers(false);
        header("Access-Control-Allow-Origin: *");
        header("Access-Control-Allow-Methods: GET, POST, OPTIONS");
        header("Access-Control-Allow-Headers: Authorization, Content-Type, Accept");
    }
}

function discovery_doc(array $prov, string $baseUrl): array
{
    $issuer = $baseUrl . "/" . $prov["idp_id"];
    $algs = [];
    foreach (filter_publishable_keys_for_provider($prov) as $k) {
        $alg = normalize_jwa_alg((string) ($k["alg"] ?? ""));
        if ($alg !== "" && !in_array($alg, $algs, true)) {
            $algs[] = $alg;
        }
    }
    if (!empty($prov["alg"])) {
        $provAlg = normalize_jwa_alg((string) $prov["alg"]);
        if ($provAlg !== "" && !in_array($provAlg, $algs, true)) {
            $algs[] = $provAlg;
        }
    }
    if (empty($algs)) {
        $algs = ["RS256"];
    }

    return [
        "issuer" => $issuer,
        "authorization_endpoint" => $issuer . "/oauth2/authorize",
        "token_endpoint" => $issuer . "/oauth2/token",
        "userinfo_endpoint" => $issuer . "/oauth2/userinfo",
        "end_session_endpoint" => $issuer . "/oauth2/logout",
        "jwks_uri" => $issuer . "/jwks",
        "saml_metadata_uri" => $issuer . "/saml/metadata",
        "saml_sso_endpoint" => $issuer . "/saml/sso",
        "scim_endpoint" => $issuer . "/scim/v2",
        // Response types that return an access token from /authorize ("token id_token")
        // only while the operator allows them (oidc_front_channel_access_tokens_allowed()).
        "response_types_supported" => oidc_front_channel_access_tokens_allowed()
            ? ["code", "id_token", "token id_token", "code id_token"]
            : ["code", "id_token", "code id_token"],
        "response_modes_supported" => ["query", "fragment", "form_post"],
        "grant_types_supported" => [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "implicit",
        ],
        "subject_types_supported" => ["public"],
        "id_token_signing_alg_values_supported" => array_values($algs),
        "token_endpoint_auth_methods_supported" => [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "code_challenge_methods_supported" => oidc_plain_pkce_allowed() ? ["S256", "plain"] : ["S256"],
        "scopes_supported" => [
            "openid",
            "profile",
            "email",
            "phone",
            "groups",
            "offline_access",
        ],
        "claims_supported" => [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "acr",
            "amr",
            "name",
            "given_name",
            "family_name",
            "preferred_username",
            "email",
            "email_verified",
            "phone_number",
            "groups",
        ],
    ];
}

// ---------- OIDC Storage ----------

/**
 * storage_db() plus this lane's additive migrations (schema_ensure()). Use it for
 * every OIDC table access. Migrations only run outside a transaction, and they are
 * applied once, by the first OIDC request after an upgrade; request handlers call
 * this before they open a transaction.
 */
function oidc_db(string $storePath): PDO
{
    $pdo = storage_db($storePath);
    if ($pdo->inTransaction()) {
        return $pdo;
    }
    try {
        schema_ensure($pdo, "oidc.tokens_v2", [
            // Refresh-token families: the original auth_time, an absolute family
            // expiry, consumed_at tombstones for reuse detection and the SSO session
            // binding (sid, a SHA-256 of the session id; see oidc_session_ref()).
            "ALTER TABLE oidc_tokens ADD COLUMN auth_time INTEGER",
            "ALTER TABLE oidc_tokens ADD COLUMN family_id TEXT",
            "ALTER TABLE oidc_tokens ADD COLUMN family_expires_at INTEGER",
            "ALTER TABLE oidc_tokens ADD COLUMN consumed_at INTEGER",
            "ALTER TABLE oidc_tokens ADD COLUMN sid TEXT",
            "CREATE INDEX IF NOT EXISTS idx_oidc_tokens_user ON oidc_tokens(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_oidc_tokens_family ON oidc_tokens(family_id)",
            "CREATE INDEX IF NOT EXISTS idx_oidc_tokens_expires ON oidc_tokens(expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_oidc_tokens_sid ON oidc_tokens(sid)",
            "ALTER TABLE oidc_auth_codes ADD COLUMN sid TEXT",
            // Existing codes were issued for an explicit redirect_uri as far as the
            // token endpoint is concerned, so they keep requiring it.
            "ALTER TABLE oidc_auth_codes ADD COLUMN redirect_uri_supplied INTEGER NOT NULL DEFAULT 1",
            "CREATE INDEX IF NOT EXISTS idx_oidc_auth_codes_expires ON oidc_auth_codes(expires_at)",
        ]);
        schema_ensure($pdo, "oidc.secret_previews_v1", [
            // Previews used to be the first 8 characters of the secret, which showed
            // most or all of a short admin-chosen secret to anyone who can read client
            // metadata. Existing previews keep only the "sec_" prefix of generated
            // secrets; new ones are built with secret_preview_mask().
            "UPDATE oidc_clients SET client_secret_preview = " .
                "CASE WHEN substr(client_secret_preview, 1, 4) = 'sec_' THEN 'sec_••••••••' ELSE '••••••••' END " .
                "WHERE client_secret_preview IS NOT NULL AND client_secret_preview != ''",
        ]);
    } catch (LogicException $e) {
        // Reached inside a caller's transaction that PDO did not report: the
        // migration runs on the next call made outside a transaction.
    }
    return $pdo;
}

function oidc_rollback_quietly(PDO $pdo): void
{
    try {
        $pdo->exec("ROLLBACK");
    } catch (Throwable $e) {
        // No transaction was open, or it is already gone.
    }
}

/**
 * Value stored in the sid columns for an SSO session id. The session id is the
 * SSO cookie value, a bearer secret, so only its SHA-256 is kept next to tokens.
 */
function oidc_session_ref(?string $ssoSessionId): ?string
{
    $sid = trim((string) $ssoSessionId);
    return $sid === "" ? null : hash("sha256", $sid);
}

/**
 * True while SSO session $ssoSessionId of $userId exists for $providerId and has not
 * expired. Call it in the write transaction that stores codes or tokens bound to the
 * session: the session's row is deleted in the same transaction that revokes or moves
 * what is bound to it (oidc_revoke_tokens_for_session(), oidc_rebind_session_tokens()),
 * so whatever is stored after this check is either revoked or moved with the session.
 */
function oidc_sso_session_live(
    PDO $pdo,
    string $providerId,
    string $ssoSessionId,
    string $userId
): bool {
    $sid = trim($ssoSessionId);
    if ($sid === "" || $userId === "") {
        return false;
    }
    $stmt = $pdo->prepare(
        "SELECT 1 FROM sso_sessions WHERE id = :id AND provider_id = :pid AND user_id = :uid " .
            "AND expires_at > :now LIMIT 1"
    );
    storage_execute($stmt, [
        ":id" => $sid,
        ":pid" => $providerId,
        ":uid" => $userId,
        ":now" => time(),
    ]);
    $live = $stmt->fetchColumn() !== false;
    $stmt->closeCursor();
    return $live;
}

function oidc_scope_list(string $scope): array
{
    $parts = preg_split('/\s+/', trim($scope), -1, PREG_SPLIT_NO_EMPTY);
    return is_array($parts) ? $parts : [];
}

/**
 * legacy_token_claims (env OIDC_LEGACY_TOKEN_CLAIMS, default off): restores the old
 * token contents (full profile for scope=openid, custom attributes, identity claims
 * in access tokens with typ JWT and aud = client_id). Read on every call.
 */
function oidc_legacy_token_claims(): bool
{
    return config_flag("legacy_token_claims", "OIDC_LEGACY_TOKEN_CLAIMS");
}

/**
 * legacy_oauth_flows (env OIDC_LEGACY_OAUTH_FLOWS, default off): restores the old
 * leniency (registered grant_types not enforced, "plain" PKCE for every client, a
 * code_verifier without a stored challenge ignored). Read on every call.
 */
function oidc_legacy_oauth_flows(): bool
{
    return config_flag("legacy_oauth_flows", "OIDC_LEGACY_OAUTH_FLOWS");
}

/**
 * Whether code_challenge_method=plain is accepted from confidential clients that do not
 * require PKCE: legacy_pkce_plain (env OIDC_LEGACY_PKCE_PLAIN, default off) or
 * legacy_oauth_flows. Otherwise every client must use S256 (OAuth 2.1, RFC 9700 section
 * 2.1.1); public and require_pkce clients need S256 even with the flag. Read on every call.
 */
function oidc_plain_pkce_allowed(): bool
{
    return config_flag("legacy_pkce_plain", "OIDC_LEGACY_PKCE_PLAIN") || oidc_legacy_oauth_flows();
}

/**
 * Whether response types that return an access token from the authorization endpoint
 * ("token id_token", "id_token token") are accepted: legacy_implicit_access_tokens (env
 * OIDC_LEGACY_IMPLICIT_ACCESS_TOKENS, default off) or legacy_oauth_flows. Otherwise access
 * tokens come only from the token endpoint (OAuth 2.1, RFC 9700 section 2.1.2), and the
 * implicit grant type allows "id_token" and "code id_token". Read on every call.
 */
function oidc_front_channel_access_tokens_allowed(): bool
{
    return config_flag("legacy_implicit_access_tokens", "OIDC_LEGACY_IMPLICIT_ACCESS_TOKENS") ||
        oidc_legacy_oauth_flows();
}

/**
 * Whether the client is registered for a grant type (see OIDC_GRANT_TYPES).
 * legacy_oauth_flows allows every grant type to every client again.
 */
function oidc_client_has_grant(array $client, string $grantType): bool
{
    return in_array($grantType, (array) ($client["grant_types"] ?? []), true) ||
        oidc_legacy_oauth_flows();
}

/**
 * Registered grant types needed for a response_type at the authorization endpoint:
 * "code" needs authorization_code, and any response_type that returns token or
 * id_token from the authorization endpoint (implicit or hybrid) needs implicit. A
 * response_type with "token" is refused first unless
 * oidc_front_channel_access_tokens_allowed(). Throws InvalidArgumentException
 * (unsupported_response_type or unauthorized_client).
 */
function oidc_assert_response_type_allowed(array $client, string $responseType): void
{
    $parts = oidc_scope_list($responseType);
    if (in_array("token", $parts, true) && !oidc_front_channel_access_tokens_allowed()) {
        throw new InvalidArgumentException(
            "unsupported_response_type: response_type \"" .
                trim($responseType) .
                "\" returns an access token from the authorization endpoint, which this server does not do. " .
                "Use response_type=code and get tokens from the token endpoint"
        );
    }
    $needed = [];
    if (in_array("code", $parts, true)) {
        $needed[] = "authorization_code";
    }
    if (in_array("token", $parts, true) || in_array("id_token", $parts, true)) {
        $needed[] = "implicit";
    }
    foreach ($needed as $grantType) {
        if (!oidc_client_has_grant($client, $grantType)) {
            throw new InvalidArgumentException(
                "unauthorized_client: response_type \"" .
                    trim($responseType) .
                    "\" needs the \"$grantType\" grant type, which is not enabled for this client"
            );
        }
    }
}

/**
 * Normalizes a client's grant_types on save. Omitted or empty means
 * OIDC_DEFAULT_GRANT_TYPES. When the list was sent ($validate), every value must be
 * in OIDC_GRANT_TYPES and a public client cannot have client_credentials; a stored
 * list is kept as is, except that client_credentials is dropped when the client
 * becomes public.
 */
function oidc_normalize_grant_types(mixed $value, bool $isPublic, bool $validate): array
{
    if (is_string($value)) {
        // "authorization_code refresh_token" or a comma-separated list.
        $value = preg_split('/[\s,]+/', $value, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }
    $grantTypes = normalize_string_list($value ?? OIDC_DEFAULT_GRANT_TYPES);
    if ($grantTypes === []) {
        $grantTypes = OIDC_DEFAULT_GRANT_TYPES;
    }
    if ($validate) {
        foreach ($grantTypes as $grantType) {
            if (!in_array($grantType, OIDC_GRANT_TYPES, true)) {
                throw new InvalidArgumentException(
                    "Unsupported grant type \"$grantType\": use authorization_code, implicit, refresh_token or client_credentials"
                );
            }
        }
        if ($isPublic && in_array("client_credentials", $grantTypes, true)) {
            throw new InvalidArgumentException(
                "Public clients cannot use the client_credentials grant"
            );
        }
        return $grantTypes;
    }
    if ($isPublic) {
        $grantTypes = array_values(array_diff($grantTypes, ["client_credentials"]));
        if ($grantTypes === []) {
            $grantTypes = OIDC_DEFAULT_GRANT_TYPES;
        }
    }
    return $grantTypes;
}

// ---------- OIDC Client Persistence ----------

function hydrate_oidc_client_row(array $r): array
{
    $grantTypes = json_decode((string) ($r["grant_types_json"] ?? "[]"), true);
    $grantTypes = is_array($grantTypes)
        ? array_values(array_filter($grantTypes, "is_string"))
        : [];
    return [
        "id" => (string) $r["id"],
        "provider_id" => (string) $r["provider_id"],
        "name" => (string) $r["name"],
        "client_id" => (string) $r["client_id"],
        "is_public" => empty($r["client_secret_hash"]),
        "client_secret_preview" => (string) ($r["client_secret_preview"] ?? ""),
        "redirect_uris" =>
            json_decode((string) ($r["redirect_uris_json"] ?? "[]"), true) ?: [],
        "post_logout_redirect_uris" =>
            json_decode(
                (string) ($r["post_logout_redirect_uris_json"] ?? "[]"),
                true
            ) ?: [],
        "grant_types" => $grantTypes ?: OIDC_DEFAULT_GRANT_TYPES,
        "require_pkce" => (int) ($r["require_pkce"] ?? 0) === 1,
        "auth_policy" => (string) ($r["auth_policy"] ?? "flexible"),
        "login_uri" => (string) ($r["login_uri"] ?? ""),
        "custom_claims" =>
            json_decode((string) ($r["custom_claims_json"] ?? "{}"), true) ?: [],
        "assigned_groups" =>
            json_decode((string) ($r["assigned_groups_json"] ?? "[]"), true) ?:
            [],
        "access_token_ttl" => (int) ($r["access_token_ttl"] ?? 3600),
        "created_at" => $r["created_at"] ?? null,
    ];
}

function oidc_list_clients(string $storePath, string $providerId): array
{
    $pdo = oidc_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM oidc_clients WHERE provider_id = :pid ORDER BY created_at DESC"
    );
    $stmt->execute([":pid" => $providerId]);
    $out = [];
    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $out[] = hydrate_oidc_client_row($r);
    }
    return $out;
}

function oidc_get_client(
    string $storePath,
    string $providerId,
    string $id
): ?array {
    $pdo = oidc_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM oidc_clients WHERE id = :id AND provider_id = :pid LIMIT 1"
    );
    $stmt->execute([":id" => $id, ":pid" => $providerId]);
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    return $r ? hydrate_oidc_client_row($r) : null;
}

function oidc_find_client_by_client_id(
    string $storePath,
    string $providerId,
    string $clientId
): ?array {
    $pdo = oidc_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM oidc_clients WHERE provider_id = :pid AND client_id = :cid LIMIT 1"
    );
    $stmt->execute([":pid" => $providerId, ":cid" => trim($clientId)]);
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$r) {
        return null;
    }
    $c = hydrate_oidc_client_row($r);
    $c["_client_secret_hash"] = $r["client_secret_hash"] ?? null;
    return $c;
}

function oidc_resolve_client(
    string $storePath,
    string $providerId,
    string $idOrClientId
): ?array {
    $byUuid = oidc_get_client($storePath, $providerId, $idOrClientId);
    if ($byUuid) {
        return $byUuid;
    }
    $byCid = oidc_find_client_by_client_id(
        $storePath,
        $providerId,
        $idOrClientId
    );
    if ($byCid) {
        unset($byCid["_client_secret_hash"]);
        return $byCid;
    }
    return null;
}

/**
 * Validates an auth_policy value sent by a caller. null or "" means "inherit"
 * (the provider default); any value outside OIDC_AUTH_POLICIES is rejected
 * instead of being replaced by a weaker policy.
 */
function oidc_normalize_auth_policy(mixed $value): string
{
    if ($value === null) {
        return "inherit";
    }
    if (!is_string($value)) {
        throw new InvalidArgumentException(
            "Invalid auth_policy: use inherit, flexible, touchid_only or mfa"
        );
    }
    $policy = trim($value);
    if ($policy === "") {
        return "inherit";
    }
    if (!in_array($policy, OIDC_AUTH_POLICIES, true)) {
        throw new InvalidArgumentException(
            "Invalid auth_policy: use inherit, flexible, touchid_only or mfa"
        );
    }
    return $policy;
}

/**
 * client_id is unique per provider (S03-14). Refuses one that another client of the provider
 * ($id is the client being saved) already uses, with a plain error instead of the database
 * constraint message. The exception code is 409 so the admin API can answer 409 Conflict.
 */
function oidc_assert_client_id_available(
    PDO $pdo,
    string $providerId,
    string $clientId,
    string $id
): void {
    $stmt = $pdo->prepare(
        "SELECT 1 FROM oidc_clients WHERE provider_id = :pid AND client_id = :cid AND id != :id LIMIT 1"
    );
    $stmt->execute([":pid" => $providerId, ":cid" => $clientId, ":id" => $id]);
    $taken = $stmt->fetchColumn() !== false;
    $stmt->closeCursor();
    if ($taken) {
        throw new RuntimeException("client_id already exists on this provider", 409);
    }
}

/**
 * client_ids starting with "builtin-" are reserved for clients the IdP creates itself. The
 * only one that may be saved is this provider's own playground client,
 * "builtin-oidc-playground-{idp_id}" (S03-14).
 */
function oidc_assert_client_id_not_reserved(PDO $pdo, string $providerId, string $clientId): void
{
    if (!str_starts_with(strtolower($clientId), "builtin-")) {
        return;
    }
    $stmt = $pdo->prepare("SELECT idp_id FROM providers WHERE id = :id LIMIT 1");
    $stmt->execute([":id" => $providerId]);
    $idpId = $stmt->fetchColumn();
    $stmt->closeCursor();
    if (!is_string($idpId) || $clientId !== "builtin-oidc-playground-" . $idpId) {
        throw new InvalidArgumentException(
            "client_id values starting with \"builtin-\" are reserved for clients the identity provider creates"
        );
    }
}

/**
 * $e, or a plain RuntimeException with code 409 (as in oidc_assert_client_id_available) when
 * it is the database's unique-client_id constraint (a concurrent save took the client_id), so
 * the raw constraint message is never shown.
 */
function oidc_client_id_conflict_error(Throwable $e): Throwable
{
    if (
        $e instanceof PDOException &&
        str_contains($e->getMessage(), "UNIQUE constraint failed") &&
        str_contains($e->getMessage(), "client_id")
    ) {
        return new RuntimeException("client_id already exists on this provider", 409, $e);
    }
    return $e;
}

function oidc_save_client(
    string $storePath,
    string $providerId,
    array $input,
    ?string $existingId = null
): array {
    // On update the request is merged over the stored client. Only the fields the
    // caller sends are validated again, so a stored value that predates a stricter
    // rule cannot block an unrelated change such as a secret rotation (stored
    // redirect URIs are checked again at request time).
    $sentFields = $input;
    if ($existingId !== null) {
        $existingClient = oidc_get_client($storePath, $providerId, $existingId);
        if (!$existingClient) {
            throw new RuntimeException("OIDC client not found");
        }
        $input = array_merge($existingClient, $input);
    }
    $isUpdate = $existingId !== null;
    $mustValidate = static fn (string $key): bool => !$isUpdate || array_key_exists($key, $sentFields);

    $name = trim((string) ($input["name"] ?? ""));
    if ($name === "") {
        throw new InvalidArgumentException("Client application name is required");
    }

    // Redirect, post-logout and initiate-login URIs receive bearer artifacts: no
    // fragment, and https unless loopback (validate_endpoint_url()).
    $redirectUris = [];
    foreach (normalize_string_list($input["redirect_uris"] ?? []) as $ru) {
        $redirectUris[] = $mustValidate("redirect_uris")
            ? validate_endpoint_url($ru, true, "Redirect URI")
            : $ru;
    }

    $postLogoutUris = [];
    foreach (normalize_string_list($input["post_logout_redirect_uris"] ?? []) as $plu) {
        $postLogoutUris[] = $mustValidate("post_logout_redirect_uris")
            ? validate_endpoint_url($plu, true, "Post-Logout Redirect URI")
            : $plu;
    }

    $loginUri = trim((string) ($input["login_uri"] ?? ""));
    if ($loginUri !== "" && $mustValidate("login_uri")) {
        $loginUri = validate_endpoint_url($loginUri, false, "Initiate Login URI");
    }

    $isPublic = !empty($input["is_public"]);
    // grant_types decide which flows the client may use; they are enforced at
    // /authorize and /token unless legacy_oauth_flows is on.
    $grantTypes = oidc_normalize_grant_types(
        $input["grant_types"] ?? null,
        $isPublic,
        $mustValidate("grant_types")
    );
    // An omitted require_pkce means true on create (the documented API default) and
    // keeps the stored value on update. Public clients always require PKCE.
    $requirePkce = $isPublic || !empty($input["require_pkce"] ?? true);
    // Closed enum: an unknown value is a 400, never a silent "flexible". Omitted on
    // create means "inherit"; omitted on update keeps the stored value.
    $authPolicy = $mustValidate("auth_policy")
        ? oidc_normalize_auth_policy($sentFields["auth_policy"] ?? null)
        : (string) ($input["auth_policy"] ?? "inherit");

    $customClaims =
        isset($input["custom_claims"]) && is_array($input["custom_claims"])
            ? $input["custom_claims"]
            : [];
    $assignedGroups = normalize_string_list($input["assigned_groups"] ?? []);
    // A TTL the caller sends must parse (S13-11): "1.5h" or a typo is a 400, never a silent
    // one hour. Seconds or durations such as "15m", "1h" or "1d", at most 365 days, at least
    // 60 seconds; omitted or empty means 3600. A stored value is kept as it is on update.
    $ttlSpec = $input["access_token_ttl"] ?? null;
    if ($ttlSpec === null || (is_string($ttlSpec) && trim($ttlSpec) === "")) {
        $ttlSpec = 3600;
    }
    $ttlSeconds = parse_duration_seconds($ttlSpec);
    if ($ttlSeconds === null) {
        if ($mustValidate("access_token_ttl")) {
            throw new InvalidArgumentException(
                "Invalid access_token_ttl: use a number of seconds or a duration such as 15m, 1h or 1d (at most 365 days)"
            );
        }
        $ttlSeconds = parse_validity_to_seconds($ttlSpec);
    }
    $ttl = max(60, $ttlSeconds);

    $pdo = oidc_db($storePath);
    $id = $existingId ?: uuidv4();
    $now = gmdate("Y-m-d\TH:i:s\Z");
    $issuedSecretOnce = null;

    if ($existingId !== null) {
        $pdo->exec("BEGIN IMMEDIATE");
        try {
            $stmt = $pdo->prepare(
                "SELECT * FROM oidc_clients WHERE id = :id AND provider_id = :pid LIMIT 1"
            );
            $stmt->execute([":id" => $existingId, ":pid" => $providerId]);
            $prev = $stmt->fetch(PDO::FETCH_ASSOC);
            $stmt->closeCursor();
            if (!$prev) {
                throw new RuntimeException("OIDC client not found");
            }
            $prevClientId = (string) $prev["client_id"];
            $clientId =
                isset($input["client_id"]) && trim((string) $input["client_id"]) !== ""
                    ? trim((string) $input["client_id"])
                    : $prevClientId;
            if ($clientId !== $prevClientId) {
                oidc_assert_client_id_not_reserved($pdo, $providerId, $clientId);
                oidc_assert_client_id_available($pdo, $providerId, $clientId, $existingId);
            }

            if ($isPublic) {
                $secretHash = null;
                $secretPreview = null;
            } elseif (!empty($input["rotate_secret"]) || empty($prev["client_secret_hash"])) {
                $issuedSecretOnce = "sec_" . base64url_encode(random_bytes(24));
                $secretHash = machine_secret_hash($issuedSecretOnce);
                $secretPreview = "sec_" . secret_preview_mask($issuedSecretOnce);
            } else {
                $secretHash = $prev["client_secret_hash"];
                $secretPreview = $prev["client_secret_preview"] ?? "sec_••••••••";
            }

            $upd = $pdo->prepare(
                "UPDATE oidc_clients SET " .
                    "name = :name, client_id = :cid, client_secret_hash = :sh, client_secret_preview = :sprev, " .
                    "redirect_uris_json = :ru, post_logout_redirect_uris_json = :plu, grant_types_json = :gt, " .
                    "require_pkce = :pkce, auth_policy = :pol, login_uri = :luri, custom_claims_json = :cc, " .
                    "assigned_groups_json = :grp, access_token_ttl = :ttl " .
                    "WHERE id = :id AND provider_id = :pid"
            );
            $upd->execute([
                ":name" => $name,
                ":cid" => $clientId,
                ":sh" => $secretHash,
                ":sprev" => $secretPreview,
                ":ru" => json_encode($redirectUris, JSON_UNESCAPED_SLASHES),
                ":plu" => json_encode($postLogoutUris, JSON_UNESCAPED_SLASHES),
                ":gt" => json_encode($grantTypes, JSON_UNESCAPED_SLASHES),
                ":pkce" => $requirePkce ? 1 : 0,
                ":pol" => $authPolicy,
                ":luri" => $loginUri,
                ":cc" => json_encode($customClaims, JSON_UNESCAPED_SLASHES),
                ":grp" => json_encode($assignedGroups, JSON_UNESCAPED_SLASHES),
                ":ttl" => $ttl,
                ":id" => $existingId,
                ":pid" => $providerId,
            ]);

            // Tokens and codes are bound to the client_id they were issued to. When it
            // changes they are revoked, so a client created later with the old
            // client_id cannot inherit them; when a confidential client becomes
            // public, its refresh tokens would otherwise be redeemable without a
            // secret.
            if (
                $clientId !== $prevClientId ||
                ($isPublic && !empty($prev["client_secret_hash"]))
            ) {
                oidc_delete_client_grants($pdo, $providerId, $prevClientId);
            }
            $pdo->exec("COMMIT");
        } catch (Throwable $e) {
            oidc_rollback_quietly($pdo);
            throw oidc_client_id_conflict_error($e);
        }
    } else {
        $suppliedClientId = trim((string) ($input["client_id"] ?? ""));
        if ($suppliedClientId !== "") {
            oidc_assert_client_id_not_reserved($pdo, $providerId, $suppliedClientId);
        }
        $clientId = $suppliedClientId !== "" ? $suppliedClientId : "0oa" . bin2hex(random_bytes(10));
        oidc_assert_client_id_available($pdo, $providerId, $clientId, $id);
        if ($isPublic) {
            $secretHash = null;
            $secretPreview = null;
        } else {
            $suppliedSecret = trim((string) ($input["client_secret"] ?? ""));
            if ($suppliedSecret !== "") {
                $secretLength = strlen($suppliedSecret);
                if (
                    $secretLength < OIDC_CLIENT_SECRET_MIN_LENGTH ||
                    $secretLength > OIDC_CLIENT_SECRET_MAX_LENGTH
                ) {
                    throw new InvalidArgumentException(
                        "client_secret must be " .
                            OIDC_CLIENT_SECRET_MIN_LENGTH .
                            " to " .
                            OIDC_CLIENT_SECRET_MAX_LENGTH .
                            " characters long; omit it to have a strong secret generated"
                    );
                }
                $issuedSecretOnce = $suppliedSecret;
                // Never derived from the start of an admin-chosen secret.
                $secretPreview = secret_preview_mask($suppliedSecret);
            } else {
                $issuedSecretOnce = "sec_" . base64url_encode(random_bytes(24));
                $secretPreview = "sec_" . secret_preview_mask($issuedSecretOnce);
            }
            // High-entropy machine secret: one SHA-256 to verify instead of bcrypt,
            // so the public token endpoint cannot be used to burn CPU.
            $secretHash = machine_secret_hash($issuedSecretOnce);
        }

        $ins = $pdo->prepare(
            "INSERT INTO oidc_clients (" .
                "id, provider_id, name, client_id, client_secret_hash, client_secret_preview, " .
                "redirect_uris_json, post_logout_redirect_uris_json, grant_types_json, require_pkce, " .
                "auth_policy, login_uri, custom_claims_json, assigned_groups_json, access_token_ttl, created_at" .
            ") VALUES (" .
                ":id, :pid, :name, :cid, :sh, :sprev, :ru, :plu, :gt, :pkce, :pol, :luri, :cc, :grp, :ttl, :cat" .
            ")"
        );
        try {
            $ins->execute([
                ":id" => $id,
                ":pid" => $providerId,
                ":name" => $name,
                ":cid" => $clientId,
                ":sh" => $secretHash,
                ":sprev" => $secretPreview,
                ":ru" => json_encode($redirectUris, JSON_UNESCAPED_SLASHES),
                ":plu" => json_encode($postLogoutUris, JSON_UNESCAPED_SLASHES),
                ":gt" => json_encode($grantTypes, JSON_UNESCAPED_SLASHES),
                ":pkce" => $requirePkce ? 1 : 0,
                ":pol" => $authPolicy,
                ":luri" => $loginUri,
                ":cc" => json_encode($customClaims, JSON_UNESCAPED_SLASHES),
                ":grp" => json_encode($assignedGroups, JSON_UNESCAPED_SLASHES),
                ":ttl" => $ttl,
                ":cat" => $now,
            ]);
        } catch (Throwable $e) {
            // A concurrent save took the client_id between the check and the insert.
            throw oidc_client_id_conflict_error($e);
        }
    }

    $saved = oidc_get_client($storePath, $providerId, $id) ?? [];
    if ($issuedSecretOnce !== null) {
        // Returned ONLY once upon creation or explicit rotation!
        $saved["client_secret"] = $issuedSecretOnce;
    }
    return $saved;
}

function oidc_delete_client(
    string $storePath,
    string $providerId,
    string $id
): bool {
    $pdo = oidc_db($storePath);
    $pdo->exec("BEGIN IMMEDIATE");
    try {
        $sel = $pdo->prepare(
            "SELECT client_id FROM oidc_clients WHERE id = :id AND provider_id = :pid LIMIT 1"
        );
        $sel->execute([":id" => $id, ":pid" => $providerId]);
        $clientId = $sel->fetchColumn();
        $sel->closeCursor();

        $stmt = $pdo->prepare(
            "DELETE FROM oidc_clients WHERE id = :id AND provider_id = :pid"
        );
        $stmt->execute([":id" => $id, ":pid" => $providerId]);
        $deleted = $stmt->rowCount() > 0;

        if ($deleted && is_string($clientId) && $clientId !== "") {
            // Tokens and codes end with their client, so creating a client with the
            // same client_id later cannot bring them back.
            oidc_delete_client_grants($pdo, $providerId, $clientId);
        }
        $pdo->exec("COMMIT");
        return $deleted;
    } catch (Throwable $e) {
        oidc_rollback_quietly($pdo);
        throw $e;
    }
}

/**
 * Deletes every token (access, refresh and consumed refresh tombstones) and every
 * unredeemed authorization code issued to a client_id. Runs in the caller's
 * transaction; errors are thrown.
 */
function oidc_delete_client_grants(PDO $pdo, string $providerId, string $clientId): void
{
    $args = [":pid" => $providerId, ":cid" => $clientId];
    $pdo->prepare(
        "DELETE FROM oidc_tokens WHERE provider_id = :pid AND client_id = :cid"
    )->execute($args);
    $pdo->prepare(
        "DELETE FROM oidc_auth_codes WHERE provider_id = :pid AND client_id = :cid"
    )->execute($args);
}

// ---------- OIDC Claims & Protocol Logic ----------

/**
 * The OIDC subject. It is the user's immutable "subject" attribute (users created
 * before it existed keep their email there, so existing RP bindings survive); the
 * email/username fallback only applies to user records that do not carry it.
 */
function oidc_subject_for_user(array $user): string
{
    $subject = (string) ($user["subject"] ?? "");
    if ($subject !== "") {
        return $subject;
    }
    $email = (string) ($user["email"] ?? "");
    return $email !== "" ? $email : (string) ($user["username"] ?? "");
}

/**
 * User claims for ID tokens and userinfo. Only the granted scopes release claims:
 * openid gives sub; profile gives name, given_name, family_name and
 * preferred_username; email gives email and email_verified (the stored per-user
 * flag); phone gives phone_number; groups gives groups. Custom directory attributes
 * are never copied. The client's custom_claims are added but cannot override any
 * claim in OIDC_PROTECTED_CLAIMS. legacy_token_claims restores the old claim set
 * (oidc_build_legacy_profile_claims()).
 */
function oidc_build_user_profile_claims(
    array $user,
    string $scopeStr,
    array $clientCustomClaims = []
): array {
    if (oidc_legacy_token_claims()) {
        return oidc_build_legacy_profile_claims($user, $scopeStr, $clientCustomClaims);
    }
    $scopes = oidc_scope_list($scopeStr);
    $claims = ["sub" => oidc_subject_for_user($user)];

    if (in_array("profile", $scopes, true)) {
        $profileFields = [
            "name" => "display_name",
            "given_name" => "given_name",
            "family_name" => "family_name",
            "preferred_username" => "username",
        ];
        foreach ($profileFields as $claim => $field) {
            $value = (string) ($user[$field] ?? "");
            if ($value !== "") {
                $claims[$claim] = $value;
            }
        }
    }
    if (in_array("email", $scopes, true)) {
        $email = (string) ($user["email"] ?? "");
        if ($email !== "") {
            $claims["email"] = $email;
            $claims["email_verified"] = !empty($user["email_verified"] ?? true);
        }
    }
    if (in_array("phone", $scopes, true)) {
        $phone = (string) ($user["mobile_phone"] ?? "");
        if ($phone !== "") {
            $claims["phone_number"] = $phone;
        }
    }
    if (in_array("groups", $scopes, true)) {
        $claims["groups"] = array_values(
            array_filter((array) ($user["groups"] ?? []), "is_string")
        );
    }

    return $claims + oidc_filter_custom_claims($clientCustomClaims, OIDC_PROTECTED_CLAIMS);
}

/**
 * The claim set issued before scopes were honored (legacy_token_claims): scope=openid
 * alone releases the full profile, email and groups, preferred_username is always
 * present, email_verified is always true, every custom directory attribute is copied
 * and client custom_claims may override standard claims. Only OIDC_RESERVED_CLAIMS
 * are protected.
 */
function oidc_build_legacy_profile_claims(
    array $user,
    string $scopeStr,
    array $clientCustomClaims = []
): array {
    $scopes = preg_split('/\s+/', trim($scopeStr)) ?: ["openid"];
    $includeAll = count($scopes) <= 1 && ($scopes[0] ?? "") === "openid";

    $claims = [
        "sub" => oidc_subject_for_user($user),
        "preferred_username" => $user["username"],
    ];

    if ($includeAll || in_array("profile", $scopes, true)) {
        $claims["name"] = $user["display_name"];
        if ($user["given_name"] !== "") {
            $claims["given_name"] = $user["given_name"];
        }
        if ($user["family_name"] !== "") {
            $claims["family_name"] = $user["family_name"];
        }
    }
    if ($includeAll || in_array("email", $scopes, true)) {
        $claims["email"] = $user["email"];
        $claims["email_verified"] = true;
    }
    if (in_array("phone", $scopes, true) && $user["mobile_phone"] !== "") {
        $claims["phone_number"] = $user["mobile_phone"];
    }
    if ($includeAll || in_array("groups", $scopes, true)) {
        $claims["groups"] = $user["groups"] ?? [];
    }

    foreach ($user["attributes"] ?? [] as $k => $v) {
        if (
            is_string($k) &&
            !isset(OIDC_RESERVED_CLAIMS[$k]) &&
            !isset($claims[$k])
        ) {
            $claims[$k] = $v;
        }
    }

    foreach ($clientCustomClaims as $k => $v) {
        if (is_string($k) && !isset(OIDC_RESERVED_CLAIMS[$k])) {
            $claims[$k] = $v;
        }
    }

    return $claims;
}

/**
 * A client's custom_claims without the claim names in $protected (a set such as
 * OIDC_PROTECTED_CLAIMS).
 */
function oidc_filter_custom_claims(array $customClaims, array $protected): array
{
    $out = [];
    foreach ($customClaims as $k => $v) {
        if (is_string($k) && $k !== "" && !isset($protected[$k])) {
            $out[$k] = $v;
        }
    }
    return $out;
}

/**
 * at_hash / c_hash value (OIDC Core sections 3.1.3.6 and 3.3.2.11): base64url of the
 * left half of the hash of the ASCII value, using the hash of the ID token's JWS
 * alg: SHA-256, SHA-384 or SHA-512 for the 256, 384 and 512 variants, and SHA-512
 * for EdDSA (Ed25519).
 */
function oidc_token_hash_claim(string $value, string $alg): string
{
    $alg = normalize_jwa_alg($alg);
    if ($alg === "EdDSA" || str_ends_with($alg, "512")) {
        $hashAlg = "sha512";
    } elseif (str_ends_with($alg, "384")) {
        $hashAlg = "sha384";
    } else {
        $hashAlg = "sha256";
    }
    $digest = hash($hashAlg, $value, true);
    return base64url_encode(substr($digest, 0, intdiv(strlen($digest), 2)));
}

function oidc_acr_from_amr(array $amr): string
{
    if (
        in_array("mfa", $amr, true) ||
        (in_array("pwd", $amr, true) && in_array("hwk", $amr, true))
    ) {
        return "urn:idp:acr:mfa";
    }
    if (in_array("hwk", $amr, true)) {
        return "urn:idp:acr:phishing-resistant";
    }
    return "urn:idp:acr:1fa";
}

// ---------- Redirect URIs ----------

/**
 * RFC 8252 section 7.3: an http redirect URI registered on the loopback IP literal
 * 127.0.0.1 or [::1] also matches a requested URI that differs only in its port,
 * because native apps listen on an ephemeral port. Scheme, host, path and query
 * must be identical. "localhost" gets no such leniency (RFC 8252 section 8.3).
 */
function oidc_loopback_redirect_matches(string $registered, string $requested): bool
{
    if (
        str_contains($registered, "#") ||
        str_contains($requested, "#") ||
        str_contains($requested, "\\")
    ) {
        return false;
    }
    $reg = parse_url($registered);
    $req = parse_url($requested);
    if (!is_array($reg) || !is_array($req)) {
        return false;
    }
    foreach ([$reg, $req] as $parts) {
        if (
            strtolower((string) ($parts["scheme"] ?? "")) !== "http" ||
            isset($parts["user"]) ||
            isset($parts["pass"])
        ) {
            return false;
        }
    }
    $host = strtolower((string) ($reg["host"] ?? ""));
    return in_array($host, ["127.0.0.1", "[::1]"], true) &&
        strtolower((string) ($req["host"] ?? "")) === $host &&
        (string) ($reg["path"] ?? "") === (string) ($req["path"] ?? "") &&
        ($reg["query"] ?? null) === ($req["query"] ?? null);
}

/**
 * Request-time redirect_uri check, run at /authorize and again right before the
 * authorization response is sent. The URI must be registered for the client,
 * either exactly or as an RFC 8252 loopback match that differs only in the port.
 * A loopback match is accepted only with response_type=code and, for public
 * clients, PKCE with S256 (RFC 8252 section 8.1). The URI must also pass
 * validate_endpoint_url(): no fragment, and https unless it is loopback or
 * allow_insecure_http_endpoints is on. Returns the URI exactly as requested, which
 * is what the code stores and the token endpoint compares. Throws
 * InvalidArgumentException.
 */
function oidc_check_redirect_uri(
    array $client,
    string $requested,
    string $responseType = "code",
    string $codeChallenge = "",
    string $codeChallengeMethod = ""
): string {
    if ($requested === "") {
        throw new InvalidArgumentException("Invalid or unregistered redirect_uri");
    }
    $registered = array_values(
        array_filter((array) ($client["redirect_uris"] ?? []), "is_string")
    );
    if (!in_array($requested, $registered, true)) {
        $loopbackMatch = false;
        foreach ($registered as $candidate) {
            if (oidc_loopback_redirect_matches($candidate, $requested)) {
                $loopbackMatch = true;
                break;
            }
        }
        if (!$loopbackMatch) {
            throw new InvalidArgumentException(
                "Invalid or unregistered redirect_uri"
            );
        }
        if (trim($responseType) !== "code") {
            throw new InvalidArgumentException(
                "A loopback redirect_uri on a different port is only accepted with response_type=code"
            );
        }
        if (
            !empty($client["is_public"]) &&
            ($codeChallenge === "" || $codeChallengeMethod !== "S256")
        ) {
            throw new InvalidArgumentException(
                "A loopback redirect_uri on a different port requires PKCE with code_challenge_method=S256"
            );
        }
    }
    return validate_endpoint_url($requested, true, "redirect_uri");
}

/**
 * Adds response parameters to a redirect URI. Mode "query" merges them into the
 * query component: the URI's own query is kept (RFC 6749 section 3.1.2) except
 * for parameters the response sets, so none appears twice, and a fragment stays
 * after the query. Mode "fragment" replaces the fragment. Without parameters the
 * URI is returned unchanged.
 */
function oidc_build_redirect_url(
    string $baseUri,
    array $params,
    string $mode = "query"
): string {
    $encoded = http_build_query($params, "", "&", PHP_QUERY_RFC3986);
    if ($encoded === "") {
        return $baseUri;
    }
    $fragment = null;
    $hashPos = strpos($baseUri, "#");
    if ($hashPos !== false) {
        $fragment = substr($baseUri, $hashPos + 1);
        $baseUri = substr($baseUri, 0, $hashPos);
    }
    if ($mode === "fragment") {
        return $baseUri . "#" . $encoded;
    }
    $query = "";
    $queryPos = strpos($baseUri, "?");
    if ($queryPos !== false) {
        $query = substr($baseUri, $queryPos + 1);
        $baseUri = substr($baseUri, 0, $queryPos);
    }
    $pairs = [];
    foreach (explode("&", $query) as $pair) {
        if ($pair === "") {
            continue;
        }
        $name = urldecode(explode("=", $pair, 2)[0]);
        if (!array_key_exists($name, $params)) {
            $pairs[] = $pair;
        }
    }
    $pairs[] = $encoded;
    $url = $baseUri . "?" . implode("&", $pairs);
    return $fragment !== null ? $url . "#" . $fragment : $url;
}

// ---------- Authorization Endpoint ----------

/**
 * PKCE rules for an authorization request (RFC 7636, RFC 9700 section 2.1.1). A
 * require_pkce client (every public client) must send a code_challenge whenever a
 * code is returned, and the method must be S256 or plain. Plain (also an omitted
 * method, RFC 7636 section 4.3) is refused for every client; with
 * oidc_plain_pkce_allowed() only for public and require_pkce clients. The challenge
 * syntax is checked: 43 base64url characters for S256, 43-128 unreserved characters
 * for plain. legacy_oauth_flows keeps only the first two checks. Throws
 * InvalidArgumentException.
 */
function oidc_assert_pkce_request(
    array $client,
    string $responseType,
    string $codeChallenge,
    string $codeChallengeMethod
): void {
    if (
        !empty($client["require_pkce"]) &&
        in_array("code", oidc_scope_list($responseType), true) &&
        $codeChallenge === ""
    ) {
        throw new InvalidArgumentException(
            "PKCE code_challenge is required for this OIDC client"
        );
    }
    if ($codeChallenge === "") {
        return;
    }
    if (!in_array($codeChallengeMethod, ["S256", "plain"], true)) {
        throw new InvalidArgumentException(
            "Unsupported code_challenge_method: $codeChallengeMethod"
        );
    }
    if (oidc_legacy_oauth_flows()) {
        return;
    }
    if (
        $codeChallengeMethod !== "S256" &&
        (!empty($client["is_public"]) || !empty($client["require_pkce"]) || !oidc_plain_pkce_allowed())
    ) {
        throw new InvalidArgumentException(
            "code_challenge_method=S256 is required for this OIDC client (an omitted code_challenge_method means plain)"
        );
    }
    if ($codeChallengeMethod === "S256") {
        if (preg_match('/^[A-Za-z0-9_-]{43}$/D', $codeChallenge) !== 1) {
            throw new InvalidArgumentException(
                "Malformed code_challenge: S256 needs the 43-character base64url SHA-256 of the code_verifier"
            );
        }
    } elseif (preg_match('/^[A-Za-z0-9._~-]{43,128}$/D', $codeChallenge) !== 1) {
        throw new InvalidArgumentException(
            "Malformed code_challenge: use 43 to 128 characters from A-Z, a-z, 0-9 and -._~"
        );
    }
}

/**
 * Rejects (invalid_request) authorization request parameters that are not single strings,
 * not valid UTF-8 or larger than OIDC_AUTHORIZE_PARAM_MAX_BYTES (S12-11). Unauthenticated
 * requests store these values in a sign-in transaction, so they are checked before anything
 * is looked up or stored. The code_challenge syntax itself is checked by
 * oidc_assert_pkce_request().
 */
function oidc_assert_authorize_param_sizes(array $params): void
{
    foreach (OIDC_AUTHORIZE_PARAM_MAX_BYTES as $name => $maxBytes) {
        if (!isset($params[$name])) {
            continue;
        }
        $value = $params[$name];
        if (!is_string($value)) {
            throw new InvalidArgumentException("invalid_request: $name must be a single value");
        }
        if (strlen($value) > $maxBytes) {
            throw new InvalidArgumentException(
                "invalid_request: $name is too long (at most $maxBytes bytes)"
            );
        }
        if (preg_match('//u', $value) !== 1) {
            throw new InvalidArgumentException("invalid_request: $name is not valid UTF-8");
        }
    }
}

function oidc_validate_authorize_request(
    string $storePath,
    array $provider,
    array $params
): array {
    oidc_assert_authorize_param_sizes($params);
    $clientId = trim((string) ($params["client_id"] ?? ""));
    $redirectUri = trim((string) ($params["redirect_uri"] ?? ""));
    $responseType = trim((string) ($params["response_type"] ?? "code"));
    $scope = trim((string) ($params["scope"] ?? "openid profile email groups"));
    $state = (string) ($params["state"] ?? "");
    $nonce = (string) ($params["nonce"] ?? "");
    $codeChallenge = trim((string) ($params["code_challenge"] ?? ""));
    // RFC 7636 section 4.3: the method defaults to "plain"; an empty parameter
    // counts as omitted (RFC 6749 section 3.1).
    $codeChallengeMethod = trim((string) ($params["code_challenge_method"] ?? ""));
    if ($codeChallengeMethod === "") {
        $codeChallengeMethod = "plain";
    }
    $prompt = trim((string) ($params["prompt"] ?? ""));
    $responseMode = trim((string) ($params["response_mode"] ?? ""));
    $maxAgeParam = trim((string) ($params["max_age"] ?? ""));

    if ($clientId === "") {
        throw new InvalidArgumentException("Missing client_id parameter");
    }
    $client = oidc_find_client_by_client_id(
        $storePath,
        $provider["id"],
        $clientId
    );
    if (!$client) {
        throw new InvalidArgumentException("Unknown OIDC client_id");
    }

    // redirect_uri may be omitted only when exactly one is registered; the token
    // request may then omit it too (RFC 6749 section 4.1.3).
    $allowedUris = array_values(
        array_filter((array) ($client["redirect_uris"] ?? []), "is_string")
    );
    $redirectUriSupplied = $redirectUri !== "";
    if (!$redirectUriSupplied && count($allowedUris) === 1) {
        $redirectUri = $allowedUris[0];
    }
    $redirectUri = oidc_check_redirect_uri(
        $client,
        $redirectUri,
        $responseType,
        $codeChallenge,
        $codeChallengeMethod
    );

    $supportedRespTypes = [
        "code",
        "id_token",
        "token id_token",
        "id_token token",
        "code id_token",
    ];
    if (!in_array($responseType, $supportedRespTypes, true)) {
        throw new InvalidArgumentException(
            "Unsupported response_type: $responseType"
        );
    }
    // The client's registered grant_types decide which flows it may use.
    oidc_assert_response_type_allowed($client, $responseType);

    $respParts = preg_split('/\s+/', $responseType) ?: ["code"];
    $returnsDirectTokens =
        in_array("id_token", $respParts, true) ||
        in_array("token", $respParts, true);

    if (in_array("id_token", $respParts, true) && $nonce === "") {
        throw new InvalidArgumentException(
            "nonce parameter is required when requesting id_token directly"
        );
    }

    oidc_assert_pkce_request(
        $client,
        $responseType,
        $codeChallenge,
        $codeChallengeMethod
    );

    if ($responseMode === "") {
        $responseMode = $returnsDirectTokens ? "fragment" : "query";
    }
    if (!in_array($responseMode, ["query", "fragment", "form_post"], true)) {
        throw new InvalidArgumentException("Unsupported response_mode");
    }
    if ($returnsDirectTokens && $responseMode === "query") {
        throw new InvalidArgumentException(
            "response_mode=query is forbidden when returning tokens from authorization endpoint"
        );
    }

    $maxAge = null;
    if ($maxAgeParam !== "") {
        if (preg_match('/^\d{1,10}$/D', $maxAgeParam) !== 1) {
            throw new InvalidArgumentException(
                "max_age must be a whole number of seconds"
            );
        }
        $maxAge = (int) $maxAgeParam;
    }

    return [
        "client" => $client,
        "client_id" => $client["client_id"],
        "redirect_uri" => $redirectUri,
        "response_type" => $responseType,
        "response_mode" => $responseMode,
        "scope" => $scope ?: "openid",
        "state" => $state,
        "nonce" => $nonce,
        "code_challenge" => $codeChallenge,
        "code_challenge_method" => $codeChallengeMethod,
        "prompt" => $prompt,
        "max_age" => $maxAge,
        "redirect_uri_supplied" => $redirectUriSupplied,
    ];
}

/**
 * Issues the authorization response (code and/or implicit/hybrid tokens) and
 * redirects to the client. $authTime is when the user actually authenticated (the
 * reused SSO session's time); it defaults to now. $ssoSessionId binds the code and
 * the tokens minted from it to that SSO session, so ending the session revokes
 * them (oidc_revoke_tokens_for_session()), except offline_access grants. The code
 * and the tokens are stored in one write transaction that first checks that the
 * session still exists for $user (oidc_sso_session_live()). A logout or a new
 * sign-in that ended the session after the caller read it therefore either commits
 * first, and the client receives error=login_required instead, or commits later and
 * revokes or moves what was stored here.
 */
function oidc_issue_authorization_response(
    string $storePath,
    array &$providers,
    array &$provider,
    string $baseUrl,
    array $authReq,
    array $user,
    array $amr,
    string $keysDir = "",
    ?int $authTime = null,
    ?string $ssoSessionId = null
): never {
    $pdo = oidc_db($storePath);
    $now = time();
    if ($authTime === null || $authTime <= 0 || $authTime > $now) {
        $authTime = $now;
    }
    $sessionRef = oidc_session_ref($ssoSessionId);
    $client = $authReq["client"];
    $responseType = (string) ($authReq["response_type"] ?? "code");
    $state = (string) ($authReq["state"] ?? "");
    $nonce = (string) ($authReq["nonce"] ?? "");
    $scope = (string) ($authReq["scope"] ?? "openid");
    $codeChallenge = (string) ($authReq["code_challenge"] ?? "");
    $codeChallengeMethod = (string) ($authReq["code_challenge_method"] ?? "");
    if ($codeChallengeMethod === "") {
        $codeChallengeMethod = "plain";
    }

    // Hosted login can take minutes: check the client's current grant types, PKCE
    // requirements and redirect_uri registration again before anything is sent.
    try {
        oidc_assert_response_type_allowed($client, $responseType);
        oidc_assert_pkce_request(
            $client,
            $responseType,
            $codeChallenge,
            $codeChallengeMethod
        );
        $redirectUri = oidc_check_redirect_uri(
            $client,
            (string) ($authReq["redirect_uri"] ?? ""),
            $responseType,
            $codeChallenge,
            $codeChallengeMethod
        );
    } catch (InvalidArgumentException $e) {
        render_modern_status_page(
            400,
            "OIDC Authorization Error",
            $e->getMessage(),
            ["variant" => "error"]
        );
    }

    $responseParams = [];
    if ($state !== "") {
        $responseParams["state"] = $state;
    }

    $respParts = preg_split('/\s+/', $responseType) ?: ["code"];

    $code = in_array("code", $respParts, true) ? base64url_encode(random_bytes(32)) : null;
    $returnsAccessToken = in_array("token", $respParts, true);
    $built = null;
    if ($returnsAccessToken || in_array("id_token", $respParts, true)) {
        // An access token is only minted when the response returns one. The ID token
        // carries c_hash for a code and at_hash for an access token returned with it
        // (OIDC Core sections 3.3.2.11 and 3.2.2.10). Signed before the transaction
        // below, which stores the rows.
        $built = oidc_build_token_bundle(
            $storePath,
            $providers,
            $provider,
            $baseUrl,
            $client,
            $user,
            $scope,
            $nonce,
            $amr,
            $authTime,
            false,
            $keysDir,
            oidc_new_token_family($authTime, $sessionRef),
            $code,
            $returnsAccessToken
        );
    }

    $codeParams = null;
    if ($code !== null) {
        $codeParams = [
            ":c" => $code,
            ":pid" => $provider["id"],
            ":cid" => $client["client_id"],
            ":uid" => $user["id"],
            ":ru" => $redirectUri,
            ":sc" => $scope,
            ":nc" => $nonce !== "" ? $nonce : null,
            ":cc" => $codeChallenge !== "" ? $codeChallenge : null,
            ":ccm" => $codeChallenge !== "" ? $codeChallengeMethod : null,
            ":amr" => json_encode(array_values($amr), JSON_UNESCAPED_SLASHES),
            ":at" => $authTime,
            ":exp" => $now + 300,
            ":sid" => $sessionRef,
            ":rus" => !empty($authReq["redirect_uri_supplied"] ?? true) ? 1 : 0,
        ];
    }
    $stored = storage_write_transaction(
        $pdo,
        function (PDO $pdo) use ($provider, $user, $ssoSessionId, $sessionRef, $codeParams, $built): bool {
            if (
                $sessionRef !== null &&
                !oidc_sso_session_live(
                    $pdo,
                    (string) $provider["id"],
                    (string) $ssoSessionId,
                    (string) $user["id"]
                )
            ) {
                return false;
            }
            if ($codeParams !== null) {
                $pdo->prepare(
                    "INSERT INTO oidc_auth_codes (" .
                        "code, provider_id, client_id, user_id, redirect_uri, scope, nonce, " .
                        "code_challenge, code_challenge_method, amr_json, auth_time, expires_at, " .
                        "sid, redirect_uri_supplied" .
                    ") VALUES (:c, :pid, :cid, :uid, :ru, :sc, :nc, :cc, :ccm, :amr, :at, :exp, :sid, :rus)"
                )->execute($codeParams);
            }
            if ($built !== null) {
                oidc_store_token_rows($pdo, $built["rows"]);
            }
            return true;
        }
    );
    if (!$stored) {
        // The SSO session ended (logout, or a new sign-in in this browser) after the
        // caller read it: nothing was stored, and the client has to sign the user in again.
        $errParams = [
            "error" => "login_required",
            "error_description" => "The sign-in session has ended",
        ];
        if ($state !== "") {
            $errParams["state"] = $state;
        }
        oidc_send_authorization_redirect(
            $redirectUri,
            $errParams,
            (string) ($authReq["response_mode"] ?? "query")
        );
    }
    if ($code !== null) {
        $responseParams["code"] = $code;
    }

    if ($built !== null) {
        oidc_after_token_issue($storePath, $providers, $provider);
        $tokens = $built["response"];
        if ($returnsAccessToken) {
            $responseParams["access_token"] = $tokens["access_token"];
            $responseParams["token_type"] = "Bearer";
            $responseParams["expires_in"] = (string) $tokens["expires_in"];
        }
        if (in_array("id_token", $respParts, true)) {
            $responseParams["id_token"] = $tokens["id_token"];
        }
    }

    audit_log_append(
        $storePath,
        $provider["id"],
        "oidc",
        "authorize_success",
        "success",
        $client["name"],
        $user["username"],
        $amr,
        [
            "client_id" => $client["client_id"],
            "response_type" => $responseType,
            "redirect_uri" => $redirectUri,
        ]
    );

    oidc_purge_expired($pdo);

    oidc_send_authorization_redirect(
        $redirectUri,
        $responseParams,
        (string) ($authReq["response_mode"] ?? "query")
    );
}

function oidc_send_authorization_redirect(
    string $redirectUri,
    array $params,
    string $responseMode = "query"
): never {
    try {
        $redirectUri = validate_endpoint_url($redirectUri, true, "redirect_uri");
    } catch (InvalidArgumentException $e) {
        render_modern_status_page(
            400,
            "OIDC Authorization Error",
            $e->getMessage(),
            ["variant" => "error"]
        );
    }

    if ($responseMode === "form_post") {
        $inputs = "";
        foreach ($params as $k => $v) {
            $inputs .=
                '<input type="hidden" name="' .
                html_escape((string) $k) .
                '" value="' .
                html_escape((string) $v) .
                '" />';
        }
        $escAction = html_escape($redirectUri);
        html_response(
            200,
            "<!doctype html><html><body onload=\"document.forms[0].submit()\"><form method=\"post\" action=\"{$escAction}\">{$inputs}</form></body></html>"
        );
    }

    $target = oidc_build_redirect_url(
        $redirectUri,
        $params,
        $responseMode === "fragment" ? "fragment" : "query"
    );
    send_security_headers(false);
    header("Location: " . $target, true, 302);
    exit();
}

// ---------- Token Issuance ----------

/**
 * Starts a token family: the tokens of one authorization and every rotation of
 * its refresh token. The family ends OIDC_REFRESH_FAMILY_MAX_LIFETIME after the
 * user authenticated, and keeps that auth_time and the SSO session binding.
 */
function oidc_new_token_family(int $authTime, ?string $sessionRef = null): array
{
    $now = time();
    $start = $authTime > 0 && $authTime <= $now ? $authTime : $now;
    return [
        "id" => uuidv4(),
        "expires_at" => $start + OIDC_REFRESH_FAMILY_MAX_LIFETIME,
        "auth_time" => $authTime,
        "sid" => $sessionRef,
    ];
}

/**
 * The signing key for $provider (resolve_signing_key_for_provider(), which may rotate it).
 * Only this provider is handed over, so a rotation triggered by a token request never
 * involves other tenants' providers (S10-07); $providers receives the updated copy in memory.
 */
function oidc_resolve_signing_key(
    string $storePath,
    array &$providers,
    array &$provider,
    string $keysDir
): array {
    $providersForSigning = [$provider];
    $key = resolve_signing_key_for_provider(
        $storePath,
        $providersForSigning,
        $provider,
        $keysDir
    );
    foreach ($providers as $i => $p) {
        if (is_array($p) && (string) ($p["id"] ?? "") === (string) $provider["id"]) {
            $providers[$i] = $provider;
        }
    }
    return $key;
}

/**
 * Signs the ID token and, unless $includeAccessToken is false, the access token
 * (and creates a refresh token when allowed) without writing them: returns
 * ["response" => token response, "rows" => the oidc_tokens rows to store with
 * oidc_store_token_rows()]. Callers store the rows in the same transaction that
 * consumes the code or refresh token. The ID token carries at_hash for the access
 * token returned with it and c_hash for $authorizationCode (hybrid flow).
 * Access tokens follow RFC 9068 unless legacy_token_claims is on (see
 * oidc_build_access_token_claims()).
 */
function oidc_build_token_bundle(
    string $storePath,
    array &$providers,
    array &$provider,
    string $baseUrl,
    array $client,
    array $user,
    string $scope,
    string $nonce,
    array $amr,
    int $authTime,
    bool $issueRefresh,
    string $keysDir,
    array $family,
    ?string $authorizationCode = null,
    bool $includeAccessToken = true
): array {
    $keyToUse = oidc_resolve_signing_key($storePath, $providers, $provider, $keysDir);
    $alg = (string) ($keyToUse["alg"] ?? "RS256");
    $now = time();
    $ttl = max(60, (int) ($client["access_token_ttl"] ?? 3600));
    $issuer = $baseUrl . "/" . $provider["idp_id"];

    $profileClaims = oidc_build_user_profile_claims(
        $user,
        $scope,
        (array) ($client["custom_claims"] ?? [])
    );

    // The access token is signed first, so the ID token can carry its at_hash.
    $accessToken = null;
    if ($includeAccessToken) {
        $accessToken = oidc_sign_access_token(
            $keyToUse,
            oidc_build_access_token_claims(
                $issuer,
                $client,
                $user,
                $profileClaims,
                $scope,
                $amr,
                $authTime,
                $now,
                $ttl
            )
        );
    }

    $idTokenClaims = array_merge($profileClaims, [
        "iss" => $issuer,
        "aud" => $client["client_id"],
        "iat" => $now,
        "nbf" => $now,
        "exp" => $now + $ttl,
        "jti" => uuidv4(),
        "auth_time" => $authTime,
        "amr" => array_values($amr),
        "acr" => oidc_acr_from_amr($amr),
    ]);
    if ($nonce !== "") {
        $idTokenClaims["nonce"] = $nonce;
    }
    if ($accessToken !== null) {
        $idTokenClaims["at_hash"] = oidc_token_hash_claim($accessToken, $alg);
    }
    if ($authorizationCode !== null && $authorizationCode !== "") {
        $idTokenClaims["c_hash"] = oidc_token_hash_claim($authorizationCode, $alg);
    }
    $idToken = sign_jwt_with_key($keyToUse, $idTokenClaims);
    oidc_record_signed_token_exp($storePath, $provider, $keyToUse, $now + $ttl);

    $rowBase = [
        "provider_id" => (string) $provider["id"],
        "client_id" => (string) $client["client_id"],
        "user_id" => (string) $user["id"],
        "scope" => $scope,
        "amr_json" => (string) json_encode(array_values($amr), JSON_UNESCAPED_SLASHES),
        "auth_time" => $authTime,
        "family_id" => (string) $family["id"],
        "family_expires_at" => (int) $family["expires_at"],
        "sid" => $family["sid"] ?? null,
    ];
    $rows = [];
    if ($accessToken !== null) {
        $rows[] = $rowBase + [
            "token_hash" => hash("sha256", $accessToken),
            "token_type" => "access",
            "expires_at" => $now + $ttl,
        ];
    }

    // A refresh token requires the client's refresh_token grant (legacy_oauth_flows
    // also accepts the offline_access scope alone) and comes only with an access
    // token. It is valid for 30 days and never past the end of its family.
    $refreshToken = null;
    $refreshAllowed =
        in_array("refresh_token", (array) ($client["grant_types"] ?? []), true) ||
        (in_array("offline_access", oidc_scope_list($scope), true) &&
            oidc_legacy_oauth_flows());
    $refreshExpiresAt = min(
        $now + OIDC_REFRESH_TOKEN_TTL,
        (int) $family["expires_at"]
    );
    if (
        $issueRefresh &&
        $accessToken !== null &&
        $refreshAllowed &&
        $refreshExpiresAt > $now
    ) {
        $refreshToken = "rt_" . base64url_encode(random_bytes(32));
        $rows[] = $rowBase + [
            "token_hash" => hash("sha256", $refreshToken),
            "token_type" => "refresh",
            "expires_at" => $refreshExpiresAt,
        ];
    }

    $response = [];
    if ($accessToken !== null) {
        $response["access_token"] = $accessToken;
        $response["token_type"] = "Bearer";
        $response["expires_in"] = $ttl;
    }
    $response["id_token"] = $idToken;
    $response["scope"] = $scope;
    if ($refreshToken !== null) {
        $response["refresh_token"] = $refreshToken;
    }
    return ["response" => $response, "rows" => $rows];
}

/**
 * Claims of an access token issued for a user. By default they follow RFC 9068:
 * aud is the provider issuer (never the client_id, so an access token cannot pass
 * as an ID token), client_id names the client, and only sub, scope, auth_time and
 * acr describe the user: no profile data or PII. The client's custom_claims are
 * kept, but cannot replace any of these. legacy_token_claims restores the old
 * token: the full profile claim set, amr and aud = client_id.
 */
function oidc_build_access_token_claims(
    string $issuer,
    array $client,
    array $user,
    array $profileClaims,
    string $scope,
    array $amr,
    int $authTime,
    int $now,
    int $ttl
): array {
    if (oidc_legacy_token_claims()) {
        return array_merge($profileClaims, [
            "iss" => $issuer,
            "aud" => $client["client_id"],
            "client_id" => $client["client_id"],
            "scope" => $scope,
            "iat" => $now,
            "nbf" => $now,
            "exp" => $now + $ttl,
            "jti" => uuidv4(),
            "amr" => array_values($amr),
        ]);
    }
    return array_merge(
        oidc_filter_custom_claims(
            (array) ($client["custom_claims"] ?? []),
            OIDC_PROTECTED_CLAIMS
        ),
        [
            "iss" => $issuer,
            "sub" => oidc_subject_for_user($user),
            "aud" => $issuer,
            "client_id" => $client["client_id"],
            "scope" => $scope,
            "iat" => $now,
            "nbf" => $now,
            "exp" => $now + $ttl,
            "jti" => uuidv4(),
            "auth_time" => $authTime,
            "acr" => oidc_acr_from_amr($amr),
        ]
    );
}

/**
 * Signs access token claims: JOSE typ "at+jwt" (RFC 9068 section 2.1), or "JWT"
 * when legacy_token_claims is on.
 */
function oidc_sign_access_token(array $key, array $claims): string
{
    if (oidc_legacy_token_claims()) {
        return sign_jwt_with_key($key, $claims);
    }
    return sign_jwt_with_key($key, $claims, "at+jwt");
}

/**
 * Records that a token signed with $key stays valid until $exp, so the key stays
 * published in the JWKS until then (provider_key_record_token_exp(), crypto lane;
 * best-effort, skipped where it does not exist yet).
 */
function oidc_record_signed_token_exp(
    string $storePath,
    array $provider,
    array $key,
    int $exp
): void {
    if (!function_exists("provider_key_record_token_exp")) {
        return;
    }
    try {
        provider_key_record_token_exp(
            $storePath,
            (string) $provider["id"],
            (string) ($key["kid"] ?? ""),
            $exp
        );
    } catch (Throwable $e) {
        error_log("oidc: could not record a signing key's token expiry: " . $e->getMessage());
    }
}

function oidc_store_token_rows(PDO $pdo, array $rows): void
{
    $ins = $pdo->prepare(
        "INSERT INTO oidc_tokens (" .
            "token_hash, token_type, provider_id, client_id, user_id, scope, amr_json, expires_at, " .
            "auth_time, family_id, family_expires_at, sid" .
        ") VALUES (:th, :tt, :pid, :cid, :uid, :sc, :amr, :exp, :at, :fid, :fexp, :sid)"
    );
    foreach ($rows as $row) {
        $ins->execute([
            ":th" => $row["token_hash"],
            ":tt" => $row["token_type"],
            ":pid" => $row["provider_id"],
            ":cid" => $row["client_id"],
            ":uid" => $row["user_id"],
            ":sc" => $row["scope"],
            ":amr" => $row["amr_json"],
            ":exp" => $row["expires_at"],
            ":at" => $row["auth_time"],
            ":fid" => $row["family_id"],
            ":fexp" => $row["family_expires_at"],
            ":sid" => $row["sid"],
        ]);
    }
}

/**
 * Bookkeeping after tokens were issued. Only this provider's last_issued_at
 * column is written: the request's snapshot of all providers is never saved back,
 * because that reverted concurrent admin changes and deleted providers created in
 * the meantime. Best-effort.
 */
function oidc_after_token_issue(
    string $storePath,
    array &$providers,
    array &$provider
): void {
    $issuedAt = date("c");
    try {
        storage_db($storePath)
            ->prepare("UPDATE providers SET last_issued_at = :t WHERE id = :id")
            ->execute([":t" => $issuedAt, ":id" => (string) $provider["id"]]);
    } catch (Throwable $e) {
        error_log("oidc: could not update providers.last_issued_at: " . $e->getMessage());
    }
    $provider["last_issued_at"] = $issuedAt;
    foreach ($providers as $i => $p) {
        if (is_array($p) && ($p["id"] ?? null) === $provider["id"]) {
            $providers[$i]["last_issued_at"] = $issuedAt;
            break;
        }
    }
}

/**
 * Signs and stores a token bundle. Used for implicit/hybrid responses and by
 * callers that consumed a code themselves. $family continues an existing token
 * family (see oidc_new_token_family()); by default a new one starts at $authTime.
 * $authorizationCode (a code returned together with the ID token) adds c_hash;
 * $includeAccessToken = false mints only the ID token (response_type id_token or
 * code id_token). $providers may be the request's provider list or just
 * [$provider]; it is never written back.
 */
function oidc_mint_token_bundle(
    string $storePath,
    array &$providers,
    array &$provider,
    string $baseUrl,
    array $client,
    array $user,
    string $scope,
    string $nonce,
    array $amr,
    int $authTime,
    bool $issueRefresh = true,
    string $keysDir = "",
    ?array $family = null,
    ?string $authorizationCode = null,
    bool $includeAccessToken = true
): array {
    $pdo = oidc_db($storePath);
    $built = oidc_build_token_bundle(
        $storePath,
        $providers,
        $provider,
        $baseUrl,
        $client,
        $user,
        $scope,
        $nonce,
        $amr,
        $authTime,
        $issueRefresh,
        $keysDir,
        $family ?? oidc_new_token_family($authTime),
        $authorizationCode,
        $includeAccessToken
    );
    $ownTransaction = !$pdo->inTransaction() && $built["rows"] !== [];
    try {
        if ($ownTransaction) {
            $pdo->exec("BEGIN IMMEDIATE");
        }
        oidc_store_token_rows($pdo, $built["rows"]);
        if ($ownTransaction) {
            $pdo->exec("COMMIT");
        }
    } catch (Throwable $e) {
        if ($ownTransaction) {
            oidc_rollback_quietly($pdo);
        }
        throw $e;
    }
    oidc_after_token_issue($storePath, $providers, $provider);
    return $built["response"];
}

// ---------- Token Revocation & Cleanup ----------

/**
 * Deletes a whole refresh-token family: its refresh tokens, their consumed
 * tombstones and the access tokens issued with them. $tokenHash also deletes one
 * row that has no family (issued before families existed). Best-effort.
 */
function oidc_revoke_token_family(
    PDO $pdo,
    string $providerId,
    string $familyId,
    string $tokenHash = ""
): void {
    try {
        if ($familyId !== "") {
            $pdo->prepare(
                "DELETE FROM oidc_tokens WHERE provider_id = :pid AND family_id = :fid"
            )->execute([":pid" => $providerId, ":fid" => $familyId]);
        }
        if ($tokenHash !== "") {
            $pdo->prepare(
                "DELETE FROM oidc_tokens WHERE provider_id = :pid AND token_hash = :th"
            )->execute([":pid" => $providerId, ":th" => $tokenHash]);
        }
    } catch (Throwable $e) {
        error_log("oidc: could not revoke a token family: " . $e->getMessage());
    }
}

/**
 * Deletes, in the caller's write transaction, what is bound to the SSO session
 * reference $sessionRef (oidc_session_ref()): its tokens whose scope lacks
 * offline_access (refresh tokens, their tombstones and access tokens) and its
 * unredeemed authorization codes. offline_access grants are meant to outlive the
 * session (OIDC Core section 11) and are kept.
 */
function oidc_delete_session_bound_rows(PDO $pdo, string $providerId, string $sessionRef): void
{
    $sel = $pdo->prepare(
        "SELECT token_hash, scope FROM oidc_tokens WHERE provider_id = :pid AND sid = :sid"
    );
    $sel->execute([":pid" => $providerId, ":sid" => $sessionRef]);
    $rows = $sel->fetchAll(PDO::FETCH_ASSOC);
    $del = $pdo->prepare(
        "DELETE FROM oidc_tokens WHERE provider_id = :pid AND token_hash = :th"
    );
    foreach ($rows as $row) {
        if (!in_array("offline_access", oidc_scope_list((string) $row["scope"]), true)) {
            $del->execute([
                ":pid" => $providerId,
                ":th" => (string) $row["token_hash"],
            ]);
        }
    }
    $pdo->prepare(
        "DELETE FROM oidc_auth_codes WHERE provider_id = :pid AND sid = :sid"
    )->execute([":pid" => $providerId, ":sid" => $sessionRef]);
}

/** Deletes the row of SSO session $ssoSessionId, in the caller's write transaction. */
function oidc_delete_sso_session_row(PDO $pdo, string $providerId, string $ssoSessionId): void
{
    $pdo->prepare(
        "DELETE FROM sso_sessions WHERE id = :id AND provider_id = :pid"
    )->execute([":id" => trim($ssoSessionId), ":pid" => $providerId]);
}

/**
 * Call when an SSO session ends (IdP logout). Deletes the tokens bound to that
 * session whose scope lacks offline_access and the session's unredeemed
 * authorization codes (oidc_delete_session_bound_rows()), and the session's row
 * itself. All of it happens in one write transaction (BEGIN IMMEDIATE), so a
 * concurrent refresh, code exchange or authorization response either commits first,
 * and what it stored is deleted too, or runs afterwards and finds its refresh token,
 * code or session gone (oidc_sso_session_live()). The caller may delete the session
 * row again afterwards. $ssoSessionId is the session id given to
 * oidc_issue_authorization_response().
 * Best-effort: errors are logged, never thrown, so logout always completes.
 */
function oidc_revoke_tokens_for_session(
    string $storePath,
    string $providerId,
    string $ssoSessionId
): void {
    $sessionRef = oidc_session_ref($ssoSessionId);
    if ($sessionRef === null) {
        return;
    }
    try {
        storage_write_transaction(
            oidc_db($storePath),
            function (PDO $pdo) use ($providerId, $sessionRef, $ssoSessionId): void {
                oidc_delete_session_bound_rows($pdo, $providerId, $sessionRef);
                oidc_delete_sso_session_row($pdo, $providerId, $ssoSessionId);
            }
        );
    } catch (Throwable $e) {
        error_log("oidc: could not revoke the tokens of an ended SSO session: " . $e->getMessage());
    }
}

/**
 * Call when a new sign-in replaces SSO session $previousSsoSessionId in the same
 * browser (prompt=login, max_age, step-up or another user signing in): sso_set_session()
 * calls it for each previous session id the browser presented, after inserting the new
 * session $newSsoSessionId. The tokens and codes of $userId, the user of the new
 * session, that are bound to the previous session move to the new one, so logging out
 * of the new session also ends them. Anything else bound to the previous session
 * belongs to another user, whose session this sign-in ended: it is revoked as on
 * logout (oidc_delete_session_bound_rows(); offline_access grants are kept). The
 * previous session's row is deleted in the same write transaction, like in
 * oidc_revoke_tokens_for_session(), so an authorization response for the previous
 * session either commits first, and its code or tokens are moved or revoked here, or
 * finds the session gone. The caller may delete that row before or after this call.
 * Best-effort: errors are logged, never thrown, so the sign-in completes.
 */
function oidc_rebind_session_tokens(
    string $storePath,
    string $providerId,
    string $previousSsoSessionId,
    string $newSsoSessionId,
    string $userId
): void {
    $previousRef = oidc_session_ref($previousSsoSessionId);
    $newRef = oidc_session_ref($newSsoSessionId);
    if ($previousRef === null || $previousRef === $newRef) {
        return;
    }
    try {
        storage_write_transaction(
            oidc_db($storePath),
            function (PDO $pdo) use (
                $providerId,
                $previousRef,
                $newRef,
                $userId,
                $previousSsoSessionId
            ): void {
                if ($newRef !== null && $userId !== "") {
                    foreach (["oidc_tokens", "oidc_auth_codes"] as $table) {
                        $pdo->prepare(
                            "UPDATE " . $table . " SET sid = :new " .
                                "WHERE provider_id = :pid AND sid = :old AND user_id = :uid"
                        )->execute([
                            ":new" => $newRef,
                            ":pid" => $providerId,
                            ":old" => $previousRef,
                            ":uid" => $userId,
                        ]);
                    }
                }
                oidc_delete_session_bound_rows($pdo, $providerId, $previousRef);
                oidc_delete_sso_session_row($pdo, $providerId, $previousSsoSessionId);
            }
        );
    } catch (Throwable $e) {
        error_log("oidc: could not move the tokens of a replaced SSO session: " . $e->getMessage());
    }
}

/**
 * $rows from oidc_build_token_bundle(), bound to $sessionRef: the SSO session
 * reference the consumed code or refresh token has inside the transaction that stores
 * them. The bundle was built from an earlier read, and a new sign-in may have moved
 * the binding to its session since then (oidc_rebind_session_tokens()).
 */
function oidc_bind_token_rows_to_session(array $rows, mixed $sessionRef): array
{
    $ref = is_string($sessionRef) && $sessionRef !== "" ? $sessionRef : null;
    foreach ($rows as $i => $row) {
        $rows[$i]["sid"] = $ref;
    }
    return $rows;
}

/**
 * Revokes every OIDC token and unredeemed authorization code of a user, for use
 * when the user's password is changed or cleared, the user is suspended, or a
 * credential is removed. Both deletes run in one write transaction, so a concurrent
 * code exchange cannot store tokens between them. Best-effort; returns the number of
 * deleted token rows.
 */
function oidc_revoke_tokens_for_user(string $storePath, string $userId): int
{
    if ($userId === "") {
        return 0;
    }
    try {
        return (int) storage_write_transaction(
            oidc_db($storePath),
            function (PDO $pdo) use ($userId): int {
                $del = $pdo->prepare("DELETE FROM oidc_tokens WHERE user_id = :uid");
                $del->execute([":uid" => $userId]);
                $count = $del->rowCount();
                $pdo->prepare("DELETE FROM oidc_auth_codes WHERE user_id = :uid")->execute([
                    ":uid" => $userId,
                ]);
                return $count;
            }
        );
    } catch (Throwable $e) {
        error_log("oidc: could not revoke a user's tokens: " . $e->getMessage());
        return 0;
    }
}

/**
 * Deletes expired authorization codes and tokens, at most OIDC_PURGE_BATCH_SIZE
 * rows per table per run: each delete is a short statement of its own, so a large
 * backlog (for example the first purge after an upgrade) is removed over several
 * runs instead of holding the write lock during an ordinary request. A consumed
 * refresh token stays until its own expiry (at most 30 days after it was issued),
 * so replaying a rotated token that would otherwise still be valid is recognized as
 * reuse. Runs at most once per request, and only for about one call in 50 unless
 * forced.
 */
function oidc_purge_expired(PDO $pdo, bool $force = false): void
{
    static $done = false;
    if ($done || (!$force && random_int(1, 50) !== 1)) {
        return;
    }
    $done = true;
    $now = time();
    try {
        foreach (["oidc_auth_codes", "oidc_tokens"] as $table) {
            storage_execute(
                $pdo->prepare(
                    "DELETE FROM " . $table . " WHERE rowid IN (SELECT rowid FROM " . $table .
                        " WHERE expires_at < :now LIMIT " . OIDC_PURGE_BATCH_SIZE . ")"
                ),
                [":now" => $now]
            );
        }
    } catch (Throwable $e) {
        error_log("oidc: could not purge expired codes and tokens: " . $e->getMessage());
    }
}

// ---------- Token Endpoint ----------

function oidc_extract_client_credentials(array $postParams): array
{
    $clientId = trim((string) ($postParams["client_id"] ?? ""));
    $clientSecret = (string) ($postParams["client_secret"] ?? "");

    $auth = get_auth_header();
    if (preg_match('/^\s*Basic\s+([A-Za-z0-9+\/=]+)\s*$/i', $auth, $m)) {
        $decoded = base64_decode($m[1], true);
        if ($decoded !== false && str_contains($decoded, ":")) {
            [$bId, $bSec] = explode(":", $decoded, 2);
            $clientId = rawurldecode($bId);
            $clientSecret = rawurldecode($bSec);
        }
    }
    return [$clientId, $clientSecret];
}

/**
 * Checks a client's credentials. Public clients need none. Secrets are verified
 * with machine_secret_verify(): one SHA-256 for current digests, password_verify()
 * only for legacy digests ($upgradedHash then receives the fast digest to
 * persist). Unknown clients fail without any hashing: client_ids are public.
 */
function oidc_verify_client_auth(
    ?array $client,
    string $providedSecret,
    ?string &$upgradedHash = null
): bool {
    $upgradedHash = null;
    if ($client === null) {
        return false;
    }
    if (!empty($client["is_public"])) {
        return true;
    }
    $hash = $client["_client_secret_hash"] ?? null;
    if (!is_string($hash) || $hash === "") {
        return false;
    }
    return machine_secret_verify($providedSecret, $hash, $upgradedHash);
}

/**
 * Counts a failed client authentication in each bucket that is not locked yet;
 * a locked bucket is not written again, so a flood causes few writes.
 * $buckets maps bucket => attempts allowed per 5 minutes (then a 5-minute lock).
 */
function oidc_record_token_auth_failure(string $storePath, array $buckets): void
{
    foreach ($buckets as $bucket => $maxAttempts) {
        try {
            if (!rate_limit_is_blocked($storePath, (string) $bucket)) {
                rate_limit_record_failure(
                    $storePath,
                    (string) $bucket,
                    (int) $maxAttempts,
                    300,
                    300
                );
            }
        } catch (Throwable $e) {
            error_log("oidc: could not record a failed client authentication: " . $e->getMessage());
        }
    }
}

/**
 * Gives back one attempt that rate_limit_hit() reserved in $bucket: the bucket's count
 * for its current window drops by one (never below zero), and a lock is never
 * shortened. If the window restarted since the reservation, the new window gains at
 * most this one attempt. Best-effort: errors are logged, and the attempt then stays
 * counted.
 */
function oidc_release_rate_limit_attempt(string $storePath, string $bucket): void
{
    try {
        storage_execute(
            storage_db($storePath)->prepare(
                "UPDATE auth_rate_limits SET failures = failures - 1 WHERE bucket = :b AND failures > 0"
            ),
            [":b" => rate_limit_storage_key($bucket)]
        );
    } catch (Throwable $e) {
        error_log("oidc: could not give back a client authentication attempt: " . $e->getMessage());
    }
}

/**
 * Reserves one check of a client secret stored as a legacy password_hash() digest
 * (bcrypt) for the caller's network, or answers 429 itself. One attempt is reserved
 * with rate_limit_hit() in each budget described at OIDC_LEGACY_SECRET_CLIENT_MAX_CHECKS:
 * "oidc_tok_legacy" per provider, client and network, then "oidc_tok_legacy_ip" per
 * network across every provider and client. A refused reservation runs no bcrypt, and
 * the attempt already reserved in the first budget is given back, so a request that
 * the per-network budget refuses uses up nothing of its client's budget. Returns the
 * two buckets in that order.
 */
function oidc_reserve_legacy_secret_check(
    string $storePath,
    string $providerId,
    string $clientId
): array {
    $network = client_ip_bucket();
    $budgets = [
        [
            rate_limit_bucket("oidc_tok_legacy", $providerId, $clientId, $network),
            OIDC_LEGACY_SECRET_CLIENT_MAX_CHECKS,
            OIDC_LEGACY_SECRET_CLIENT_WINDOW_SECONDS,
        ],
        [
            rate_limit_bucket("oidc_tok_legacy_ip", $network),
            OIDC_LEGACY_SECRET_NETWORK_MAX_CHECKS,
            OIDC_LEGACY_SECRET_NETWORK_WINDOW_SECONDS,
        ],
    ];
    $reserved = [];
    foreach ($budgets as [$bucket, $maxChecks, $windowSeconds]) {
        if (rate_limit_hit($storePath, $bucket, $maxChecks, $windowSeconds, $windowSeconds)) {
            foreach ($reserved as $reservedBucket) {
                oidc_release_rate_limit_attempt($storePath, $reservedBucket);
            }
            if (!headers_sent()) {
                header("Retry-After: " . $windowSeconds);
            }
            json_response(429, [
                "error" => "too_many_requests",
                "error_description" => "Too many client authentication attempts from this network; try again later",
            ]);
        }
        $reserved[] = $bucket;
    }
    return $reserved;
}

/**
 * Authenticates the client at the token endpoint and answers 401/429 itself.
 * A secret stored as a machine_secret_hash() digest costs one SHA-256, and a
 * correct one is always accepted, even while a failure bucket is locked. A legacy
 * password_hash() digest (bcrypt) is checked only after attempts were reserved in
 * the budgets of the caller's network (oidc_reserve_legacy_secret_check()), so one
 * network can neither burn much CPU nor guess quickly. Nothing consulted before that
 * check is keyed by the client alone: anyone can send wrong secrets for a public
 * client_id, and that uses up only the budgets of the sender's own network, never
 * those of the network the client calls from. The 5-minute failure lockouts are
 * consulted only after a failed check. After a successful check the digest is
 * replaced by the fast one, except for a secret shorter than 32 characters, which
 * stays on this path.
 */
function oidc_authenticate_token_client(
    string $storePath,
    array $provider,
    string $clientId,
    string $clientSecret
): array {
    $providerId = (string) $provider["id"];
    $ipBucket = rate_limit_bucket("oidc_tok_ip", $providerId, client_ip_bucket());
    $failed = [
        "error" => "invalid_client",
        "error_description" => "Client authentication failed",
    ];

    $client = oidc_find_client_by_client_id($storePath, $providerId, $clientId);
    if ($client === null) {
        oidc_record_token_auth_failure($storePath, [$ipBucket => 20]);
        json_response(401, $failed);
    }
    if (!empty($client["is_public"])) {
        return $client;
    }

    $clientBucket = rate_limit_bucket(
        "oidc_tok_client",
        $providerId,
        (string) $client["client_id"]
    );
    $storedHash = (string) ($client["_client_secret_hash"] ?? "");
    if (str_starts_with($storedHash, 's256$')) {
        if (oidc_verify_client_auth($client, $clientSecret)) {
            return $client;
        }
    } elseif (
        // Only a check that would run bcrypt reserves attempts.
        $clientSecret !== "" &&
        strlen($clientSecret) <= OIDC_CLIENT_SECRET_MAX_LENGTH &&
        !empty(password_get_info($storedHash)["algo"])
    ) {
        [$clientNetworkBucket, $networkBucket] = oidc_reserve_legacy_secret_check(
            $storePath,
            $providerId,
            (string) $client["client_id"]
        );
        $upgradedHash = null;
        if (oidc_verify_client_auth($client, $clientSecret, $upgradedHash)) {
            // A correct secret (one shorter than 32 characters is never upgraded and stays
            // on this path) clears its client's budget for this network, but gives back
            // only its own attempt in the budget that every client calling from the
            // network shares: what wrong secrets for other clients used up stays counted.
            try {
                rate_limit_clear($storePath, $clientNetworkBucket);
            } catch (Throwable $e) {
                error_log("oidc: could not clear a legacy client secret budget: " . $e->getMessage());
            }
            oidc_release_rate_limit_attempt($storePath, $networkBucket);
            if ($upgradedHash !== null) {
                // Compare-and-swap, so a concurrent rotation is never overwritten.
                try {
                    oidc_db($storePath)
                        ->prepare(
                            "UPDATE oidc_clients SET client_secret_hash = :new " .
                                "WHERE id = :id AND client_secret_hash = :old"
                        )
                        ->execute([
                            ":new" => $upgradedHash,
                            ":id" => (string) $client["id"],
                            ":old" => $storedHash,
                        ]);
                } catch (Throwable $e) {
                    error_log("oidc: could not upgrade a client secret digest: " . $e->getMessage());
                }
            }
            return $client;
        }
    }

    // Only a failed check reaches the failure lockouts.
    if (
        rate_limit_is_blocked($storePath, $clientBucket) ||
        rate_limit_is_blocked($storePath, $ipBucket)
    ) {
        if (!headers_sent()) {
            header("Retry-After: 300");
        }
        json_response(429, [
            "error" => "too_many_requests",
            "error_description" => "Too many failed client authentication attempts; try again later",
        ]);
    }
    oidc_record_token_auth_failure($storePath, [
        $clientBucket => 10,
        $ipBucket => 20,
    ]);
    json_response(401, $failed);
}

/**
 * Atomically consumes a single-use OIDC authorization code inside a write lock.
 * With $clientId, only a code issued to that client is matched and consumed.
 */
function oidc_consume_auth_code_atomic(
    string $storePath,
    string $providerId,
    string $code,
    ?string $clientId = null
): ?array {
    $pdo = oidc_db($storePath);
    $sql = "SELECT * FROM oidc_auth_codes WHERE code = :c AND provider_id = :pid";
    $args = [":c" => $code, ":pid" => $providerId];
    if ($clientId !== null) {
        $sql .= " AND client_id = :cid";
        $args[":cid"] = $clientId;
    }
    $pdo->exec("BEGIN IMMEDIATE");
    try {
        $stmt = $pdo->prepare($sql . " LIMIT 1");
        $stmt->execute($args);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        $stmt->closeCursor();
        if ($row) {
            $del = $pdo->prepare(
                "DELETE FROM oidc_auth_codes WHERE code = :c AND provider_id = :pid"
            );
            $del->execute([":c" => $code, ":pid" => $providerId]);
        }
        $pdo->exec("COMMIT");
        return $row ?: null;
    } catch (Throwable $e) {
        oidc_rollback_quietly($pdo);
        throw $e;
    }
}

function oidc_burn_auth_code(PDO $pdo, string $providerId, string $code): void
{
    try {
        $pdo->prepare(
            "DELETE FROM oidc_auth_codes WHERE code = :c AND provider_id = :pid"
        )->execute([":c" => $code, ":pid" => $providerId]);
    } catch (Throwable $e) {
        error_log("oidc: could not delete a rejected authorization code: " . $e->getMessage());
    }
}

/**
 * Ends a failed token-endpoint write transaction: rolls back, so the code or
 * refresh token that was being consumed stays usable, and answers 503 for storage
 * errors (for example the database stayed locked past busy_timeout).
 */
function oidc_fail_token_transaction(PDO $pdo, Throwable $e): never
{
    oidc_rollback_quietly($pdo);
    if ($e instanceof PDOException) {
        error_log("oidc token endpoint: storage error: " . $e->getMessage());
        json_response(503, [
            "error" => "temporarily_unavailable",
            "error_description" => "The request could not be completed; retry it",
        ]);
    }
    throw $e;
}

function oidc_audit_refresh_failure(
    string $storePath,
    array $provider,
    array $client,
    string $userId,
    string $eventType,
    array $amr,
    array $details
): void {
    try {
        $user = $userId !== ""
            ? directory_get_user_by_id($storePath, $userId, $provider["owner"])
            : null;
        audit_log_append(
            $storePath,
            (string) $provider["id"],
            "oidc",
            $eventType,
            "error",
            (string) ($client["name"] ?? ""),
            (string) ($user["username"] ?? ""),
            $amr,
            ["client_id" => (string) $client["client_id"]] + $details
        );
    } catch (Throwable $e) {
        error_log("oidc: could not audit a refresh_token failure: " . $e->getMessage());
    }
}

function oidc_token_grant_authorization_code(
    string $storePath,
    array &$providers,
    array &$provider,
    string $baseUrl,
    string $keysDir,
    array $client,
    array $postParams
): never {
    $pdo = oidc_db($storePath);
    $providerId = (string) $provider["id"];
    $code = trim((string) ($postParams["code"] ?? ""));
    $redirectUri = trim((string) ($postParams["redirect_uri"] ?? ""));
    $codeVerifier = trim((string) ($postParams["code_verifier"] ?? ""));

    if (!oidc_client_has_grant($client, "authorization_code")) {
        json_response(400, [
            "error" => "unauthorized_client",
            "error_description" => "The authorization_code grant is not enabled for this client",
        ]);
    }
    if ($code === "") {
        json_response(400, [
            "error" => "invalid_request",
            "error_description" => "Missing authorization code",
        ]);
    }

    // Read the code without consuming it. The tokens are signed first and the code
    // is consumed in the transaction that stores them, so a failed write leaves the
    // code usable for a retry and a concurrent redemption is refused.
    $stmt = $pdo->prepare(
        "SELECT * FROM oidc_auth_codes WHERE code = :c AND provider_id = :pid LIMIT 1"
    );
    $stmt->execute([":c" => $code, ":pid" => $providerId]);
    $codeRow = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt->closeCursor();

    if (!$codeRow || (int) $codeRow["expires_at"] < time()) {
        json_response(400, [
            "error" => "invalid_grant",
            "error_description" => "Authorization code invalid or expired",
        ]);
    }
    if ((string) $codeRow["client_id"] !== (string) $client["client_id"]) {
        // Another client cannot burn this client's code.
        json_response(400, [
            "error" => "invalid_grant",
            "error_description" => "Code was issued to a different client",
        ]);
    }

    // From here on every rejection also burns the code.
    $storedRedirect = (string) ($codeRow["redirect_uri"] ?? "");
    $redirectWasSupplied = (int) ($codeRow["redirect_uri_supplied"] ?? 1) === 1;
    if (
        $storedRedirect !== "" &&
        ($redirectWasSupplied || $redirectUri !== "") &&
        $redirectUri !== $storedRedirect
    ) {
        oidc_burn_auth_code($pdo, $providerId, $code);
        json_response(400, [
            "error" => "invalid_grant",
            "error_description" => "Missing or mismatched redirect_uri",
        ]);
    }

    $storedChallenge = (string) ($codeRow["code_challenge"] ?? "");
    $pkceStrict = !oidc_legacy_oauth_flows();
    if ($pkceStrict && $storedChallenge === "" && $codeVerifier !== "") {
        // PKCE downgrade (RFC 9700 section 2.1.1): the client holds a verifier, so it
        // sent a code_challenge, but this code was issued without one. It was
        // obtained from an authorization request the client did not make.
        oidc_burn_auth_code($pdo, $providerId, $code);
        json_response(400, [
            "error" => "invalid_grant",
            "error_description" => "code_verifier sent for a code that was issued without a code_challenge",
        ]);
    }
    if ($storedChallenge !== "" || !empty($client["require_pkce"])) {
        if ($codeVerifier === "") {
            oidc_burn_auth_code($pdo, $providerId, $code);
            json_response(400, [
                "error" => "invalid_grant",
                "error_description" => "Missing PKCE code_verifier",
            ]);
        }
        if (
            $pkceStrict &&
            preg_match('/^[A-Za-z0-9._~-]{43,128}$/D', $codeVerifier) !== 1
        ) {
            // RFC 7636 section 4.1.
            oidc_burn_auth_code($pdo, $providerId, $code);
            json_response(400, [
                "error" => "invalid_grant",
                "error_description" => "Malformed code_verifier: use 43 to 128 characters from A-Z, a-z, 0-9 and -._~",
            ]);
        }
        $method = (string) ($codeRow["code_challenge_method"] ?? "plain");
        $computed =
            $method === "S256"
                ? base64url_encode(hash("sha256", $codeVerifier, true))
                : $codeVerifier;
        if (!hash_equals($storedChallenge, $computed)) {
            oidc_burn_auth_code($pdo, $providerId, $code);
            json_response(400, [
                "error" => "invalid_grant",
                "error_description" => "PKCE code_verifier check failed",
            ]);
        }
    }

    $user = directory_get_user_by_id(
        $storePath,
        (string) $codeRow["user_id"],
        $provider["owner"]
    );
    if (!$user || ($user["status"] ?? "active") !== "active") {
        oidc_burn_auth_code($pdo, $providerId, $code);
        json_response(400, [
            "error" => "invalid_grant",
            "error_description" => "User inactive or deleted",
        ]);
    }

    $amr = json_decode((string) ($codeRow["amr_json"] ?? "[]"), true) ?: [
        "pwd",
    ];
    $authTime = (int) $codeRow["auth_time"];
    $sessionRef = (string) ($codeRow["sid"] ?? "");
    $built = oidc_build_token_bundle(
        $storePath,
        $providers,
        $provider,
        $baseUrl,
        $client,
        $user,
        (string) $codeRow["scope"],
        (string) ($codeRow["nonce"] ?? ""),
        $amr,
        $authTime,
        true,
        $keysDir,
        oidc_new_token_family($authTime, $sessionRef !== "" ? $sessionRef : null)
    );

    try {
        $pdo->exec("BEGIN IMMEDIATE");
        $codeArgs = [
            ":c" => $code,
            ":pid" => $providerId,
            ":cid" => (string) $client["client_id"],
        ];
        $cur = $pdo->prepare(
            "SELECT sid FROM oidc_auth_codes WHERE code = :c AND provider_id = :pid AND client_id = :cid LIMIT 1"
        );
        $cur->execute($codeArgs);
        $currentSessionRef = $cur->fetchColumn();
        $cur->closeCursor();
        $del = $pdo->prepare(
            "DELETE FROM oidc_auth_codes WHERE code = :c AND provider_id = :pid AND client_id = :cid"
        );
        $del->execute($codeArgs);
        if ($del->rowCount() !== 1) {
            // Redeemed (or revoked) by a concurrent request.
            $pdo->exec("ROLLBACK");
            json_response(400, [
                "error" => "invalid_grant",
                "error_description" => "Authorization code invalid or expired",
            ]);
        }
        oidc_store_token_rows(
            $pdo,
            oidc_bind_token_rows_to_session($built["rows"], $currentSessionRef)
        );
        $pdo->exec("COMMIT");
    } catch (Throwable $e) {
        oidc_fail_token_transaction($pdo, $e);
    }

    oidc_after_token_issue($storePath, $providers, $provider);
    audit_log_append(
        $storePath,
        $providerId,
        "oidc",
        "token_exchange",
        "success",
        $client["name"],
        $user["username"],
        $amr,
        ["grant_type" => "authorization_code"]
    );
    oidc_purge_expired($pdo);

    json_response(200, $built["response"]);
}

/**
 * refresh_token grant with rotation and reuse detection (RFC 9700 section 4.14.2).
 * A used refresh token is kept as a consumed tombstone; presenting it again revokes
 * its whole family. Each refresh re-checks that the user is active, the client
 * still has the refresh_token grant (unless legacy_oauth_flows), the user is in
 * the client's assigned groups and the stored amr satisfies the client's
 * effective sign-on policy; a failure revokes the family. Refreshed ID tokens keep
 * the family's original auth_time (OIDC Core section 12.2), and a family ends 90
 * days after the user signed in.
 */
function oidc_token_grant_refresh_token(
    string $storePath,
    array &$providers,
    array &$provider,
    string $baseUrl,
    string $keysDir,
    array $client,
    array $postParams
): never {
    $pdo = oidc_db($storePath);
    $providerId = (string) $provider["id"];
    $rt = trim((string) ($postParams["refresh_token"] ?? ""));
    if ($rt === "") {
        json_response(400, [
            "error" => "invalid_request",
            "error_description" => "Missing refresh_token",
        ]);
    }
    $tokenHash = hash("sha256", $rt);
    $invalid = [
        "error" => "invalid_grant",
        "error_description" => "Invalid or expired refresh_token",
    ];

    $stmt = $pdo->prepare(
        "SELECT * FROM oidc_tokens WHERE token_hash = :th AND token_type = 'refresh' AND provider_id = :pid LIMIT 1"
    );
    $stmt->execute([":th" => $tokenHash, ":pid" => $providerId]);
    $tokRow = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt->closeCursor();

    // Another client's token is refused without touching it.
    if (!$tokRow || (string) $tokRow["client_id"] !== (string) $client["client_id"]) {
        json_response(400, $invalid);
    }

    $now = time();
    $storedFamilyId = (string) ($tokRow["family_id"] ?? "");
    $userId = (string) ($tokRow["user_id"] ?? "");

    if (($tokRow["consumed_at"] ?? null) !== null) {
        // A rotated refresh token came back: it was copied. Revoke the family, so
        // neither the thief nor the legitimate client can continue it.
        oidc_revoke_token_family($pdo, $providerId, $storedFamilyId, $tokenHash);
        oidc_audit_refresh_failure($storePath, $provider, $client, $userId, "refresh_token_reuse", [], [
            "family_id" => $storedFamilyId,
        ]);
        json_response(400, $invalid);
    }

    $familyId = $storedFamilyId;
    $familyExpiresAt = (int) ($tokRow["family_expires_at"] ?? 0);
    $authTime = (int) ($tokRow["auth_time"] ?? 0);
    if ($familyId === "") {
        // Issued before token families existed: it starts one now. Its sign-in time
        // is unknown; the time it was minted (expiry minus the 30-day lifetime) is
        // the closest value that is not newer than what the client already saw.
        $familyId = uuidv4();
        $familyExpiresAt = $now + OIDC_REFRESH_FAMILY_MAX_LIFETIME;
        $authTime = (int) $tokRow["expires_at"] - OIDC_REFRESH_TOKEN_TTL;
    }
    if ($authTime <= 0 || $authTime > $now) {
        $authTime = $now;
    }

    if ((int) $tokRow["expires_at"] < $now || $familyExpiresAt < $now) {
        oidc_revoke_token_family($pdo, $providerId, $storedFamilyId, $tokenHash);
        json_response(400, $invalid);
    }

    $user = directory_get_user_by_id($storePath, $userId, $provider["owner"]);
    $amr = json_decode((string) ($tokRow["amr_json"] ?? "[]"), true);
    if (!is_array($amr) || $amr === []) {
        $amr = ["pwd"];
    }

    $denyReason = null;
    if (!$user || ($user["status"] ?? "active") !== "active") {
        $denyReason = "user_inactive";
    } elseif (!oidc_client_has_grant($client, "refresh_token")) {
        $denyReason = "refresh_token_grant_not_allowed";
    } elseif (
        !directory_user_matches_assigned_groups(
            $user,
            (array) ($client["assigned_groups"] ?? [])
        )
    ) {
        $denyReason = "not_in_assigned_groups";
    } elseif (!auth_policy_satisfied(effective_auth_policy($provider, $client), $amr)) {
        $denyReason = "auth_policy_not_satisfied";
    }
    if ($denyReason !== null) {
        oidc_revoke_token_family($pdo, $providerId, $storedFamilyId, $tokenHash);
        oidc_audit_refresh_failure($storePath, $provider, $client, $userId, "refresh_denied", $amr, [
            "reason" => $denyReason,
        ]);
        json_response(400, [
            "error" => "invalid_grant",
            "error_description" => "The refresh token is no longer valid for this client",
        ]);
    }

    $sessionRef = (string) ($tokRow["sid"] ?? "");
    $family = [
        "id" => $familyId,
        "expires_at" => $familyExpiresAt,
        "auth_time" => $authTime,
        "sid" => $sessionRef !== "" ? $sessionRef : null,
    ];
    $built = oidc_build_token_bundle(
        $storePath,
        $providers,
        $provider,
        $baseUrl,
        $client,
        $user,
        (string) $tokRow["scope"],
        "",
        $amr,
        $authTime,
        true,
        $keysDir,
        $family
    );

    try {
        $pdo->exec("BEGIN IMMEDIATE");
        $cur = $pdo->prepare(
            "SELECT consumed_at, family_id, sid FROM oidc_tokens " .
                "WHERE token_hash = :th AND token_type = 'refresh' AND provider_id = :pid LIMIT 1"
        );
        $cur->execute([":th" => $tokenHash, ":pid" => $providerId]);
        $current = $cur->fetch(PDO::FETCH_ASSOC);
        $cur->closeCursor();
        if (!$current) {
            // Revoked or rotated away by a concurrent request.
            $pdo->exec("ROLLBACK");
            json_response(400, $invalid);
        }
        if (($current["consumed_at"] ?? null) !== null) {
            // Used by a concurrent request: the same token was presented twice.
            $raceFamilyId = (string) ($current["family_id"] ?? "");
            oidc_revoke_token_family($pdo, $providerId, $raceFamilyId, $tokenHash);
            $pdo->exec("COMMIT");
            oidc_audit_refresh_failure($storePath, $provider, $client, $userId, "refresh_token_reuse", $amr, [
                "family_id" => $raceFamilyId,
            ]);
            json_response(400, $invalid);
        }
        // Keep the used token as a tombstone of its family for reuse detection.
        $upd = $pdo->prepare(
            "UPDATE oidc_tokens SET consumed_at = :now, family_id = :fid, family_expires_at = :fexp, auth_time = :at " .
                "WHERE token_hash = :th AND consumed_at IS NULL"
        );
        $upd->execute([
            ":now" => $now,
            ":fid" => $familyId,
            ":fexp" => $familyExpiresAt,
            ":at" => $authTime,
            ":th" => $tokenHash,
        ]);
        oidc_store_token_rows(
            $pdo,
            oidc_bind_token_rows_to_session($built["rows"], $current["sid"] ?? null)
        );
        $pdo->exec("COMMIT");
    } catch (Throwable $e) {
        oidc_fail_token_transaction($pdo, $e);
    }

    oidc_after_token_issue($storePath, $providers, $provider);
    oidc_purge_expired($pdo);
    json_response(200, $built["response"]);
}

/**
 * client_credentials grant (RFC 6749 section 4.4), for confidential clients that are
 * registered for it (any confidential client with legacy_oauth_flows). The scope
 * must use RFC 6749 scope syntax; there is no per-client scope allowlist. The access
 * token follows RFC 9068 (sub = client_id, aud = the issuer, typ at+jwt) unless
 * legacy_token_claims is on.
 */
function oidc_token_grant_client_credentials(
    string $storePath,
    array &$providers,
    array &$provider,
    string $baseUrl,
    string $keysDir,
    array $client,
    array $postParams
): never {
    if (!empty($client["is_public"])) {
        json_response(400, [
            "error" => "unauthorized_client",
            "error_description" =>
                "Public clients cannot use client_credentials grant",
        ]);
    }
    if (!oidc_client_has_grant($client, "client_credentials")) {
        json_response(400, [
            "error" => "unauthorized_client",
            "error_description" => "The client_credentials grant is not enabled for this client",
        ]);
    }
    $scope = oidc_normalize_requested_scope((string) ($postParams["scope"] ?? ""));
    if ($scope === null) {
        json_response(400, [
            "error" => "invalid_scope",
            "error_description" => "scope must be space-separated scope tokens (RFC 6749 section 3.3), at most 1024 characters",
        ]);
    }

    $pdo = oidc_db($storePath);
    $keyToUse = oidc_resolve_signing_key($storePath, $providers, $provider, $keysDir);
    $now = time();
    $ttl = max(60, (int) ($client["access_token_ttl"] ?? 3600));
    $issuer = $baseUrl . "/" . $provider["idp_id"];
    $legacyClaims = oidc_legacy_token_claims();

    $claims = array_merge(
        oidc_filter_custom_claims(
            (array) ($client["custom_claims"] ?? []),
            $legacyClaims ? OIDC_RESERVED_CLAIMS : OIDC_PROTECTED_CLAIMS
        ),
        [
            "iss" => $issuer,
            "sub" => $client["client_id"],
            "aud" => $legacyClaims ? $client["client_id"] : $issuer,
            "client_id" => $client["client_id"],
            "scope" => $scope,
            "iat" => $now,
            "nbf" => $now,
            "exp" => $now + $ttl,
            "jti" => uuidv4(),
        ]
    );
    $accessToken = oidc_sign_access_token($keyToUse, $claims);
    oidc_record_signed_token_exp($storePath, $provider, $keyToUse, $now + $ttl);

    try {
        $insTok = $pdo->prepare(
            "INSERT INTO oidc_tokens (token_hash, token_type, provider_id, client_id, user_id, scope, amr_json, expires_at) " .
                "VALUES (:th, 'access', :pid, :cid, NULL, :sc, '[\"client_secret\"]', :exp)"
        );
        $insTok->execute([
            ":th" => hash("sha256", $accessToken),
            ":pid" => $provider["id"],
            ":cid" => $client["client_id"],
            ":sc" => $scope,
            ":exp" => $now + $ttl,
        ]);
    } catch (Throwable $e) {
        oidc_fail_token_transaction($pdo, $e);
    }
    // Client-credentials-only deployments would otherwise never purge.
    oidc_purge_expired($pdo);

    json_response(200, [
        "access_token" => $accessToken,
        "token_type" => "Bearer",
        "expires_in" => $ttl,
        "scope" => $scope,
    ]);
}

/**
 * Normalizes a requested scope: space-separated scope tokens of printable ASCII
 * without '"' and '\' (RFC 6749 section 3.3), at most 1024 bytes, duplicates
 * removed. "" stays "". Returns null when the scope is invalid.
 */
function oidc_normalize_requested_scope(string $scope): ?string
{
    $scope = trim($scope);
    if ($scope === "") {
        return "";
    }
    if (strlen($scope) > 1024) {
        return null;
    }
    $tokens = [];
    foreach (oidc_scope_list($scope) as $token) {
        if (preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/D', $token) !== 1) {
            return null;
        }
        if (!in_array($token, $tokens, true)) {
            $tokens[] = $token;
        }
    }
    return implode(" ", $tokens);
}

/**
 * Token request parameters: the form body, or a JSON object body. Only string-keyed
 * scalar values are kept, as strings, so a JSON scalar or list, or an array
 * parameter such as grant_type[]=x, counts as missing instead of causing a
 * TypeError (HTTP 500) or an array-to-string conversion.
 */
function oidc_read_token_request_params(): array
{
    $params = $_POST;
    if (empty($params)) {
        $raw = file_get_contents("php://input", false, null, 0, 131072) ?: "";
        $ct = strtolower((string) ($_SERVER["CONTENT_TYPE"] ?? ""));
        if (str_contains($ct, "application/json")) {
            $decoded = json_decode($raw, true, 16);
            $params = is_array($decoded) ? $decoded : [];
        } else {
            parse_str($raw, $params);
        }
    }
    $out = [];
    foreach ($params as $name => $value) {
        if (is_string($name) && is_scalar($value)) {
            $out[$name] = (string) $value;
        }
    }
    return $out;
}

function oidc_handle_oauth2_token(
    string $storePath,
    array &$providers,
    array &$provider,
    string $baseUrl,
    string $keysDir = ""
): never {
    send_oidc_cors_headers();
    // Applies pending OIDC migrations before any transaction is opened.
    oidc_db($storePath);

    $postParams = oidc_read_token_request_params();

    $grantType = trim((string) ($postParams["grant_type"] ?? ""));
    [$clientId, $clientSecret] = oidc_extract_client_credentials($postParams);

    if ($clientId === "") {
        json_response(401, [
            "error" => "invalid_client",
            "error_description" => "Missing client_id",
        ]);
    }
    $client = oidc_authenticate_token_client(
        $storePath,
        $provider,
        $clientId,
        $clientSecret
    );

    if ($grantType === "authorization_code") {
        oidc_token_grant_authorization_code(
            $storePath,
            $providers,
            $provider,
            $baseUrl,
            $keysDir,
            $client,
            $postParams
        );
    }

    if ($grantType === "refresh_token") {
        oidc_token_grant_refresh_token(
            $storePath,
            $providers,
            $provider,
            $baseUrl,
            $keysDir,
            $client,
            $postParams
        );
    }

    if ($grantType === "client_credentials") {
        oidc_token_grant_client_credentials(
            $storePath,
            $providers,
            $provider,
            $baseUrl,
            $keysDir,
            $client,
            $postParams
        );
    }

    json_response(400, [
        "error" => "unsupported_grant_type",
        "error_description" => "Unsupported grant_type: $grantType",
    ]);
}

function oidc_handle_userinfo(string $storePath, array $provider): never
{
    send_oidc_cors_headers();

    $auth = get_auth_header();
    $bearer = "";
    if (preg_match('/^\s*Bearer\s+(\S+)\s*$/i', $auth, $m)) {
        $bearer = $m[1];
    } elseif (is_string($_POST["access_token"] ?? null)) {
        $bearer = trim($_POST["access_token"]);
    }

    $invalidToken = static function (): never {
        if (!headers_sent()) {
            header('WWW-Authenticate: Bearer error="invalid_token"');
        }
        json_response(401, ["error" => "invalid_token"]);
    };

    if ($bearer === "") {
        $invalidToken();
    }

    $pdo = oidc_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM oidc_tokens WHERE token_hash = :th AND token_type = 'access' AND provider_id = :pid LIMIT 1"
    );
    $stmt->execute([
        ":th" => hash("sha256", $bearer),
        ":pid" => $provider["id"],
    ]);
    $tokRow = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt->closeCursor();

    if (!$tokRow || (int) $tokRow["expires_at"] < time()) {
        $invalidToken();
    }

    // A token is only as good as its client: once the client is deleted (or its
    // client_id changed), its tokens stop working here too.
    $client = oidc_find_client_by_client_id(
        $storePath,
        (string) $provider["id"],
        (string) $tokRow["client_id"]
    );
    if (!$client) {
        $invalidToken();
    }

    if (empty($tokRow["user_id"])) {
        json_response(200, ["sub" => $tokRow["client_id"]]);
    }

    $user = directory_get_user_by_id(
        $storePath,
        (string) $tokRow["user_id"],
        $provider["owner"]
    );
    if (!$user || ($user["status"] ?? "active") !== "active") {
        $invalidToken();
    }

    $claims = oidc_build_user_profile_claims(
        $user,
        (string) $tokRow["scope"],
        (array) ($client["custom_claims"] ?? [])
    );
    json_response(200, $claims);
}
