<?php
declare(strict_types=1);

const SAML_NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata";
const SAML_NS_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_NS_ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAML_NS_DS = "http://www.w3.org/2000/09/xmldsig#";
const SAML_NS_XENC = "http://www.w3.org/2001/04/xmlenc#";
const SAML_NS_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

const SAML_BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
const SAML_BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

const SAML_STATUS_PREFIX = "urn:oasis:names:tc:SAML:2.0:status:";

// Canonicalization algorithms accepted in signatures: [exclusive, with comments].
const SAML_C14N_ALGORITHMS = [
    "http://www.w3.org/2001/10/xml-exc-c14n#" => [true, false],
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments" => [true, true],
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" => [false, false],
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments" => [false, true],
];

// NameID formats (SAML Core 8.3). SAML_IDP_NAMEID_FORMATS are the ones this IdP can produce.
const SAML_NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const SAML_NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
const SAML_NAMEID_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const SAML_NAMEID_TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
const SAML_IDP_NAMEID_FORMATS = [
    SAML_NAMEID_EMAIL,
    SAML_NAMEID_UNSPECIFIED,
    SAML_NAMEID_PERSISTENT,
    SAML_NAMEID_TRANSIENT,
];

// XML Encryption block ciphers for <EncryptedAssertion> (see saml_encryption_cipher()).
const SAML_ENC_AES128_CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
const SAML_ENC_AES192_CBC = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
const SAML_ENC_AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
const SAML_ENC_AES128_GCM = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
const SAML_ENC_AES192_GCM = "http://www.w3.org/2009/xmlenc11#aes192-gcm";
const SAML_ENC_AES256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
// New apps; apps stored before encryption_alg was always written keep AES-256-CBC.
const SAML_ENC_DEFAULT = SAML_ENC_AES256_GCM;

// Incoming protocol messages: size cap of the decoded XML, IssueInstant freshness
// (maximum age plus clock skew, in seconds) and how long request IDs are kept for replay checks.
const SAML_MAX_MESSAGE_BYTES = 65536;
const SAML_REQUEST_MAX_AGE = 300;
const SAML_CLOCK_SKEW = 60;
const SAML_REPLAY_TTL = 900;

// Structure limits of an incoming request (AuthnRequest, LogoutRequest), checked by
// saml_xml_structure_error() before libxml2 parses it (G1c-01). Real requests stay far below
// them (a signed AuthnRequest has about 20 elements, 40 attributes and 5 namespace
// declarations). At these limits, parsing and the XML-DSig canonicalization of the request
// stay at tens of milliseconds even on libxml2 2.9. That canonicalization grows with elements
// times namespaces in scope. Nodes are elements, comments, processing instructions and CDATA
// sections. Attribute counts include namespace declarations, and the default namespace counts
// as a prefix.
const SAML_MESSAGE_LIMITS = [
    "nodes" => 256,
    "depth" => 32,
    "element_attributes" => 64,
    "attributes" => 512,
    "namespace_declarations" => 64,
    "namespace_prefixes" => 16,
];

// AuthnContextClassRef values this IdP asserts (see saml_authn_class_for_rank()).
const SAML_AC_UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
const SAML_AC_PASSWORD_PROTECTED_TRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
const SAML_AC_PASSKEY = "urn:idp:acr:phishing-resistant";
const SAML_AC_REFEDS_MFA = "https://refeds.org/profile/mfa";

/**
 * A SAML request that has to be answered with a non-success <samlp:Status> posted to the
 * SP's ACS (see saml_build_status_response()) instead of an assertion. statusCode and
 * subStatusCode hold full status URNs (short names such as "Responder" are expanded).
 * authnRequest is the parsed AuthnRequest being answered, when the thrower had it (pass it
 * as $authnReq to saml_build_status_response() for InResponseTo and the ACS).
 */
final class SamlStatusError extends RuntimeException
{
    public readonly string $statusCode;
    public readonly string $subStatusCode;
    public readonly ?array $authnRequest;

    public function __construct(
        string $statusCode,
        string $subStatusCode = "",
        string $message = "",
        ?Throwable $previous = null,
        ?array $authnRequest = null
    ) {
        $this->authnRequest = $authnRequest;
        $this->statusCode = saml_status_code_uri($statusCode) ?? $statusCode;
        $this->subStatusCode =
            $subStatusCode === ""
                ? ""
                : (saml_status_code_uri($subStatusCode) ?? $subStatusCode);
        parent::__construct(
            $message !== "" ? $message : "The SAML request cannot be fulfilled",
            0,
            $previous
        );
    }
}

/**
 * Expands a SAML 2.0 status code ("Responder" or its full URN) to the full URN, or returns
 * null when it is not a status code defined by SAML Core 3.2.2.2.
 */
function saml_status_code_uri(string $code): ?string
{
    $known = [
        "Success", "Requester", "Responder", "VersionMismatch",
        "AuthnFailed", "InvalidAttrNameOrValue", "InvalidNameIDPolicy", "NoAuthnContext",
        "NoAvailableIDP", "NoPassive", "NoSupportedIDP", "PartialLogout",
        "ProxyCountExceeded", "RequestDenied", "RequestUnsupported",
        "RequestVersionDeprecated", "RequestVersionTooHigh", "RequestVersionTooLow",
        "ResourceNotRecognized", "TooManyResponses", "UnknownAttrProfile",
        "UnknownPrincipal", "UnsupportedBinding",
    ];
    $name = trim($code);
    if (str_starts_with($name, SAML_STATUS_PREFIX)) {
        $name = substr($name, strlen(SAML_STATUS_PREFIX));
    }
    return in_array($name, $known, true) ? SAML_STATUS_PREFIX . $name : null;
}

/**
 * Compatibility flag legacy_saml_compat (env OIDC_LEGACY_SAML_COMPAT, default off), read on
 * every use. When on, the old interop behavior returns: the AuthnContextClassRef is always
 * PasswordProtectedTransport and RequestedAuthnContext is ignored; any requested NameIDPolicy
 * Format is honored when the app's supported list is empty (and a configured or requested
 * emailAddress format may carry a non-email value); AuthnRequests get no ID-presence,
 * Version, IssueInstant, replay, Destination-presence, ProtocolBinding or ACS-index checks,
 * and an unknown AssertionConsumerServiceIndex falls back to the default ACS. AuthnInstant and
 * SessionNotOnOrAfter stay accurate either way.
 */
function saml_legacy_compat(): bool
{
    return config_flag("legacy_saml_compat", "OIDC_LEGACY_SAML_COMPAT");
}

/**
 * Compatibility flag legacy_saml_persistent_ids (env OIDC_LEGACY_SAML_PERSISTENT_IDS, default
 * off), read on every use (S02-10). Off: every app's persistent NameIDs are keyed per provider
 * ("hmac"), whatever its stored persistent_id_scheme. On: apps whose persistent_id_scheme is
 * "legacy" keep the unkeyed hash, which anyone who knows a user's id can compute for every SP.
 * Apps saved before keyed identifiers existed are marked "legacy". The flag lets their SPs keep
 * the identifiers they already know until each app is switched to "hmac" (which gives every
 * user a new NameID at that SP).
 */
function saml_legacy_persistent_ids(): bool
{
    return config_flag("legacy_saml_persistent_ids", "OIDC_LEGACY_SAML_PERSISTENT_IDS");
}

/**
 * The SQLite store for SAML state: $storePath when given, else the global $PROVIDERS_FILE
 * set up by bootstrap.php, so callers written before the optional parameter keep working.
 */
function saml_store_path(?string $storePath = null): string
{
    if ($storePath !== null && $storePath !== "") {
        return $storePath;
    }
    $global = $GLOBALS["PROVIDERS_FILE"] ?? null;
    if (is_string($global) && $global !== "") {
        return $global;
    }
    throw new RuntimeException("The SAML data store is not configured");
}

// ---------- SAML App Persistence ----------

/**
 * storage_db() plus this lane's additive schema migrations. schema_ensure() refuses to run
 * inside a transaction, so a pending migration is applied by the next call made outside one.
 */
function saml_db(string $storePath): PDO
{
    $pdo = storage_db($storePath);
    if (!$pdo->inTransaction()) {
        schema_ensure($pdo, "saml.entity_id_unique_v1", [
            static function (PDO $db): void {
                saml_create_entity_id_index_if_unique($db);
            },
        ]);
        // Persistent NameIDs: apps saved before keyed pairwise IDs existed are marked "legacy",
        // so the legacy_saml_persistent_ids flag can keep the unkeyed values their SPs already
        // know (see saml_persistent_name_id()). saml_save_app() stores "hmac" for new apps.
        schema_ensure($pdo, "saml.persistent_id_v1", [
            "ALTER TABLE saml_apps ADD COLUMN persistent_id_scheme TEXT NOT NULL DEFAULT 'legacy'",
            "CREATE TABLE IF NOT EXISTS saml_pairwise_secrets (" .
                "provider_id TEXT PRIMARY KEY, secret TEXT NOT NULL, created_at TEXT NOT NULL, " .
                "FOREIGN KEY(provider_id) REFERENCES providers(id) ON DELETE CASCADE)",
        ]);
        schema_ensure($pdo, "saml.request_replay_v1", [
            "CREATE TABLE IF NOT EXISTS saml_request_replay (" .
                "replay_key TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)",
            "CREATE INDEX IF NOT EXISTS idx_saml_request_replay_expires ON saml_request_replay(expires_at)",
        ]);
        // The SP's SLO endpoint besides slo_url (S02-05): its Binding ("" means HTTP-POST, as
        // for apps saved before) and its ResponseLocation ("": LogoutResponses go to slo_url).
        schema_ensure($pdo, "saml.slo_endpoint_v1", [
            "ALTER TABLE saml_apps ADD COLUMN slo_binding TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE saml_apps ADD COLUMN slo_response_url TEXT NOT NULL DEFAULT ''",
        ]);
    }
    return $pdo;
}

/**
 * The per-provider key of keyed ("hmac") persistent NameIDs: 32 random bytes created on
 * first use and kept in saml_pairwise_secrets. It does not depend on the Host header, the
 * base URL or the vault key, so the identifiers stay stable. A stored value that is not a
 * valid key is an error (replacing it would silently re-key every SP account).
 */
function saml_pairwise_secret(string $storePath, string $providerId): string
{
    static $cache = [];
    $cacheKey = $storePath . "\0" . $providerId;
    if (isset($cache[$cacheKey])) {
        return $cache[$cacheKey];
    }
    if ($providerId === "") {
        throw new RuntimeException("Persistent NameIDs need the provider id");
    }
    $pdo = saml_db($storePath);
    $select = $pdo->prepare("SELECT secret FROM saml_pairwise_secrets WHERE provider_id = :pid");
    $select->execute([":pid" => $providerId]);
    $hex = $select->fetchColumn();
    $select->closeCursor();
    if ($hex === false) {
        // Concurrent first uses race on the primary key; every caller reads back the winner.
        $pdo->prepare(
            "INSERT OR IGNORE INTO saml_pairwise_secrets (provider_id, secret, created_at) VALUES (:pid, :s, :at)"
        )->execute([
            ":pid" => $providerId,
            ":s" => bin2hex(random_bytes(32)),
            ":at" => gmdate("Y-m-d\TH:i:s\Z"),
        ]);
        $select->execute([":pid" => $providerId]);
        $hex = $select->fetchColumn();
        $select->closeCursor();
    }
    if (!is_string($hex) || strlen($hex) !== 64 || !ctype_xdigit($hex)) {
        throw new RuntimeException("The persistent NameID key of this identity provider is unreadable");
    }
    return $cache[$cacheKey] = (string) hex2bin($hex);
}

/**
 * Replay check for signature-verified requests (SAML Profiles 4.1.4.1): records the request
 * ID of $issuer at $providerId for SAML_REPLAY_TTL seconds and throws RuntimeException when
 * it was already recorded. Unsigned requests are not recorded: anyone can mint a fresh ID for
 * them, so a replay cache would protect nothing and only grow with unauthenticated traffic.
 */
function saml_record_request_id(
    string $storePath,
    string $providerId,
    string $issuer,
    string $requestId
): void {
    $material = json_encode(
        [$providerId, $issuer, $requestId],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
    );
    if (!is_string($material)) {
        throw new RuntimeException("Cannot record the SAML request ID");
    }
    $now = time();
    $pdo = saml_db($storePath);
    $pdo->prepare("DELETE FROM saml_request_replay WHERE expires_at < :now")->execute([":now" => $now]);
    $insert = $pdo->prepare(
        "INSERT OR IGNORE INTO saml_request_replay (replay_key, expires_at) VALUES (:k, :exp)"
    );
    $insert->execute([":k" => hash("sha256", $material), ":exp" => $now + SAML_REPLAY_TTL]);
    if ($insert->rowCount() !== 1) {
        throw new RuntimeException(
            "This SAML request was already used (replay); start the sign-in again at the service provider"
        );
    }
}

/**
 * Creates the UNIQUE (provider_id, sp_entity_id) index unless duplicates saved before
 * uniqueness was enforced still exist (saml_save_app() refuses new duplicates either way).
 * Returns true when the index exists afterwards.
 */
function saml_create_entity_id_index_if_unique(PDO $pdo): bool
{
    $st = $pdo->query(
        "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_saml_apps_provider_entity'"
    );
    $exists = $st->fetchColumn();
    $st->closeCursor();
    if ($exists !== false) {
        return true;
    }
    $st = $pdo->query(
        "SELECT provider_id FROM saml_apps GROUP BY provider_id, sp_entity_id HAVING COUNT(*) > 1 LIMIT 1"
    );
    $dupProvider = $st->fetchColumn();
    $st->closeCursor();
    if ($dupProvider !== false) {
        error_log(
            "saml: provider " . (string) $dupProvider .
                " has several SAML apps with the same SP Entity ID; SP-initiated SSO uses the oldest one." .
                " The unique index is added once the duplicates are deleted or renamed."
        );
        return false;
    }
    $pdo->exec(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_saml_apps_provider_entity ON saml_apps(provider_id, sp_entity_id)"
    );
    return true;
}

/** Best-effort retry of the unique index after an admin write that may have removed duplicates. */
function saml_try_entity_id_index(PDO $pdo): void
{
    try {
        saml_create_entity_id_index_if_unique($pdo);
    } catch (Throwable $e) {
        error_log("saml: could not add the SP Entity ID unique index: " . $e->getMessage());
    }
}

function hydrate_saml_app_row(array $r): array
{
    $signResponse = (int) ($r["sign_response"] ?? 1) === 1;
    $signAssertion = (int) ($r["sign_assertion"] ?? 1) === 1;
    if (!$signResponse && !$signAssertion) {
        // Rows saved with both flags off (API default before signing was enforced) are signed
        // in full when a response is built, so report what is actually sent.
        $signResponse = true;
        $signAssertion = true;
    }
    $persistentIdScheme = ($r["persistent_id_scheme"] ?? "legacy") === "legacy" ? "legacy" : "hmac";
    return [
        "id" => (string) $r["id"],
        "provider_id" => (string) $r["provider_id"],
        "name" => (string) $r["name"],
        "org_display_name" => (string) ($r["org_display_name"] ?? ""),
        "sp_entity_id" => (string) $r["sp_entity_id"],
        "acs_url" => (string) $r["acs_url"],
        // The endpoints actually honored (HTTP-POST only, always including acs_url).
        "acs_endpoints" => saml_effective_acs_endpoints(
            (string) $r["acs_url"],
            json_decode((string) ($r["acs_endpoints_json"] ?? "[]"), true)
        ),
        "slo_url" => (string) ($r["slo_url"] ?? ""),
        // The SLO endpoint's Binding ("" means HTTP-POST) and ResponseLocation ("": LogoutResponses
        // go to slo_url), see saml_normalize_slo_endpoint().
        "slo_binding" => (string) ($r["slo_binding"] ?? ""),
        "slo_response_url" => (string) ($r["slo_response_url"] ?? ""),
        "name_id_format" => (string) ($r["name_id_format"] ?? SAML_NAMEID_EMAIL),
        "name_id_source" => (string) ($r["name_id_source"] ?? "email"),
        // The stored setting, which saves send back unchanged: "hmac" (keyed per provider; new
        // apps) or "legacy" (apps saved before keyed identifiers existed). "legacy" is used only
        // while the legacy_saml_persistent_ids flag is on. The _effective value is the scheme
        // assertions use now (read-only).
        "persistent_id_scheme" => $persistentIdScheme,
        "persistent_id_scheme_effective" =>
            $persistentIdScheme === "legacy" && saml_legacy_persistent_ids() ? "legacy" : "hmac",
        "supported_name_id_formats" => saml_name_id_format_list(
            json_decode((string) ($r["supported_name_id_formats_json"] ?? "[]"), true)
        ),
        "sign_response" => $signResponse,
        "sign_assertion" => $signAssertion,
        "verify_authn_request_sig" =>
            (int) ($r["verify_authn_request_sig"] ?? 0) === 1,
        "allow_weak_sha1" => (int) ($r["allow_weak_sha1"] ?? 0) === 1,
        "encrypt_assertion" => (int) ($r["encrypt_assertion"] ?? 0) === 1,
        "encryption_alg" => (string) ($r["encryption_alg"] ?? SAML_ENC_AES256_CBC),
        "sp_signing_cert_pem" => (string) ($r["sp_signing_cert_pem"] ?? ""),
        "sp_encryption_cert_pem" =>
            (string) ($r["sp_encryption_cert_pem"] ?? ""),
        "attribute_mapping" =>
            json_decode((string) ($r["attribute_mapping_json"] ?? "[]"), true) ?:
            [],
        "default_relay_state" => (string) ($r["default_relay_state"] ?? ""),
        "auth_policy" => (string) ($r["auth_policy"] ?? "flexible"),
        "assigned_groups" =>
            json_decode((string) ($r["assigned_groups_json"] ?? "[]"), true) ?:
            [],
        "has_raw_metadata" =>
            trim((string) ($r["raw_sp_metadata_xml"] ?? "")) !== "",
        "created_at" => $r["created_at"] ?? null,
    ];
}

function saml_list_apps(string $storePath, string $providerId): array
{
    $pdo = saml_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM saml_apps WHERE provider_id = :pid ORDER BY created_at DESC, rowid DESC"
    );
    $stmt->execute([":pid" => $providerId]);
    $out = [];
    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $out[] = hydrate_saml_app_row($r);
    }
    return $out;
}

function saml_get_app(
    string $storePath,
    string $providerId,
    string $appId
): ?array {
    $pdo = saml_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM saml_apps WHERE id = :id AND provider_id = :pid LIMIT 1"
    );
    $stmt->execute([":id" => $appId, ":pid" => $providerId]);
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    return $r ? hydrate_saml_app_row($r) : null;
}

function saml_find_app_by_entity_id(
    string $storePath,
    string $providerId,
    string $spEntityId
): ?array {
    $pdo = saml_db($storePath);
    // Deterministic: if duplicates saved before uniqueness was enforced remain, the oldest wins
    // (saml_save_app() then only lets that one be edited).
    $stmt = $pdo->prepare(
        "SELECT * FROM saml_apps WHERE provider_id = :pid AND sp_entity_id = :eid " .
            "ORDER BY created_at ASC, rowid ASC LIMIT 1"
    );
    $stmt->execute([":pid" => $providerId, ":eid" => trim($spEntityId)]);
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    return $r ? hydrate_saml_app_row($r) : null;
}

function saml_default_attribute_mappings(): array
{
    return [
        [
            "name" => "firstName",
            "friendly_name" => "First Name",
            "name_format" => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "required" => true,
            "source" => "user.given_name",
        ],
        [
            "name" => "lastName",
            "friendly_name" => "Last Name",
            "name_format" => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "required" => true,
            "source" => "user.family_name",
        ],
        [
            "name" => "email",
            "friendly_name" => "Email",
            "name_format" => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "required" => true,
            "source" => "user.email",
        ],
        [
            "name" => "groups",
            "friendly_name" => "Groups",
            "name_format" => "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "required" => false,
            "source" => "user.groups",
        ],
    ];
}

/**
 * An app's supported NameID formats (the NameIDPolicy allowlist, see
 * saml_effective_name_id_format()): unique trimmed URIs, at most 32, each up to 256 bytes.
 */
function saml_name_id_format_list(mixed $value): array
{
    $out = [];
    foreach (normalize_string_list($value) as $format) {
        if (strlen($format) <= 256) {
            $out[] = $format;
        }
        if (count($out) >= 32) {
            break;
        }
    }
    return $out;
}

/** An ACS endpoint index (SAML unsignedShort), or null when missing or invalid. */
function saml_endpoint_index(mixed $value): ?int
{
    if (is_string($value)) {
        $value = trim($value);
        if (preg_match('/^\d{1,5}$/D', $value) !== 1) {
            return null;
        }
        $value = (int) $value;
    } elseif (is_float($value) && floor($value) === $value && abs($value) < 1.0e6) {
        $value = (int) $value;
    }
    return is_int($value) && $value >= 0 && $value <= 65535 ? $value : null;
}

/**
 * Builds the stored/honored ACS endpoint list from [index|null, location] pairs: the first
 * entry per index wins, entries without an index get the lowest free one, and $acsUrl is
 * always included (at $acsUrlIndex when that index is free). Only HTTP-POST endpoints exist.
 */
function saml_finalize_acs_endpoints(string $acsUrl, array $pairs, ?int $acsUrlIndex = null): array
{
    $byIndex = [];
    $unindexed = [];
    foreach ($pairs as [$index, $location]) {
        if ($index === null) {
            $unindexed[] = $location;
        } elseif (!isset($byIndex[$index])) {
            $byIndex[$index] = $location;
        }
    }
    $lowestFree = static function (array $used): int {
        $i = 0;
        while (isset($used[$i])) {
            $i++;
        }
        return $i;
    };
    foreach ($unindexed as $location) {
        $byIndex[$lowestFree($byIndex)] = $location;
    }
    if ($acsUrl !== "" && !in_array($acsUrl, $byIndex, true)) {
        $index =
            $acsUrlIndex !== null && !isset($byIndex[$acsUrlIndex])
                ? $acsUrlIndex
                : $lowestFree($byIndex);
        $byIndex[$index] = $acsUrl;
    }
    ksort($byIndex);
    $out = [];
    $defaultSeen = false;
    foreach ($byIndex as $index => $location) {
        $isDefault = !$defaultSeen && $location === $acsUrl;
        $defaultSeen = $defaultSeen || $isDefault;
        $out[] = [
            "index" => (int) $index,
            "is_default" => $isDefault,
            "binding" => SAML_BINDING_POST,
            "location" => $location,
        ];
    }
    return $out;
}

/**
 * Normalizes candidate ACS endpoints for storage. acs_url and acs_endpoints form one
 * allowlist: only HTTP-POST entries are kept (a missing binding counts as HTTP-POST),
 * locations that fail validate_endpoint_url() are not stored, $revokedLocations (a replaced
 * ACS URL) are dropped, and $acsUrl is always present, taking over a revoked entry's index.
 */
function saml_normalize_acs_endpoints(
    string $acsUrl,
    mixed $candidates,
    array $revokedLocations = []
): array {
    $pairs = [];
    $revokedIndex = null;
    foreach (is_array($candidates) ? $candidates : [] as $ep) {
        if (!is_array($ep)) {
            continue;
        }
        $location = is_string($ep["location"] ?? null) ? trim($ep["location"]) : "";
        $binding = is_string($ep["binding"] ?? null) ? trim($ep["binding"]) : "";
        if ($location === "" || ($binding !== "" && $binding !== SAML_BINDING_POST)) {
            continue;
        }
        $index = saml_endpoint_index($ep["index"] ?? null);
        if (in_array($location, $revokedLocations, true)) {
            $revokedIndex ??= $index;
            continue;
        }
        try {
            $location = validate_endpoint_url($location, false, "ACS Endpoint Location");
        } catch (InvalidArgumentException $e) {
            continue; // never authorized: assertions must not be delivered there
        }
        $pairs[] = [$index, $location];
    }
    return saml_finalize_acs_endpoints($acsUrl, $pairs, $revokedIndex);
}

/**
 * The ACS endpoints an app honors, computed from the stored list: HTTP-POST entries only,
 * always including acs_url. A stored list that lacks acs_url dates from an ACS URL edit made
 * before the two were kept in sync; it is ignored, leaving only acs_url, at the index of the
 * replaced default, so a URL the admin replaced is never authorized again.
 */
function saml_effective_acs_endpoints(string $acsUrl, mixed $stored): array
{
    $acsUrl = trim($acsUrl);
    $pairs = [];
    $firstIndex = null;
    $defaultIndex = null;
    foreach (is_array($stored) ? $stored : [] as $ep) {
        if (!is_array($ep)) {
            continue;
        }
        $location = is_string($ep["location"] ?? null) ? trim($ep["location"]) : "";
        $binding = is_string($ep["binding"] ?? null) ? trim($ep["binding"]) : "";
        if ($location === "" || ($binding !== "" && $binding !== SAML_BINDING_POST)) {
            continue;
        }
        $index = saml_endpoint_index($ep["index"] ?? null);
        $pairs[] = [$index, $location];
        if ($index !== null) {
            $firstIndex ??= $index;
            if (!empty($ep["is_default"])) {
                $defaultIndex = $index;
            }
        }
    }
    if ($acsUrl !== "" && !in_array($acsUrl, array_column($pairs, 1), true)) {
        return saml_finalize_acs_endpoints($acsUrl, [], $defaultIndex ?? $firstIndex ?? 0);
    }
    return saml_finalize_acs_endpoints($acsUrl, $pairs);
}

/** Boolean API input: null gives $default; strings "1/true/on/yes" and "0/false/off/no/" parse. */
function saml_input_bool(mixed $value, bool $default): bool
{
    if ($value === null) {
        return $default;
    }
    if (is_bool($value)) {
        return $value;
    }
    if (is_int($value) || is_float($value)) {
        return $value != 0;
    }
    if (is_string($value)) {
        $v = strtolower(trim($value));
        if (in_array($v, ["1", "true", "on", "yes"], true)) {
            return true;
        }
        if (in_array($v, ["0", "false", "off", "no", ""], true)) {
            return false;
        }
    }
    return $default;
}

/**
 * Sign-on policy of an app: "inherit" (the provider's default_auth_policy, resolved at request
 * time by effective_auth_policy()), "flexible", "touchid_only" or "mfa". null or "" mean
 * inherit; any other value is rejected rather than silently weakened.
 */
function saml_normalize_auth_policy(mixed $value): string
{
    if ($value === null) {
        return "inherit";
    }
    $policy = is_string($value) ? strtolower(trim($value)) : "invalid";
    if ($policy === "") {
        return "inherit";
    }
    if (!in_array($policy, ["inherit", "flexible", "touchid_only", "mfa"], true)) {
        throw new InvalidArgumentException(
            "auth_policy must be one of: inherit, flexible, touchid_only, mfa"
        );
    }
    return $policy;
}

/**
 * Refuses a second app with the same SP Entity ID in a provider (SP-initiated SSO could only
 * ever reach one of them). For duplicates saved before this was enforced, only the app that
 * SP-initiated SSO resolves to (the oldest) may still be saved unchanged; the newer one has to
 * be deleted or given another entity ID. Call inside the write transaction.
 */
function saml_assert_entity_id_available(
    PDO $pdo,
    string $providerId,
    string $spEntityId,
    string $appId,
    ?array $existing
): void {
    $stmt = $pdo->prepare(
        "SELECT id, name FROM saml_apps WHERE provider_id = :pid AND sp_entity_id = :eid " .
            "ORDER BY created_at ASC, rowid ASC"
    );
    $stmt->execute([":pid" => $providerId, ":eid" => $spEntityId]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $other = null;
    foreach ($rows as $row) {
        if ((string) $row["id"] !== $appId) {
            $other = $row;
            break;
        }
    }
    if ($other === null) {
        return;
    }
    $otherName = sanitize_label((string) $other["name"], 120);
    if ($existing === null || trim((string) $existing["sp_entity_id"]) !== $spEntityId) {
        throw new InvalidArgumentException(
            "Another SAML application in this provider (\"" . $otherName .
                "\") already uses this SP Entity ID; edit that application instead"
        );
    }
    if ((string) $rows[0]["id"] !== $appId) {
        throw new InvalidArgumentException(
            "This application has the same SP Entity ID as \"" . $otherName .
                "\", which handles all SP-initiated sign-ins for it; delete one of the two or give this one a different SP Entity ID"
        );
    }
}

/**
 * slo_binding and slo_response_url of an app being saved (S02-05), as [binding, response URL].
 * They describe the SP's SingleLogoutService at slo_url: its Binding ("" for a hand-entered
 * slo_url, which means HTTP-POST; else the HTTP-POST or HTTP-Redirect URI, the bindings a browser
 * can carry a LogoutResponse over) and its ResponseLocation ("" when LogoutResponses go to
 * slo_url). SP metadata sets them together with slo_url (saml_parse_sp_metadata()); a request
 * may also send them. Without slo_url both are "".
 *
 * A response location is kept only with the slo_url it was published for: when slo_url changes
 * and the request does not change slo_response_url, the old value is cleared, because
 * LogoutResponses would otherwise keep going to an endpoint the admin replaced. The console sends
 * every field back, so a value equal to the stored one is not a change. The binding is kept: it
 * belongs to the SP software, which a new URL rarely changes.
 *
 * $input is the merged input, $sent the fields the request sends, $existing the stored app (null
 * on create), $metadataSloUrl the SLO Location of SP metadata imported by this request (null
 * without one) and $sloUrl the slo_url being stored. Throws InvalidArgumentException for a value
 * the request sets that cannot be used.
 */
function saml_normalize_slo_endpoint(
    array $input,
    array $sent,
    ?array $existing,
    ?string $metadataSloUrl,
    string $sloUrl
): array {
    // A value this request sets: sent, and different from the stored one.
    $changes = static function (string $key) use ($sent, $existing): bool {
        if (!array_key_exists($key, $sent)) {
            return false;
        }
        $value = $sent[$key] ?? "";
        return !is_string($value) || trim($value) !== trim((string) ($existing[$key] ?? ""));
    };
    $read = static function (string $key) use ($input): string {
        $value = $input[$key] ?? "";
        if (!is_string($value)) {
            throw new InvalidArgumentException("$key must be a string");
        }
        return trim($value);
    };

    $binding = $read("slo_binding");
    if (!in_array($binding, ["", SAML_BINDING_POST, SAML_BINDING_REDIRECT], true)) {
        if ($changes("slo_binding")) {
            throw new InvalidArgumentException(
                "slo_binding must be " . SAML_BINDING_POST . " or " . SAML_BINDING_REDIRECT .
                    " (LogoutResponses are sent through the browser), or empty for HTTP-POST"
            );
        }
        $binding = "";
    }

    $responseUrl = $read("slo_response_url");
    $responseUrlChanges = $changes("slo_response_url");
    $responseUrlFromMetadata =
        $metadataSloUrl !== null && !array_key_exists("slo_response_url", $sent);
    if ($responseUrl !== "" && !$responseUrlChanges) {
        $publishedFor = $responseUrlFromMetadata
            ? $metadataSloUrl
            : trim((string) ($existing["slo_url"] ?? ""));
        if ($publishedFor !== $sloUrl) {
            $responseUrl = "";
        }
    }
    if ($sloUrl === "") {
        if ($responseUrl !== "" && $responseUrlChanges) {
            throw new InvalidArgumentException(
                "slo_response_url needs slo_url, the Location of the service provider's SingleLogoutService"
            );
        }
        return ["", ""];
    }
    if ($responseUrl !== "") {
        try {
            $responseUrl = validate_endpoint_url($responseUrl, false, "SLO Response URL");
        } catch (InvalidArgumentException $e) {
            if ($responseUrlChanges) {
                throw $e;
            }
            if ($responseUrlFromMetadata) {
                // Optional and published by the SP: not stored when it cannot be delivered to.
                $responseUrl = "";
            }
            // An unchanged stored value is kept; it is validated again before anything is sent to it.
        }
    }
    return [$binding, $responseUrl];
}

function saml_save_app(
    string $storePath,
    string $providerId,
    array $input,
    ?string $existingId = null
): array {
    $existing = null;
    if ($existingId !== null) {
        $existing = saml_get_app($storePath, $providerId, $existingId);
        if (!$existing) {
            throw new RuntimeException("SAML application not found");
        }
    }

    // Programmatic API clients may pass inline SP Metadata XML when creating or updating an app.
    $inlineXml = trim((string) ($input["sp_metadata_xml"] ?? ""));
    unset($input["sp_metadata_xml"]);
    $sent = $input; // the fields this request sets explicitly
    $endpointsFromMetadata = false;
    $metadataSloUrl = null; // the SLO Location of metadata imported by this request
    if ($inlineXml !== "") {
        $parsedXml = saml_parse_sp_metadata($inlineXml);
        $endpointsFromMetadata = !array_key_exists("acs_endpoints", $sent);
        $metadataSloUrl = (string) ($parsedXml["slo_url"] ?? "");
        if ($existing !== null) {
            // Metadata refresh: only facts the SP publishes change (ACS URL and endpoints, SLO
            // endpoint with its binding and response location, supported NameID formats, and
            // its certificates when the metadata has them). Signing, encryption and
            // AuthnRequest-signature settings, the NameID format and source, attribute mappings
            // and the name stay as they are unless sent.
            if (
                !array_key_exists("sp_entity_id", $sent) &&
                $parsedXml["sp_entity_id"] !== $existing["sp_entity_id"]
            ) {
                throw new InvalidArgumentException(
                    "The metadata entityID (" . sanitize_label($parsedXml["sp_entity_id"], 200) .
                        ") does not match this application's SP Entity ID (" .
                        sanitize_label($existing["sp_entity_id"], 200) .
                        "); send sp_entity_id explicitly to change it"
                );
            }
            $fromMetadata = array_intersect_key(
                $parsedXml,
                array_flip([
                    "acs_url",
                    "acs_endpoints",
                    "slo_url",
                    "slo_binding",
                    "slo_response_url",
                    "supported_name_id_formats",
                    "raw_sp_metadata_xml",
                ])
            );
            foreach (["sp_signing_cert_pem", "sp_encryption_cert_pem"] as $certKey) {
                if (trim((string) ($parsedXml[$certKey] ?? "")) !== "") {
                    $fromMetadata[$certKey] = $parsedXml[$certKey];
                }
            }
            $input = array_merge($existing, $fromMetadata, $sent);
        } else {
            $input = array_merge($parsedXml, $sent);
        }
    } elseif ($existing !== null) {
        $input = array_merge($existing, $sent);
    }

    $name = trim((string) ($input["name"] ?? ""));
    $spEntityId = trim((string) ($input["sp_entity_id"] ?? ""));
    $acsUrl = validate_endpoint_url(
        trim((string) ($input["acs_url"] ?? "")),
        false,
        "ACS URL"
    );
    if ($name === "" || $spEntityId === "") {
        throw new InvalidArgumentException(
            "Application name, SP Entity ID, and ACS URL are required"
        );
    }

    $sloUrlClean = trim((string) ($input["slo_url"] ?? ""));
    if ($sloUrlClean !== "") {
        try {
            $sloUrlClean = validate_endpoint_url($sloUrlClean, false, "SLO URL");
        } catch (InvalidArgumentException $e) {
            if ($inlineXml !== "" && !array_key_exists("slo_url", $sent)) {
                // Optional and published by the SP: not stored when it cannot be delivered to.
                $sloUrlClean = "";
            } elseif (
                $existing === null ||
                $sloUrlClean !== trim((string) ($existing["slo_url"] ?? ""))
            ) {
                throw $e;
            }
            // An unchanged stored value is kept; it is validated again before anything is sent to it.
        }
    }
    [$sloBinding, $sloResponseUrl] = saml_normalize_slo_endpoint(
        $input,
        $sent,
        $existing,
        $metadataSloUrl,
        $sloUrlClean
    );

    // A replaced ACS URL stops being authorized, even when the client sends the old endpoint
    // list back (the console round-trips it). Endpoints freshly published by the SP's
    // metadata are taken as they are.
    $revokedLocations = [];
    if ($existing !== null && !$endpointsFromMetadata) {
        $previousAcsUrl = trim((string) ($existing["acs_url"] ?? ""));
        if ($previousAcsUrl !== "" && $previousAcsUrl !== $acsUrl) {
            $revokedLocations[] = $previousAcsUrl;
        }
    }
    $acsEndpoints = saml_normalize_acs_endpoints(
        $acsUrl,
        $input["acs_endpoints"] ?? [],
        $revokedLocations
    );

    $mappings =
        isset($input["attribute_mapping"]) &&
        is_array($input["attribute_mapping"])
            ? $input["attribute_mapping"]
            : saml_default_attribute_mappings();

    // Omitted on create: inherit the provider's default sign-on policy. Omitted on update: the
    // stored value is kept as it is; only a value the caller sends is validated (G1e-02).
    $authPolicy = $existing === null || array_key_exists("auth_policy", $sent)
        ? saml_normalize_auth_policy($sent["auth_policy"] ?? null)
        : (string) ($existing["auth_policy"] ?? "inherit");

    // HTTP-POST responses must be signed: both flags default to on, and turning both off is refused.
    $signResponse = saml_input_bool($input["sign_response"] ?? null, true);
    $signAssertion = saml_input_bool($input["sign_assertion"] ?? null, true);
    if (!$signResponse && !$signAssertion) {
        throw new InvalidArgumentException(
            "Enable sign_response, sign_assertion or both: SAML responses delivered over HTTP-POST must be signed"
        );
    }

    // Assertion encryption never silently degrades to plaintext: enabling it needs a usable
    // RSA encryption certificate, and any certificate supplied is validated. A stored
    // certificate that is left unchanged while encryption stays off is kept as it is.
    $encryptAssertion = saml_input_bool($input["encrypt_assertion"] ?? null, false);
    $encCertInput = $input["sp_encryption_cert_pem"] ?? "";
    if (!is_string($encCertInput)) {
        throw new InvalidArgumentException("sp_encryption_cert_pem must be a PEM certificate string");
    }
    $encCert = trim($encCertInput);
    if ($encCert !== "") {
        $encCertError = saml_encryption_certificate_error($encCert);
        if ($encCertError === null) {
            $encCert = trim((string) saml_certificate_pem($encCert));
        } elseif (
            $encryptAssertion ||
            $encCert !== trim((string) ($existing["sp_encryption_cert_pem"] ?? ""))
        ) {
            throw new InvalidArgumentException(
                "sp_encryption_cert_pem cannot be used for assertion encryption: " . $encCertError
            );
        }
    }
    if ($encryptAssertion && $encCert === "") {
        throw new InvalidArgumentException(
            "encrypt_assertion requires sp_encryption_cert_pem, the service provider's RSA encryption certificate"
        );
    }

    // The SP signing certificate verifies AuthnRequest and LogoutRequest signatures. Only a PEM
    // certificate or public key (or the bare base64 body SAML metadata carries) is stored,
    // normalized to PEM, so a value such as "file://..." can never reach OpenSSL (S10-08). A
    // stored value that the request leaves unchanged is kept as it is.
    $signCertInput = $input["sp_signing_cert_pem"] ?? "";
    if (!is_string($signCertInput)) {
        throw new InvalidArgumentException("sp_signing_cert_pem must be a PEM certificate string");
    }
    $signCert = trim($signCertInput);
    if ($signCert !== "" && $signCert !== trim((string) ($existing["sp_signing_cert_pem"] ?? ""))) {
        $signPem = saml_certificate_pem($signCert);
        if ($signPem === null || @openssl_pkey_get_public($signPem) === false) {
            throw new InvalidArgumentException(
                "sp_signing_cert_pem must be the service provider's X.509 signing certificate in PEM format"
            );
        }
        $signCert = trim($signPem);
    }

    // Exact algorithm URIs only (see saml_encryption_cipher()). Omitted: AES-256-GCM for a new
    // app; an existing app stored without one keeps the AES-256-CBC it was always sent.
    $encAlgInput = $input["encryption_alg"] ?? "";
    if (!is_string($encAlgInput)) {
        throw new InvalidArgumentException("encryption_alg must be an algorithm URI string");
    }
    $encryptionAlg = trim($encAlgInput);
    if ($encryptionAlg === "") {
        $encryptionAlg = $existing !== null ? SAML_ENC_AES256_CBC : SAML_ENC_DEFAULT;
    }
    if (
        saml_encryption_cipher($encryptionAlg) === null &&
        ($encryptAssertion ||
            $encryptionAlg !== trim((string) ($existing["encryption_alg"] ?? "")))
    ) {
        throw new InvalidArgumentException(
            "Unsupported encryption_alg; use one of: " .
                implode(", ", saml_supported_encryption_algorithms())
        );
    }

    // Persistent NameIDs are keyed per provider ("hmac", the default for new apps). An app that
    // is "legacy" stays so until it is switched. Choosing "legacy" for any other app needs the
    // legacy_saml_persistent_ids flag (S02-10). Without the flag the value would have no effect
    // now, but turning the flag on later would silently re-key that app's SP accounts.
    $schemeInput = $input["persistent_id_scheme"] ?? "";
    if (!is_string($schemeInput)) {
        throw new InvalidArgumentException("persistent_id_scheme must be \"hmac\" or \"legacy\"");
    }
    $persistentIdScheme = strtolower(trim($schemeInput));
    if ($persistentIdScheme === "") {
        $persistentIdScheme =
            $existing !== null ? (string) ($existing["persistent_id_scheme"] ?? "legacy") : "hmac";
    }
    if (!in_array($persistentIdScheme, ["hmac", "legacy"], true)) {
        throw new InvalidArgumentException("persistent_id_scheme must be \"hmac\" or \"legacy\"");
    }
    if (
        $persistentIdScheme === "legacy" &&
        ($existing["persistent_id_scheme"] ?? "hmac") !== "legacy" &&
        !saml_legacy_persistent_ids()
    ) {
        throw new InvalidArgumentException(
            "persistent_id_scheme \"legacy\" (unkeyed persistent NameIDs, which anyone who knows a user's id " .
                "can compute) can only be chosen while the legacy_saml_persistent_ids compatibility flag is on"
        );
    }

    $id = $existingId ?: uuidv4();
    $now = gmdate("Y-m-d\TH:i:s\Z");
    $pdo = saml_db($storePath);

    // One write transaction, so the duplicate entity ID check cannot race another save.
    $pdo->exec("BEGIN IMMEDIATE");
    try {
        if (
            $existingId !== null &&
            saml_get_app($storePath, $providerId, $existingId) === null
        ) {
            throw new RuntimeException("SAML application not found");
        }
        saml_assert_entity_id_available($pdo, $providerId, $spEntityId, $id, $existing);

        if ($existingId !== null) {
            $stmt = $pdo->prepare(
                "UPDATE saml_apps SET " .
                    "name = :name, org_display_name = :org, sp_entity_id = :eid, acs_url = :acs, " .
                    "acs_endpoints_json = :acse, slo_url = :slo, slo_binding = :slob, slo_response_url = :slor, " .
                    "name_id_format = :nfmt, name_id_source = :nsrc, " .
                    "supported_name_id_formats_json = :snfmt, sign_response = :sresp, sign_assertion = :sass, " .
                    "verify_authn_request_sig = :vsig, allow_weak_sha1 = :wsha1, encrypt_assertion = :enc, encryption_alg = :encalg, " .
                    "sp_signing_cert_pem = :scert, sp_encryption_cert_pem = :ecert, attribute_mapping_json = :amap, " .
                    "default_relay_state = :rstate, auth_policy = :pol, assigned_groups_json = :grp, " .
                    "raw_sp_metadata_xml = COALESCE(:raw, raw_sp_metadata_xml), " .
                    "persistent_id_scheme = :pids " .
                    "WHERE id = :id AND provider_id = :pid"
            );
        } else {
            $stmt = $pdo->prepare(
                "INSERT INTO saml_apps (" .
                    "id, provider_id, name, org_display_name, sp_entity_id, acs_url, acs_endpoints_json, " .
                    "slo_url, slo_binding, slo_response_url, " .
                    "name_id_format, name_id_source, supported_name_id_formats_json, sign_response, sign_assertion, " .
                    "verify_authn_request_sig, allow_weak_sha1, encrypt_assertion, encryption_alg, sp_signing_cert_pem, sp_encryption_cert_pem, " .
                    "attribute_mapping_json, default_relay_state, auth_policy, assigned_groups_json, raw_sp_metadata_xml, " .
                    "persistent_id_scheme, created_at" .
                ") VALUES (" .
                    ":id, :pid, :name, :org, :eid, :acs, :acse, :slo, :slob, :slor, :nfmt, :nsrc, :snfmt, :sresp, :sass, " .
                    ":vsig, :wsha1, :enc, :encalg, :scert, :ecert, :amap, :rstate, :pol, :grp, :raw, :pids, :cat" .
                ")"
            );
            $stmt->bindValue(":cat", $now);
        }

        $stmt->bindValue(":id", $id);
        $stmt->bindValue(":pid", $providerId);
        $stmt->bindValue(":name", $name);
        $stmt->bindValue(":org", trim((string) ($input["org_display_name"] ?? "")));
        $stmt->bindValue(":eid", $spEntityId);
        $stmt->bindValue(":acs", $acsUrl);
        $stmt->bindValue(
            ":acse",
            json_encode($acsEndpoints, JSON_UNESCAPED_SLASHES)
        );
        $stmt->bindValue(":slo", $sloUrlClean);
        $stmt->bindValue(":slob", $sloBinding);
        $stmt->bindValue(":slor", $sloResponseUrl);
        $stmt->bindValue(
            ":nfmt",
            trim((string) ($input["name_id_format"] ?? SAML_NAMEID_EMAIL))
        );
        $stmt->bindValue(
            ":nsrc",
            trim((string) ($input["name_id_source"] ?? "email"))
        );
        $stmt->bindValue(
            ":snfmt",
            json_encode(
                saml_name_id_format_list($input["supported_name_id_formats"] ?? []),
                JSON_UNESCAPED_SLASHES
            )
        );
        $stmt->bindValue(":sresp", $signResponse ? 1 : 0, PDO::PARAM_INT);
        $stmt->bindValue(":sass", $signAssertion ? 1 : 0, PDO::PARAM_INT);
        $stmt->bindValue(
            ":vsig",
            saml_input_bool($input["verify_authn_request_sig"] ?? null, false) ? 1 : 0,
            PDO::PARAM_INT
        );
        $stmt->bindValue(
            ":wsha1",
            saml_input_bool($input["allow_weak_sha1"] ?? null, false) ? 1 : 0,
            PDO::PARAM_INT
        );
        $stmt->bindValue(":enc", $encryptAssertion ? 1 : 0, PDO::PARAM_INT);
        $stmt->bindValue(":encalg", $encryptionAlg);
        $stmt->bindValue(":scert", $signCert);
        $stmt->bindValue(":ecert", $encCert);
        $stmt->bindValue(":pids", $persistentIdScheme);
        $stmt->bindValue(":amap", json_encode($mappings, JSON_UNESCAPED_SLASHES));
        $stmt->bindValue(
            ":rstate",
            trim((string) ($input["default_relay_state"] ?? ""))
        );
        $stmt->bindValue(":pol", $authPolicy);
        $stmt->bindValue(
            ":grp",
            json_encode(
                normalize_string_list($input["assigned_groups"] ?? []),
                JSON_UNESCAPED_SLASHES
            )
        );
        // hydrate_saml_app_row() does not return the stored SP metadata copy, so an update that
        // sends neither raw_sp_metadata_xml nor sp_metadata_xml keeps it (NULL, see the
        // COALESCE above) instead of wiping it (G1e-01); an explicit "" still clears it.
        if (array_key_exists("raw_sp_metadata_xml", $input)) {
            $stmt->bindValue(":raw", (string) ($input["raw_sp_metadata_xml"] ?? ""));
        } elseif ($existingId !== null) {
            $stmt->bindValue(":raw", null, PDO::PARAM_NULL);
        } else {
            $stmt->bindValue(":raw", "");
        }
        $stmt->execute();
        $pdo->exec("COMMIT");
    } catch (Throwable $e) {
        try {
            $pdo->exec("ROLLBACK");
        } catch (Throwable $rollbackError) {
            // The original error is the one worth reporting.
        }
        throw $e;
    }
    saml_try_entity_id_index($pdo);

    return saml_get_app($storePath, $providerId, $id) ?? [];
}

function saml_delete_app(
    string $storePath,
    string $providerId,
    string $appId
): bool {
    $pdo = saml_db($storePath);
    $stmt = $pdo->prepare(
        "DELETE FROM saml_apps WHERE id = :id AND provider_id = :pid"
    );
    $stmt->execute([":id" => $appId, ":pid" => $providerId]);
    $deleted = $stmt->rowCount() > 0;
    if ($deleted) {
        // Deleting a legacy duplicate may allow the unique entity ID index now.
        saml_try_entity_id_index($pdo);
    }
    return $deleted;
}

// ---------- Safe XML Loading ----------

/**
 * Parses $xml with libxml2: at most 512 KB, no DOCTYPE or ENTITY declarations, no network
 * access. With $inboundMessage (a request sent by an unauthenticated client, see
 * saml_load_inbound_message()), the bytes must first pass saml_xml_structure_error(). Throws
 * InvalidArgumentException.
 */
function saml_load_xml_safely(string $xml, bool $inboundMessage = false): DOMDocument
{
    $trimmed = trim($xml);
    if ($trimmed === "") {
        throw new InvalidArgumentException("Empty XML document");
    }
    if (strlen($trimmed) > 524288) {
        throw new InvalidArgumentException("XML document exceeds maximum size (512 KB)");
    }
    if (preg_match('/<!(?:DOCTYPE|ENTITY)\b/i', $trimmed)) {
        throw new InvalidArgumentException("XML DOCTYPE/ENTITY declarations are forbidden");
    }
    if ($inboundMessage) {
        $structureError = saml_xml_structure_error($trimmed);
        if ($structureError !== null) {
            throw new InvalidArgumentException("The SAML message was not parsed: $structureError");
        }
    }
    $prev = libxml_use_internal_errors(true);
    libxml_clear_errors();
    $doc = new DOMDocument();
    $doc->preserveWhiteSpace = true;
    $doc->formatOutput = false;
    $ok = $doc->loadXML($trimmed, LIBXML_NONET | LIBXML_NSCLEAN);
    $errs = libxml_get_errors();
    libxml_clear_errors();
    libxml_use_internal_errors($prev);

    if (!$ok || !$doc->documentElement || $doc->doctype !== null) {
        $msg = !empty($errs) ? trim($errs[0]->message) : "Malformed XML";
        throw new InvalidArgumentException("Failed to parse XML: $msg");
    }
    return $doc;
}

/**
 * Checks the structure of an incoming SAML request before libxml2 parses it (G1c-01): null
 * when it is within SAML_MESSAGE_LIMITS, else the reason. libxml2 before 2.12 compares the
 * attributes of a start tag pairwise, so one element with tens of thousands of attributes
 * costs seconds of CPU. XMLReader runs that same parser, so the bytes are scanned here instead,
 * in linear time.
 *
 * The counts hold only for markup read the way libxml2 reads it, and libxml2 goes on parsing
 * after many errors (markup hidden behind one would not be counted). So anything this scan
 * cannot read exactly is refused. A well-formed request in an ASCII-compatible encoding always
 * passes these format checks. The scan requires: no NUL bytes; an XML declaration, if
 * present, that is well formed and names UTF-8, US-ASCII or a single-byte ISO-8859 or
 * windows-125x charset; no character that libxml2 would decode to one XML does not allow (one
 * ends a comment, CDATA section or processing instruction early); comments whose first "--"
 * starts the "-->" that closes them (XML forbids "--" inside a comment, and libxml2 may then
 * end the comment further on); and markup made only of start and end tags, comments, CDATA
 * sections and processing instructions with a target name.
 */
function saml_xml_structure_error(string $xml): ?string
{
    $limits = SAML_MESSAGE_LIMITS;
    // Control characters, and UTF-8 sequences for U+FFFE/U+FFFF, surrogates or code points
    // above U+10FFFF. Other invalid UTF-8 makes libxml2 read the rest as ISO-8859-1, which keeps
    // ASCII as it is.
    $badBytes = '/[\x00-\x08\x0B\x0C\x0E-\x1F]|\xEF\xBF[\xBE\xBF]|\xED[\xA0-\xBF][\x80-\xBF]' .
        '|\xF4[\x90-\xBF][\x80-\xBF]{2}|[\xF5-\xF7][\x80-\xBF]{3}/';
    if (preg_match($badBytes, $xml) !== 0) {
        return "it contains characters XML does not allow, or is not in UTF-8";
    }
    $pos = str_starts_with($xml, "\xEF\xBB\xBF") ? 3 : 0;
    if (($xml[$pos] ?? "") !== "<") {
        return "it does not start with markup";
    }
    if (preg_match('/\G<\?xml[ \t\r\n]/', $xml, $unused, 0, $pos) === 1) {
        // After an error in its declaration libxml2 skips to the next ">", wherever that is.
        $s = '[ \t\r\n]';
        $declaration = '/\G<\?xml' . $s . '+version' . $s . '*=' . $s . '*(["\'])1\.[0-9]+\1' .
            '(?:' . $s . '+encoding' . $s . '*=' . $s . '*(["\'])([A-Za-z][A-Za-z0-9._-]*)\2)?' .
            '(?:' . $s . '+standalone' . $s . '*=' . $s . '*(["\'])(?:yes|no)\4)?' . $s . '*\?>/';
        if (preg_match($declaration, $xml, $decl, 0, $pos) !== 1) {
            return "its XML declaration is malformed";
        }
        // libxml2 decodes the rest with the declared charset: only ones that keep ASCII bytes.
        $encoding = strtolower($decl[3] ?? "");
        if (
            !in_array($encoding, ["", "utf-8", "utf8", "us-ascii", "ascii"], true) &&
            preg_match('/^(?:iso[-_]?8859-(?:[1-9]|1[0-6])|latin-?[1-9]|(?:windows-|cp)125[0-8])$/D', $encoding) !== 1
        ) {
            return "its encoding is not supported; send it in UTF-8";
        }
        $pos += strlen($decl[0]);
    }

    $space = " \t\r\n";
    $nameEnd = " \t\r\n<>/=\"'";
    $nodes = 0;
    $depth = 0;
    $attributes = 0;
    $declarations = 0;
    $prefixes = [];
    while (($lt = strpos($xml, "<", $pos)) !== false) {
        $next = $xml[$lt + 1] ?? "";
        if ($next === "/") {
            // End tag: "</" Name S? ">".
            $p = $lt + 2;
            $nameLength = strcspn($xml, $nameEnd, $p);
            $p += $nameLength;
            $p += strspn($xml, $space, $p);
            if ($nameLength === 0 || ($xml[$p] ?? "") !== ">" || --$depth < 0) {
                return "it has a malformed end tag";
            }
            $pos = $p + 1;
            continue;
        }
        if (++$nodes > $limits["nodes"]) {
            return "it has more than " . $limits["nodes"] . " elements and other nodes";
        }
        if ($next === "!" || $next === "?") {
            // A CDATA section or processing instruction ends at its first terminator, as in
            // libxml2. A processing instruction needs a target name: without one libxml2 parses
            // what follows as content. XML forbids "--" inside a comment (XML 1.0, section 2.5).
            // libxml2 reports one but reads on, and may then end the comment past the first
            // "-->", so the first "--" after "<!--" must be the start of the closing "-->".
            if (substr($xml, $lt, 4) === "<!--") {
                $end = strpos($xml, "--", $lt + 4);
                if ($end === false || ($xml[$end + 2] ?? "") !== ">") {
                    return "it has a malformed or unterminated comment";
                }
                $endLength = 3;
            } elseif (substr($xml, $lt, 9) === "<![CDATA[") {
                [$end, $endLength] = [strpos($xml, "]]>", $lt + 9), 3];
            } elseif (preg_match('/\G<\?[A-Za-z_:][A-Za-z0-9_:.-]*+(?:[ \t\r\n]|\?>)/', $xml, $unused, 0, $lt) === 1) {
                [$end, $endLength] = [strpos($xml, "?>", $lt + 2), 2];
            } else {
                return "it has markup other than elements, comments, CDATA sections and processing instructions";
            }
            if ($end === false) {
                return "it has an unterminated CDATA section or processing instruction";
            }
            $pos = $end + $endLength;
            continue;
        }
        // Start tag: "<" Name (S Name S? "=" S? Value)* S? ("/>" | ">"); a value has no "<".
        $p = $lt + 1;
        $nameLength = strcspn($xml, $nameEnd, $p);
        if ($nameLength === 0) {
            return "it has a malformed start tag";
        }
        $p += $nameLength;
        if (++$depth > $limits["depth"]) {
            return "it nests elements more than " . $limits["depth"] . " levels deep";
        }
        $elementAttributes = 0;
        while (true) {
            $spaceLength = strspn($xml, $space, $p);
            $p += $spaceLength;
            $c = $xml[$p] ?? "";
            if ($c === ">") {
                $p++;
                break;
            }
            if ($c === "/" && ($xml[$p + 1] ?? "") === ">") {
                $depth--;
                $p += 2;
                break;
            }
            $attrLength = $spaceLength > 0 ? strcspn($xml, $nameEnd, $p) : 0;
            if ($attrLength === 0) {
                return "it has a malformed start tag";
            }
            $attrName = substr($xml, $p, $attrLength);
            $p += $attrLength;
            $p += strspn($xml, $space, $p);
            if (($xml[$p] ?? "") !== "=") {
                return "it has a malformed attribute";
            }
            $p++;
            $p += strspn($xml, $space, $p);
            $quote = $xml[$p] ?? "";
            $valueEnd = $quote === '"' || $quote === "'" ? strpos($xml, $quote, $p + 1) : false;
            if ($valueEnd === false || strcspn($xml, "<", $p + 1, $valueEnd - $p - 1) !== $valueEnd - $p - 1) {
                return "it has a malformed attribute";
            }
            $p = $valueEnd + 1;
            if (++$elementAttributes > $limits["element_attributes"]) {
                return "an element has more than " . $limits["element_attributes"] . " attributes";
            }
            if (++$attributes > $limits["attributes"]) {
                return "it has more than " . $limits["attributes"] . " attributes";
            }
            if ($attrName === "xmlns" || str_starts_with($attrName, "xmlns:")) {
                $prefixes[$attrName] = true;
                if (
                    ++$declarations > $limits["namespace_declarations"] ||
                    count($prefixes) > $limits["namespace_prefixes"]
                ) {
                    return "it declares more namespaces than a SAML request needs";
                }
            }
        }
        $pos = $p;
    }
    return $depth === 0 ? null : "it has an unclosed element";
}

/**
 * saml_load_xml_safely($xml, true) for an incoming request, with each request parsed once
 * (G1c-01). The routes parse a request first without the app, to find it by Issuer, and then
 * with it. When the second call passes byte-for-byte the same $xml, it gets the document the
 * first call built, so a signature checked over $xml always covers the parsed document. The
 * request parsers only read the document. A stored document is handed out once.
 */
function saml_load_inbound_message(string $xml): DOMDocument
{
    static $last = null;
    if ($last !== null && $last[0] === $xml) {
        $doc = $last[1];
        $last = null;
        return $doc;
    }
    $last = null;
    $doc = saml_load_xml_safely($xml, true);
    $last = [$xml, $doc];
    return $doc;
}

function saml_xpath(DOMDocument $doc): DOMXPath
{
    $xp = new DOMXPath($doc);
    $xp->registerNamespace("md", SAML_NS_MD);
    $xp->registerNamespace("samlp", SAML_NS_PROTOCOL);
    $xp->registerNamespace("saml", SAML_NS_ASSERTION);
    $xp->registerNamespace("ds", SAML_NS_DS);
    $xp->registerNamespace("xenc", SAML_NS_XENC);
    return $xp;
}

function saml_guess_attribute_source(string $attrName): string
{
    $lower = strtolower(trim($attrName));
    // Also strip common URI prefixes if any
    if (str_contains($lower, "/")) {
        $parts = explode("/", $lower);
        $lower = end($parts) ?: $lower;
    }
    return match ($lower) {
        "firstname", "givenname", "given_name", "first_name" => "user.given_name",
        "lastname", "surname", "sn", "familyname", "family_name", "last_name" => "user.family_name",
        "email", "emailaddress", "mail", "e-mail" => "user.email",
        "username", "uid", "samaccountname", "login" => "user.username",
        "displayname", "name", "cn", "fullname", "full_name" => "user.display_name",
        "mobilephone", "mobile", "mobile_phone", "phone", "telephonenumber" => "user.mobile_phone",
        "groups", "group" => "user.groups",
        "memberof", "member_of" => "attr:memberOf",
        default => "attr:" . trim($attrName),
    };
}

/**
 * Parses an SP Metadata XML export (such as Palo Alto Networks / Okta CIAM glow-in-the-dark.eu.xml)
 * into a ready-to-save SAML app configuration object.
 */
function saml_parse_sp_metadata(string $xml): array
{
    $doc = saml_load_xml_safely($xml);
    $xp = saml_xpath($doc);

    $entityNode = $xp->query("//md:EntityDescriptor")->item(0);
    if (!($entityNode instanceof DOMElement)) {
        throw new InvalidArgumentException("Missing md:EntityDescriptor in SP metadata");
    }
    $spEntityId = trim($entityNode->getAttribute("entityID"));
    if ($spEntityId === "") {
        throw new InvalidArgumentException("Missing entityID on md:EntityDescriptor");
    }

    $spDesc = $xp->query(".//md:SPSSODescriptor", $entityNode)->item(0);
    if (!($spDesc instanceof DOMElement)) {
        throw new InvalidArgumentException("Missing md:SPSSODescriptor in SP metadata");
    }

    $authnRequestsSigned =
        strtolower(trim($spDesc->getAttribute("AuthnRequestsSigned"))) === "true";
    $wantAssertionsSigned =
        strtolower(trim($spDesc->getAttribute("WantAssertionsSigned"))) !== "false";

    // Signing & Encryption Certificates
    $signingCertPem = "";
    foreach (
        $xp->query(
            "./md:KeyDescriptor[@use='signing' or not(@use)]//ds:X509Certificate",
            $spDesc
        )
        as $certNode
    ) {
        $body = trim($certNode->textContent);
        if ($body !== "") {
            $signingCertPem = wrap_pem_certificate($body);
            break;
        }
    }

    $encryptionCertPem = "";
    $encryptionMethods = [];
    foreach (
        $xp->query(
            "./md:KeyDescriptor[@use='encryption' or not(@use)]",
            $spDesc
        )
        as $kd
    ) {
        if ($kd instanceof DOMElement) {
            $certNode = $xp->query(".//ds:X509Certificate", $kd)->item(0);
            if ($certNode && $encryptionCertPem === "") {
                // Only a certificate that can encrypt an assertion (RSA) is imported; a
                // signing-only or EC key published without use="signing" is skipped.
                $candidate = saml_certificate_pem($certNode->textContent);
                if ($candidate !== null && saml_encryption_certificate_error($candidate) === null) {
                    $encryptionCertPem = $candidate;
                }
            }
            foreach ($xp->query("./md:EncryptionMethod", $kd) as $em) {
                if ($em instanceof DOMElement) {
                    $alg = trim($em->getAttribute("Algorithm"));
                    if (
                        $alg !== "" &&
                        strlen($alg) <= 256 &&
                        count($encryptionMethods) < 32 &&
                        !in_array($alg, $encryptionMethods, true)
                    ) {
                        $encryptionMethods[] = $alg;
                    }
                }
            }
        }
    }

    // Authenticated AES-GCM whenever the SP advertises it; CBC only when that is all it lists.
    // An SP that lists no supported block cipher gets the default (AES-256-GCM).
    $preferredEncAlg = SAML_ENC_DEFAULT;
    foreach (saml_supported_encryption_algorithms() as $candAlg) {
        if (in_array($candAlg, $encryptionMethods, true)) {
            $preferredEncAlg = $candAlg;
            break;
        }
    }

    // NameIDFormats
    $nameIdFormats = [];
    foreach ($xp->query("./md:NameIDFormat", $spDesc) as $nf) {
        $nameIdFormats[] = trim($nf->textContent);
    }
    $nameIdFormats = saml_name_id_format_list($nameIdFormats);
    // emailAddress when the SP lists it, else the first listed format this IdP can produce.
    $chosenNameIdFormat = SAML_NAMEID_EMAIL;
    if (!empty($nameIdFormats) && !in_array($chosenNameIdFormat, $nameIdFormats, true)) {
        $producible = array_values(array_intersect($nameIdFormats, SAML_IDP_NAMEID_FORMATS));
        $chosenNameIdFormat = $producible[0] ?? $nameIdFormats[0];
    }

    // AssertionConsumerService endpoints. Responses are only ever delivered with HTTP-POST, so
    // only HTTP-POST endpoints are imported (a missing Binding counts as HTTP-POST).
    $acsEndpoints = [];
    $defaultAcsUrl = "";
    foreach ($xp->query("./md:AssertionConsumerService", $spDesc) as $acs) {
        if (!($acs instanceof DOMElement)) {
            continue;
        }
        $binding = trim($acs->getAttribute("Binding"));
        $loc = trim($acs->getAttribute("Location"));
        $isDef = strtolower(trim($acs->getAttribute("isDefault"))) === "true";
        if ($loc === "" || ($binding !== "" && $binding !== SAML_BINDING_POST)) {
            continue;
        }
        $acsEndpoints[] = [
            "index" => saml_endpoint_index($acs->getAttribute("index")),
            "is_default" => $isDef,
            "binding" => SAML_BINDING_POST,
            "location" => $loc,
        ];
        if ($defaultAcsUrl === "" || $isDef) {
            $defaultAcsUrl = $loc;
        }
    }
    if ($defaultAcsUrl === "") {
        throw new InvalidArgumentException(
            "No HTTP-POST md:AssertionConsumerService Location found in SP metadata (only the HTTP-POST binding is supported)"
        );
    }

    // SingleLogoutService: where this IdP answers the SP's LogoutRequests (S02-05). The answer
    // travels through the browser, so the first HTTP-POST endpoint is taken (the signed message
    // this IdP has always posted), else the first HTTP-Redirect one; SOAP, Artifact and unknown
    // bindings are skipped, and so is an endpoint whose Location or ResponseLocation fails
    // validate_endpoint_url(). A missing Binding counts as HTTP-POST, as for the ACS.
    // slo_response_url is the chosen endpoint's ResponseLocation ("": answer at slo_url).
    $sloEndpoints = [];
    foreach ($xp->query("./md:SingleLogoutService", $spDesc) as $slo) {
        if (!($slo instanceof DOMElement)) {
            continue;
        }
        $binding = trim($slo->getAttribute("Binding"));
        if ($binding === "") {
            $binding = SAML_BINDING_POST;
        }
        if (
            ($binding !== SAML_BINDING_POST && $binding !== SAML_BINDING_REDIRECT) ||
            isset($sloEndpoints[$binding])
        ) {
            continue;
        }
        $loc = trim($slo->getAttribute("Location"));
        $responseLoc = trim($slo->getAttribute("ResponseLocation"));
        try {
            validate_endpoint_url($loc, false, "SLO URL");
            if ($responseLoc !== "") {
                validate_endpoint_url($responseLoc, false, "SLO Response URL");
            }
        } catch (InvalidArgumentException $e) {
            continue; // a LogoutResponse could not be delivered there
        }
        $sloEndpoints[$binding] = [$loc, $responseLoc];
    }
    $sloBinding = "";
    $sloUrl = "";
    $sloResponseUrl = "";
    foreach ([SAML_BINDING_POST, SAML_BINDING_REDIRECT] as $candidateBinding) {
        if (isset($sloEndpoints[$candidateBinding])) {
            $sloBinding = $candidateBinding;
            [$sloUrl, $sloResponseUrl] = $sloEndpoints[$candidateBinding];
            break;
        }
    }

    // ServiceName & RequestedAttribute mappings
    $serviceName = "";
    $svcNode = $xp
        ->query("./md:AttributeConsumingService/md:ServiceName", $spDesc)
        ->item(0);
    if ($svcNode) {
        $serviceName = trim($svcNode->textContent);
    }

    $orgDisplayName = "";
    $orgNode = $xp
        ->query("./md:Organization/md:OrganizationDisplayName", $entityNode)
        ->item(0);
    if (!$orgNode) {
        $orgNode = $xp
            ->query("./md:Organization/md:OrganizationName", $entityNode)
            ->item(0);
    }
    if ($orgNode) {
        $orgDisplayName = trim($orgNode->textContent);
    }

    if ($serviceName === "") {
        $host = parse_url($defaultAcsUrl, PHP_URL_HOST) ?: parse_url($spEntityId, PHP_URL_HOST);
        $serviceName = $orgDisplayName !== "" ? $orgDisplayName : ($host ?: "SAML SP");
    } elseif ($orgDisplayName !== "" && strcasecmp($serviceName, $orgDisplayName) !== 0) {
        $serviceName = $serviceName . " (" . $orgDisplayName . ")";
    }

    $attributeMappings = [];
    foreach (
        $xp->query(
            "./md:AttributeConsumingService/md:RequestedAttribute",
            $spDesc
        )
        as $ra
    ) {
        if (!($ra instanceof DOMElement)) {
            continue;
        }
        $attrName = trim($ra->getAttribute("Name"));
        if ($attrName === "") {
            continue;
        }
        $friendly = trim($ra->getAttribute("FriendlyName"));
        $nameFmt = trim($ra->getAttribute("NameFormat"));
        if ($nameFmt === "") {
            $nameFmt = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";
        }
        $isReq = strtolower(trim($ra->getAttribute("isRequired"))) === "true";

        $attributeMappings[] = [
            "name" => $attrName,
            "friendly_name" => $friendly,
            "name_format" => $nameFmt,
            "required" => $isReq,
            "source" => saml_guess_attribute_source($attrName),
        ];
    }

    if (empty($attributeMappings)) {
        $attributeMappings = saml_default_attribute_mappings();
    }

    return [
        "name" => $serviceName,
        "org_display_name" => $orgDisplayName,
        "sp_entity_id" => $spEntityId,
        "acs_url" => $defaultAcsUrl,
        "acs_endpoints" => $acsEndpoints,
        "slo_url" => $sloUrl,
        "slo_binding" => $sloBinding,
        "slo_response_url" => $sloResponseUrl,
        "name_id_format" => $chosenNameIdFormat,
        "name_id_source" => "email",
        "supported_name_id_formats" => $nameIdFormats,
        "sign_response" => true,
        "sign_assertion" => $wantAssertionsSigned,
        "verify_authn_request_sig" => $authnRequestsSigned && $signingCertPem !== "",
        "encrypt_assertion" => false,
        "encryption_alg" => $preferredEncAlg,
        "encryption_methods_supported" => $encryptionMethods,
        "sp_signing_cert_pem" => $signingCertPem,
        "sp_encryption_cert_pem" => $encryptionCertPem,
        "attribute_mapping" => $attributeMappings,
        "raw_sp_metadata_xml" => $xml,
    ];
}

// ---------- IdP Metadata Generation ----------

/**
 * IdP metadata. $samlCert is the active signing certificate (and, with $signMetadata, its key);
 * $additionalSigningCerts are further published certificates (e.g. a staged "next" one or one
 * retired within the grace period, from list_published_provider_saml_certs()), given as rows
 * with "cert_pem" or as PEM strings. One signing KeyDescriptor is emitted per distinct
 * certificate, the active one first; only certificates are read from the rows, never keys.
 */
function saml_build_idp_metadata(
    array $provider,
    string $baseUrl,
    array $samlCert,
    bool $signMetadata = false,
    array $additionalSigningCerts = []
): string {
    $issuer = $baseUrl . "/" . $provider["idp_id"];
    $ssoUrl = $issuer . "/saml/sso";
    $sloUrl = $issuer . "/saml/slo";
    $certBodies = [];
    foreach (array_merge([$samlCert], array_values($additionalSigningCerts)) as $certEntry) {
        $pem = is_array($certEntry) ? ($certEntry["cert_pem"] ?? "") : $certEntry;
        $body = is_string($pem) ? clean_pem_certificate_body($pem) : "";
        if ($body !== "" && !in_array($body, $certBodies, true)) {
            $certBodies[] = $body;
        }
    }

    $doc = new DOMDocument("1.0", "UTF-8");
    $doc->formatOutput = false;

    $ed = $doc->createElementNS(SAML_NS_MD, "md:EntityDescriptor");
    $ed->setAttribute("entityID", $issuer);
    $metaId = "_idp_" . bin2hex(random_bytes(12));
    $ed->setAttribute("ID", $metaId);
    $ed->setIdAttribute("ID", true);
    // SPs that refresh metadata pick up a staged or rotated signing certificate within a day.
    $ed->setAttribute("cacheDuration", "PT24H");
    $doc->appendChild($ed);

    $idpDesc = $doc->createElementNS(SAML_NS_MD, "md:IDPSSODescriptor");
    $idpDesc->setAttribute("WantAuthnRequestsSigned", "false");
    $idpDesc->setAttribute(
        "protocolSupportEnumeration",
        SAML_NS_PROTOCOL
    );
    $ed->appendChild($idpDesc);

    // KeyDescriptor use="signing", one per published certificate
    foreach ($certBodies as $certBody) {
        $kd = $doc->createElementNS(SAML_NS_MD, "md:KeyDescriptor");
        $kd->setAttribute("use", "signing");
        $idpDesc->appendChild($kd);

        $ki = $doc->createElementNS(SAML_NS_DS, "ds:KeyInfo");
        $kd->appendChild($ki);
        $x509Data = $doc->createElementNS(SAML_NS_DS, "ds:X509Data");
        $ki->appendChild($x509Data);
        $x509Cert = $doc->createElementNS(SAML_NS_DS, "ds:X509Certificate", $certBody);
        $x509Data->appendChild($x509Cert);
    }

    // SingleLogoutService
    foreach ([SAML_BINDING_REDIRECT, SAML_BINDING_POST] as $binding) {
        $slo = $doc->createElementNS(SAML_NS_MD, "md:SingleLogoutService");
        $slo->setAttribute("Binding", $binding);
        $slo->setAttribute("Location", $sloUrl);
        $idpDesc->appendChild($slo);
    }

    // NameIDFormats
    foreach (SAML_IDP_NAMEID_FORMATS as $fmt) {
        $nf = $doc->createElementNS(SAML_NS_MD, "md:NameIDFormat", $fmt);
        $idpDesc->appendChild($nf);
    }

    // SingleSignOnService (HTTP-POST & HTTP-Redirect)
    foreach ([SAML_BINDING_POST, SAML_BINDING_REDIRECT] as $binding) {
        $sso = $doc->createElementNS(SAML_NS_MD, "md:SingleSignOnService");
        $sso->setAttribute("Binding", $binding);
        $sso->setAttribute("Location", $ssoUrl);
        $idpDesc->appendChild($sso);
    }

    if ($signMetadata && !empty($samlCert["private_key_pem"])) {
        saml_sign_dom_element(
            $doc,
            $ed,
            (string) $samlCert["private_key_pem"],
            (string) $samlCert["cert_pem"],
            $ed->firstChild
        );
    }

    return (string) $doc->saveXML();
}

// ---------- Exclusive XML-DSig Signing & Verification ----------

function saml_sign_dom_element(
    DOMDocument $doc,
    DOMElement $targetEl,
    string $privateKeyPem,
    string $certPem,
    ?DOMNode $insertBeforeNode = null
): void {
    $id = $targetEl->getAttribute("ID");
    if ($id === "") {
        $id = "_" . bin2hex(random_bytes(16));
        $targetEl->setAttribute("ID", $id);
    }
    $targetEl->setIdAttribute("ID", true);

    $canonTarget = $targetEl->C14N(true, false);
    if ($canonTarget === false || $canonTarget === "") {
        throw new RuntimeException("XML Exclusive C14N failed on target element");
    }
    $digestB64 = base64_encode(hash("sha256", $canonTarget, true));

    $sigEl = $doc->createElementNS(SAML_NS_DS, "ds:Signature");
    $signedInfo = $doc->createElementNS(SAML_NS_DS, "ds:SignedInfo");
    $sigEl->appendChild($signedInfo);

    $c14nMethod = $doc->createElementNS(SAML_NS_DS, "ds:CanonicalizationMethod");
    $c14nMethod->setAttribute(
        "Algorithm",
        "http://www.w3.org/2001/10/xml-exc-c14n#"
    );
    $signedInfo->appendChild($c14nMethod);

    $sigMethod = $doc->createElementNS(SAML_NS_DS, "ds:SignatureMethod");
    $sigMethod->setAttribute(
        "Algorithm",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    );
    $signedInfo->appendChild($sigMethod);

    $ref = $doc->createElementNS(SAML_NS_DS, "ds:Reference");
    $ref->setAttribute("URI", "#" . $id);
    $signedInfo->appendChild($ref);

    $transforms = $doc->createElementNS(SAML_NS_DS, "ds:Transforms");
    $ref->appendChild($transforms);

    $t1 = $doc->createElementNS(SAML_NS_DS, "ds:Transform");
    $t1->setAttribute(
        "Algorithm",
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
    );
    $transforms->appendChild($t1);

    $t2 = $doc->createElementNS(SAML_NS_DS, "ds:Transform");
    $t2->setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#");
    $transforms->appendChild($t2);

    $digestMethod = $doc->createElementNS(SAML_NS_DS, "ds:DigestMethod");
    $digestMethod->setAttribute(
        "Algorithm",
        "http://www.w3.org/2001/04/xmlenc#sha256"
    );
    $ref->appendChild($digestMethod);

    $digestVal = $doc->createElementNS(SAML_NS_DS, "ds:DigestValue", $digestB64);
    $ref->appendChild($digestVal);

    // Insert Signature right after Issuer (per SAML 2.0 XSD schema order) BEFORE SignedInfo C14N
    if ($insertBeforeNode === null) {
        $xp = saml_xpath($doc);
        $issuerNode = $xp->query("./saml:Issuer", $targetEl)->item(0);
        if ($issuerNode) {
            $insertBeforeNode = $issuerNode->nextSibling;
        }
    }
    if ($insertBeforeNode !== null) {
        $targetEl->insertBefore($sigEl, $insertBeforeNode);
    } else {
        $targetEl->appendChild($sigEl);
    }

    $canonSignedInfo = $signedInfo->C14N(true, false);
    if ($canonSignedInfo === false || $canonSignedInfo === "") {
        throw new RuntimeException("XML Exclusive C14N failed on ds:SignedInfo");
    }

    $privRes = openssl_pkey_get_private($privateKeyPem);
    if (!$privRes) {
        throw new RuntimeException("Invalid SAML RSA private key");
    }
    if (!openssl_sign($canonSignedInfo, $rawSig, $privRes, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException("OpenSSL RSA-SHA256 XML signing failed");
    }

    $sigVal = $doc->createElementNS(
        SAML_NS_DS,
        "ds:SignatureValue",
        base64_encode($rawSig)
    );
    $sigEl->appendChild($sigVal);

    $keyInfo = $doc->createElementNS(SAML_NS_DS, "ds:KeyInfo");
    $x509Data = $doc->createElementNS(SAML_NS_DS, "ds:X509Data");
    $x509Cert = $doc->createElementNS(
        SAML_NS_DS,
        "ds:X509Certificate",
        clean_pem_certificate_body($certPem)
    );
    $x509Data->appendChild($x509Cert);
    $keyInfo->appendChild($x509Data);
    $sigEl->appendChild($keyInfo);
}

/**
 * Verifies an enveloped XML-DSig signature on $targetEl against $trustedCertPem,
 * enforcing strict XML Signature Wrapping (XSW) and SHA-2+ algorithm checks.
 */
function saml_verify_dom_element_signature(
    DOMElement $targetEl,
    string $trustedCertPem,
    bool $allowWeakSha1 = false
): bool {
    $doc = $targetEl->ownerDocument;
    if (!$doc) {
        return false;
    }
    $xp = saml_xpath($doc);
    $sigNodes = $xp->query("./ds:Signature", $targetEl);
    if (!$sigNodes || $sigNodes->length !== 1) {
        throw new RuntimeException("Expected exactly one enveloped ds:Signature element");
    }
    $sigNode = $sigNodes->item(0);
    if (!($sigNode instanceof DOMElement)) {
        throw new RuntimeException("Missing enveloped ds:Signature element");
    }

    $signedInfo = $xp->query("./ds:SignedInfo", $sigNode)->item(0);
    $sigValueNode = $xp->query("./ds:SignatureValue", $sigNode)->item(0);
    $refNodes = $xp->query("./ds:SignedInfo/ds:Reference", $sigNode);
    $refNode = $refNodes ? $refNodes->item(0) : null;
    $digestValNode = $xp
        ->query("./ds:SignedInfo/ds:Reference/ds:DigestValue", $sigNode)
        ->item(0);
    $digestMethodNode = $xp
        ->query("./ds:SignedInfo/ds:Reference/ds:DigestMethod", $sigNode)
        ->item(0);
    $sigMethodNode = $xp
        ->query("./ds:SignedInfo/ds:SignatureMethod", $sigNode)
        ->item(0);
    $c14nMethodNode = $xp
        ->query("./ds:SignedInfo/ds:CanonicalizationMethod", $sigNode)
        ->item(0);

    if (
        !($signedInfo instanceof DOMElement) ||
        !$sigValueNode ||
        !$refNodes ||
        $refNodes->length !== 1 ||
        !($refNode instanceof DOMElement) ||
        !$digestValNode
    ) {
        throw new RuntimeException("Malformed ds:Signature structure");
    }

    // XSW Defense: target element MUST have a non-empty, document-unique ID, and Reference URI MUST match "#<ID>"
    $targetId = trim($targetEl->getAttribute("ID"));
    if ($targetId === "" || !preg_match('/^[A-Za-z_][A-Za-z0-9._\-]{0,127}$/D', $targetId)) {
        throw new RuntimeException("Signed SAML element has missing or invalid ID attribute");
    }
    $uri = trim($refNode->getAttribute("URI"));
    if ($uri !== "#" . $targetId) {
        throw new RuntimeException(
            "ds:Reference URI ($uri) must strictly match target element ID (#$targetId)"
        );
    }
    $matchingIdNodes = $xp->query("//*[@ID='" . $targetId . "']");
    if (
        !$matchingIdNodes ||
        $matchingIdNodes->length !== 1 ||
        !$matchingIdNodes->item(0)->isSameNode($targetEl)
    ) {
        throw new RuntimeException(
            "XML Signature Wrapping detected: duplicate or mismatched element ID"
        );
    }

    // SignedInfo is canonicalized exactly as its CanonicalizationMethod says: inclusive or
    // exclusive, #WithComments, and an exclusive InclusiveNamespaces PrefixList. It stays in
    // the document, so inclusive canonicalization sees the namespaces in scope from ancestors.
    $siExclusive = true;
    $siWithComments = false;
    $siPrefixes = null;
    if ($c14nMethodNode instanceof DOMElement) {
        $cAlg = trim($c14nMethodNode->getAttribute("Algorithm"));
        if (!isset(SAML_C14N_ALGORITHMS[$cAlg])) {
            throw new RuntimeException("Unsupported CanonicalizationMethod: $cAlg");
        }
        [$siExclusive, $siWithComments] = SAML_C14N_ALGORITHMS[$cAlg];
        $siPrefixes = $siExclusive ? saml_c14n_inclusive_prefixes($c14nMethodNode) : null;
    }
    $canonSignedInfo = $signedInfo->C14N($siExclusive, $siWithComments, null, $siPrefixes);
    if (!is_string($canonSignedInfo) || $canonSignedInfo === "") {
        throw new RuntimeException("XML C14N failed on ds:SignedInfo");
    }

    $sigMethodAlg =
        $sigMethodNode instanceof DOMElement
            ? trim($sigMethodNode->getAttribute("Algorithm"))
            : "";
    [$opensslAlg, $keyType] = saml_signature_algorithm(
        $sigMethodAlg,
        $allowWeakSha1,
        "XML SignatureMethod"
    );

    $pubKey = saml_trusted_public_key(
        $trustedCertPem,
        "Invalid trusted X.509 certificate for XML-DSig verification"
    );
    $rawSig = base64_decode(
        preg_replace('/\s+/', "", $sigValueNode->textContent) ?? "",
        true
    );
    if ($rawSig === false) {
        throw new RuntimeException("Invalid base64 in ds:SignatureValue");
    }

    if (!saml_openssl_verify($canonSignedInfo, $rawSig, $pubKey, $opensslAlg, $keyType)) {
        throw new RuntimeException(
            "XML-DSig cryptographic signature verification failed"
        );
    }

    // Transforms allowlist (SAML Core 5.4.4): the enveloped-signature transform, optionally
    // followed by a canonicalization. The last canonicalization transform decides; with none,
    // XML-DSig 4.3.3.2 converts the remaining node-set with inclusive Canonical XML 1.0.
    $refExclusive = null;
    $refPrefixes = null;
    $sawEnvelopedTransform = false;
    foreach ($xp->query("./ds:Transforms/ds:Transform", $refNode) as $tr) {
        if ($tr instanceof DOMElement) {
            $tAlg = trim($tr->getAttribute("Algorithm"));
            if ($tAlg === "http://www.w3.org/2000/09/xmldsig#enveloped-signature") {
                $sawEnvelopedTransform = true;
            } elseif (isset(SAML_C14N_ALGORITHMS[$tAlg])) {
                $refExclusive = SAML_C14N_ALGORITHMS[$tAlg][0];
                $refPrefixes = $refExclusive ? saml_c14n_inclusive_prefixes($tr) : null;
            } else {
                throw new RuntimeException("Forbidden XML-DSig Transform: $tAlg");
            }
        }
    }
    if (!$sawEnvelopedTransform) {
        throw new RuntimeException("Missing enveloped-signature transform");
    }
    $refExclusive ??= false;

    // The referenced element is canonicalized in its own document (so inclusive mode and a
    // PrefixList see the namespaces in scope from its ancestors), over the node-set of the
    // "#ID" reference minus exactly the enveloped ds:Signature being verified: the one child
    // ds:Signature of the element that carries this (document-unique, checked above) ID.
    // Comments are never part of a "#ID" reference (XML-DSig 4.3.3.3).
    $refNodeSet = [
        "query" =>
            "(.//. | .//@* | .//namespace::*)[not(self::comment()) and " .
            "not(ancestor-or-self::ds:Signature[parent::*[@ID='" . $targetId . "']])]",
        "namespaces" => ["ds" => SAML_NS_DS],
    ];
    $canonTarget = $targetEl->C14N($refExclusive, false, $refNodeSet, $refPrefixes);
    if (!is_string($canonTarget) || $canonTarget === "") {
        throw new RuntimeException("XML C14N failed on the signed element");
    }
    $digestAlg =
        $digestMethodNode instanceof DOMElement
            ? trim($digestMethodNode->getAttribute("Algorithm"))
            : "";
    $hashAlgo = match ($digestAlg) {
        "http://www.w3.org/2001/04/xmlenc#sha256" => "sha256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => "sha384",
        "http://www.w3.org/2001/04/xmlenc#sha512" => "sha512",
        "http://www.w3.org/2000/09/xmldsig#sha1" => $allowWeakSha1
            ? "sha1"
            : throw new RuntimeException(
                "Unsupported or weak XML DigestMethod: $digestAlg"
            ),
        default => throw new RuntimeException(
            "Unsupported or weak XML DigestMethod: $digestAlg"
        ),
    };

    $computedDigest = base64_encode(hash($hashAlgo, $canonTarget, true));
    $expectedDigest =
        preg_replace('/\s+/', "", $digestValNode->textContent) ?? "";

    if (!hash_equals($expectedDigest, $computedDigest)) {
        throw new RuntimeException("XML-DSig Reference DigestValue mismatch");
    }

    return true;
}

/**
 * PrefixList tokens of the ec:InclusiveNamespaces child of an exclusive canonicalization
 * Transform or CanonicalizationMethod (Exclusive XML Canonicalization 1.0, section 3), in the
 * form DOMNode::C14N() takes ("#default" stands for the default namespace), or null when there
 * is none. Throws RuntimeException for a malformed list.
 */
function saml_c14n_inclusive_prefixes(DOMElement $methodEl): ?array
{
    $prefixes = [];
    $found = 0;
    foreach ($methodEl->childNodes as $child) {
        if (
            !($child instanceof DOMElement) ||
            $child->namespaceURI !== SAML_NS_EXC_C14N ||
            $child->localName !== "InclusiveNamespaces"
        ) {
            continue;
        }
        if (++$found > 1) {
            throw new RuntimeException("A canonicalization method has more than one InclusiveNamespaces element");
        }
        $tokens = preg_split('/\s+/', trim($child->getAttribute("PrefixList")), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        foreach ($tokens as $token) {
            if ($token !== "#default" && preg_match('/^[\p{L}_][\p{L}\p{N}._\-]{0,63}$/uD', $token) !== 1) {
                throw new RuntimeException("Invalid InclusiveNamespaces PrefixList");
            }
            if (!in_array($token, $prefixes, true)) {
                $prefixes[] = $token;
            }
            if (count($prefixes) > 32) {
                throw new RuntimeException("InclusiveNamespaces PrefixList is too long");
            }
        }
    }
    return $prefixes === [] ? null : $prefixes;
}

/**
 * A certificate (or public key) given as PEM (text before the first "-----BEGIN " line, such
 * as "openssl x509 -text" output, is dropped) or as the bare base64 DER body SAML metadata
 * carries, returned as PEM; null for anything else. Only PEM text ever reaches OpenSSL, which
 * would otherwise read a "file://..." value as a path on the server.
 */
function saml_certificate_pem(string $value): ?string
{
    $value = trim($value);
    if ($value === "" || strlen($value) > 65536) {
        return null;
    }
    $pemStart = strpos($value, "-----BEGIN ");
    if ($pemStart !== false) {
        return substr($value, $pemStart) . "\n";
    }
    $body = preg_replace('/\s+/', "", $value) ?? "";
    if (
        $body === "" ||
        preg_match('#^[A-Za-z0-9+/]+={0,2}$#D', $body) !== 1 ||
        base64_decode($body, true) === false
    ) {
        return null;
    }
    return wrap_pem_certificate($body);
}

/** The public key of a trusted certificate (see saml_certificate_pem()); throws $errorMessage. */
function saml_trusted_public_key(string $certPem, string $errorMessage): OpenSSLAsymmetricKey
{
    $pem = saml_certificate_pem($certPem);
    $key = $pem !== null ? openssl_pkey_get_public($pem) : false;
    if ($key === false) {
        throw new RuntimeException($errorMessage);
    }
    return $key;
}

/**
 * The query-string parameter name PHP files a raw name under in $_GET: URL-decoded ("+" is a
 * space), cut at a NUL byte, leading spaces dropped, cut at "[" (array syntax), and " " and
 * "." turned into "_".
 */
function saml_php_query_name(string $rawName): string
{
    $name = urldecode($rawName);
    $nul = strpos($name, "\0");
    if ($nul !== false) {
        $name = substr($name, 0, $nul);
    }
    $name = ltrim($name, " ");
    $bracket = strpos($name, "[");
    if ($bracket !== false) {
        $name = substr($name, 0, $bracket);
    }
    return strtr($name, [" " => "_", "." => "_"]);
}

/**
 * Parses an HTTP-Redirect binding query string once (SAML Bindings 3.4.4). Returns the
 * URL-decoded values of SAMLRequest, SAMLResponse, RelayState, SigAlg and Signature (null when
 * absent), which are exactly what PHP puts in $_GET for them, and under "raw" the still
 * URL-encoded values of those present, which a Redirect signature covers. Throws
 * InvalidArgumentException when one of them appears more than once or under any other
 * spelling PHP also maps to its name (an encoded name, leading spaces or "+", ".", " " or
 * "[...]" forms, a NUL), or when the query has more parameters than PHP registers, so the
 * values that are verified are always the values that are processed. Take SAMLRequest and
 * RelayState of GET requests from here rather than from $_GET.
 */
function saml_redirect_binding_params(string $rawQueryString): array
{
    $names = ["SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature"];
    $out = array_fill_keys($names, null);
    $raw = [];
    $separators = (string) ini_get("arg_separator.input");
    if ($separators === "") {
        $separators = "&";
    }
    $pairs = preg_split("/[" . preg_quote($separators, "/") . "]/", $rawQueryString) ?: [];
    $maxPairs = 100;
    $maxInputVars = (int) ini_get("max_input_vars");
    if ($maxInputVars > 0 && $maxInputVars < $maxPairs) {
        $maxPairs = $maxInputVars;
    }
    $count = 0;
    foreach ($pairs as $pair) {
        if ($pair === "") {
            continue;
        }
        if (++$count > $maxPairs) {
            throw new InvalidArgumentException("The SAML request URL has too many query parameters");
        }
        $eq = strpos($pair, "=");
        $rawName = $eq === false ? $pair : substr($pair, 0, $eq);
        $phpName = saml_php_query_name($rawName);
        if (!in_array($phpName, $names, true)) {
            continue;
        }
        if ($rawName !== $phpName) {
            throw new InvalidArgumentException(
                "The $phpName query parameter must appear under its exact name"
            );
        }
        if (array_key_exists($phpName, $raw)) {
            throw new InvalidArgumentException("The $phpName query parameter appears more than once");
        }
        $raw[$phpName] = $eq === false ? "" : substr($pair, $eq + 1);
        $out[$phpName] = urldecode($raw[$phpName]);
    }
    $out["raw"] = $raw;
    return $out;
}

/**
 * Verifies the detached HTTP-Redirect signature (SAML Bindings 3.4.4.1) over the raw, still
 * URL-encoded parameters from saml_redirect_binding_params():
 * <$messageParam>=<value>[&RelayState=<value>]&SigAlg=<value>, where $messageParam is
 * "SAMLRequest" or "SAMLResponse". Throws RuntimeException on failure, and
 * InvalidArgumentException for an ambiguous query. $verifiedParams receives the parsed
 * parameters the signature was checked against.
 */
function saml_verify_redirect_query_signature(
    string $rawQueryString,
    string $trustedCertPem,
    bool $allowWeakSha1 = false,
    ?array &$verifiedParams = null,
    string $messageParam = "SAMLRequest"
): bool {
    $verifiedParams = null;
    if (!in_array($messageParam, ["SAMLRequest", "SAMLResponse"], true)) {
        throw new InvalidArgumentException("Unsupported HTTP-Redirect message parameter");
    }
    $params = saml_redirect_binding_params($rawQueryString);
    $rawParams = $params["raw"];
    $otherParam = $messageParam === "SAMLRequest" ? "SAMLResponse" : "SAMLRequest";
    if (array_key_exists($otherParam, $rawParams)) {
        throw new InvalidArgumentException("An HTTP-Redirect message carries either SAMLRequest or SAMLResponse, not both");
    }
    if (
        ($rawParams[$messageParam] ?? "") === "" ||
        ($rawParams["SigAlg"] ?? "") === "" ||
        ($rawParams["Signature"] ?? "") === ""
    ) {
        throw new RuntimeException("Missing SigAlg or Signature on the HTTP-Redirect SAML message");
    }

    $signedQuery = $messageParam . "=" . $rawParams[$messageParam];
    if (($rawParams["RelayState"] ?? "") !== "") {
        $signedQuery .= "&RelayState=" . $rawParams["RelayState"];
    }
    $signedQuery .= "&SigAlg=" . $rawParams["SigAlg"];

    $sigAlgUri = (string) $params["SigAlg"];
    $sigBin = base64_decode(rawurldecode($rawParams["Signature"]), true);
    if ($sigBin === false) {
        throw new RuntimeException("Invalid base64 Signature in HTTP-Redirect query");
    }

    [$opensslAlg, $keyType] = saml_signature_algorithm(
        $sigAlgUri,
        $allowWeakSha1,
        "HTTP-Redirect SigAlg"
    );

    $pubKey = saml_trusted_public_key($trustedCertPem, "Invalid SP signing certificate");
    if (!saml_openssl_verify($signedQuery, $sigBin, $pubKey, $opensslAlg, $keyType)) {
        throw new RuntimeException("HTTP-Redirect SAML message signature verification failed");
    }
    $verifiedParams = $params;
    return true;
}

/**
 * Maps an XML-DSig / HTTP-Redirect signature algorithm URI to [OpenSSL digest, key type].
 * The key type binds the algorithm to the certificate: an RSA key never verifies an ecdsa-*
 * signature and vice versa. SHA-1 is only accepted with $allowWeakSha1.
 */
function saml_signature_algorithm(string $uri, bool $allowWeakSha1, string $label): array
{
    return match ($uri) {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => [OPENSSL_ALGO_SHA256, OPENSSL_KEYTYPE_RSA],
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" => [OPENSSL_ALGO_SHA384, OPENSSL_KEYTYPE_RSA],
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => [OPENSSL_ALGO_SHA512, OPENSSL_KEYTYPE_RSA],
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" => [OPENSSL_ALGO_SHA256, OPENSSL_KEYTYPE_EC],
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" => [OPENSSL_ALGO_SHA384, OPENSSL_KEYTYPE_EC],
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" => [OPENSSL_ALGO_SHA512, OPENSSL_KEYTYPE_EC],
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => $allowWeakSha1
            ? [OPENSSL_ALGO_SHA1, OPENSSL_KEYTYPE_RSA]
            : throw new RuntimeException("Unsupported or weak $label: $uri"),
        default => throw new RuntimeException("Unsupported or weak $label: $uri"),
    };
}

/**
 * openssl_verify() for SAML signatures. The key must be of $keyType. ECDSA values are
 * accepted as the fixed-length r||s concatenation that XML-DSig 1.1 (6.4.3) and RFC 4050
 * define, converted to the DER ECDSA-Sig-Value OpenSSL expects, and also as DER, which some
 * SAML stacks emit (both encode the same r and s).
 */
function saml_openssl_verify(
    string $data,
    string $signature,
    OpenSSLAsymmetricKey $publicKey,
    int $opensslAlg,
    int $keyType
): bool {
    $details = openssl_pkey_get_details($publicKey);
    if (!is_array($details) || ($details["type"] ?? null) !== $keyType) {
        throw new RuntimeException(
            "The signature algorithm does not match the key type of the signing certificate"
        );
    }
    if ($signature === "") {
        return false;
    }
    if ($keyType !== OPENSSL_KEYTYPE_EC) {
        return openssl_verify($data, $signature, $publicKey, $opensslAlg) === 1;
    }
    $coordLen = intdiv((int) ($details["bits"] ?? 0) + 7, 8);
    $candidates = [];
    if ($coordLen > 0 && strlen($signature) === 2 * $coordLen) {
        $candidates[] = der_sequence(
            der_integer_unsigned(substr($signature, 0, $coordLen)) .
                der_integer_unsigned(substr($signature, $coordLen))
        );
    }
    if ($signature[0] === "\x30") {
        $candidates[] = $signature;
    }
    foreach ($candidates as $derSignature) {
        if (openssl_verify($data, $derSignature, $publicKey, $opensslAlg) === 1) {
            return true;
        }
    }
    return false;
}

// ---------- Incoming AuthnRequest Parsing ----------

/**
 * Decodes a SAMLRequest/SAMLResponse parameter: base64, then DEFLATE for HTTP-Redirect. The
 * decoded XML is capped at SAML_MAX_MESSAGE_BYTES (64 KiB).
 */
function saml_decode_binding_payload(string $b64Payload, string $binding): string
{
    // Base64 of 64 KiB, with room for the line breaks some SPs insert.
    if (strlen($b64Payload) > 2 * SAML_MAX_MESSAGE_BYTES) {
        throw new InvalidArgumentException("SAML payload exceeds maximum allowed size");
    }
    $raw = base64_decode($b64Payload, true);
    if ($raw === false || $raw === "") {
        throw new InvalidArgumentException("Invalid base64 SAML payload");
    }
    if ($binding === SAML_BINDING_REDIRECT) {
        $inflated = @gzinflate($raw, SAML_MAX_MESSAGE_BYTES);
        if ($inflated === false) {
            $inflated = @gzuncompress($raw, SAML_MAX_MESSAGE_BYTES);
        }
        if ($inflated === false) {
            if (
                strlen($raw) <= SAML_MAX_MESSAGE_BYTES &&
                (str_contains($raw, "AuthnRequest") ||
                    str_contains($raw, "LogoutRequest") ||
                    str_contains($raw, "LogoutResponse"))
            ) {
                return $raw;
            }
            throw new InvalidArgumentException(
                "Failed to DEFLATE-decompress the HTTP-Redirect SAML message (or it exceeds 64 KB)"
            );
        }
        return $inflated;
    }
    if (strlen($raw) > SAML_MAX_MESSAGE_BYTES) {
        throw new InvalidArgumentException("SAML message exceeds maximum allowed size (64 KB)");
    }
    return $raw;
}

/**
 * Unix time of an xs:dateTime (SAML Core 1.3.3: UTC, "Z" or no zone; an explicit offset is
 * applied), or null when it is not one.
 */
function saml_parse_instant(string $value): ?int
{
    if (
        preg_match(
            '/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})?$/D',
            trim($value),
            $m
        ) !== 1
    ) {
        return null;
    }
    [$year, $month, $day, $hour, $minute, $second] = array_map("intval", array_slice($m, 1, 6));
    if (!checkdate($month, $day, $year) || $hour > 23 || $minute > 59 || $second > 60) {
        return null;
    }
    $ts = gmmktime($hour, $minute, min($second, 59), $month, $day, $year);
    if (!is_int($ts)) {
        return null;
    }
    $zone = $m[7] ?? "";
    if ($zone !== "" && $zone !== "Z") {
        $offset = (int) substr($zone, 1, 2) * 3600 + (int) substr($zone, 4, 2) * 60;
        if ($offset > 14 * 3600) {
            return null;
        }
        $ts += $zone[0] === "-" ? $offset : -$offset;
    }
    return $ts;
}

/**
 * Message checks shared by incoming SAML requests (SAML Core 3.2.1): a non-empty NCName ID
 * (at most 128 characters), Version 2.0, and an IssueInstant no older than
 * SAML_REQUEST_MAX_AGE plus SAML_CLOCK_SKEW seconds and at most SAML_CLOCK_SKEW seconds
 * ahead. Throws InvalidArgumentException; returns [ID, IssueInstant or null].
 */
function saml_check_request_header(DOMElement $root, string $label, bool $enforce = true): array
{
    $reqId = trim($root->getAttribute("ID"));
    if ($reqId === "" && $enforce) {
        throw new InvalidArgumentException("$label is missing its ID");
    }
    if ($reqId !== "" && preg_match('/^[A-Za-z_][A-Za-z0-9._\-]{0,127}$/D', $reqId) !== 1) {
        throw new InvalidArgumentException("$label ID is not a valid XML NCName");
    }
    $issueInstant = null;
    if ($enforce) {
        if (trim($root->getAttribute("Version")) !== "2.0") {
            throw new InvalidArgumentException("$label must be a SAML 2.0 message (Version=\"2.0\")");
        }
        $issueInstant = saml_parse_instant($root->getAttribute("IssueInstant"));
        if ($issueInstant === null) {
            throw new InvalidArgumentException("$label has a missing or invalid IssueInstant");
        }
        $now = time();
        if ($issueInstant < $now - SAML_REQUEST_MAX_AGE - SAML_CLOCK_SKEW) {
            throw new InvalidArgumentException(
                "$label has expired (IssueInstant is too old); start the sign-in again at the service provider"
            );
        }
        if ($issueInstant > $now + SAML_CLOCK_SKEW) {
            throw new InvalidArgumentException("$label IssueInstant is in the future; check the service provider's clock");
        }
    }
    return [$reqId, $issueInstant];
}

/**
 * The SAML Issuer element directly under $root: trimmed, at most 1024 bytes. Throws
 * InvalidArgumentException when it is missing or too long.
 */
function saml_message_issuer(DOMXPath $xp, DOMElement $root, string $label): string
{
    $issuerNode = $xp->query("./saml:Issuer", $root)->item(0);
    $issuer = $issuerNode ? trim($issuerNode->textContent) : "";
    if ($issuer === "") {
        throw new InvalidArgumentException("$label is missing saml:Issuer");
    }
    if (strlen($issuer) > 1024) {
        throw new InvalidArgumentException("$label Issuer is too long");
    }
    return $issuer;
}

/**
 * For an HTTP-Redirect message with its raw query string: parses the query once (see
 * saml_redirect_binding_params()) and requires that $xml is exactly the decoded $param of that
 * query, so a signature checked over the query covers the XML being processed. Returns the
 * parsed parameters.
 */
function saml_redirect_params_matching_xml(string $rawQueryString, string $xml, string $param): array
{
    $params = saml_redirect_binding_params($rawQueryString);
    $encoded = (string) ($params[$param] ?? "");
    if ($encoded === "") {
        throw new InvalidArgumentException("The HTTP-Redirect query has no $param parameter");
    }
    if (trim(saml_decode_binding_payload($encoded, SAML_BINDING_REDIRECT)) !== trim($xml)) {
        throw new InvalidArgumentException(
            "The SAML message does not match the $param parameter of the HTTP-Redirect query"
        );
    }
    return $params;
}

/**
 * Parses an incoming SP-initiated <AuthnRequest> (HTTP-Redirect or HTTP-POST).
 *
 * Message checks, always: the structure limits (SAML_MESSAGE_LIMITS, checked before libxml2
 * parses $xml), a root samlp:AuthnRequest with an Issuer (at most 1024 bytes), a
 * NameIDPolicy Format of at most 256 bytes, and a Destination equal to
 * $expectedDestinationUrl when one is present. Unless legacy_saml_compat is on, also an NCName
 * ID, Version 2.0, an IssueInstant within SAML_REQUEST_MAX_AGE plus SAML_CLOCK_SKEW seconds, a
 * ProtocolBinding of HTTP-POST (or none) and a valid AssertionConsumerServiceIndex. For
 * HTTP-Redirect with $rawQueryString, the query is parsed once and $xml must be exactly its
 * SAMLRequest (see saml_redirect_binding_params()).
 *
 * Without $matchedApp (the preliminary parse that finds the app by Issuer) nothing else is
 * checked. The call with the app reuses the document the preliminary call built for the same
 * $xml, so libxml2 parses each request once (saml_load_inbound_message()). With $matchedApp,
 * call it once per request; it also:
 *  - verifies the signature when the app requires signed AuthnRequests: the HTTP-Redirect
 *    query signature over exactly the parsed values, or the enveloped XML signature;
 *  - for signed requests (unless legacy_saml_compat): requires a Destination and records the
 *    request ID for replay detection (saml_record_request_id(), in $storePath, by default the
 *    global store), so the same signed request is accepted only once;
 *  - throws SamlStatusError, carrying the parsed request in ->authnRequest, for a
 *    NameIDPolicy Format the app does not allow (Requester/InvalidNameIDPolicy) and for an
 *    authentication context no sign-in here can meet (Responder/NoAuthnContext).
 * Other failures throw InvalidArgumentException or RuntimeException.
 */
function saml_parse_authn_request(
    string $xml,
    string $binding,
    string $rawQueryString = "",
    ?array $matchedApp = null,
    ?string $expectedDestinationUrl = null,
    ?string $storePath = null
): array {
    $doc = saml_load_inbound_message($xml);
    $root = $doc->documentElement;
    if (
        !$root ||
        $root->namespaceURI !== SAML_NS_PROTOCOL ||
        $root->localName !== "AuthnRequest"
    ) {
        throw new InvalidArgumentException("Root element is not a SAML 2.0 AuthnRequest");
    }
    $legacy = saml_legacy_compat();

    $xp = saml_xpath($doc);
    $issuer = saml_message_issuer($xp, $root, "AuthnRequest");
    [$reqId] = saml_check_request_header($root, "AuthnRequest", !$legacy);

    $acsUrl = trim($root->getAttribute("AssertionConsumerServiceURL"));
    $acsIndexAttr = null;
    if ($root->hasAttribute("AssertionConsumerServiceIndex")) {
        $rawAcsIndex = $root->getAttribute("AssertionConsumerServiceIndex");
        $acsIndexAttr = saml_endpoint_index($rawAcsIndex);
        if ($acsIndexAttr === null) {
            if (!$legacy) {
                throw new InvalidArgumentException(
                    "AuthnRequest AssertionConsumerServiceIndex is not a valid endpoint index"
                );
            }
            $acsIndexAttr = (int) $rawAcsIndex;
        }
    }
    // Responses are only ever delivered with HTTP-POST (SAML Core 3.4.1).
    $protocolBinding = trim($root->getAttribute("ProtocolBinding"));
    if (!$legacy && $protocolBinding !== "" && $protocolBinding !== SAML_BINDING_POST) {
        throw new InvalidArgumentException(
            "Unsupported ProtocolBinding in the AuthnRequest: this identity provider only sends responses with the HTTP-POST binding"
        );
    }
    $destination = trim($root->getAttribute("Destination"));
    if (
        $expectedDestinationUrl !== null &&
        $destination !== "" &&
        $destination !== $expectedDestinationUrl
    ) {
        throw new RuntimeException(
            "AuthnRequest Destination mismatch (expected $expectedDestinationUrl)"
        );
    }
    // xs:boolean: "true" or "1" (S06-03). ForceAuthn="1" must not silently reuse an SSO
    // session, and IsPassive="1" must not show the sign-in page.
    $forceAuthn = in_array(strtolower(trim($root->getAttribute("ForceAuthn"))), ["true", "1"], true);
    $isPassive = in_array(strtolower(trim($root->getAttribute("IsPassive"))), ["true", "1"], true);

    $nameIdPolicyNode = $xp->query("./samlp:NameIDPolicy", $root)->item(0);
    $requestedNameIdFormat =
        $nameIdPolicyNode instanceof DOMElement
            ? trim($nameIdPolicyNode->getAttribute("Format"))
            : "";
    if (strlen($requestedNameIdFormat) > 256) {
        throw new InvalidArgumentException("AuthnRequest NameIDPolicy Format is too long");
    }
    $requestedAuthnContext = saml_parse_requested_authn_context($xp, $root);

    // One parse of the Redirect query: what is verified below is what is processed.
    if ($binding === SAML_BINDING_REDIRECT && $rawQueryString !== "") {
        saml_redirect_params_matching_xml($rawQueryString, $xml, "SAMLRequest");
    }

    $signatureVerified = false;
    if ($matchedApp !== null && !empty($matchedApp["verify_authn_request_sig"])) {
        $spCert = trim((string) ($matchedApp["sp_signing_cert_pem"] ?? ""));
        if ($spCert === "") {
            throw new RuntimeException(
                "App requires signed AuthnRequests, but no SP signing certificate is configured"
            );
        }
        $allowWeakSha1 = !empty($matchedApp["allow_weak_sha1"]);
        if ($binding === SAML_BINDING_REDIRECT) {
            // An empty $rawQueryString fails here (no SigAlg/Signature); a non-empty one was
            // matched against $xml above and is parsed again identically.
            $signatureVerified = saml_verify_redirect_query_signature(
                $rawQueryString,
                $spCert,
                $allowWeakSha1
            );
        } else {
            $signatureVerified = saml_verify_dom_element_signature(
                $root,
                $spCert,
                $allowWeakSha1
            );
        }
    }

    if ($signatureVerified && !$legacy) {
        // SAML Bindings 3.4.5.2 / 3.5.5.2: a signed message must name where it was sent.
        if ($destination === "") {
            throw new RuntimeException("Signed AuthnRequests must carry a Destination");
        }
        saml_record_request_id(
            saml_store_path($storePath),
            (string) ($matchedApp["provider_id"] ?? ""),
            $issuer,
            $reqId
        );
    }

    $parsed = [
        "id" => $reqId,
        "issuer" => $issuer,
        "acs_url" => $acsUrl,
        "acs_index" => $acsIndexAttr,
        "destination" => $destination,
        "force_authn" => $forceAuthn,
        "is_passive" => $isPassive,
        "requested_name_id_format" => $requestedNameIdFormat,
        // null, or ["comparison" => exact|minimum|maximum|better, "class_refs" => [...], "decl_refs" => [...]]
        "requested_authn_context" => $requestedAuthnContext,
        "signature_verified" => $signatureVerified,
    ];

    if ($matchedApp !== null) {
        // SAML Core 3.4.1.1: a NameIDPolicy Format the app does not allow is refused up front.
        saml_effective_name_id_format($matchedApp, $requestedNameIdFormat, $parsed);

        // SAML Core 3.3.2.2.1: a requested context the IdP cannot satisfy with any sign-in it
        // offers is answered with Responder/NoAuthnContext (one it can satisfy may need a
        // step-up, see saml_requested_min_auth_policy()).
        if (
            $requestedAuthnContext !== null &&
            saml_required_authn_rank($requestedAuthnContext) === null
        ) {
            throw new SamlStatusError(
                "Responder",
                "NoAuthnContext",
                "The authentication context requested by the service provider is not supported by this identity provider",
                null,
                $parsed
            );
        }
    }

    return $parsed;
}

/**
 * Parses an SP-initiated <samlp:LogoutRequest> (HTTP-Redirect or HTTP-POST) for Single Logout.
 * Returns id, issuer, destination, name_id, name_id_format, session_indexes (list),
 * not_on_or_after (Unix time or null) and signature_verified.
 *
 * Checks: the structure limits (SAML_MESSAGE_LIMITS, before libxml2 parses $xml); a root
 * samlp:LogoutRequest; an Issuer, equal to the app's SP Entity ID when $app is
 * given; an NCName ID, Version 2.0 and a fresh IssueInstant; exactly one saml:NameID
 * (EncryptedID and BaseID are not supported); NotOnOrAfter not passed; a present Destination
 * equal to $expectedDestinationUrl. For HTTP-Redirect with $rawQueryString, $xml must be
 * exactly the query's SAMLRequest. When $app has an SP signing certificate, a signature is
 * required and verified (HTTP-Redirect: the query signature over the
 * saml_redirect_binding_params() values; HTTP-POST: the enveloped XML signature) and the
 * Destination must be present. Every failure throws InvalidArgumentException. A call with $app
 * after one without it, for the same $xml, reuses that call's document
 * (saml_load_inbound_message()).
 *
 * signature_verified is false when there is no $app or it has no signing certificate: such a
 * request does not prove that the SP sent it, so confirm with the user (and match NameID and
 * SessionIndex to the session) before ending an SSO session for it.
 */
function saml_parse_logout_request(
    string $xml,
    string $binding,
    string $rawQueryString = "",
    ?array $app = null,
    ?string $expectedDestinationUrl = null
): array {
    try {
        $doc = saml_load_inbound_message($xml);
        $root = $doc->documentElement;
        if (
            !$root ||
            $root->namespaceURI !== SAML_NS_PROTOCOL ||
            $root->localName !== "LogoutRequest"
        ) {
            throw new InvalidArgumentException("Root element is not a SAML 2.0 LogoutRequest");
        }
        $xp = saml_xpath($doc);
        $issuer = saml_message_issuer($xp, $root, "LogoutRequest");
        if ($app !== null && $issuer !== trim((string) ($app["sp_entity_id"] ?? ""))) {
            throw new InvalidArgumentException(
                "LogoutRequest Issuer does not match the application's SP Entity ID"
            );
        }
        [$reqId] = saml_check_request_header($root, "LogoutRequest");

        $notOnOrAfter = null;
        if ($root->hasAttribute("NotOnOrAfter")) {
            $notOnOrAfter = saml_parse_instant($root->getAttribute("NotOnOrAfter"));
            if ($notOnOrAfter === null) {
                throw new InvalidArgumentException("LogoutRequest NotOnOrAfter is invalid");
            }
            if ($notOnOrAfter + SAML_CLOCK_SKEW <= time()) {
                throw new InvalidArgumentException("LogoutRequest has expired (NotOnOrAfter)");
            }
        }

        $destination = trim($root->getAttribute("Destination"));
        if (
            $expectedDestinationUrl !== null &&
            $destination !== "" &&
            $destination !== $expectedDestinationUrl
        ) {
            throw new InvalidArgumentException(
                "LogoutRequest Destination mismatch (expected $expectedDestinationUrl)"
            );
        }

        if ($xp->query("./saml:EncryptedID | ./saml:BaseID", $root)->length > 0) {
            throw new InvalidArgumentException(
                "Encrypted or base identifiers in a LogoutRequest are not supported"
            );
        }
        $nameIdNodes = $xp->query("./saml:NameID", $root);
        $nameIdNode = $nameIdNodes->item(0);
        if ($nameIdNodes->length !== 1 || !($nameIdNode instanceof DOMElement)) {
            throw new InvalidArgumentException("LogoutRequest must carry exactly one saml:NameID");
        }
        $nameId = trim($nameIdNode->textContent);
        $nameIdFormat = trim($nameIdNode->getAttribute("Format"));
        if ($nameId === "" || strlen($nameId) > 1024 || strlen($nameIdFormat) > 256) {
            throw new InvalidArgumentException("LogoutRequest NameID is empty or too long");
        }

        $sessionIndexes = [];
        foreach ($xp->query("./samlp:SessionIndex", $root) as $sessionIndexNode) {
            $sessionIndex = trim($sessionIndexNode->textContent);
            if ($sessionIndex === "" || in_array($sessionIndex, $sessionIndexes, true)) {
                continue;
            }
            if (strlen($sessionIndex) > 256 || count($sessionIndexes) >= 16) {
                throw new InvalidArgumentException(
                    "LogoutRequest SessionIndex values are too long or too many"
                );
            }
            $sessionIndexes[] = $sessionIndex;
        }

        if ($binding === SAML_BINDING_REDIRECT && $rawQueryString !== "") {
            saml_redirect_params_matching_xml($rawQueryString, $xml, "SAMLRequest");
        }

        $signatureVerified = false;
        $spCert = $app !== null ? trim((string) ($app["sp_signing_cert_pem"] ?? "")) : "";
        if ($spCert !== "") {
            $allowWeakSha1 = !empty($app["allow_weak_sha1"]);
            if ($binding === SAML_BINDING_REDIRECT) {
                $signatureVerified = saml_verify_redirect_query_signature(
                    $rawQueryString,
                    $spCert,
                    $allowWeakSha1
                );
            } else {
                $signatureVerified = saml_verify_dom_element_signature(
                    $root,
                    $spCert,
                    $allowWeakSha1
                );
            }
            // SAML Bindings 3.4.5.2 / 3.5.5.2: a signed message must name where it was sent.
            if ($destination === "") {
                throw new InvalidArgumentException("Signed LogoutRequests must carry a Destination");
            }
        }
    } catch (RuntimeException $e) {
        throw new InvalidArgumentException("Invalid LogoutRequest: " . $e->getMessage(), 0, $e);
    }

    return [
        "id" => $reqId,
        "issuer" => $issuer,
        "destination" => $destination,
        "name_id" => $nameId,
        "name_id_format" => $nameIdFormat,
        "session_indexes" => $sessionIndexes,
        "not_on_or_after" => $notOnOrAfter,
        "signature_verified" => $signatureVerified,
    ];
}

/**
 * Parses <samlp:RequestedAuthnContext>. Returns null when there is none, when it names no
 * context, or when legacy_saml_compat is on (it is then ignored); throws
 * InvalidArgumentException when it is malformed.
 */
function saml_parse_requested_authn_context(DOMXPath $xp, DOMElement $root): ?array
{
    if (saml_legacy_compat()) {
        return null;
    }
    $nodes = $xp->query("./samlp:RequestedAuthnContext", $root);
    if (!$nodes || $nodes->length === 0) {
        return null;
    }
    $racNode = $nodes->item(0);
    if ($nodes->length > 1 || !($racNode instanceof DOMElement)) {
        throw new InvalidArgumentException("AuthnRequest must not carry more than one RequestedAuthnContext");
    }
    $comparison = $racNode->hasAttribute("Comparison")
        ? strtolower(trim($racNode->getAttribute("Comparison")))
        : "exact";
    if (!in_array($comparison, ["exact", "minimum", "maximum", "better"], true)) {
        throw new InvalidArgumentException("Unsupported RequestedAuthnContext Comparison");
    }
    $refs = ["class_refs" => [], "decl_refs" => []];
    $total = 0;
    foreach (["class_refs" => "AuthnContextClassRef", "decl_refs" => "AuthnContextDeclRef"] as $key => $element) {
        foreach ($xp->query("./saml:" . $element, $racNode) as $refNode) {
            $ref = trim($refNode->textContent);
            if ($ref === "" || in_array($ref, $refs[$key], true)) {
                continue;
            }
            if (strlen($ref) > 1024) {
                throw new InvalidArgumentException("RequestedAuthnContext reference is too long");
            }
            if (++$total > 16) {
                throw new InvalidArgumentException("RequestedAuthnContext lists too many authentication contexts");
            }
            $refs[$key][] = $ref;
        }
    }
    if ($total === 0) {
        return null; // requests nothing
    }
    return [
        "comparison" => $comparison,
        "class_refs" => $refs["class_refs"],
        "decl_refs" => $refs["decl_refs"],
    ];
}

// ---------- Authentication Context (AuthnContextClassRef) ----------
//
// Sign-ins are ranked like the sign-on policies (flexible < touchid_only < mfa):
//   0 = password (PasswordProtectedTransport), 1 = passkey with user verification
//   (urn:idp:acr:phishing-resistant, as oidc_acr_from_amr()), 2 = password + passkey
//   (REFEDS MFA). A stronger sign-in also meets a weaker requested class.

/** Rank of the sign-in described by $amr, -1 when it contains no known method. */
function saml_amr_rank(array $amr): int
{
    $hasPwd = in_array("pwd", $amr, true);
    $hasHwk = in_array("hwk", $amr, true);
    if (in_array("mfa", $amr, true) || ($hasPwd && $hasHwk)) {
        return 2;
    }
    if ($hasHwk) {
        return 1;
    }
    return $hasPwd ? 0 : -1;
}

/** The AuthnContextClassRef this IdP asserts for a sign-in rank. */
function saml_authn_class_for_rank(int $rank): string
{
    if ($rank >= 2) {
        return SAML_AC_REFEDS_MFA;
    }
    if ($rank === 1) {
        return SAML_AC_PASSKEY;
    }
    return $rank === 0 ? SAML_AC_PASSWORD_PROTECTED_TRANSPORT : SAML_AC_UNSPECIFIED;
}

/**
 * Rank a requested AuthnContextClassRef needs: -1 for unspecified (any sign-in), null for a
 * class this IdP cannot produce (X509, Kerberos, Smartcard, ...).
 */
function saml_authn_class_rank(string $classRef): ?int
{
    return match ($classRef) {
        SAML_AC_UNSPECIFIED => -1,
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
        SAML_AC_PASSWORD_PROTECTED_TRANSPORT,
        "https://refeds.org/profile/sfa",
        "urn:idp:acr:1fa" => 0,
        SAML_AC_PASSKEY => 1,
        SAML_AC_REFEDS_MFA,
        "urn:idp:acr:mfa",
        "http://schemas.microsoft.com/claims/multipleauthn" => 2,
        default => null,
    };
}

/**
 * The AuthnContextClassRef to assert for a sign-in ($amr) under a parsed
 * RequestedAuthnContext, or null when that sign-in does not satisfy it.
 *   exact:   the strongest requested class the sign-in meets.
 *   minimum: the actual sign-in's class, if it meets at least one requested class.
 *   better:  the actual sign-in's class, if it is stronger than at least one requested class.
 *   maximum: never more than a requested class: the strongest one the sign-in meets, or the
 *            sign-in's own weaker class.
 * Classes this IdP cannot produce, and AuthnContextDeclRef values, are never met.
 */
function saml_select_authn_context_class(array $requested, array $amr): ?string
{
    $achieved = saml_amr_rank($amr);
    $comparison = (string) ($requested["comparison"] ?? "exact");
    $best = null;
    $anyKnown = false;
    foreach ((array) ($requested["class_refs"] ?? []) as $classRef) {
        $rank = is_string($classRef) ? saml_authn_class_rank($classRef) : null;
        if ($rank === null) {
            continue;
        }
        $anyKnown = true;
        $met = $comparison === "better" ? $rank < $achieved : $rank <= $achieved;
        if ($met && ($best === null || $rank > $best[1])) {
            $best = [$classRef, $rank];
        }
    }
    if ($comparison === "maximum") {
        if (!$anyKnown) {
            return null;
        }
        return $best !== null ? $best[0] : saml_authn_class_for_rank($achieved);
    }
    if ($best === null) {
        return null;
    }
    if ($comparison === "minimum" || $comparison === "better") {
        return saml_authn_class_for_rank($achieved);
    }
    return $best[0];
}

/**
 * Lowest sign-in rank that satisfies a parsed RequestedAuthnContext (-1: any sign-in), or
 * null when no sign-in this IdP offers can satisfy it.
 */
function saml_required_authn_rank(array $requested): ?int
{
    $comparison = (string) ($requested["comparison"] ?? "exact");
    $required = null;
    foreach ((array) ($requested["class_refs"] ?? []) as $classRef) {
        $rank = is_string($classRef) ? saml_authn_class_rank($classRef) : null;
        if ($rank === null) {
            continue;
        }
        if ($comparison === "maximum") {
            return -1; // only caps the asserted class (see saml_select_authn_context_class())
        }
        $need = $comparison === "better" ? $rank + 1 : $rank;
        if ($need > 2) {
            continue;
        }
        $required = $required === null ? $need : min($required, $need);
    }
    return $required;
}

/**
 * True when a sign-in with $amr satisfies the AuthnRequest's RequestedAuthnContext. Also
 * true when nothing was requested or legacy_saml_compat is on.
 */
function saml_authn_context_satisfied(array $authnReq, array $amr): bool
{
    if (saml_legacy_compat()) {
        return true;
    }
    $requested = $authnReq["requested_authn_context"] ?? null;
    if ($requested === null) {
        return true;
    }
    return is_array($requested) &&
        saml_select_authn_context_class($requested, $amr) !== null;
}

/**
 * Minimum sign-on policy (for effective_auth_policy()) whose sign-ins satisfy the
 * AuthnRequest's RequestedAuthnContext: "flexible", "touchid_only" or "mfa" ("mfa" also when
 * it cannot be satisfied at all). null when nothing was requested or legacy_saml_compat is on.
 */
function saml_requested_min_auth_policy(array $authnReq): ?string
{
    if (saml_legacy_compat()) {
        return null;
    }
    $requested = $authnReq["requested_authn_context"] ?? null;
    if ($requested === null) {
        return null;
    }
    $rank = is_array($requested) ? saml_required_authn_rank($requested) : null;
    if ($rank === null || $rank >= 2) {
        return "mfa";
    }
    return $rank === 1 ? "touchid_only" : "flexible";
}

/**
 * The AuthnContextClassRef for a response. Throws SamlStatusError (Responder/NoAuthnContext)
 * when the sign-in does not satisfy the request, so no assertion ever overstates it. With
 * legacy_saml_compat on: always PasswordProtectedTransport.
 */
function saml_authn_context_class_for_response(array $amr, ?array $authnReq): string
{
    if (saml_legacy_compat()) {
        return SAML_AC_PASSWORD_PROTECTED_TRANSPORT;
    }
    $requested = $authnReq["requested_authn_context"] ?? null;
    if ($requested === null) {
        return saml_authn_class_for_rank(saml_amr_rank($amr));
    }
    $classRef = is_array($requested)
        ? saml_select_authn_context_class($requested, $amr)
        : null;
    if ($classRef === null) {
        throw new SamlStatusError(
            "Responder",
            "NoAuthnContext",
            "The sign-in does not meet the authentication context requested by the service provider",
            null,
            $authnReq
        );
    }
    return $classRef;
}

// ---------- XML Encryption (<saml2:EncryptedAssertion>) ----------

/**
 * The block cipher behind an XML Encryption EncryptionMethod URI, matched exactly:
 * [OpenSSL cipher, key bytes, IV bytes, is GCM], or null when unsupported (never mapped to a
 * different cipher). GCM ciphertext is IV || data || 128-bit tag (XML Encryption 1.1, 5.2.4).
 */
function saml_encryption_cipher(string $uri): ?array
{
    return match ($uri) {
        SAML_ENC_AES256_GCM => ["aes-256-gcm", 32, 12, true],
        SAML_ENC_AES192_GCM => ["aes-192-gcm", 24, 12, true],
        SAML_ENC_AES128_GCM => ["aes-128-gcm", 16, 12, true],
        SAML_ENC_AES256_CBC => ["aes-256-cbc", 32, 16, false],
        SAML_ENC_AES192_CBC => ["aes-192-cbc", 24, 16, false],
        SAML_ENC_AES128_CBC => ["aes-128-cbc", 16, 16, false],
        default => null,
    };
}

/** The encryption_alg values saml_save_app() accepts, most preferred first. */
function saml_supported_encryption_algorithms(): array
{
    return [
        SAML_ENC_AES256_GCM,
        SAML_ENC_AES128_GCM,
        SAML_ENC_AES192_GCM,
        SAML_ENC_AES256_CBC,
        SAML_ENC_AES128_CBC,
        SAML_ENC_AES192_CBC,
    ];
}

/**
 * Why $certPem cannot be used to encrypt assertions, or null when it can: it must be an X.509
 * certificate (PEM, or the bare base64 body metadata carries) with an RSA public key of at
 * least 1024 bits, since the key transport is RSA-OAEP. Expiry is not checked: SAML metadata
 * certificates are key containers and are often self-signed and long expired.
 */
function saml_encryption_certificate_error(string $certPem): ?string
{
    $pem = saml_certificate_pem($certPem);
    if ($pem === null) {
        return "it is not a PEM or base64 X.509 certificate";
    }
    $cert = @openssl_x509_read($pem);
    if ($cert === false) {
        return "the X.509 certificate cannot be parsed";
    }
    $key = openssl_pkey_get_public($cert);
    $details = $key !== false ? openssl_pkey_get_details($key) : false;
    if (!is_array($details) || ($details["type"] ?? null) !== OPENSSL_KEYTYPE_RSA) {
        return "assertion encryption (RSA-OAEP key transport) needs an RSA key";
    }
    if ((int) ($details["bits"] ?? 0) < 1024) {
        return "the RSA key is shorter than 1024 bits";
    }
    return null;
}

/**
 * How the assertion for $app is encrypted: null when encrypt_assertion is off, otherwise
 * ["cert_pem" => ..., "alg" => ...]. Throws RuntimeException when encryption is on but cannot
 * be done (no or unusable certificate, unsupported algorithm): the assertion is then not sent
 * at all, never sent in plaintext instead.
 */
function saml_assertion_encryption(array $app): ?array
{
    if (empty($app["encrypt_assertion"])) {
        return null;
    }
    $certPem = trim((string) ($app["sp_encryption_cert_pem"] ?? ""));
    if ($certPem === "") {
        throw new RuntimeException(
            "Assertion encryption is enabled for this application, but no SP encryption certificate is configured; no assertion was sent"
        );
    }
    $certError = saml_encryption_certificate_error($certPem);
    if ($certError !== null) {
        throw new RuntimeException(
            "Assertion encryption is enabled for this application, but its SP encryption certificate is unusable (" .
                $certError . "); no assertion was sent"
        );
    }
    // Apps stored before encryption_alg was always written were encrypted with AES-256-CBC.
    $alg = trim((string) ($app["encryption_alg"] ?? ""));
    if ($alg === "") {
        $alg = SAML_ENC_AES256_CBC;
    }
    if (saml_encryption_cipher($alg) === null) {
        throw new RuntimeException(
            "Assertion encryption is enabled for this application, but its encryption algorithm is not supported; no assertion was sent"
        );
    }
    return ["cert_pem" => $certPem, "alg" => $alg];
}

function saml_encrypt_assertion_xml(
    DOMDocument $parentDoc,
    string $assertionXml,
    string $spEncryptionCertPem,
    string $encAlgUri = SAML_ENC_DEFAULT
): DOMElement {
    $cipher = saml_encryption_cipher($encAlgUri);
    if ($cipher === null) {
        throw new RuntimeException(
            "Unsupported assertion encryption algorithm: " . sanitize_label($encAlgUri, 200)
        );
    }
    [$cipherName, $keyLen, $ivLen, $isGcm] = $cipher;
    $certError = saml_encryption_certificate_error($spEncryptionCertPem);
    if ($certError !== null) {
        throw new RuntimeException("Invalid SP encryption X.509 certificate: " . $certError);
    }
    $pubKey = openssl_pkey_get_public((string) saml_certificate_pem($spEncryptionCertPem));
    if ($pubKey === false) {
        throw new RuntimeException("Invalid SP encryption X.509 certificate");
    }

    $symKey = random_bytes($keyLen);
    $iv = random_bytes($ivLen);

    if ($isGcm) {
        $tag = "";
        $ciphertext = openssl_encrypt(
            $assertionXml,
            $cipherName,
            $symKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            "",
            16
        );
        if ($ciphertext === false || strlen($tag) !== 16) {
            throw new RuntimeException("AES-GCM encryption failed");
        }
        $cipherPayloadB64 = base64_encode($iv . $ciphertext . $tag);
    } else {
        $ciphertext = openssl_encrypt(
            $assertionXml,
            $cipherName,
            $symKey,
            OPENSSL_RAW_DATA,
            $iv
        );
        if ($ciphertext === false) {
            throw new RuntimeException("AES-CBC encryption failed");
        }
        $cipherPayloadB64 = base64_encode($iv . $ciphertext);
    }

    if (
        !openssl_public_encrypt(
            $symKey,
            $encryptedSymKey,
            $pubKey,
            OPENSSL_PKCS1_OAEP_PADDING
        )
    ) {
        throw new RuntimeException("RSA-OAEP key encryption failed");
    }

    $encAssertion = $parentDoc->createElementNS(
        SAML_NS_ASSERTION,
        "saml2:EncryptedAssertion"
    );
    $encData = $parentDoc->createElementNS(SAML_NS_XENC, "xenc:EncryptedData");
    $encData->setAttribute("Id", "_ed_" . bin2hex(random_bytes(12)));
    $encData->setAttribute("Type", "http://www.w3.org/2001/04/xmlenc#Element");
    $encAssertion->appendChild($encData);

    $encMethod = $parentDoc->createElementNS(
        SAML_NS_XENC,
        "xenc:EncryptionMethod"
    );
    $encMethod->setAttribute("Algorithm", $encAlgUri);
    $encData->appendChild($encMethod);

    $keyInfo = $parentDoc->createElementNS(SAML_NS_DS, "ds:KeyInfo");
    $encData->appendChild($keyInfo);

    $encKey = $parentDoc->createElementNS(SAML_NS_XENC, "xenc:EncryptedKey");
    $encKey->setAttribute("Id", "_ek_" . bin2hex(random_bytes(12)));
    $keyInfo->appendChild($encKey);

    $keyEncMethod = $parentDoc->createElementNS(
        SAML_NS_XENC,
        "xenc:EncryptionMethod"
    );
    $keyEncMethod->setAttribute(
        "Algorithm",
        "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
    );
    $digestMethod = $parentDoc->createElementNS(SAML_NS_DS, "ds:DigestMethod");
    $digestMethod->setAttribute(
        "Algorithm",
        "http://www.w3.org/2000/09/xmldsig#sha1"
    );
    $keyEncMethod->appendChild($digestMethod);
    $encKey->appendChild($keyEncMethod);

    $ekKeyInfo = $parentDoc->createElementNS(SAML_NS_DS, "ds:KeyInfo");
    $x509Data = $parentDoc->createElementNS(SAML_NS_DS, "ds:X509Data");
    $x509Cert = $parentDoc->createElementNS(
        SAML_NS_DS,
        "ds:X509Certificate",
        clean_pem_certificate_body($spEncryptionCertPem)
    );
    $x509Data->appendChild($x509Cert);
    $ekKeyInfo->appendChild($x509Data);
    $encKey->appendChild($ekKeyInfo);

    $ekCipherData = $parentDoc->createElementNS(SAML_NS_XENC, "xenc:CipherData");
    $ekCipherVal = $parentDoc->createElementNS(
        SAML_NS_XENC,
        "xenc:CipherValue",
        base64_encode($encryptedSymKey)
    );
    $ekCipherData->appendChild($ekCipherVal);
    $encKey->appendChild($ekCipherData);

    $cipherData = $parentDoc->createElementNS(SAML_NS_XENC, "xenc:CipherData");
    $cipherVal = $parentDoc->createElementNS(
        SAML_NS_XENC,
        "xenc:CipherValue",
        $cipherPayloadB64
    );
    $cipherData->appendChild($cipherVal);
    $encData->appendChild($cipherData);

    return $encAssertion;
}

// ---------- Outgoing SAML 2.0 Response & Assertion Builder ----------

/**
 * Resolves where a response for $app may be posted: the AuthnRequest's
 * AssertionConsumerServiceURL (exact match) or AssertionConsumerServiceIndex, among the app's
 * HTTP-POST endpoints (acs_url and acs_endpoints form one allowlist), else acs_url. An
 * unregistered URL or index throws RuntimeException (with legacy_saml_compat an unknown index
 * falls back to acs_url). The result is checked again with validate_endpoint_url(), except
 * URLs under $trustedBaseUrl (the IdP's own base URL, e.g. the built-in test inspector),
 * which share its scheme.
 */
function saml_resolve_acs_url(
    array $app,
    ?array $authnReq = null,
    ?string $trustedBaseUrl = null
): string {
    $acsUrl = trim((string) ($app["acs_url"] ?? ""));
    $endpoints = saml_effective_acs_endpoints($acsUrl, $app["acs_endpoints"] ?? []);
    $resolved = $acsUrl;

    $requestedUrl = trim((string) ($authnReq["acs_url"] ?? ""));
    if ($requestedUrl !== "") {
        $match = null;
        foreach ($endpoints as $ep) {
            if ($ep["location"] === $requestedUrl) {
                $match = $ep["location"];
                break;
            }
        }
        if ($match === null) {
            throw new RuntimeException(
                "Requested AssertionConsumerServiceURL is not registered for this SAML app"
            );
        }
        $resolved = $match;
    } elseif (isset($authnReq["acs_index"]) && $authnReq["acs_index"] !== null) {
        $match = null;
        foreach ($endpoints as $ep) {
            if ($ep["index"] === (int) $authnReq["acs_index"]) {
                $match = $ep["location"];
                break;
            }
        }
        if ($match !== null) {
            $resolved = $match;
        } elseif (!saml_legacy_compat()) {
            // SAML Core 3.4.1 allows an error or the default ACS; an index the SP did not
            // register is refused rather than silently redirected.
            throw new RuntimeException(
                "Requested AssertionConsumerServiceIndex is not registered for this SAML app"
            );
        }
    }

    if ($trustedBaseUrl !== null) {
        $base = rtrim(trim($trustedBaseUrl), "/");
        if ($base !== "" && str_starts_with($resolved, $base . "/")) {
            return $resolved;
        }
    }
    return validate_endpoint_url($resolved, false, "ACS URL");
}

/**
 * The NameID format to issue for $app when the AuthnRequest's NameIDPolicy asks for
 * $requestedFormat (SAML Core 3.4.1.1). None, "unspecified" or the app's configured format
 * gives the configured format. Another format is honored only when the app allows it (it is in
 * supported_name_id_formats or, when that list is empty, it is the configured format or
 * unspecified) and this IdP can produce it (SAML_IDP_NAMEID_FORMATS); anything else throws
 * SamlStatusError Requester/InvalidNameIDPolicy carrying $authnReq. With legacy_saml_compat:
 * the old rule (any requested format when the list is empty, a listed one otherwise, and
 * silently the configured format for the rest).
 */
function saml_effective_name_id_format(
    array $app,
    ?string $requestedFormat,
    ?array $authnReq = null
): string {
    $configured = trim((string) ($app["name_id_format"] ?? ""));
    if ($configured === "") {
        $configured = SAML_NAMEID_EMAIL;
    }
    $requested = trim((string) $requestedFormat);
    if ($requested === "" || $requested === SAML_NAMEID_UNSPECIFIED || $requested === $configured) {
        return $configured;
    }
    $supported = saml_name_id_format_list($app["supported_name_id_formats"] ?? []);
    if (saml_legacy_compat()) {
        return empty($supported) || in_array($requested, $supported, true) ? $requested : $configured;
    }
    $allowed = $supported !== [] ? $supported : [$configured, SAML_NAMEID_UNSPECIFIED];
    if (!in_array($requested, $allowed, true) || !in_array($requested, SAML_IDP_NAMEID_FORMATS, true)) {
        throw new SamlStatusError(
            "Requester",
            "InvalidNameIDPolicy",
            "The NameID format requested by the service provider is not enabled for this application",
            null,
            $authnReq
        );
    }
    return $requested;
}

/** True for an addr-spec shaped value (local-part@domain), as SAML Core 8.3.2 requires for emailAddress. */
function saml_is_email_address(string $value): bool
{
    return preg_match('/^[^@\s]+@[^@\s]+$/uD', $value) === 1;
}

/**
 * The pairwise persistent identifier of $user at $app (SAML Core 8.3.7). By default, for every
 * app: "u_" plus 32 hex characters of HMAC-SHA256 under the provider's key
 * (saml_pairwise_secret()) over provider id | SP entity ID | user id. Parties that learn a
 * user's internal id (SCIM clients, SPs mapping user.id) cannot compute it for other SPs, and
 * it does not depend on the Host header. Only while the legacy_saml_persistent_ids flag is on,
 * an app whose persistent_id_scheme is "legacy" (saved before keyed identifiers existed, and
 * not switched since) gets the old unkeyed SHA-256 over the IdP entity ID, SP entity ID and
 * user id, so accounts at its SP stay linked (S02-10).
 */
function saml_persistent_name_id(
    array $user,
    array $app,
    string $idpEntityId,
    ?string $storePath = null
): string {
    $spEntityId = (string) ($app["sp_entity_id"] ?? "");
    $userId = (string) ($user["id"] ?? "");
    if ($userId === "") {
        throw new RuntimeException("A persistent NameID needs the user's id");
    }
    if (($app["persistent_id_scheme"] ?? "legacy") === "legacy" && saml_legacy_persistent_ids()) {
        return "u_" . substr(hash("sha256", $idpEntityId . "|" . $spEntityId . "|" . $userId), 0, 32);
    }
    $providerId = (string) ($app["provider_id"] ?? "");
    $key = saml_pairwise_secret(saml_store_path($storePath), $providerId);
    return "u_" .
        substr(hash_hmac("sha256", $providerId . "|" . $spEntityId . "|" . $userId, $key), 0, 32);
}

/**
 * The NameID of $user at $app: ["format" => ..., "value" => ...]. The format comes from
 * saml_effective_name_id_format() (which may throw SamlStatusError). The value is chosen by
 * exact format URI: transient gives a one-time random value, persistent (or name_id_source
 * "persistent") the pairwise identifier (saml_persistent_name_id(), never the email or
 * username), otherwise the username or email per name_id_source. A value that is not an
 * email address is never labelled emailAddress: it is sent with the unspecified format.
 * legacy_saml_compat keeps the old labelling and substring format matching.
 */
function saml_compute_name_id(
    array $user,
    array $app,
    string $idpEntityId,
    ?string $requestedFormat = null,
    ?string $storePath = null,
    ?array $authnReq = null
): array {
    $format = saml_effective_name_id_format($app, $requestedFormat, $authnReq);
    $legacy = saml_legacy_compat();
    $source = (string) ($app["name_id_source"] ?? "email");
    $isTransient = $legacy ? str_contains($format, "transient") : $format === SAML_NAMEID_TRANSIENT;
    $isPersistent = $legacy ? str_contains($format, "persistent") : $format === SAML_NAMEID_PERSISTENT;

    if ($isTransient) {
        $value = "_tr_" . bin2hex(random_bytes(16));
    } elseif ($isPersistent || $source === "persistent") {
        $value = saml_persistent_name_id($user, $app, $idpEntityId, $storePath);
    } elseif ($source === "username") {
        $value = (string) ($user["username"] ?? "");
    } else {
        $value = (string) ($user["email"] ?? "");
        if ($value === "") {
            $value = (string) ($user["username"] ?? "");
        }
    }
    if ($value === "") {
        throw new RuntimeException("The user has no value for this application's NameID");
    }

    // A username (or any other non-address value) is never labelled emailAddress.
    if (!$legacy && $format === SAML_NAMEID_EMAIL && !saml_is_email_address($value)) {
        $format = SAML_NAMEID_UNSPECIFIED;
    }

    return ["format" => $format, "value" => $value];
}

/**
 * Builds and signs a complete SAML 2.0 <saml2p:Response> + <saml2:Assertion>
 * compliant with OpenSAML / Okta CIAM / Palo Alto Networks SP requirements.
 *
 * $authTime is when the user actually authenticated (the SSO session's auth time) and
 * $sessionExpiresAt when that SSO session ends; AuthnInstant and SessionNotOnOrAfter follow
 * them. Throws SamlStatusError (with ->authnRequest) when $amr does not satisfy the request's
 * RequestedAuthnContext (Responder/NoAuthnContext) or the NameID policy cannot be met
 * (InvalidNameIDPolicy): answer it with saml_build_status_response(). Throws RuntimeException
 * when the response cannot be built as configured, e.g. assertion encryption is enabled but
 * not possible (the assertion is never sent in plaintext instead) or the ACS is not
 * registered: show an error page. $storePath (default: the global store) holds the per-provider
 * key of keyed persistent NameIDs.
 *
 * $sessionIndex is the AuthnStatement SessionIndex to assert, returned as session_index
 * (S02-05, S02-06): routes_idp.php derives one per SSO session and SP, so /saml/slo can match
 * a LogoutRequest that echoes it. It is used when it is an NCName of at most 64 ASCII letters,
 * digits, "_", "." and "-" (not starting with a digit, "." or "-"); null, "" or any other value
 * gets a random one, as before.
 */
function saml_build_signed_response(
    array $provider,
    string $baseUrl,
    array $samlCert,
    array $app,
    array $user,
    array $amr = ["pwd"],
    ?array $authnReq = null,
    ?int $authTime = null,
    ?int $sessionExpiresAt = null,
    ?string $storePath = null,
    ?string $sessionIndex = null
): array {
    $issuer = $baseUrl . "/" . $provider["idp_id"];
    $authnContextClassRef = saml_authn_context_class_for_response($amr, $authnReq);
    $recipientUrl = saml_resolve_acs_url($app, $authnReq, $baseUrl);
    $inResponseTo = (string) ($authnReq["id"] ?? "");
    // Fail closed before anything is built: encryption on means encrypted or nothing.
    $encryption = saml_assertion_encryption($app);

    $now = time();
    $issueInstant = gmdate("Y-m-d\TH:i:s\Z", $now);
    $notBefore = gmdate("Y-m-d\TH:i:s\Z", $now - 60); // 60s clock-skew grace
    $notOnOrAfter = gmdate("Y-m-d\TH:i:s\Z", $now + 300);
    // When the user really authenticated (never in the future), not when this assertion is issued.
    $authnInstant = gmdate(
        "Y-m-d\TH:i:s\Z",
        $authTime !== null && $authTime > 0 ? min($authTime, $now) : $now
    );
    // Never outlives the IdP SSO session the assertion was issued from.
    $sessionEnd = $now + 28800;
    if ($sessionExpiresAt !== null && $sessionExpiresAt > 0) {
        $sessionEnd = min($sessionEnd, $sessionExpiresAt);
    }
    $sessionNotOnOrAfter = gmdate("Y-m-d\TH:i:s\Z", $sessionEnd);

    $responseId = "_resp_" . bin2hex(random_bytes(16));
    $assertionId = "_asrt_" . bin2hex(random_bytes(16));
    if ($sessionIndex === null || preg_match('/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/D', $sessionIndex) !== 1) {
        if ($sessionIndex !== null && $sessionIndex !== "") {
            error_log("saml: the SessionIndex passed for an assertion is not a short NCName; a random one is used");
        }
        $sessionIndex = "_sess_" . bin2hex(random_bytes(12));
    }

    $nameIdInfo = saml_compute_name_id(
        $user,
        $app,
        $issuer,
        $authnReq["requested_name_id_format"] ?? null,
        $storePath,
        $authnReq
    );

    // Build standalone Assertion DOM first so Exclusive C14N namespaces are 100% self-contained
    $assertDoc = new DOMDocument("1.0", "UTF-8");
    $assertDoc->preserveWhiteSpace = true;
    $assertDoc->formatOutput = false;

    $assertion = $assertDoc->createElementNS(
        SAML_NS_ASSERTION,
        "saml2:Assertion"
    );
    $assertion->setAttribute("ID", $assertionId);
    $assertion->setIdAttribute("ID", true);
    $assertion->setAttribute("IssueInstant", $issueInstant);
    $assertion->setAttribute("Version", "2.0");
    $assertion->setAttributeNS(
        "http://www.w3.org/2000/xmlns/",
        "xmlns:xs",
        "http://www.w3.org/2001/XMLSchema"
    );
    $assertion->setAttributeNS(
        "http://www.w3.org/2000/xmlns/",
        "xmlns:xsi",
        "http://www.w3.org/2001/XMLSchema-instance"
    );
    $assertDoc->appendChild($assertion);

    $aIssuer = $assertDoc->createElementNS(SAML_NS_ASSERTION, "saml2:Issuer");
    $aIssuer->textContent = clean_xml_text($issuer);
    $assertion->appendChild($aIssuer);

    // Subject
    $subject = $assertDoc->createElementNS(SAML_NS_ASSERTION, "saml2:Subject");
    $nameIdEl = $assertDoc->createElementNS(SAML_NS_ASSERTION, "saml2:NameID");
    $nameIdEl->textContent = clean_xml_text($nameIdInfo["value"]);
    $nameIdEl->setAttribute("Format", $nameIdInfo["format"]);
    $subject->appendChild($nameIdEl);

    $subjConf = $assertDoc->createElementNS(
        SAML_NS_ASSERTION,
        "saml2:SubjectConfirmation"
    );
    $subjConf->setAttribute(
        "Method",
        "urn:oasis:names:tc:SAML:2.0:cm:bearer"
    );
    $subjConfData = $assertDoc->createElementNS(
        SAML_NS_ASSERTION,
        "saml2:SubjectConfirmationData"
    );
    if ($inResponseTo !== "") {
        $subjConfData->setAttribute("InResponseTo", $inResponseTo);
    }
    $subjConfData->setAttribute("NotOnOrAfter", $notOnOrAfter);
    $subjConfData->setAttribute("Recipient", $recipientUrl);
    $subjConf->appendChild($subjConfData);
    $subject->appendChild($subjConf);
    $assertion->appendChild($subject);

    // Conditions
    $conditions = $assertDoc->createElementNS(
        SAML_NS_ASSERTION,
        "saml2:Conditions"
    );
    $conditions->setAttribute("NotBefore", $notBefore);
    $conditions->setAttribute("NotOnOrAfter", $notOnOrAfter);
    $audRestr = $assertDoc->createElementNS(
        SAML_NS_ASSERTION,
        "saml2:AudienceRestriction"
    );
    $audEl = $assertDoc->createElementNS(SAML_NS_ASSERTION, "saml2:Audience");
    $audEl->textContent = clean_xml_text($app["sp_entity_id"]);
    $audRestr->appendChild($audEl);
    $conditions->appendChild($audRestr);
    $assertion->appendChild($conditions);

    // AuthnStatement
    $authnStmt = $assertDoc->createElementNS(
        SAML_NS_ASSERTION,
        "saml2:AuthnStatement"
    );
    $authnStmt->setAttribute("AuthnInstant", $authnInstant);
    $authnStmt->setAttribute("SessionIndex", $sessionIndex);
    $authnStmt->setAttribute("SessionNotOnOrAfter", $sessionNotOnOrAfter);
    $authnCtx = $assertDoc->createElementNS(
        SAML_NS_ASSERTION,
        "saml2:AuthnContext"
    );
    // How the user actually signed in (see saml_authn_context_class_for_response()).
    $authnCtxRef = $assertDoc->createElementNS(
        SAML_NS_ASSERTION,
        "saml2:AuthnContextClassRef"
    );
    $authnCtxRef->textContent = clean_xml_text($authnContextClassRef);
    $authnCtx->appendChild($authnCtxRef);
    $authnStmt->appendChild($authnCtx);
    $assertion->appendChild($authnStmt);

    // AttributeStatement
    $attrStmt = $assertDoc->createElementNS(
        SAML_NS_ASSERTION,
        "saml2:AttributeStatement"
    );
    $resolvedAttributesForSummary = [];

    $mappings = $app["attribute_mapping"] ?? [];
    foreach ($mappings as $m) {
        $attrName = trim((string) ($m["name"] ?? ""));
        if ($attrName === "") {
            continue;
        }
        $nameFmt = trim(
            (string) ($m["name_format"] ??
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
        );
        $friendly = trim((string) ($m["friendly_name"] ?? ""));
        $isReq = !empty($m["required"]);
        $source = (string) ($m["source"] ?? "");

        $vals = directory_resolve_user_attribute($user, $source);
        if (empty($vals) && $isReq) {
            // Ensure required attributes are never omitted if user field happens to be blank
            $vals = [""];
        }
        if (empty($vals)) {
            continue;
        }

        $attrEl = $assertDoc->createElementNS(
            SAML_NS_ASSERTION,
            "saml2:Attribute"
        );
        $attrEl->setAttribute("Name", $attrName);
        $attrEl->setAttribute("NameFormat", $nameFmt);
        if ($friendly !== "") {
            $attrEl->setAttribute("FriendlyName", $friendly);
        }

        foreach ($vals as $v) {
            $valEl = $assertDoc->createElementNS(
                SAML_NS_ASSERTION,
                "saml2:AttributeValue"
            );
            $valEl->textContent = clean_xml_text((string) $v);
            $valEl->setAttributeNS(
                "http://www.w3.org/2001/XMLSchema-instance",
                "xsi:type",
                "xs:string"
            );
            $attrEl->appendChild($valEl);
        }
        $attrStmt->appendChild($attrEl);
        $resolvedAttributesForSummary[$attrName] = $vals;
    }

    // Also attach authentication method metadata attribute for visibility if helpful
    $amrEl = $assertDoc->createElementNS(SAML_NS_ASSERTION, "saml2:Attribute");
    $amrEl->setAttribute("Name", "amr");
    $amrEl->setAttribute(
        "NameFormat",
        "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
    );
    foreach ($amr as $methodVal) {
        $vEl = $assertDoc->createElementNS(
            SAML_NS_ASSERTION,
            "saml2:AttributeValue"
        );
        $vEl->textContent = clean_xml_text((string) $methodVal);
        $vEl->setAttributeNS(
            "http://www.w3.org/2001/XMLSchema-instance",
            "xsi:type",
            "xs:string"
        );
        $amrEl->appendChild($vEl);
    }
    $attrStmt->appendChild($amrEl);

    if ($attrStmt->hasChildNodes()) {
        $assertion->appendChild($attrStmt);
    }

    // An HTTP-POST response must carry a signature: an app stored with both flags off
    // (possible before signing was enforced at save time) gets both.
    $signAssertion = !empty($app["sign_assertion"]);
    $signResponse = !empty($app["sign_response"]);
    if (!$signAssertion && !$signResponse) {
        $signAssertion = true;
        $signResponse = true;
    }

    // Sign Assertion if configured (WantAssertionsSigned="true")
    if ($signAssertion) {
        saml_sign_dom_element(
            $assertDoc,
            $assertion,
            (string) $samlCert["private_key_pem"],
            (string) $samlCert["cert_pem"],
            $aIssuer->nextSibling
        );
    }

    // Build outer <saml2p:Response>
    $respDoc = new DOMDocument("1.0", "UTF-8");
    $respDoc->preserveWhiteSpace = true;
    $respDoc->formatOutput = false;

    $response = $respDoc->createElementNS(SAML_NS_PROTOCOL, "saml2p:Response");
    $response->setAttribute("Destination", $recipientUrl);
    $response->setAttribute("ID", $responseId);
    $response->setIdAttribute("ID", true);
    if ($inResponseTo !== "") {
        $response->setAttribute("InResponseTo", $inResponseTo);
    }
    $response->setAttribute("IssueInstant", $issueInstant);
    $response->setAttribute("Version", "2.0");
    $respDoc->appendChild($response);

    $rIssuer = $respDoc->createElementNS(SAML_NS_ASSERTION, "saml2:Issuer");
    $rIssuer->textContent = clean_xml_text($issuer);
    $response->appendChild($rIssuer);

    $status = $respDoc->createElementNS(SAML_NS_PROTOCOL, "saml2p:Status");
    $statusCode = $respDoc->createElementNS(
        SAML_NS_PROTOCOL,
        "saml2p:StatusCode"
    );
    $statusCode->setAttribute(
        "Value",
        "urn:oasis:names:tc:SAML:2.0:status:Success"
    );
    $status->appendChild($statusCode);
    $response->appendChild($status);

    // Attach either EncryptedAssertion or plain signed Assertion (saml_assertion_encryption()
    // above already refused a response that should be encrypted but cannot be).
    if ($encryption !== null) {
        $assertionXml = (string) $assertDoc->saveXML($assertion);
        $encNode = saml_encrypt_assertion_xml(
            $respDoc,
            $assertionXml,
            $encryption["cert_pem"],
            $encryption["alg"]
        );
        $response->appendChild($encNode);
    } else {
        $importedAssertion = $respDoc->importNode($assertion, true);
        $response->appendChild($importedAssertion);
    }

    // Sign outer Response if configured
    if ($signResponse) {
        saml_sign_dom_element(
            $respDoc,
            $response,
            (string) $samlCert["private_key_pem"],
            (string) $samlCert["cert_pem"],
            $rIssuer->nextSibling
        );
    }

    $rawResponseXml = (string) $respDoc->saveXML();
    return [
        "xml" => $rawResponseXml,
        "saml_response_b64" => base64_encode($rawResponseXml),
        "acs_url" => $recipientUrl,
        "response_id" => $responseId,
        "assertion_id" => $assertionId,
        "name_id" => $nameIdInfo,
        "session_index" => $sessionIndex,
        "authn_context_class_ref" => $authnContextClassRef,
        "attributes" => $resolvedAttributesForSummary,
    ];
}

/**
 * Builds a signed <saml2p:Response> that carries only a non-success Status (no assertion),
 * for errors that SAML requires to be returned to the SP, e.g. Responder/NoAuthnContext,
 * Responder/NoPassive or Requester/InvalidNameIDPolicy (see SamlStatusError). Codes are full
 * status URNs or their short names. It goes to the same ACS an assertion would (so the URL is
 * validated the same way) and is ready for saml_render_auto_post_form().
 */
function saml_build_status_response(
    array $provider,
    string $baseUrl,
    array $samlCert,
    array $app,
    ?array $authnReq,
    string $statusCode,
    string $subStatusCode = "",
    string $message = ""
): array {
    $topUri = saml_status_code_uri($statusCode);
    if (
        $topUri === null ||
        !in_array(
            $topUri,
            [
                SAML_STATUS_PREFIX . "Requester",
                SAML_STATUS_PREFIX . "Responder",
                SAML_STATUS_PREFIX . "VersionMismatch",
            ],
            true
        )
    ) {
        throw new InvalidArgumentException("Invalid top-level SAML status code for an error response");
    }
    $subUri = null;
    if ($subStatusCode !== "") {
        $subUri = saml_status_code_uri($subStatusCode);
        if ($subUri === null) {
            throw new InvalidArgumentException("Invalid second-level SAML status code");
        }
    }

    $issuer = $baseUrl . "/" . $provider["idp_id"];
    $acsUrl = saml_resolve_acs_url($app, $authnReq, $baseUrl);
    $inResponseTo = (string) ($authnReq["id"] ?? "");
    $responseId = "_resp_" . bin2hex(random_bytes(16));

    $doc = new DOMDocument("1.0", "UTF-8");
    $doc->preserveWhiteSpace = true;
    $doc->formatOutput = false;

    $response = $doc->createElementNS(SAML_NS_PROTOCOL, "saml2p:Response");
    $response->setAttribute("Destination", $acsUrl);
    $response->setAttribute("ID", $responseId);
    $response->setIdAttribute("ID", true);
    if ($inResponseTo !== "") {
        $response->setAttribute("InResponseTo", $inResponseTo);
    }
    $response->setAttribute("IssueInstant", gmdate("Y-m-d\TH:i:s\Z"));
    $response->setAttribute("Version", "2.0");
    $doc->appendChild($response);

    $rIssuer = $doc->createElementNS(SAML_NS_ASSERTION, "saml2:Issuer");
    $rIssuer->textContent = clean_xml_text($issuer);
    $response->appendChild($rIssuer);

    $status = $doc->createElementNS(SAML_NS_PROTOCOL, "saml2p:Status");
    $topCode = $doc->createElementNS(SAML_NS_PROTOCOL, "saml2p:StatusCode");
    $topCode->setAttribute("Value", $topUri);
    if ($subUri !== null) {
        $subCode = $doc->createElementNS(SAML_NS_PROTOCOL, "saml2p:StatusCode");
        $subCode->setAttribute("Value", $subUri);
        $topCode->appendChild($subCode);
    }
    $status->appendChild($topCode);
    $message = utf8_truncate(trim($message), 256);
    if ($message !== "") {
        $statusMessage = $doc->createElementNS(SAML_NS_PROTOCOL, "saml2p:StatusMessage");
        $statusMessage->textContent = clean_xml_text($message);
        $status->appendChild($statusMessage);
    }
    $response->appendChild($status);

    saml_sign_dom_element(
        $doc,
        $response,
        (string) $samlCert["private_key_pem"],
        (string) $samlCert["cert_pem"],
        $rIssuer->nextSibling
    );

    $rawXml = (string) $doc->saveXML();
    return [
        "xml" => $rawXml,
        "saml_response_b64" => base64_encode($rawXml),
        "acs_url" => $acsUrl,
        "response_id" => $responseId,
    ];
}

function saml_render_auto_post_form(
    string $acsUrl,
    string $samlResponseB64,
    string $relayState = ""
): never {
    $escAcs = html_escape($acsUrl);
    $escResp = html_escape($samlResponseB64);
    $relayInput =
        $relayState !== ""
            ? '<input type="hidden" name="RelayState" value="' .
                html_escape($relayState) .
                '" />'
            : "";

    $html = <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Completing SAML Sign-In…</title>
  <style>
    :root { --bg:#f6f8fb; --card:#fff; --txt:#0f172a; --sub:#64748b; --bdr:#e2e8f0; --ring:#e2e8f0; --acc:#4f46e5; }
    @media (prefers-color-scheme: dark) {
      :root { --bg:#090d16; --card:#101726; --txt:#f8fafc; --sub:#94a3b8; --bdr:rgba(148,163,184,0.16); --ring:#1e293b; --acc:#6366f1; }
    }
    body { font-family: -apple-system, BlinkMacSystemFont, "Inter", sans-serif; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; background:var(--bg); color:var(--txt); }
    .card { background:var(--card); border:1px solid var(--bdr); padding:2.25rem 2.75rem; border-radius:20px; box-shadow:0 20px 50px -12px rgba(0,0,0,0.15); text-align:center; }
    .spinner { width:34px; height:34px; border:3px solid var(--ring); border-top-color:var(--acc); border-radius:50%; animation:spin 0.75s linear infinite; margin:0 auto 1.1rem; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body onload="document.forms[0].submit()">
  <div class="card">
    <div class="spinner"></div>
    <div style="font-weight:700;font-size:15px;margin-bottom:4px;">Completing SAML 2.0 Sign-In</div>
    <div style="font-size:13px;color:var(--sub);">Redirecting securely to service provider…</div>
    <form method="post" action="{$escAcs}">
      <input type="hidden" name="SAMLResponse" value="{$escResp}" />
      {$relayInput}
      <noscript><button type="submit" style="margin-top:1.25rem;padding:0.6rem 1.2rem;border-radius:9px;border:none;background:#4f46e5;color:#fff;font-weight:600;cursor:pointer;">Continue</button></noscript>
    </form>
  </div>
</body>
</html>
HTML;

    http_response_code(200);
    if (!headers_sent()) {
        send_security_headers(true);
        header("Content-Type: text/html; charset=utf-8");
        header("Cache-Control: no-store, no-cache, must-revalidate");
        header("Pragma: no-cache");
    }
    echo $html;
    exit();
}

/**
 * A signed <saml2p:LogoutResponse> with the top-level status Success (the IdP session ended),
 * enveloped-signed for HTTP-POST (an HTTP-Redirect sender removes the signature and signs the
 * query instead). $secondLevelStatus, when not "", is nested in the Success StatusCode (SAML
 * Core 3.2.2.2): only PartialLogout (full URN or short name) qualifies a successful logout,
 * for when logout did not reach every other session participant (SAML Core 3.7.3.2). Any other
 * value throws InvalidArgumentException.
 */
function saml_build_logout_response(
    array $provider,
    string $baseUrl,
    array $samlCert,
    string $destination,
    string $inResponseTo = "",
    string $secondLevelStatus = ""
): string {
    $subStatusUri = null;
    if (trim($secondLevelStatus) !== "") {
        $subStatusUri = saml_status_code_uri($secondLevelStatus);
        if ($subStatusUri !== SAML_STATUS_PREFIX . "PartialLogout") {
            throw new InvalidArgumentException(
                "A successful LogoutResponse can only carry the second-level status PartialLogout"
            );
        }
    }
    $issuer = $baseUrl . "/" . $provider["idp_id"];
    $doc = new DOMDocument("1.0", "UTF-8");
    $doc->formatOutput = false;

    $lr = $doc->createElementNS(SAML_NS_PROTOCOL, "saml2p:LogoutResponse");
    $lr->setAttribute("ID", "_slo_" . bin2hex(random_bytes(12)));
    $lr->setIdAttribute("ID", true);
    $lr->setAttribute("Version", "2.0");
    $lr->setAttribute("IssueInstant", gmdate("Y-m-d\TH:i:s\Z"));
    if ($destination !== "") {
        $lr->setAttribute("Destination", $destination);
    }
    if ($inResponseTo !== "") {
        $lr->setAttribute("InResponseTo", $inResponseTo);
    }
    $doc->appendChild($lr);

    $iss = $doc->createElementNS(SAML_NS_ASSERTION, "saml2:Issuer");
    $iss->textContent = clean_xml_text($issuer);
    $lr->appendChild($iss);

    $status = $doc->createElementNS(SAML_NS_PROTOCOL, "saml2p:Status");
    $sc = $doc->createElementNS(SAML_NS_PROTOCOL, "saml2p:StatusCode");
    $sc->setAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success");
    if ($subStatusUri !== null) {
        $subCode = $doc->createElementNS(SAML_NS_PROTOCOL, "saml2p:StatusCode");
        $subCode->setAttribute("Value", $subStatusUri);
        $sc->appendChild($subCode);
    }
    $status->appendChild($sc);
    $lr->appendChild($status);

    saml_sign_dom_element(
        $doc,
        $lr,
        (string) $samlCert["private_key_pem"],
        (string) $samlCert["cert_pem"],
        $iss->nextSibling
    );

    return (string) $doc->saveXML();
}
