<?php
declare(strict_types=1);

/**
 * A directory write was refused because its $precondition rejected the stored resource, for
 * example a SCIM If-Match version that no longer matches. The write transaction was rolled
 * back, so nothing changed. Code 412: answer it with 412 Precondition Failed.
 */
final class DirectoryPreconditionFailed extends RuntimeException
{
}

function normalize_string_list($val): array
{
    if (is_string($val)) {
        $parts = preg_split('/[\r\n,]+/', $val) ?: [];
    } elseif (is_array($val)) {
        $parts = $val;
    } else {
        return [];
    }
    $out = [];
    foreach ($parts as $p) {
        if (is_scalar($p)) {
            $s = trim((string) $p);
            if ($s !== "" && !in_array($s, $out, true)) {
                $out[] = $s;
            }
        }
    }
    return $out;
}

/**
 * $credentials are the passkeys embedded in the record (at most
 * directory_user_credentials_limit(), the newest). $credentialCount, when given, is the user's
 * total number of passkeys for touchid_count; otherwise count($credentials) is used.
 */
function hydrate_idp_user_row(array $row, array $credentials = [], ?int $credentialCount = null): array
{
    $groups = json_decode((string) ($row["groups_json"] ?? "[]"), true);
    if (!is_array($groups)) {
        $groups = [];
    }
    $attrs = json_decode((string) ($row["attributes_json"] ?? "{}"), true);
    if (!is_array($attrs)) {
        $attrs = [];
    }
    $displayName = trim((string) ($row["display_name"] ?? ""));
    if ($displayName === "") {
        $full = trim(
            trim((string) ($row["given_name"] ?? "")) .
                " " .
                trim((string) ($row["family_name"] ?? ""))
        );
        $displayName = $full !== "" ? $full : (string) $row["username"];
    }
    return [
        "id" => (string) $row["id"],
        "owner" => (string) $row["owner"],
        "username" => (string) $row["username"],
        "email" => (string) $row["email"],
        // Immutable OIDC subject, never empty. Rows from before the column existed fall back to
        // the value the migration stores for them (email, else username, else id).
        "subject" => directory_user_subject($row),
        // Users created before the flag existed count as verified, as they always were.
        "email_verified" => isset($row["email_verified"]) ? (int) $row["email_verified"] === 1 : true,
        "has_password" =>
            isset($row["password_hash"]) &&
            is_string($row["password_hash"]) &&
            $row["password_hash"] !== "",
        "given_name" => (string) ($row["given_name"] ?? ""),
        "family_name" => (string) ($row["family_name"] ?? ""),
        "display_name" => $displayName,
        "mobile_phone" => (string) ($row["mobile_phone"] ?? ""),
        "groups" => array_values($groups),
        "attributes" => $attrs,
        "external_id" => (string) ($row["external_id"] ?? ""),
        "status" => (string) ($row["status"] ?? "active"),
        "created_at" => $row["created_at"] ?? null,
        "updated_at" => ($row["updated_at"] ?? null) ?: ($row["created_at"] ?? null),
        "last_login_at" => $row["last_login_at"] ?? null,
        "credentials" => $credentials,
        "touchid_count" => $credentialCount ?? count($credentials),
    ];
}

/**
 * The most passkeys embedded in one user record ("credentials"; the newest ones). touchid_count
 * still counts all of them. Accounts that registered more passkeys before the per-user cap
 * existed (G1c-03) therefore no longer inflate user listings, SCIM responses and syncs. Equal
 * to WEBAUTHN_OPTIONS_MAX_CREDENTIALS (webauthn.php), the most credentials a WebAuthn options
 * request lists.
 */
function directory_user_credentials_limit(): int
{
    return defined("WEBAUTHN_OPTIONS_MAX_CREDENTIALS")
        ? max(1, (int) constant("WEBAUTHN_OPTIONS_MAX_CREDENTIALS"))
        : 50;
}

/**
 * The newest passkeys of one user, at most directory_user_credentials_limit() (no public keys),
 * and the user's total number of passkeys: ["credentials" => rows, "count" => int].
 */
function directory_load_user_credentials(PDO $pdo, string $userId): array
{
    $limit = directory_user_credentials_limit();
    $credStmt = $pdo->prepare(
        "SELECT id, user_id, rp_id, friendly_name, cose_alg, sign_count, created_at, last_used_at " .
            "FROM webauthn_credentials WHERE user_id = :uid ORDER BY created_at DESC LIMIT " . $limit
    );
    $credStmt->execute([":uid" => $userId]);
    $creds = $credStmt->fetchAll(PDO::FETCH_ASSOC);
    $count = count($creds);
    if ($count >= $limit) {
        $countStmt = $pdo->prepare("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = :uid");
        $countStmt->execute([":uid" => $userId]);
        $count = max($count, (int) $countStmt->fetchColumn());
        $countStmt->closeCursor();
    }
    return ["credentials" => $creds, "count" => $count];
}

/** The stored OIDC subject of an idp_users row, or its legacy fallback (email, username, id). */
function directory_user_subject(array $row): string
{
    foreach (["subject", "email", "username", "id"] as $column) {
        $value = (string) ($row[$column] ?? "");
        if (trim($value) !== "") {
            return $value;
        }
    }
    return "";
}

/**
 * Prefix of the marker that replaces a deleted group's name in app assignments and SCIM token
 * filters. No group may be named with it, and it never matches a user's groups.
 */
function directory_deleted_group_prefix(): string
{
    return "__deleted_group__:";
}

function directory_is_reserved_group_name(string $name): bool
{
    return str_starts_with(strtolower(trim($name)), directory_deleted_group_prefix());
}

function directory_assert_group_name_allowed(string $name): void
{
    if (directory_is_reserved_group_name($name)) {
        throw new InvalidArgumentException(
            "Group names starting with \"" . directory_deleted_group_prefix() . "\" are reserved"
        );
    }
}

/** Normalizes group names from input; a reserved deleted-group marker is rejected. */
function directory_normalize_group_names($groups): array
{
    $clean = normalize_string_list($groups);
    foreach ($clean as $name) {
        directory_assert_group_name_allowed($name);
    }
    return $clean;
}

/** Returns a valid user status, or throws: an unknown value is never coerced. */
function directory_validate_user_status($status): string
{
    if (!is_string($status) || !in_array($status, ["active", "suspended"], true)) {
        throw new InvalidArgumentException("Invalid status: expected \"active\" or \"suspended\"");
    }
    return $status;
}

/**
 * JSON text for a JSON column. A value that cannot be encoded (invalid UTF-8, for example) is
 * rejected; it is never stored as an empty string, which would silently wipe the column.
 */
function directory_encode_json(array $value, string $field): string
{
    $json = json_encode($value, JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new InvalidArgumentException("Invalid " . $field . ": " . json_last_error_msg());
    }
    return $json;
}

// ---------- Directory user password policy (S06-04) ----------

/** Minimum length, in characters, of a password a directory user is given. */
const DIRECTORY_PASSWORD_MIN_LENGTH = 12;

/**
 * Whether passwords given to directory users must pass directory_assert_password_allowed().
 * The flag allow_weak_directory_passwords (env OIDC_ALLOW_WEAK_DIRECTORY_PASSWORDS) restores
 * accepting any non-empty password, for legacy imports and SCIM clients that sync passwords
 * from a directory with a weaker policy.
 */
function directory_password_policy_enforced(): bool
{
    return !config_flag("allow_weak_directory_passwords", "OIDC_ALLOW_WEAK_DIRECTORY_PASSWORDS");
}

/**
 * Lowercase passwords of at least DIRECTORY_PASSWORD_MIN_LENGTH characters that lead breach
 * lists; directory_assert_password_allowed() refuses them in any letter case.
 */
function directory_common_passwords(): array
{
    return [
        "123456789012", "1234567890123", "12345678901234", "123456789012345",
        "123123123123", "123412341234", "121212121212", "123456123456", "112233445566",
        "987654321098", "password1234", "password12345", "password123!", "password@123",
        "passw0rd1234", "passw0rd123!", "p@ssw0rd1234", "p@ssw0rd123!", "p@ssword1234",
        "passwordpassword", "qwerty123456", "qwertyuiop12", "qwertyuiop123", "qwertyuiopasdf",
        "qwertyqwerty", "1q2w3e4r5t6y", "q1w2e3r4t5y6", "1qaz2wsx3edc", "1qazxsw23edc",
        "zaq12wsxcde3", "abc123456789", "abcd12345678", "abcdefghijkl", "iloveyou1234",
        "welcome12345", "welcome1234!", "welcome@1234", "changeme1234", "letmein12345",
        "administrator", "admin1234567", "football1234", "sunshine1234", "princess1234",
    ];
}

/**
 * The password of a create or update input: "" when absent or empty. A value that is not a
 * scalar (a JSON array or object) is rejected rather than cast to a string.
 */
function directory_password_input(mixed $value): string
{
    if ($value === null) {
        return "";
    }
    if (!is_scalar($value)) {
        throw new InvalidArgumentException("password must be a string");
    }
    return (string) $value;
}

/**
 * Throws InvalidArgumentException (an API or SCIM 400) for a password a directory user may not
 * be given: fewer than DIRECTORY_PASSWORD_MIN_LENGTH characters, one character repeated, one of
 * directory_common_passwords(), or equal to one of $identifiers (the user's username and
 * email) or to the part of one before its "@", ignoring case. directory_create_user() and
 * directory_update_user() apply it to every password they are given, including one equal to
 * the stored password: exempting that one would let a client that may write the user tell
 * whether a weak legacy password is right without changing it. Nothing is checked while
 * directory_password_policy_enforced() is false.
 */
function directory_assert_password_allowed(string $password, array $identifiers = []): void
{
    if (!directory_password_policy_enforced()) {
        return;
    }
    // Characters of valid UTF-8 (every API and SCIM request body is JSON), else bytes.
    $length = preg_match('//u', $password) === 1
        ? (int) preg_match_all('/./su', $password)
        : strlen($password);
    if ($length < DIRECTORY_PASSWORD_MIN_LENGTH) {
        throw new InvalidArgumentException(
            "Password must be at least " . DIRECTORY_PASSWORD_MIN_LENGTH . " characters long"
        );
    }
    $lower = strtolower($password);
    if (
        preg_match('/^(.)\1*$/su', $password) === 1 ||
        in_array($lower, directory_common_passwords(), true)
    ) {
        throw new InvalidArgumentException("Password is too easy to guess; choose a less common one");
    }
    foreach ($identifiers as $identifier) {
        $identifier = is_scalar($identifier) ? strtolower(trim((string) $identifier)) : "";
        if ($identifier === "") {
            continue;
        }
        $at = strrpos($identifier, "@");
        $localPart = $at !== false && $at > 0 ? substr($identifier, 0, $at) : null;
        if ($lower === $identifier || $lower === $localPart) {
            throw new InvalidArgumentException("Password must not be the same as the username or email");
        }
    }
}

/**
 * Every directory user of $owner, by username, as hydrate_idp_user_row() returns them. With
 * $withCredentials (the default) each record embeds its newest passkeys, at most
 * directory_user_credentials_limit(), and touchid_count counts all of them. The credential rows
 * are streamed and only those are kept, so memory stays bounded however many passkeys an account
 * registered before the per-user cap existed (G1c-03). With false, "credentials" is empty and
 * touchid_count still holds the total, for callers that need only the user fields.
 */
function directory_list_users(string $storePath, string $owner, bool $withCredentials = true): array
{
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM idp_users WHERE owner = :owner ORDER BY username COLLATE NOCASE ASC"
    );
    $stmt->execute([":owner" => $owner]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $credsByUser = [];
    $countByUser = [];
    if ($withCredentials) {
        $limit = directory_user_credentials_limit();
        $credStmt = $pdo->prepare(
            "SELECT id, user_id, rp_id, friendly_name, cose_alg, sign_count, created_at, last_used_at " .
                "FROM webauthn_credentials WHERE owner = :owner ORDER BY created_at DESC"
        );
        $credStmt->execute([":owner" => $owner]);
        while ($c = $credStmt->fetch(PDO::FETCH_ASSOC)) {
            $uid = (string) $c["user_id"];
            $countByUser[$uid] = ($countByUser[$uid] ?? 0) + 1;
            if ($countByUser[$uid] > $limit) {
                continue;
            }
            $credsByUser[$uid][] = [
                "id" => $c["id"],
                "rp_id" => $c["rp_id"],
                "friendly_name" => $c["friendly_name"],
                "cose_alg" => (int) $c["cose_alg"],
                "sign_count" => (int) $c["sign_count"],
                "created_at" => $c["created_at"],
                "last_used_at" => $c["last_used_at"],
            ];
        }
    } else {
        $countStmt = $pdo->prepare(
            "SELECT user_id, COUNT(*) AS n FROM webauthn_credentials WHERE owner = :owner GROUP BY user_id"
        );
        $countStmt->execute([":owner" => $owner]);
        while ($c = $countStmt->fetch(PDO::FETCH_ASSOC)) {
            $countByUser[(string) $c["user_id"]] = (int) $c["n"];
        }
    }

    $out = [];
    foreach ($rows as $r) {
        $uid = (string) $r["id"];
        $out[] = hydrate_idp_user_row($r, $credsByUser[$uid] ?? [], $countByUser[$uid] ?? 0);
    }
    return $out;
}

function directory_get_user_by_id(
    string $storePath,
    string $userId,
    ?string $owner = null
): ?array {
    $pdo = storage_db($storePath);
    if ($owner !== null) {
        $stmt = $pdo->prepare(
            "SELECT * FROM idp_users WHERE id = :id AND owner = :owner LIMIT 1"
        );
        $stmt->execute([":id" => $userId, ":owner" => $owner]);
    } else {
        $stmt = $pdo->prepare("SELECT * FROM idp_users WHERE id = :id LIMIT 1");
        $stmt->execute([":id" => $userId]);
    }
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt->closeCursor();
    if (!$row) {
        return null;
    }

    $creds = directory_load_user_credentials($pdo, (string) $row["id"]);
    $user = hydrate_idp_user_row($row, $creds["credentials"], $creds["count"]);
    $user["_password_hash"] = $row["password_hash"] ?? null;
    return $user;
}

function directory_find_user_by_identifier(
    string $storePath,
    string $owner,
    string $identifier
): ?array {
    $ident = trim($identifier);
    if ($ident === "") {
        return null;
    }
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM idp_users WHERE owner = :owner AND (LOWER(username) = LOWER(:ident) OR LOWER(email) = LOWER(:ident)) LIMIT 2"
    );
    $stmt->execute([":owner" => $owner, ":ident" => $ident]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    if (count($rows) !== 1) {
        if (count($rows) > 1) {
            // Data created before usernames and emails shared one namespace can still collide.
            // Never pick one of the accounts: the result would depend on row order.
            error_log(sprintf(
                "directory: sign-in identifier matches more than one user of owner '%s' (user ids %s); " .
                    "refusing to resolve it until the usernames/emails are made unique",
                sanitize_label($owner, 120),
                implode(", ", array_map(fn($r) => (string) $r["id"], $rows))
            ));
        }
        return null;
    }
    $row = $rows[0];

    $creds = directory_load_user_credentials($pdo, (string) $row["id"]);
    $user = hydrate_idp_user_row($row, $creds["credentials"], $creds["count"]);
    $user["_password_hash"] = $row["password_hash"] ?? null;
    return $user;
}

/**
 * Returns the id of a user of $owner (other than $exceptUserId) whose username or email
 * equals any of $identifiers, ignoring case, or null. Usernames and emails share one namespace
 * per owner, so a sign-in identifier resolves to at most one user; a user's own username may
 * still equal its own email. Call it in the same write transaction as the insert or update.
 */
function directory_identifier_conflict(
    PDO $pdo,
    string $owner,
    array $identifiers,
    ?string $exceptUserId = null
): ?string {
    $idents = [];
    foreach ($identifiers as $ident) {
        $ident = trim((string) $ident);
        if ($ident !== "" && !isset($idents[strtolower($ident)])) {
            $idents[strtolower($ident)] = $ident;
        }
    }
    if (empty($idents)) {
        return null;
    }
    $params = [":owner" => $owner];
    $placeholders = [];
    foreach (array_values($idents) as $n => $ident) {
        $placeholders[] = "LOWER(:ident" . $n . ")";
        $params[":ident" . $n] = $ident;
    }
    $in = implode(", ", $placeholders);
    $sql =
        "SELECT id FROM idp_users WHERE owner = :owner " .
        "AND (LOWER(username) IN (" . $in . ") OR LOWER(email) IN (" . $in . "))";
    if ($exceptUserId !== null) {
        $sql .= " AND id != :except";
        $params[":except"] = $exceptUserId;
    }
    $stmt = $pdo->prepare($sql . " LIMIT 1");
    $stmt->execute($params);
    $id = $stmt->fetchColumn();
    $stmt->closeCursor();
    return $id === false || $id === null ? null : (string) $id;
}

function directory_create_user(
    string $storePath,
    string $owner,
    array $input
): array {
    $username = trim((string) ($input["username"] ?? ""));
    $email = trim((string) ($input["email"] ?? ""));
    if ($username === "" && $email !== "") {
        $username = $email;
    }
    if ($email === "" && str_contains($username, "@")) {
        $email = $username;
    }
    if ($username === "" || $email === "") {
        throw new InvalidArgumentException("Username and email are required");
    }

    $givenName = trim((string) ($input["given_name"] ?? ($input["firstName"] ?? "")));
    $familyName = trim((string) ($input["family_name"] ?? ($input["lastName"] ?? "")));
    $displayName = trim((string) ($input["display_name"] ?? ""));
    if ($displayName === "") {
        $full = trim($givenName . " " . $familyName);
        $displayName = $full !== "" ? $full : $username;
    }
    $mobilePhone = trim((string) ($input["mobile_phone"] ?? ($input["mobilePhone"] ?? "")));
    $groups = directory_normalize_group_names($input["groups"] ?? []);
    $attrs = isset($input["attributes"]) && is_array($input["attributes"])
        ? $input["attributes"]
        : [];
    $attrsJson = directory_encode_json($attrs, "attributes");
    $externalId = trim((string) ($input["external_id"] ?? ($input["externalId"] ?? "")));
    $status = isset($input["status"]) ? directory_validate_user_status($input["status"]) : "active";
    // Nothing verifies addresses, so a new user's email counts as verified only when the
    // caller says so explicitly.
    $emailVerified = !empty($input["email_verified"]) ? 1 : 0;

    $passwordRaw = directory_password_input($input["password"] ?? null);
    if ($passwordRaw !== "") {
        directory_assert_password_allowed($passwordRaw, [$username, $email]);
    }
    $passwordHash =
        $passwordRaw !== "" ? password_hash($passwordRaw, PASSWORD_DEFAULT) : null;

    $pdo = storage_db($storePath);
    $id = uuidv4();
    $now = gmdate("Y-m-d\TH:i:s\Z");
    $params = [
        ":id" => $id,
        ":owner" => $owner,
        ":u" => $username,
        ":e" => $email,
        ":ph" => $passwordHash,
        // Set inside the transaction below.
        ":pe" => null,
        ":gn" => $givenName,
        ":fn" => $familyName,
        ":dn" => $displayName,
        ":mp" => $mobilePhone,
        ":grp" => directory_encode_json($groups, "groups"),
        ":attr" => $attrsJson,
        ":ext" => $externalId,
        ":st" => $status,
        // The immutable OIDC subject of a new user is its id, never an address that can be
        // renamed or handed to someone else later.
        ":sub" => $id,
        ":ev" => $emailVerified,
        ":cat" => $now,
        ":uat" => $now,
    ];
    // The uniqueness check and the insert share one write lock, so two concurrent requests
    // cannot both pass the check. The password was hashed above, outside the lock.
    storage_write_transaction($pdo, function (PDO $pdo) use (
        $storePath,
        $owner,
        $username,
        $email,
        $groups,
        $params,
        $passwordRaw
    ): void {
        if (directory_identifier_conflict($pdo, $owner, [$username, $email]) !== null) {
            throw new RuntimeException("A user with this username or email already exists");
        }
        // A recoverable copy for outbound password push is kept only while the owner has a
        // push_passwords connector and the password copy policy allows one (S04-08). It is made
        // here, under the write lock, so a connector removed and purged meanwhile cannot leave a
        // copy behind.
        $params[":pe"] = $passwordRaw !== ""
            ? vault_user_password_copy($storePath, $owner, $passwordRaw)
            : null;
        storage_execute(
            $pdo->prepare(
                "INSERT INTO idp_users (" .
                    "id, owner, username, email, password_hash, password_enc, given_name, family_name, display_name, " .
                    "mobile_phone, groups_json, attributes_json, external_id, status, subject, email_verified, created_at, updated_at" .
                ") VALUES (:id, :owner, :u, :e, :ph, :pe, :gn, :fn, :dn, :mp, :grp, :attr, :ext, :st, :sub, :ev, :cat, :uat)"
            ),
            $params
        );
        if (!empty($groups)) {
            directory_insert_missing_groups($pdo, $owner, $groups);
        }
    });

    if (empty($input["_skip_scim_auto_sync"]) && function_exists("scim_trigger_auto_sync_for_owner")) {
        scim_trigger_auto_sync_for_owner($storePath, $owner);
    }

    return directory_get_user_by_id($storePath, $id, $owner) ?? [];
}

/**
 * Updates the fields present in $input. Absent fields keep their stored values, so an update
 * never writes back a stale copy of groups, attributes or any other column: a SCIM user PATCH,
 * for example, can no longer undo a concurrent group removal. A new password is hashed before
 * the write lock is taken; the read, the uniqueness check and the UPDATE then run in one
 * BEGIN IMMEDIATE transaction.
 *
 * Setting a new password or clearing it, or changing the status to anything but "active", also
 * voids a pending enrollment link and deletes the user's OIDC tokens, authorization codes and
 * SSO sessions in the same transaction. A password must pass directory_assert_password_allowed()
 * (S06-04). A password equal to the stored one (a SCIM client that sends the password with every
 * PUT) is not hashed again and ends no session or token (G2a-06); the explicit revoke action
 * does that. The recoverable copy for outbound password push (password_enc) is made inside the
 * transaction by vault_user_password_copy(), so it exists only while the owner has a
 * push_passwords connector and the policy allows it (S04-08). An unknown status is rejected.
 * email_verified may be set explicitly; otherwise a changed email resets it to false. The
 * subject never changes.
 *
 * "groups" and "attributes" replace the whole list or map. A caller that derived them from a
 * copy it read earlier (a SCIM PUT or PATCH, the admin console) also passes that copy as
 * "groups_base" / "attributes_base": then only what the caller changed relative to the copy is
 * applied to the values read inside the transaction (directory_merge_group_names(),
 * directory_merge_attributes()), so a group or attribute that another request changed
 * meanwhile, for example a removed role, is not reverted.
 *
 * $precondition, when given, is called inside the transaction, before anything is written,
 * with the stored user as directory_get_user_by_id() returns it. Returning false aborts the
 * update with DirectoryPreconditionFailed (a SCIM If-Match check, for example).
 */
function directory_update_user(
    string $storePath,
    string $owner,
    string $userId,
    array $input,
    ?Closure $precondition = null
): array {
    $pdo = storage_db($storePath);
    // The stored hash is read before the write lock, so a supplied password can be compared
    // with it (bcrypt) without holding the lock.
    $existing = $pdo->prepare(
        "SELECT username, email, password_hash FROM idp_users WHERE id = :id AND owner = :owner LIMIT 1"
    );
    $existing->execute([":id" => $userId, ":owner" => $owner]);
    $before = $existing->fetch(PDO::FETCH_ASSOC);
    $existing->closeCursor();
    if (!is_array($before)) {
        throw new RuntimeException("User not found");
    }

    // Column => new value, for the supplied fields only. Column names never come from input.
    $set = [];
    foreach (["username", "email"] as $column) {
        if (isset($input[$column])) {
            $value = trim((string) $input[$column]);
            if ($value === "") {
                throw new InvalidArgumentException("Username and email cannot be empty");
            }
            $set[$column] = $value;
        }
    }
    foreach (["given_name", "family_name", "mobile_phone"] as $column) {
        if (array_key_exists($column, $input)) {
            $set[$column] = trim((string) $input[$column]);
        }
    }
    if (array_key_exists("external_id", $input)) {
        $set["external_id"] = trim((string) $input["external_id"]);
    } elseif (array_key_exists("externalId", $input)) {
        $set["external_id"] = trim((string) $input["externalId"]);
    }
    // Groups and attributes are combined with the values read under the write lock below;
    // values that cannot be stored are rejected before the lock is taken.
    $groups = null;
    $groupsBase = null;
    if (array_key_exists("groups", $input)) {
        $groups = directory_normalize_group_names($input["groups"]);
        directory_encode_json($groups, "groups");
        if (isset($input["groups_base"])) {
            if (!is_array($input["groups_base"]) && !is_string($input["groups_base"])) {
                throw new InvalidArgumentException("groups_base must be a list of group names");
            }
            $groupsBase = normalize_string_list($input["groups_base"]);
        }
    }
    $attributes = null;
    $attributesBase = null;
    if (array_key_exists("attributes", $input) && is_array($input["attributes"])) {
        $attributes = $input["attributes"];
        directory_encode_json($attributes, "attributes");
        if (isset($input["attributes_base"])) {
            if (!is_array($input["attributes_base"])) {
                throw new InvalidArgumentException("attributes_base must be an object");
            }
            $attributesBase = $input["attributes_base"];
        }
    }
    $newStatus = isset($input["status"]) ? directory_validate_user_status($input["status"]) : null;
    if ($newStatus !== null) {
        $set["status"] = $newStatus;
    }
    $displayName = array_key_exists("display_name", $input)
        ? trim((string) $input["display_name"])
        : null;
    $emailVerified = array_key_exists("email_verified", $input)
        ? (!empty($input["email_verified"]) ? 1 : 0)
        : null;

    $passwordChanged = false;
    // A new password, whose push copy is made inside the transaction.
    $newPassword = null;
    // A supplied password equal to the stored one, and the stored hash it matched.
    $samePassword = null;
    $samePasswordHash = null;
    if (!empty($input["clear_password"])) {
        $set["password_hash"] = null;
        $set["password_enc"] = null;
        $passwordChanged = true;
    } else {
        $password = directory_password_input($input["password"] ?? null);
        if ($password !== "") {
            directory_assert_password_allowed($password, [
                $set["username"] ?? (string) $before["username"],
                $set["email"] ?? (string) $before["email"],
            ]);
            // bcrypt runs here, before the write lock, so it never stalls other writers.
            $storedHash = $before["password_hash"] ?? null;
            if (is_string($storedHash) && $storedHash !== "" && password_verify($password, $storedHash)) {
                $samePassword = $password;
                $samePasswordHash = $storedHash;
            } else {
                $set["password_hash"] = password_hash($password, PASSWORD_DEFAULT);
                $newPassword = $password;
                $passwordChanged = true;
            }
        }
    }

    $now = gmdate("Y-m-d\TH:i:s\Z");
    storage_write_transaction(
        $pdo,
        function (PDO $pdo) use (
            $storePath,
            $owner,
            $userId,
            $set,
            $groups,
            $groupsBase,
            $attributes,
            $attributesBase,
            $displayName,
            $emailVerified,
            $newStatus,
            $passwordChanged,
            $newPassword,
            $samePassword,
            $samePasswordHash,
            $precondition,
            $now
        ): void {
            $cur = $pdo->prepare(
                "SELECT username, email, given_name, family_name, status, groups_json, attributes_json, " .
                    "password_hash, password_enc FROM idp_users WHERE id = :id AND owner = :owner LIMIT 1"
            );
            $cur->execute([":id" => $userId, ":owner" => $owner]);
            $stored = $cur->fetch(PDO::FETCH_ASSOC);
            $cur->closeCursor();
            if (!$stored) {
                throw new RuntimeException("User not found");
            }
            if ($precondition !== null) {
                $fresh = directory_get_user_by_id($storePath, $userId, $owner);
                if ($fresh === null) {
                    throw new RuntimeException("User not found");
                }
                directory_check_precondition($precondition, $fresh);
            }
            // Written only when the result differs from the stored value, so a no-op does not
            // bump updated_at (and with it the SCIM version).
            $nextGroups = null;
            if ($groups !== null) {
                $decoded = json_decode((string) ($stored["groups_json"] ?? ""), true);
                $storedGroups = is_array($decoded) ? array_values($decoded) : [];
                $nextGroups = $groupsBase !== null
                    ? directory_merge_group_names(normalize_string_list($storedGroups), $groupsBase, $groups)
                    : $groups;
                if ($nextGroups !== $storedGroups) {
                    $set["groups_json"] = directory_encode_json($nextGroups, "groups");
                }
            }
            if ($attributes !== null) {
                $decoded = json_decode((string) ($stored["attributes_json"] ?? ""), true);
                $storedAttrs = is_array($decoded) ? $decoded : [];
                $nextAttrs = $attributesBase !== null
                    ? directory_merge_attributes($storedAttrs, $attributesBase, $attributes)
                    : $attributes;
                if ($nextAttrs !== $storedAttrs) {
                    $set["attributes_json"] = directory_encode_json($nextAttrs, "attributes");
                }
            }
            // Only identifiers that change are checked, so a collision left over from older
            // data never blocks editing the other fields, or renaming one of the accounts.
            $changed = [];
            foreach (["username", "email"] as $column) {
                if (
                    isset($set[$column]) &&
                    strtolower($set[$column]) !== strtolower((string) $stored[$column])
                ) {
                    $changed[] = $set[$column];
                }
            }
            if (
                !empty($changed) &&
                directory_identifier_conflict($pdo, $owner, $changed, $userId) !== null
            ) {
                throw new RuntimeException("Another user already uses this username or email");
            }
            if ($displayName !== null) {
                if ($displayName === "") {
                    // Same default as on create, from the values this update leaves in place.
                    $full = trim(
                        ($set["given_name"] ?? (string) $stored["given_name"]) .
                            " " .
                            ($set["family_name"] ?? (string) $stored["family_name"])
                    );
                    $displayName = $full !== ""
                        ? $full
                        : ($set["username"] ?? (string) $stored["username"]);
                }
                $set["display_name"] = $displayName;
            }
            if ($emailVerified !== null) {
                $set["email_verified"] = $emailVerified;
            } elseif (
                isset($set["email"]) &&
                strtolower($set["email"]) !== strtolower((string) $stored["email"])
            ) {
                // Whatever was true of the old address, the new one has not been verified.
                $set["email_verified"] = 0;
            }
            // The recoverable copy for outbound password push (S04-08) is made here, under the
            // write lock, so a push connector removed and purged meanwhile cannot leave one
            // behind. vault_user_password_copy() returns null unless the owner has a
            // push_passwords connector and the policy allows a copy.
            if ($newPassword !== null) {
                // Null also drops the copy of the old password.
                $set["password_enc"] = vault_user_password_copy($storePath, $owner, $newPassword);
            } elseif (
                $samePassword !== null &&
                hash_equals($samePasswordHash, (string) ($stored["password_hash"] ?? ""))
            ) {
                // The stored password, sent again and still unchanged: a copy of it is kept as
                // it is, made when a push connector now needs one, or dropped when none may be
                // kept. Skipped when the password changed meanwhile.
                $copy = vault_user_password_copy($storePath, $owner, $samePassword);
                $hasCopy = is_string($stored["password_enc"] ?? null) && $stored["password_enc"] !== "";
                if ($copy === null && $hasCopy) {
                    $set["password_enc"] = null;
                } elseif ($copy !== null && !$hasCopy) {
                    $set["password_enc"] = $copy;
                }
            }
            // A new or cleared password, or a suspension, is how an admin contains a leaked
            // credential or invite link: end the user's sessions and void the link at once.
            $revokeAccess =
                $passwordChanged ||
                ($newStatus !== null &&
                    $newStatus !== "active" &&
                    $newStatus !== (string) $stored["status"]);
            if ($revokeAccess) {
                $set["enrollment_token"] = null;
                $set["enrollment_expires_at"] = null;
            }
            if (empty($set)) {
                return;
            }
            $set["updated_at"] = $now;
            $assignments = [];
            $params = [":id" => $userId, ":owner" => $owner];
            foreach ($set as $column => $value) {
                $assignments[] = $column . " = :c_" . $column;
                $params[":c_" . $column] = $value;
            }
            storage_execute(
                $pdo->prepare(
                    "UPDATE idp_users SET " . implode(", ", $assignments) .
                        " WHERE id = :id AND owner = :owner"
                ),
                $params
            );
            if ($revokeAccess) {
                directory_revoke_user_access($pdo, $userId);
            }
            if (isset($set["groups_json"]) && !empty($nextGroups)) {
                directory_insert_missing_groups($pdo, $owner, $nextGroups);
            }
        }
    );

    if (empty($input["_skip_scim_auto_sync"]) && function_exists("scim_trigger_auto_sync_for_owner")) {
        scim_trigger_auto_sync_for_owner($storePath, $owner);
    }

    return directory_get_user_by_id($storePath, $userId, $owner) ?? [];
}

/**
 * Runs a write's $precondition on the stored resource, inside the write transaction. False
 * aborts the write with DirectoryPreconditionFailed; an exception it throws aborts it as well.
 */
function directory_check_precondition(?Closure $precondition, array $resource): void
{
    if ($precondition !== null && $precondition($resource) === false) {
        throw new DirectoryPreconditionFailed(
            "The resource was changed by another request; read it again and retry",
            412
        );
    }
}

/**
 * Three-way merge of a user's group names. When nothing changed since the caller read $base
 * (the list it derived $new from), the result is $new. Otherwise, compared case-insensitively,
 * the groups that $new adds to $base are added to $stored and the groups it removes are
 * removed, so groups that another request added or removed meanwhile stay as stored. Stored
 * groups keep their order; added groups go at the end.
 */
function directory_merge_group_names(array $stored, array $base, array $new): array
{
    if ($stored === $base) {
        return $new;
    }
    $baseSet = [];
    foreach ($base as $name) {
        $baseSet[strtolower((string) $name)] = true;
    }
    $newSet = [];
    foreach ($new as $name) {
        $newSet[strtolower((string) $name)] = true;
    }
    $out = [];
    $seen = [];
    foreach ($stored as $name) {
        $key = strtolower((string) $name);
        if (isset($seen[$key]) || (isset($baseSet[$key]) && !isset($newSet[$key]))) {
            continue;
        }
        $seen[$key] = true;
        $out[] = $name;
    }
    foreach ($new as $name) {
        $key = strtolower((string) $name);
        if (!isset($baseSet[$key]) && !isset($seen[$key])) {
            $seen[$key] = true;
            $out[] = $name;
        }
    }
    return $out;
}

/**
 * Three-way merge of a user's custom attributes: only the keys that $new changes relative to
 * $base (the map the caller derived $new from) are applied to $stored, so a key that only
 * another request changed meanwhile keeps its stored value. A key that $new drops is removed
 * and a key it adds or changes is set. When another request changed the same key meanwhile
 * and the old and the new value are lists of scalars (a missing value counts as an empty
 * list), only the values that $new adds and removes are applied to the stored list, so a
 * concurrent change to other values of a multi-valued attribute, such as roles, is kept too.
 */
function directory_merge_attributes(array $stored, array $base, array $new): array
{
    foreach (array_keys($base + $new) as $key) {
        $inBase = array_key_exists($key, $base);
        $inNew = array_key_exists($key, $new);
        if ($inBase && $inNew && $base[$key] === $new[$key]) {
            continue;
        }
        $inStored = array_key_exists($key, $stored);
        $changedMeanwhile = $inStored !== $inBase || ($inBase && $stored[$key] !== $base[$key]);
        if ($changedMeanwhile) {
            $old = $inBase ? $base[$key] : [];
            $next = $inNew ? $new[$key] : [];
            $current = $inStored ? $stored[$key] : [];
            if (
                directory_is_scalar_list($old) &&
                directory_is_scalar_list($next) &&
                directory_is_scalar_list($current)
            ) {
                $merged = directory_merge_value_list($current, $old, $next);
                if ($merged === [] && !$inNew) {
                    unset($stored[$key]);
                } else {
                    $stored[$key] = $merged;
                }
                continue;
            }
        }
        if ($inNew) {
            $stored[$key] = $new[$key];
        } else {
            unset($stored[$key]);
        }
    }
    return $stored;
}

/**
 * $current without the values that $old has and $new lacks, followed by the values that $new
 * has and $old lacks (unless already present). Values compare by type and value.
 */
function directory_merge_value_list(array $current, array $old, array $new): array
{
    $oldSet = [];
    foreach ($old as $value) {
        $oldSet[serialize($value)] = true;
    }
    $newSet = [];
    foreach ($new as $value) {
        $newSet[serialize($value)] = true;
    }
    $out = [];
    $seen = [];
    foreach ($current as $value) {
        $id = serialize($value);
        if (isset($oldSet[$id]) && !isset($newSet[$id])) {
            continue;
        }
        $seen[$id] = true;
        $out[] = $value;
    }
    foreach ($new as $value) {
        $id = serialize($value);
        if (!isset($oldSet[$id]) && !isset($seen[$id])) {
            $seen[$id] = true;
            $out[] = $value;
        }
    }
    return $out;
}

/** True for a list (array_is_list(); [] included) whose items are all scalars. */
function directory_is_scalar_list(mixed $value): bool
{
    if (!is_array($value) || !array_is_list($value)) {
        return false;
    }
    foreach ($value as $item) {
        if (!is_scalar($item)) {
            return false;
        }
    }
    return true;
}

/**
 * Ends every session and token of a user: OIDC access and refresh tokens, unredeemed
 * authorization codes and SSO sessions. Runs in the caller's write transaction.
 */
function directory_revoke_user_access(PDO $pdo, string $userId): void
{
    foreach (["oidc_tokens", "oidc_auth_codes", "sso_sessions"] as $table) {
        $pdo->prepare("DELETE FROM " . $table . " WHERE user_id = :uid")->execute([":uid" => $userId]);
    }
}

/**
 * Deletes a user; returns true when a row was deleted. $precondition, when given, is called in
 * the write transaction with the stored user (directory_get_user_by_id()) before the delete;
 * returning false aborts it with DirectoryPreconditionFailed.
 */
function directory_delete_user(
    string $storePath,
    string $owner,
    string $userId,
    bool $skipAutoSync = false,
    ?Closure $precondition = null
): bool {
    $deleted = (bool) storage_write_transaction(
        storage_db($storePath),
        function (PDO $pdo) use ($storePath, $owner, $userId, $precondition): bool {
            if ($precondition !== null) {
                $fresh = directory_get_user_by_id($storePath, $userId, $owner);
                if ($fresh === null) {
                    return false;
                }
                directory_check_precondition($precondition, $fresh);
            }
            $stmt = $pdo->prepare(
                "DELETE FROM idp_users WHERE id = :id AND owner = :owner"
            );
            $stmt->execute([":id" => $userId, ":owner" => $owner]);
            return $stmt->rowCount() > 0;
        }
    );
    if ($deleted && !$skipAutoSync && function_exists("scim_trigger_auto_sync_for_owner")) {
        scim_trigger_auto_sync_for_owner($storePath, $owner);
    }
    return $deleted;
}

/**
 * Internal helper used exclusively by Outbound SCIM 2.0 Connectors when `push_passwords` is enabled.
 * The stored copy is opened only as the password copy policy in force allows
 * (vault_user_password_for_push(), S04-08): never while password push is off, and only a copy
 * under OIDC_SCIM_ENCRYPTION_KEY while that key is the policy. Otherwise null.
 */
function directory_get_user_password_for_scim(
    string $storePath,
    string $owner,
    string $userId
): ?string {
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT password_enc FROM idp_users WHERE id = :id AND owner = :owner LIMIT 1"
    );
    $stmt->execute([":id" => $userId, ":owner" => $owner]);
    $enc = $stmt->fetchColumn();
    $stmt->closeCursor();
    if (!is_string($enc) || $enc === "") {
        return null;
    }
    return vault_user_password_for_push($storePath, $enc);
}

/**
 * Checks a sign-in password against the user's stored hash. Unknown users and users without
 * a password are checked against dummy_password_hash(), whose cost matches PASSWORD_DEFAULT,
 * so the response time does not reveal whether the account exists. With $storePath, a hash
 * that verifies but was made with older parameters (for example cost 10 from PHP < 8.4) is
 * upgraded to PASSWORD_DEFAULT, best effort.
 */
function directory_verify_password(?array $user, string $password, ?string $storePath = null): bool
{
    $hash = $user !== null ? ($user["_password_hash"] ?? null) : null;
    if ($password === "" || !is_string($hash) || $hash === "") {
        password_verify($password, dummy_password_hash());
        return false;
    }
    if (!password_verify($password, $hash)) {
        return false;
    }
    if ($storePath !== null && $storePath !== "" && password_needs_rehash($hash, PASSWORD_DEFAULT)) {
        directory_upgrade_password_hash($storePath, (string) ($user["id"] ?? ""), $hash, $password);
    }
    return true;
}

/**
 * Re-hashes a password that just verified, with PASSWORD_DEFAULT. Compare-and-swap on the old
 * hash, so a password changed concurrently is never overwritten. Failures are only logged.
 */
function directory_upgrade_password_hash(
    string $storePath,
    string $userId,
    string $oldHash,
    string $password
): void {
    if ($userId === "") {
        return;
    }
    try {
        $newHash = password_hash($password, PASSWORD_DEFAULT);
        storage_db($storePath)
            ->prepare("UPDATE idp_users SET password_hash = :new WHERE id = :id AND password_hash = :old")
            ->execute([":new" => $newHash, ":id" => $userId, ":old" => $oldHash]);
    } catch (Throwable $e) {
        error_log("directory: password hash upgrade skipped (" . get_class($e) . ")");
    }
}

function directory_touch_last_login(string $storePath, string $userId): void
{
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "UPDATE idp_users SET last_login_at = :ts WHERE id = :id"
    );
    $stmt->execute([":ts" => gmdate("Y-m-d\TH:i:s\Z"), ":id" => $userId]);
}

/** Digest stored for an enrollment link token; the token itself is never stored. */
function directory_enrollment_token_hash(string $token): string
{
    return hash("sha256", $token);
}

/**
 * Issues a new single-use enrollment link token for the user (replacing any earlier one) and
 * returns it. Only its SHA-256 is stored. The link works only while the user is active.
 */
function directory_create_enrollment_token(
    string $storePath,
    string $owner,
    string $userId,
    int $ttlSeconds = 86400
): string {
    $user = directory_get_user_by_id($storePath, $userId, $owner);
    if (!$user) {
        throw new RuntimeException("User not found");
    }
    $token = base64url_encode(random_bytes(24));
    $exp = gmdate("Y-m-d\TH:i:s\Z", time() + max(60, $ttlSeconds));
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "UPDATE idp_users SET enrollment_token = :tok, enrollment_expires_at = :exp WHERE id = :id AND owner = :owner"
    );
    $stmt->execute([
        ":tok" => directory_enrollment_token_hash($token),
        ":exp" => $exp,
        ":id" => $userId,
        ":owner" => $owner,
    ]);
    if ($stmt->rowCount() < 1) {
        throw new RuntimeException("User not found");
    }
    return $token;
}

/**
 * The active user whose pending, unexpired enrollment link token is $token, or null. A
 * suspended user's link does not work (and suspending a user voids it).
 */
function directory_find_user_by_enrollment_token(
    string $storePath,
    string $token
): ?array {
    $token = trim($token);
    if ($token === "" || strlen($token) > 512) {
        return null;
    }
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT id, enrollment_expires_at FROM idp_users " .
            "WHERE enrollment_token = :tok AND status = 'active' LIMIT 1"
    );
    $stmt->execute([":tok" => directory_enrollment_token_hash($token)]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt->closeCursor();
    if (!$row) {
        return null;
    }
    $exp = isset($row["enrollment_expires_at"])
        ? strtotime((string) $row["enrollment_expires_at"])
        : false;
    if ($exp === false || $exp <= time()) {
        return null;
    }
    $user = directory_get_user_by_id($storePath, (string) $row["id"]);
    return $user !== null && ($user["status"] ?? "") === "active" ? $user : null;
}

/**
 * Consumes an enrollment link. With $token, it is consumed atomically and only if it is the
 * user's current, unexpired token and the user is active; returns true when this call consumed
 * it (rowCount() === 1), so of two concurrent requests with one link only one succeeds. Call it
 * in the same write transaction as the credential insert (storage_write_transaction), so a
 * failed registration rolls the consumption back. Without $token the user's link is cleared
 * unconditionally (legacy behavior); returns true when the user exists.
 */
function directory_consume_enrollment_token(
    string $storePath,
    string $userId,
    ?string $token = null
): bool {
    $pdo = storage_db($storePath);
    if ($token === null) {
        $stmt = $pdo->prepare(
            "UPDATE idp_users SET enrollment_token = NULL, enrollment_expires_at = NULL WHERE id = :id"
        );
        $stmt->execute([":id" => $userId]);
        return $stmt->rowCount() > 0;
    }
    $token = trim($token);
    if ($token === "" || strlen($token) > 512) {
        return false;
    }
    // Timestamps are all gmdate("Y-m-d\TH:i:s\Z"), so text order is time order.
    $stmt = $pdo->prepare(
        "UPDATE idp_users SET enrollment_token = NULL, enrollment_expires_at = NULL " .
            "WHERE id = :id AND enrollment_token = :tok AND enrollment_expires_at > :now AND status = 'active'"
    );
    $stmt->execute([
        ":id" => $userId,
        ":tok" => directory_enrollment_token_hash($token),
        ":now" => gmdate("Y-m-d\TH:i:s\Z"),
    ]);
    return $stmt->rowCount() === 1;
}

function directory_user_matches_assigned_groups(
    array $user,
    array $assignedGroups
): bool {
    $cleanAssigned = normalize_string_list($assignedGroups);
    if (empty($cleanAssigned)) {
        return true; // Empty = all active directory users allowed
    }
    $userGroups = array_map("strtolower", $user["groups"] ?? []);
    foreach ($cleanAssigned as $g) {
        // The marker of a deleted group keeps the list restricted but never matches anyone.
        if (directory_is_reserved_group_name($g)) {
            continue;
        }
        if (in_array(strtolower($g), $userGroups, true)) {
            return true;
        }
    }
    return false;
}

/**
 * Resolves a mapped attribute value (scalar or array of strings) from an idp_user record.
 * Supported source expressions:
 *  - user.email, user.username, user.given_name, user.family_name, user.display_name, user.mobile_phone, user.groups, user.id
 *  - attr:<key>  (looks up $user['attributes'][<key>], with fallback for memberOf -> user.groups)
 *  - static:<literal>
 */
function directory_resolve_user_attribute(array $user, string $source): array
{
    $src = trim($source);
    if ($src === "") {
        return [];
    }
    if (str_starts_with($src, "static:")) {
        $val = substr($src, 7);
        return $val !== "" ? [$val] : [];
    }

    switch ($src) {
        case "user.id":
            return [$user["id"]];
        case "user.username":
            return $user["username"] !== "" ? [$user["username"]] : [];
        case "user.email":
            return $user["email"] !== "" ? [$user["email"]] : [];
        case "user.given_name":
            return $user["given_name"] !== "" ? [$user["given_name"]] : [];
        case "user.family_name":
            return $user["family_name"] !== "" ? [$user["family_name"]] : [];
        case "user.display_name":
            return $user["display_name"] !== "" ? [$user["display_name"]] : [];
        case "user.mobile_phone":
            return $user["mobile_phone"] !== "" ? [$user["mobile_phone"]] : [];
        case "user.groups":
            return array_values(
                array_filter(
                    array_map("strval", $user["groups"] ?? []),
                    fn($v) => $v !== ""
                )
            );
    }

    $attrKey = str_starts_with($src, "attr:") ? substr($src, 5) : $src;
    $attrs = $user["attributes"] ?? [];
    if (array_key_exists($attrKey, $attrs)) {
        $raw = $attrs[$attrKey];
        if (is_array($raw)) {
            $list = [];
            foreach ($raw as $item) {
                if (is_scalar($item) && trim((string) $item) !== "") {
                    $list[] = trim((string) $item);
                }
            }
            return $list;
        }
        if (is_bool($raw)) {
            return [$raw ? "true" : "false"];
        }
        if (is_scalar($raw) && trim((string) $raw) !== "") {
            $str = trim((string) $raw);
            // A string is one value, commas included ("Director, Sales", or an LDAP DN such as
            // "CN=Doe\, John,OU=Users"). Multi-valued attributes are stored as arrays. The
            // legacy_attribute_split flag restores splitting such strings on commas/newlines.
            if (
                str_contains($str, ",") &&
                config_flag("legacy_attribute_split", "OIDC_LEGACY_ATTRIBUTE_SPLIT")
            ) {
                return normalize_string_list($str);
            }
            return [$str];
        }
    }

    // Helpful fallback: if attr:memberOf is unset in custom attributes, fall back to user.groups
    if (strcasecmp($attrKey, "memberOf") === 0 && !empty($user["groups"])) {
        return array_values($user["groups"]);
    }

    return [];
}

/**
 * Discovers custom attributes referenced across all SAML apps owned by $owner,
 * so the Directory User UI can render labeled form fields automatically.
 */
function directory_discover_custom_attribute_schema(
    string $storePath,
    string $owner
): array {
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT s.name AS app_name, s.attribute_mapping_json " .
            "FROM saml_apps s JOIN providers p ON p.id = s.provider_id " .
            "WHERE p.owner = :owner"
    );
    $stmt->execute([":owner" => $owner]);

    $builtinSources = [
        "user.id",
        "user.username",
        "user.email",
        "user.given_name",
        "user.family_name",
        "user.display_name",
        "user.mobile_phone",
        "user.groups",
    ];
    $found = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $mappings = json_decode($row["attribute_mapping_json"] ?? "[]", true);
        if (!is_array($mappings)) {
            continue;
        }
        foreach ($mappings as $m) {
            $source = trim((string) ($m["source"] ?? ""));
            if (
                $source === "" ||
                in_array($source, $builtinSources, true) ||
                str_starts_with($source, "static:")
            ) {
                continue;
            }
            $key = str_starts_with($source, "attr:")
                ? substr($source, 5)
                : $source;
            if ($key === "") {
                continue;
            }
            if (!isset($found[$key])) {
                $found[$key] = [
                    "key" => $key,
                    "friendly_name" =>
                        (string) ($m["friendly_name"] ?: $m["name"] ?: $key),
                    "required" => !empty($m["required"]),
                    "apps" => [$row["app_name"]],
                ];
            } else {
                if (!empty($m["required"])) {
                    $found[$key]["required"] = true;
                }
                if (!in_array($row["app_name"], $found[$key]["apps"], true)) {
                    $found[$key]["apps"][] = $row["app_name"];
                }
            }
        }
    }
    return array_values($found);
}

// ---------- Directory Groups (Synced with idp_users.groups_json & SCIM 2.0) ----------

/**
 * Makes sure an idp_groups row exists for each name (compared case-insensitively), in one write
 * transaction. Reserved deleted-group markers are skipped.
 */
function directory_ensure_groups(
    string $storePath,
    string $owner,
    array $groupNames
): void {
    $clean = normalize_string_list($groupNames);
    if (empty($clean)) {
        return;
    }
    storage_write_transaction(storage_db($storePath), function (PDO $pdo) use ($owner, $clean): void {
        directory_insert_missing_groups($pdo, $owner, $clean);
    });
}

/**
 * Inserts an idp_groups row for each name that has none yet (compared case-insensitively).
 * Runs in the caller's write transaction, so the check and the insert are atomic.
 */
function directory_insert_missing_groups(PDO $pdo, string $owner, array $groupNames): void
{
    $known = [];
    $sel = $pdo->prepare("SELECT display_name FROM idp_groups WHERE owner = :owner");
    $sel->execute([":owner" => $owner]);
    foreach ($sel->fetchAll(PDO::FETCH_COLUMN) as $existing) {
        $known[strtolower(trim((string) $existing))] = true;
    }
    $now = gmdate("Y-m-d\TH:i:s\Z");
    // OR IGNORE also covers the UNIQUE(owner, display_name COLLATE NOCASE) constraint.
    $ins = $pdo->prepare(
        "INSERT OR IGNORE INTO idp_groups (id, owner, display_name, external_id, created_at, updated_at) " .
            "VALUES (:id, :owner, :dn, '', :cat, :uat)"
    );
    foreach (normalize_string_list($groupNames) as $dn) {
        $key = strtolower($dn);
        if (isset($known[$key]) || directory_is_reserved_group_name($dn)) {
            continue;
        }
        $known[$key] = true;
        $ins->execute([
            ":id" => uuidv4(),
            ":owner" => $owner,
            ":dn" => $dn,
            ":cat" => $now,
            ":uat" => $now,
        ]);
    }
}

/**
 * Group names that users of $owner carry in groups_json but that have no idp_groups row yet
 * (compared case-insensitively; the first spelling found wins).
 */
function directory_missing_group_names(PDO $pdo, string $owner): array
{
    $known = [];
    $groupStmt = $pdo->prepare("SELECT display_name FROM idp_groups WHERE owner = :owner");
    $groupStmt->execute([":owner" => $owner]);
    foreach ($groupStmt->fetchAll(PDO::FETCH_COLUMN) as $dn) {
        $known[strtolower(trim((string) $dn))] = true;
    }
    $userStmt = $pdo->prepare("SELECT groups_json FROM idp_users WHERE owner = :owner");
    $userStmt->execute([":owner" => $owner]);
    $missing = [];
    foreach ($userStmt->fetchAll(PDO::FETCH_COLUMN) as $json) {
        $names = json_decode((string) $json, true);
        if (!is_array($names)) {
            continue;
        }
        foreach ($names as $name) {
            if (!is_scalar($name)) {
                continue;
            }
            $name = trim((string) $name);
            $key = strtolower($name);
            if ($name === "" || isset($known[$key]) || directory_is_reserved_group_name($name)) {
                continue;
            }
            $known[$key] = true;
            $missing[] = $name;
        }
    }
    return $missing;
}

/**
 * Creates idp_groups rows for names that users carry in groups_json but that have no row yet.
 * When nothing is missing (the usual case) this only reads. Otherwise the check is repeated
 * under the write lock, so a group deleted in the meantime is not recreated from a stale read.
 */
function directory_sync_groups_from_users(string $storePath, string $owner): void
{
    $pdo = storage_db($storePath);
    if (empty(directory_missing_group_names($pdo, $owner))) {
        return;
    }
    storage_write_transaction($pdo, function (PDO $pdo) use ($owner): void {
        $missing = directory_missing_group_names($pdo, $owner);
        if (!empty($missing)) {
            directory_insert_missing_groups($pdo, $owner, $missing);
        }
    });
}

function directory_list_groups(string $storePath, string $owner): array
{
    directory_sync_groups_from_users($storePath, $owner);
    // Member entries need no passkeys.
    $users = directory_list_users($storePath, $owner, false);
    $membersByGroupLower = [];
    foreach ($users as $u) {
        foreach ($u["groups"] ?? [] as $gn) {
            $k = strtolower(trim((string) $gn));
            if ($k !== "") {
                $membersByGroupLower[$k][] = [
                    "id" => $u["id"],
                    "username" => $u["username"],
                    "display_name" => $u["display_name"],
                    "email" => $u["email"],
                ];
            }
        }
    }

    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM idp_groups WHERE owner = :owner ORDER BY display_name COLLATE NOCASE ASC"
    );
    $stmt->execute([":owner" => $owner]);
    $out = [];
    while ($r = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $dn = (string) $r["display_name"];
        $out[] = [
            "id" => (string) $r["id"],
            "owner" => (string) $r["owner"],
            "display_name" => $dn,
            "external_id" => (string) ($r["external_id"] ?? ""),
            "members" => $membersByGroupLower[strtolower($dn)] ?? [],
            "created_at" => (string) $r["created_at"],
            "updated_at" => (string) (($r["updated_at"] ?? "") ?: $r["created_at"]),
        ];
    }
    return $out;
}

function directory_get_group_by_id(
    string $storePath,
    string $owner,
    string $groupId
): ?array {
    directory_sync_groups_from_users($storePath, $owner);
    $pdo = storage_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM idp_groups WHERE id = :id AND owner = :owner LIMIT 1"
    );
    $stmt->execute([":id" => $groupId, ":owner" => $owner]);
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$r) {
        return null;
    }
    $dn = (string) $r["display_name"];
    $dnLower = strtolower($dn);
    $members = [];
    foreach (directory_list_users($storePath, $owner, false) as $u) {
        foreach ($u["groups"] ?? [] as $gn) {
            if (strtolower(trim((string) $gn)) === $dnLower) {
                $members[] = [
                    "id" => $u["id"],
                    "username" => $u["username"],
                    "display_name" => $u["display_name"],
                    "email" => $u["email"],
                ];
                break;
            }
        }
    }
    return [
        "id" => (string) $r["id"],
        "owner" => (string) $r["owner"],
        "display_name" => $dn,
        "external_id" => (string) ($r["external_id"] ?? ""),
        "members" => $members,
        "created_at" => (string) $r["created_at"],
        "updated_at" => (string) (($r["updated_at"] ?? "") ?: $r["created_at"]),
    ];
}

/**
 * Sets the members of one group to exactly $memberUserIds (ids of users of $owner; other ids
 * are ignored). With $oldDisplayName (a rename), entries under the old name are rewritten. Runs
 * in one write transaction on a fresh read.
 */
function directory_set_group_members(
    string $storePath,
    string $owner,
    string $groupDisplayName,
    array $memberUserIds,
    ?string $oldDisplayName = null
): void {
    storage_write_transaction(
        storage_db($storePath),
        function (PDO $pdo) use ($owner, $groupDisplayName, $memberUserIds, $oldDisplayName): void {
            directory_apply_group_membership($pdo, $owner, $groupDisplayName, $oldDisplayName, $memberUserIds);
        }
    );
}

/** Set of the non-empty scalar ids in $ids, as string keys. */
function directory_id_set(array $ids): array
{
    $set = [];
    foreach ($ids as $id) {
        if (is_scalar($id) && trim((string) $id) !== "") {
            $set[trim((string) $id)] = true;
        }
    }
    return $set;
}

/**
 * Rewrites one group's membership in idp_users.groups_json, inside the caller's write
 * transaction. Rows are read fresh under the lock and only rows whose membership (or spelling of
 * the group name) changes are written, so concurrent changes to other users, or to the user's
 * other groups, are never overwritten.
 *  - $memberUserIds: the exact member list, or null to keep the current members.
 *  - $addUserIds / $removeUserIds: applied on top (delta updates, such as a SCIM PATCH).
 *  - $oldDisplayName: on a rename, entries under the old name count as membership and are
 *    rewritten to the new name.
 * Returns the number of users updated.
 */
function directory_apply_group_membership(
    PDO $pdo,
    string $owner,
    string $groupDisplayName,
    ?string $oldDisplayName,
    ?array $memberUserIds,
    array $addUserIds = [],
    array $removeUserIds = []
): int {
    $newName = trim($groupDisplayName);
    if ($newName === "") {
        return 0;
    }
    $newLower = strtolower($newName);
    $oldLower = $oldDisplayName !== null ? strtolower(trim($oldDisplayName)) : $newLower;
    $exact = $memberUserIds !== null ? directory_id_set($memberUserIds) : null;
    $add = directory_id_set($addUserIds);
    $remove = directory_id_set($removeUserIds);

    $sel = $pdo->prepare("SELECT id, groups_json FROM idp_users WHERE owner = :owner");
    $sel->execute([":owner" => $owner]);
    $rows = $sel->fetchAll(PDO::FETCH_ASSOC);

    $now = gmdate("Y-m-d\TH:i:s\Z");
    $upd = $pdo->prepare(
        "UPDATE idp_users SET groups_json = :grp, updated_at = :uat WHERE id = :id AND owner = :owner"
    );
    $updated = 0;
    foreach ($rows as $row) {
        $uid = (string) $row["id"];
        $decoded = json_decode((string) ($row["groups_json"] ?? "[]"), true);
        $current = is_array($decoded) ? normalize_string_list($decoded) : [];
        $isMember = false;
        foreach ($current as $g) {
            $gl = strtolower($g);
            if ($gl === $newLower || $gl === $oldLower) {
                $isMember = true;
                break;
            }
        }
        $shouldBeMember = $exact !== null ? isset($exact[$uid]) : $isMember;
        if (isset($add[$uid])) {
            $shouldBeMember = true;
        }
        if (isset($remove[$uid])) {
            $shouldBeMember = false;
        }
        if (!$isMember && !$shouldBeMember) {
            continue;
        }
        // The group keeps its place in the user's list; a new membership goes at the end.
        $next = [];
        $placed = false;
        foreach ($current as $g) {
            $gl = strtolower($g);
            if ($gl === $newLower || $gl === $oldLower) {
                if ($shouldBeMember && !$placed) {
                    $next[] = $newName;
                    $placed = true;
                }
                continue;
            }
            $next[] = $g;
        }
        if ($shouldBeMember && !$placed) {
            $next[] = $newName;
        }
        $next = normalize_string_list($next);
        if ($next === $current) {
            continue;
        }
        $upd->execute([
            ":grp" => directory_encode_json($next, "groups"),
            ":uat" => $now,
            ":id" => $uid,
            ":owner" => $owner,
        ]);
        $updated++;
    }
    return $updated;
}

/**
 * Replaces a group name (matched case-insensitively, like access checks) in the name-based
 * group references of every provider of $owner: assigned_groups_json of OIDC clients, SAML apps
 * and SCIM connectors, and filter_groups_json of SCIM tokens. Runs in the caller's write
 * transaction. Returns the number of rows changed.
 */
function directory_rewrite_group_references(
    PDO $pdo,
    string $owner,
    string $oldName,
    string $replacement
): int {
    $oldLower = strtolower(trim($oldName));
    $replacement = trim($replacement);
    if ($oldLower === "" || $replacement === "") {
        return 0;
    }
    $targets = [
        "oidc_clients" => "assigned_groups_json",
        "saml_apps" => "assigned_groups_json",
        "scim_connectors" => "assigned_groups_json",
        "scim_tokens" => "filter_groups_json",
    ];
    $changed = 0;
    foreach ($targets as $table => $column) {
        $sel = $pdo->prepare(
            "SELECT id, " . $column . " AS refs FROM " . $table .
                " WHERE provider_id IN (SELECT id FROM providers WHERE owner = :owner)"
        );
        $sel->execute([":owner" => $owner]);
        $rows = $sel->fetchAll(PDO::FETCH_ASSOC);
        $upd = $pdo->prepare("UPDATE " . $table . " SET " . $column . " = :refs WHERE id = :id");
        foreach ($rows as $row) {
            $names = json_decode((string) ($row["refs"] ?? "[]"), true);
            if (!is_array($names)) {
                continue;
            }
            $next = [];
            $seen = [];
            $hit = false;
            foreach ($names as $name) {
                if (!is_scalar($name) || trim((string) $name) === "") {
                    continue;
                }
                $name = trim((string) $name);
                if (strtolower($name) === $oldLower) {
                    $name = $replacement;
                    $hit = true;
                }
                $key = strtolower($name);
                if (!isset($seen[$key])) {
                    $seen[$key] = true;
                    $next[] = $name;
                }
            }
            if (!$hit) {
                continue;
            }
            $upd->execute([
                ":refs" => directory_encode_json($next, "group list"),
                ":id" => (string) $row["id"],
            ]);
            $changed++;
        }
    }
    return $changed;
}

function directory_create_group(
    string $storePath,
    string $owner,
    string $displayName,
    string $externalId = "",
    array $memberUserIds = [],
    bool $skipAutoSync = false
): array {
    $dn = trim($displayName);
    if ($dn === "") {
        throw new InvalidArgumentException("Group displayName is required");
    }
    directory_assert_group_name_allowed($dn);
    $id = uuidv4();
    $now = gmdate("Y-m-d\TH:i:s\Z");
    // Check, insert and membership in one write transaction.
    storage_write_transaction(
        storage_db($storePath),
        function (PDO $pdo) use ($owner, $dn, $externalId, $memberUserIds, $id, $now): void {
            // A name that users already carry is an existing group.
            $missing = directory_missing_group_names($pdo, $owner);
            if (!empty($missing)) {
                directory_insert_missing_groups($pdo, $owner, $missing);
            }
            $dup = $pdo->prepare(
                "SELECT id FROM idp_groups WHERE owner = :owner AND LOWER(display_name) = LOWER(:dn) LIMIT 1"
            );
            $dup->execute([":owner" => $owner, ":dn" => $dn]);
            $exists = $dup->fetchColumn() !== false;
            $dup->closeCursor();
            if ($exists) {
                throw new RuntimeException("A group with this displayName already exists");
            }
            $pdo->prepare(
                "INSERT INTO idp_groups (id, owner, display_name, external_id, created_at, updated_at) " .
                    "VALUES (:id, :owner, :dn, :ext, :cat, :uat)"
            )->execute([
                ":id" => $id,
                ":owner" => $owner,
                ":dn" => $dn,
                ":ext" => trim($externalId),
                ":cat" => $now,
                ":uat" => $now,
            ]);
            if (!empty($memberUserIds)) {
                directory_apply_group_membership($pdo, $owner, $dn, null, $memberUserIds);
            }
        }
    );

    if (!$skipAutoSync && function_exists("scim_trigger_auto_sync_for_owner")) {
        scim_trigger_auto_sync_for_owner($storePath, $owner);
    }

    return directory_get_group_by_id($storePath, $owner, $id) ?? [];
}

/**
 * Updates a group in one write transaction on fresh data. A null $displayName or $externalId
 * keeps the stored value; a null $memberUserIds keeps the members, otherwise it is the new
 * member list. Pass $baseMemberUserIds (the member ids that $memberUserIds was computed from,
 * such as the group read before applying a SCIM PATCH) to apply only the difference, so
 * concurrent membership changes are merged instead of overwritten. A rename also rewrites the
 * owner's app assignments and SCIM token filters that name the group. A caller that patches a
 * copy it read earlier should pass null for the name and externalId unless it changes them, so
 * a concurrent rename is not undone.
 *
 * $precondition, when given, is called inside the transaction, before anything is written,
 * with the stored group as directory_get_group_by_id() returns it. Returning false aborts the
 * update with DirectoryPreconditionFailed (a SCIM If-Match check, for example).
 */
function directory_update_group(
    string $storePath,
    string $owner,
    string $groupId,
    ?string $displayName,
    ?string $externalId,
    ?array $memberUserIds,
    bool $skipAutoSync = false,
    ?array $baseMemberUserIds = null,
    ?Closure $precondition = null
): array {
    $requestedDn = $displayName !== null ? trim($displayName) : null;
    storage_write_transaction(
        storage_db($storePath),
        function (PDO $pdo) use (
            $storePath,
            $owner,
            $groupId,
            $requestedDn,
            $externalId,
            $memberUserIds,
            $baseMemberUserIds,
            $precondition
        ): void {
            $missing = directory_missing_group_names($pdo, $owner);
            if (!empty($missing)) {
                directory_insert_missing_groups($pdo, $owner, $missing);
            }
            $sel = $pdo->prepare(
                "SELECT display_name, external_id FROM idp_groups WHERE id = :id AND owner = :owner LIMIT 1"
            );
            $sel->execute([":id" => $groupId, ":owner" => $owner]);
            $group = $sel->fetch(PDO::FETCH_ASSOC);
            $sel->closeCursor();
            if (!$group) {
                throw new RuntimeException("Group not found");
            }
            if ($precondition !== null) {
                $fresh = directory_get_group_by_id($storePath, $owner, $groupId);
                if ($fresh === null) {
                    throw new RuntimeException("Group not found");
                }
                directory_check_precondition($precondition, $fresh);
            }
            if ($requestedDn === "") {
                throw new InvalidArgumentException("Group displayName cannot be empty");
            }
            $oldDn = (string) $group["display_name"];
            $newDn = $requestedDn ?? $oldDn;
            $newExt = $externalId !== null ? trim($externalId) : (string) ($group["external_id"] ?? "");
            $renamed = $newDn !== $oldDn;
            if ($renamed) {
                directory_assert_group_name_allowed($newDn);
                $dup = $pdo->prepare(
                    "SELECT id FROM idp_groups WHERE owner = :owner AND id != :id AND LOWER(display_name) = LOWER(:dn) LIMIT 1"
                );
                $dup->execute([":owner" => $owner, ":id" => $groupId, ":dn" => $newDn]);
                $taken = $dup->fetchColumn() !== false;
                $dup->closeCursor();
                if ($taken) {
                    throw new RuntimeException("Another group already uses this displayName");
                }
            }
            $pdo->prepare(
                "UPDATE idp_groups SET display_name = :dn, external_id = :ext, updated_at = :uat " .
                    "WHERE id = :id AND owner = :owner"
            )->execute([
                ":dn" => $newDn,
                ":ext" => $newExt,
                ":uat" => gmdate("Y-m-d\TH:i:s\Z"),
                ":id" => $groupId,
                ":owner" => $owner,
            ]);

            if ($memberUserIds !== null && $baseMemberUserIds !== null) {
                $target = directory_id_set($memberUserIds);
                $base = directory_id_set($baseMemberUserIds);
                directory_apply_group_membership(
                    $pdo,
                    $owner,
                    $newDn,
                    $oldDn,
                    null,
                    array_keys(array_diff_key($target, $base)),
                    array_keys(array_diff_key($base, $target))
                );
            } elseif ($memberUserIds !== null) {
                directory_apply_group_membership($pdo, $owner, $newDn, $oldDn, $memberUserIds);
            } elseif ($renamed) {
                directory_apply_group_membership($pdo, $owner, $newDn, $oldDn, null);
            }
            if ($renamed) {
                // Apps and tokens follow the group, and a later group created under the old
                // name does not inherit them.
                directory_rewrite_group_references($pdo, $owner, $oldDn, $newDn);
            }
        }
    );

    if (!$skipAutoSync && function_exists("scim_trigger_auto_sync_for_owner")) {
        scim_trigger_auto_sync_for_owner($storePath, $owner);
    }

    return directory_get_group_by_id($storePath, $owner, $groupId) ?? [];
}

/**
 * Deletes a group: removes it from its members and replaces its name in the owner's app
 * assignments and SCIM token filters with "__deleted_group__:<group id>", all in one write
 * transaction. Removing the name instead could leave an empty list, which means "everyone".
 * $precondition, when given, is called in the transaction with the stored group
 * (directory_get_group_by_id()) before anything is written; returning false aborts the delete
 * with DirectoryPreconditionFailed.
 */
function directory_delete_group(
    string $storePath,
    string $owner,
    string $groupId,
    bool $skipAutoSync = false,
    ?Closure $precondition = null
): bool {
    $deleted = (bool) storage_write_transaction(
        storage_db($storePath),
        function (PDO $pdo) use ($storePath, $owner, $groupId, $precondition): bool {
            $sel = $pdo->prepare(
                "SELECT display_name FROM idp_groups WHERE id = :id AND owner = :owner LIMIT 1"
            );
            $sel->execute([":id" => $groupId, ":owner" => $owner]);
            $name = $sel->fetchColumn();
            $sel->closeCursor();
            if ($name === false || $name === null) {
                return false;
            }
            if ($precondition !== null) {
                $fresh = directory_get_group_by_id($storePath, $owner, $groupId);
                if ($fresh === null) {
                    return false;
                }
                directory_check_precondition($precondition, $fresh);
            }
            $name = (string) $name;
            directory_apply_group_membership($pdo, $owner, $name, null, []);
            directory_rewrite_group_references(
                $pdo,
                $owner,
                $name,
                directory_deleted_group_prefix() . $groupId
            );
            $del = $pdo->prepare("DELETE FROM idp_groups WHERE id = :id AND owner = :owner");
            $del->execute([":id" => $groupId, ":owner" => $owner]);
            return $del->rowCount() > 0;
        }
    );
    if ($deleted && !$skipAutoSync && function_exists("scim_trigger_auto_sync_for_owner")) {
        scim_trigger_auto_sync_for_owner($storePath, $owner);
    }
    return $deleted;
}
