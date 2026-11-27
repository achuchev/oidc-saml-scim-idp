<?php
declare(strict_types=1);

// Errors are never shown to clients, whatever php.ini says, from the first statement on
// (S15-09). Details go to the error log only, and exception traces carry no argument
// values. Uncaught exceptions get a generic 500 (bootstrap_exception_handler), and an
// error log that php.ini places inside the web root is moved out of it.
ini_set("display_errors", "0");
ini_set("display_startup_errors", "0");
ini_set("html_errors", "0");
ini_set("zend.exception_ignore_args", "1");
error_reporting(E_ALL);
set_exception_handler("bootstrap_exception_handler");
bootstrap_guard_error_log();

/**
 * Returns the first environment variable in $names that is set and not blank, trimmed
 * (a stray space or newline in a path must not change the path), or null.
 */
function env_string(array $names): ?string
{
    foreach ($names as $name) {
        $value = getenv($name);
        if (is_string($value) && trim($value) !== "") {
            return trim($value);
        }
    }
    return null;
}

// ============================================================================
// Shared security helpers (foundation)
//
// Pure additions used by every lane. Other files call these functions, so keep
// their names, parameter order and types stable and add only optional trailing
// parameters. They are unconditional top-level functions: PHP binds them when
// this file is compiled, so they can be called from any line of bootstrap,
// including the startup statements at the top of this file.
//
//   Configuration: local_config, config_value, config_flag, config_list
//   Text:          utf8_truncate, sanitize_label
//   Credentials:   dummy_password_hash, machine_secret_hash,
//                  machine_secret_verify, secret_preview_mask
//   Network:       ip_is_public_unicast, client_ip_bucket, rate_limit_bucket
//   Validation:    validate_endpoint_url, parse_duration_seconds,
//                  effective_auth_policy, sri_integrity_ok
//   Schema:        schema_ensure
// ============================================================================

// ---------- Configuration and compatibility flags ----------
// Precedence: environment variable > config.php > secure default. Keys are
// snake_case and the environment variable is "OIDC_" . strtoupper($key), plus
// any legacy aliases. Read settings where they are used: do not cache them in
// globals or constants, and do not read getenv() or $LOCAL_CONFIG directly for
// these keys. config.example.php documents every key.

/**
 * Returns the array returned by the git-ignored <root>/config.php, or [] when the
 * file is missing, unreadable, does not return an array or fails to load. The file
 * is required once per request (static cache). Never echoes, exits or throws: any
 * output the file produces is discarded and load errors are logged.
 *
 * $loadError (optional) is set on every call, also when the result comes from the
 * cache, to why an existing config.php was ignored: "unreadable" (the PHP process
 * cannot read it), "exception" (loading it threw, for example a syntax error) or
 * "not_array" (it did not return an array). It is null when the file loaded or does
 * not exist. The IP allowlist reads it (src/ip_allowlist.php), so that a config.php
 * that sets ip_allowlist but stops loading refuses every request instead of turning
 * the check off.
 */
function local_config(?string &$loadError = null): array
{
    static $config = null;
    static $error = null;
    if (is_array($config)) {
        $loadError = $error;
        return $config;
    }
    // Set before loading, so a config.php that calls back into these helpers gets [].
    $config = [];
    $file = dirname(__DIR__) . DIRECTORY_SEPARATOR . "config.php";
    if (!is_file($file)) {
        $loadError = $error;
        return $config;
    }
    if (!is_readable($file)) {
        $error = "unreadable";
        error_log("config.php ignored: it is not readable by the PHP process");
        $loadError = $error;
        return $config;
    }
    // Require the file in its own scope, so variables it assigns cannot clobber this
    // function's state. It only sees $ROOT_DIR: config.php used to be included at
    // global scope right after $ROOT_DIR was set.
    $load = static function (string $configFile): mixed {
        $ROOT_DIR = dirname($configFile);
        return require $configFile;
    };
    $obLevel = ob_get_level();
    ob_start();
    try {
        $loaded = $load($file);
        if (is_array($loaded)) {
            $config = $loaded;
        } else {
            // Also a file without a return statement (require gives 1) or "return 1;".
            $error = "not_array";
            error_log("config.php ignored: it must return an array (return [ ... ];)");
        }
    } catch (Throwable $e) {
        $error = "exception";
        // Class and line only: a parse error message can quote configuration values.
        error_log(sprintf(
            "config.php ignored: %s on line %d (check it with php -l)",
            get_class($e),
            $e->getLine()
        ));
    } finally {
        // Also drops buffers the file left open; stop if one cannot be removed.
        while (ob_get_level() > $obLevel) {
            if (!ob_end_clean()) {
                break;
            }
        }
    }
    $loadError = $error;
    return $config;
}

/**
 * Reads one setting. The first environment variable in $envNames with a non-blank
 * value wins and is returned trimmed (always a string); blank variables count as
 * unset. Otherwise a non-null config.php value for $key is returned (strings
 * trimmed, so possibly "", other types as stored). Otherwise $default.
 */
function config_value(string $key, string|array $envNames = [], mixed $default = null): mixed
{
    foreach ((array) $envNames as $name) {
        if (!is_string($name) || $name === "") {
            continue;
        }
        $v = getenv($name);
        if (is_string($v) && trim($v) !== "") {
            return trim($v);
        }
    }
    $config = local_config();
    if (array_key_exists($key, $config) && $config[$key] !== null) {
        return is_string($config[$key]) ? trim($config[$key]) : $config[$key];
    }
    return $default;
}

/**
 * Reads a boolean flag through config_value(). Unset gives $default. A bool is
 * returned as is, a number is true when non-zero, and a string is true only for
 * "1", "true", "on" or "yes" (case-insensitive). Every other value ("0", "false",
 * "off", "no", unknown words, arrays) is false, so OIDC_X=0 overrides a config.php
 * true and a value that does not parse never enables a legacy behavior.
 */
function config_flag(string $key, string|array $envNames, bool $default = false): bool
{
    $v = config_value($key, $envNames, null);
    if ($v === null) {
        return $default;
    }
    if (is_bool($v)) {
        return $v;
    }
    if (is_int($v) || is_float($v)) {
        return $v != 0;
    }
    if (is_string($v)) {
        return in_array(strtolower(trim($v)), ["1", "true", "on", "yes"], true);
    }
    return false;
}

/**
 * Reads a list setting through config_value(). Unset gives $default. A string is
 * split on commas and whitespace; an array contributes its scalar elements cast to
 * string. Entries are trimmed, empty entries dropped and duplicates removed (first
 * occurrence kept). Returns a list of strings; callers validate the entries.
 */
function config_list(string $key, string|array $envNames, array $default = []): array
{
    $v = config_value($key, $envNames, null);
    if ($v === null) {
        return $default;
    }
    $items = [];
    if (is_string($v)) {
        $split = preg_split('/[\s,]+/', $v);
        $items = is_array($split) ? $split : [];
    } elseif (is_array($v)) {
        foreach ($v as $item) {
            if (is_scalar($item)) {
                $items[] = (string) $item;
            }
        }
    } elseif (is_scalar($v)) {
        $items[] = (string) $v;
    }
    $out = [];
    foreach ($items as $item) {
        $item = trim($item);
        if ($item !== "" && !in_array($item, $out, true)) {
            $out[] = $item;
        }
    }
    return $out;
}

// ---------- Text helpers ----------

/**
 * Returns valid UTF-8 holding at most $maxChars code points of $s ($maxChars is
 * clamped to 0..65535). Invalid byte sequences are replaced with U+FFFD first;
 * nothing else changes. Never throws and needs no mbstring. (mb_scrub() is not
 * used: its substitute character is an ini setting that defaults to "?".)
 */
function utf8_truncate(string $s, int $maxChars): string
{
    $maxChars = max(0, min(65535, $maxChars));
    if ($maxChars === 0 || $s === "") {
        return "";
    }
    // Every output code point consumes 1 to 4 input bytes and the decoder looks at
    // most 3 bytes ahead, so cutting the input at 4 * $maxChars bytes cannot change
    // the first $maxChars code points. This bounds the work for huge inputs.
    if (strlen($s) > 4 * $maxChars) {
        $s = substr($s, 0, 4 * $maxChars);
    }
    if (preg_match('//u', $s) !== 1) {
        $s = htmlspecialchars_decode(
            htmlspecialchars($s, ENT_NOQUOTES | ENT_SUBSTITUTE, "UTF-8"),
            ENT_NOQUOTES
        );
    }
    return preg_match('/^.{0,' . $maxChars . '}/su', $s, $m) === 1 ? $m[0] : "";
}

/**
 * Cleans text for display labels and log/audit fields: invalid UTF-8 becomes
 * U+FFFD; control characters (C0, DEL, C1) and the invisible bidi/format marks
 * U+061C, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069 and U+FEFF are removed;
 * every whitespace run (tabs and line breaks included) becomes one space; the
 * result is trimmed and cut to $maxChars code points. Returns "" when nothing is
 * left; callers apply their own default.
 */
function sanitize_label(string $s, int $maxChars): string
{
    if (preg_match('//u', $s) !== 1) {
        $s = htmlspecialchars_decode(
            htmlspecialchars($s, ENT_NOQUOTES | ENT_SUBSTITUTE, "UTF-8"),
            ENT_NOQUOTES
        );
    }
    // Whitespace controls (U+0009-U+000D, U+0085) are kept for the next step, so a
    // line break separates two words instead of joining them.
    $s = preg_replace(
        '/[\x{0000}-\x{0008}\x{000E}-\x{001F}\x{007F}-\x{0084}\x{0086}-\x{009F}\x{061C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]+/u',
        "",
        $s
    );
    if (!is_string($s)) {
        return "";
    }
    // Unicode White_Space characters.
    $s = preg_replace(
        '/[\x{0009}-\x{000D}\x{0020}\x{0085}\x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]+/u',
        " ",
        $s
    );
    if (!is_string($s)) {
        return "";
    }
    return rtrim(utf8_truncate(trim($s), $maxChars));
}

// ---------- Credential helpers ----------

/**
 * Bcrypt digest used only to equalize timing on unknown-user and no-password
 * branches: password_verify($input, dummy_password_hash()). Its cost matches
 * PASSWORD_DEFAULT (12 on PHP 8.4). When the bcrypt default cost differs (10 before
 * PHP 8.4), the same digest is built with that cost: checking it costs as much as
 * checking a real one, and building it costs nothing. Hashing a dummy instead would add
 * a full password_hash() to the first unknown-user check of every request, about twice
 * the time of a real check, which tells which usernames exist. Only a default that is
 * not bcrypt gets a generated digest (once per request).
 */
function dummy_password_hash(): string
{
    static $hash = null;
    if ($hash === null) {
        $hash = '$2y$12$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG';
        if (password_needs_rehash($hash, PASSWORD_DEFAULT)) {
            $hash = PASSWORD_DEFAULT === PASSWORD_BCRYPT
                ? sprintf(
                    '$2y$%02d$',
                    defined("PASSWORD_BCRYPT_DEFAULT_COST") ? PASSWORD_BCRYPT_DEFAULT_COST : 10
                ) . 'usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG'
                : password_hash(base64url_encode(random_bytes(18)), PASSWORD_DEFAULT);
        }
    }
    return $hash;
}

/**
 * Fast digest ("s256$" + 64 lowercase hex chars) for server-generated or
 * high-entropy (>= 32 characters) machine credentials: the full idp_scim_ or
 * idp_sagt_ token, admin API client secrets and OIDC client secrets. Hash exactly
 * the string that used to go to password_hash(). Never use it for human passwords.
 */
function machine_secret_hash(string $secret): string
{
    return 's256$' . hash("sha256", $secret);
}

/**
 * Verifies a machine credential: "s256$" digests with hash_equals(), legacy
 * password_hash() digests with password_verify(); any other format fails. When a
 * legacy digest verifies and the secret has at least 32 characters, $upgradedHash
 * receives machine_secret_hash($secret); persist it best-effort with
 * UPDATE ... SET col = :new WHERE id = :id AND col = :old. Look the row up by its
 * public id (client_id, token_id) first and run no dummy hash for unknown ids.
 */
function machine_secret_verify(string $secret, string $storedHash, ?string &$upgradedHash = null): bool
{
    $upgradedHash = null;
    if ($secret === "" || strlen($secret) > 4096 || $storedHash === "") {
        return false;
    }
    if (str_starts_with($storedHash, 's256$')) {
        return hash_equals($storedHash, machine_secret_hash($secret));
    }
    $info = password_get_info($storedHash);
    if (empty($info["algo"])) {
        return false;
    }
    $ok = password_verify($secret, $storedHash);
    if ($ok && strlen($secret) >= 32) {
        $upgradedHash = machine_secret_hash($secret);
    }
    return $ok;
}

/**
 * Preview that cannot be used to recover an admin-supplied or third-party secret:
 * the mask alone when the secret is shorter than 32 bytes, otherwise the mask plus
 * its last 4 characters (only when those are printable ASCII, so the preview stays
 * valid UTF-8). Never derive a preview from the start of a secret. For
 * server-generated secrets callers may prepend the non-secret prefix, for example
 * "sec_" . secret_preview_mask($secret).
 */
function secret_preview_mask(string $secret): string
{
    $mask = "••••••••";
    if (strlen($secret) < 32) {
        return $mask;
    }
    $tail = substr($secret, -4);
    return preg_match('/^[\x21-\x7E]{4}$/D', $tail) === 1 ? $mask . $tail : $mask;
}

// ---------- Network helpers ----------

/**
 * True only for a globally routable unicast IP literal (brackets around IPv6 are
 * accepted). Pure function, no DNS; invalid input returns false.
 * IPv4 must pass filter_var() with the private, reserved and global-range flags and
 * must not be in 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24,
 * 192.0.2/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4 or 240/4
 * (which includes 255.255.255.255).
 * IPv6 must be in 2000::/3, the only block allocated for global unicast, which
 * excludes ::/96 (:: and ::1), 100::/64, 64:ff9b:1::/48, fc00::/7, fe80::/10,
 * fec0::/10 and ff00::/8; it must also not be in 2001::/23 (Teredo 2001::/32 and
 * the other IETF protocol assignments), 2001:db8::/32 or 3fff::/20 (documentation).
 * IPv4-mapped (::ffff:0:0/96), NAT64 (64:ff9b::/96) and 6to4 (2002::/16) addresses
 * are judged by their embedded IPv4 address.
 */
function ip_is_public_unicast(string $ip): bool
{
    if (strlen($ip) > 2 && $ip[0] === "[" && $ip[strlen($ip) - 1] === "]") {
        $ip = substr($ip, 1, -1);
    }
    if ($ip === "" || filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return false;
    }
    $bin = inet_pton($ip);
    if (!is_string($bin)) {
        return false;
    }
    // Is the packed address $addr inside $network/$bits (same address family)?
    $inNet = static function (string $addr, string $network, int $bits): bool {
        $net = (string) inet_pton($network);
        if (strlen($net) !== strlen($addr)) {
            return false;
        }
        $whole = intdiv($bits, 8);
        if (substr($addr, 0, $whole) !== substr($net, 0, $whole)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;
        return (ord($addr[$whole]) & $mask) === (ord($net[$whole]) & $mask);
    };
    $v4IsPublic = static function (string $b4) use ($inNet): bool {
        $text = inet_ntop($b4);
        if (
            !is_string($text) ||
            filter_var(
                $text,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4 |
                    FILTER_FLAG_NO_PRIV_RANGE |
                    FILTER_FLAG_NO_RES_RANGE |
                    FILTER_FLAG_GLOBAL_RANGE
            ) === false
        ) {
            return false;
        }
        $blocked = [
            ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
            ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
            ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
            ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
        ];
        foreach ($blocked as [$network, $bits]) {
            if ($inNet($b4, $network, $bits)) {
                return false;
            }
        }
        return true;
    };
    if (strlen($bin) === 4) {
        return $v4IsPublic($bin);
    }
    if (strlen($bin) !== 16) {
        return false;
    }
    if ($inNet($bin, "::ffff:0:0", 96) || $inNet($bin, "64:ff9b::", 96)) {
        return $v4IsPublic(substr($bin, 12, 4));
    }
    if ($inNet($bin, "2002::", 16)) {
        return $v4IsPublic(substr($bin, 2, 4));
    }
    if (!$inNet($bin, "2000::", 3)) {
        return false;
    }
    foreach ([["2001::", 23], ["2001:db8::", 32], ["3fff::", 20]] as [$network, $bits]) {
        if ($inNet($bin, $network, $bits)) {
            return false;
        }
    }
    return true;
}

/**
 * Rate-limit identity for a client IP (default: client_ip_address()). IPv4,
 * including IPv4-mapped IPv6, gives "v4:a.b.c.d"; other IPv6 gives "v6:" plus the
 * hex of its first 8 bytes (the /64); invalid input gives "ip:unknown". Use it for
 * every per-IP throttle; keep client_ip_address() for logging and last_used_ip.
 */
function client_ip_bucket(?string $ip = null): string
{
    $ip = trim($ip ?? client_ip_address());
    if (strlen($ip) > 2 && $ip[0] === "[" && $ip[strlen($ip) - 1] === "]") {
        $ip = substr($ip, 1, -1);
    }
    if ($ip === "" || filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return "ip:unknown";
    }
    $bin = inet_pton($ip);
    if (is_string($bin) && strlen($bin) === 4) {
        return "v4:" . (string) inet_ntop($bin);
    }
    if (is_string($bin) && strlen($bin) === 16) {
        if (substr($bin, 0, 12) === str_repeat("\x00", 10) . "\xff\xff") {
            return "v4:" . (string) inet_ntop(substr($bin, 12, 4));
        }
        return "v6:" . bin2hex(substr($bin, 0, 8));
    }
    return "ip:unknown";
}

/**
 * Builds an unambiguous auth_rate_limits key of bounded size (at most 81 bytes):
 * $purpose . ":" . the first 40 hex chars of sha256(JSON list of $parts).
 * $purpose must match /^[a-z0-9_]{1,40}$/, otherwise InvalidArgumentException.
 * Parts (strings; cast ids first) are typically the provider id, the client_id,
 * token id or normalized identifier, and client_ip_bucket(). Raw usernames never
 * appear in keys.
 */
function rate_limit_bucket(string $purpose, string ...$parts): string
{
    if (preg_match('/^[a-z0-9_]{1,40}$/D', $purpose) !== 1) {
        throw new InvalidArgumentException("Invalid rate-limit bucket purpose");
    }
    $json = json_encode(
        array_values($parts),
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE
    );
    return $purpose . ":" . substr(hash("sha256", (string) $json), 0, 40);
}

// ---------- Validation and policy helpers ----------

/**
 * Strict validator for URLs that receive bearer artifacts (SAML ACS, ACS endpoint
 * and SLO URLs; OIDC redirect, post-logout and initiate-login URIs), used at save
 * time and again at request time. Applies validate_safe_url(), then rejects any
 * '#' fragment or backslash, and rejects plain http:// unless the host is
 * localhost, in 127.0.0.0/8 or ::1 or the allow_insecure_http_endpoints flag is on.
 * Returns the trimmed URL; throws InvalidArgumentException.
 */
function validate_endpoint_url(
    string $url,
    bool $allowCustomAppScheme = false,
    string $fieldLabel = "URL"
): string {
    $u = validate_safe_url($url, $allowCustomAppScheme, $fieldLabel);
    if (str_contains($u, "#")) {
        throw new InvalidArgumentException("$fieldLabel must not contain a fragment");
    }
    // Browsers read "\" as "/", but parse_url() does not: "http://evil.example\@localhost/"
    // has the host "localhost" for PHP and "evil.example" for a browser. A backslash is
    // never valid in a URI.
    if (str_contains($u, "\\")) {
        throw new InvalidArgumentException("$fieldLabel must not contain a backslash");
    }
    if (
        strtolower((string) parse_url($u, PHP_URL_SCHEME)) === "http" &&
        !config_flag("allow_insecure_http_endpoints", "OIDC_ALLOW_INSECURE_HTTP_ENDPOINTS")
    ) {
        $host = strtolower(trim((string) parse_url($u, PHP_URL_HOST), "[]"));
        $bin = filter_var($host, FILTER_VALIDATE_IP) !== false ? inet_pton($host) : false;
        $isLoopback =
            $host === "localhost" ||
            (is_string($bin) && strlen($bin) === 4 && $bin[0] === "\x7f") ||
            (is_string($bin) && $bin === inet_pton("::1"));
        if (!$isLoopback) {
            throw new InvalidArgumentException(
                "$fieldLabel must use https:// (plain http:// is only allowed for localhost, 127.0.0.0/8 and [::1])"
            );
        }
    }
    return $u;
}

/**
 * Strict parser for user-supplied durations; null means invalid (callers answer
 * 400 and list the accepted formats). An int >= 0 or a digits-only string is a
 * number of seconds. Otherwise the trimmed, case-insensitive string must be one or
 * more "<integer><unit>" groups, optionally separated by spaces, for example
 * "90min", "1w", "2h30m" or "1 day". Units: s, sec, secs, second, seconds, m, min,
 * mins, minute, minutes, h, hr, hrs, hour, hours, d, day, days, w, week, weeks.
 * Rejected: "", negatives, decimals, other types, unknown units, strings longer
 * than 128 bytes, and results above $maxSeconds. There is no clamp and no fallback.
 */
function parse_duration_seconds(mixed $spec, int $maxSeconds = 31536000): ?int
{
    if ($maxSeconds < 0) {
        return null;
    }
    if (is_int($spec)) {
        return $spec >= 0 && $spec <= $maxSeconds ? $spec : null;
    }
    if (!is_string($spec)) {
        return null;
    }
    $s = strtolower(trim($spec));
    if ($s === "" || strlen($s) > 128) {
        return null;
    }
    $groups = [];
    if (preg_match('/^\d+$/D', $s) === 1) {
        $groups[] = [$s, "s"];
    } elseif (
        preg_match('/^(?:\d+ *[a-z]+ *)+$/D', $s) === 1 &&
        preg_match_all('/(\d+) *([a-z]+)/', $s, $matches, PREG_SET_ORDER) > 0
    ) {
        foreach ($matches as $match) {
            $groups[] = [$match[1], $match[2]];
        }
    } else {
        return null;
    }
    $units = [
        "s" => 1, "sec" => 1, "secs" => 1, "second" => 1, "seconds" => 1,
        "m" => 60, "min" => 60, "mins" => 60, "minute" => 60, "minutes" => 60,
        "h" => 3600, "hr" => 3600, "hrs" => 3600, "hour" => 3600, "hours" => 3600,
        "d" => 86400, "day" => 86400, "days" => 86400,
        "w" => 604800, "week" => 604800, "weeks" => 604800,
    ];
    $total = 0;
    foreach ($groups as [$digits, $unit]) {
        if (!isset($units[$unit])) {
            return null;
        }
        $digits = ltrim($digits, "0");
        if (strlen($digits) > 18) {
            return null;
        }
        $n = (int) ($digits === "" ? "0" : $digits);
        // Keeps $total <= $maxSeconds, which also rules out integer overflow.
        if ($n > intdiv($maxSeconds - $total, $units[$unit])) {
            return null;
        }
        $total += $n * $units[$unit];
    }
    return $total;
}

/**
 * Single resolver for the sign-on policy of a provider and an optional target app
 * or client. A missing, empty or "inherit" target policy (or no target) uses the
 * provider's default_auth_policy ("flexible" when absent). A result outside
 * flexible, touchid_only and mfa becomes "mfa" (fail closed). A valid $minimum that
 * is stricter (flexible < touchid_only < mfa) wins. Pure function.
 */
function effective_auth_policy(array $provider, ?array $target = null, ?string $minimum = null): string
{
    $rank = ["flexible" => 0, "touchid_only" => 1, "mfa" => 2];
    // null is "not set"; any other non-scalar value is invalid and fails closed below.
    $normalize = static function (mixed $v): string {
        if ($v === null) {
            return "";
        }
        return is_scalar($v) ? strtolower(trim((string) $v)) : "invalid";
    };
    $policy = $target === null ? "" : $normalize($target["auth_policy"] ?? null);
    if ($policy === "" || $policy === "inherit") {
        $policy = $normalize($provider["default_auth_policy"] ?? "flexible");
    }
    if (!isset($rank[$policy])) {
        $policy = "mfa";
    }
    if ($minimum !== null) {
        $min = strtolower(trim($minimum));
        if (isset($rank[$min]) && $rank[$min] > $rank[$policy]) {
            return $min;
        }
    }
    return $policy;
}

/**
 * True for a well-formed Subresource Integrity value: one or more whitespace-separated
 * sha256/sha384/sha512 hashes in base64 or base64url, each optionally followed by "?options"
 * (S14-05). A browser loads a file unchecked when the attribute holds no hash it can use, so
 * callers treat anything else as missing and do not load the file. Shared by the admin
 * console and /api/docs. Pure function.
 */
function sri_integrity_ok(string $integrity): bool
{
    $hash = 'sha(?:256|384|512)-[A-Za-z0-9+\/_-]+={0,2}(?:\?\S*)?';
    return preg_match('/^\s*' . $hash . '(?:\s+' . $hash . ')*\s*$/D', $integrity) === 1;
}

// ---------- Schema migrations ----------

/**
 * Run-once, additive schema/data migration for lanes that do not own db.php.
 * Applied ids are kept in schema_migrations(id, applied_at) and cached per PDO for
 * the request. If $migrationId is not applied yet: throws LogicException when
 * called inside a transaction, then runs BEGIN IMMEDIATE, re-checks the id and runs
 * $steps in order. A string step is one SQL statement passed to exec(); a
 * PDOException mentioning "duplicate column name" or "already exists" is ignored.
 * A callable step is invoked as $step($pdo) inside the same transaction (it must
 * not begin or commit). Any other failure rolls back, is logged and is rethrown.
 * Finally the id is recorded and the transaction committed.
 * Ids look like "<lane>.<topic>_vN" and are never reused. Steps must be additive.
 */
function schema_ensure(PDO $pdo, string $migrationId, array $steps): void
{
    static $appliedByPdo = null;
    if ($appliedByPdo === null) {
        // Keyed by the PDO object itself, so a later connection never inherits ids.
        $appliedByPdo = new WeakMap();
    }
    $known = isset($appliedByPdo[$pdo]) ? $appliedByPdo[$pdo] : [];
    if (isset($known[$migrationId])) {
        return;
    }
    if ($migrationId === "") {
        throw new InvalidArgumentException("schema_ensure() needs a migration id");
    }
    $isApplied = static function () use ($pdo, $migrationId): bool {
        try {
            $st = $pdo->prepare("SELECT 1 FROM schema_migrations WHERE id = :id");
            $st->execute([":id" => $migrationId]);
            $found = $st->fetchColumn() !== false;
            $st->closeCursor();
            return $found;
        } catch (PDOException $e) {
            if (str_contains(strtolower($e->getMessage()), "no such table")) {
                return false;
            }
            throw $e;
        }
    };
    $previousErrMode = $pdo->getAttribute(PDO::ATTR_ERRMODE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    try {
        if (!$isApplied()) {
            if ($pdo->inTransaction()) {
                throw new LogicException(
                    "schema_ensure($migrationId) must be called outside a transaction"
                );
            }
            try {
                $pdo->exec("BEGIN IMMEDIATE");
            } catch (PDOException $e) {
                if (str_contains(strtolower($e->getMessage()), "within a transaction")) {
                    throw new LogicException(
                        "schema_ensure($migrationId) must be called outside a transaction",
                        0,
                        $e
                    );
                }
                throw $e;
            }
            try {
                $pdo->exec(
                    "CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
                );
                if (!$isApplied()) {
                    foreach ($steps as $index => $step) {
                        if (is_string($step)) {
                            try {
                                $pdo->exec($step);
                            } catch (PDOException $e) {
                                $msg = strtolower($e->getMessage());
                                if (
                                    !str_contains($msg, "duplicate column name") &&
                                    !str_contains($msg, "already exists")
                                ) {
                                    throw $e;
                                }
                            }
                        } elseif (is_callable($step)) {
                            $step($pdo);
                        } else {
                            throw new InvalidArgumentException(
                                "schema_ensure($migrationId): step $index is neither SQL nor callable"
                            );
                        }
                    }
                    $ins = $pdo->prepare(
                        "INSERT INTO schema_migrations (id, applied_at) VALUES (:id, :at)"
                    );
                    $ins->execute([
                        ":id" => $migrationId,
                        ":at" => gmdate("Y-m-d\TH:i:s\Z"),
                    ]);
                }
                $pdo->exec("COMMIT");
            } catch (Throwable $e) {
                try {
                    $pdo->exec("ROLLBACK");
                } catch (Throwable $rollbackError) {
                    // The original error is the one worth reporting.
                }
                error_log(
                    "schema_ensure($migrationId) failed and was rolled back: " . $e->getMessage()
                );
                throw $e;
            }
        }
    } finally {
        $pdo->setAttribute(PDO::ATTR_ERRMODE, $previousErrMode);
    }
    $known[$migrationId] = true;
    $appliedByPdo[$pdo] = $known;
}

// ============================================================================
// End of shared security helpers
// ============================================================================

// ============================================================================
// Core: startup guards, data paths, request target, proxies and sessions
// ============================================================================

/**
 * Last-resort handler for uncaught exceptions (registered on the first lines of this
 * file). The class, message, location and trace (without argument values) go to the
 * error log only; the client gets a generic 500 without details.
 */
function bootstrap_exception_handler(Throwable $e): void
{
    error_log(sprintf(
        "Uncaught %s: %s in %s:%d\nStack trace:\n%s",
        get_class($e),
        $e->getMessage(),
        $e->getFile(),
        $e->getLine(),
        $e->getTraceAsString()
    ));
    if (PHP_SAPI === "cli" || headers_sent()) {
        return;
    }
    while (ob_get_level() > 0 && @ob_end_clean()) {
        // Drop partial output so the error page is not appended to half a document.
    }
    http_response_code(500);
    send_security_headers(false);
    header("Content-Type: text/plain; charset=utf-8");
    header("Cache-Control: no-store");
    echo "Internal Server Error\n";
}

/**
 * Sends a short text/plain response and ends the request. Used before routing, for
 * requests that are refused outright (400, 403, 421, 500); never creates a session.
 */
function bootstrap_plain_response(int $code, string $text): never
{
    http_response_code($code);
    if (!headers_sent()) {
        send_security_headers(false);
        header("Content-Type: text/plain; charset=utf-8");
        header("Cache-Control: no-store");
    }
    echo $text . "\n";
    exit();
}

/**
 * Answers a request that Apache's ErrorDocument (htaccess.example, section 0) sent to index.php
 * with the original error status, before it is routed: such a request arrives as a GET of the
 * original URL (REDIRECT_STATUS 4xx/5xx), so routing it would run a different request than the
 * client sent. Runs after the IP allowlist check, which answers refused addresses itself.
 * REDIRECT_STATUS is set by the server, never from a request header; 200 is a normal rewrite.
 */
function bootstrap_error_document_passthrough(): void
{
    $status = $_SERVER["REDIRECT_STATUS"] ?? null;
    if (PHP_SAPI === "cli" || !is_string($status) || preg_match('/^[45]\d\d$/D', $status) !== 1) {
        return;
    }
    $code = (int) $status;
    bootstrap_plain_response(
        $code,
        [403 => "Forbidden", 404 => "Not found", 413 => "Request body too large"][$code] ?? "Request refused"
    );
}

/**
 * Stops the request because the deployment is misconfigured: the reason (which may name
 * paths) goes to the error log, or to stderr with exit code 1 in the CLI. The client gets
 * a 500 with only the generic $publicHint, never paths or values.
 */
function bootstrap_fail_closed(string $reason, string $publicHint = ""): never
{
    $message = "IdP refused to start: " . $reason;
    if (PHP_SAPI === "cli") {
        if (defined("STDERR")) {
            fwrite(STDERR, $message . PHP_EOL);
        }
        exit(1);
    }
    error_log($message);
    bootstrap_plain_response(
        500,
        "Server configuration error." . ($publicHint !== "" ? " " . $publicHint : "") .
            " Details are in the server error log."
    );
}

/**
 * Canonical absolute form of $path for containment checks, using "/" separators. A
 * relative path is taken relative to the current working directory (as PHP resolves
 * it). The deepest existing ancestor is resolved with realpath(), so symlinks count;
 * the missing rest is normalized lexically. Works for paths that do not exist yet.
 */
function bootstrap_canonical_path(string $path): string
{
    $path = str_replace("\\", "/", trim($path));
    $isAbsolute = $path !== "" && ($path[0] === "/" || preg_match('#^[A-Za-z]:/#', $path) === 1);
    if (!$isAbsolute) {
        $cwd = getcwd();
        $path = (is_string($cwd) ? str_replace("\\", "/", $cwd) : "") . "/" . $path;
    }
    $drive = "";
    if (preg_match('#^([A-Za-z]:)(/.*)$#', $path, $m) === 1) {
        $drive = $m[1];
        $path = $m[2];
    }
    $real = @realpath($drive . $path);
    if (is_string($real)) {
        $real = rtrim(str_replace("\\", "/", $real), "/");
        return $real === "" ? "/" : $real;
    }
    $segments = [];
    foreach (explode("/", $path) as $segment) {
        if ($segment === "" || $segment === ".") {
            continue;
        }
        if ($segment === "..") {
            array_pop($segments);
            continue;
        }
        $segments[] = $segment;
    }
    for ($n = count($segments); $n >= 0; $n--) {
        $real = @realpath($drive . "/" . implode("/", array_slice($segments, 0, $n)));
        if (!is_string($real)) {
            continue;
        }
        $parts = array_merge(
            [rtrim(str_replace("\\", "/", $real), "/")],
            array_slice($segments, $n)
        );
        $joined = implode("/", $parts);
        return $joined === "" ? "/" : $joined;
    }
    return $drive . "/" . implode("/", $segments);
}

/**
 * Is the canonical path $path equal to, or inside, the canonical directory $base?
 */
function bootstrap_path_within(string $path, string $base): bool
{
    if (PHP_OS_FAMILY === "Windows") {
        $path = strtolower($path);
        $base = strtolower($base);
    }
    $base = rtrim($base, "/");
    return $base === "" || $path === $base || str_starts_with($path, $base . "/");
}

/**
 * Canonical directories the web server may serve files from: the project folder and
 * $_SERVER["DOCUMENT_ROOT"] (which contains it in a subdirectory install).
 */
function bootstrap_web_roots(): array
{
    static $roots = null;
    if ($roots === null) {
        $roots = [bootstrap_canonical_path(dirname(__DIR__))];
        $docRoot = $_SERVER["DOCUMENT_ROOT"] ?? "";
        if (is_string($docRoot) && trim($docRoot) !== "") {
            $roots[] = bootstrap_canonical_path($docRoot);
        }
        $roots = array_values(array_unique($roots));
    }
    return $roots;
}

/**
 * Does $path (existing or not) resolve inside the project folder or the document root?
 */
function bootstrap_path_in_webroot(string $path): bool
{
    $canonical = bootstrap_canonical_path($path);
    foreach (bootstrap_web_roots() as $webRoot) {
        if (bootstrap_path_within($canonical, $webRoot)) {
            return true;
        }
    }
    return false;
}

/**
 * Keeps PHP's own error log out of the web root (S15-09). php.ini's error_log may be a
 * relative name (the shipped cPanel ini used "error_log"), which PHP resolves against the
 * script directory, so the log could be downloaded. First call (no argument, before the
 * data directory is known): such a log falls back to the server's own log. Second call:
 * it moves to <data dir>/php-error.log. An empty error_log (the server log), syslog and
 * paths outside the web root are left alone.
 */
function bootstrap_guard_error_log(?string $configDir = null): void
{
    static $moved = false;
    if ($configDir === null) {
        $current = trim((string) ini_get("error_log"));
        if ($current !== "" && strtolower($current) !== "syslog" && bootstrap_path_in_webroot($current)) {
            @ini_set("error_log", "");
            $moved = true;
        }
        return;
    }
    if ($moved) {
        @ini_set("error_log", path_join($configDir, "php-error.log"));
    }
}

/**
 * Writes a deny-all .htaccess (the same rules as src/.htaccess) into a data or session
 * directory, unless one exists. Never into a directory that contains the web root:
 * Apache applies .htaccess files to every subdirectory, so that would take the site down.
 */
function bootstrap_write_deny_htaccess(string $dir): void
{
    $file = rtrim($dir, "/\\") . DIRECTORY_SEPARATOR . ".htaccess";
    if (file_exists($file) || !is_dir($dir) || !is_writable($dir)) {
        return;
    }
    $canonical = bootstrap_canonical_path($dir);
    foreach (bootstrap_web_roots() as $webRoot) {
        if (bootstrap_path_within($webRoot, $canonical)) {
            return;
        }
    }
    @file_put_contents(
        $file,
        "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n" .
            "<IfModule !mod_authz_core.c>\n  Order allow,deny\n  Deny from all\n</IfModule>\n",
        LOCK_EX
    );
}

/**
 * Creates $dir with mode 0700 when it is missing and adds the deny-all .htaccess.
 * Returns whether the directory now exists and is writable.
 */
function bootstrap_ensure_private_dir(string $dir): bool
{
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    if (!is_dir($dir) || !is_writable($dir)) {
        return false;
    }
    bootstrap_write_deny_htaccess($dir);
    return true;
}

/**
 * Checks and prepares a data directory candidate. Returns null when it is usable,
 * otherwise why not. The web-root check runs before anything is created, so a refused
 * candidate normally never leaves an empty directory inside the web root. It runs again
 * once the directory exists, when realpath() resolves the whole path exactly as the file
 * system does (a missing path is normalized lexically, which a symlink followed by ".."
 * can defeat).
 */
function bootstrap_prepare_data_dir(string $dir, bool $allowWebroot): ?string
{
    $inWebroot = "is inside the web root (the project folder or DOCUMENT_ROOT)";
    if (!$allowWebroot && bootstrap_path_in_webroot($dir)) {
        return $inWebroot;
    }
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    if (!is_dir($dir)) {
        return "does not exist and cannot be created";
    }
    if (!$allowWebroot && bootstrap_path_in_webroot($dir)) {
        return $inWebroot;
    }
    if (!is_writable($dir)) {
        return "is not writable by the PHP process";
    }
    bootstrap_write_deny_htaccess($dir);
    return null;
}

/**
 * With allow_webroot_data_dir off, data that older versions kept in the project folder
 * (.data/, keys/, users.txt, providers.sqlite, api_keys.sqlite, scim_master.key) is no
 * longer used, yet stays downloadable unless the web server denies it. Adds the deny-all
 * .htaccess to such legacy directories and logs what was found, at most once an hour (the
 * mtime of a marker file in the data directory), so an operator whose install starts
 * without its old users or database learns why.
 */
function bootstrap_warn_legacy_webroot_data(string $rootDir, string $configDir): void
{
    $found = [];
    foreach ([".data", "keys"] as $name) {
        $dir = path_join($rootDir, $name);
        if (is_dir($dir)) {
            bootstrap_write_deny_htaccess($dir);
            $found[] = $name . "/";
        }
    }
    foreach (["users.txt", "providers.sqlite", "api_keys.sqlite", "scim_master.key"] as $name) {
        if (file_exists(path_join($rootDir, $name))) {
            $found[] = $name;
        }
    }
    if ($found === []) {
        return;
    }
    $marker = path_join($configDir, "legacy-webroot-data.warned");
    $last = @filemtime($marker);
    if (is_int($last) && $last > time() - 3600) {
        return;
    }
    @touch($marker);
    error_log(
        "IdP: legacy data found in the web root " . $rootDir . " and ignored: " . implode(", ", $found) .
            ". It may be downloadable: move it to the data directory " . $configDir .
            " (keep scim_master.key next to providers.sqlite, it decrypts stored secrets) and delete" .
            " it from the web root, or set OIDC_ALLOW_WEBROOT_DATA_DIR (allow_webroot_data_dir in" .
            " config.php) to keep using it there for now."
    );
}

/**
 * Resolves the data paths (S15-01). The data directory is OIDC_CONFIG_DIR / CONFIG_DIR,
 * else config.php "config_dir", else the sibling "<project folder>_config"; it is
 * created with mode 0700 when missing and gets a deny-all .htaccess. The request stops
 * (bootstrap_fail_closed) when that directory cannot be created, is not writable or is
 * inside the web root, and when an explicit OIDC_USERS_FILE, OIDC_STORAGE_FILE,
 * OIDC_KEYS_DIR or OIDC_APIKEYS_FILE path is inside the web root. There is no fallback
 * and no lookup in the project folder, unless allow_webroot_data_dir is on: it restores
 * the fallback to <project folder>/.data, the project-folder users.txt,
 * providers.sqlite, keys/ and api_keys.sqlite, and data paths inside the web root.
 * Without it, leftovers of that layout are logged (bootstrap_warn_legacy_webroot_data()).
 *
 * @return array{config_dir: string, users_file: string, providers_file: string, keys_dir: string, apikeys_file: string}
 */
function bootstrap_resolve_data_paths(string $rootDir): array
{
    $legacy = config_flag("allow_webroot_data_dir", "OIDC_ALLOW_WEBROOT_DATA_DIR");
    $hint = "Set OIDC_CONFIG_DIR (or config_dir in config.php) to a writable directory outside the web root.";

    $configured = config_value("config_dir", ["OIDC_CONFIG_DIR", "CONFIG_DIR"]);
    $configDir = is_string($configured) && $configured !== ""
        ? $configured
        : path_join(dirname($rootDir), basename($rootDir) . "_config");
    $problem = bootstrap_prepare_data_dir($configDir, $legacy);
    if ($problem !== null && $legacy) {
        $fallback = path_join($rootDir, ".data");
        if (bootstrap_prepare_data_dir($fallback, true) === null) {
            $configDir = $fallback;
            $problem = null;
        }
    }
    if ($problem !== null) {
        bootstrap_fail_closed("the data directory " . $configDir . " " . $problem . ". " . $hint, $hint);
    }
    $configDir = bootstrap_canonical_path($configDir);

    $refuse = static function (string $name, string $value): never {
        bootstrap_fail_closed(
            $name . " (" . $value . ") is inside the web root; data files must live outside it.",
            "Move " . $name . " outside the web root."
        );
    };

    $usersEnv = env_string(["OIDC_USERS_FILE", "USERS_FILE"]);
    $usersFile = $usersEnv ?? path_join($configDir, "users.txt");
    if ($legacy) {
        $rootUsers = path_join($rootDir, "users.txt");
        if (!is_readable($usersFile) && is_readable($rootUsers)) {
            $usersFile = $rootUsers;
        }
    } elseif ($usersEnv !== null && bootstrap_path_in_webroot($usersEnv)) {
        $refuse("OIDC_USERS_FILE", $usersEnv);
    }

    $storageEnv = env_string(["OIDC_STORAGE_FILE", "PROVIDERS_FILE"]);
    $providersFile = $storageEnv ?? path_join($configDir, "providers.sqlite");
    if ($legacy) {
        $rootProviders = path_join($rootDir, "providers.sqlite");
        if (!is_file($providersFile) && is_file($rootProviders)) {
            $providersFile = $rootProviders;
        }
    } elseif ($storageEnv !== null && bootstrap_path_in_webroot($storageEnv)) {
        $refuse("OIDC_STORAGE_FILE", $storageEnv);
    }
    $providersDir = dirname($providersFile);
    if (!is_dir($providersDir) && @mkdir($providersDir, 0700, true)) {
        bootstrap_write_deny_htaccess($providersDir);
    }

    $keysEnv = env_string(["OIDC_KEYS_DIR", "KEYS_DIR"]);
    $keysDir = $keysEnv ?? path_join($configDir, "keys");
    if ($legacy) {
        $rootKeys = path_join($rootDir, "keys");
        if (!is_dir($keysDir) && is_dir($rootKeys)) {
            $keysDir = $rootKeys;
            bootstrap_write_deny_htaccess($rootKeys);
        }
    } elseif ($keysEnv !== null && bootstrap_path_in_webroot($keysEnv)) {
        $refuse("OIDC_KEYS_DIR", $keysEnv);
    }

    $apiKeysFile = env_string(["OIDC_APIKEYS_FILE", "APIKEYS_FILE"]) ?? $providersFile;
    if ($apiKeysFile !== $providersFile) {
        if ($legacy) {
            $rootApiKeys = path_join($rootDir, "api_keys.sqlite");
            if (!is_file($apiKeysFile) && is_file($rootApiKeys)) {
                $apiKeysFile = $rootApiKeys;
            }
        } elseif (bootstrap_path_in_webroot($apiKeysFile)) {
            $refuse("OIDC_APIKEYS_FILE", $apiKeysFile);
        }
        $apiDir = dirname($apiKeysFile);
        if (!is_dir($apiDir) && @mkdir($apiDir, 0700, true)) {
            bootstrap_write_deny_htaccess($apiDir);
        }
    }

    if (!$legacy) {
        bootstrap_warn_legacy_webroot_data($rootDir, $configDir);
    }

    return [
        "config_dir" => $configDir,
        "users_file" => $usersFile,
        "providers_file" => $providersFile,
        "keys_dir" => $keysDir,
        "apikeys_file" => $apiKeysFile,
    ];
}

/**
 * Private session directory <data dir>/sessions (0700, deny-all .htaccess) for the
 * "files" session handler, so session files (named after the session IDs) are not
 * listed in a shared /tmp (X3-19). Returns null, keeping php.ini's save_path, for other
 * handlers (their save_path is not a directory) or when the directory is unusable.
 */
function bootstrap_session_save_dir(string $configDir): ?string
{
    if (strtolower(trim((string) ini_get("session.save_handler"))) !== "files") {
        return null;
    }
    $dir = path_join($configDir, "sessions");
    // The files handler reads "N;MODE;/path", so a ';' in the path would be misparsed.
    if (str_contains($dir, ";") || !bootstrap_ensure_private_dir($dir)) {
        error_log("IdP: cannot use " . $dir . " for sessions; keeping session.save_path from php.ini");
        return null;
    }
    if ((int) ini_get("session.gc_probability") <= 0) {
        // Distributions that leave session cleanup to a cron job only clean their own
        // directory, so let PHP collect expired files here.
        @ini_set("session.gc_probability", "1");
    }
    return $dir;
}

/**
 * The file in which the "files" session handler keeps session $id, or null for other
 * handlers. $saveDir is bootstrap's private session directory; null means php.ini's
 * session.save_path ("[N;[MODE;]]/path": N directory levels named after the first
 * characters of the id; an empty path is the system temporary directory).
 */
function bootstrap_session_file(string $id, ?string $saveDir): ?string
{
    if (strtolower(trim((string) ini_get("session.save_handler"))) !== "files") {
        return null;
    }
    $path = $saveDir ?? (string) ini_get("session.save_path");
    $depth = 0;
    if (str_contains($path, ";")) {
        $parts = explode(";", $path);
        $path = (string) array_pop($parts);
        $depth = max(0, (int) $parts[0]);
    }
    if (trim($path) === "") {
        $path = sys_get_temp_dir();
    }
    $dir = rtrim($path, "/\\");
    for ($i = 0; $i < $depth && $i < strlen($id); $i++) {
        $dir .= DIRECTORY_SEPARATOR . $id[$i];
    }
    return $dir . DIRECTORY_SEPARATOR . "sess_" . $id;
}

/**
 * May the session named by the request's cookie ($id, already syntax-checked) be resumed?
 * With the "files" handler only when its file exists and was used within
 * session.gc_maxlifetime (G1c-06, G2a-04). PHP would otherwise create a file and send a new
 * cookie for every unknown id a client makes up, and it reads an expired file however old it
 * is, until garbage collection happens to delete it. Other handlers are left to
 * session.use_strict_mode.
 */
function bootstrap_session_resumable(string $id, ?string $saveDir): bool
{
    $file = bootstrap_session_file($id, $saveDir);
    if ($file === null) {
        return true;
    }
    // PHP touches the file whenever a request closes the session, so its mtime is the last use.
    $mtime = @filemtime($file);
    if (!is_int($mtime)) {
        return false;
    }
    $maxLifetime = (int) ini_get("session.gc_maxlifetime");
    return $maxLifetime <= 0 || $mtime >= time() - $maxLifetime;
}

/**
 * Is $path (the path inside the install) a route that never uses the PHP session: OIDC
 * discovery and JWKS, the token and userinfo endpoints, SCIM, the on-prem agent relay, SAML
 * metadata and certificates, and the public OpenAPI document? Bootstrap does not open the
 * session there even when the cookie is sent (G1c-06), so these requests take no session lock
 * and cannot be queued behind one.
 */
function bootstrap_route_is_stateless(string $path): bool
{
    return $path === "/openapi.json" ||
        preg_match(
            '#^/(?!api/)[^/]+/(?:\.well-known/.+|jwks|oauth2/(?:token|userinfo|introspect|revoke)|scim/v2(?:/.*)?|scim/agent/(?:poll|result)|saml/(?:metadata(?:\.xml)?|cert\.(?:pem|cer)))$#i',
            $path
        ) === 1;
}

/**
 * Path part of the request target (S15-10), or null when the target is malformed (the
 * caller answers 400). Origin-form targets are split at '?' (and '#'); absolute-form
 * targets go through parse_url() and must yield a string. Runs of slashes collapse to
 * one, so "//x/api/me" is not parsed as a host name and "//.data/x" cannot slip past the
 * sensitive-path check.
 */
function bootstrap_request_path(string $target): ?string
{
    if ($target === "") {
        return "/";
    }
    if (preg_match('#^[A-Za-z][A-Za-z0-9+.-]*://#', $target) === 1) {
        $parsed = parse_url($target, PHP_URL_PATH);
        if ($parsed === null) {
            return "/";
        }
        if (!is_string($parsed)) {
            return null;
        }
        $path = $parsed;
    } else {
        $path = explode("#", explode("?", $target, 2)[0], 2)[0];
    }
    if ($path === "" || $path[0] !== "/") {
        return null;
    }
    $collapsed = preg_replace('#/{2,}#', "/", $path);
    return is_string($collapsed) ? $collapsed : null;
}

/**
 * Is $path one that must never be served: source, data, keys, VCS and server-config
 * files, databases, keys, logs and similar? $path is the path inside the install (the
 * subdirectory prefix stripped), the one the router matches; the rules are applied to it
 * raw and percent-decoded. The public SAML certificate route /{idpId}/saml/cert.pem is
 * exempt from the file-extension rules (never from the directory rules). The exemption is
 * decided once, on the raw path as the router sees it, so an idp ID that holds an encoded
 * character such as %2F keeps its route. The PHP router never serves files, so this is
 * defense in depth for requests that reach PHP; the web server's own rules must deny
 * these paths for static requests.
 */
function bootstrap_is_sensitive_path(string $path): bool
{
    $publicCertRoute = preg_match('#^/[^/]+/saml/cert\.pem$#i', $path) === 1;
    $decoded = preg_replace('#/{2,}#', "/", rawurldecode($path));
    foreach (array_unique([$path, is_string($decoded) ? $decoded : $path]) as $candidate) {
        if (
            preg_match(
                '#^/(src|\.data|keys|samples|onprem-scim-agent|\.git|\.svn|\.ht[^/]*|\.env[^/]*|\.user\.ini)(/|$)#i',
                $candidate
            ) === 1 ||
            preg_match('#(^|/)error_log$#i', $candidate) === 1
        ) {
            return true;
        }
        if (
            !$publicCertRoute &&
            preg_match(
                '#\.(sqlite3?|db)(-wal|-shm|-journal)?$|\.(wal|shm|ini|fcgi|pem|key|md|txt|log)$#i',
                $candidate
            ) === 1
        ) {
            return true;
        }
    }
    return false;
}

/**
 * Packed form of an IP literal (brackets allowed) for CIDR checks; IPv4-mapped IPv6
 * addresses become their 4-byte IPv4 form. Null when $ip is not an IP address.
 */
function bootstrap_ip_bytes(string $ip): ?string
{
    $ip = trim($ip);
    if (strlen($ip) > 2 && $ip[0] === "[" && str_ends_with($ip, "]")) {
        $ip = substr($ip, 1, -1);
    }
    if ($ip === "" || filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return null;
    }
    $bin = inet_pton($ip);
    if (!is_string($bin)) {
        return null;
    }
    if (strlen($bin) === 16 && str_starts_with($bin, str_repeat("\x00", 10) . "\xff\xff")) {
        return substr($bin, 12);
    }
    return $bin;
}

/**
 * Is $ip inside one of $cidrs (IPv4 or IPv6 addresses or CIDR blocks)? Invalid entries
 * are ignored. IPv4 addresses match IPv4 entries also when written as IPv4-mapped IPv6.
 */
function bootstrap_ip_in_cidrs(string $ip, array $cidrs): bool
{
    $addr = bootstrap_ip_bytes($ip);
    if ($addr === null) {
        return false;
    }
    foreach ($cidrs as $entry) {
        if (!is_scalar($entry)) {
            continue;
        }
        $network = trim((string) $entry);
        $bits = null;
        $slash = strpos($network, "/");
        if ($slash !== false) {
            $length = substr($network, $slash + 1);
            if (preg_match('/^\d{1,3}$/D', $length) !== 1) {
                continue;
            }
            $bits = (int) $length;
            $network = substr($network, 0, $slash);
        }
        $net = bootstrap_ip_bytes($network);
        if ($net === null || strlen($net) !== strlen($addr)) {
            continue;
        }
        $maxBits = strlen($net) * 8;
        if ($bits === null) {
            $bits = $maxBits;
        } elseif (strlen($net) === 4 && str_contains($network, ":")) {
            $bits -= 96; // an IPv4-mapped block such as ::ffff:10.0.0.0/104
        }
        if ($bits < 0 || $bits > $maxBits) {
            continue;
        }
        $whole = intdiv($bits, 8);
        if (substr($addr, 0, $whole) !== substr($net, 0, $whole)) {
            continue;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;
        if ((ord($addr[$whole]) & $mask) === (ord($net[$whole]) & $mask)) {
            return true;
        }
    }
    return false;
}

/**
 * Is the direct peer (REMOTE_ADDR) listed in trusted_proxies (OIDC_TRUSTED_PROXIES)?
 */
function bootstrap_peer_is_trusted_proxy(): bool
{
    $remote = (string) ($_SERVER["REMOTE_ADDR"] ?? "");
    if (trim($remote) === "") {
        return false;
    }
    $trusted = config_list("trusted_proxies", "OIDC_TRUSTED_PROXIES");
    return $trusted !== [] && bootstrap_ip_in_cidrs($remote, $trusted);
}

/**
 * Is the direct peer a loopback address (a reverse proxy on the same host)?
 */
function bootstrap_peer_is_loopback(): bool
{
    return bootstrap_ip_in_cidrs((string) ($_SERVER["REMOTE_ADDR"] ?? ""), ["127.0.0.0/8", "::1"]);
}

/**
 * May the direct peer tell us the original scheme (X-Forwarded-Proto)? Yes for peers in
 * trusted_proxies, for loopback peers and, with trust_proxy (OIDC_TRUST_PROXY), for any
 * peer. X-Forwarded-For is a separate, stricter decision: see client_ip_address().
 */
function bootstrap_peer_trusted_for_proto(): bool
{
    return config_flag("trust_proxy", "OIDC_TRUST_PROXY") ||
        bootstrap_peer_is_loopback() ||
        bootstrap_peer_is_trusted_proxy();
}

/**
 * One X-Forwarded-For entry as a normalized IP address, or null when it is not one.
 * Accepts "[v6]", "[v6]:port" and "v4:port", which some proxies send.
 */
function bootstrap_forwarded_hop_ip(string $hop): ?string
{
    $hop = trim($hop);
    if ($hop === "" || strlen($hop) > 64) {
        return null;
    }
    if (preg_match('/^\[([0-9A-Fa-f:.]+)\](?::\d{1,5})?$/D', $hop, $m) === 1) {
        $hop = $m[1];
    } elseif (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/D', $hop, $m) === 1) {
        $hop = $m[1];
    }
    if (filter_var($hop, FILTER_VALIDATE_IP) === false) {
        return null;
    }
    $bin = inet_pton($hop);
    $text = is_string($bin) ? inet_ntop($bin) : false;
    return is_string($text) ? $text : null;
}

/**
 * Is $host (the Host header without its port) allowed as the base URL host when
 * public_base_url is not set? localhost, 127.0.0.1 and ::1 always are. Entries of
 * $allowedHosts are exact host names or IP addresses (ports are ignored), "*.suffix"
 * for the subdomains of suffix (not suffix itself), or "*" for any host (the legacy
 * behavior). Comparison is case-insensitive.
 */
function bootstrap_host_allowed(string $host, array $allowedHosts): bool
{
    $normalize = static function (string $h): string {
        $h = rtrim(strtolower(trim($h)), ".");
        if (strlen($h) > 2 && $h[0] === "[" && str_ends_with($h, "]")) {
            $h = substr($h, 1, -1);
        }
        if (filter_var($h, FILTER_VALIDATE_IP) !== false) {
            $bin = inet_pton($h);
            $text = is_string($bin) ? inet_ntop($bin) : false;
            return is_string($text) ? $text : $h;
        }
        return $h;
    };
    $host = $normalize($host);
    if ($host === "") {
        return false;
    }
    if (in_array($host, ["localhost", "127.0.0.1", "::1"], true)) {
        return true;
    }
    foreach ($allowedHosts as $entry) {
        if (!is_scalar($entry)) {
            continue;
        }
        $entry = strtolower(trim((string) $entry));
        if ($entry === "*") {
            return true;
        }
        if (preg_match('/^\[([^\]]+)\](?::\d+)?$/D', $entry, $m) === 1) {
            $entry = $m[1];
        } elseif (preg_match('/^([^:]+):\d+$/D', $entry, $m) === 1) {
            $entry = $m[1];
        }
        if (str_starts_with($entry, "*.")) {
            $suffix = rtrim(substr($entry, 1), ".");
            if (strlen($suffix) > 1 && strlen($host) > strlen($suffix) && str_ends_with($host, $suffix)) {
                return true;
            }
            continue;
        }
        $entry = $normalize($entry);
        if ($entry !== "" && $host === $entry) {
            return true;
        }
    }
    return false;
}

/**
 * Should responses carry HSTS? Only when the effective scheme is https (also behind a
 * TLS-offloading proxy with an https public_base_url) and the host is a real name, not
 * localhost or an IP literal, where HSTS would pin every port of a development host.
 */
function bootstrap_hsts_applies(): bool
{
    $scheme = $GLOBALS["scheme"] ?? null;
    $host = $GLOBALS["rpId"] ?? null;
    if ($scheme !== "https" || !is_string($host)) {
        return false;
    }
    $host = strtolower(trim($host, "[] \t"));
    if ($host === "" || $host === "localhost" || str_ends_with($host, ".localhost")) {
        return false;
    }
    return filter_var($host, FILTER_VALIDATE_IP) === false;
}

/**
 * Does the request show that TLS ended at a proxy in front of PHP: X-Forwarded-Proto (any
 * hop), X-Forwarded-Scheme, X-Url-Scheme or CloudFront-Forwarded-Proto "https",
 * X-Forwarded-Ssl or Front-End-Https "on", a Forwarded header with proto=https, or the
 * server's REQUEST_SCHEME "https"? Read from any peer: it only keeps the HTTPS redirect from
 * looping behind a proxy that is not declared in trusted_proxies, and never makes a request
 * count as HTTPS.
 */
function bootstrap_request_has_tls_hint(): bool
{
    $header = static fn(string $name): string => is_string($_SERVER[$name] ?? null)
        ? strtolower(trim($_SERVER[$name]))
        : "";
    foreach (explode(",", $header("HTTP_X_FORWARDED_PROTO")) as $proto) {
        if (trim($proto) === "https") {
            return true;
        }
    }
    foreach (["HTTP_X_FORWARDED_SCHEME", "HTTP_X_URL_SCHEME", "HTTP_CLOUDFRONT_FORWARDED_PROTO", "REQUEST_SCHEME"] as $name) {
        if ($header($name) === "https") {
            return true;
        }
    }
    foreach (["HTTP_X_FORWARDED_SSL", "HTTP_FRONT_END_HTTPS"] as $name) {
        if ($header($name) === "on") {
            return true;
        }
    }
    return preg_match('/(?:^|[;,\s])proto\s*=\s*"?https"?\s*(?:[;,]|$)/', $header("HTTP_FORWARDED")) === 1;
}

/**
 * Ends a plain-HTTP request that should have used HTTPS (S13-07): GET and HEAD get a 301 to
 * $target (the same path on the https public base URL) plus the original query string; any
 * other method gets a 403, so credentials and tokens sent over HTTP are not processed and no
 * session is created for them. Never cached, so changing public_base_url takes effect at once.
 */
function bootstrap_https_redirect(string $target, string $method): never
{
    if (!in_array($method, ["GET", "HEAD"], true)) {
        bootstrap_plain_response(
            403,
            "HTTPS required: this identity provider accepts this request only over HTTPS." .
                " Send it to " . $target . " instead."
        );
    }
    $query = $_SERVER["QUERY_STRING"] ?? "";
    if (is_string($query) && $query !== "") {
        $target .= "?" . $query;
    }
    http_response_code(301);
    if (!headers_sent()) {
        send_security_headers(false);
        header("Location: " . $target);
        header("Content-Type: text/plain; charset=utf-8");
        header("Cache-Control: no-store");
    }
    echo "Moved to HTTPS\n";
    exit();
}

function send_security_headers(bool $isHtml = false): void
{
    if (headers_sent()) {
        return;
    }
    header("X-Content-Type-Options: nosniff");
    // same-origin, not no-referrer: under no-referrer browsers send "Origin: null" on
    // same-origin form POSTs (the logout forms), which the CSRF check rejects (S15-02).
    // Other sites still get no Referer.
    header("Referrer-Policy: same-origin");
    header("X-Frame-Options: DENY");
    if (bootstrap_hsts_applies()) {
        // No includeSubDomains or preload: those would bind hosts this IdP does not own.
        header("Strict-Transport-Security: max-age=31536000");
    }
    if ($isHtml) {
        header("Content-Security-Policy: frame-ancestors 'none'; base-uri 'self'; object-src 'none'");
    }
}

if (!function_exists("parse_validity_to_seconds")) {
    /**
     * Lenient duration parser for environment and config values (SIGNING_KEY_TTL and
     * similar): numbers are seconds clamped to 0..365 days; other strings use the
     * parse_duration_seconds() grammar ("90min", "1w", "2h30m", "1 day", ...) and are
     * clamped to 365 days; an empty or unparseable value gives 3600. Input typed by a
     * user must go through parse_duration_seconds() instead, which rejects what it
     * cannot parse rather than turning it into one hour (S13-11).
     */
    function parse_validity_to_seconds($spec): int
    {
        $max = 365 * 86400;
        if (is_int($spec) || is_float($spec) || (is_string($spec) && is_numeric($spec))) {
            return max(0, min($max, (int) $spec));
        }
        if (!is_string($spec)) {
            return 3600;
        }
        $normalized = preg_replace('/\s+/', " ", strtolower(trim($spec)));
        if (!is_string($normalized) || $normalized === "") {
            return 3600;
        }
        $seconds = parse_duration_seconds($normalized, PHP_INT_MAX);
        return $seconds === null ? 3600 : min($max, $seconds);
    }
}

function read_users(string $file): array
{
    if (!is_readable($file)) {
        http_response_code(500);
        send_security_headers();
        header("Content-Type: application/json; charset=utf-8");
        echo json_encode(["error" => "Admin users configuration unavailable"]);
        exit();
    }
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    return admin_users_parse_lines(is_array($lines) ? $lines : []);
}

/**
 * Parses users.txt lines ("username:password_hash"; a legacy plaintext password is accepted
 * only with the allow_plaintext_admin_passwords flag, see admin_password_verify(); blank
 * lines and "#" comments are skipped) into [username => stored value].
 */
function admin_users_parse_lines(array $lines): array
{
    $users = [];
    foreach ($lines as $line) {
        if (!is_string($line)) {
            continue;
        }
        $trimmed = trim($line);
        if ($trimmed === "" || str_starts_with($trimmed, "#")) {
            continue;
        }
        if (strpos($line, ":") === false) {
            continue;
        }
        [$u, $p] = array_map("trim", explode(":", $line, 2));
        if ($u !== "" && $p !== "") {
            $users[$u] = $p;
        }
    }
    return $users;
}

/**
 * Verifies an administrator's console password against $users (parsed users.txt). Kept for
 * callers written against bootstrap; it applies exactly the rules of admin_password_verify()
 * in src/admin_clients.php (G2a-03, G2a-07), which index.php loads before any route runs:
 * - A value that starts with "$" is always a password hash. password_verify() checks it when
 *   PHP can verify its format (admin_password_hash_format(): bcrypt $2y$/$2a$/$2b$/$2x$,
 *   argon2 when PHP has it, SHA-crypt $5$/$6$, MD5-crypt $1$); any other format, such as
 *   Apache's $apr1$, is refused with an error_log line. It is never compared as plaintext,
 *   so the text of a hash never works as the password.
 * - A plaintext value is refused unless the operator sets allow_plaintext_admin_passwords
 *   (env OIDC_ALLOW_PLAINTEXT_ADMIN_PASSWORDS), and then needs at least 12 characters; every
 *   sign-in with one logs a warning.
 * Unknown users and refused entries run a dummy_password_hash() check, so timing does not
 * reveal which usernames exist. Fails closed (false, logged) when admin_clients.php is not
 * loaded.
 */
function verify_admin_credentials(
    array $users,
    string $username,
    string $password
): bool {
    if (function_exists("admin_password_verify")) {
        return admin_password_verify($users, $username, $password);
    }
    password_verify($password, dummy_password_hash());
    error_log("IdP: admin sign-in refused: the admin password check (src/admin_clients.php) is not loaded");
    return false;
}

function load_json_file(string $file, array|object $default)
{
    $s = @file_get_contents($file);
    if ($s === false || $s === "") {
        return $default;
    }
    $j = json_decode($s, true);
    return is_array($j) ? $j : $default;
}

function save_json_file(string $file, array|object $data): void
{
    file_put_contents(
        $file,
        json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
    );
    @chmod($file, 0600);
}

function base64url_encode(string $data): string
{
    return rtrim(strtr(base64_encode($data), "+/", "-_"), "=");
}

function base64url_decode(string $data): string
{
    $b64 = strtr($data, "-_", "+/");
    $pad = strlen($b64) % 4;
    if ($pad === 1) {
        return "";
    }
    if ($pad > 0) {
        $b64 .= str_repeat("=", 4 - $pad);
    }
    $decoded = base64_decode($b64, true);
    return $decoded === false ? "" : $decoded;
}

/**
 * Encodes data safely for embedding inside HTML <script> tags without </script> or <!-- breakouts.
 */
function safe_json_for_script(mixed $data): string
{
    // Invalid UTF-8 (for example a stored label) becomes U+FFFD instead of failing the
    // whole page.
    $encoded = json_encode(
        $data,
        JSON_HEX_TAG |
            JSON_HEX_AMP |
            JSON_HEX_APOS |
            JSON_HEX_QUOT |
            JSON_UNESCAPED_UNICODE |
            JSON_INVALID_UTF8_SUBSTITUTE
    );
    if ($encoded === false) {
        error_log("safe_json_for_script(): cannot encode data: " . json_last_error_msg());
        return "{}";
    }
    return $encoded;
}

function json_response(int $code, array|object $payload): never
{
    // Encode before sending the status: invalid UTF-8 is replaced with U+FFFD, and any
    // other encoding failure is logged and answered with a 500, never with a 2xx and an
    // error body.
    $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($json === false) {
        error_log("json_response(): cannot encode the response: " . json_last_error_msg());
        $code = 500;
        $json = '{"error":"Failed to encode response"}';
    }

    http_response_code($code);
    if (!headers_sent()) {
        send_security_headers(false);
        header("Content-Type: application/json; charset=utf-8");
        header("Cache-Control: no-store, no-cache, must-revalidate");
        header("Pragma: no-cache");
    }

    echo $json;
    exit();
}

function html_response(int $code, string $html): never
{
    http_response_code($code);
    if (!headers_sent()) {
        send_security_headers(true);
        header("Content-Type: text/html; charset=utf-8");
        header("Cache-Control: no-store, no-cache, must-revalidate");
        header("Pragma: no-cache");
    }
    echo $html;
    exit();
}

function path_join(string $base, string $child): string
{
    if ($base === "") {
        $base = DIRECTORY_SEPARATOR;
    }
    $baseTrimmed = rtrim($base, DIRECTORY_SEPARATOR);
    $childTrimmed = ltrim($child, DIRECTORY_SEPARATOR);

    if ($baseTrimmed === "") {
        return DIRECTORY_SEPARATOR . $childTrimmed;
    }
    if ($childTrimmed === "") {
        return $baseTrimmed;
    }
    return $baseTrimmed . DIRECTORY_SEPARATOR . $childTrimmed;
}

function debug_enabled(string $configDir): bool
{
    $env = env_string(["OIDC_DEBUG", "DEBUG"]);
    if (is_string($env)) {
        $normalized = strtolower(trim($env));
        return in_array($normalized, ["1", "true", "on", "yes"], true);
    }
    $flagPath = path_join($configDir, "debug.enabled");
    return is_file($flagPath);
}

/**
 * Starts the PHP session if none is active (never in the CLI). Bootstrap configures the
 * cookie name, parameters and save path, but resumes a session only when the request
 * carries the cookie of an existing session and the route uses sessions (S15-08, G1c-06),
 * so call this before the first $_SESSION write. csrf_token() and admin_session_login()
 * call it.
 */
function session_ensure_started(): void
{
    if (PHP_SAPI === "cli" || session_status() !== PHP_SESSION_NONE) {
        return;
    }
    if (headers_sent($file, $line)) {
        error_log("session_ensure_started(): output already started at " . $file . ":" . $line . "; no session started");
        return;
    }
    session_start();
}

/**
 * Resumes the browser's session where bootstrap left it closed because the route normally
 * needs none (bootstrap_route_is_stateless(), G1c-06): the request carried the cookie of an
 * existing session, but its lock was not taken. current_user() and
 * csrf_session_token_matches() call this, so such a route still sees the signed-in admin and
 * the CSRF token. Never creates a session or a cookie.
 */
function session_resume_deferred(): void
{
    if (empty($GLOBALS["sessionDeferred"]) || PHP_SAPI === "cli" || session_status() !== PHP_SESSION_NONE) {
        return;
    }
    $GLOBALS["sessionDeferred"] = false;
    session_ensure_started();
}

function csrf_token(): string
{
    session_ensure_started();
    if (empty($_SESSION["csrf_token"]) || !is_string($_SESSION["csrf_token"])) {
        $_SESSION["csrf_token"] = base64url_encode(random_bytes(32));
    }
    return $_SESSION["csrf_token"];
}

/**
 * Does $provided equal the CSRF token of the current session? Never starts a new session or
 * creates a token (an existing session that bootstrap deferred is resumed): without a
 * session there is nothing a request could match, so a cross-site request without the
 * cookie is refused without receiving a new cookie.
 */
function csrf_session_token_matches(string $provided): bool
{
    if ($provided === "" || strlen($provided) > 512) {
        return false;
    }
    session_resume_deferred();
    if (PHP_SAPI !== "cli" && session_status() !== PHP_SESSION_ACTIVE) {
        return false;
    }
    $expected = $_SESSION["csrf_token"] ?? null;
    return is_string($expected) && $expected !== "" && hash_equals($expected, $provided);
}

/**
 * Protects cookie-authenticated state-changing endpoints against Cross-Site Request Forgery:
 *  1. Verifies Origin / Referer header matches $expectedOrigin when present.
 *  2. If $requireToken is true, also verifies X-CSRF-Token matches session csrf_token.
 *  3. If $acceptFormToken is true (plain HTML form POSTs: the sign-out forms), the token may
 *     come from the POST field "csrf_token" when the X-CSRF-Token header is absent. A
 *     verified same-origin Origin (or, without Origin, Referer) is then sufficient on its
 *     own, so a form whose session, and with it the token, has expired since the page was
 *     rendered still works (S15-02). So is "Origin: null" (the browser hides the origin, for
 *     example under a no-referrer setting) together with "Sec-Fetch-Site: same-origin",
 *     which pages cannot set. Any other "Origin: null" (sandboxed frames, older browsers) is
 *     accepted only together with a valid token, and without Origin and Referer the token is
 *     required when $requireToken is true.
 */
function verify_request_csrf(
    string $expectedOrigin,
    bool $requireToken = true,
    bool $acceptFormToken = false
): void {
    $provided = trim((string) ($_SERVER["HTTP_X_CSRF_TOKEN"] ?? ""));
    if ($provided === "" && $acceptFormToken && is_string($_POST["csrf_token"] ?? null)) {
        $provided = trim($_POST["csrf_token"]);
    }
    // A cross-site page cannot make a browser send this IdP's origin, so a matching Origin
    // or Referer proves the request came from one of this IdP's own pages.
    $sameOriginVerified = false;
    $reqOrigin = trim((string) ($_SERVER["HTTP_ORIGIN"] ?? ""));
    if ($reqOrigin !== "") {
        if (strcasecmp(rtrim($reqOrigin, "/"), rtrim($expectedOrigin, "/")) === 0) {
            $sameOriginVerified = true;
        } elseif (
            $acceptFormToken &&
            strtolower($reqOrigin) === "null" &&
            strtolower(trim((string) ($_SERVER["HTTP_SEC_FETCH_SITE"] ?? ""))) === "same-origin"
        ) {
            $sameOriginVerified = true;
        } elseif (
            !(
                $acceptFormToken &&
                strtolower($reqOrigin) === "null" &&
                csrf_session_token_matches($provided)
            )
        ) {
            json_response(403, ["error" => "Cross-origin request forbidden"]);
        }
    } else {
        $referer = trim((string) ($_SERVER["HTTP_REFERER"] ?? ""));
        if ($referer !== "") {
            $refScheme = (string) parse_url($referer, PHP_URL_SCHEME);
            $refHost = (string) parse_url($referer, PHP_URL_HOST);
            $refPort = parse_url($referer, PHP_URL_PORT);
            $refOrigin =
                $refScheme . "://" . $refHost . ($refPort ? ":" . $refPort : "");
            if (
                strcasecmp(rtrim($refOrigin, "/"), rtrim($expectedOrigin, "/")) !==
                0
            ) {
                json_response(403, ["error" => "Cross-origin referer forbidden"]);
            }
            $sameOriginVerified = true;
        }
    }

    if ($acceptFormToken && $sameOriginVerified) {
        return;
    }
    if ($requireToken && !csrf_session_token_matches($provided)) {
        json_response(403, [
            "error" => "Invalid or missing CSRF token; please reload page",
        ]);
    }
}

/**
 * users.txt ($USERS_FILE) parsed once per request; null when it cannot be read. Unlike
 * read_users() it never ends the request.
 */
function admin_users_cached(): ?array
{
    static $cache = [];
    $file = $GLOBALS["USERS_FILE"] ?? null;
    if (!is_string($file) || $file === "") {
        return null;
    }
    if (!array_key_exists($file, $cache)) {
        $lines = is_readable($file)
            ? @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)
            : false;
        $cache[$file] = is_array($lines) ? admin_users_parse_lines($lines) : null;
    }
    return $cache[$file];
}

/**
 * Is $username an admin in users.txt? An unreadable users.txt gives false.
 */
function admin_account_exists(string $username): bool
{
    $users = admin_users_cached();
    return $username !== "" && is_array($users) && isset($users[$username]);
}

// Console session limits (S10-04, G2a-04): a login ends 12 hours after it was made, and after
// 30 minutes without a request (or sooner when session.gc_maxlifetime is shorter, see
// bootstrap_session_resumable()). The last-activity time is written at most once a minute.
const ADMIN_SESSION_MAX_SECONDS = 43200;
const ADMIN_SESSION_IDLE_SECONDS = 1800;
const ADMIN_SESSION_TOUCH_SECONDS = 60;

/**
 * The per-admin key of console session fingerprints: 32 random bytes created on first use
 * and kept in the providers database (table admin_session_keys), never in the session.
 * $rotate replaces it, which ends every console session of that admin
 * (admin_sessions_revoke_all()); an unreadable stored key is replaced the same way. Null when
 * the database cannot be used; callers then deny access.
 */
function admin_session_key(string $username, bool $rotate = false): ?string
{
    static $cache = [];
    $store = $GLOBALS["PROVIDERS_FILE"] ?? null;
    if ($username === "" || !is_string($store) || $store === "" || !function_exists("storage_db")) {
        return null;
    }
    if (!$rotate && isset($cache[$store][$username])) {
        return $cache[$store][$username];
    }
    try {
        $pdo = storage_db($store);
        schema_ensure($pdo, "core.admin_session_keys_v1", [
            "CREATE TABLE IF NOT EXISTS admin_session_keys (" .
                "username TEXT PRIMARY KEY, secret TEXT NOT NULL, created_at TEXT NOT NULL)",
        ]);
        $params = [
            ":u" => $username,
            ":s" => bin2hex(random_bytes(32)),
            ":at" => gmdate("Y-m-d\TH:i:s\Z"),
        ];
        if ($rotate) {
            $pdo->prepare(
                "INSERT INTO admin_session_keys (username, secret, created_at) VALUES (:u, :s, :at) " .
                    "ON CONFLICT(username) DO UPDATE SET secret = excluded.secret, created_at = excluded.created_at"
            )->execute($params);
        }
        $select = $pdo->prepare("SELECT secret FROM admin_session_keys WHERE username = :u");
        $select->execute([":u" => $username]);
        $hex = $select->fetchColumn();
        $select->closeCursor();
        if ($hex === false) {
            // Concurrent first uses race on the primary key; every caller reads back the winner.
            $pdo->prepare(
                "INSERT OR IGNORE INTO admin_session_keys (username, secret, created_at) VALUES (:u, :s, :at)"
            )->execute($params);
            $select->execute([":u" => $username]);
            $hex = $select->fetchColumn();
            $select->closeCursor();
        }
    } catch (Throwable $e) {
        error_log("IdP: admin session keys are unavailable: " . get_class($e) . ": " . $e->getMessage());
        return null;
    }
    if (!is_string($hex) || strlen($hex) !== 64 || !ctype_xdigit($hex)) {
        if ($rotate) {
            return null;
        }
        // Sessions bound to a key that cannot be read are lost anyway.
        error_log("IdP: replacing the unreadable admin session key of " . sanitize_label($username, 64));
        return admin_session_key($username, true);
    }
    return $cache[$store][$username] = (string) hex2bin($hex);
}

/**
 * Fingerprint of $username's current users.txt entry, "v2.<salt>.<hmac>": HMAC-SHA256 under
 * the admin's session key (admin_session_key()) over a random per-session salt, the username
 * and the entry. The key never enters the session, so session storage (also a redis or
 * memcached save_path, or a backup of the sessions directory) holds nothing that can be
 * checked offline against the entry, which is the password itself for legacy plaintext
 * entries. Null when the user is unknown, users.txt cannot be read or the key is unavailable.
 */
function admin_session_fingerprint(string $username, ?string $salt = null): ?string
{
    $users = admin_users_cached();
    if (!is_array($users) || !isset($users[$username])) {
        return null;
    }
    $key = admin_session_key($username);
    if ($key === null) {
        return null;
    }
    $salt ??= base64url_encode(random_bytes(16));
    return "v2." . $salt . "." .
        hash_hmac("sha256", $salt . "\0" . $username . "\0" . $users[$username], $key);
}

/**
 * Compares a stored session fingerprint with $username's current users.txt entry and session
 * key: true when it matches; false when it does not (also for a fingerprint in another format);
 * null when it cannot be checked now (users.txt unreadable, session key unavailable).
 */
function admin_session_fingerprint_check(string $username, string $fingerprint): ?bool
{
    $parts = explode(".", $fingerprint);
    if (count($parts) !== 3 || $parts[0] !== "v2" || preg_match('/^[A-Za-z0-9_-]{16,64}$/D', $parts[1]) !== 1) {
        return false;
    }
    $expected = admin_session_fingerprint($username, $parts[1]);
    return $expected === null ? null : hash_equals($expected, $fingerprint);
}

/**
 * Does the stored session fingerprint still match $username's users.txt entry and session key?
 */
function admin_session_fingerprint_matches(string $username, string $fingerprint): bool
{
    return admin_session_fingerprint_check($username, $fingerprint) === true;
}

/**
 * Removes the admin login (and its CSRF token and pending admin passkey registration)
 * from the current session. Other session data is kept.
 */
function admin_session_clear(): void
{
    if (isset($_SESSION) && is_array($_SESSION)) {
        unset(
            $_SESSION["user"],
            $_SESSION["user_fp"],
            $_SESSION["login_at"],
            $_SESSION["last_seen"],
            $_SESSION["csrf_token"],
            $_SESSION["admin_webauthn_reg"]
        );
    }
}

/**
 * Logs $username into the admin console after the sign-in checks succeeded (the password
 * with admin_password_verify(), plus any second factor): starts the session if needed,
 * issues a new session ID, stores the user, a fingerprint of their users.txt entry, the
 * login and last-activity times, and returns a new CSRF token.
 */
function admin_session_login(string $username): string
{
    session_ensure_started();
    if (session_status() === PHP_SESSION_ACTIVE && !headers_sent()) {
        session_regenerate_id(true);
    }
    admin_session_clear();
    $_SESSION["user"] = $username;
    $fingerprint = admin_session_fingerprint($username);
    if ($fingerprint !== null) {
        $_SESSION["user_fp"] = $fingerprint;
    }
    $now = time();
    $_SESSION["login_at"] = $now;
    $_SESSION["last_seen"] = $now;
    $_SESSION["csrf_token"] = base64url_encode(random_bytes(32));
    return $_SESSION["csrf_token"];
}

/**
 * Signs $username out of every console session ("sign out everywhere", G2a-04): replaces the
 * admin's session key, so no stored session fingerprint of that admin matches any more and
 * each of those sessions ends on its next request. With $keepCurrent the calling session
 * stays signed in when it belongs to $username (it gets a fingerprint under the new key);
 * otherwise its admin login ends now. Returns false when the key could not be replaced.
 */
function admin_sessions_revoke_all(string $username, bool $keepCurrent = true): bool
{
    if ($username === "" || admin_session_key($username, true) === null) {
        return false;
    }
    if (isset($_SESSION) && is_array($_SESSION) && ($_SESSION["user"] ?? null) === $username) {
        $fingerprint = $keepCurrent ? admin_session_fingerprint($username) : null;
        if ($fingerprint !== null) {
            $_SESSION["user_fp"] = $fingerprint;
        } else {
            admin_session_clear();
        }
    }
    return true;
}

/**
 * The CSRF token for the admin console page and /api/me (G1c-06): the session's token while
 * an admin is signed in, otherwise "" without starting a session. /api/login needs no token
 * and returns a new one, so anonymous visits to the console create no session.
 */
function admin_console_csrf_token(): string
{
    return current_user() !== null ? csrf_token() : "";
}

/**
 * The logged-in admin, or null. The session is re-checked on every request (S10-04,
 * G2a-04): the login ends when its user is removed from users.txt, when the user's
 * users.txt entry changes (password change), when the admin signed out everywhere
 * (admin_sessions_revoke_all()), 12 hours after the login, and after 30 minutes without a
 * request. A session without these records (made by an older version) is signed out. An
 * unreadable users.txt or session key denies access without ending the login.
 * A client outside console_ip_allowlist gets the empty 404 before any session is touched
 * (console_ip_allowlist_enforce()).
 */
function current_user(): ?string
{
    console_ip_allowlist_enforce();
    session_resume_deferred();
    $user = $_SESSION["user"] ?? null;
    if (!is_string($user) || $user === "") {
        return null;
    }
    $users = admin_users_cached();
    if ($users === null) {
        return null;
    }
    if (!isset($users[$user])) {
        admin_session_clear();
        return null;
    }
    $now = time();
    $loginAt = $_SESSION["login_at"] ?? null;
    $lastSeen = $_SESSION["last_seen"] ?? null;
    if (
        !is_int($loginAt) ||
        !is_int($lastSeen) ||
        $now - $loginAt > ADMIN_SESSION_MAX_SECONDS ||
        $now - $lastSeen > ADMIN_SESSION_IDLE_SECONDS
    ) {
        admin_session_clear();
        return null;
    }
    $fingerprint = $_SESSION["user_fp"] ?? null;
    if ($fingerprint === null) {
        // The session key was unavailable at login: bind the session as soon as it is.
        $stamp = admin_session_fingerprint($user);
        if ($stamp === null) {
            return null;
        }
        $_SESSION["user_fp"] = $stamp;
    } else {
        $matches = is_string($fingerprint) ? admin_session_fingerprint_check($user, $fingerprint) : false;
        if ($matches === null) {
            return null;
        }
        if ($matches === false) {
            admin_session_clear();
            return null;
        }
    }
    if ($now - $lastSeen >= ADMIN_SESSION_TOUCH_SECONDS) {
        $_SESSION["last_seen"] = $now;
    }
    return $user;
}

function require_login(?string $csrfExpectedOrigin = null): string
{
    $u = current_user();
    if (!$u) {
        json_response(401, ["error" => "Not authenticated"]);
    }
    $m = strtoupper((string) ($_SERVER["REQUEST_METHOD"] ?? "GET"));
    if (
        $csrfExpectedOrigin !== null &&
        in_array($m, ["POST", "PUT", "PATCH", "DELETE"], true)
    ) {
        verify_request_csrf($csrfExpectedOrigin, true);
    }
    return $u;
}

function uuidv4(): string
{
    $d = random_bytes(16);
    $d[6] = chr((ord($d[6]) & 0x0f) | 0x40);
    $d[8] = chr((ord($d[8]) & 0x3f) | 0x80);
    return vsprintf("%s%s-%s-%s-%s-%s%s%s", str_split(bin2hex($d), 4));
}

function idp_id_for(string $owner, string $friendly): string
{
    return rawurlencode($owner . "-" . $friendly);
}

function get_auth_header(): string
{
    $h1 = $_SERVER["HTTP_AUTHORIZATION"] ?? "";
    $h2 = $_SERVER["REDIRECT_HTTP_AUTHORIZATION"] ?? "";
    $h3 = "";
    if (function_exists("getallheaders")) {
        $all = getallheaders();
        if (isset($all["Authorization"])) {
            $h3 = $all["Authorization"];
        } elseif (isset($all["authorization"])) {
            $h3 = $all["authorization"];
        }
    }
    return (string) ($h1 ?: ($h2 ?: $h3));
}

function get_api_key(): ?string
{
    $auth = get_auth_header();
    if (preg_match('/^\s*ApiKey\s+([A-Za-z0-9\-_]+)\s*$/i', $auth, $m)) {
        return $m[1];
    }
    if (!empty($_SERVER["HTTP_X_API_KEY"])) {
        $k = trim((string) $_SERVER["HTTP_X_API_KEY"]);
        if (preg_match('/^[A-Za-z0-9\-_]+$/', $k)) {
            return $k;
        }
    }
    return null;
}

/**
 * Safely reads a JSON request body (capped at 512 KB) and enforces Content-Type: application/json
 * to block HTML <form enctype="text/plain"> cross-site simple-request attacks.
 */
function read_json_body(bool $enforceJsonContentType = true): array
{
    if ($enforceJsonContentType) {
        $ct = strtolower((string) ($_SERVER["CONTENT_TYPE"] ?? ($_SERVER["HTTP_CONTENT_TYPE"] ?? "")));
        if ($ct !== "" && !str_contains($ct, "application/json")) {
            json_response(415, [
                "error" => "Content-Type must be application/json",
            ]);
        }
    }
    $raw = file_get_contents("php://input", false, null, 0, 524289);
    if ($raw === false || trim($raw) === "") {
        return [];
    }
    if (strlen($raw) > 524288) {
        json_response(413, ["error" => "Request JSON payload too large"]);
    }
    $decoded = json_decode($raw, true, 32);
    return is_array($decoded) ? $decoded : [];
}

function html_escape(string $val): string
{
    return htmlspecialchars($val, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
}

function clean_xml_text(string $val): string
{
    return preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', "", $val) ?? "";
}

/**
 * Validates URLs stored for SAML ACS/SLO or OIDC Redirect/Login URIs.
 * Blocks dangerous schemes (javascript:, data:, vbscript:, file:, blob:).
 */
function validate_safe_url(
    string $url,
    bool $allowCustomAppScheme = false,
    string $fieldLabel = "URL"
): string {
    $u = trim($url);
    if ($u === "" || preg_match('/[\r\n\x00-\x1f]/', $u)) {
        throw new InvalidArgumentException("Invalid $fieldLabel");
    }
    $scheme = strtolower((string) parse_url($u, PHP_URL_SCHEME));
    $banned = ["javascript", "data", "vbscript", "file", "blob", "about"];
    if ($scheme === "" || in_array($scheme, $banned, true)) {
        throw new InvalidArgumentException(
            "Forbidden or missing URI scheme in $fieldLabel"
        );
    }
    if (!$allowCustomAppScheme && !in_array($scheme, ["https", "http"], true)) {
        throw new InvalidArgumentException(
            "$fieldLabel must use https:// or http://"
        );
    }
    if (in_array($scheme, ["https", "http"], true)) {
        $host = parse_url($u, PHP_URL_HOST);
        if (!is_string($host) || $host === "") {
            throw new InvalidArgumentException("$fieldLabel is missing a valid host");
        }
    }
    return $u;
}

function sanitize_host_header(string $rawHost, string $fallbackServerName = "localhost"): string
{
    $candidate = trim($rawHost);
    if (
        $candidate !== "" &&
        preg_match(
            '/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*|\[[0-9a-fA-F:]+\])(?::([1-9]\d{0,4}))?$/',
            $candidate,
            $m
        )
    ) {
        if (!isset($m[1]) || ((int) $m[1] >= 1 && (int) $m[1] <= 65535)) {
            return strtolower($candidate);
        }
    }
    $fb = trim($fallbackServerName);
    if ($fb !== "" && preg_match('/^[a-zA-Z0-9.\-]+$/', $fb)) {
        return strtolower($fb);
    }
    return "localhost";
}

/**
 * The client's IP address, for logs, last_used_ip and (through client_ip_bucket()) rate
 * limits. X-Forwarded-For is used only when the direct peer is listed in
 * trusted_proxies: the header is read from the right, skipping trusted proxies, and the
 * first other hop is the client if it is a valid IP address. Anything else (no list,
 * an untrusted peer, a missing header, a malformed hop) gives REMOTE_ADDR, so clients
 * can never choose their own address. OIDC_TRUST_PROXY and loopback peers do not enable
 * X-Forwarded-For.
 */
function client_ip_address(): string
{
    $remote = trim((string) ($_SERVER["REMOTE_ADDR"] ?? ""));
    if ($remote === "") {
        return "0.0.0.0";
    }
    if (!bootstrap_peer_is_trusted_proxy()) {
        return $remote;
    }
    $header = $_SERVER["HTTP_X_FORWARDED_FOR"] ?? "";
    if (!is_string($header) || trim($header) === "") {
        return $remote;
    }
    $trusted = config_list("trusted_proxies", "OIDC_TRUSTED_PROXIES");
    $hops = array_slice(explode(",", $header), -20);
    for ($i = count($hops) - 1; $i >= 0; $i--) {
        $hop = bootstrap_forwarded_hop_ip($hops[$i]);
        if ($hop === null) {
            break;
        }
        if (!bootstrap_ip_in_cidrs($hop, $trusted)) {
            return $hop;
        }
    }
    return $remote;
}

// ---------- Configuration & data paths (S15-01) ----------
$ROOT_DIR = dirname(__DIR__);

// Optional local overrides (git-ignored, loaded once by local_config()). See config.example.php.
$LOCAL_CONFIG = local_config();

// ---------- IP allowlist (src/ip_allowlist.php) ----------
// The first check that can answer a request. An address outside ip_allowlist (config.php or
// OIDC_IP_ALLOWLIST) gets an empty 404 that is the same for every URL and method: before the
// data-directory checks (their 500 names this product's settings), the 400, 403 and 421 answers
// and the HTTPS redirect below, and before any session, cookie or header. Refused requests are
// recorded in <data dir>/blocked_requests.sqlite (src/blocked_requests.php). Nothing happens
// while ip_allowlist is empty; command-line runs are exempt.
require_once __DIR__ . "/ip_allowlist.php";
require_once __DIR__ . "/blocked_requests.php";
ip_allowlist_enforce();
// Apache's own 403/404/413 answers reach index.php through ErrorDocument, so the check above
// answers them for refused addresses; everyone else gets the original status here.
bootstrap_error_document_passthrough();

$dataPaths = bootstrap_resolve_data_paths($ROOT_DIR);
$CONFIG_DIR = $dataPaths["config_dir"];
$USERS_FILE = $dataPaths["users_file"];
$PROVIDERS_FILE = $dataPaths["providers_file"];
$KEYS_DIR = $dataPaths["keys_dir"];
$APIKEYS_FILE = $dataPaths["apikeys_file"];
unset($dataPaths);

// A PHP error log that php.ini placed inside the web root now goes to the data directory.
bootstrap_guard_error_log($CONFIG_DIR);

// ---------- Request target and base-path aware routing variables (S15-10) ----------
$method = strtoupper((string) ($_SERVER["REQUEST_METHOD"] ?? "GET"));
$reqPath = bootstrap_request_path((string) ($_SERVER["REQUEST_URI"] ?? "/"));
if ($reqPath === null) {
    bootstrap_plain_response(400, "Bad Request");
}
$scriptDir = rtrim(
    (string) preg_replace('#/{2,}#', "/", str_replace("\\", "/", dirname((string) ($_SERVER["SCRIPT_NAME"] ?? "")))),
    "/"
);
if ($scriptDir === "." || $scriptDir === "/") {
    $scriptDir = "";
}
$path = $reqPath;
if ($scriptDir !== "" && ($reqPath === $scriptDir || str_starts_with($reqPath, $scriptDir . "/"))) {
    $path = substr($reqPath, strlen($scriptDir)) ?: "/";
}

// Block direct requests to internal / sensitive filenames even when run under php -S without
// Apache. Only the path inside the install (the one the router matches) is checked: the raw
// request path of a subdirectory install still carries the prefix, which would hide the
// public /{idpId}/saml/cert.pem route from its exemption and would block every request of an
// install whose subdirectory is named like a protected folder (keys/, src/, ...). The suffix
// rules give the same answer on both paths.
if (bootstrap_is_sensitive_path($path)) {
    bootstrap_plain_response(403, "Forbidden");
}

// ---------- Reverse proxies and HTTPS detection ----------
$requestIsHttps =
    (!empty($_SERVER["HTTPS"]) && strtolower((string) $_SERVER["HTTPS"]) !== "off") ||
    (int) ($_SERVER["SERVER_PORT"] ?? 0) === 443 ||
    (bootstrap_peer_trusted_for_proto() &&
        strtolower(trim((string) ($_SERVER["HTTP_X_FORWARDED_PROTO"] ?? ""))) === "https");

// ---------- Base URL, origin and WebAuthn rpId ----------
$configuredPublicBase = config_value("public_base_url", ["OIDC_PUBLIC_BASE_URL", "PUBLIC_BASE_URL"]);
if (is_string($configuredPublicBase) && $configuredPublicBase !== "") {
    // The configured URL fixes scheme, host, port and path; the Host header is ignored.
    $baseUrl = rtrim($configuredPublicBase, "/");
    $publicUrlParts = parse_url($baseUrl);
    $pScheme = is_array($publicUrlParts) ? strtolower((string) ($publicUrlParts["scheme"] ?? "")) : "";
    $pHost = is_array($publicUrlParts) ? strtolower((string) ($publicUrlParts["host"] ?? "")) : "";
    if (
        !in_array($pScheme, ["http", "https"], true) ||
        $pHost === "" ||
        isset($publicUrlParts["user"]) ||
        isset($publicUrlParts["pass"]) ||
        isset($publicUrlParts["query"]) ||
        isset($publicUrlParts["fragment"])
    ) {
        bootstrap_fail_closed(
            "public_base_url (OIDC_PUBLIC_BASE_URL) must be an absolute http:// or https:// URL without credentials, query or fragment",
            "Check OIDC_PUBLIC_BASE_URL (public_base_url in config.php)."
        );
    }
    $pPort = isset($publicUrlParts["port"]) ? (int) $publicUrlParts["port"] : null;
    $scheme = $pScheme;
    $rpId = $pHost;
    // Browsers omit the default port in the Origin header, so the origin must too.
    $origin =
        $pScheme . "://" . $pHost .
        ($pPort !== null && $pPort !== ($pScheme === "https" ? 443 : 80) ? ":" . $pPort : "");
} else {
    $scheme = $requestIsHttps ? "https" : "http";
    $hostWithPort = sanitize_host_header(
        (string) ($_SERVER["HTTP_HOST"] ?? ""),
        (string) ($_SERVER["SERVER_NAME"] ?? "localhost")
    );
    $rpId = strtolower((string) preg_replace('/:\d+$/', "", $hostWithPort));
    // Without a configured base URL the issuer, SAML entity IDs, playground redirect URIs
    // and the rpId follow the Host header, so only allowed hosts are served. This runs
    // before any session or other state is created.
    if (
        PHP_SAPI !== "cli" &&
        !bootstrap_host_allowed($rpId, config_list("allowed_hosts", "OIDC_ALLOWED_HOSTS"))
    ) {
        bootstrap_plain_response(
            421,
            "Misdirected Request: this host name is not configured for this identity provider.\n" .
                "Administrator: set OIDC_PUBLIC_BASE_URL (or public_base_url in config.php), or add the host to OIDC_ALLOWED_HOSTS."
        );
    }
    $origin = $scheme . "://" . $hostWithPort;
    $baseUrl = rtrim($origin . ($scriptDir !== "" ? $scriptDir : ""), "/");
}

// Effective HTTPS (S13-07): the request arrived over TLS, or the public base URL is
// https (TLS terminated by a proxy that is not declared). Session and SSO cookies are
// Secure whenever this is true; index.php passes it to the IdP routes.
$isHttps = $requestIsHttps || $scheme === "https";

// ---------- HTTPS redirect (S13-07) ----------
// With an https public_base_url, a request that reached PHP over plain HTTP is sent to the
// same URL on the public base URL (GET and HEAD) or refused (any other method), before a
// session or other state is created. Requests that show TLS ended at a proxy in front of PHP
// are left alone, so an undeclared TLS-offloading proxy cannot loop.
// allow_plain_http_requests (OIDC_ALLOW_PLAIN_HTTP_REQUESTS) restores processing them, for
// proxies that send no such header.
if (
    PHP_SAPI !== "cli" &&
    $scheme === "https" &&
    !$requestIsHttps &&
    !bootstrap_request_has_tls_hint() &&
    !config_flag("allow_plain_http_requests", "OIDC_ALLOW_PLAIN_HTTP_REQUESTS")
) {
    bootstrap_https_redirect($baseUrl . $path, $method);
}

// ---------- Session ----------
// Set when the request carries the cookie of an existing session on a route that needs none
// (see session_resume_deferred()).
$sessionDeferred = false;
if (PHP_SAPI !== "cli" && session_status() === PHP_SESSION_NONE) {
    @ini_set("session.use_strict_mode", "1");
    @ini_set("session.cookie_httponly", "1");
    // __Host- cookies must be Secure, host-only and Path=/, so no other site or subdomain
    // can set or shadow them.
    session_name($isHttps ? "__Host-IDPSESSID" : "IDPSESSID");
    session_set_cookie_params([
        "lifetime" => 0,
        "path" => "/",
        "domain" => "",
        "secure" => $isHttps,
        "httponly" => true,
        "samesite" => "Lax",
    ]);
    $sessionSaveDir = bootstrap_session_save_dir($CONFIG_DIR);
    if ($sessionSaveDir !== null) {
        session_save_path($sessionSaveDir);
    }
    // Lazy sessions (S15-08): resume a session only when the browser presents its cookie.
    // Everything else starts one on demand (session_ensure_started()), so a cross-site
    // POST, which carries no SameSite=Lax cookie, gets no Set-Cookie that would replace
    // the admin's session cookie. A malformed cookie, and the cookie of a session that no
    // longer exists or has expired (G1c-06), is ignored, so no session file or cookie is
    // created for it and PHP issues a fresh ID if a session is started later. On routes that
    // never use the session the existing session is not opened either, so they take no
    // session lock (session_resume_deferred() opens it if one of them does need it).
    $sessionCookie = $_COOKIE[session_name()] ?? null;
    if (
        is_string($sessionCookie) &&
        preg_match('/^[A-Za-z0-9,-]{1,256}$/D', $sessionCookie) === 1 &&
        bootstrap_session_resumable($sessionCookie, $sessionSaveDir)
    ) {
        if (bootstrap_route_is_stateless($path)) {
            $sessionDeferred = true;
        } else {
            session_start();
        }
    } elseif ($sessionCookie !== null) {
        unset($_COOKIE[session_name()]);
    }
    unset($sessionCookie, $sessionSaveDir);
}
