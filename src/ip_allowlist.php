<?php
declare(strict_types=1);

/**
 * IP allowlist with a stealth refusal (ip_allowlist in config.php, env OIDC_IP_ALLOWLIST).
 *
 * Off until ip_allowlist has an entry. Then ip_allowlist_enforce(), the first check in
 * src/bootstrap.php that can answer a request, serves only clients whose address is inside one
 * of the listed IPv4 or IPv6 ranges. Every other request gets the same empty 404 for every URL
 * and method (ip_allowlist_refuse()) and is recorded in <data dir>/blocked_requests.sqlite
 * (src/blocked_requests.php). Command-line runs are never filtered.
 *
 * Fail closed: a request is refused when its address is not listed, when the client address
 * cannot be determined (a REMOTE_ADDR that is not an IP address, a malformed X-Forwarded-For hop
 * from a trusted proxy, more than 32 hops), when no entry is usable, when config.php does not
 * load while it sets ip_allowlist, and when the check itself throws. ip_allowlist_report_only
 * (OIDC_IP_ALLOWLIST_REPORT_ONLY) serves everything and records would-be refusals instead.
 *
 * Gate-time limits: the gate runs right after local_config(), before the data paths are
 * resolved and before db.php and admin_clients.php are loaded. Code it can reach calls only
 * env_string, local_config, config_value, config_flag, config_list, sanitize_label, path_join,
 * bootstrap_ip_bytes, bootstrap_forwarded_hop_ip, bootstrap_canonical_path and
 * bootstrap_path_in_webroot (bootstrap.php), blocked_requests_record(), and PHP built-ins.
 * Route-time code (status, viewer access) may also use json_response() and
 * auth_require_session_only(). This file defines only constants and functions.
 *
 * Console allowlist (console_ip_allowlist, env OIDC_CONSOLE_IP_ALLOWLIST): a second, narrower
 * list for the Administrator Console only, off until it has an entry. console_ip_allowlist_enforce()
 * runs before the console page, POST /api/login and /api/logout, and every console-session
 * check (current_user()), and refuses other addresses with the same empty 404, recorded as
 * console_not_listed or console_config_error. An /api request that presents no Admin API
 * client credential reaches current_user() and is refused too; requests with an Admin API
 * client credential and the public IdP endpoints are not affected. The site-wide
 * ip_allowlist still applies to every request first. While config.php is unreadable it is
 * ignored as a whole, so console_ip_allowlist (unless set in the environment) does not apply.
 *
 * Data shapes (shared with src/blocked_requests.php, src/routes_api.php and the console):
 *   $range    ["family" => 4|6, "net" => packed address (4 or 16 bytes, host bits zero),
 *              "bits" => int, "cidr" => canonical "net/bits", "normalized" => host bits were set]
 *   $item     ["label" => string ("" when none), "entry" => string (as written), "range" => $range]
 *   $client   ["ip" => ?string (canonical; null when refused for a problem),
 *              "bin" => ?string (packed: 4 bytes for IPv4, also for ::ffff:a.b.c.d; 16 for IPv6),
 *              "peer" => string (REMOTE_ADDR), "via_proxy" => bool (from X-Forwarded-For),
 *              "problem" => null|"unknown_address"|"bad_forwarded_for"]
 *   $policy   ["state" => "disabled"|"active"|"deny_all", "report_only" => bool,
 *              "source" => "none"|"env"|"config",
 *              "config_php" => "absent"|"loaded"|"unreadable"|"failed",
 *              "ranges" => list<$item>, "problems" => list<string>]
 *   $decision ["decision" => "disabled"|"allowed"|"refused", "reason" => ?string,
 *              "matched" => ?["label" => string, "cidr" => string]]
 */

// Most valid entries ip_allowlist may hold; later entries are ignored and reported.
const IP_ALLOWLIST_MAX_ENTRIES = 4096;
// Longest entry (an address or CIDR block, brackets included), in bytes.
const IP_ALLOWLIST_MAX_ENTRY_LENGTH = 64;
// Longest X-Forwarded-For header, and most hops in it, accepted from a trusted proxy.
const IP_ALLOWLIST_MAX_FORWARDED_BYTES = 4096;
const IP_ALLOWLIST_MAX_FORWARDED_HOPS = 32;
// One warning topic reaches the PHP error log at most once in this many seconds.
const IP_ALLOWLIST_WARN_INTERVAL_SECONDS = 3600;
// Why a request was refused. The gate, the blocked-request store, the API and the console use
// exactly these values.
const IP_ALLOWLIST_REASONS = [
    "not_listed",
    "bad_forwarded_for",
    "unknown_address",
    "config_error",
    "check_failed",
    // Refused by console_ip_allowlist (the console only): not listed, or no usable entry.
    "console_not_listed",
    "console_config_error",
];

// ---------- Parsing and matching (pure; never DNS) ----------

/**
 * Parses one allowlist or trusted-proxy entry: an IPv4 or IPv6 address (one host) or a CIDR
 * block. IPv6 may be written in brackets ("[2001:db8::]/32"). An IPv4-mapped IPv6 entry
 * (::ffff:0:0/96 space, prefix 96 or more) becomes the IPv4 range, the form in which
 * bootstrap_ip_bytes() presents such clients. Host bits are cleared ("normalized" tells
 * whether any were set). Returns null for anything else: host names, wildcards, "a-b"
 * ranges, zone IDs, leading zeros ("010.0.0.1", "/032"), prefixes beyond the family and
 * entries over IP_ALLOWLIST_MAX_ENTRY_LENGTH bytes. NAT64, 6to4 and Teredo addresses stay IPv6.
 */
function ip_allowlist_parse_range(string $entry): ?array
{
    $entry = trim($entry);
    if ($entry === "" || strlen($entry) > IP_ALLOWLIST_MAX_ENTRY_LENGTH) {
        return null;
    }
    $address = $entry;
    $prefix = null;
    if (preg_match('#^(.*)/(0|[1-9][0-9]{0,2})$#D', $entry, $m) === 1) {
        $address = $m[1];
        $prefix = (int) $m[2];
    } elseif (str_contains($entry, "/")) {
        return null;
    }
    $bracketed = strlen($address) > 2 && $address[0] === "[" && str_ends_with($address, "]");
    if ($bracketed) {
        $address = substr($address, 1, -1);
    }
    // Brackets belong to IPv6 only. filter_var() rejects zone IDs, spaces and leading zeros.
    if (filter_var($address, FILTER_VALIDATE_IP, $bracketed ? FILTER_FLAG_IPV6 : 0) === false) {
        return null;
    }
    $bin = inet_pton($address);
    if (!is_string($bin) || (strlen($bin) !== 4 && strlen($bin) !== 16)) {
        return null;
    }
    if (strlen($bin) === 16 && str_starts_with($bin, str_repeat("\x00", 10) . "\xff\xff")) {
        if ($prefix !== null) {
            if ($prefix < 96) {
                return null;
            }
            $prefix -= 96;
        }
        $bin = substr($bin, 12);
    }
    $maxBits = strlen($bin) * 8;
    $bits = $prefix ?? $maxBits;
    if ($bits > $maxBits) {
        return null;
    }
    $whole = intdiv($bits, 8);
    $rest = $bits % 8;
    $net = substr($bin, 0, $whole);
    if ($rest !== 0) {
        $net .= chr(ord($bin[$whole]) & ((0xFF << (8 - $rest)) & 0xFF));
    }
    $net = str_pad($net, strlen($bin), "\x00");
    $text = inet_ntop($net);
    if (!is_string($text)) {
        return null;
    }
    return [
        "family" => strlen($net) === 4 ? 4 : 6,
        "net" => $net,
        "bits" => $bits,
        "cidr" => $text . "/" . $bits,
        "normalized" => $net !== $bin,
    ];
}

/**
 * Are the first $bits bits of the packed addresses $a and $b equal? Both must have the same
 * length. Whole bytes are compared with substr(), then one masked byte (the technique of
 * bootstrap_ip_in_cidrs()).
 */
function ip_allowlist_prefix_equal(string $a, string $b, int $bits): bool
{
    if (strlen($a) !== strlen($b) || $bits < 0 || $bits > 8 * strlen($a)) {
        return false;
    }
    $whole = intdiv($bits, 8);
    if (substr($a, 0, $whole) !== substr($b, 0, $whole)) {
        return false;
    }
    $rest = $bits % 8;
    if ($rest === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $rest)) & 0xFF;
    return (ord($a[$whole]) & $mask) === (ord($b[$whole]) & $mask);
}

/**
 * Reads the ip_allowlist setting: a string (split on commas and whitespace, no labels) or an
 * array. In an array an integer key holds such a string, and a string key pairs an entry with
 * its label in either orientation ("203.0.113.0/24" => "Office" or "Office" => "203.0.113.0/24"),
 * so a swapped pair never locks anyone out. Invalid entries are reported and ignored,
 * duplicates are skipped, and entries beyond IP_ALLOWLIST_MAX_ENTRIES are ignored with one
 * problem. "configured" is false for null, false, "", [] and input with nothing in it (" ",
 * [""], ","); anything else, even an unusable value such as true or 0, counts as configured.
 * $settingName names the setting in problem messages (console_ip_allowlist uses the same syntax).
 *
 * @return array{configured: bool, ranges: list<array>, problems: list<string>}
 */
function ip_allowlist_parse_setting(mixed $raw, string $settingName = "ip_allowlist"): array
{
    if ($raw === null || $raw === false || $raw === "" || $raw === []) {
        return ["configured" => false, "ranges" => [], "problems" => []];
    }
    $ranges = [];
    $problems = [];
    $given = false;
    $full = false;
    $seen = [];
    $invalid = static fn (string $text): string =>
        "'" . sanitize_label($text, 64) . "' is not an IPv4 or IPv6 address or CIDR block";
    // Considers one candidate; $range is passed when the caller has parsed it already.
    $add = static function (string $text, string $label, ?array $range = null) use (
        &$ranges,
        &$problems,
        &$given,
        &$full,
        &$seen,
        $invalid,
        $settingName
    ): void {
        if ($full) {
            return;
        }
        $given = true;
        $range ??= ip_allowlist_parse_range($text);
        if ($range === null) {
            $problems[] = $invalid($text);
            return;
        }
        if (isset($seen[$range["cidr"]])) {
            return;
        }
        if (count($ranges) >= IP_ALLOWLIST_MAX_ENTRIES) {
            $problems[] = $settingName . " has more than " . IP_ALLOWLIST_MAX_ENTRIES . " entries: the rest are ignored";
            $full = true;
            return;
        }
        $seen[$range["cidr"]] = true;
        $ranges[] = [
            "label" => sanitize_label($label, 64),
            "entry" => sanitize_label($text, 64),
            "range" => $range,
        ];
    };
    $split = static function (string $text): array {
        $parts = preg_split('/[\s,]+/', $text, -1, PREG_SPLIT_NO_EMPTY);
        return is_array($parts) ? $parts : [];
    };

    if (is_string($raw)) {
        foreach ($split($raw) as $candidate) {
            $add($candidate, "");
        }
    } elseif (is_array($raw)) {
        foreach ($raw as $key => $value) {
            if ($full) {
                break;
            }
            if (is_int($key)) {
                if (is_string($value)) {
                    foreach ($split($value) as $candidate) {
                        $add($candidate, "");
                    }
                } else {
                    $given = true;
                    $problems[] = "entry " . $key . " is not a string (" . get_debug_type($value) . ")";
                }
                continue;
            }
            $keyRange = ip_allowlist_parse_range($key);
            if ($keyRange !== null) {
                $add($key, is_string($value) ? $value : "", $keyRange);
                continue;
            }
            $valueRange = is_string($value) ? ip_allowlist_parse_range($value) : null;
            if ($valueRange !== null) {
                $add($value, $key, $valueRange);
                continue;
            }
            $given = true;
            $problems[] = is_string($value) && trim($value) !== ""
                ? "neither '" . sanitize_label($key, 64) . "' nor '" . sanitize_label($value, 64) .
                    "' is an IPv4 or IPv6 address or CIDR block"
                : $invalid($key);
        }
    } else {
        $given = true;
        $problems[] = $settingName . " must be a list or a string";
    }
    return ["configured" => $given, "ranges" => $ranges, "problems" => $problems];
}

/**
 * The first $item of $items whose range contains the packed address $ipBin (4 bytes for IPv4,
 * 16 for IPv6, as bootstrap_ip_bytes() returns it), or null. Families never mix: an IPv4
 * client, also one written as ::ffff:a.b.c.d, matches only IPv4 entries.
 */
function ip_allowlist_match(string $ipBin, array $items): ?array
{
    foreach ($items as $item) {
        $net = $item["range"]["net"] ?? null;
        $bits = $item["range"]["bits"] ?? null;
        if (!is_string($net) || !is_int($bits) || strlen($net) !== strlen($ipBin)) {
            continue;
        }
        if (ip_allowlist_prefix_equal($ipBin, $net, $bits)) {
            return $item;
        }
    }
    return null;
}

/**
 * Do the ranges $a and $b ($range shapes) share an address? Same family, and their first
 * min(bits) bits are equal.
 */
function ip_allowlist_ranges_overlap(array $a, array $b): bool
{
    $netA = $a["net"] ?? null;
    $netB = $b["net"] ?? null;
    if (!is_string($netA) || !is_string($netB) || strlen($netA) !== strlen($netB)) {
        return false;
    }
    return ip_allowlist_prefix_equal($netA, $netB, min((int) ($a["bits"] ?? 0), (int) ($b["bits"] ?? 0)));
}

// ---------- Policy ----------

/**
 * The IP allowlist policy of this request ($policy shape), computed once (static cache).
 * "disabled" while ip_allowlist is empty; "active" with at least one valid entry; "deny_all"
 * when it is configured without a valid entry, or when config.php fails to load (it throws
 * or does not return an array) while OIDC_IP_ALLOWLIST is unset and config.php contains
 * 'ip_allowlist' quoted outside comments (ip_allowlist_config_mentions_key()). An unreadable
 * config.php cannot be examined, so it keeps today's behaviour (ignored). report_only applies
 * to "active" and "deny_all" only.
 */
function ip_allowlist_policy(): array
{
    static $policy = null;
    if (is_array($policy)) {
        return $policy;
    }
    $loadError = null;
    local_config($loadError);
    $raw = config_value("ip_allowlist", "OIDC_IP_ALLOWLIST");
    $file = dirname(__DIR__) . DIRECTORY_SEPARATOR . "config.php";
    if ($loadError === "unreadable") {
        $configPhp = "unreadable";
    } elseif ($loadError === "exception" || $loadError === "not_array") {
        $configPhp = "failed";
    } else {
        $configPhp = is_file($file) ? "loaded" : "absent";
    }
    $result = [
        "state" => "disabled",
        "report_only" => false,
        "source" => "none",
        "config_php" => $configPhp,
        "ranges" => [],
        "problems" => [],
    ];
    // Fast path: nothing is configured and config.php loaded (or is absent).
    if ($raw === null && $loadError === null) {
        return $policy = $result;
    }
    if (env_string(["OIDC_IP_ALLOWLIST"]) !== null) {
        $source = "env";
    } else {
        $source = $raw !== null ? "config" : "none";
    }
    if ($source === "none" && $configPhp === "failed" && ip_allowlist_config_mentions_key($file, "ip_allowlist")) {
        $result["state"] = "deny_all";
        $result["problems"] = [
            "config.php does not load and sets ip_allowlist: every request is refused until it loads again (check it with php -l config.php)",
        ];
    } else {
        $parsed = ip_allowlist_parse_setting($raw);
        if ($parsed["configured"] && $parsed["ranges"] === []) {
            $result["state"] = "deny_all";
            $result["problems"] = array_merge($parsed["problems"], ["no usable entry: every request is refused"]);
        } elseif ($parsed["configured"]) {
            $result["state"] = "active";
            $result["ranges"] = $parsed["ranges"];
            $result["problems"] = $parsed["problems"];
        }
    }
    if ($result["state"] !== "disabled") {
        $result["source"] = $source;
        $result["report_only"] = config_flag("ip_allowlist_report_only", "OIDC_IP_ALLOWLIST_REPORT_ONLY");
    }
    return $policy = $result;
}

/**
 * Does $file contain $key quoted ('key' or "key") outside comments? Used when config.php fails
 * to load, so the file usually has an error; either of two scans counts. Reads at most 1 MiB.
 * 1. The tokenizer, which lexes a file with a syntax error (token_get_all() without
 *    TOKEN_PARSE): a string token equal to 'key' or "key".
 * 2. The source with its comments stripped by a regular expression that ignores strings (also
 *    the only scan without the tokenizer extension). It finds the key where an error hides it
 *    from the tokenizer: a string left open above the key (its quotes then pair up the wrong
 *    way), or "<?" with short_open_tag off or a "?>" in a comment (the rest lexes as inline
 *    HTML). A commented-out line such as config.example.php's // "ip_allowlist" => [] still
 *    never counts, so a broken config.php that never set the key does not refuse everyone.
 */
function ip_allowlist_config_mentions_key(string $file, string $key): bool
{
    $src = @file_get_contents($file, false, null, 0, 1048576);
    if (!is_string($src) || $src === "") {
        return false;
    }
    $quoted = ["'" . $key . "'", '"' . $key . '"'];
    if (function_exists("token_get_all")) {
        foreach (@token_get_all($src) as $token) {
            if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING && in_array($token[1], $quoted, true)) {
                return true;
            }
        }
    }
    $stripped = preg_replace('~/\*.*?\*/|//[^\r\n]*|#[^\r\n]*~s', "", $src);
    // If the expression fails (a PCRE limit, such as an unclosed /* near 1 MiB of text), search
    // the whole file: a key in a comment then counts.
    $haystack = is_string($stripped) ? $stripped : $src;
    return str_contains($haystack, $quoted[0]) || str_contains($haystack, $quoted[1]);
}

/**
 * trusted_proxies (OIDC_TRUSTED_PROXIES) as the IP allowlist uses it. Entries that cover every
 * address (prefix 0, such as 0.0.0.0/0) go to "any" and are ignored: they would let any client
 * choose its address with X-Forwarded-For. Unparseable entries go to "invalid". "any" and
 * "invalid" hold the entries as written, cleaned for display. Not cached.
 *
 * @return array{ranges: list<array>, any: list<string>, invalid: list<string>}
 */
function ip_allowlist_trusted_proxies(): array
{
    $ranges = [];
    $any = [];
    $invalid = [];
    foreach (config_list("trusted_proxies", "OIDC_TRUSTED_PROXIES") as $entry) {
        $text = sanitize_label($entry, 64);
        $range = ip_allowlist_parse_range($entry);
        if ($range === null) {
            $invalid[] = $text;
        } elseif ($range["bits"] === 0) {
            $any[] = $text;
        } else {
            $ranges[] = ["label" => "", "entry" => $text, "range" => $range];
        }
    }
    return ["ranges" => $ranges, "any" => $any, "invalid" => $invalid];
}

/**
 * May the console administrator $username open the IP allowlist status and its blocked
 * requests (view, export, purge)? Everyone unless ip_allowlist_admins (OIDC_IP_ALLOWLIST_ADMINS)
 * lists users.txt names (exact, case-sensitive match).
 */
function ip_allowlist_admin_allowed(string $username): bool
{
    $admins = config_list("ip_allowlist_admins", "OIDC_IP_ALLOWLIST_ADMINS");
    return $username !== "" && ($admins === [] || in_array($username, $admins, true));
}

// ---------- Client address and decision ----------

/**
 * The client of this request ($client shape), resolved strictly. The client is REMOTE_ADDR,
 * unless REMOTE_ADDR is a trusted proxy that sent X-Forwarded-For: then the hops are walked
 * right to left and the first one that is not a trusted proxy is the client (the left-most
 * hop when all are). Problems that clients or a misconfiguration control are refused rather
 * than resolved to a fallback: "unknown_address" for a REMOTE_ADDR that is not an IP address
 * (empty, a zone ID, ip:port, a Unix socket), "bad_forwarded_for" for a malformed hop, a header
 * over IP_ALLOWLIST_MAX_FORWARDED_BYTES or more than IP_ALLOWLIST_MAX_FORWARDED_HOPS hops.
 * X-Forwarded-For is never read from a direct client, and Forwarded, X-Real-IP,
 * CF-Connecting-IP and similar headers are never read. client_ip_address() (rate limits, audit)
 * keeps its own rules.
 */
function ip_allowlist_client(): array
{
    $remote = $_SERVER["REMOTE_ADDR"] ?? "";
    $remote = is_string($remote) ? trim($remote) : "";
    $peerBin = bootstrap_ip_bytes($remote);
    if ($peerBin === null) {
        return [
            "ip" => null,
            "bin" => null,
            "peer" => sanitize_label($remote, 64),
            "via_proxy" => false,
            "problem" => "unknown_address",
        ];
    }
    $peer = (string) inet_ntop($peerBin);
    $direct = ["ip" => $peer, "bin" => $peerBin, "peer" => $peer, "via_proxy" => false, "problem" => null];
    $trusted = ip_allowlist_trusted_proxies()["ranges"];
    if ($trusted === [] || ip_allowlist_match($peerBin, $trusted) === null) {
        return $direct;
    }
    $header = $_SERVER["HTTP_X_FORWARDED_FOR"] ?? null;
    if (!is_string($header) || trim($header) === "") {
        return $direct; // the proxy's own request
    }
    $bad = ["ip" => null, "bin" => null, "peer" => $peer, "via_proxy" => false, "problem" => "bad_forwarded_for"];
    if (strlen($header) > IP_ALLOWLIST_MAX_FORWARDED_BYTES) {
        return $bad;
    }
    $hops = explode(",", $header);
    if (count($hops) > IP_ALLOWLIST_MAX_FORWARDED_HOPS) {
        return $bad;
    }
    $clientBin = null;
    for ($i = count($hops) - 1; $i >= 0; $i--) {
        $hop = bootstrap_forwarded_hop_ip($hops[$i]);
        $hopBin = $hop === null ? null : bootstrap_ip_bytes($hop);
        if ($hopBin === null) {
            // Unlike client_ip_address(), never fall back to the proxy: when the proxy's own
            // address is listed, that would let any client behind it in.
            return $bad;
        }
        $clientBin = $hopBin;
        if (ip_allowlist_match($hopBin, $trusted) === null) {
            break;
        }
    }
    if ($clientBin === null) {
        return $bad;
    }
    return [
        "ip" => (string) inet_ntop($clientBin),
        "bin" => $clientBin,
        "peer" => $peer,
        "via_proxy" => true,
        "problem" => null,
    ];
}

/**
 * A $client for the literal address $ip (the CLI "check" command): peer is the address and
 * via_proxy false. Null when $ip is not an IP address.
 */
function ip_allowlist_client_for_ip(string $ip): ?array
{
    $bin = bootstrap_ip_bytes($ip);
    if ($bin === null) {
        return null;
    }
    $text = (string) inet_ntop($bin);
    return ["ip" => $text, "bin" => $bin, "peer" => $text, "via_proxy" => false, "problem" => null];
}

/**
 * The decision for $client under $policy ($decision shape). The gate, the status page's viewer
 * section and "ip-allowlist check" all use this function, so they always agree. Report-only
 * does not change the decision (the caller serves would-be refusals). A state other than
 * "disabled" or "active" refuses everyone.
 */
function ip_allowlist_decide(array $policy, array $client): array
{
    $refused = static fn (string $reason): array => ["decision" => "refused", "reason" => $reason, "matched" => null];
    $state = $policy["state"] ?? null;
    if ($state === "disabled") {
        return ["decision" => "disabled", "reason" => null, "matched" => null];
    }
    if ($state !== "active") {
        return $refused("config_error");
    }
    $problem = $client["problem"] ?? null;
    if ($problem !== null) {
        return $refused(in_array($problem, IP_ALLOWLIST_REASONS, true) ? $problem : "unknown_address");
    }
    $bin = $client["bin"] ?? null;
    if (!is_string($bin)) {
        return $refused("unknown_address");
    }
    $item = ip_allowlist_match($bin, is_array($policy["ranges"] ?? null) ? $policy["ranges"] : []);
    if ($item === null) {
        return $refused("not_listed");
    }
    return [
        "decision" => "allowed",
        "reason" => null,
        "matched" => ["label" => (string) $item["label"], "cidr" => (string) $item["range"]["cidr"]],
    ];
}

// ---------- Gate ----------

/**
 * The IP allowlist check, called by bootstrap right after local_config(): returns for allowed
 * clients (and while the allowlist is off or in the CLI), otherwise answers with
 * ip_allowlist_refuse() and ends the request. Fails closed: any Throwable refuses
 * ("check_failed"), unless report-only was already known to be on, in which case the request is
 * served and recorded with enforced=0 like every other would-be refusal.
 */
function ip_allowlist_enforce(): void
{
    if (PHP_SAPI === "cli") {
        return;
    }
    $client = ["ip" => null, "bin" => null, "peer" => "", "via_proxy" => false, "problem" => null];
    $reportOnly = false;
    $reason = "check_failed";
    try {
        $policy = ip_allowlist_policy();
        if ($policy["state"] === "disabled") {
            return;
        }
        $reportOnly = $policy["report_only"] === true;
        if ($policy["problems"] !== []) {
            ip_allowlist_warn("config", "IP allowlist: ip_allowlist has " . count($policy["problems"]) .
                " problem(s)" . ($policy["state"] === "deny_all" ? "; every request is refused" : "") .
                ". Run php index.php ip-allowlist to see them.");
        }
        $client = ip_allowlist_client();
        $decision = ip_allowlist_decide($policy, $client);
        if ($decision["decision"] !== "refused") {
            return;
        }
        $reason = (string) $decision["reason"];
    } catch (Throwable $e) {
        $reason = "check_failed";
        ip_allowlist_warn("error", "IP allowlist: the check failed (" . get_class($e) . ")");
    }
    if ($reportOnly) {
        // Known to be on before any failure: serve the request and record it.
        try {
            blocked_requests_record((string) (ip_allowlist_data_dir() ?? ""), $reason, $client, false);
        } catch (Throwable $e) {
            // Recording never changes the response.
        }
        return;
    }
    ip_allowlist_refuse($reason, $client); // fail closed, also when the policy itself failed
}

/**
 * The refusal: status 404 with the server's own reason phrase, an empty body and no header but
 * Content-Length: 0 from PHP, the same for every path, method, query, body, Host, cookie and
 * credential, so a refused client learns nothing but that the URL exists. No session, cookie
 * or data directory is created. The request is then recorded (best effort, after the response
 * is finished where the SAPI allows it) and the script ends.
 */
function ip_allowlist_refuse(string $reason, array $client): never
{
    try {
        if (function_exists("session_status") && session_status() === PHP_SESSION_ACTIVE) {
            @session_abort(); // session.auto_start
        }
    } catch (Throwable $e) {
        // The refusal below does not depend on it.
    }
    while (ob_get_level() > 0 && @ob_end_clean()) {
        // output_buffering, ob_gzhandler
    }
    $clean = !headers_sent();
    if ($clean) {
        @ini_set("zlib.output_compression", "0");
        @ini_set("default_mimetype", ""); // no default Content-Type
        header_remove(); // X-Powered-By, a queued Set-Cookie, everything
        http_response_code(404);
        header("Content-Length: 0");
    }
    try {
        if (function_exists("ignore_user_abort")) {
            ignore_user_abort(true);
        }
        if (function_exists("fastcgi_finish_request")) { // literal guards: tools/phpcheck.py
            @fastcgi_finish_request();
        } elseif (function_exists("litespeed_finish_request")) {
            @litespeed_finish_request();
        }
        $dir = ip_allowlist_data_dir();
        if ($dir !== null) {
            blocked_requests_record($dir, $reason, $client, true);
        }
    } catch (Throwable $e) {
        // Never changes the response.
    }
    if (!$clean) {
        ip_allowlist_warn("output", "IP allowlist: output was sent before the check (display_errors or display_startup_errors on in php.ini?), so a refusal could not be hidden");
    }
    exit();
}

// ---------- Console allowlist ----------

/**
 * The console IP allowlist policy ($policy shape), computed once (static cache), from
 * console_ip_allowlist (env OIDC_CONSOLE_IP_ALLOWLIST; same syntax as ip_allowlist, labels
 * included). "disabled" while it is empty; "active" with at least one valid entry; "deny_all"
 * when it is configured without a valid entry, or when config.php fails to load while
 * OIDC_CONSOLE_IP_ALLOWLIST is unset and config.php names console_ip_allowlist outside
 * comments. There is no report-only mode: report_only is always false.
 */
function console_ip_allowlist_policy(): array
{
    static $policy = null;
    if (is_array($policy)) {
        return $policy;
    }
    $loadError = null;
    local_config($loadError);
    $raw = config_value("console_ip_allowlist", "OIDC_CONSOLE_IP_ALLOWLIST");
    $file = dirname(__DIR__) . DIRECTORY_SEPARATOR . "config.php";
    if ($loadError === "unreadable") {
        $configPhp = "unreadable";
    } elseif ($loadError !== null) {
        $configPhp = "failed";
    } else {
        $configPhp = is_file($file) ? "loaded" : "absent";
    }
    $result = [
        "state" => "disabled",
        "report_only" => false,
        "source" => "none",
        "config_php" => $configPhp,
        "ranges" => [],
        "problems" => [],
    ];
    if ($raw === null && $loadError === null) {
        return $policy = $result;
    }
    if (env_string(["OIDC_CONSOLE_IP_ALLOWLIST"]) !== null) {
        $source = "env";
    } else {
        $source = $raw !== null ? "config" : "none";
    }
    if (
        $source === "none" &&
        $configPhp === "failed" &&
        ip_allowlist_config_mentions_key($file, "console_ip_allowlist")
    ) {
        $result["state"] = "deny_all";
        $result["source"] = "config";
        $result["problems"] = [
            "config.php does not load and sets console_ip_allowlist: the console is refused to every address until it loads again (check it with php -l config.php)",
        ];
        return $policy = $result;
    }
    $parsed = ip_allowlist_parse_setting($raw, "console_ip_allowlist");
    if ($parsed["configured"] && $parsed["ranges"] === []) {
        $result["state"] = "deny_all";
        $result["problems"] = array_merge($parsed["problems"], ["no usable entry: the console is refused to every address"]);
    } elseif ($parsed["configured"]) {
        $result["state"] = "active";
        $result["ranges"] = $parsed["ranges"];
        $result["problems"] = $parsed["problems"];
    }
    if ($result["state"] !== "disabled") {
        $result["source"] = $source;
    }
    return $policy = $result;
}

/**
 * The console IP allowlist check. Returns while console_ip_allowlist is off, in the CLI, and
 * for a client whose address (ip_allowlist_client(), resolved strictly) is listed; otherwise
 * answers with ip_allowlist_refuse(), the empty 404 of the site-wide allowlist, recorded in
 * Blocked Requests as console_not_listed (also for an address that cannot be resolved) or
 * console_config_error (no usable entry), and ends the request. Called before anything that
 * serves the console or uses a console session: render_admin_spa(), POST /api/login and
 * /api/logout, and current_user(). Requests with an Admin API client credential never reach
 * it. Fails closed (check_failed).
 */
function console_ip_allowlist_enforce(): void
{
    static $passed = false;
    if ($passed || PHP_SAPI === "cli") {
        return;
    }
    $client = ["ip" => null, "bin" => null, "peer" => "", "via_proxy" => false, "problem" => null];
    try {
        $policy = console_ip_allowlist_policy();
        if ($policy["state"] === "disabled") {
            $passed = true;
            return;
        }
        if ($policy["problems"] !== []) {
            ip_allowlist_warn("console_config", "Console IP allowlist: console_ip_allowlist has " . count($policy["problems"]) .
                " problem(s)" . ($policy["state"] === "deny_all" ? "; the console is refused to every address" : "") .
                ". Run php index.php ip-allowlist to see them.");
        }
        $client = ip_allowlist_client();
        $decision = ip_allowlist_decide($policy, $client);
        if ($decision["decision"] !== "refused") {
            $passed = true;
            return;
        }
        $reason = $decision["reason"] === "config_error" ? "console_config_error" : "console_not_listed";
    } catch (Throwable $e) {
        $reason = "check_failed";
        ip_allowlist_warn("console_error", "Console IP allowlist: the check failed (" . get_class($e) . ")");
    }
    ip_allowlist_refuse($reason, $client);
}

/**
 * The data directory, without creating anything: $CONFIG_DIR once bootstrap has resolved it,
 * otherwise (at gate time) the directory bootstrap_resolve_data_paths() would pick, if it
 * already exists, is writable and (unless allow_webroot_data_dir is on) is outside the web
 * root. Null when there is none. Never creates a directory or an .htaccess file.
 */
function ip_allowlist_data_dir(): ?string
{
    static $computed = false;
    static $dir = null;
    $resolved = $GLOBALS["CONFIG_DIR"] ?? null;
    if (is_string($resolved) && $resolved !== "") {
        return $resolved;
    }
    if ($computed) {
        return $dir;
    }
    $computed = true;
    $root = dirname(__DIR__);
    $legacy = config_flag("allow_webroot_data_dir", "OIDC_ALLOW_WEBROOT_DATA_DIR");
    $configured = config_value("config_dir", ["OIDC_CONFIG_DIR", "CONFIG_DIR"]);
    $candidates = [
        is_string($configured) && $configured !== ""
            ? $configured
            : path_join(dirname($root), basename($root) . "_config"),
    ];
    if ($legacy) {
        $candidates[] = path_join($root, ".data");
    }
    foreach ($candidates as $candidate) {
        if (@is_dir($candidate) && @is_writable($candidate) && ($legacy || !bootstrap_path_in_webroot($candidate))) {
            $dir = bootstrap_canonical_path($candidate);
            return $dir;
        }
    }
    return null;
}

/**
 * Writes "IdP: $message" to the PHP error log, at most once an hour per topic $id (the mtime of
 * <data dir>/ip-allowlist-<id>.warned). Without a data directory, or when the marker cannot be
 * written, a warning is logged with probability 1/1000, so a flood of refused requests cannot
 * flood the log. Does nothing in the CLI, so no root-owned marker can block the web server.
 * Messages are fixed text, counts and class names only, never request data or configuration
 * values. Never throws and never produces output.
 */
function ip_allowlist_warn(string $id, string $message): void
{
    if (PHP_SAPI === "cli" || preg_match('/^[a-z0-9_]{1,32}$/D', $id) !== 1) {
        return;
    }
    try {
        $dir = ip_allowlist_data_dir();
        if ($dir !== null) {
            $marker = path_join($dir, "ip-allowlist-" . $id . ".warned");
            $last = @filemtime($marker);
            if (is_int($last) && $last > time() - IP_ALLOWLIST_WARN_INTERVAL_SECONDS) {
                return;
            }
            if (@touch($marker)) {
                error_log("IdP: " . $message);
                return;
            }
        }
        if (random_int(1, 1000) === 1) {
            error_log("IdP: " . $message);
        }
    } catch (Throwable $e) {
        // A warning never fails the request.
    }
}

// ---------- Status and viewer access (route time) ----------

/**
 * Admits the caller of the IP allowlist API: a console session (Admin API clients get the 403
 * of auth_require_session_only()) of an administrator allowed by ip_allowlist_admins. Answers
 * 403 otherwise. Returns the administrator's name.
 */
function ip_allowlist_require_viewer(array $auth): string
{
    $owner = auth_require_session_only($auth);
    if (!ip_allowlist_admin_allowed($owner)) {
        json_response(403, [
            "error" => "Only the administrators listed in ip_allowlist_admins can open the IP allowlist and its blocked requests",
        ]);
    }
    return $owner;
}

/**
 * The GET /api/ip-allowlist document: the policy, the ranges, problems, warnings, the viewer's
 * own address and decision, trusted_proxies and the blocked-request log statistics (which also
 * prunes rows past the retention). Never contains a filesystem path.
 */
function ip_allowlist_status(string $configDir): array
{
    $policy = ip_allowlist_policy();
    $client = ip_allowlist_client();
    $decision = ip_allowlist_decide($policy, $client);
    $viewer = [
        "ip" => $client["ip"],
        "peer" => $client["peer"],
        "via_proxy" => $client["via_proxy"],
        "problem" => $client["problem"],
        "decision" => $decision["decision"],
        "reason" => $decision["reason"],
        "matched" => $decision["matched"],
        "suggested_entry" => is_string($client["bin"]) ? ip_allowlist_suggested_entry($client["bin"]) : null,
    ];
    try {
        $log = blocked_requests_stats($configDir);
    } catch (Throwable $e) {
        error_log("IdP: IP allowlist status: the blocked-request log statistics failed (" . get_class($e) . ": " . $e->getMessage() . ")");
        $log = ip_allowlist_log_placeholder(false);
    }
    $doc = ip_allowlist_status_document($policy, ip_allowlist_trusted_proxies(), $log, $viewer);
    $doc["console"] = ip_allowlist_console_status($client);
    return $doc;
}

/**
 * Assembles the status document from its parts. $viewer is null in the CLI: the document then
 * has no "viewer" key, and the warnings that depend on the web request or on the web server's
 * php.ini are left out.
 */
function ip_allowlist_status_document(array $policy, array $trusted, array $log, ?array $viewer): array
{
    $doc = [
        "state" => $policy["state"],
        "enforcing" => $policy["state"] !== "disabled" && !$policy["report_only"],
        "report_only" => $policy["report_only"],
        "source" => $policy["source"],
        "config_php" => $policy["config_php"],
        "ranges" => ip_allowlist_status_ranges($policy["ranges"]),
        "problems" => array_values($policy["problems"]),
        "warnings" => ip_allowlist_warnings($policy, $trusted, $log, $viewer),
    ];
    if ($viewer !== null) {
        $doc["viewer"] = $viewer;
    }
    $proxies = [];
    foreach (config_list("trusted_proxies", "OIDC_TRUSTED_PROXIES") as $entry) {
        $proxies[] = sanitize_label($entry, 64);
    }
    $doc["trusted_proxies"] = $proxies;
    $doc["log"] = $log;
    return $doc;
}

/** The ranges ($item list) of a policy as the status document shows them. */
function ip_allowlist_status_ranges(array $items): array
{
    $ranges = [];
    foreach ($items as $item) {
        $range = $item["range"];
        $notes = [];
        if ($range["normalized"]) {
            $notes[] = "host bits set: treated as " . $range["cidr"];
        }
        if ($range["bits"] === 0) {
            $notes[] = "matches every IPv" . $range["family"] . " address";
        }
        $ranges[] = [
            "label" => $item["label"],
            "entry" => $item["entry"],
            "cidr" => $range["cidr"],
            "family" => $range["family"],
            "prefix" => $range["bits"],
            "notes" => $notes,
        ];
    }
    return $ranges;
}

/**
 * The "console" part of the status document (console_ip_allowlist): state, source, ranges,
 * problems, warnings and, for the web request's $client (null in the CLI), the viewer's
 * decision with the reason code Blocked Requests would record (console_not_listed or
 * console_config_error). The warnings are those of ip_allowlist_warnings() that concern the
 * console ranges (a trusted proxy inside them, a range that covers every address) and, while
 * ip_allowlist is off (its own warnings then stop early), those about resolving the client
 * address (trusted_proxies covering everything or invalid, X-Forwarded-For ignored or missing).
 */
function ip_allowlist_console_status(?array $client): array
{
    $policy = console_ip_allowlist_policy();
    $out = [
        "state" => $policy["state"],
        "source" => $policy["source"],
        "ranges" => ip_allowlist_status_ranges($policy["ranges"]),
        "problems" => array_values($policy["problems"]),
        "warnings" => [],
    ];
    $viewer = null;
    if ($client !== null) {
        $decision = ip_allowlist_decide($policy, $client);
        $reason = $decision["reason"];
        if ($reason !== null) {
            $reason = $reason === "config_error" ? "console_config_error" : "console_not_listed";
        }
        $out["viewer"] = [
            "decision" => $decision["decision"],
            "reason" => $reason,
            "matched" => $decision["matched"],
        ];
        $viewer = ["peer" => $client["peer"], "ip" => $client["ip"], "decision" => $decision["decision"]];
    }
    if ($policy["state"] !== "disabled") {
        $codes = ["proxy_address_listed", "everything_range"];
        if (ip_allowlist_policy()["state"] === "disabled") {
            $codes = array_merge($codes, ["trusted_proxy_any", "trusted_proxy_invalid", "forwarded_for_ignored", "forwarded_for_missing"]);
        }
        $consolePolicy = ["state" => "active", "report_only" => false, "config_php" => "loaded"] + $policy;
        $warnings = ip_allowlist_warnings($consolePolicy, ip_allowlist_trusted_proxies(), ["enabled" => true], $viewer);
        foreach ($warnings as $warning) {
            if (in_array($warning["code"], $codes, true)) {
                $out["warnings"][] = $warning;
            }
        }
    }
    return $out;
}

/**
 * The entry to add for the packed address $ipBin: "a.b.c.d/32" for IPv4, the /64 network for
 * IPv6 (devices change address inside it). "" for anything else.
 */
function ip_allowlist_suggested_entry(string $ipBin): string
{
    if (strlen($ipBin) === 4) {
        return inet_ntop($ipBin) . "/32";
    }
    if (strlen($ipBin) === 16) {
        return inet_ntop(substr($ipBin, 0, 8) . str_repeat("\x00", 8)) . "/64";
    }
    return "";
}

/**
 * A log object (the "log" shape of blocked_requests_stats()) for when the statistics could not
 * be read: $available false after a failure; null when the file was deliberately not opened
 * (the CLI run by another user), in which case the counts are null (unknown) too.
 */
function ip_allowlist_log_placeholder(?bool $available): array
{
    $settings = [];
    try {
        $settings = blocked_requests_settings();
    } catch (Throwable $e) {
        // Defaults below.
    }
    $maxMb = is_int($settings["max_mb"] ?? null) ? $settings["max_mb"] : 32;
    $count = $available === null ? null : 0;
    return [
        "enabled" => ($settings["enabled"] ?? true) !== false,
        "available" => $available,
        "file_name" => "blocked_requests.sqlite",
        "size_bytes" => $count,
        "max_bytes" => $maxMb * 1048576,
        "retention_days" => is_int($settings["retention_days"] ?? null) ? $settings["retention_days"] : 30,
        "rows" => $count,
        "hits" => $count,
        "oldest" => null,
        "newest" => null,
    ];
}

/**
 * Warnings for the status page and the CLI, in a fixed order (configuration and the viewer's
 * own address first, deployment and log last):
 * list<array{code: string, level: "error"|"warning"|"info", message: string}>. While the
 * allowlist is disabled only config_php_unusable is computed. $viewer is the status "viewer"
 * object, or null in the CLI, which leaves out the warnings about the viewer's own request,
 * htaccess_outdated and php_display_errors (its context and php.ini differ from the web
 * server's). Messages hold no filesystem paths.
 */
function ip_allowlist_warnings(array $policy, array $trusted, array $log, ?array $viewer): array
{
    $warnings = [];
    $add = static function (string $code, string $level, string $message) use (&$warnings): void {
        $warnings[] = ["code" => $code, "level" => $level, "message" => $message];
    };
    $state = $policy["state"] ?? "disabled";
    $reportOnly = ($policy["report_only"] ?? false) === true;
    $configPhp = $policy["config_php"] ?? "absent";

    if ($configPhp === "unreadable" || $configPhp === "failed") {
        $loadError = null;
        local_config($loadError);
        if ($configPhp === "unreadable") {
            $why = "it is not readable by the PHP process";
        } elseif ($loadError === "not_array") {
            $why = "it does not return an array";
        } else {
            $why = "it does not load: a syntax error or an exception";
        }
        // deny_all without a source: config.php fails while it sets ip_allowlist.
        $deniesAll = $state === "deny_all" && ($policy["source"] ?? "") === "none";
        $add(
            "config_php_unusable",
            "error",
            "config.php is ignored (" . $why . "): none of its settings apply" .
                ($deniesAll
                    ? ", and because it sets ip_allowlist every request is refused until it loads again"
                    : ", including ip_allowlist") .
                ". " .
                ($configPhp === "unreadable"
                    ? "Make it readable by the web server user."
                    : "Check it with php -l config.php.")
        );
    }
    if ($state === "disabled") {
        return $warnings;
    }

    $problems = is_array($policy["problems"] ?? null) ? $policy["problems"] : [];
    if ($problems !== []) {
        $refusedAll = "";
        if ($state === "deny_all") {
            $refusedAll = $reportOnly
                ? "; every request would be refused once report-only is off"
                : "; every request is refused";
        }
        $add(
            "config_problems",
            "error",
            count($problems) . " problem(s) in ip_allowlist (listed below); unusable entries are ignored" . $refusedAll . "."
        );
    }

    if ($viewer !== null && ($viewer["decision"] ?? "") === "refused") {
        $reason = (string) ($viewer["reason"] ?? "");
        $who = is_string($viewer["ip"] ?? null) ? "Your address " . $viewer["ip"] : "Your request";
        $message = $who . " would be refused once report-only is off (" . $reason . ").";
        $suggested = $viewer["suggested_entry"] ?? null;
        if ($reason === "not_listed" && is_string($suggested) && $suggested !== "") {
            $message .= " Add " . $suggested . " first.";
        } elseif ($reason === "config_error") {
            $message .= " Fix the problems listed below first.";
        } elseif ($reason === "bad_forwarded_for") {
            $message .= " The proxy " . (string) ($viewer["peer"] ?? "") . " sent an X-Forwarded-For header with a" .
                " malformed entry or more than " . IP_ALLOWLIST_MAX_FORWARDED_HOPS . " entries.";
        } elseif ($reason === "unknown_address") {
            $message .= " The web server did not pass an IP address in REMOTE_ADDR.";
        }
        $add("viewer_not_allowed", "error", $message);
    }

    $any = is_array($trusted["any"] ?? null) ? $trusted["any"] : [];
    if ($any !== []) {
        $many = count($any) > 1;
        $add(
            "trusted_proxy_any",
            "error",
            "trusted_proxies contains " . implode(", ", $any) . ", which " . ($many ? "let" : "lets") .
                " any client set its address with X-Forwarded-For; the IP allowlist ignores " .
                ($many ? "them" : "it") . "."
        );
    }
    $invalid = is_array($trusted["invalid"] ?? null) ? $trusted["invalid"] : [];
    if ($invalid !== []) {
        $add(
            "trusted_proxy_invalid",
            "warning",
            "These trusted_proxies entries are not addresses or CIDR blocks and the IP allowlist ignores them: " .
                implode(", ", $invalid)
        );
    }

    $trustedRanges = is_array($trusted["ranges"] ?? null) ? $trusted["ranges"] : [];
    if ($viewer !== null) {
        $header = $_SERVER["HTTP_X_FORWARDED_FOR"] ?? null;
        $hasForwardedFor = is_string($header) && trim($header) !== "";
        $peer = (string) ($viewer["peer"] ?? "");
        $peerBin = bootstrap_ip_bytes($peer);
        $peerTrusted = $peerBin !== null && ip_allowlist_match($peerBin, $trustedRanges) !== null;
        if ($hasForwardedFor && $peerBin !== null && !$peerTrusted) {
            $allowed = ($viewer["decision"] ?? "") === "allowed";
            $add(
                "forwarded_for_ignored",
                $allowed ? "error" : "warning",
                "Your request came through " . $peer . " with X-Forwarded-For, but " . $peer .
                    " is not in trusted_proxies: every client behind it counts as " . $peer .
                    ($allowed ? " and is allowed" : "") . "."
            );
        } elseif ($peerTrusted && !$hasForwardedFor) {
            $add(
                "forwarded_for_missing",
                "warning",
                "Your request came through the trusted proxy " . $peer . " without X-Forwarded-For, so it" .
                    " counts as the proxy's own request. Make the proxy append X-Forwarded-For."
            );
        }
    }

    $allowedRanges = is_array($policy["ranges"] ?? null) ? $policy["ranges"] : [];
    foreach ($trustedRanges as $proxy) {
        foreach ($allowedRanges as $item) {
            if (!ip_allowlist_ranges_overlap($proxy["range"], $item["range"])) {
                continue;
            }
            $inside = $proxy["range"]["bits"] >= $item["range"]["bits"];
            $add(
                "proxy_address_listed",
                "warning",
                "The trusted proxy " . $proxy["entry"] . ($inside ? " is inside" : " overlaps") .
                    " the allowed range " . $item["range"]["cidr"] .
                    ($item["label"] !== "" ? " (" . $item["label"] . ")" : "") .
                    ": requests it sends without X-Forwarded-For are allowed."
            );
            break;
        }
    }

    $families = [];
    foreach ($allowedRanges as $item) {
        $families[$item["range"]["family"]] = true;
        if ($item["range"]["bits"] === 0) {
            $add(
                "everything_range",
                "warning",
                $item["range"]["cidr"] . " allows every IPv" . $item["range"]["family"] . " address."
            );
        }
    }
    if ($state === "active") {
        $refused = $reportOnly ? "would be refused" : "are refused";
        if (!isset($families[6])) {
            $add(
                "no_ipv6_range",
                "warning",
                "No IPv6 range is listed: clients reaching this server over IPv6 " . $refused . ". If the" .
                    " host name has an AAAA record, list your IPv6 networks (at least each /64)."
            );
        }
        if (!isset($families[4])) {
            $add(
                "no_ipv4_range",
                "warning",
                "No IPv4 range is listed: clients reaching this server over IPv4 " . $refused . ". If the" .
                    " host name has an A record, list your IPv4 networks."
            );
        }
    }

    if ($reportOnly) {
        $add("report_only", "info", "Report-only: nothing is refused; would-be refusals are recorded.");
    }

    if ($viewer !== null && ip_allowlist_htaccess_outdated()) {
        $add(
            "htaccess_outdated",
            "warning",
            "The web-root .htaccess predates the IP allowlist: the web server still answers favicon.ico" .
                " and its own 403 pages for refused addresses, which identifies this site. Update it from" .
                " htaccess.example."
        );
    }
    if ($viewer !== null && ip_allowlist_php_displays_errors()) {
        $add(
            "php_display_errors",
            "warning",
            "php.ini displays errors (display_errors or display_startup_errors): startup warnings (for" .
                " example for an oversized POST) are printed before the allowlist check and show refused" .
                " clients that this is PHP. Set both to Off in php.ini."
        );
    }

    if (($log["enabled"] ?? true) === false) {
        $add("log_disabled", "info", "ip_allowlist_log is false: refused requests are not recorded.");
    } elseif (($log["available"] ?? null) === false) {
        $add(
            "log_unavailable",
            "warning",
            "Refused requests cannot be recorded (data directory or blocked_requests.sqlite not writable;" .
                " see the PHP error log)."
        );
    }
    return $warnings;
}

/**
 * Under Apache or LiteSpeed (SERVER_SOFTWARE), is the web-root .htaccess older than the IP
 * allowlist? True when it is missing or unreadable, lacks an active (not commented out)
 * "ErrorDocument 403 ...index.php" or "ErrorDocument 404 ...index.php" line, or still has an
 * active "RewriteRule ^favicon..." line, so the web server itself would answer favicon.ico and
 * its own 403 pages for refused addresses.
 */
function ip_allowlist_htaccess_outdated(): bool
{
    $software = $_SERVER["SERVER_SOFTWARE"] ?? "";
    if (!is_string($software) || preg_match('/apache|litespeed/i', $software) !== 1) {
        return false;
    }
    $file = dirname(__DIR__) . DIRECTORY_SEPARATOR . ".htaccess";
    $src = @is_file($file) ? @file_get_contents($file, false, null, 0, 1048576) : false;
    if (!is_string($src)) {
        return true;
    }
    foreach (["403", "404"] as $status) {
        if (preg_match('/^[ \t]*ErrorDocument[ \t]+' . $status . '[ \t]+"?[^\s"]*index\.php"?[ \t\r]*$/mi', $src) !== 1) {
            return true;
        }
    }
    return preg_match('/^[ \t]*RewriteRule[ \t]+"?\^\/?favicon/mi', $src) === 1;
}

/**
 * Does php.ini itself (the global value, which bootstrap's ini_set() calls do not change)
 * display errors? PHP prints startup warnings before any script runs, so such a setting shows
 * refused clients that this is PHP. Off means "", "0", "off", "false" or "no".
 */
function ip_allowlist_php_displays_errors(): bool
{
    if (!function_exists("ini_get_all")) {
        return false;
    }
    $all = @ini_get_all(null, true);
    if (!is_array($all)) {
        return false;
    }
    foreach (["display_errors", "display_startup_errors"] as $name) {
        $value = $all[$name]["global_value"] ?? null;
        if (is_scalar($value) && !in_array(strtolower(trim((string) $value)), ["", "0", "off", "false", "no"], true)) {
            return true;
        }
    }
    return false;
}

// ---------- Command line: php index.php ip-allowlist ... ----------

/**
 * The "ip-allowlist" command line (run it as the web server user), for lockout diagnosis and
 * deploy checks. $args are the arguments after "ip-allowlist".
 *   [status] [--json]   the policy, ranges, problems, warnings and log statistics; --json prints
 *                       the status document without "viewer". Exit 0, or 1 when there are
 *                       problems, every request is refused or config.php is ignored (it does
 *                       not load or cannot be read): a pre-flight check.
 *   check <ip>          whether <ip> gets in, and why. Exit 0 allowed or off, 1 refused or
 *                       would be refused (report-only), 2 when <ip> is not an IP address.
 *   recent [--limit=N]  the newest N refused-request rows (default 20, 1..500), tab-separated.
 *                       Exit 0, 1 when the log cannot be read, 2 for a bad --limit.
 * Anything else prints the usage text (exit 2). It never creates blocked_requests.sqlite or
 * marker files, and it opens the log only as the file's owner.
 */
function ip_allowlist_cli(array $args, string $configDir): int
{
    $positional = [];
    $options = [];
    foreach ($args as $arg) {
        $arg = is_scalar($arg) ? (string) $arg : "";
        if (str_starts_with($arg, "--")) {
            $options[] = $arg;
        } else {
            $positional[] = $arg;
        }
    }
    $command = $positional[0] ?? "status";
    if ($command === "status" && count($positional) <= 1 && array_diff($options, ["--json"]) === []) {
        return ip_allowlist_cli_status(in_array("--json", $options, true), $configDir);
    }
    if ($command === "check" && count($positional) === 2 && $options === []) {
        return ip_allowlist_cli_check($positional[1]);
    }
    if ($command === "recent" && count($positional) === 1 && count($options) <= 1) {
        $limit = 20;
        $option = $options[0] ?? null;
        if ($option !== null && str_starts_with($option, "--limit=")) {
            if (preg_match('/^--limit=(\d{1,3})$/D', $option, $m) !== 1 || (int) $m[1] < 1 || (int) $m[1] > 500) {
                ip_allowlist_cli_print("--limit must be a whole number from 1 to 500", true);
                return 2;
            }
            $limit = (int) $m[1];
            $option = null;
        }
        if ($option === null) {
            return ip_allowlist_cli_recent($limit, $configDir);
        }
    }
    ip_allowlist_cli_print(implode(PHP_EOL, [
        "Usage: php index.php ip-allowlist [status] [--json]",
        "       php index.php ip-allowlist check <ip>",
        "       php index.php ip-allowlist recent [--limit=N]",
        "",
        "  status   the IP allowlist (ip_allowlist in config.php or OIDC_IP_ALLOWLIST), its problems",
        "           and the blocked-request log; exit code 1 when there are problems, every request",
        "           is refused or config.php does not load. --json prints the status as JSON.",
        "  check    whether <ip> gets in, and why; exit code 0 allowed (or the list is off), 1 refused.",
        "  recent   the newest refused requests, tab-separated (N from 1 to 500, default 20).",
        "",
        "Run it as the web server user. OIDC_IP_ALLOWLIST_REPORT_ONLY=1 stops refusing at once.",
    ]), true);
    return 2;
}

/**
 * Writes one line to standard output, or to standard error with $toStderr.
 */
function ip_allowlist_cli_print(string $text, bool $toStderr = false): void
{
    if ($toStderr) {
        $stream = defined("STDERR") ? STDERR : @fopen("php://stderr", "wb");
    } else {
        $stream = defined("STDOUT") ? STDOUT : @fopen("php://stdout", "wb");
    }
    if (is_resource($stream)) {
        fwrite($stream, $text . PHP_EOL);
    }
}

/**
 * Null when the CLI may open blocked_requests.sqlite, otherwise why not. Opened by another
 * user (typically root), SQLite would leave -wal and -shm files that the web server cannot
 * write, which would stop it from recording; so only the file's owner reads it. A missing file
 * is fine: the store does not create it for readers.
 */
function ip_allowlist_cli_log_access(string $configDir): ?string
{
    $file = blocked_requests_path($configDir);
    if (function_exists("posix_geteuid") && @file_exists($file)) {
        $owner = @fileowner($file);
        if (!is_int($owner) || posix_geteuid() !== $owner) {
            return "run this as the owner of blocked_requests.sqlite (the web server user) to read the log";
        }
    }
    return null;
}

/**
 * "ip-allowlist [status] [--json]".
 */
function ip_allowlist_cli_status(bool $json, string $configDir): int
{
    $policy = ip_allowlist_policy();
    $logNote = null;
    try {
        $logNote = ip_allowlist_cli_log_access($configDir);
        $log = $logNote === null ? blocked_requests_stats($configDir, false) : ip_allowlist_log_placeholder(null);
    } catch (Throwable $e) {
        $logNote = "the blocked-request log cannot be read: " . sanitize_label($e->getMessage(), 500);
        $log = ip_allowlist_log_placeholder(false);
    }
    $doc = ip_allowlist_status_document($policy, ip_allowlist_trusted_proxies(), $log, null);
    $doc["console"] = ip_allowlist_console_status(null);
    // Also 1 while config.php is ignored (it does not load or cannot be read): none of its
    // settings apply, and the scan for ip_allowlist in a broken file is a heuristic, so a
    // pre-flight check must not pass whatever state it shows. The console allowlist counts
    // the same way.
    $exit = $policy["problems"] !== [] || $policy["state"] === "deny_all" ||
        $doc["console"]["problems"] !== [] || $doc["console"]["state"] === "deny_all" ||
        in_array($policy["config_php"], ["failed", "unreadable"], true) ? 1 : 0;

    if ($json) {
        $encoded = json_encode($doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        ip_allowlist_cli_print(is_string($encoded) ? $encoded : "{}");
        if ($logNote !== null) {
            ip_allowlist_cli_print("Log: " . $logNote, true);
        }
        return $exit;
    }

    $reportOnly = $policy["report_only"] === true;
    $state = match ($policy["state"]) {
        "disabled" => "disabled (ip_allowlist is empty: every address is served)",
        "active" => $reportOnly ? "report-only (nothing is refused; would-be refusals are recorded)" : "enforcing",
        default => $reportOnly
            ? "report-only, but every request would be refused (nothing is refused yet)"
            : "refusing every request",
    };
    $lines = [
        "IP allowlist: " . $state,
        "Source: " . match ($policy["source"]) {
            "env" => "the environment (OIDC_IP_ALLOWLIST; it replaces ip_allowlist in config.php)",
            "config" => "config.php (ip_allowlist)",
            default => "none",
        },
        "config.php: " . match ($policy["config_php"]) {
            "loaded" => "loaded",
            "unreadable" => "not readable (ignored)",
            "failed" => "does not load (ignored; check it with php -l config.php)",
            default => "absent",
        },
    ];
    if ($doc["warnings"] !== []) {
        $lines[] = "Warnings:";
        foreach ($doc["warnings"] as $warning) {
            $lines[] = "  " . $warning["level"] . " (" . $warning["code"] . "): " . $warning["message"];
        }
    }
    $lines[] = "Ranges: " . count($doc["ranges"]);
    foreach ($doc["ranges"] as $range) {
        $line = "  " . str_pad($range["cidr"], 44) . ($range["label"] !== "" ? $range["label"] : "-");
        if ($range["notes"] !== []) {
            $line .= "  (" . implode("; ", $range["notes"]) . ")";
        }
        $lines[] = $line;
    }
    $lines[] = "Problems: " . count($doc["problems"]);
    foreach ($doc["problems"] as $problem) {
        $lines[] = "  - " . $problem;
    }
    $console = $doc["console"];
    $lines[] = "Console allowlist: " . match ($console["state"]) {
        "disabled" => "disabled (console_ip_allowlist is empty: the console is served wherever ip_allowlist allows)",
        "active" => "enforcing",
        default => "refusing the console to every address",
    } . match ($console["source"]) {
        "env" => " (source: OIDC_CONSOLE_IP_ALLOWLIST)",
        "config" => " (source: config.php)",
        default => "",
    };
    foreach ($console["ranges"] as $range) {
        $lines[] = "  " . str_pad($range["cidr"], 44) . ($range["label"] !== "" ? $range["label"] : "-");
    }
    foreach ($console["problems"] as $problem) {
        $lines[] = "  - problem: " . $problem;
    }
    $lines[] = "Trusted proxies: " . ($doc["trusted_proxies"] === [] ? "none" : implode(", ", $doc["trusted_proxies"]));
    if ($logNote !== null) {
        $lines[] = "Log: " . $logNote;
    } elseif (($log["enabled"] ?? true) === false) {
        $lines[] = "Log: off (ip_allowlist_log is false)";
    } else {
        $int = static fn (mixed $v): int => is_int($v) ? $v : 0;
        $lines[] = sprintf(
            "Log: %s%d rows, %d requests, oldest %s, newest %s; %.1f of %.0f MiB; rows are kept %d days",
            ($log["available"] ?? true) === false ? "not writable (see the PHP error log); " : "",
            $int($log["rows"] ?? 0),
            $int($log["hits"] ?? 0),
            is_string($log["oldest"] ?? null) ? $log["oldest"] : "-",
            is_string($log["newest"] ?? null) ? $log["newest"] : "-",
            $int($log["size_bytes"] ?? 0) / 1048576,
            $int($log["max_bytes"] ?? 0) / 1048576,
            $int($log["retention_days"] ?? 0)
        );
    }
    foreach ($lines as $line) {
        ip_allowlist_cli_print($line);
    }
    return $exit;
}

/**
 * "ip-allowlist check <ip>".
 */
function ip_allowlist_cli_check(string $ip): int
{
    $client = ip_allowlist_client_for_ip($ip);
    if ($client === null) {
        ip_allowlist_cli_print("not an IP address: " . sanitize_label($ip, 64), true);
        return 2;
    }
    $policy = ip_allowlist_policy();
    $decision = ip_allowlist_decide($policy, $client);
    if ($policy["problems"] !== []) {
        ip_allowlist_cli_print(
            "note: ip_allowlist has " . count($policy["problems"]) . " problem(s); run php index.php ip-allowlist to see them",
            true
        );
    }
    // The console allowlist is reported on its own line; the exit code follows ip_allowlist.
    $consoleDecision = ip_allowlist_decide(console_ip_allowlist_policy(), $client);
    $consoleLine = "console: " . match ($consoleDecision["decision"]) {
        "disabled" => "allowed (the console allowlist is off)",
        "allowed" => "allowed by " . $consoleDecision["matched"]["cidr"] .
            ($consoleDecision["matched"]["label"] !== "" ? " (" . $consoleDecision["matched"]["label"] . ")" : ""),
        default => "refused: " . ($consoleDecision["reason"] === "config_error" ? "console_config_error" : "console_not_listed"),
    };
    if ($decision["decision"] === "disabled") {
        ip_allowlist_cli_print("allowed: the IP allowlist is off");
        ip_allowlist_cli_print($consoleLine);
        return 0;
    }
    if ($decision["decision"] === "allowed") {
        $matched = $decision["matched"];
        ip_allowlist_cli_print(
            "allowed by " . $matched["cidr"] . ($matched["label"] !== "" ? " (" . $matched["label"] . ")" : "")
        );
        ip_allowlist_cli_print($consoleLine);
        return 0;
    }
    ip_allowlist_cli_print(
        ($policy["report_only"] === true ? "would be refused (report-only): " : "refused: ") . (string) $decision["reason"]
    );
    ip_allowlist_cli_print($consoleLine);
    return 1;
}

/**
 * "ip-allowlist recent [--limit=N]": the newest rows, newest first, one per line:
 * last_seen, address_key, hits, reason (" (report-only)" when not enforced), last_request,
 * user_agent, separated by tabs. The store cleaned the values when it wrote them; they are
 * cleaned again here, so no stored text can reach the terminal as a control sequence.
 */
function ip_allowlist_cli_recent(int $limit, string $configDir): int
{
    try {
        $denied = ip_allowlist_cli_log_access($configDir);
        if ($denied !== null) {
            ip_allowlist_cli_print($denied, true);
            return 1;
        }
        $page = blocked_requests_list(
            $configDir,
            ["ip" => null, "since" => null, "until" => null, "reason" => null, "enforced" => null],
            $limit,
            null
        );
    } catch (Throwable $e) {
        ip_allowlist_cli_print("the blocked-request log cannot be read: " . sanitize_label($e->getMessage(), 500), true);
        return 1;
    }
    $entries = is_array($page["entries"] ?? null) ? $page["entries"] : [];
    $cell = static fn (mixed $value, int $max): string =>
        is_scalar($value) ? sanitize_label((string) $value, $max) : "";
    foreach ($entries as $entry) {
        $enforced = $entry["enforced"] ?? true;
        $reportOnly = $enforced === false || $enforced === 0 || $enforced === "0";
        ip_allowlist_cli_print(implode("\t", [
            $cell($entry["last_seen"] ?? "", 32),
            $cell($entry["address_key"] ?? "", 64),
            $cell($entry["hits"] ?? "", 20),
            $cell($entry["reason"] ?? "", 32) . ($reportOnly ? " (report-only)" : ""),
            $cell($entry["last_request"] ?? "", 300),
            $cell($entry["user_agent"] ?? "", 200),
        ]));
    }
    if ($entries === []) {
        ip_allowlist_cli_print("no refused requests are recorded", true);
    }
    return 0;
}
