<?php
declare(strict_types=1);

// ============================================================================
// Blocked requests: the record of the requests the IP allowlist refused
//
// <data dir>/blocked_requests.sqlite, a SQLite file with a PDO connection of its
// own. It never uses storage_db(), which waits 5 s for locks, creates directories
// and runs migrations; db.php is not even loaded when the IP allowlist check runs.
// One row per hour, client address (an IPv6 /64), reason and enforcement
// (report-only rows have enforced = 0), with the number of requests and the first
// and the last one: method and path, never the query string. Rows whose last
// request is older than ip_allowlist_log_retention_days are pruned, and the file
// never grows past ip_allowlist_log_max_mb (PRAGMA max_page_count): when it is
// full, the oldest rows make room. Read by the console and the Admin API
// (src/routes_api.php: GET and DELETE /api/ip-allowlist/blocked-requests, the log
// section of GET /api/ip-allowlist) and by "php index.php ip-allowlist".
//
// Loaded by bootstrap with src/ip_allowlist.php, before the IP allowlist check:
// this file only defines constants and functions. blocked_requests_record() and
// what it calls run inside that check, before db.php and admin_clients.php are
// loaded and before the data directory is resolved, so they use only
// config_value(), config_flag(), sanitize_label(), path_join() and
// ip_allowlist_warn(); blocked_requests_record() never throws and never prints.
// The functions for the console and the API throw RuntimeException (PDOException
// included) before any output when the log cannot be opened or read; a missing
// file means empty results.
// ============================================================================

/** File name of the log inside the data directory (config_dir). */
const BLOCKED_REQUESTS_FILE = "blocked_requests.sqlite";

/** Longest lock wait of a refused request's write, in ms: a refusal never queues for long. */
const BLOCKED_REQUESTS_BUSY_MS = 50;

/** Longest lock wait of the console, the Admin API and the command line, in ms. */
const BLOCKED_REQUESTS_ADMIN_BUSY_MS = 2000;

/** One recorded refusal in this many also prunes rows past the retention. */
const BLOCKED_REQUESTS_PRUNE_ONE_IN = 50;

/** Most rows past the retention that one prune deletes. */
const BLOCKED_REQUESTS_PRUNE_BATCH = 500;

/** Oldest rows deleted when the file has reached ip_allowlist_log_max_mb. */
const BLOCKED_REQUESTS_ROOM_BATCH = 1000;

/** Most rows of one page of GET /api/ip-allowlist/blocked-requests. */
const BLOCKED_REQUESTS_LIST_MAX = 500;

/** Most rows of one CSV export (the newest). */
const BLOCKED_REQUESTS_CSV_MAX_ROWS = 100000;

/** Rows a CSV export reads per query. */
const BLOCKED_REQUESTS_CSV_BATCH = 1000;

/** Size the write-ahead log (-wal) is cut back to after a checkpoint (PRAGMA journal_size_limit). */
const BLOCKED_REQUESTS_WAL_LIMIT_BYTES = 4194304;

/** Header row of the CSV export (enforced is 1 or 0; times are UTC). */
const BLOCKED_REQUESTS_CSV_COLUMNS = [
    "id",
    "hour_start_utc",
    "first_seen_utc",
    "last_seen_utc",
    "hits",
    "address",
    "address_key",
    "peer_address",
    "forwarded_for",
    "reason",
    "enforced",
    "first_method",
    "first_path",
    "last_method",
    "last_path",
    "host",
    "user_agent",
];

// ---------- Settings ----------

/**
 * The log settings, read at the point of use: enabled (ip_allowlist_log, env
 * OIDC_IP_ALLOWLIST_LOG, default true), retention_days (ip_allowlist_log_retention_days,
 * 1..365, default 30) and max_mb (ip_allowlist_log_max_mb, 1..1024, default 32).
 *
 * @return array{enabled: bool, retention_days: int, max_mb: int}
 */
function blocked_requests_settings(): array
{
    return [
        "enabled" => config_flag("ip_allowlist_log", "OIDC_IP_ALLOWLIST_LOG", true),
        "retention_days" => blocked_requests_int_setting(
            "ip_allowlist_log_retention_days",
            "OIDC_IP_ALLOWLIST_LOG_RETENTION_DAYS",
            30,
            1,
            365
        ),
        "max_mb" => blocked_requests_int_setting(
            "ip_allowlist_log_max_mb",
            "OIDC_IP_ALLOWLIST_LOG_MAX_MB",
            32,
            1,
            1024
        ),
    ];
}

/**
 * A whole-number setting, read like max_passkeys_per_user: a config.php int, or digits
 * only (at most 9) from the environment or config.php, clamped to $min..$max. Unset gives
 * $default; any other value gives $default and a throttled PHP error log line, which names
 * the setting but never quotes its value.
 */
function blocked_requests_int_setting(string $key, string $env, int $default, int $min, int $max): int
{
    $value = config_value($key, $env);
    if (is_string($value) && preg_match('/^\d{1,9}$/D', $value) === 1) {
        $value = (int) $value;
    }
    if (is_int($value)) {
        return max($min, min($max, $value));
    }
    if ($value !== null) {
        $warnId = match ($key) {
            "ip_allowlist_log_retention_days" => "log_retention",
            "ip_allowlist_log_max_mb" => "log_max_mb",
            default => "log_setting",
        };
        ip_allowlist_warn(
            $warnId,
            "IP allowlist: " . $key . " is not a whole number; using " . $default
        );
    }
    return $default;
}

// ---------- File, connection and schema ----------

/** Path of the log in the data directory $dataDir. */
function blocked_requests_path(string $dataDir): string
{
    return path_join($dataDir, BLOCKED_REQUESTS_FILE);
}

/**
 * Opens the log $file with a connection of its own, waiting at most $busyMs for locks and
 * capped at $maxMb MiB. Without $create a missing file gives null (nothing is created).
 * Throws RuntimeException (PDOException included) when the file cannot be opened: without
 * pdo_sqlite, when the path exists but is not a regular file, or on the command line when
 * the file belongs to another user. Such a reader (typically root) could otherwise leave
 * -wal and -shm files of its own behind, which would stop the web server from recording.
 */
function blocked_requests_open(string $file, int $busyMs, bool $create, int $maxMb): ?PDO
{
    if (!is_file($file)) {
        if (file_exists($file)) {
            throw new RuntimeException(BLOCKED_REQUESTS_FILE . " is not a regular file");
        }
        if (!$create) {
            return null;
        }
    } elseif (PHP_SAPI === "cli" && function_exists("posix_geteuid")) {
        $owner = @fileowner($file);
        if (is_int($owner) && posix_geteuid() !== $owner) {
            throw new RuntimeException(
                "run this as the owner of " . BLOCKED_REQUESTS_FILE . " (the web server user) to read the log"
            );
        }
    }
    if (!extension_loaded("pdo_sqlite")) {
        throw new RuntimeException("the PDO SQLite extension (pdo_sqlite) is required for " . BLOCKED_REQUESTS_FILE);
    }
    $pdo = new PDO("sqlite:" . $file, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    // First, so no later statement waits longer than $busyMs (PDO's own default is 60 s).
    $pdo->exec("PRAGMA busy_timeout = " . max(0, $busyMs));
    try {
        $pdo->exec("PRAGMA journal_mode = WAL");
    } catch (PDOException $e) {
        // Keeps the default rollback journal: slower under load, still correct.
    }
    $pdo->exec("PRAGMA synchronous = NORMAL");
    $pdo->exec("PRAGMA journal_size_limit = " . BLOCKED_REQUESTS_WAL_LIMIT_BYTES);
    // Deleted rows (pruned, purged, made room for) are overwritten, not left in free pages.
    $pdo->exec("PRAGMA secure_delete = ON");
    // The size cap holds for this connection only, so every open sets it. A full file
    // raises SQLITE_FULL (errorInfo[1] 13), which blocked_requests_record() answers by
    // deleting the oldest rows. It cannot be set below the current size: a lowered cap
    // takes effect as space is reused.
    $pageSize = (int) $pdo->query("PRAGMA page_size")->fetchColumn();
    $pageSize = $pageSize > 0 ? $pageSize : 4096;
    $pdo->exec("PRAGMA max_page_count = " . max(1, intdiv(max(1, $maxMb) * 1048576, $pageSize)));
    // Owner only. -wal and -shm files that SQLite creates later copy this mode.
    foreach (["", "-wal", "-shm"] as $suffix) {
        $perms = is_file($file . $suffix) ? @fileperms($file . $suffix) : false;
        if (is_int($perms) && ($perms & 0777) !== 0600) {
            @chmod($file . $suffix, 0600);
        }
    }
    return $pdo;
}

/**
 * Creates the table and its indexes when they are missing (idempotent), in one
 * transaction, so a failure never leaves a table without the bucket index that the
 * write's ON CONFLICT needs. Only the write path calls it; readers treat a missing table
 * as an empty log.
 */
function blocked_requests_schema(PDO $pdo): void
{
    $pdo->exec("BEGIN IMMEDIATE");
    try {
        // hour: Unix time / 3600. ip_key: "203.0.113.9", "2001:db8:1:2::/64" or "unknown".
        // key_bin: 4 bytes (IPv4), 16 bytes (the IPv6 /64, low 8 bytes zero) or '' (unknown).
        $pdo->exec(
            "CREATE TABLE IF NOT EXISTS blocked_requests (
                id INTEGER PRIMARY KEY,
                hour INTEGER NOT NULL,
                ip_key TEXT NOT NULL,
                key_bin BLOB NOT NULL,
                ip TEXT NOT NULL DEFAULT '', peer_ip TEXT NOT NULL DEFAULT '', forwarded_for TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL, enforced INTEGER NOT NULL DEFAULT 1, hits INTEGER NOT NULL DEFAULT 1,
                first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                first_method TEXT NOT NULL DEFAULT '', first_path TEXT NOT NULL DEFAULT '',
                last_method TEXT NOT NULL DEFAULT '', last_path TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '')"
        );
        $pdo->exec(
            "CREATE UNIQUE INDEX IF NOT EXISTS ux_blocked_requests_bucket " .
                "ON blocked_requests(hour, ip_key, reason, enforced)"
        );
        $pdo->exec("CREATE INDEX IF NOT EXISTS ix_blocked_requests_key ON blocked_requests(key_bin)");
        $pdo->exec("CREATE INDEX IF NOT EXISTS ix_blocked_requests_last_seen ON blocked_requests(last_seen)");
        $pdo->exec("PRAGMA user_version = 1");
        $pdo->exec("COMMIT");
    } catch (Throwable $e) {
        try {
            $pdo->exec("ROLLBACK");
        } catch (Throwable $ignored) {
            // The transaction already ended with the error.
        }
        throw $e;
    }
}

/** Does the log's table exist? (Reads never create it.) */
function blocked_requests_table_exists(PDO $pdo): bool
{
    return $pdo->query(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'blocked_requests'"
    )->fetchColumn() !== false;
}

/**
 * Binds $params and executes $stmt: placeholders whose name ends in "_bin" as BLOB (TEXT
 * would sort before every BLOB and break the address range filter), int and bool as
 * INTEGER, null as NULL, anything else as TEXT. (storage_execute() is in db.php, which is
 * not loaded when the IP allowlist check records a refusal.)
 */
function blocked_requests_execute(PDOStatement $stmt, array $params): PDOStatement
{
    foreach ($params as $name => $value) {
        $name = (string) $name;
        if (is_bool($value)) {
            $value = $value ? 1 : 0;
        }
        if (str_ends_with($name, "_bin")) {
            $stmt->bindValue($name, (string) $value, PDO::PARAM_LOB);
        } elseif (is_int($value)) {
            $stmt->bindValue($name, $value, PDO::PARAM_INT);
        } elseif ($value === null) {
            $stmt->bindValue($name, null, PDO::PARAM_NULL);
        } else {
            $stmt->bindValue($name, (string) $value, PDO::PARAM_STR);
        }
    }
    $stmt->execute();
    return $stmt;
}

// ---------- Recording (runs inside the IP allowlist check) ----------

/**
 * Records one refused request ($enforced) or, in report-only mode, one request that would
 * have been refused (!$enforced) for $reason (one of IP_ALLOWLIST_REASONS) and $client (an
 * ip_allowlist_client() result) in $dataDir's log: one UPSERT into the bucket of this hour,
 * address (IPv6: its /64), reason and enforcement. The query string is never stored; it
 * carries enrollment tokens, SAML requests, codes and states. Never throws and never prints:
 * every failure (no pdo_sqlite, a read-only or full disk, a corrupt file, a lock held longer
 * than BLOCKED_REQUESTS_BUSY_MS) ends in a throttled PHP error log line, so under contention
 * the counts are lower bounds. Nothing happens while ip_allowlist_log is false or without a
 * data directory ($dataDir "").
 */
function blocked_requests_record(string $dataDir, string $reason, array $client, bool $enforced): void
{
    try {
        if ($dataDir === "") {
            return;
        }
        $settings = blocked_requests_settings();
        if (!$settings["enabled"]) {
            return;
        }
        $now = time();
        $params = blocked_requests_row($reason, $client, $enforced, $now);
        $pdo = blocked_requests_open(
            blocked_requests_path($dataDir),
            BLOCKED_REQUESTS_BUSY_MS,
            true,
            $settings["max_mb"]
        );
        if ($pdo === null) {
            return;
        }
        $write = static function () use ($pdo, $params): void {
            blocked_requests_execute(
                $pdo->prepare(
                    "INSERT INTO blocked_requests (hour, ip_key, key_bin, ip, peer_ip, forwarded_for, reason, " .
                        "enforced, hits, first_seen, last_seen, first_method, first_path, last_method, last_path, " .
                        "host, user_agent) " .
                        "VALUES (:hour, :ip_key, :key_bin, :ip, :peer, :xff, :reason, :enforced, 1, :now1, :now2, " .
                        ":m1, :p1, :m2, :p2, :host, :ua) " .
                        "ON CONFLICT(hour, ip_key, reason, enforced) DO UPDATE SET hits = hits + 1, " .
                        "last_seen = excluded.last_seen, ip = excluded.ip, peer_ip = excluded.peer_ip, " .
                        "forwarded_for = excluded.forwarded_for, last_method = excluded.last_method, " .
                        "last_path = excluded.last_path, host = excluded.host, user_agent = excluded.user_agent"
                ),
                $params
            );
        };
        try {
            $write();
        } catch (PDOException $e) {
            if (str_contains($e->getMessage(), "no such table")) {
                blocked_requests_schema($pdo); // the first refusal: create the table, then retry once
            } elseif ((int) (is_array($e->errorInfo) ? ($e->errorInfo[1] ?? 0) : 0) === 13) {
                // SQLITE_FULL: the file has reached ip_allowlist_log_max_mb. Freed pages are
                // reused, so it does not grow past the cap.
                blocked_requests_prune($pdo, $now, $settings["retention_days"], true);
            } else {
                throw $e;
            }
            $write();
        }
        if (random_int(1, BLOCKED_REQUESTS_PRUNE_ONE_IN) === 1) {
            try {
                blocked_requests_prune($pdo, $now, $settings["retention_days"]);
            } catch (Throwable $e) {
                // Best effort: the next pruning write or status view retries.
            }
        }
    } catch (Throwable $e) {
        try {
            ip_allowlist_warn(
                "log_write",
                "IP allowlist: a refused request could not be recorded (" . get_class($e) . ")"
            );
        } catch (Throwable $ignored) {
            // Recording never changes the answer to the request.
        }
    }
}

/**
 * The UPSERT parameters of blocked_requests_record() for the current request ($_SERVER).
 * Every text passes through sanitize_label() (control characters removed, whitespace runs
 * collapsed, length capped), so printing a stored value cannot inject terminal escapes.
 */
function blocked_requests_row(string $reason, array $client, bool $enforced, int $now): array
{
    if (!in_array($reason, IP_ALLOWLIST_REASONS, true)) {
        $reason = "check_failed"; // the store, the API and the console know only these values
    }
    $bin = $client["bin"] ?? null;
    $ipKey = "unknown";
    $keyBin = "";
    if (is_string($bin) && strlen($bin) === 4) {
        $text = inet_ntop($bin);
        if (is_string($text)) {
            $ipKey = $text;
            $keyBin = $bin;
        }
    } elseif (is_string($bin) && strlen($bin) === 16) {
        // One bucket per IPv6 /64: a device changes its address inside it.
        $net = substr($bin, 0, 8) . str_repeat("\0", 8);
        $text = inet_ntop($net);
        if (is_string($text)) {
            $ipKey = $text . "/64";
            $keyBin = $net;
        }
    }
    $ip = is_string($client["ip"] ?? null) ? blocked_requests_label($client["ip"], 64) : null;
    $viaProxy = ($client["via_proxy"] ?? false) === true;
    $peer = $client["peer"] ?? "";
    $peerIp = ($viaProxy || $ip === null) && is_string($peer) ? blocked_requests_label($peer, 64) : "";
    $forwardedFor = $viaProxy || $reason === "bad_forwarded_for"
        ? blocked_requests_label(blocked_requests_server("HTTP_X_FORWARDED_FOR"), 200)
        : "";
    // An Apache ErrorDocument redirect (REDIRECT_STATUS 4xx/5xx) arrives as a GET; the
    // client's method is in REDIRECT_REQUEST_METHOD.
    $method = blocked_requests_server("REQUEST_METHOD");
    $redirectMethod = blocked_requests_server("REDIRECT_REQUEST_METHOD");
    if ($redirectMethod !== "" && preg_match('/^[45]\d\d$/D', blocked_requests_server("REDIRECT_STATUS")) === 1) {
        $method = $redirectMethod;
    }
    $method = strtoupper($method);
    if (preg_match('/^[A-Z][A-Z0-9_-]{0,15}$/D', $method) !== 1) {
        $method = "OTHER";
    }
    $uri = blocked_requests_server("REQUEST_URI");
    $path = blocked_requests_label(substr($uri, 0, strcspn($uri, "?#")), 256);
    $host = blocked_requests_label(blocked_requests_server("HTTP_HOST"), 128);
    $userAgent = blocked_requests_label(blocked_requests_server("HTTP_USER_AGENT"), 200);
    return [
        ":hour" => intdiv($now, 3600),
        ":ip_key" => $ipKey,
        ":key_bin" => $keyBin,
        ":ip" => $ip ?? "",
        ":peer" => $peerIp,
        ":xff" => $forwardedFor,
        ":reason" => $reason,
        ":enforced" => $enforced ? 1 : 0,
        ":now1" => $now,
        ":now2" => $now,
        ":m1" => $method,
        ":p1" => $path,
        ":m2" => $method,
        ":p2" => $path,
        ":host" => $host,
        ":ua" => $userAgent,
    ];
}

/** $_SERVER[$name] when it is a string, else "". */
function blocked_requests_server(string $name): string
{
    $value = $_SERVER[$name] ?? null;
    return is_string($value) ? $value : "";
}

/**
 * sanitize_label($raw, $maxChars), after cutting $raw to 16 bytes per kept character: the
 * work per refused request stays bounded when a server passes oversized headers or targets.
 */
function blocked_requests_label(string $raw, int $maxChars): string
{
    $limit = 16 * max(1, $maxChars);
    return sanitize_label(strlen($raw) > $limit ? substr($raw, 0, $limit) : $raw, $maxChars);
}

/**
 * Deletes up to BLOCKED_REQUESTS_PRUNE_BATCH rows whose last request is older than
 * $retentionDays before $now and, with $makeRoom (the file is full), also the
 * BLOCKED_REQUESTS_ROOM_BATCH oldest rows (lowest ids). Returns the number of rows deleted.
 */
function blocked_requests_prune(PDO $pdo, int $now, int $retentionDays, bool $makeRoom = false): int
{
    $deleted = blocked_requests_execute(
        $pdo->prepare(
            "DELETE FROM blocked_requests WHERE id IN (" .
                "SELECT id FROM blocked_requests WHERE last_seen < :cutoff LIMIT :batch)"
        ),
        [":cutoff" => $now - max(1, $retentionDays) * 86400, ":batch" => BLOCKED_REQUESTS_PRUNE_BATCH]
    )->rowCount();
    if ($makeRoom) {
        $deleted += blocked_requests_execute(
            $pdo->prepare(
                "DELETE FROM blocked_requests WHERE id IN (" .
                    "SELECT id FROM blocked_requests ORDER BY id ASC LIMIT :batch)"
            ),
            [":batch" => BLOCKED_REQUESTS_ROOM_BATCH]
        )->rowCount();
    }
    return $deleted;
}

// ---------- Filters (GET query and DELETE body of /api/ip-allowlist/blocked-requests) ----------

/**
 * The filters in $input (the query string or the JSON body): ip (an address or CIDR block;
 * IPv6 is matched per /64), since and until (ISO 8601 or Unix seconds), reason (one of
 * IP_ALLOWLIST_REASONS) and enforced (false selects report-only rows). Other keys are
 * ignored; empty strings and null count as unset. Every key is present in the result, null
 * when not set. Throws InvalidArgumentException with a message for the client (400).
 *
 * @return array{ip: ?array{text: string, len: int, lo: string, hi: string}, since: ?int,
 *               until: ?int, reason: ?string, enforced: ?bool}
 */
function blocked_requests_filters(array $input): array
{
    $filters = ["ip" => null, "since" => null, "until" => null, "reason" => null, "enforced" => null];
    $value = static function (string $key) use ($input): mixed {
        $v = $input[$key] ?? null;
        return is_string($v) && trim($v) === "" ? null : $v;
    };

    $ip = $value("ip");
    if ($ip !== null) {
        $range = is_string($ip) && strlen(trim($ip)) <= 64 ? ip_allowlist_parse_range(trim($ip)) : null;
        if (!is_array($range)) {
            throw new InvalidArgumentException("ip must be an IPv4 or IPv6 address or CIDR block");
        }
        $filters["ip"] = blocked_requests_ip_filter($range);
    }
    foreach (["since", "until"] as $field) {
        $time = $value($field);
        if ($time !== null) {
            $filters[$field] = blocked_requests_parse_time($time, $field);
        }
    }
    $reason = $value("reason");
    if ($reason !== null) {
        if (!is_string($reason) || !in_array(trim($reason), IP_ALLOWLIST_REASONS, true)) {
            throw new InvalidArgumentException("reason must be one of " . implode(", ", IP_ALLOWLIST_REASONS));
        }
        $filters["reason"] = trim($reason);
    }
    $enforced = $value("enforced");
    if ($enforced !== null) {
        $word = is_string($enforced) ? strtolower(trim($enforced)) : null;
        if (is_bool($enforced)) {
            $filters["enforced"] = $enforced;
        } elseif ($enforced === 0 || $enforced === 1) {
            $filters["enforced"] = $enforced === 1;
        } elseif ($word === "1" || $word === "true") {
            $filters["enforced"] = true;
        } elseif ($word === "0" || $word === "false") {
            $filters["enforced"] = false;
        } else {
            throw new InvalidArgumentException("enforced must be 0, 1, true or false");
        }
    }
    return $filters;
}

/**
 * The ip filter for an ip_allowlist_parse_range() result: the key_bin range [lo, hi] of
 * the rows inside it. IPv6 rows are stored per /64, so longer IPv6 prefixes widen to their
 * /64; text is the block that is actually matched, for audit details.
 *
 * @return array{text: string, len: int, lo: string, hi: string}
 */
function blocked_requests_ip_filter(array $range): array
{
    $net = $range["net"] ?? null;
    $bits = $range["bits"] ?? null;
    $len = is_string($net) ? strlen($net) : 0;
    if (($len !== 4 && $len !== 16) || !is_int($bits) || $bits < 0 || $bits > 8 * $len) {
        throw new InvalidArgumentException("ip must be an IPv4 or IPv6 address or CIDR block");
    }
    if ($len === 4) {
        [$lo, $hi] = blocked_requests_prefix_bounds($net, $bits);
    } else {
        $bits = min($bits, 64);
        [$lo, $hi] = blocked_requests_prefix_bounds(substr($net, 0, 8), $bits);
        $lo .= str_repeat("\0", 8);
        $hi .= str_repeat("\0", 8);
    }
    return ["text" => (string) inet_ntop($lo) . "/" . $bits, "len" => $len, "lo" => $lo, "hi" => $hi];
}

/**
 * The lowest and the highest byte string sharing the first $bits bits of $bytes: [the
 * bytes with every bit after $bits cleared, the bytes with every bit after $bits set].
 *
 * @return array{0: string, 1: string}
 */
function blocked_requests_prefix_bounds(string $bytes, int $bits): array
{
    $lo = "";
    $hi = "";
    $count = strlen($bytes);
    for ($i = 0; $i < $count; $i++) {
        $keep = max(0, min(8, $bits - 8 * $i)); // bits of this byte inside the prefix
        $mask = (0xFF << (8 - $keep)) & 0xFF;
        $byte = ord($bytes[$i]) & $mask;
        $lo .= chr($byte);
        $hi .= chr($byte | (~$mask & 0xFF));
    }
    return [$lo, $hi];
}

/**
 * A since or until value as Unix seconds: an int >= 0, up to 10 digits, or an ISO 8601
 * date with an optional time ("2026-11-26", "2026-11-26T09:41", "2026-11-26T09:41:02.123Z",
 * "2026-11-26 09:41:02+01:00"); without an offset the time is UTC. The pattern keeps out
 * the relative formats DateTimeImmutable also accepts ("yesterday"), and its warnings keep
 * out dates that do not exist (2026-02-31). Throws InvalidArgumentException naming $field.
 */
function blocked_requests_parse_time(mixed $value, string $field): int
{
    $error = $field . " must be an ISO 8601 date-time (for example 2026-11-26T09:00:00Z) or Unix seconds";
    if (is_int($value)) {
        if ($value < 0) {
            throw new InvalidArgumentException($error);
        }
        return $value;
    }
    if (!is_string($value)) {
        throw new InvalidArgumentException($error);
    }
    $value = trim($value);
    if (preg_match('/^\d{1,10}$/D', $value) === 1) {
        return (int) $value;
    }
    if (
        preg_match(
            '/^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/D',
            $value
        ) !== 1
    ) {
        throw new InvalidArgumentException($error);
    }
    try {
        $time = new DateTimeImmutable($value, new DateTimeZone("UTC"));
    } catch (Exception $e) {
        throw new InvalidArgumentException($error);
    }
    $problems = DateTimeImmutable::getLastErrors();
    if (is_array($problems) && ($problems["warning_count"] > 0 || $problems["error_count"] > 0)) {
        throw new InvalidArgumentException($error);
    }
    return $time->getTimestamp();
}

/** Is no filter set in $filters (a blocked_requests_filters() result, or [])? */
function blocked_requests_filters_empty(array $filters): bool
{
    foreach (["ip", "since", "until", "reason", "enforced"] as $key) {
        if (($filters[$key] ?? null) !== null) {
            return false;
        }
    }
    return true;
}

/**
 * The filters that are set, for audit details: ip (the CIDR block matched), since and
 * until (ISO 8601 UTC), reason and enforced.
 */
function blocked_requests_filters_public(array $filters): array
{
    $public = [];
    $ip = $filters["ip"] ?? null;
    if (is_array($ip) && is_string($ip["text"] ?? null)) {
        $public["ip"] = $ip["text"];
    }
    foreach (["since", "until"] as $key) {
        if (is_int($filters[$key] ?? null)) {
            $public[$key] = blocked_requests_iso($filters[$key]);
        }
    }
    if (is_string($filters["reason"] ?? null)) {
        $public["reason"] = $filters["reason"];
    }
    if (is_bool($filters["enforced"] ?? null)) {
        $public["enforced"] = $filters["enforced"];
    }
    return $public;
}

/**
 * The SQL conditions and parameters of $filters (a blocked_requests_filters() result, or []
 * for every row). A filter that is set but malformed throws InvalidArgumentException, so a
 * purge is never widened by a filter that was dropped.
 *
 * @return array{0: list<string>, 1: array<string, mixed>}
 */
function blocked_requests_where(array $filters): array
{
    $clauses = [];
    $params = [];
    $ip = $filters["ip"] ?? null;
    if ($ip !== null) {
        $len = is_array($ip) ? ($ip["len"] ?? null) : null;
        $lo = is_array($ip) ? ($ip["lo"] ?? null) : null;
        $hi = is_array($ip) ? ($ip["hi"] ?? null) : null;
        if (($len !== 4 && $len !== 16) || !is_string($lo) || !is_string($hi) || strlen($lo) !== $len || strlen($hi) !== $len) {
            throw new InvalidArgumentException("malformed ip filter");
        }
        $clauses[] = "length(key_bin) = :key_len AND key_bin BETWEEN :lo_bin AND :hi_bin";
        $params += [":key_len" => $len, ":lo_bin" => $lo, ":hi_bin" => $hi];
    }
    foreach (["since" => "last_seen >= :since", "until" => "first_seen <= :until"] as $key => $condition) {
        $time = $filters[$key] ?? null;
        if ($time === null) {
            continue;
        }
        if (!is_int($time)) {
            throw new InvalidArgumentException("malformed " . $key . " filter");
        }
        $clauses[] = $condition;
        $params[":" . $key] = $time;
    }
    $reason = $filters["reason"] ?? null;
    if ($reason !== null) {
        if (!is_string($reason)) {
            throw new InvalidArgumentException("malformed reason filter");
        }
        $clauses[] = "reason = :reason";
        $params[":reason"] = $reason;
    }
    $enforced = $filters["enforced"] ?? null;
    if ($enforced !== null) {
        if (!is_bool($enforced) && $enforced !== 0 && $enforced !== 1) {
            throw new InvalidArgumentException("malformed enforced filter");
        }
        $clauses[] = "enforced = :enforced";
        $params[":enforced"] = $enforced ? 1 : 0;
    }
    return [$clauses, $params];
}

/** " WHERE c1 AND c2 ..." for $clauses, or "" when there are none. */
function blocked_requests_sql_where(array $clauses): string
{
    return $clauses === [] ? "" : " WHERE " . implode(" AND ", $clauses);
}

// ---------- Reading, export and purge (console, Admin API, command line) ----------

/** A Unix time as ISO 8601 UTC ("2026-11-26T09:41:02Z"). */
function blocked_requests_iso(int $time): string
{
    return gmdate("Y-m-d\TH:i:s\Z", $time);
}

/**
 * Opens $dataDir's log for the console, the Admin API or the command line (never creating
 * it); null when it does not exist. Throws RuntimeException when it cannot be opened.
 */
function blocked_requests_open_existing(string $dataDir): ?PDO
{
    if ($dataDir === "") {
        return null;
    }
    return blocked_requests_open(
        blocked_requests_path($dataDir),
        BLOCKED_REQUESTS_ADMIN_BUSY_MS,
        false,
        blocked_requests_settings()["max_mb"]
    );
}

/**
 * Up to $limit rows matching $clauses and $params (blocked_requests_where()), newest
 * (highest id) first, below the id $before when it is set.
 */
function blocked_requests_rows(PDO $pdo, array $clauses, array $params, ?int $before, int $limit): array
{
    if ($before !== null) {
        $clauses[] = "id < :cursor";
        $params[":cursor"] = $before;
    }
    $stmt = $pdo->prepare(
        "SELECT id, hour, ip_key, ip, peer_ip, forwarded_for, reason, enforced, hits, first_seen, last_seen, " .
            "first_method, first_path, last_method, last_path, host, user_agent FROM blocked_requests" .
            blocked_requests_sql_where($clauses) . " ORDER BY id DESC LIMIT :limit"
    );
    return blocked_requests_execute($stmt, $params + [":limit" => $limit])->fetchAll(PDO::FETCH_ASSOC);
}

/** One row of the log as an entry of GET /api/ip-allowlist/blocked-requests. */
function blocked_requests_entry(array $row): array
{
    return [
        "id" => (int) $row["id"],
        "hour_start" => blocked_requests_iso((int) $row["hour"] * 3600),
        "address" => (string) $row["ip"],
        "address_key" => (string) $row["ip_key"],
        "peer_address" => (string) $row["peer_ip"],
        "forwarded_for" => (string) $row["forwarded_for"],
        "reason" => (string) $row["reason"],
        "enforced" => (int) $row["enforced"] !== 0,
        "hits" => (int) $row["hits"],
        "first_seen" => blocked_requests_iso((int) $row["first_seen"]),
        "last_seen" => blocked_requests_iso((int) $row["last_seen"]),
        "first_request" => trim((string) $row["first_method"] . " " . (string) $row["first_path"]),
        "last_request" => trim((string) $row["last_method"] . " " . (string) $row["last_path"]),
        "host" => (string) $row["host"],
        "user_agent" => (string) $row["user_agent"],
    ];
}

/**
 * One page of the log, newest bucket first: {entries, next_cursor, total}. $limit is clamped
 * to 1..BLOCKED_REQUESTS_LIST_MAX; $cursor is the next_cursor of the previous page (rows
 * below that id). total counts every row matching $filters; next_cursor is null on the last
 * page. A missing file or table gives an empty page. Throws RuntimeException when the log
 * cannot be opened or read.
 *
 * @return array{entries: list<array>, next_cursor: ?string, total: int}
 */
function blocked_requests_list(string $dataDir, array $filters, int $limit, ?int $cursor): array
{
    [$clauses, $params] = blocked_requests_where($filters);
    $page = ["entries" => [], "next_cursor" => null, "total" => 0];
    $pdo = blocked_requests_open_existing($dataDir);
    if ($pdo === null) {
        return $page;
    }
    $limit = max(1, min(BLOCKED_REQUESTS_LIST_MAX, $limit));
    // One read snapshot for the count and the page. In WAL mode readers never block writers.
    $pdo->beginTransaction();
    try {
        $rows = [];
        if (blocked_requests_table_exists($pdo)) {
            $page["total"] = (int) blocked_requests_execute(
                $pdo->prepare("SELECT COUNT(*) FROM blocked_requests" . blocked_requests_sql_where($clauses)),
                $params
            )->fetchColumn();
            $rows = blocked_requests_rows($pdo, $clauses, $params, $cursor, $limit + 1);
        }
        $pdo->commit();
    } catch (Throwable $e) {
        try {
            $pdo->rollBack();
        } catch (Throwable $ignored) {
            // Closing the connection ends the transaction anyway.
        }
        throw $e;
    }
    $more = count($rows) > $limit;
    if ($more) {
        $rows = array_slice($rows, 0, $limit);
    }
    foreach ($rows as $row) {
        $page["entries"][] = blocked_requests_entry($row);
    }
    if ($more) {
        $page["next_cursor"] = (string) (int) $rows[$limit - 1]["id"];
    }
    return $page;
}

/**
 * $cell for a spreadsheet: a text that starts with =, +, -, @, a tab or a carriage return
 * gets a leading ', so it is never run as a formula (CSV injection).
 */
function blocked_requests_csv_guard(string $cell): string
{
    return $cell !== "" && str_contains("=+-@\t\r", $cell[0]) ? "'" . $cell : $cell;
}

/** One row of the log as a CSV record (BLOCKED_REQUESTS_CSV_COLUMNS), formula-guarded. */
function blocked_requests_csv_row(array $row): array
{
    $cells = [
        (int) $row["id"],
        blocked_requests_iso((int) $row["hour"] * 3600),
        blocked_requests_iso((int) $row["first_seen"]),
        blocked_requests_iso((int) $row["last_seen"]),
        (int) $row["hits"],
        (string) $row["ip"],
        (string) $row["ip_key"],
        (string) $row["peer_ip"],
        (string) $row["forwarded_for"],
        (string) $row["reason"],
        (int) $row["enforced"] !== 0 ? 1 : 0,
        (string) $row["first_method"],
        (string) $row["first_path"],
        (string) $row["last_method"],
        (string) $row["last_path"],
        (string) $row["host"],
        (string) $row["user_agent"],
    ];
    foreach ($cells as $i => $cell) {
        if (is_string($cell)) {
            $cells[$i] = blocked_requests_csv_guard($cell);
        }
    }
    return $cells;
}

/**
 * Sends the rows matching $filters as a CSV download (status 200 and the headers included):
 * the header row (BLOCKED_REQUESTS_CSV_COLUMNS), then at most BLOCKED_REQUESTS_CSV_MAX_ROWS
 * rows, newest first, read in keyset batches. A missing file gives the header row only.
 * Returns the number of rows sent and does not exit, so the caller can audit the export.
 * Throws RuntimeException before any output when the log cannot be opened or read; a read
 * that fails after the download has started ends the file early (the reason goes to the
 * PHP error log).
 */
function blocked_requests_send_csv(string $dataDir, array $filters): int
{
    [$clauses, $params] = blocked_requests_where($filters);
    $pdo = blocked_requests_open_existing($dataDir);
    // The first batch is read before anything is sent, so a log that cannot be read gets
    // the caller's error answer instead of a truncated file.
    $batch = $pdo !== null && blocked_requests_table_exists($pdo)
        ? blocked_requests_rows($pdo, $clauses, $params, null, min(BLOCKED_REQUESTS_CSV_BATCH, BLOCKED_REQUESTS_CSV_MAX_ROWS))
        : [];
    $out = fopen("php://output", "wb");
    if ($out === false) {
        throw new RuntimeException("php://output cannot be opened");
    }
    if (!headers_sent()) {
        send_security_headers(false);
        header("Content-Type: text/csv; charset=utf-8");
        header('Content-Disposition: attachment; filename="blocked-requests-' . gmdate('Ymd\THis\Z') . '.csv"');
        header("Cache-Control: no-store");
    }
    @set_time_limit(120);
    // An empty escape character: RFC 4180 quoting only (PHP 8.4 deprecates the default "\\").
    fputcsv($out, BLOCKED_REQUESTS_CSV_COLUMNS, ",", "\"", "");
    $sent = 0;
    try {
        while ($batch !== [] && $pdo !== null) {
            foreach ($batch as $row) {
                fputcsv($out, blocked_requests_csv_row($row), ",", "\"", "");
                $sent++;
            }
            $size = count($batch);
            if ($size < BLOCKED_REQUESTS_CSV_BATCH || $sent >= BLOCKED_REQUESTS_CSV_MAX_ROWS) {
                break;
            }
            $batch = blocked_requests_rows(
                $pdo,
                $clauses,
                $params,
                (int) $batch[$size - 1]["id"],
                min(BLOCKED_REQUESTS_CSV_BATCH, BLOCKED_REQUESTS_CSV_MAX_ROWS - $sent)
            );
        }
    } catch (Throwable $e) {
        // The status and part of the file are already sent: end the file here.
        error_log(
            "IP allowlist: the CSV export of " . BLOCKED_REQUESTS_FILE . " stopped after " . $sent .
                " rows: " . get_class($e) . ": " . $e->getMessage()
        );
    }
    fclose($out);
    return $sent;
}

/**
 * Deletes the rows matching $filters, or every row when no filter is set ([] included; the
 * route insists on an explicit "all"), and returns how many were deleted. Deleted rows are
 * overwritten (secure_delete) and the write-ahead log is truncated afterwards, so the
 * personal data does not linger. A missing file or table deletes nothing. Throws
 * RuntimeException when the log cannot be opened or written.
 */
function blocked_requests_purge(string $dataDir, array $filters): int
{
    [$clauses, $params] = blocked_requests_where($filters);
    $pdo = blocked_requests_open_existing($dataDir);
    if ($pdo === null || !blocked_requests_table_exists($pdo)) {
        return 0;
    }
    $deleted = blocked_requests_execute(
        $pdo->prepare("DELETE FROM blocked_requests" . blocked_requests_sql_where($clauses)),
        $params
    )->rowCount();
    try {
        $pdo->exec("PRAGMA wal_checkpoint(TRUNCATE)");
    } catch (Throwable $e) {
        // A reader holds the log; the next checkpoint truncates it.
    }
    return $deleted;
}

/**
 * The log section of the IP allowlist status: {enabled, available, file_name, size_bytes
 * (the file plus its -wal), max_bytes, retention_days, rows, hits, oldest, newest (ISO 8601
 * UTC, null without rows)}. available is false when $dataDir is not a writable directory,
 * or when the file (or its -wal or -shm) exists but cannot be written, opened or read; the
 * details go to the PHP error log. With $prune, rows past the retention are deleted first
 * (best effort, for at most about 2 seconds). Never creates the file; a log that cannot be
 * opened or read is reported in available, not thrown. Paths are never returned.
 */
function blocked_requests_stats(string $dataDir, bool $prune = true): array
{
    $settings = blocked_requests_settings();
    $log = [
        "enabled" => $settings["enabled"],
        "available" => $dataDir !== "" && is_dir($dataDir) && is_writable($dataDir),
        "file_name" => BLOCKED_REQUESTS_FILE,
        "size_bytes" => 0,
        "max_bytes" => $settings["max_mb"] * 1048576,
        "retention_days" => $settings["retention_days"],
        "rows" => 0,
        "hits" => 0,
        "oldest" => null,
        "newest" => null,
    ];
    $file = $dataDir !== "" ? blocked_requests_path($dataDir) : "";
    if ($file === "" || !file_exists($file)) {
        return $log;
    }
    foreach (["", "-wal", "-shm"] as $suffix) {
        if (file_exists($file . $suffix) && !is_writable($file . $suffix)) {
            $log["available"] = false;
            error_log("IP allowlist: " . BLOCKED_REQUESTS_FILE . $suffix . " is not writable by the PHP process");
        }
    }
    try {
        $pdo = blocked_requests_open_existing($dataDir);
        if ($pdo !== null && blocked_requests_table_exists($pdo)) {
            if ($prune) {
                try {
                    $deadline = microtime(true) + 2.0;
                    do {
                        $pruned = blocked_requests_prune($pdo, time(), $settings["retention_days"]);
                    } while ($pruned >= BLOCKED_REQUESTS_PRUNE_BATCH && microtime(true) < $deadline);
                } catch (Throwable $e) {
                    error_log(
                        "IP allowlist: old rows of " . BLOCKED_REQUESTS_FILE . " could not be deleted: " .
                            get_class($e) . ": " . $e->getMessage()
                    );
                }
            }
            $counts = $pdo->query(
                "SELECT COUNT(*) AS n, COALESCE(SUM(hits), 0) AS hits, MIN(first_seen) AS oldest, " .
                    "MAX(last_seen) AS newest FROM blocked_requests"
            )->fetch(PDO::FETCH_ASSOC);
            if (is_array($counts)) {
                $log["rows"] = (int) $counts["n"];
                $log["hits"] = (int) $counts["hits"];
                $log["oldest"] = $counts["oldest"] !== null ? blocked_requests_iso((int) $counts["oldest"]) : null;
                $log["newest"] = $counts["newest"] !== null ? blocked_requests_iso((int) $counts["newest"]) : null;
            }
        }
    } catch (Throwable $e) {
        $log["available"] = false;
        error_log(
            "IP allowlist: " . BLOCKED_REQUESTS_FILE . " cannot be read: " . get_class($e) . ": " . $e->getMessage()
        );
    }
    // Measured after the connection is closed: the last connection checkpoints the -wal.
    $pdo = null;
    clearstatcache();
    foreach (["", "-wal"] as $suffix) {
        $size = is_file($file . $suffix) ? @filesize($file . $suffix) : false;
        $log["size_bytes"] += is_int($size) ? $size : 0;
    }
    return $log;
}
