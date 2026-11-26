<?php
declare(strict_types=1);

require_once __DIR__ . "/src/bootstrap.php";
require_once __DIR__ . "/src/db.php";
require_once __DIR__ . "/src/crypto.php";
require_once __DIR__ . "/src/directory.php";
require_once __DIR__ . "/src/webauthn.php";
require_once __DIR__ . "/src/saml.php";
require_once __DIR__ . "/src/oidc.php";
require_once __DIR__ . "/src/scim.php";
require_once __DIR__ . "/src/auth_flow.php";
require_once __DIR__ . "/src/admin_clients.php";
require_once __DIR__ . "/src/openapi.php";
require_once __DIR__ . "/src/routes_api.php";
require_once __DIR__ . "/src/routes_idp.php";
require_once __DIR__ . "/src/admin_spa.php";

// Command line: "php index.php hash-admin-password <username>" prints the users.txt line
// "<username>:<password_hash()>" for an administrator (G2a-07): users.txt entries must be
// hashes unless allow_plaintext_admin_passwords is on. The password (at least 12 characters)
// is read from standard input, on a terminal twice and without echo, never from the command
// line. It reads no data, so it runs before the database is opened. Exit code 0 when the line
// was printed, 1 when the input was refused, 2 for a usage error.
if (PHP_SAPI === "cli" && ($argv[1] ?? "") === "hash-admin-password") {
    $adminName = (string) ($argv[2] ?? "");
    if ($adminName === "" || count($argv) > 3) {
        fwrite(
            STDERR,
            "Usage: php index.php hash-admin-password <username>" . PHP_EOL .
                "The password is read from standard input, never from the command line." . PHP_EOL
        );
        exit(2);
    }
    $interactive = stream_isatty(STDIN);
    $hideInput = $interactive && PHP_OS_FAMILY !== "Windows" && function_exists("shell_exec");
    $readPassword = static function (string $prompt) use ($interactive, $hideInput): string {
        if ($interactive) {
            fwrite(STDERR, $prompt);
        }
        if ($hideInput) {
            shell_exec("stty -echo");
        }
        $line = fgets(STDIN);
        if ($hideInput) {
            shell_exec("stty echo");
            fwrite(STDERR, PHP_EOL);
        }
        return is_string($line) ? rtrim($line, "\r\n") : "";
    };
    $adminPassword = $readPassword("Password for " . sanitize_label($adminName, 64) . ": ");
    if ($interactive && $readPassword("Repeat the password: ") !== $adminPassword) {
        fwrite(STDERR, "The passwords do not match" . PHP_EOL);
        exit(1);
    }
    try {
        fwrite(STDOUT, admin_password_hash_line($adminName, $adminPassword) . PHP_EOL);
        exit(0);
    } catch (InvalidArgumentException | ValueError $e) {
        fwrite(STDERR, $e->getMessage() . PHP_EOL);
        exit(1);
    }
}

// Command line: "php index.php ip-allowlist [status|check <ip>|recent]" shows the IP allowlist
// (ip_allowlist in config.php), why an address is allowed or refused, and the newest refused
// requests; for lockout recovery and deploy checks (exit codes in src/ip_allowlist.php). Run it
// as the web server user. It reads no main database, so it runs before it is opened.
if (PHP_SAPI === "cli" && ($argv[1] ?? "") === "ip-allowlist") {
    exit(ip_allowlist_cli(array_slice($argv, 2), $CONFIG_DIR));
}

// favicon.ico is answered here, after the IP allowlist check in bootstrap, never by the web
// server: the icon identifies the product. "private" keeps shared caches from handing it to
// refused addresses.
if (PHP_SAPI !== "cli" && $path === "/favicon.ico" && ($method === "GET" || $method === "HEAD")) {
    $icon = @file_get_contents(__DIR__ . "/favicon.ico");
    if (is_string($icon)) {
        send_security_headers(false);
        header("Content-Type: image/x-icon");
        header("Cache-Control: private, max-age=86400");
        header("Content-Length: " . strlen($icon));
        if ($method === "GET") {
            echo $icon;
        }
        exit();
    }
}

storage_initialize($PROVIDERS_FILE);
if ($APIKEYS_FILE !== $PROVIDERS_FILE) {
    storage_initialize($APIKEYS_FILE);
}

// Command line: "php index.php scim-sync" continues queued outbound SCIM syncs (direct-mode
// syncs that stopped at their time budget) without waiting for the next directory change.
// Run it from cron as the web server user, so the data directory is readable, e.g.
//   */5 * * * * php /path/to/index.php scim-sync
// It syncs only active auto-sync connectors with pending changes, each under its lease and
// time budget, and prints connector id => status as JSON.
if (PHP_SAPI === "cli" && ($argv[1] ?? "") === "scim-sync") {
    if (!function_exists("scim_run_pending_syncs")) {
        fwrite(STDERR, "scim-sync is not available in this version" . PHP_EOL);
        exit(1);
    }
    $syncResult = scim_run_pending_syncs($PROVIDERS_FILE);
    fwrite(STDOUT, (string) json_encode($syncResult, JSON_UNESCAPED_SLASHES) . PHP_EOL);
    exit(0);
}

// 1. Admin & Automation REST API (/api/*)
handle_api_routes(
    $method,
    $path,
    $CONFIG_DIR,
    $USERS_FILE,
    $PROVIDERS_FILE,
    $APIKEYS_FILE,
    $KEYS_DIR,
    $scriptDir,
    $origin,
    $baseUrl,
    $rpId
);

// 2. Public Identity Provider Endpoints (OIDC, SAML 2.0, Hosted Touch ID Login, Portal, Test Harness)
handle_idp_routes(
    $method,
    $path,
    $PROVIDERS_FILE,
    $KEYS_DIR,
    $isHttps,
    $origin,
    $baseUrl,
    $rpId
);

// 3. Admin Console SPA (the base URL gives the console its path prefix in subdirectory installs)
if ($method === "GET" && ($path === "/" || $path === "/index.php")) {
    render_admin_spa($baseUrl);
}

http_response_code(404);
send_security_headers(false);
header("Content-Type: text/plain; charset=utf-8");
echo "Not found";
