<?php
declare(strict_types=1);

require_once __DIR__ . "/src/bootstrap.php";
// The admin login check (current_user()) reads the per-admin session keys from the database.
require_once __DIR__ . "/src/db.php";

if (!debug_enabled($CONFIG_DIR)) {
    http_response_code(404);
    header("Content-Type: text/plain; charset=utf-8");
    echo "Not found\n";
    exit();
}

require_login();

header("Content-Type: text/plain; charset=utf-8");
echo "PHP runtime test\n";
echo "time=" . gmdate("c") . "\n";
echo "sapi=" . php_sapi_name() . "\n";
echo "version=" . PHP_VERSION . "\n";
echo "pdo_sqlite=" . (extension_loaded("pdo_sqlite") ? "yes" : "no") . "\n";
echo "openssl=" . (extension_loaded("openssl") ? "yes" : "no") . "\n";
echo "status=ok\n";
