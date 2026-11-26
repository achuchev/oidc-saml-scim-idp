<?php
declare(strict_types=1);

function normalize_jwa_alg(string $alg): string
{
    $u = strtoupper(trim($alg));
    if ($u === "EDDSA") {
        return "EdDSA";
    }
    return $u;
}

function provider_ttl_seconds(array $prov): int
{
    $spec = $prov["key_ttl_seconds"] ?? null;
    if (is_int($spec) && $spec > 0) {
        return $spec;
    }
    $env = getenv("SIGNING_KEY_TTL");
    if (!$env || trim($env) === "") {
        $env = getenv("SIGNING_KEY_VALIDITY");
    }
    if (!$env || trim($env) === "") {
        $env = "1h";
    }
    return max(1, parse_validity_to_seconds($env));
}

function provider_retention_seconds(array $prov): int
{
    $spec = $prov["expired_key_retention_seconds"] ?? null;
    if (is_int($spec) && $spec >= 0) {
        return $spec;
    }
    // Not set on the provider: EXPIRED_KEY_RETENTION, else one hour, so a key that has
    // just expired stays in the JWKS while relying parties still check its tokens.
    $env = getenv("EXPIRED_KEY_RETENTION");
    if (!is_string($env) || trim($env) === "") {
        $env = "1h";
    }
    return max(0, parse_validity_to_seconds($env));
}

function key_is_expired(array $k): bool
{
    $exp = $k["expires_at"] ?? null;
    if (!$exp) {
        return false;
    }
    $ts = @strtotime($exp);
    if ($ts === false) {
        return false;
    }
    return $ts <= time();
}

function filter_unexpired_keys(array $keys): array
{
    $now = time();
    return array_values(
        array_filter($keys, function ($k) use ($now) {
            $exp = $k["expires_at"] ?? null;
            if (!$exp) {
                return true;
            }
            $ts = @strtotime($exp);
            return $ts === false ? true : $ts > $now;
        })
    );
}

/**
 * Creation time of a key (created_at, else valid_from) as a Unix timestamp; 0 if unknown.
 */
function provider_key_created_ts(array $k): int
{
    foreach (["created_at", "valid_from"] as $field) {
        $v = $k[$field] ?? null;
        if (is_string($v) && $v !== "") {
            $ts = strtotime($v);
            if ($ts !== false) {
                return $ts;
            }
        }
    }
    return 0;
}

/**
 * The provider's active signing key: the key named by active_kid, else the newest
 * unexpired key, else the newest key. Null only when the provider has no keys.
 */
function provider_active_signing_key(array $prov): ?array
{
    $keys = array_values(array_filter($prov["keys"] ?? [], "is_array"));
    $activeKid = (string) ($prov["active_kid"] ?? "");
    if ($activeKid !== "") {
        foreach ($keys as $k) {
            if ((string) ($k["kid"] ?? "") === $activeKid) {
                return $k;
            }
        }
    }
    $best = null;
    $bestUnexpired = false;
    $bestTs = 0;
    foreach ($keys as $k) {
        $unexpired = !key_is_expired($k);
        $ts = provider_key_created_ts($k);
        // Unexpired beats expired, then newer beats older; on a tie the later entry wins.
        if (
            $best === null ||
            ($unexpired && !$bestUnexpired) ||
            ($unexpired === $bestUnexpired && $ts >= $bestTs)
        ) {
            $best = $k;
            $bestUnexpired = $unexpired;
            $bestTs = $ts;
        }
    }
    return $best;
}

/**
 * Unix time until which a key must stay in the JWKS: its expiry plus the provider's
 * retention, or the latest exp of a token it signed (max_token_exp), whichever is
 * later. Null when the key has no usable expiry; such keys are always published.
 */
function provider_key_publish_until(array $prov, array $k): ?int
{
    $exp = $k["expires_at"] ?? null;
    if (!is_string($exp) || trim($exp) === "") {
        return null;
    }
    $ts = strtotime($exp);
    if ($ts === false) {
        return null;
    }
    return max(
        $ts + provider_retention_seconds($prov),
        (int) ($k["max_token_exp"] ?? 0)
    );
}

/**
 * Whether a key belongs in the provider's JWKS: the active signing key always does
 * (so the set is never empty while the provider has keys), any other key until
 * provider_key_publish_until(). Keys for which this is false can be pruned.
 */
function provider_key_is_publishable(array $prov, array $k, ?int $now = null): bool
{
    $active = provider_active_signing_key($prov);
    if ($active !== null && (string) ($active["kid"] ?? "") === (string) ($k["kid"] ?? "")) {
        return true;
    }
    $until = provider_key_publish_until($prov, $k);
    return $until === null || $until > ($now ?? time());
}

function filter_publishable_keys_for_provider(array $prov): array
{
    $now = time();
    $active = provider_active_signing_key($prov);
    $activeKid = $active !== null ? (string) ($active["kid"] ?? "") : null;
    return array_values(
        array_filter($prov["keys"] ?? [], function ($k) use ($prov, $now, $activeKid) {
            if (!is_array($k)) {
                return false;
            }
            if ($activeKid !== null && (string) ($k["kid"] ?? "") === $activeKid) {
                return true;
            }
            $until = provider_key_publish_until($prov, $k);
            return $until === null || $until > $now;
        })
    );
}

/**
 * Records that a token expiring at $exp was signed with this provider key, so the key
 * stays in the JWKS until then (provider_keys.max_token_exp only ever grows). Call it
 * after signing every token with a provider key. Best effort: errors are logged, never
 * thrown.
 */
function provider_key_record_token_exp(
    string $storePath,
    string $providerId,
    string $kid,
    int $exp
): void {
    if ($exp <= 0 || $providerId === "" || $kid === "") {
        return;
    }
    try {
        $stmt = storage_db($storePath)->prepare(
            "UPDATE provider_keys SET max_token_exp = MAX(COALESCE(max_token_exp, 0), CAST(:exp AS INTEGER)) " .
                "WHERE provider_id = :p AND kid = :k"
        );
        // Bound as an integer: SQLite's MAX() ranks any TEXT above every INTEGER.
        $stmt->bindValue(":exp", $exp, PDO::PARAM_INT);
        $stmt->bindValue(":p", $providerId, PDO::PARAM_STR);
        $stmt->bindValue(":k", $kid, PDO::PARAM_STR);
        $stmt->execute();
    } catch (Throwable $e) {
        error_log("provider_key_record_token_exp failed: " . $e->getMessage());
    }
}

// ---------- ASN.1 / DER Read & Write Helpers ----------

function der_read_tlv(string $der, int &$off): array
{
    $n = strlen($der);
    if ($off >= $n) {
        throw new RuntimeException("DER underrun");
    }
    $tag = ord($der[$off++]);
    if ($off >= $n) {
        throw new RuntimeException("DER underrun len");
    }
    $len = ord($der[$off++]);
    if ($len & 0x80) {
        $nb = $len & 0x7f;
        if ($nb === 0 || $nb > 4) {
            throw new RuntimeException("Invalid DER len");
        }
        if ($off + $nb > $n) {
            throw new RuntimeException("DER underrun");
        }
        $len = 0;
        for ($i = 0; $i < $nb; $i++) {
            $len = ($len << 8) | ord($der[$off++]);
        }
    }
    if ($off + $len > $n) {
        throw new RuntimeException("DER len beyond data");
    }
    $val = substr($der, $off, $len);
    $off += $len;
    return [$tag, $len, $val];
}

function der_encode_length(int $len): string
{
    if ($len < 0x80) {
        return chr($len);
    }
    $bytes = "";
    $tmp = $len;
    while ($tmp > 0) {
        $bytes = chr($tmp & 0xff) . $bytes;
        $tmp >>= 8;
    }
    return chr(0x80 | strlen($bytes)) . $bytes;
}

function der_tlv(int $tag, string $content): string
{
    return chr($tag) . der_encode_length(strlen($content)) . $content;
}

function der_sequence(string $content): string
{
    return der_tlv(0x30, $content);
}

function der_bit_string(string $bytes): string
{
    return der_tlv(0x03, "\x00" . $bytes);
}

function der_integer_unsigned(string $bigEndianBytes): string
{
    $trimmed = ltrim($bigEndianBytes, "\x00");
    if ($trimmed === "") {
        $trimmed = "\x00";
    }
    if (ord($trimmed[0]) & 0x80) {
        $trimmed = "\x00" . $trimmed;
    }
    return der_tlv(0x02, $trimmed);
}

function hash_spki_kid_from_pkey_details(array $det): string
{
    $pem = $det["key"] ?? "";
    if (!is_string($pem) || $pem === "") {
        return base64url_encode(random_bytes(16));
    }
    $lines = array_filter(
        array_map("trim", explode("\n", $pem)),
        fn($l) => !str_starts_with($l, "---") && $l !== ""
    );
    $der = base64_decode(implode("", $lines));
    if ($der === false) {
        return base64url_encode(random_bytes(16));
    }
    return base64url_encode(hash("sha256", $der, true));
}

function spki_xy_from_ec_spki(string $spkiPem): array
{
    $lines = array_filter(
        array_map("trim", explode("\n", $spkiPem)),
        fn($l) => !str_starts_with($l, "---") && $l !== ""
    );
    $der = base64_decode(implode("", $lines));
    if ($der === false) {
        throw new RuntimeException("Invalid SPKI base64");
    }
    $off = 0;
    [$t0, , $v0] = der_read_tlv($der, $off);
    if ($t0 !== 0x30) {
        throw new RuntimeException("SPKI not a SEQUENCE");
    }
    $subOff = 0;
    [$tAlg] = der_read_tlv($v0, $subOff);
    if ($tAlg !== 0x30) {
        throw new RuntimeException("AlgId not SEQUENCE");
    }
    [$tPub, , $vPub] = der_read_tlv($v0, $subOff);
    if ($tPub !== 0x03) {
        throw new RuntimeException("PubKey not BIT STRING");
    }
    if ($vPub === "" || $vPub[0] !== "\x00") {
        throw new RuntimeException("Bad pubkey BIT STRING");
    }
    $point = substr($vPub, 1);
    if ($point === "" || $point[0] !== "\x04") {
        throw new RuntimeException("Only uncompressed EC points supported");
    }
    $len = strlen($point);
    if ($len % 2 !== 1) {
        throw new RuntimeException("Invalid EC point len");
    }
    $coordLen = intdiv($len - 1, 2);
    $x = substr($point, 1, $coordLen);
    $y = substr($point, 1 + $coordLen, $coordLen);
    return ["x" => $x, "y" => $y];
}

function create_keypair(string $alg, string $KEYS_DIR = ""): array
{
    $algNorm = normalize_jwa_alg($alg);
    if (in_array($algNorm, ["RS256", "RS384", "RS512"], true)) {
        $res = openssl_pkey_new([
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "private_key_bits" => 2048,
        ]);
        if (!$res) {
            throw new RuntimeException("RSA gen failed");
        }
        openssl_pkey_export($res, $pem);
        $kid = hash_spki_kid_from_pkey_details(openssl_pkey_get_details($res));
        return ["type" => "pem", "pem_content" => $pem, "kid" => $kid];
    } elseif (in_array($algNorm, ["ES256", "ES384", "ES512"], true)) {
        $curve =
            $algNorm === "ES256"
                ? "prime256v1"
                : ($algNorm === "ES384"
                    ? "secp384r1"
                    : "secp521r1");
        $res = openssl_pkey_new([
            "private_key_type" => OPENSSL_KEYTYPE_EC,
            "curve_name" => $curve,
        ]);
        if (!$res) {
            throw new RuntimeException("EC gen failed ($curve)");
        }
        openssl_pkey_export($res, $pem);
        $kid = hash_spki_kid_from_pkey_details(openssl_pkey_get_details($res));
        return ["type" => "pem", "pem_content" => $pem, "kid" => $kid];
    } elseif ($algNorm === "EdDSA") {
        if (!function_exists("sodium_crypto_sign_keypair")) {
            throw new RuntimeException("libsodium required for Ed25519");
        }
        $kp = sodium_crypto_sign_keypair();
        $sk = sodium_crypto_sign_secretkey($kp);
        $pk = sodium_crypto_sign_publickey($kp);
        return [
            "type" => "ed25519",
            "ed_secret" => base64url_encode($sk),
            "ed_public" => base64url_encode($pk),
            "kid" => base64url_encode(hash("sha256", $pk, true)),
        ];
    }
    throw new InvalidArgumentException("Unsupported alg: $alg");
}

/**
 * Imports a pasted private key and returns its key material (type, pem_content or
 * ed_secret/ed_public, kid, alg). Accepted: unencrypted PEM (RSA of 2048-16384 bits,
 * EC on P-256/P-384/P-521, Ed25519 PKCS#8), or a raw Ed25519 32-byte seed or 64-byte
 * secret key (seed followed by its public key) in hex, base64 or base64url. Only text
 * starting with "-----BEGIN " reaches OpenSSL, so "file://" paths and other OpenSSL
 * input forms never make the server read a key from its own disk.
 * Throws InvalidArgumentException for anything else.
 */
function import_private_key_auto(string $text, string $KEYS_DIR = ""): array
{
    $raw = trim($text);
    if (str_starts_with($raw, "\xEF\xBB\xBF")) {
        $raw = trim(substr($raw, 3));
    }
    if ($raw === "") {
        throw new InvalidArgumentException("No private key provided");
    }
    if (strlen($raw) > 65536) {
        throw new InvalidArgumentException("Private key text is too large");
    }

    if (str_starts_with($raw, "-----BEGIN ")) {
        // Ed25519 PKCS#8 is decoded here, independently of OpenSSL's Ed25519 support.
        $seed = ed25519_seed_from_pkcs8_pem($raw);
        if ($seed !== null) {
            return ed25519_key_material_from_seed($seed);
        }
        // Explicit empty passphrase: encrypted keys are rejected instead of prompting.
        $res = @openssl_pkey_get_private($raw, "");
        if ($res === false) {
            throw new InvalidArgumentException(
                "Could not parse the PEM private key (it must be an unencrypted RSA, EC or Ed25519 key)"
            );
        }
        $det = openssl_pkey_get_details($res);
        $pem = "";
        if (!is_array($det) || !@openssl_pkey_export($res, $pem) || !is_string($pem) || $pem === "") {
            throw new InvalidArgumentException("Could not read the PEM private key");
        }
        if ($det["type"] === OPENSSL_KEYTYPE_RSA) {
            $bits = (int) ($det["bits"] ?? 0);
            if ($bits < 2048) {
                throw new InvalidArgumentException("RSA keys must be at least 2048 bits (this key has $bits)");
            }
            if ($bits > 16384) {
                throw new InvalidArgumentException("RSA keys larger than 16384 bits are not supported");
            }
            $alg = "RS256";
        } elseif ($det["type"] === OPENSSL_KEYTYPE_EC) {
            $curve = (string) ($det["ec"]["curve_name"] ?? "");
            if ($curve === "prime256v1") {
                $alg = "ES256";
            } elseif ($curve === "secp384r1") {
                $alg = "ES384";
            } elseif ($curve === "secp521r1") {
                $alg = "ES512";
            } else {
                throw new InvalidArgumentException("Unsupported EC curve: $curve");
            }
        } else {
            throw new InvalidArgumentException(
                "Unsupported key type: use RSA (2048 bits or more), EC P-256/P-384/P-521 or Ed25519"
            );
        }
        $mat = [
            "type" => "pem",
            "pem_content" => $pem,
            "kid" => hash_spki_kid_from_pkey_details($det),
            "alg" => $alg,
        ];
        // Fail now rather than later in /jwks: the key must convert to a JWK.
        try {
            jwk_from_key(["kid" => $mat["kid"], "alg" => $alg, "material" => $mat]);
        } catch (Throwable $e) {
            throw new InvalidArgumentException("The key cannot be published as a JWK: " . $e->getMessage());
        }
        return $mat;
    }

    // Raw Ed25519. Strict hex first: every hex string is also valid base64, but a
    // 32- or 64-byte key is 43/44 or 86/88 base64 characters, never 64 or 128.
    if (preg_match('/^(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$/D', $raw) === 1) {
        $bin = (string) hex2bin($raw);
    } else {
        $bin = base64url_decode($raw);
        if ($bin === "") {
            $bin = base64_decode($raw, true) ?: "";
        }
    }
    $len = strlen($bin);
    if ($len !== 32 && $len !== 64) {
        throw new InvalidArgumentException(
            "Could not detect key type: paste an unencrypted PEM private key, or a raw Ed25519 seed (32 bytes) or secret key (64 bytes) in hex, base64 or base64url"
        );
    }
    $mat = ed25519_key_material_from_seed(substr($bin, 0, 32));
    // A 64-byte secret key is seed || public key; libsodium signs with the stored
    // public half, so a mismatch would publish a key that verifies no signature.
    if ($len === 64 && !hash_equals(base64url_decode($mat["ed_public"]), substr($bin, 32))) {
        throw new InvalidArgumentException(
            "Ed25519 secret key is inconsistent: its last 32 bytes are not the public key of its seed"
        );
    }
    return $mat;
}

/**
 * Ed25519 key material derived from a 32-byte seed.
 */
function ed25519_key_material_from_seed(string $seed): array
{
    if (!function_exists("sodium_crypto_sign_seed_keypair")) {
        throw new RuntimeException("libsodium required for Ed25519");
    }
    if (strlen($seed) !== 32) {
        throw new InvalidArgumentException("An Ed25519 seed is 32 bytes");
    }
    $kp = sodium_crypto_sign_seed_keypair($seed);
    $sk = sodium_crypto_sign_secretkey($kp);
    $pk = sodium_crypto_sign_publickey($kp);
    return [
        "type" => "ed25519",
        "ed_secret" => base64url_encode($sk),
        "ed_public" => base64url_encode($pk),
        "kid" => base64url_encode(hash("sha256", $pk, true)),
        "alg" => "EdDSA",
    ];
}

/**
 * Returns the 32-byte seed of an unencrypted Ed25519 PKCS#8 key ("BEGIN PRIVATE KEY",
 * RFC 8410, with or without the optional public key), or null when the text holds no
 * such key. Throws InvalidArgumentException when an Ed25519 key is malformed or its
 * embedded public key does not belong to its seed.
 */
function ed25519_seed_from_pkcs8_pem(string $pem): ?string
{
    if (
        preg_match(
            '/-----BEGIN PRIVATE KEY-----([A-Za-z0-9+\/=\s]+)-----END PRIVATE KEY-----/',
            $pem,
            $m
        ) !== 1
    ) {
        return null;
    }
    $der = base64_decode((string) preg_replace('/\s+/', "", $m[1]), true);
    if (!is_string($der) || $der === "") {
        return null;
    }
    $malformed = "Malformed Ed25519 private key";
    $publicKey = null;
    try {
        $off = 0;
        [$tSeq, , $seq] = der_read_tlv($der, $off);
        if ($tSeq !== 0x30) {
            return null;
        }
        $o = 0;
        [$tVer, , $ver] = der_read_tlv($seq, $o);
        [$tAlg, , $algId] = der_read_tlv($seq, $o);
        if ($tVer !== 0x02 || $tAlg !== 0x30) {
            return null;
        }
        $ao = 0;
        [$tOid, , $oid] = der_read_tlv($algId, $ao);
        if ($tOid !== 0x06 || $oid !== "\x2B\x65\x70") {
            return null; // not id-Ed25519 (1.3.101.112)
        }
        // An Ed25519 key from here on: problems are errors, not "another key type".
        if ($ao !== strlen($algId) || ($ver !== "\x00" && $ver !== "\x01")) {
            throw new InvalidArgumentException($malformed);
        }
        [$tPriv, , $privOctets] = der_read_tlv($seq, $o);
        if ($tPriv !== 0x04) {
            throw new InvalidArgumentException($malformed);
        }
        $po = 0;
        [$tSeed, , $seed] = der_read_tlv($privOctets, $po);
        if ($tSeed !== 0x04 || strlen($seed) !== 32 || $po !== strlen($privOctets)) {
            throw new InvalidArgumentException($malformed);
        }
        while ($o < strlen($seq)) {
            [$tExtra, , $extra] = der_read_tlv($seq, $o);
            if ($tExtra === 0x81) {
                // publicKey [1] IMPLICIT BIT STRING: no unused bits, then 32 bytes.
                if (strlen($extra) !== 33 || $extra[0] !== "\x00") {
                    throw new InvalidArgumentException($malformed);
                }
                $publicKey = substr($extra, 1);
            }
        }
    } catch (RuntimeException $e) {
        throw new InvalidArgumentException($malformed);
    }
    if ($publicKey !== null) {
        $derived = base64url_decode(ed25519_key_material_from_seed($seed)["ed_public"]);
        if (!hash_equals($derived, $publicKey)) {
            throw new InvalidArgumentException(
                "Ed25519 private key is inconsistent: its public key does not belong to its seed"
            );
        }
    }
    return $seed;
}

function wrap_key_entry(
    array $mat,
    string $alg,
    ?string $validFromIso = null
): array {
    $nowIso = date("c");
    $startIso = $validFromIso ?: $nowIso;
    $ttlSec = max(
        1,
        parse_validity_to_seconds(
            getenv("SIGNING_KEY_TTL") ?: (getenv("SIGNING_KEY_VALIDITY") ?: "1h")
        )
    );
    return [
        "kid" => $mat["kid"],
        "alg" => normalize_jwa_alg($alg),
        "type" => $mat["type"],
        "material" => $mat,
        "created_at" => $nowIso,
        "valid_from" => $startIso,
        "expires_at" => date("c", strtotime($startIso) + $ttlSec),
        "valid_for_seconds" => $ttlSec,
    ];
}

/**
 * PEM text of a stored RSA/EC key: material pem_content, or the legacy "pem" file path
 * (KEY_STORAGE_MIGRATION.md). Returns "" unless the result is PEM text, so a stored
 * value can never make OpenSSL load a key from a path or URI of its own choosing.
 */
function signing_key_material_pem(array $mat): string
{
    $pem = $mat["pem_content"] ?? null;
    if ((!is_string($pem) || $pem === "") && is_string($mat["pem"] ?? null) && $mat["pem"] !== "") {
        $pem = @file_get_contents($mat["pem"]);
    }
    $pem = is_string($pem) ? trim($pem) : "";
    return str_starts_with($pem, "-----BEGIN ") ? $pem : "";
}

/**
 * openssl_pkey_get_details() of a stored RSA/EC private key; throws RuntimeException.
 */
function signing_key_pkey_details(array $mat): array
{
    $pem = signing_key_material_pem($mat);
    if ($pem === "") {
        throw new RuntimeException("No PEM content available for key");
    }
    $res = openssl_pkey_get_private($pem, "");
    $det = $res !== false ? openssl_pkey_get_details($res) : false;
    if (!is_array($det)) {
        throw new RuntimeException("Unable to load stored private key");
    }
    return $det;
}

function jwk_from_key(array $key): array
{
    $alg = normalize_jwa_alg((string) ($key["alg"] ?? "RS256"));
    $kid = $key["kid"];
    $mat = is_array($key["material"] ?? null) ? $key["material"] : [];
    if (str_starts_with($alg, "RS")) {
        $det = signing_key_pkey_details($mat);
        if (!isset($det["rsa"]["n"], $det["rsa"]["e"])) {
            throw new RuntimeException("Key $kid is not an RSA key");
        }
        return [
            "kty" => "RSA",
            "alg" => $alg,
            "use" => "sig",
            "n" => base64url_encode($det["rsa"]["n"]),
            "e" => base64url_encode($det["rsa"]["e"]),
            "kid" => $kid,
        ];
    } elseif (str_starts_with($alg, "ES")) {
        $det = signing_key_pkey_details($mat);
        $curves = [
            "prime256v1" => ["P-256", 32],
            "secp384r1" => ["P-384", 48],
            "secp521r1" => ["P-521", 66],
        ];
        $curve = (string) ($det["ec"]["curve_name"] ?? "");
        if (!isset($curves[$curve])) {
            throw new RuntimeException("Unsupported EC curve for JWK: $curve");
        }
        [$crv, $size] = $curves[$curve];
        // Affine coordinates from OpenSSL work whatever point encoding the key uses
        // (an imported key may carry a compressed point). They come without leading
        // zero bytes, and a JWK needs them at the full curve size.
        $x = (string) ($det["ec"]["x"] ?? "");
        $y = (string) ($det["ec"]["y"] ?? "");
        if ($x === "" || $y === "" || strlen($x) > $size || strlen($y) > $size) {
            $xy = spki_xy_from_ec_spki((string) ($det["key"] ?? ""));
            $x = $xy["x"];
            $y = $xy["y"];
        }
        return [
            "kty" => "EC",
            "alg" => $alg,
            "use" => "sig",
            "crv" => $crv,
            "x" => base64url_encode(str_pad($x, $size, "\x00", STR_PAD_LEFT)),
            "y" => base64url_encode(str_pad($y, $size, "\x00", STR_PAD_LEFT)),
            "kid" => $kid,
        ];
    } elseif ($alg === "EdDSA") {
        return [
            "kty" => "OKP",
            "alg" => "EdDSA",
            "use" => "sig",
            "crv" => "Ed25519",
            "x" => $mat["ed_public"],
            "kid" => $kid,
        ];
    }
    throw new InvalidArgumentException("Unsupported alg for JWK: $alg");
}

function ecdsa_der_to_jose(string $der, int $coordLen): string
{
    $off = 0;
    [, , $v0] = der_read_tlv($der, $off);
    $sub = 0;
    [, , $rB] = der_read_tlv($v0, $sub);
    [, , $sB] = der_read_tlv($v0, $sub);
    $r = ltrim($rB, "\x00");
    $s = ltrim($sB, "\x00");
    $r = str_pad($r, $coordLen, "\x00", STR_PAD_LEFT);
    $s = str_pad($s, $coordLen, "\x00", STR_PAD_LEFT);
    return $r . $s;
}

/**
 * Signs $claims as a compact JWS with a provider key. $typ is the JOSE header "typ"
 * (RFC 7515 4.1.9): "JWT" by default, "at+jwt" for RFC 9068 access tokens, so that a
 * verifier can tell token types apart even when issuer, key and audience are shared.
 */
function sign_jwt_with_key(array $key, array $claims, string $typ = "JWT"): string
{
    if (preg_match('/^[A-Za-z0-9+.-]{1,32}$/D', $typ) !== 1) {
        throw new InvalidArgumentException("Invalid JWT typ header value");
    }
    $alg = normalize_jwa_alg((string) ($key["alg"] ?? "RS256"));
    $header = ["typ" => $typ, "kid" => $key["kid"], "alg" => $alg];

    $h = base64url_encode((string) json_encode($header, JSON_UNESCAPED_SLASHES));
    $p = base64url_encode((string) json_encode($claims, JSON_UNESCAPED_SLASHES));
    $input = $h . "." . $p;

    if (str_starts_with($alg, "RS") || str_starts_with($alg, "ES")) {
        $pem = signing_key_material_pem($key["material"] ?? []);
        if ($pem === "") {
            throw new RuntimeException("No PEM content available for signing");
        }
        $res = openssl_pkey_get_private($pem, "");
        if ($res === false) {
            throw new RuntimeException("Unable to load the signing key");
        }
        $hash =
            $alg === "RS256" || $alg === "ES256"
                ? OPENSSL_ALGO_SHA256
                : ($alg === "RS384" || $alg === "ES384"
                    ? OPENSSL_ALGO_SHA384
                    : OPENSSL_ALGO_SHA512);
        $ok = openssl_sign($input, $sig, $res, $hash);
        if (!$ok) {
            throw new RuntimeException("OpenSSL signing failed");
        }
        if (str_starts_with($alg, "ES")) {
            $coordLen = $alg === "ES256" ? 32 : ($alg === "ES384" ? 48 : 66);
            $sig = ecdsa_der_to_jose($sig, $coordLen);
        }
    } elseif ($alg === "EdDSA") {
        $sk = base64url_decode($key["material"]["ed_secret"]);
        $sig = sodium_crypto_sign_detached($input, $sk);
    } else {
        throw new InvalidArgumentException("Unsupported alg: $alg");
    }
    return $input . "." . base64url_encode($sig);
}

// Automatic key rotation (resolve_signing_key_for_provider()). Timings stored before the
// admin API enforced its limits are clamped at runtime, so they cannot make every signing
// call rotate (S10-07): a key TTL is at least PROVIDER_KEY_MIN_TTL_SECONDS, and the lead
// time leaves every key at least that long as the active key (the API rule: lead 0, or
// TTL - lead >= 300 s). Rotation removes up to PROVIDER_KEY_PRUNE_BATCH keys that have left
// the JWKS and keeps at most PROVIDER_KEY_ROTATION_MAX_KEYS keys per provider. A key that
// still verifies an unexpired token it signed is never removed to stay under that limit
// (S04-03): when every key is still needed, the current key is kept for another key TTL
// instead of adding one (provider_key_extend_current()), which is logged. With the default
// 1-hour key TTL that happens only for tokens valid for more than about 99 hours that are
// issued at least once per key period.
const PROVIDER_KEY_MIN_TTL_SECONDS = 300;
const PROVIDER_KEY_ROTATION_MAX_KEYS = 100;
const PROVIDER_KEY_PRUNE_BATCH = 100;

/** [key TTL, rotation lead time] in seconds for automatic rotation, clamped (see above). */
function provider_key_rotation_timing(array $provider): array
{
    $ttlSec = max(PROVIDER_KEY_MIN_TTL_SECONDS, provider_ttl_seconds($provider));
    $leadTimeSec = max(
        0,
        min(
            (int) ($provider["key_rotation_lead_time_seconds"] ?? 0),
            $ttlSec - PROVIDER_KEY_MIN_TTL_SECONDS
        )
    );
    return [$ttlSec, $leadTimeSec];
}

/** expires_at of a key as a Unix timestamp, or null when it has none that parses. */
function provider_key_expiry_ts(array $k): ?int
{
    $exp = $k["expires_at"] ?? null;
    if (!is_string($exp) || trim($exp) === "") {
        return null;
    }
    $ts = strtotime($exp);
    return $ts === false ? null : $ts;
}

/**
 * The key a provider signs with before any rotation: the key named by active_kid, else its
 * first key; null when it has no keys.
 */
function provider_current_signing_key(array $provider): ?array
{
    $keys = array_values(array_filter($provider["keys"] ?? [], "is_array"));
    $activeKid = (string) ($provider["active_kid"] ?? "");
    foreach ($keys as $k) {
        if ((string) ($k["kid"] ?? "") === $activeKid) {
            return $k;
        }
    }
    return $keys[0] ?? null;
}

/**
 * When a key stops being used for signing: its expires_at, or for a key without a usable
 * expiry, $ttlSec after its creation (counted from now when that is unknown as well).
 */
function provider_key_effective_expiry_ts(array $key, int $ttlSec, int $now): int
{
    $expTs = provider_key_expiry_ts($key);
    if ($expTs !== null) {
        return $expTs;
    }
    $created = provider_key_created_ts($key);
    return ($created > 0 ? $created : $now) + $ttlSec;
}

/**
 * Is the provider's current key due for replacement (its effective expiry minus the lead
 * time has passed)?
 */
function provider_key_rotation_due(array $key, int $ttlSec, int $leadTimeSec, int $now): bool
{
    return $now >= provider_key_effective_expiry_ts($key, $ttlSec, $now) - $leadTimeSec;
}

/**
 * Another key of the provider (not $currentKid, the key being replaced) that may take over as
 * the active key: unexpired and not yet within the lead time of its effective expiry, or null.
 */
function provider_key_rotation_candidate(
    array $provider,
    int $ttlSec,
    int $leadTimeSec,
    int $now,
    string $currentKid = ""
): ?array {
    foreach ($provider["keys"] ?? [] as $cand) {
        if (
            !is_array($cand) ||
            ($currentKid !== "" && (string) ($cand["kid"] ?? "") === $currentKid) ||
            key_is_expired($cand)
        ) {
            continue;
        }
        if ($now < provider_key_effective_expiry_ts($cand, $ttlSec, $now) - $leadTimeSec) {
            return $cand;
        }
    }
    return null;
}

/**
 * What provider_key_make_room() deletes before a rotated key is added, as
 * ["prune" => kids, "evict" => kids, "room" => bool]. Pure; $keepKid (the key being
 * replaced) and the active key are never listed.
 * - prune: up to PROVIDER_KEY_PRUNE_BATCH keys that have left the JWKS (see
 *   provider_key_is_publishable()), in key order.
 * - evict: while PROVIDER_KEY_ROTATION_MAX_KEYS keys or more would remain, up to as many
 *   published keys that no unexpired token needs any more (max_token_exp has passed, so only
 *   the retention period keeps them published), the soonest to leave the JWKS first. A key
 *   that still verifies an unexpired token it signed is never evicted (S04-03).
 * - room: whether fewer than PROVIDER_KEY_ROTATION_MAX_KEYS keys are left afterwards, so a
 *   key can be added without exceeding the limit (S10-07).
 */
function provider_key_room_plan(array $provider, int $now, string $keepKid = ""): array
{
    $active = provider_active_signing_key($provider);
    $activeKid = $active !== null ? (string) ($active["kid"] ?? "") : "";
    $prune = [];
    $remaining = [];
    foreach ($provider["keys"] ?? [] as $k) {
        if (!is_array($k)) {
            continue;
        }
        $kid = (string) ($k["kid"] ?? "");
        // For a key that is not the active one this is provider_key_is_publishable().
        $until = provider_key_publish_until($provider, $k);
        if (
            $kid !== $activeKid &&
            $kid !== $keepKid &&
            count($prune) < PROVIDER_KEY_PRUNE_BATCH &&
            $until !== null &&
            $until <= $now
        ) {
            $prune[] = $kid;
            continue;
        }
        $remaining[] = $k;
    }

    $excess = min(
        PROVIDER_KEY_PRUNE_BATCH,
        count($remaining) - PROVIDER_KEY_ROTATION_MAX_KEYS + 1
    );
    $evict = [];
    if ($excess > 0) {
        $evictable = [];
        foreach ($remaining as $k) {
            $kid = (string) ($k["kid"] ?? "");
            if ($kid === $activeKid || $kid === $keepKid || (int) ($k["max_token_exp"] ?? 0) > $now) {
                continue;
            }
            $evictable[] = [
                "kid" => $kid,
                "until" => provider_key_publish_until($provider, $k) ?? PHP_INT_MAX,
                "created" => provider_key_created_ts($k),
            ];
        }
        usort(
            $evictable,
            static fn(array $a, array $b): int => [$a["until"], $a["created"]] <=> [$b["until"], $b["created"]]
        );
        $evict = array_column(array_slice($evictable, 0, $excess), "kid");
    }
    return [
        "prune" => $prune,
        "evict" => $evict,
        "room" => count($remaining) - count($evict) < PROVIDER_KEY_ROTATION_MAX_KEYS,
    ];
}

/**
 * Makes room before a rotated key is added (S10-07, S04-03): deletes the keys
 * provider_key_room_plan() lists and logs the evicted ones. Returns true when the provider
 * then has fewer than PROVIDER_KEY_ROTATION_MAX_KEYS keys; false when every remaining key
 * still verifies an unexpired token, and the caller must keep the current key
 * (provider_key_extend_current()) instead of adding one. The active key, $keepKid and the
 * last key are never deleted (provider_key_delete()). Runs inside the caller's write
 * transaction.
 */
function provider_key_make_room(string $storePath, array $provider, int $now, string $keepKid = ""): bool
{
    $providerId = (string) $provider["id"];
    $plan = provider_key_room_plan($provider, $now, $keepKid);
    $deleted = 0;
    foreach ($plan["prune"] as $kid) {
        if (provider_key_delete($storePath, $providerId, $kid)) {
            $deleted++;
        }
    }
    $evicted = [];
    foreach ($plan["evict"] as $kid) {
        if (provider_key_delete($storePath, $providerId, $kid)) {
            $evicted[] = $kid;
        }
    }
    if ($evicted !== []) {
        error_log(
            "Key rotation for provider " . $providerId . " reached " . PROVIDER_KEY_ROTATION_MAX_KEYS .
                " keys and removed published key(s) whose signed tokens have all expired (kept only by the" .
                " retention period): " . implode(", ", $evicted)
        );
    }
    $total = count(array_filter($provider["keys"] ?? [], "is_array"));
    return $total - $deleted - count($evicted) < PROVIDER_KEY_ROTATION_MAX_KEYS;
}

/**
 * Keeps $key, the provider's current signing key, in use for another $ttlSec instead of
 * adding a key (S04-03): used when the provider holds PROVIDER_KEY_ROTATION_MAX_KEYS keys
 * that all still verify unexpired tokens, so that neither a key such a token needs is
 * removed nor the key limit (S10-07) exceeded. expires_at becomes $now + $ttlSec (never
 * earlier than before), valid_for_seconds follows, and the key becomes active_kid. Logs the
 * extension. Returns false, changing nothing, when the key no longer exists. Runs inside the
 * caller's write transaction.
 */
function provider_key_extend_current(
    string $storePath,
    array $provider,
    array $key,
    int $ttlSec,
    int $now
): bool {
    $providerId = (string) $provider["id"];
    $kid = (string) ($key["kid"] ?? "");
    if ($kid === "") {
        return false;
    }
    $newExp = max(provider_key_expiry_ts($key) ?? 0, $now + $ttlSec);
    $start = provider_key_created_ts($key);
    $stmt = storage_db($storePath)->prepare(
        "UPDATE provider_keys SET expires_at = :exp, valid_for_seconds = COALESCE(:vfs, valid_for_seconds) " .
            "WHERE provider_id = :p AND kid = :k"
    );
    storage_execute($stmt, [
        ":exp" => date("c", $newExp),
        ":vfs" => $start > 0 && $start < $newExp ? $newExp - $start : null,
        ":p" => $providerId,
        ":k" => $kid,
    ]);
    if ($stmt->rowCount() !== 1) {
        return false;
    }
    provider_update_fields($storePath, $providerId, [
        "active_kid" => $kid,
        "alg" => normalize_jwa_alg((string) (($key["alg"] ?? null) ?: ($provider["alg"] ?? null) ?: "RS256")),
    ]);
    error_log(
        "Key rotation for provider " . $providerId . ": the provider has reached the limit of " .
            PROVIDER_KEY_ROTATION_MAX_KEYS . " signing keys and no key that still verifies unexpired tokens" .
            " is removed to make room, so key " . $kid . " stays in use until " . date("c", $newExp) .
            " instead of being replaced. Shorter token lifetimes or a longer key TTL let rotation resume."
    );
    return true;
}

/**
 * Rotates the provider's signing key in one BEGIN IMMEDIATE transaction (S06-02, X4-02,
 * S10-07, S04-03): re-reads the provider, keeps a key another request activated in the
 * meantime, else promotes a candidate key (active_kid and alg follow it), else adds $newEntry,
 * generated by the caller outside the lock, as the active key after making room. When no room
 * can be made because every key still verifies unexpired tokens, the current key is kept for
 * another key TTL instead (provider_key_extend_current()). Only this provider's rows are
 * written, never a snapshot of all providers. Returns [the provider as stored afterwards, the
 * key to sign with]; $newEntry is generated here only when it is needed but the caller did
 * not expect it.
 */
function provider_key_rotate(
    string $storePath,
    string $providerId,
    ?array $newEntry,
    string $keysDir = ""
): array {
    storage_initialize($storePath);
    $pdo = storage_db($storePath);
    return storage_write_transaction(
        $pdo,
        function (PDO $pdo) use ($storePath, $providerId, $newEntry, $keysDir): array {
            $fresh = storage_load_providers($pdo, $providerId)[0] ?? null;
            if ($fresh === null) {
                throw new RuntimeException("Provider not found");
            }
            [$ttlSec, $leadTimeSec] = provider_key_rotation_timing($fresh);
            $now = time();
            $current = provider_current_signing_key($fresh);
            if ($current !== null && !provider_key_rotation_due($current, $ttlSec, $leadTimeSec, $now)) {
                // Another request rotated (or an admin activated a key) in the meantime.
                return [$fresh, $current];
            }
            $candidate = provider_key_rotation_candidate(
                $fresh,
                $ttlSec,
                $leadTimeSec,
                $now,
                $current !== null ? (string) ($current["kid"] ?? "") : ""
            );
            if ($candidate !== null) {
                provider_update_fields($storePath, $providerId, [
                    "active_kid" => (string) $candidate["kid"],
                    "alg" => normalize_jwa_alg(
                        (string) ($candidate["alg"] ?? ($fresh["alg"] ?? "RS256"))
                    ),
                ]);
            } else {
                // A provider without keys ($current === null) always has room.
                $hasRoom = $current === null ||
                    provider_key_make_room($storePath, $fresh, $now, (string) ($current["kid"] ?? ""));
                if (!$hasRoom && provider_key_extend_current($storePath, $fresh, $current, $ttlSec, $now)) {
                    $candidate = $current;
                } else {
                    if ($newEntry === null) {
                        $newEntry = provider_key_new_rotation_entry($fresh, $current, $ttlSec, $keysDir);
                    }
                    provider_key_insert($storePath, $providerId, $newEntry, true);
                    $candidate = $newEntry;
                }
            }
            $stored = storage_load_providers($pdo, $providerId)[0] ?? $fresh;
            foreach ($stored["keys"] ?? [] as $k) {
                if (is_array($k) && (string) ($k["kid"] ?? "") === (string) $candidate["kid"]) {
                    $candidate = $k;
                    break;
                }
            }
            return [$stored, $candidate];
        }
    );
}

/**
 * A new key entry for automatic rotation: the algorithm of the key being replaced (else the
 * provider's alg, else RS256), so rotation never switches the algorithm back (S10-09), valid
 * for $ttlSec from now.
 */
function provider_key_new_rotation_entry(
    array $provider,
    ?array $currentKey,
    int $ttlSec,
    string $keysDir = ""
): array {
    $algToUse = normalize_jwa_alg(
        (string) (($currentKey["alg"] ?? null) ?: ($provider["alg"] ?? null) ?: "RS256")
    );
    $mat = create_keypair($algToUse, $keysDir);
    $newEntry = wrap_key_entry($mat, $algToUse, date("c"));
    $newEntry["valid_for_seconds"] = $ttlSec;
    $newEntry["expires_at"] = date("c", time() + $ttlSec);
    return $newEntry;
}

/**
 * Selects (and auto-rotates if within lead time / expired) the active signing key for a provider.
 * A rotation writes only this provider's rows (provider_key_rotate()); $provider and the
 * matching entries of $providers are updated in memory. If the database is busy, signing
 * continues with the current key and the rotation is retried on a later call.
 */
function resolve_signing_key_for_provider(
    string $storePath,
    array &$providers,
    array &$provider,
    string $keysDir = ""
): array {
    $keyToUse = provider_current_signing_key($provider);
    if (!$keyToUse) {
        throw new RuntimeException("No active key set");
    }

    [$ttlSec, $leadTimeSec] = provider_key_rotation_timing($provider);
    $now = time();
    if (provider_key_rotation_due($keyToUse, $ttlSec, $leadTimeSec, $now)) {
        // The key pair is generated before the write lock is taken; it is discarded if
        // another request has rotated meanwhile. None is generated when a candidate key takes
        // over, or when no key can be added because every key still verifies unexpired
        // tokens (the current key is then extended, S04-03).
        $currentKid = (string) ($keyToUse["kid"] ?? "");
        $needsNewKey = provider_key_rotation_candidate(
            $provider,
            $ttlSec,
            $leadTimeSec,
            $now,
            $currentKid
        ) === null && provider_key_room_plan($provider, $now, $currentKid)["room"];
        $newEntry = $needsNewKey
            ? provider_key_new_rotation_entry($provider, $keyToUse, $ttlSec, $keysDir)
            : null;
        try {
            [$stored, $keyToUse] = provider_key_rotate(
                $storePath,
                (string) $provider["id"],
                $newEntry,
                $keysDir
            );
            $provider = $stored;
            foreach ($providers as $i => $pp) {
                if (is_array($pp) && (string) ($pp["id"] ?? "") === (string) $stored["id"]) {
                    $providers[$i] = $stored;
                }
            }
        } catch (PDOException $e) {
            if (storage_db($storePath)->inTransaction()) {
                // Part of the caller's transaction: the caller has to roll back.
                throw $e;
            }
            error_log(
                "Signing key rotation for provider " . (string) $provider["id"] .
                    " failed; signing with the current key: " . $e->getMessage()
            );
        }
    }

    if (key_is_expired($keyToUse)) {
        $keyToUse = null;
        foreach ($provider["keys"] ?? [] as $cand) {
            if (!key_is_expired($cand)) {
                $keyToUse = $cand;
                break;
            }
        }
        if (!$keyToUse) {
            throw new RuntimeException("No unexpired signing key available");
        }
    }

    return $keyToUse;
}

// ---------- SAML 2.0 X.509 Certificate Helpers ----------

function clean_pem_certificate_body(string $pem): string
{
    $lines = preg_split('/\r?\n/', trim($pem)) ?: [];
    $filtered = array_filter(
        $lines,
        fn($l) => trim($l) !== "" && !str_starts_with(trim($l), "---")
    );
    return preg_replace('/\s+/', "", implode("", $filtered)) ?? "";
}

function wrap_pem_certificate(string $base64Body): string
{
    $clean = preg_replace('/\s+/', "", $base64Body) ?? "";
    return "-----BEGIN CERTIFICATE-----\n" .
        chunk_split($clean, 64, "\n") .
        "-----END CERTIFICATE-----\n";
}

function generate_saml_self_signed_cert(
    string $commonName,
    string $orgName = "Simple IdP",
    int $days = 3650
): array {
    $privKey = openssl_pkey_new([
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
        "private_key_bits" => 2048,
    ]);
    if (!$privKey) {
        throw new RuntimeException("Failed to generate RSA-2048 key for SAML");
    }

    // X.520 caps O and CN at 64 characters, and OpenSSL rejects invalid UTF-8 and empty
    // values. Cut on code points (a byte cut can split a character), drop control and
    // bidi characters, and fall back to ASCII when nothing is left.
    $org = sanitize_label($orgName, 64);
    $cn = sanitize_label($commonName, 64);
    $dn = [
        "countryName" => "US",
        "organizationName" => $org !== "" ? $org : "Simple IdP",
        "commonName" => $cn !== "" ? $cn : "simple-idp",
    ];

    $csr = openssl_csr_new($dn, $privKey, ["digest_alg" => "sha256"]);
    if (!$csr) {
        throw new RuntimeException("Failed to create SAML X.509 CSR");
    }

    $serial = random_int(100000, PHP_INT_MAX >> 16);
    $x509 = openssl_csr_sign(
        $csr,
        null,
        $privKey,
        $days,
        ["digest_alg" => "sha256"],
        $serial
    );
    if (!$x509) {
        throw new RuntimeException("Failed to sign SAML X.509 certificate");
    }

    openssl_pkey_export($privKey, $privPem);
    openssl_x509_export($x509, $certPem);
    $fp = openssl_x509_fingerprint($x509, "sha256") ?: hash("sha256", $certPem);
    $parsed = openssl_x509_parse($x509);
    $validTo = isset($parsed["validTo_time_t"])
        ? gmdate("Y-m-d\TH:i:s\Z", (int) $parsed["validTo_time_t"])
        : gmdate("Y-m-d\TH:i:s\Z", time() + $days * 86400);

    return [
        "kid" => "saml-" . substr($fp, 0, 16),
        "private_key_pem" => $privPem,
        "cert_pem" => $certPem,
        "fingerprint_sha256" => strtolower($fp),
        "expires_at" => $validTo,
    ];
}

// SAML signing certificates have a state (columns added by crypto.saml_cert_states_v1):
//   active   is_active = 1; signs, and is published in metadata.
//   next     staged by rotate_provider_saml_cert(..., false); published, does not sign.
//   retired  replaced at retired_at; published, and can be activated again (rollback),
//            for SAML_CERT_RETIRED_GRACE_SECONDS.
// Rows written before the migration have state NULL: is_active = 1 is active, any other
// legacy row was retired at an unknown time and is neither published nor re-activated.
// Expired certificates are never published or activated, except the active one, which
// always stays published because it is the one that signs.
// Expiry (G1a-04): an expired active certificate keeps signing, because SPs that pinned it
// or ignore its validity keep working, and switching keys on its own would break them.
// Instead every row reports expired / expires_in_days / expires_soon (less than
// SAML_CERT_EXPIRY_WARNING_SECONDS left, or a third of the certificate's validity period
// when that is shorter, so a certificate with the minimum validity of 30 days is not
// reported as expiring from the day it is created), and ensure_provider_saml_cert() logs an
// expired active certificate at most once an hour and one about to expire at most once a
// day. Certificates that can never sign again lose their private key
// (provider_saml_cert_purge_unusable_keys()).
const SAML_CERT_RETIRED_GRACE_SECONDS = 30 * 86400;
const SAML_CERT_EXPIRY_WARNING_SECONDS = 30 * 86400;

/**
 * storage_db() for the provider_saml_certs helpers, with the state columns in place.
 */
function provider_saml_cert_db(string $storePath): PDO
{
    $pdo = storage_db($storePath);
    if (!$pdo->inTransaction()) {
        try {
            schema_ensure($pdo, "crypto.saml_cert_states_v1", [
                "ALTER TABLE provider_saml_certs ADD COLUMN state TEXT",
                "ALTER TABLE provider_saml_certs ADD COLUMN retired_at TEXT",
            ]);
        } catch (LogicException $e) {
            // Called inside a transaction PDO did not report; the next call migrates.
        }
    }
    return $pdo;
}

/**
 * Runs $fn($pdo) in a write transaction (BEGIN IMMEDIATE), or directly when the caller
 * already holds one.
 */
function provider_saml_cert_tx(PDO $pdo, callable $fn): mixed
{
    if ($pdo->inTransaction()) {
        return $fn($pdo);
    }
    $pdo->exec("BEGIN IMMEDIATE");
    try {
        $result = $fn($pdo);
        $pdo->exec("COMMIT");
        return $result;
    } catch (Throwable $e) {
        try {
            $pdo->exec("ROLLBACK");
        } catch (Throwable $rollbackError) {
            // The original error is the one worth reporting.
        }
        throw $e;
    }
}

/**
 * Normalizes a provider_saml_certs row: id, provider_id, kid, [private_key_pem,] cert_pem,
 * fingerprint_sha256, is_active (0/1), state (active/next/retired), created_at,
 * expires_at, retired_at, and the expiry status at the time of the call (G1a-04): expired
 * (bool), expires_in_days (whole days left, negative once expired; null when expires_at is
 * unknown) and expires_soon (not expired, less than SAML_CERT_EXPIRY_WARNING_SECONDS left,
 * or less than a third of the validity period from created_at when that is shorter).
 * is_active is authoritative for "active".
 */
function provider_saml_cert_row(array $r, bool $withPrivateKey = false): array
{
    $isActive = (int) ($r["is_active"] ?? 0) === 1;
    $state = $r["state"] ?? null;
    if ($isActive) {
        $state = "active";
    } elseif ($state !== "next" && $state !== "retired") {
        $state = "retired";
    }
    $row = [
        "id" => (string) ($r["id"] ?? ""),
        "provider_id" => (string) ($r["provider_id"] ?? ""),
        "kid" => (string) ($r["kid"] ?? ""),
    ];
    if ($withPrivateKey) {
        $row["private_key_pem"] = (string) ($r["private_key_pem"] ?? "");
    }
    $expiresAt = $r["expires_at"] ?? null;
    $expTs = is_string($expiresAt) && $expiresAt !== "" ? strtotime($expiresAt) : false;
    $left = $expTs !== false ? $expTs - time() : null;
    $createdAt = $r["created_at"] ?? null;
    $createdTs = is_string($createdAt) && $createdAt !== "" ? strtotime($createdAt) : false;
    $warnWindow = SAML_CERT_EXPIRY_WARNING_SECONDS;
    if ($expTs !== false && $createdTs !== false && $expTs > $createdTs) {
        $warnWindow = min($warnWindow, intdiv($expTs - $createdTs, 3));
    }
    return $row + [
        "cert_pem" => (string) ($r["cert_pem"] ?? ""),
        "fingerprint_sha256" => (string) ($r["fingerprint_sha256"] ?? ""),
        "is_active" => $isActive ? 1 : 0,
        "state" => $state,
        "created_at" => $r["created_at"] ?? null,
        "expires_at" => $expiresAt,
        "retired_at" => $state === "retired" ? ($r["retired_at"] ?? null) : null,
        "expired" => $left !== null && $left <= 0,
        "expires_in_days" => $left !== null ? (int) floor($left / 86400) : null,
        "expires_soon" => $left !== null && $left > 0 && $left < $warnWindow,
    ];
}

function provider_saml_cert_is_expired(array $row, ?int $now = null): bool
{
    $exp = $row["expires_at"] ?? null;
    if (!is_string($exp) || $exp === "") {
        return false;
    }
    $ts = strtotime($exp);
    return $ts !== false && $ts <= ($now ?? time());
}

/**
 * True for a certificate retired less than SAML_CERT_RETIRED_GRACE_SECONDS ago (never
 * for legacy rows, whose retirement time is unknown).
 */
function provider_saml_cert_in_grace(array $row, ?int $now = null): bool
{
    if (($row["state"] ?? null) !== "retired") {
        return false;
    }
    $at = $row["retired_at"] ?? null;
    if (!is_string($at) || $at === "") {
        return false;
    }
    $ts = strtotime($at);
    return $ts !== false && $ts + SAML_CERT_RETIRED_GRACE_SECONDS > ($now ?? time());
}

/**
 * The newest active certificate of a provider, with its private key, or null.
 */
function provider_saml_cert_find_active(PDO $pdo, string $providerId): ?array
{
    $stmt = $pdo->prepare(
        "SELECT * FROM provider_saml_certs WHERE provider_id = :pid AND is_active = 1 " .
            "ORDER BY created_at DESC, rowid DESC LIMIT 1"
    );
    $stmt->execute([":pid" => $providerId]);
    $r = $stmt->fetch(PDO::FETCH_ASSOC);
    return is_array($r) ? provider_saml_cert_row($r, true) : null;
}

/**
 * Logs that the provider's active signing certificate $cert (a provider_saml_cert_row())
 * has expired, at most once an hour, or expires soon (its expires_soon), at most once a
 * day (G1a-04). The throttle is shared by all requests (auth_rate_limits), so the
 * unauthenticated metadata endpoint cannot flood the log. Best effort, never throws.
 */
function provider_saml_cert_warn_expiry(string $storePath, string $providerId, array $cert): void
{
    $expired = !empty($cert["expired"]);
    if (!$expired && empty($cert["expires_soon"])) {
        return;
    }
    $window = $expired ? 3600 : 86400;
    try {
        $bucket = rate_limit_bucket(
            $expired ? "saml_cert_expired_log" : "saml_cert_expiring_log",
            $providerId,
            (string) ($cert["id"] ?? "")
        );
        if (rate_limit_hit($storePath, $bucket, 1, $window, $window)) {
            return;
        }
    } catch (Throwable $e) {
        return;
    }
    $what = "SAML: the active signing certificate " . (string) ($cert["kid"] ?? "") . " of provider " .
        $providerId;
    $when = (string) ($cert["expires_at"] ?? "");
    error_log(
        $expired
            ? $what . " expired at " . $when . " and still signs every SAML message; SPs that check " .
                "certificate validity reject them. Stage a new certificate, let the SPs import the " .
                "metadata, then activate it."
            : $what . " expires at " . $when . " (in " . (int) ($cert["expires_in_days"] ?? 0) .
                " day(s)). Stage a new certificate now and activate it once the SPs have imported the metadata."
    );
}

/**
 * Removes the private keys of the provider's certificates that can never sign again
 * (G1a-04): non-active certificates that have expired, and retired ones past
 * SAML_CERT_RETIRED_GRACE_SECONDS (legacy retired rows included). A staged ('next')
 * certificate keeps its key until it expires, and the certificates stay listed. Returns
 * the number of keys removed. Joins the caller's transaction when one is open.
 */
function provider_saml_cert_purge_unusable_keys(PDO $pdo, string $providerId, ?int $now = null): int
{
    $now ??= time();
    $stmt = $pdo->prepare(
        "SELECT id, provider_id, kid, is_active, state, expires_at, retired_at FROM provider_saml_certs " .
            "WHERE provider_id = :pid AND is_active = 0 AND private_key_pem <> ''"
    );
    $stmt->execute([":pid" => $providerId]);
    $ids = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $row = provider_saml_cert_row($r);
        if (
            provider_saml_cert_is_expired($row, $now) ||
            ($row["state"] !== "next" && !provider_saml_cert_in_grace($row, $now))
        ) {
            $ids[] = $row["id"];
        }
    }
    if ($ids === []) {
        return 0;
    }
    $upd = $pdo->prepare(
        "UPDATE provider_saml_certs SET private_key_pem = '' WHERE id = :id AND provider_id = :pid AND is_active = 0"
    );
    foreach ($ids as $id) {
        $upd->execute([":id" => $id, ":pid" => $providerId]);
    }
    return count($ids);
}

/**
 * Returns the provider's active signing certificate (with private_key_pem), creating
 * one if the provider has none. A staged 'next' certificate takes over only when no
 * certificate is active; a retired one is never re-activated implicitly. An expired active
 * certificate is still returned, and logged (provider_saml_cert_warn_expiry()).
 */
function ensure_provider_saml_cert(string $storePath, array $provider): array
{
    $pdo = provider_saml_cert_db($storePath);
    $providerId = (string) $provider["id"];
    $active = provider_saml_cert_find_active($pdo, $providerId);
    if ($active !== null) {
        provider_saml_cert_warn_expiry($storePath, $providerId, $active);
        // Keys whose grace period ended are removed here too, not only when an admin next
        // rotates, activates or deletes a certificate; about one call in 20 checks.
        if (mt_rand(1, 20) === 1) {
            try {
                provider_saml_cert_purge_unusable_keys($pdo, $providerId);
            } catch (Throwable $e) {
                // Best effort (for example a busy database); a later call retries.
            }
        }
        return $active;
    }

    $promote = function (PDO $pdo) use ($providerId): ?array {
        $active = provider_saml_cert_find_active($pdo, $providerId);
        if ($active !== null) {
            return $active;
        }
        $stmt = $pdo->prepare(
            "SELECT * FROM provider_saml_certs WHERE provider_id = :pid AND is_active = 0 AND state = 'next' " .
                "ORDER BY created_at DESC, rowid DESC"
        );
        $stmt->execute([":pid" => $providerId]);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
            if (provider_saml_cert_is_expired($r) || (string) ($r["private_key_pem"] ?? "") === "") {
                continue;
            }
            $pdo->prepare(
                "UPDATE provider_saml_certs SET is_active = 1, state = 'active', retired_at = NULL WHERE id = :id"
            )->execute([":id" => $r["id"]]);
            $r["is_active"] = 1;
            $r["state"] = "active";
            return provider_saml_cert_row($r, true);
        }
        return null;
    };
    $active = provider_saml_cert_tx($pdo, $promote);
    if ($active !== null) {
        return $active;
    }

    // Generate outside the write lock (RSA key generation is slow), then insert unless
    // a concurrent request has installed a certificate in the meantime.
    $generated = generate_saml_self_signed_cert(
        $provider["idp_id"],
        "Simple IdP - " . $provider["friendly"],
        3650
    );
    return provider_saml_cert_tx($pdo, function (PDO $pdo) use ($providerId, $generated, $promote): array {
        $active = $promote($pdo);
        if ($active !== null) {
            return $active;
        }
        $row = [
            "id" => uuidv4(),
            "provider_id" => $providerId,
            "kid" => $generated["kid"],
            "private_key_pem" => $generated["private_key_pem"],
            "cert_pem" => $generated["cert_pem"],
            "fingerprint_sha256" => $generated["fingerprint_sha256"],
            "is_active" => 1,
            "state" => "active",
            "created_at" => gmdate("Y-m-d\TH:i:s\Z"),
            "expires_at" => $generated["expires_at"],
            "retired_at" => null,
        ];
        provider_saml_cert_insert($pdo, $row);
        return provider_saml_cert_row($row, true);
    });
}

function provider_saml_cert_insert(PDO $pdo, array $row): void
{
    $pdo->prepare(
        "INSERT INTO provider_saml_certs (id, provider_id, kid, private_key_pem, cert_pem, fingerprint_sha256, is_active, state, created_at, expires_at, retired_at) " .
            "VALUES (:id, :pid, :kid, :priv, :cert, :fp, :active, :state, :cat, :exp, NULL)"
    )->execute([
        ":id" => $row["id"],
        ":pid" => $row["provider_id"],
        ":kid" => $row["kid"],
        ":priv" => $row["private_key_pem"],
        ":cert" => $row["cert_pem"],
        ":fp" => $row["fingerprint_sha256"],
        ":active" => (int) $row["is_active"],
        ":state" => $row["state"],
        ":cat" => $row["created_at"],
        ":exp" => $row["expires_at"],
    ]);
}

/**
 * Creates a new signing certificate for the provider and returns it (without the
 * private key). Any earlier staged ('next') certificate is retired.
 * $activateNow = true: the new certificate signs immediately, and the previous active
 * certificate is retired (still published, and re-activatable, for the grace period).
 * $activateNow = false: the new certificate is staged as 'next': published in metadata
 * so SPs can pick it up, but not used for signing until activate_provider_saml_cert().
 * Private keys of certificates that can never sign again are removed in the same
 * transaction (provider_saml_cert_purge_unusable_keys()), as on activation and deletion.
 */
function rotate_provider_saml_cert(
    string $storePath,
    array $provider,
    int $days = 3650,
    bool $activateNow = true
): array {
    $pdo = provider_saml_cert_db($storePath);
    $generated = generate_saml_self_signed_cert(
        $provider["idp_id"],
        "Simple IdP - " . $provider["friendly"],
        max(1, min(3650, $days))
    );
    $now = gmdate("Y-m-d\TH:i:s\Z");
    $row = [
        "id" => uuidv4(),
        "provider_id" => (string) $provider["id"],
        "kid" => $generated["kid"],
        "private_key_pem" => $generated["private_key_pem"],
        "cert_pem" => $generated["cert_pem"],
        "fingerprint_sha256" => $generated["fingerprint_sha256"],
        "is_active" => $activateNow ? 1 : 0,
        "state" => $activateNow ? "active" : "next",
        "created_at" => $now,
        "expires_at" => $generated["expires_at"],
        "retired_at" => null,
    ];
    provider_saml_cert_tx($pdo, function (PDO $pdo) use ($row, $now, $activateNow): void {
        $pid = $row["provider_id"];
        $pdo->prepare(
            "UPDATE provider_saml_certs SET state = 'retired', retired_at = :now " .
                "WHERE provider_id = :pid AND is_active = 0 AND state = 'next'"
        )->execute([":now" => $now, ":pid" => $pid]);
        if ($activateNow) {
            $pdo->prepare(
                "UPDATE provider_saml_certs SET is_active = 0, state = 'retired', retired_at = :now " .
                    "WHERE provider_id = :pid AND is_active = 1"
            )->execute([":now" => $now, ":pid" => $pid]);
        }
        provider_saml_cert_insert($pdo, $row);
        provider_saml_cert_purge_unusable_keys($pdo, $pid);
    });
    return provider_saml_cert_row($row);
}

/**
 * Makes a staged ('next') certificate, or one retired within the grace period, the
 * active signing certificate; the current active certificate becomes retired. Returns
 * the activated certificate (without the private key). Activating the active
 * certificate is a no-op. Throws InvalidArgumentException ("SAML certificate not
 * found" for an unknown id or another provider's certificate; otherwise the reason it
 * cannot be activated).
 */
function activate_provider_saml_cert(
    string $storePath,
    array $provider,
    string $certId
): array {
    $pdo = provider_saml_cert_db($storePath);
    $providerId = (string) $provider["id"];
    return provider_saml_cert_tx($pdo, function (PDO $pdo) use ($providerId, $certId): array {
        $stmt = $pdo->prepare(
            "SELECT * FROM provider_saml_certs WHERE id = :id AND provider_id = :pid LIMIT 1"
        );
        $stmt->execute([":id" => $certId, ":pid" => $providerId]);
        $r = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!is_array($r)) {
            throw new InvalidArgumentException("SAML certificate not found");
        }
        $row = provider_saml_cert_row($r);
        if ($row["state"] === "active") {
            return $row;
        }
        $nowTs = time();
        if (provider_saml_cert_is_expired($row, $nowTs)) {
            throw new InvalidArgumentException("This SAML certificate has expired and cannot be activated");
        }
        if ($row["state"] !== "next" && !provider_saml_cert_in_grace($row, $nowTs)) {
            throw new InvalidArgumentException(
                "Only a staged (next) certificate, or one retired less than " .
                    intdiv(SAML_CERT_RETIRED_GRACE_SECONDS, 86400) .
                    " days ago, can be activated"
            );
        }
        if ((string) ($r["private_key_pem"] ?? "") === "") {
            throw new InvalidArgumentException(
                "This SAML certificate can no longer sign: its private key has been removed"
            );
        }
        $now = gmdate("Y-m-d\TH:i:s\Z", $nowTs);
        $pdo->prepare(
            "UPDATE provider_saml_certs SET is_active = 0, state = 'retired', retired_at = :now " .
                "WHERE provider_id = :pid AND is_active = 1 AND id <> :id"
        )->execute([":now" => $now, ":pid" => $providerId, ":id" => $certId]);
        $pdo->prepare(
            "UPDATE provider_saml_certs SET is_active = 1, state = 'active', retired_at = NULL " .
                "WHERE id = :id AND provider_id = :pid"
        )->execute([":id" => $certId, ":pid" => $providerId]);
        provider_saml_cert_purge_unusable_keys($pdo, $providerId, $nowTs);
        $r["is_active"] = 1;
        $r["state"] = "active";
        return provider_saml_cert_row($r);
    });
}

/**
 * Deletes a certificate that is not active (a staged one, or a retired one, for example
 * after a key compromise so that it leaves the metadata at once). Returns false when
 * the provider has no such certificate; throws InvalidArgumentException for the active
 * certificate.
 */
function delete_provider_saml_cert(
    string $storePath,
    array $provider,
    string $certId
): bool {
    $pdo = provider_saml_cert_db($storePath);
    $providerId = (string) $provider["id"];
    return provider_saml_cert_tx($pdo, function (PDO $pdo) use ($providerId, $certId): bool {
        $stmt = $pdo->prepare(
            "SELECT is_active FROM provider_saml_certs WHERE id = :id AND provider_id = :pid LIMIT 1"
        );
        $stmt->execute([":id" => $certId, ":pid" => $providerId]);
        $isActive = $stmt->fetchColumn();
        if ($isActive === false) {
            return false;
        }
        if ((int) $isActive === 1) {
            throw new InvalidArgumentException(
                "The active SAML certificate cannot be deleted; activate or rotate to another certificate first"
            );
        }
        $del = $pdo->prepare(
            "DELETE FROM provider_saml_certs WHERE id = :id AND provider_id = :pid AND is_active = 0"
        );
        $del->execute([":id" => $certId, ":pid" => $providerId]);
        $deleted = $del->rowCount() === 1;
        provider_saml_cert_purge_unusable_keys($pdo, $providerId);
        return $deleted;
    });
}

/**
 * Every certificate of a provider (without private keys), active first, then newest
 * first, with its state, retired_at and expiry status (expired, expires_in_days,
 * expires_soon; see provider_saml_cert_row()).
 */
function list_provider_saml_certs(string $storePath, string $providerId): array
{
    $pdo = provider_saml_cert_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM provider_saml_certs WHERE provider_id = :pid ORDER BY is_active DESC, created_at DESC"
    );
    $stmt->execute([":pid" => $providerId]);
    return array_map(
        fn(array $r): array => provider_saml_cert_row($r),
        $stmt->fetchAll(PDO::FETCH_ASSOC)
    );
}

/**
 * The certificates to publish as signing keys in the provider's metadata: the active
 * certificate first, then the staged 'next' certificate, then certificates retired
 * within the grace period (most recently retired first). Expired certificates other
 * than the active one are left out. Rows have the ensure_provider_saml_cert() fields
 * except private_key_pem, which publishing never needs. Read-only: call
 * ensure_provider_saml_cert() first so that an active certificate exists.
 */
function list_published_provider_saml_certs(string $storePath, string $providerId): array
{
    $pdo = provider_saml_cert_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM provider_saml_certs WHERE provider_id = :pid ORDER BY created_at DESC, rowid DESC"
    );
    $stmt->execute([":pid" => $providerId]);
    $now = time();
    $active = [];
    $next = [];
    $retired = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $r) {
        $row = provider_saml_cert_row($r);
        if ($row["state"] === "active") {
            $active[] = $row;
        } elseif (provider_saml_cert_is_expired($row, $now)) {
            continue;
        } elseif ($row["state"] === "next") {
            $next[] = $row;
        } elseif (provider_saml_cert_in_grace($row, $now)) {
            $retired[] = $row;
        }
    }
    usort(
        $retired,
        fn(array $a, array $b): int => strcmp((string) $b["retired_at"], (string) $a["retired_at"])
    );
    return array_merge($active, $next, $retired);
}

// ---------- TLS Host Certificate Chain Export Helpers ----------

// The TLS chain of this IdP's own endpoint is read by api_fetch_public_tls_chain() (routes_api.php),
// over a connection pinned to checked addresses (S10-10). The helpers below find the trust anchor.

function find_trust_anchor_for($upperCert)
{
    $trusted = load_trust_store_certs();
    if (!$trusted) {
        return null;
    }
    if (is_self_signed($upperCert)) {
        $fp = @openssl_x509_fingerprint($upperCert, "sha256");
        if ($fp) {
            foreach ($trusted as $cand) {
                if ($fp === @openssl_x509_fingerprint($cand, "sha256")) {
                    return $cand;
                }
            }
        }
    }
    $upperInfo = @openssl_x509_parse($upperCert, false);
    $upperIssuer = $upperInfo["issuer"] ?? [];

    foreach ($trusted as $cand) {
        $candInfo = @openssl_x509_parse($cand, false);
        if (!$candInfo || !is_self_signed($cand)) {
            continue;
        }
        if (!dn_loose_match($candInfo["subject"] ?? [], $upperIssuer)) {
            continue;
        }
        $pub = @openssl_pkey_get_public($cand);
        if ($pub && openssl_x509_verify($upperCert, $pub) === 1) {
            return $cand;
        }
    }
    foreach ($trusted as $cand) {
        if (!is_self_signed($cand)) {
            continue;
        }
        $pub = @openssl_pkey_get_public($cand);
        if ($pub && openssl_x509_verify($upperCert, $pub) === 1) {
            return $cand;
        }
    }
    return null;
}

function load_trust_store_certs(): array
{
    $out = [];
    $loc = openssl_get_cert_locations();
    $bundle = $loc["default_cert_file"] ?? null;
    $cadir = $loc["default_cert_dir"] ?? null;

    if ($bundle && is_readable($bundle)) {
        $pem = @file_get_contents($bundle);
        if ($pem !== false) {
            foreach (split_pem_bundle($pem) as $one) {
                $x = @openssl_x509_read($one);
                if ($x) {
                    $out[] = $x;
                }
            }
        }
    }
    if ($cadir && is_dir($cadir) && is_readable($cadir)) {
        $dh = @opendir($cadir);
        if ($dh) {
            while (($f = readdir($dh)) !== false) {
                if ($f === "." || $f === "..") {
                    continue;
                }
                $p = $cadir . DIRECTORY_SEPARATOR . $f;
                if (!is_file($p) || !is_readable($p)) {
                    continue;
                }
                $pem = @file_get_contents($p);
                if ($pem === false) {
                    continue;
                }
                foreach (split_pem_bundle($pem) as $one) {
                    $x = @openssl_x509_read($one);
                    if ($x) {
                        $out[] = $x;
                    }
                }
            }
            closedir($dh);
        }
    }
    return $out;
}

function is_self_signed($cert): bool
{
    $info = @openssl_x509_parse($cert, false);
    if (!$info) {
        return false;
    }
    if (!dn_loose_match($info["subject"] ?? [], $info["issuer"] ?? [])) {
        return false;
    }
    $pub = @openssl_pkey_get_public($cert);
    return $pub && openssl_x509_verify($cert, $pub) === 1;
}

function certs_equal($a, $b): bool
{
    $fa = @openssl_x509_fingerprint($a, "sha256");
    $fb = @openssl_x509_fingerprint($b, "sha256");
    return $fa && $fb && hash_equals($fa, $fb);
}

function split_pem_bundle(string $pem): array
{
    if ($pem === "") {
        return [];
    }
    $out = [];
    if (
        preg_match_all(
            "/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/si",
            $pem,
            $m
        )
    ) {
        foreach ($m[0] as $block) {
            $out[] = $block;
        }
    }
    return $out;
}

function dn_loose_match(array $a, array $b): bool
{
    $keys = ["CN", "O", "OU", "C", "L", "ST", "emailAddress"];
    $na = [];
    $nb = [];
    foreach ($keys as $k) {
        if (isset($a[$k])) {
            $na[$k] = preg_replace("/\s+/", " ", strtoupper((string) $a[$k]));
        }
        if (isset($b[$k])) {
            $nb[$k] = preg_replace("/\s+/", " ", strtoupper((string) $b[$k]));
        }
    }
    foreach ($nb as $k => $v) {
        if (!isset($na[$k]) || $na[$k] !== $v) {
            return false;
        }
    }
    return true;
}

function x509_resource_to_pem($x509): string
{
    if (!$x509) {
        return "";
    }
    $pem = "";
    openssl_x509_export($x509, $pem);
    return $pem;
}

function is_self_signed_cert($x509): bool
{
    $parsed = openssl_x509_parse($x509);
    if (!$parsed) {
        return false;
    }
    return ($parsed["issuer"] ?? []) == ($parsed["subject"] ?? []);
}

// ---------- Symmetric Secret Vault (AES-256-GCM for Outbound SCIM Tokens & Optional Password Sync) ----------
//
// Key: sha256(OIDC_SCIM_ENCRYPTION_KEY) when that variable is set, otherwise 32 random
// bytes kept base64-encoded in scim_master.key next to the database. The key file is
// created once, atomically, and is never overwritten or regenerated: a file that exists
// but cannot be read or parsed fails closed. Back it up together with the database.
// Envelopes: "v2:<kid>:" . base64(iv . tag . ciphertext), where <kid> = vault_key_id()
// and "v2:<kid>" is the AES-GCM associated data. Older "v1:" envelopes (no key id) are
// still decrypted, with each known key in turn.
// The key file protects nothing against a copy of the data directory, so recoverable user
// password copies for password push need the environment key (see the password copy
// helpers at the end of this section, S04-08).

function vault_key_file(string $storePath): string
{
    return dirname($storePath) . DIRECTORY_SEPARATOR . "scim_master.key";
}

/**
 * The vault key taken from OIDC_SCIM_ENCRYPTION_KEY (SHA-256 of the trimmed value), or null
 * when the variable is unset or blank.
 */
function vault_env_key(): ?string
{
    $envKey = getenv("OIDC_SCIM_ENCRYPTION_KEY");
    return is_string($envKey) && trim($envKey) !== "" ? hash("sha256", trim($envKey), true) : null;
}

/**
 * Non-secret identifier of a vault key (16 hex characters).
 */
function vault_key_id(string $key): string
{
    return substr(hash_hmac("sha256", "simple-idp vault key id", $key), 0, 16);
}

/**
 * Reads the vault key file. Returns null when it does not exist. Throws RuntimeException,
 * after logging, when it exists but is unreadable or does not hold a base64-encoded
 * 32-byte key. Never writes.
 */
function vault_read_key_file(string $keyFile): ?string
{
    static $loaded = [];
    static $broken = [];
    if (isset($loaded[$keyFile])) {
        return $loaded[$keyFile];
    }
    if (isset($broken[$keyFile])) {
        throw new RuntimeException("Vault master key file is unreadable or malformed");
    }
    clearstatcache(true, $keyFile);
    if (!file_exists($keyFile)) {
        return null;
    }
    $problem = "is not readable";
    // A file created through the exclusive-create fallback is empty until its creator
    // has written the key (44 base64 characters), so wait briefly for a short read.
    for ($attempt = 0; $attempt < 10; $attempt++) {
        $fh = @fopen($keyFile, "rb");
        if ($fh === false) {
            break;
        }
        @flock($fh, LOCK_SH);
        $raw = stream_get_contents($fh, 4096);
        @flock($fh, LOCK_UN);
        fclose($fh);
        $raw = is_string($raw) ? trim($raw) : "";
        $decoded = base64_decode($raw, true);
        if (is_string($decoded) && strlen($decoded) === 32) {
            $loaded[$keyFile] = $decoded;
            return $decoded;
        }
        $problem = "does not hold a base64-encoded 32-byte key";
        if (strlen($raw) >= 44) {
            break;
        }
        usleep(20000);
    }
    $broken[$keyFile] = true;
    error_log(
        "Vault master key file $keyFile $problem. It is never replaced automatically: " .
            "restore it from backup, or remove it only if no stored secret depends on it."
    );
    throw new RuntimeException("Vault master key file is unreadable or malformed");
}

/**
 * Creates the vault key file with a fresh random key unless it exists, never replacing
 * an existing file, and returns the key the file holds afterwards: ours, or the one a
 * concurrent request wrote first.
 */
function vault_create_key_file(string $keyFile): string
{
    $dir = dirname($keyFile);
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    $fresh = random_bytes(32);
    $encoded = base64_encode($fresh);

    // Write a private temporary file (tempnam() creates it with mode 0600), then
    // hard-link it into place: link() fails when the target exists, so an existing key
    // is never replaced and readers never see a partly written file.
    if (function_exists("link")) {
        $tmp = @tempnam($dir, "vaultkey");
        if (is_string($tmp) && $tmp !== "") {
            try {
                if (@file_put_contents($tmp, $encoded) === strlen($encoded)) {
                    @chmod($tmp, 0600);
                    if (@link($tmp, $keyFile)) {
                        return $fresh;
                    }
                }
            } finally {
                @unlink($tmp);
            }
        }
    }
    $existing = vault_read_key_file($keyFile);
    if ($existing !== null) {
        return $existing;
    }

    // No hard links here: create the file exclusively (O_EXCL) and write it under an
    // exclusive lock; readers take a shared lock and wait for the content.
    $fh = @fopen($keyFile, "xb");
    if ($fh === false) {
        $existing = vault_read_key_file($keyFile);
        if ($existing !== null) {
            return $existing;
        }
        error_log("Cannot create vault master key file $keyFile");
        throw new RuntimeException("Cannot create the vault master key file");
    }
    @flock($fh, LOCK_EX);
    @chmod($keyFile, 0600);
    $ok = fwrite($fh, $encoded) === strlen($encoded) && fflush($fh);
    @flock($fh, LOCK_UN);
    fclose($fh);
    if (!$ok) {
        // Created by us a moment ago and never valid, so no secret depends on it.
        @unlink($keyFile);
        error_log("Cannot write vault master key file $keyFile");
        throw new RuntimeException("Cannot write the vault master key file");
    }
    return $fresh;
}

/**
 * The key used to encrypt new secrets. Creates the key file on first use unless
 * $createIfMissing is false. Throws RuntimeException when the key file exists but is
 * unreadable or malformed (fail closed), or is missing and may not be created.
 */
function vault_master_key(string $storePath, bool $createIfMissing = true): string
{
    static $cached = [];
    if (isset($cached[$storePath])) {
        return $cached[$storePath];
    }
    $envKey = vault_env_key();
    if ($envKey !== null) {
        return $cached[$storePath] = $envKey;
    }
    $keyFile = vault_key_file($storePath);
    $key = vault_read_key_file($keyFile);
    if ($key === null) {
        if (!$createIfMissing) {
            throw new RuntimeException("Vault master key file is missing");
        }
        $key = vault_create_key_file($keyFile);
    }
    return $cached[$storePath] = $key;
}

/**
 * Every key that may have encrypted a stored secret, keyed by vault_key_id(), current
 * key first: OIDC_SCIM_ENCRYPTION_KEY when set, then the key file when it exists (so
 * secrets stored before the variable was introduced stay readable). Never creates keys.
 */
function vault_decryption_keys(string $storePath): array
{
    $keys = [];
    $envKey = vault_env_key();
    if ($envKey !== null) {
        $keys[vault_key_id($envKey)] = $envKey;
    }
    try {
        $fileKey = vault_read_key_file(vault_key_file($storePath));
        if ($fileKey !== null) {
            $keys[vault_key_id($fileKey)] ??= $fileKey;
        }
    } catch (RuntimeException $e) {
        // Already logged; secrets under the environment key can still be decrypted.
    }
    return $keys;
}

function vault_encrypt_secret(string $storePath, string $plaintext): string
{
    if ($plaintext === "") {
        return "";
    }
    return vault_encrypt_with_key(vault_master_key($storePath), $plaintext);
}

/**
 * Encrypts $plaintext under the 32-byte vault key $key into a "v2:<kid>:" envelope.
 */
function vault_encrypt_with_key(string $key, string $plaintext): string
{
    $header = "v2:" . vault_key_id($key);
    $iv = random_bytes(12);
    $tag = "";
    $ct = openssl_encrypt(
        $plaintext,
        "aes-256-gcm",
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        $header,
        16
    );
    if ($ct === false || strlen($tag) !== 16) {
        throw new RuntimeException("AES-256-GCM secret encryption failed");
    }
    return $header . ":" . base64_encode($iv . $tag . $ct);
}

/**
 * Decrypts a vault envelope. Returns null (and logs why) when the envelope is malformed
 * or no known key opens it. Never creates a key.
 */
function vault_decrypt_secret(string $storePath, ?string $envelope): ?string
{
    if ($envelope === null || $envelope === "") {
        return null;
    }
    return vault_decrypt_with_keys($envelope, vault_decryption_keys($storePath));
}

/**
 * Decrypts a vault envelope with $keys only (vault_key_id() => key): a "v2:<kid>:" envelope
 * with the key of that id, a "v1:" envelope with each key in turn. Returns null when the
 * envelope is malformed or none of $keys opens it, and logs why unless $logFailure is false.
 */
function vault_decrypt_with_keys(string $envelope, array $keys, bool $logFailure = true): ?string
{
    if (preg_match('/^(v2:([0-9a-f]{16})):([A-Za-z0-9+\/]+={0,2})$/D', $envelope, $m) === 1) {
        $aad = $m[1];
        $kid = $m[2];
        $payload = $m[3];
    } elseif (str_starts_with($envelope, "v1:")) {
        $aad = "";
        $kid = null;
        $payload = substr($envelope, 3);
    } else {
        if ($logFailure) {
            error_log("Vault: stored secret has an unknown envelope format");
        }
        return null;
    }
    $raw = base64_decode($payload, true);
    if ($raw === false || strlen($raw) < 28) {
        if ($logFailure) {
            error_log("Vault: stored secret envelope is malformed");
        }
        return null;
    }
    $iv = substr($raw, 0, 12);
    $tag = substr($raw, 12, 16);
    $ct = substr($raw, 28);
    if ($kid !== null) {
        $keys = isset($keys[$kid]) ? [$kid => $keys[$kid]] : [];
    }
    foreach ($keys as $key) {
        $pt = openssl_decrypt($ct, "aes-256-gcm", $key, OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if ($pt !== false) {
            return $pt;
        }
    }
    if ($logFailure) {
        error_log(
            $keys === []
                ? "Vault: cannot decrypt a stored secret: " .
                    ($kid !== null ? "vault key $kid is not available" : "no vault key is available")
                : "Vault: cannot decrypt a stored secret with the available vault key(s)"
        );
    }
    return null;
}

// ---------- Password copies for outbound SCIM password push (S04-08) ----------
//
// idp_users.password_enc holds a vault-encrypted copy of a directory user's password next to
// its hash, only so that an outbound SCIM connector with push_passwords can send it to its
// target. Which copies may exist depends on the policy (vault_password_copy_policy()):
//   none  OIDC_SCIM_ENCRYPTION_KEY is unset and allow_password_push_with_key_file is off.
//         The only key is scim_master.key next to providers.sqlite, so a copy of the data
//         directory would decrypt every copy: password push is off, and no copy is stored,
//         pushed or kept, whatever connectors exist.
//   env   OIDC_SCIM_ENCRYPTION_KEY is set and the flag is off: only copies encrypted under
//         that key are stored, pushed and kept. A copy under any other key is never pushed.
//         When this policy takes effect, copies that the key file opens (written before the
//         variable was set, or under "any") are re-encrypted under the variable's key;
//         copies under an earlier OIDC_SCIM_ENCRYPTION_KEY cannot be opened and are cleared.
//   any   allow_password_push_with_key_file is set: the operator accepts the key-file risk,
//         and copies under any known vault key are stored, pushed and kept.
// In every policy a copy is kept only while its owner has a push_passwords connector.
// vault_purge_unused_password_copies() clears the copies the policy does not allow, and
// vault_password_copies_migrate() does so for every owner whenever the policy in force
// differs from the one last applied, which the table vault_password_copy_state records by
// label: after the upgrade (older releases kept a copy of every password) and after every
// change of policy or of OIDC_SCIM_ENCRYPTION_KEY, including a change back to a policy that
// was in force before. Operators who push passwords with the key file must set
// allow_password_push_with_key_file or OIDC_SCIM_ENCRYPTION_KEY before upgrading; otherwise
// the copies are cleared, and a password is pushed again only once its user sets a new one.
// The command line (cron) never applies a policy: its environment may lack the web server's
// settings, so it needs the same ones to push passwords (see vault_password_copies_migrate()).

/**
 * The password copy policy in force (see the section comment), as
 * ["mode" => "none"|"env"|"any", "key" => the OIDC_SCIM_ENCRYPTION_KEY vault key in "env"
 * mode, else null, "label" => "none", "any" or "env-" . vault_key_id(key)]. The label names
 * the policy without revealing the key.
 */
function vault_password_copy_policy(): array
{
    if (config_flag("allow_password_push_with_key_file", "OIDC_ALLOW_PASSWORD_PUSH_WITH_KEY_FILE")) {
        return ["mode" => "any", "key" => null, "label" => "any"];
    }
    $envKey = vault_env_key();
    if ($envKey !== null) {
        return ["mode" => "env", "key" => $envKey, "label" => "env-" . vault_key_id($envKey)];
    }
    return ["mode" => "none", "key" => null, "label" => "none"];
}

/**
 * True when the vault key comes from OIDC_SCIM_ENCRYPTION_KEY, so it is kept outside the
 * data directory, rather than from scim_master.key next to the database.
 */
function vault_key_is_external(): bool
{
    return vault_env_key() !== null;
}

/**
 * Whether outbound SCIM password push may run and password copies may be stored for it:
 * with an external vault key (vault_key_is_external()), or with the key file when the
 * operator set allow_password_push_with_key_file (env OIDC_ALLOW_PASSWORD_PUSH_WITH_KEY_FILE).
 */
function vault_password_push_allowed(): bool
{
    return vault_password_copy_policy()["mode"] !== "none";
}

/**
 * Why push_passwords cannot be enabled while vault_password_push_allowed() is false. Safe to
 * show to admin clients (it names settings, never values).
 */
function vault_password_push_blocked_reason(): string
{
    return "Password push needs the vault key in OIDC_SCIM_ENCRYPTION_KEY: with only the key file next to " .
        "the database, a copy of the data directory reveals every pushed password. Set " .
        "OIDC_SCIM_ENCRYPTION_KEY, or allow_password_push_with_key_file to accept that risk.";
}

/**
 * True when $owner has an outbound SCIM connector with push_passwords (active or paused).
 */
function vault_owner_has_password_push(PDO $pdo, string $owner): bool
{
    $stmt = $pdo->prepare(
        "SELECT 1 FROM scim_connectors c JOIN providers p ON p.id = c.provider_id " .
            "WHERE p.owner = :o AND c.push_passwords = 1 LIMIT 1"
    );
    $stmt->execute([":o" => $owner]);
    $found = $stmt->fetchColumn() !== false;
    $stmt->closeCursor();
    return $found;
}

/**
 * The value to store as idp_users.password_enc when a user of $owner gets the password
 * $plaintext: its vault envelope while $owner has a push_passwords connector and
 * vault_password_push_allowed(), else null, so no recoverable copy exists that nothing
 * pushes. Storing null also drops the copy of the previous password. In "env" mode the
 * envelope is encrypted under OIDC_SCIM_ENCRYPTION_KEY, otherwise with vault_encrypt_secret().
 * Call it inside the storage_write_transaction() that writes the idp_users row (encryption is
 * cheap; only password_hash() belongs before the lock): the connector check then runs under
 * the write lock, so a push connector removed concurrently, together with its purge
 * (vault_purge_unused_password_copies()), cannot leave a copy behind. A caller that calls it
 * earlier must re-check vault_owner_has_password_push() inside that transaction and store
 * null when it is false.
 */
function vault_user_password_copy(string $storePath, string $owner, string $plaintext): ?string
{
    $policy = vault_password_copy_policy();
    if ($plaintext === "" || $owner === "" || $policy["mode"] === "none") {
        return null;
    }
    if (!vault_owner_has_password_push(storage_db($storePath), $owner)) {
        return null;
    }
    return $policy["mode"] === "env"
        ? vault_encrypt_with_key($policy["key"], $plaintext)
        : vault_encrypt_secret($storePath, $plaintext);
}

/**
 * Decrypts a password copy for outbound SCIM password push under the policy in force: null in
 * "none" mode; in "env" mode only a copy encrypted under OIDC_SCIM_ENCRYPTION_KEY is opened,
 * so a copy under the key file is not pushed (logged once per request); in "any" mode
 * vault_decrypt_secret(). The policy is that of the running process, so "php index.php
 * scim-sync" from cron pushes passwords only with the web server's OIDC_SCIM_ENCRYPTION_KEY
 * and allow_password_push_with_key_file (vault_password_copies_warn_cli_policy() warns).
 */
function vault_user_password_for_push(string $storePath, ?string $envelope): ?string
{
    static $refusalLogged = false;
    $policy = vault_password_copy_policy();
    if ($policy["mode"] === "none" || $envelope === null || $envelope === "") {
        return null;
    }
    if ($policy["mode"] === "any") {
        return vault_decrypt_secret($storePath, $envelope);
    }
    $plain = vault_decrypt_with_keys($envelope, [vault_key_id($policy["key"]) => $policy["key"]], false);
    if ($plain === null && !$refusalLogged) {
        $refusalLogged = true;
        error_log(
            "Vault: a stored password copy that OIDC_SCIM_ENCRYPTION_KEY does not open is not pushed " .
                "(copies under the key file are pushed only with allow_password_push_with_key_file)"
        );
    }
    return $plain;
}

/**
 * Clears the password copies (idp_users.password_enc) of the users of $owner, of every owner
 * when null, that the policy in force does not allow: in "none" mode every copy, whatever
 * connectors exist; otherwise the copies of owners without a push_passwords connector and, in
 * "env" mode, every copy not encrypted under OIDC_SCIM_ENCRYPTION_KEY (a "v1:" copy names no
 * key and is kept only if that key opens it). Call it after a connector is saved with
 * push_passwords off or deleted, and after a provider is deleted. Runs in one write
 * transaction (storage_write_transaction()), joining the caller's when one is open. Returns
 * the number of copies cleared.
 */
function vault_purge_unused_password_copies(PDO $pdo, ?string $owner = null): int
{
    return vault_purge_password_copies_for_policy($pdo, vault_password_copy_policy(), $owner);
}

/**
 * vault_purge_unused_password_copies() under $policy, a vault_password_copy_policy() value.
 */
function vault_purge_password_copies_for_policy(PDO $pdo, array $policy, ?string $owner = null): int
{
    return storage_write_transaction($pdo, static function (PDO $db) use ($policy, $owner): int {
        $scope = $owner !== null ? " AND owner = :o" : "";
        $ownerParams = $owner !== null ? [":o" => $owner] : [];
        $params = $ownerParams;
        $sql = "UPDATE idp_users SET password_enc = NULL WHERE password_enc IS NOT NULL" . $scope;
        if ($policy["mode"] !== "none") {
            $sql .= " AND (NOT EXISTS (SELECT 1 FROM scim_connectors c JOIN providers p ON p.id = c.provider_id" .
                " WHERE p.owner = idp_users.owner AND c.push_passwords = 1)";
            if ($policy["mode"] === "env") {
                // Envelopes that name another key, or have no known format. "v1:" envelopes
                // name no key and are tried below.
                $prefix = "v2:" . vault_key_id($policy["key"]) . ":";
                $sql .= " OR (substr(password_enc, 1, 3) <> 'v1:' AND substr(password_enc, 1, " .
                    strlen($prefix) . ") <> :prefix)";
                $params[":prefix"] = $prefix;
            }
            $sql .= ")";
        }
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        $cleared = $stmt->rowCount();
        if ($policy["mode"] !== "env") {
            return $cleared;
        }
        $keys = [vault_key_id($policy["key"]) => $policy["key"]];
        $sel = $db->prepare(
            "SELECT id, password_enc FROM idp_users WHERE substr(password_enc, 1, 3) = 'v1:'" . $scope
        );
        $sel->execute($ownerParams);
        $stale = [];
        while (($r = $sel->fetch(PDO::FETCH_ASSOC)) !== false) {
            if (vault_decrypt_with_keys((string) $r["password_enc"], $keys, false) === null) {
                $stale[] = (string) $r["id"];
            }
        }
        $sel->closeCursor();
        $upd = $db->prepare(
            "UPDATE idp_users SET password_enc = NULL WHERE id = :id AND substr(password_enc, 1, 3) = 'v1:'"
        );
        foreach ($stale as $id) {
            $upd->execute([":id" => $id]);
            $cleared += $upd->rowCount();
        }
        return $cleared;
    });
}

/**
 * When $policy is "env", re-encrypts under OIDC_SCIM_ENCRYPTION_KEY the password copies of
 * owners with a push_passwords connector that the key file next to $storePath opens (copies
 * stored before the variable was set, or under "any"), so that moving from the key file to
 * the environment key keeps them; vault_purge_password_copies_for_policy() then clears every
 * copy still not under that key. Does nothing for another mode, for an empty $storePath, or
 * when the key file is missing or unreadable. Never creates a key. Joins the caller's write
 * transaction. Returns the number of copies re-encrypted.
 */
function vault_reencrypt_password_copies_for_env(PDO $db, array $policy, string $storePath): int
{
    if ($policy["mode"] !== "env" || $storePath === "") {
        return 0;
    }
    $envKid = vault_key_id($policy["key"]);
    $fileKeys = vault_decryption_keys($storePath);
    unset($fileKeys[$envKid]);
    if ($fileKeys === []) {
        return 0;
    }
    $prefix = "v2:" . $envKid . ":";
    $sel = $db->prepare(
        "SELECT id, password_enc FROM idp_users WHERE password_enc IS NOT NULL AND password_enc <> '' " .
            "AND substr(password_enc, 1, " . strlen($prefix) . ") <> :prefix AND EXISTS (SELECT 1 FROM " .
            "scim_connectors c JOIN providers p ON p.id = c.provider_id WHERE p.owner = idp_users.owner " .
            "AND c.push_passwords = 1)"
    );
    $sel->execute([":prefix" => $prefix]);
    $rows = $sel->fetchAll(PDO::FETCH_ASSOC);
    $envKeys = [$envKid => $policy["key"]];
    $upd = $db->prepare("UPDATE idp_users SET password_enc = :new WHERE id = :id AND password_enc = :old");
    $count = 0;
    foreach ($rows as $r) {
        $old = (string) $r["password_enc"];
        // A "v1:" copy names no key and may already be under the environment key.
        if (str_starts_with($old, "v1:") && vault_decrypt_with_keys($old, $envKeys, false) !== null) {
            continue;
        }
        $plain = vault_decrypt_with_keys($old, $fileKeys, false);
        if ($plain === null || $plain === "") {
            continue;
        }
        $upd->execute([
            ":new" => vault_encrypt_with_key($policy["key"], $plain),
            ":id" => (string) $r["id"],
            ":old" => $old,
        ]);
        $count += $upd->rowCount();
    }
    return $count;
}

/**
 * The label (see vault_password_copy_policy()) of the password copy policy that
 * vault_password_copies_migrate() applied last, or null when none is recorded. Throws
 * PDOException ("no such table") until the table vault_password_copy_state exists.
 */
function vault_password_copy_applied_label(PDO $pdo): ?string
{
    $stmt = $pdo->prepare("SELECT label FROM vault_password_copy_state WHERE id = 1");
    $stmt->execute();
    $label = $stmt->fetchColumn();
    $stmt->closeCursor();
    return is_string($label) && $label !== "" ? $label : null;
}

/**
 * Applies the password copy policy in force (vault_password_copy_policy()) to the stored
 * copies of every owner whenever it differs from the policy applied last, whose label the
 * one-row table vault_password_copy_state records: after the upgrade (older releases kept a
 * copy of every password) and after every change of policy or of OIDC_SCIM_ENCRYPTION_KEY,
 * including a change back to a policy that was in force before. One write transaction
 * re-reads the label and, when it still differs, re-encrypts the copies the key file opens
 * if the policy is "env" (vault_reencrypt_password_copies_for_env(); only when $storePath,
 * the database file of $pdo, is given), clears the copies the policy does not allow
 * (vault_purge_password_copies_for_policy()) and records the label. The change is logged
 * after the commit.
 * On the command line ("php index.php scim-sync" from cron), whose environment may lack
 * OIDC_SCIM_ENCRYPTION_KEY or allow_password_push_with_key_file, nothing is changed: the web
 * server's configuration decides (see vault_password_copies_warn_cli_policy()).
 * Call it outside a transaction, once per request (for example at the end of
 * storage_initialize()); with the policy unchanged it costs one SELECT per connection and
 * request. Failures are logged and retried on the next call.
 */
function vault_password_copies_migrate(PDO $pdo, string $storePath = ""): void
{
    static $checked = null;
    if ($checked === null) {
        // Keyed by the PDO object itself, so a later connection is checked again.
        $checked = new WeakMap();
    }
    $policy = vault_password_copy_policy();
    if (isset($checked[$pdo]) && $checked[$pdo] === $policy["label"]) {
        return;
    }
    if (PHP_SAPI === "cli") {
        $checked[$pdo] = $policy["label"];
        vault_password_copies_warn_cli_policy($pdo, $policy);
        return;
    }
    try {
        try {
            $applied = vault_password_copy_applied_label($pdo);
        } catch (PDOException $e) {
            if (!str_contains(strtolower($e->getMessage()), "no such table")) {
                throw $e;
            }
            schema_ensure($pdo, "crypto.password_copy_state_v1", [
                "CREATE TABLE IF NOT EXISTS vault_password_copy_state (" .
                    "id INTEGER PRIMARY KEY CHECK (id = 1), label TEXT NOT NULL, applied_at TEXT NOT NULL)",
            ]);
            $applied = vault_password_copy_applied_label($pdo);
        }
        if ($applied !== $policy["label"]) {
            $change = storage_write_transaction(
                $pdo,
                static function (PDO $db) use ($policy, $storePath): ?array {
                    $previous = vault_password_copy_applied_label($db);
                    if ($previous === $policy["label"]) {
                        return null;
                    }
                    $reencrypted = vault_reencrypt_password_copies_for_env($db, $policy, $storePath);
                    $cleared = vault_purge_password_copies_for_policy($db, $policy);
                    $count = $db->prepare("SELECT COUNT(*) FROM scim_connectors WHERE push_passwords = 1");
                    $count->execute();
                    $pushConnectors = (int) $count->fetchColumn();
                    $count->closeCursor();
                    $db->prepare(
                        "INSERT OR REPLACE INTO vault_password_copy_state (id, label, applied_at) " .
                            "VALUES (1, :label, :at)"
                    )->execute([":label" => $policy["label"], ":at" => gmdate("Y-m-d\TH:i:s\Z")]);
                    return [
                        "previous" => $previous,
                        "reencrypted" => $reencrypted,
                        "cleared" => $cleared,
                        "push_connectors" => $pushConnectors,
                    ];
                }
            );
            if (is_array($change)) {
                vault_password_copies_log_change($policy, $change);
            }
        }
        $checked[$pdo] = $policy["label"];
    } catch (Throwable $e) {
        error_log("Vault: password copy cleanup failed (will retry): " . $e->getMessage());
    }
}

/**
 * Logs what vault_password_copies_migrate() did when it applied $policy ($change: previous
 * label or null, reencrypted, cleared, push_connectors). Silent on the first run of a
 * database that holds no copy, unless password push is off while a connector has
 * push_passwords.
 */
function vault_password_copies_log_change(array $policy, array $change): void
{
    $previous = $change["previous"] ?? null;
    $reencrypted = (int) ($change["reencrypted"] ?? 0);
    $cleared = (int) ($change["cleared"] ?? 0);
    $pushConnectors = (int) ($change["push_connectors"] ?? 0);
    $none = $policy["mode"] === "none";
    if ($previous === null && $reencrypted === 0 && $cleared === 0 && (!$none || $pushConnectors === 0)) {
        return;
    }
    $message = "Vault: password copy policy " . ($previous === null
        ? "'" . $policy["label"] . "' applied"
        : "changed from '" . $previous . "' to '" . $policy["label"] . "'");
    if ($reencrypted > 0) {
        $message .= "; re-encrypted the stored password copies of " . $reencrypted . " directory user(s) " .
            "under OIDC_SCIM_ENCRYPTION_KEY";
    }
    if ($none) {
        $message .= "; password push is off: removed the stored password copies of " . $cleared .
            " directory user(s), and " . $pushConnectors . " SCIM connector(s) with push_passwords no " .
            "longer send passwords. " . vault_password_push_blocked_reason();
    } else {
        $message .= "; removed the stored password copies of " . $cleared . " directory user(s) whose " .
            "owner has no password-pushing SCIM connector" .
            ($policy["mode"] === "env" ? " or that OIDC_SCIM_ENCRYPTION_KEY does not open" : "") . ".";
    }
    error_log($message);
}

/**
 * On the command line, where vault_password_copies_migrate() changes nothing: logs a warning
 * when this process's password copy policy ($policy) differs from the one the web server
 * applied last while a connector has push_passwords, because scim-sync then may not be able
 * to push the copies the web server keeps (it needs the web server's OIDC_SCIM_ENCRYPTION_KEY
 * and allow_password_push_with_key_file, or that flag in config.php). Silent when no policy
 * is recorded yet or the database cannot be read.
 */
function vault_password_copies_warn_cli_policy(PDO $pdo, array $policy): void
{
    try {
        $applied = vault_password_copy_applied_label($pdo);
        if ($applied === null || $applied === $policy["label"]) {
            return;
        }
        $stmt = $pdo->prepare("SELECT 1 FROM scim_connectors WHERE push_passwords = 1 LIMIT 1");
        $stmt->execute();
        $pushing = $stmt->fetchColumn() !== false;
        $stmt->closeCursor();
    } catch (Throwable $e) {
        return;
    }
    if ($pushing) {
        error_log(
            "Vault: this command runs with the password copy policy '" . $policy["label"] . "', but the web " .
                "server applies '" . $applied . "', so it may not be able to push the stored password copies. " .
                "Give scheduled jobs the same OIDC_SCIM_ENCRYPTION_KEY and allow_password_push_with_key_file " .
                "settings as the web server (or set the flag in config.php)."
        );
    }
}
