<?php
declare(strict_types=1);

/**
 * Pure-PHP WebAuthn Level 2/3 Server tailored for macOS Touch ID (Platform Authenticators).
 */

// Passkeys one user may have, counted over all RP IDs (G1c-03). Every passkey is carried in
// the user's directory record and in WebAuthn options, so the number must stay small.
// max_passkeys_per_user (OIDC_MAX_PASSKEYS_PER_USER) changes it within
// 1..WEBAUTHN_OPTIONS_MAX_CREDENTIALS; see webauthn_max_credentials_per_user().
const WEBAUTHN_DEFAULT_MAX_CREDENTIALS_PER_USER = 20;
// Most credentials listed in excludeCredentials or allowCredentials (the newest ones).
const WEBAUTHN_OPTIONS_MAX_CREDENTIALS = 50;

function webauthn_cbor_read_uint(string $buf, int &$offset, int $ai): int
{
    $len = strlen($buf);
    if ($ai < 24) {
        return $ai;
    }
    if ($ai === 24) {
        if ($offset + 1 > $len) {
            throw new RuntimeException("CBOR truncated uint8");
        }
        return ord($buf[$offset++]);
    }
    if ($ai === 25) {
        if ($offset + 2 > $len) {
            throw new RuntimeException("CBOR truncated uint16");
        }
        $v = unpack("n", substr($buf, $offset, 2))[1];
        $offset += 2;
        return (int) $v;
    }
    if ($ai === 26) {
        if ($offset + 4 > $len) {
            throw new RuntimeException("CBOR truncated uint32");
        }
        $v = unpack("N", substr($buf, $offset, 4))[1];
        $offset += 4;
        return (int) $v;
    }
    if ($ai === 27) {
        if ($offset + 8 > $len) {
            throw new RuntimeException("CBOR truncated uint64");
        }
        $v = (int) unpack("J", substr($buf, $offset, 8))[1];
        $offset += 8;
        if ($v < 0) {
            throw new RuntimeException("CBOR uint64 overflow");
        }
        return $v;
    }
    throw new RuntimeException("Unsupported CBOR additional info: $ai");
}

function webauthn_cbor_decode(string $buf, int &$offset = 0, int $depth = 0)
{
    if ($depth > 8) {
        throw new RuntimeException("CBOR nesting depth exceeded");
    }
    $len = strlen($buf);
    if ($offset >= $len) {
        throw new RuntimeException("CBOR unexpected EOF");
    }
    $ib = ord($buf[$offset++]);
    $major = $ib >> 5;
    $ai = $ib & 0x1f;

    switch ($major) {
        case 0: // Unsigned integer
            return webauthn_cbor_read_uint($buf, $offset, $ai);

        case 1: // Negative integer
            return -1 - webauthn_cbor_read_uint($buf, $offset, $ai);

        case 2: // Byte string
            if ($ai === 31) {
                $out = "";
                $chunks = 0;
                while ($offset < $len && ord($buf[$offset]) !== 0xff) {
                    if (++$chunks > 256) {
                        throw new RuntimeException("CBOR too many bstr chunks");
                    }
                    $chunk = webauthn_cbor_decode($buf, $offset, $depth + 1);
                    if (!is_string($chunk)) {
                        throw new RuntimeException("Invalid CBOR indefinite bstr chunk");
                    }
                    $out .= $chunk;
                    if (strlen($out) > 65536) {
                        throw new RuntimeException("CBOR bstr exceeds maximum size");
                    }
                }
                if ($offset >= $len || ord($buf[$offset]) !== 0xff) {
                    throw new RuntimeException("Missing CBOR indefinite break byte");
                }
                $offset++;
                return $out;
            }
            $slen = webauthn_cbor_read_uint($buf, $offset, $ai);
            if ($slen > 65536 || $offset + $slen > $len) {
                throw new RuntimeException("CBOR bstr overrun");
            }
            $s = substr($buf, $offset, $slen);
            $offset += $slen;
            return $s;

        case 3: // Text string
            if ($ai === 31) {
                $out = "";
                $chunks = 0;
                while ($offset < $len && ord($buf[$offset]) !== 0xff) {
                    if (++$chunks > 256) {
                        throw new RuntimeException("CBOR too many tstr chunks");
                    }
                    $chunk = webauthn_cbor_decode($buf, $offset, $depth + 1);
                    if (!is_string($chunk)) {
                        throw new RuntimeException("Invalid CBOR indefinite tstr chunk");
                    }
                    $out .= $chunk;
                    if (strlen($out) > 65536) {
                        throw new RuntimeException("CBOR tstr exceeds maximum size");
                    }
                }
                if ($offset >= $len || ord($buf[$offset]) !== 0xff) {
                    throw new RuntimeException("Missing CBOR indefinite break byte");
                }
                $offset++;
                return $out;
            }
            $slen = webauthn_cbor_read_uint($buf, $offset, $ai);
            if ($slen > 65536 || $offset + $slen > $len) {
                throw new RuntimeException("CBOR tstr overrun");
            }
            $s = substr($buf, $offset, $slen);
            $offset += $slen;
            return $s;

        case 4: // Array
            $arr = [];
            if ($ai === 31) {
                while ($offset < $len && ord($buf[$offset]) !== 0xff) {
                    if (count($arr) >= 512) {
                        throw new RuntimeException("CBOR array too large");
                    }
                    $arr[] = webauthn_cbor_decode($buf, $offset, $depth + 1);
                }
                if ($offset >= $len || ord($buf[$offset]) !== 0xff) {
                    throw new RuntimeException("Missing CBOR indefinite break byte");
                }
                $offset++;
                return $arr;
            }
            $count = webauthn_cbor_read_uint($buf, $offset, $ai);
            if ($count > 512) {
                throw new RuntimeException("CBOR array count exceeds limit");
            }
            for ($i = 0; $i < $count; $i++) {
                $arr[] = webauthn_cbor_decode($buf, $offset, $depth + 1);
            }
            return $arr;

        case 5: // Map
            $map = [];
            if ($ai === 31) {
                $entries = 0;
                while ($offset < $len && ord($buf[$offset]) !== 0xff) {
                    if (++$entries > 512) {
                        throw new RuntimeException("CBOR map too large");
                    }
                    $k = webauthn_cbor_decode($buf, $offset, $depth + 1);
                    if (!is_int($k) && !is_string($k)) {
                        throw new RuntimeException("Invalid CBOR map key type");
                    }
                    $v = webauthn_cbor_decode($buf, $offset, $depth + 1);
                    $map[$k] = $v;
                }
                if ($offset >= $len || ord($buf[$offset]) !== 0xff) {
                    throw new RuntimeException("Missing CBOR indefinite break byte");
                }
                $offset++;
                return $map;
            }
            $count = webauthn_cbor_read_uint($buf, $offset, $ai);
            if ($count > 512) {
                throw new RuntimeException("CBOR map count exceeds limit");
            }
            for ($i = 0; $i < $count; $i++) {
                $k = webauthn_cbor_decode($buf, $offset, $depth + 1);
                if (!is_int($k) && !is_string($k)) {
                    throw new RuntimeException("Invalid CBOR map key type");
                }
                $v = webauthn_cbor_decode($buf, $offset, $depth + 1);
                $map[$k] = $v;
            }
            return $map;

        case 6: // Semantic Tag
            webauthn_cbor_read_uint($buf, $offset, $ai);
            return webauthn_cbor_decode($buf, $offset, $depth + 1);

        case 7: // Simple / Float
            if ($ai === 20) {
                return false;
            }
            if ($ai === 21) {
                return true;
            }
            if ($ai === 22 || $ai === 23) {
                return null;
            }
            if ($ai === 25) {
                if ($offset + 2 > $len) {
                    throw new RuntimeException("CBOR truncated float16");
                }
                $offset += 2;
                return 0.0;
            }
            if ($ai === 26) {
                if ($offset + 4 > $len) {
                    throw new RuntimeException("CBOR truncated float32");
                }
                $v = unpack("G", substr($buf, $offset, 4))[1];
                $offset += 4;
                return (float) $v;
            }
            if ($ai === 27) {
                if ($offset + 8 > $len) {
                    throw new RuntimeException("CBOR truncated float64");
                }
                $v = unpack("E", substr($buf, $offset, 8))[1];
                $offset += 8;
                return (float) $v;
            }
            return null;
    }

    throw new RuntimeException("Unsupported CBOR major type: $major");
}

/**
 * Converts a decoded COSE_Key map (ES256 P-256 or RS256) into an OpenSSL-compatible SPKI PEM public key.
 * @return array{pem: string, alg: int}
 */
function webauthn_cose_to_pem(array $coseKey): array
{
    $kty = (int) ($coseKey[1] ?? 0);
    $alg = (int) ($coseKey[3] ?? 0);

    // EC2 P-256 (ES256, alg -7) — used natively by Apple macOS Touch ID / Passkeys
    if ($kty === 2 && $alg === -7) {
        $crv = (int) ($coseKey[-1] ?? 0);
        $x = $coseKey[-2] ?? "";
        $y = $coseKey[-3] ?? "";
        if (
            $crv !== 1 ||
            !is_string($x) ||
            !is_string($y) ||
            strlen($x) !== 32 ||
            strlen($y) !== 32
        ) {
            throw new RuntimeException("Invalid P-256 COSE public key parameters");
        }
        $algId = der_sequence(
            "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" .
                "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
        );
        $spkiDer = der_sequence($algId . der_bit_string("\x04" . $x . $y));
        $pem =
            "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($spkiDer), 64, "\n") .
            "-----END PUBLIC KEY-----\n";
        $pubRes = @openssl_pkey_get_public($pem);
        if (!$pubRes) {
            throw new RuntimeException("Generated EC SPKI PEM rejected by OpenSSL");
        }
        return ["pem" => $pem, "alg" => -7];
    }

    // RSA (RS256, alg -257)
    if ($kty === 3 && $alg === -257) {
        $n = $coseKey[-1] ?? "";
        $e = $coseKey[-2] ?? "";
        if (!is_string($n) || !is_string($e) || $n === "" || $e === "") {
            throw new RuntimeException("Invalid RSA COSE public key parameters");
        }
        $nTrimmed = ltrim($n, "\x00");
        $eTrimmed = ltrim($e, "\x00");
        // Bounded both ways (G1c-03): the stored key is loaded whenever the passkey is used,
        // and real authenticators use 2048-bit (at most 4096-bit) keys with e = 65537.
        if (strlen($nTrimmed) < 256 || strlen($nTrimmed) > 512) {
            throw new RuntimeException("RSA modulus must be 2048 to 4096 bits");
        }
        if (
            $eTrimmed === "" ||
            strlen($eTrimmed) > 4 ||
            (ord($eTrimmed[strlen($eTrimmed) - 1]) & 1) === 0 ||
            ($eTrimmed === "\x01")
        ) {
            throw new RuntimeException("Invalid RSA public exponent");
        }
        $rsaPubKey = der_sequence(
            der_integer_unsigned($nTrimmed) . der_integer_unsigned($eTrimmed)
        );
        $algId = der_sequence(
            "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"
        );
        $spkiDer = der_sequence($algId . der_bit_string($rsaPubKey));
        $pem =
            "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($spkiDer), 64, "\n") .
            "-----END PUBLIC KEY-----\n";
        if (!@openssl_pkey_get_public($pem)) {
            throw new RuntimeException("Generated RSA SPKI PEM rejected by OpenSSL");
        }
        return ["pem" => $pem, "alg" => -257];
    }

    throw new RuntimeException(
        "Unsupported WebAuthn COSE key type ($kty) or alg ($alg)"
    );
}

/**
 * Returns the storage PDO after this lane's run-once WebAuthn migration, which repairs
 * stored passkey labels that are not valid UTF-8 (cut mid-character by the old byte-wise
 * truncation), so JSON responses that embed them encode again.
 */
function webauthn_db(string $storePath): PDO
{
    $pdo = storage_db($storePath);
    try {
        schema_ensure($pdo, "login.webauthn_label_utf8_v1", [
            static function (PDO $db): void {
                webauthn_repair_friendly_names($db);
            },
        ]);
    } catch (LogicException $e) {
        // Called inside the caller's own transaction: the repair runs on a later call.
    }
    return $pdo;
}

/**
 * One-time data repair run by webauthn_db(): rewrites friendly_name values that are not
 * valid UTF-8. utf8_truncate() turns the invalid bytes into U+FFFD. The old code only ever
 * left a dangling byte at the end of the label, so trailing U+FFFD are dropped.
 */
function webauthn_repair_friendly_names(PDO $pdo): void
{
    $tableCheck = $pdo->query(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'webauthn_credentials'"
    );
    $hasTable = $tableCheck !== false && $tableCheck->fetchColumn() !== false;
    if ($tableCheck !== false) {
        $tableCheck->closeCursor();
    }
    if (!$hasTable) {
        return;
    }
    $select = $pdo->query("SELECT id, friendly_name FROM webauthn_credentials");
    $rows = $select !== false ? $select->fetchAll(PDO::FETCH_ASSOC) : [];
    $update = $pdo->prepare(
        "UPDATE webauthn_credentials SET friendly_name = :fn WHERE id = :id"
    );
    foreach ($rows as $row) {
        $name = (string) ($row["friendly_name"] ?? "");
        if (preg_match('//u', $name) === 1) {
            continue;
        }
        $fixed = rtrim(
            (string) preg_replace('/\x{FFFD}+$/u', "", utf8_truncate($name, 80))
        );
        $update->execute([
            ":fn" => $fixed !== "" ? $fixed : "macOS Touch ID",
            ":id" => (string) $row["id"],
        ]);
    }
}

/**
 * The user's passkeys (all, or those of $rpId), newest first. Every column except the
 * public key, which only webauthn_verify_assertion() needs; to test whether a user has
 * passkeys, use webauthn_count_user_credentials().
 */
function webauthn_list_user_credentials(
    string $storePath,
    string $userId,
    ?string $rpId = null
): array {
    $pdo = webauthn_db($storePath);
    $columns =
        "id, user_id, owner, rp_id, friendly_name, cose_alg, sign_count, transports_json, " .
        "aaguid, created_at, last_used_at";
    if ($rpId !== null) {
        $stmt = $pdo->prepare(
            "SELECT " . $columns . " FROM webauthn_credentials WHERE user_id = :uid AND LOWER(rp_id) = LOWER(:rp) ORDER BY created_at DESC"
        );
        $stmt->execute([":uid" => $userId, ":rp" => $rpId]);
    } else {
        $stmt = $pdo->prepare(
            "SELECT " . $columns . " FROM webauthn_credentials WHERE user_id = :uid ORDER BY created_at DESC"
        );
        $stmt->execute([":uid" => $userId]);
    }
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/** Number of passkeys the user has (all, or those of $rpId). */
function webauthn_count_user_credentials(
    string $storePath,
    string $userId,
    ?string $rpId = null
): int {
    $pdo = webauthn_db($storePath);
    if ($rpId !== null) {
        $stmt = $pdo->prepare(
            "SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = :uid AND LOWER(rp_id) = LOWER(:rp)"
        );
        $stmt->execute([":uid" => $userId, ":rp" => $rpId]);
    } else {
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = :uid");
        $stmt->execute([":uid" => $userId]);
    }
    $count = (int) $stmt->fetchColumn();
    $stmt->closeCursor();
    return $count;
}

/**
 * PublicKeyCredentialDescriptors of the user's newest passkeys for $rpId, at most
 * WEBAUTHN_OPTIONS_MAX_CREDENTIALS, for excludeCredentials and allowCredentials. Only the
 * id and transports are read, never the stored public keys (G1c-03).
 */
function webauthn_credential_descriptors(
    string $storePath,
    string $userId,
    string $rpId
): array {
    $pdo = webauthn_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT id, transports_json FROM webauthn_credentials " .
            "WHERE user_id = :uid AND LOWER(rp_id) = LOWER(:rp) " .
            "ORDER BY created_at DESC LIMIT " . (int) WEBAUTHN_OPTIONS_MAX_CREDENTIALS
    );
    $stmt->execute([":uid" => $userId, ":rp" => $rpId]);
    $descriptors = [];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $cred) {
        $transports = json_decode(
            (string) ($cred["transports_json"] ?? '["internal"]'),
            true
        );
        $descriptors[] = [
            "type" => "public-key",
            "id" => (string) $cred["id"],
            "transports" => is_array($transports) ? $transports : ["internal"],
        ];
    }
    return $descriptors;
}

/**
 * Most passkeys one user may have (G1c-03): max_passkeys_per_user (env
 * OIDC_MAX_PASSKEYS_PER_USER), a whole number clamped to 1..WEBAUTHN_OPTIONS_MAX_CREDENTIALS,
 * so every passkey of a user fits in the WebAuthn options. Unset or not a whole number:
 * WEBAUTHN_DEFAULT_MAX_CREDENTIALS_PER_USER.
 */
function webauthn_max_credentials_per_user(): int
{
    $value = config_value("max_passkeys_per_user", "OIDC_MAX_PASSKEYS_PER_USER");
    if (is_string($value) && preg_match('/^\d{1,9}$/D', $value) === 1) {
        $value = (int) $value;
    }
    if (!is_int($value)) {
        if ($value !== null) {
            error_log(
                "max_passkeys_per_user is not a whole number; using " .
                    WEBAUTHN_DEFAULT_MAX_CREDENTIALS_PER_USER
            );
        }
        return WEBAUTHN_DEFAULT_MAX_CREDENTIALS_PER_USER;
    }
    return max(1, min(WEBAUTHN_OPTIONS_MAX_CREDENTIALS, $value));
}

/** The refusal for a user who already has $max passkeys (G1c-03). */
function webauthn_credential_limit_error(int $max): RuntimeException
{
    return new RuntimeException(
        "This account already has the maximum number of passkeys (" . $max . "). " .
            "A passkey it no longer uses must be removed before another can be added."
    );
}

/**
 * Deletes one passkey of $owner's directory. When a passkey was removed, the user's OIDC
 * tokens, unredeemed authorization codes and SSO sessions end with it (X3-08), so access
 * obtained with that passkey stops working.
 */
function webauthn_delete_credential(
    string $storePath,
    string $owner,
    string $credentialId
): bool {
    $pdo = webauthn_db($storePath);
    return storage_write_transaction($pdo, function (PDO $pdo) use ($owner, $credentialId): bool {
        $sel = $pdo->prepare(
            "SELECT user_id FROM webauthn_credentials WHERE id = :id AND owner = :owner LIMIT 1"
        );
        $sel->execute([":id" => $credentialId, ":owner" => $owner]);
        $userId = $sel->fetchColumn();
        $sel->closeCursor();
        if ($userId === false) {
            return false;
        }
        $stmt = $pdo->prepare(
            "DELETE FROM webauthn_credentials WHERE id = :id AND owner = :owner"
        );
        $stmt->execute([":id" => $credentialId, ":owner" => $owner]);
        if ($stmt->rowCount() === 0) {
            return false;
        }
        directory_revoke_user_access($pdo, (string) $userId);
        return true;
    });
}

/**
 * Builds PublicKeyCredentialCreationOptions for enrolling macOS Touch ID. A user who already
 * has the maximum number of passkeys is refused here with the same RuntimeException that
 * webauthn_verify_and_store_registration() enforces, before the authenticator is asked.
 */
function webauthn_build_registration_options(
    string $storePath,
    array $user,
    string $rpId,
    string $rpName = "Simple Identity Provider"
): array {
    $maxCredentials = webauthn_max_credentials_per_user();
    if (webauthn_count_user_credentials($storePath, (string) $user["id"]) >= $maxCredentials) {
        throw webauthn_credential_limit_error($maxCredentials);
    }
    $challenge = base64url_encode(random_bytes(32));
    $excludeCredentials = webauthn_credential_descriptors(
        $storePath,
        (string) $user["id"],
        $rpId
    );

    $options = [
        "challenge" => $challenge,
        "rp" => [
            "name" => $rpName,
            "id" => strtolower($rpId),
        ],
        "user" => [
            "id" => base64url_encode($user["id"]),
            "name" => $user["email"] ?: $user["username"],
            "displayName" => $user["display_name"] ?: $user["username"],
        ],
        "pubKeyCredParams" => [
            ["type" => "public-key", "alg" => -7],   // ES256 (Apple Touch ID native)
            ["type" => "public-key", "alg" => -257], // RS256 fallback
        ],
        "timeout" => 60000,
        "attestation" => "none",
        "authenticatorSelection" => [
            "authenticatorAttachment" => "platform",
            "userVerification" => "required",
            "residentKey" => "preferred",
            "requireResidentKey" => false,
        ],
        "excludeCredentials" => $excludeCredentials,
    ];

    return [
        "challenge" => $challenge,
        "publicKey" => $options,
    ];
}

/**
 * Verifies navigator.credentials.create() response and persists the Touch ID credential.
 */
function webauthn_verify_and_store_registration(
    string $storePath,
    array $user,
    string $expectedChallenge,
    string $expectedOrigin,
    string $rpId,
    array $credentialPayload,
    string $friendlyName = "macOS Touch ID"
): array {
    $response = $credentialPayload["response"] ?? [];
    $clientDataB64 = (string) ($response["clientDataJSON"] ?? "");
    $attestationB64 = (string) ($response["attestationObject"] ?? "");
    if (
        $clientDataB64 === "" ||
        $attestationB64 === "" ||
        strlen($clientDataB64) > 32768 ||
        strlen($attestationB64) > 65536
    ) {
        throw new RuntimeException("Missing or oversized WebAuthn registration payload");
    }

    $clientDataRaw = base64url_decode($clientDataB64);
    $clientData = json_decode($clientDataRaw, true, 16);
    if (!is_array($clientData)) {
        throw new RuntimeException("Invalid clientDataJSON");
    }
    if (($clientData["type"] ?? "") !== "webauthn.create") {
        throw new RuntimeException("Unexpected WebAuthn ceremony type");
    }
    if (
        !hash_equals(
            $expectedChallenge,
            (string) ($clientData["challenge"] ?? "")
        )
    ) {
        throw new RuntimeException("WebAuthn challenge mismatch");
    }
    if (
        strcasecmp(
            rtrim((string) ($clientData["origin"] ?? ""), "/"),
            rtrim($expectedOrigin, "/")
        ) !== 0
    ) {
        throw new RuntimeException("WebAuthn origin mismatch");
    }

    $attBin = base64url_decode($attestationB64);
    $cborOff = 0;
    $attObj = webauthn_cbor_decode($attBin, $cborOff);
    if (
        !is_array($attObj) ||
        !isset($attObj["authData"]) ||
        !is_string($attObj["authData"])
    ) {
        throw new RuntimeException("Invalid CBOR attestationObject");
    }

    $authData = $attObj["authData"];
    if (strlen($authData) < 55) {
        throw new RuntimeException("authenticatorData too short");
    }

    $rpIdHash = substr($authData, 0, 32);
    $expectedRpHash = hash("sha256", strtolower($rpId), true);
    if (!hash_equals($expectedRpHash, $rpIdHash)) {
        throw new RuntimeException("WebAuthn RP ID hash mismatch");
    }

    $flags = ord($authData[32]);
    $userPresent = ($flags & 0x01) !== 0;
    $userVerified = ($flags & 0x04) !== 0;
    $hasAttestedCred = ($flags & 0x40) !== 0;

    if (!$userPresent) {
        throw new RuntimeException("Authenticator did not assert User Presence (UP)");
    }
    if (!$userVerified) {
        throw new RuntimeException(
            "Biometric / Touch ID User Verification (UV) was not performed"
        );
    }
    if (!$hasAttestedCred) {
        throw new RuntimeException(
            "Missing attested credential data in authenticatorData"
        );
    }

    $signCount = (int) unpack("N", substr($authData, 33, 4))[1];
    $aaguidBin = substr($authData, 37, 16);
    $aaguidHex = bin2hex($aaguidBin);
    $credIdLen = (int) unpack("n", substr($authData, 53, 2))[1];
    if ($credIdLen < 16 || $credIdLen > 1023 || strlen($authData) < 55 + $credIdLen) {
        throw new RuntimeException("Invalid Credential ID length in authenticatorData");
    }
    $credIdBin = substr($authData, 55, $credIdLen);
    $credIdB64u = base64url_encode($credIdBin);

    $pubKeyOffset = 55 + $credIdLen;
    $coseKey = webauthn_cbor_decode($authData, $pubKeyOffset);
    if (!is_array($coseKey)) {
        throw new RuntimeException("Failed to decode COSE public key");
    }
    $converted = webauthn_cose_to_pem($coseKey);

    $allowedTransports = ["internal", "hybrid", "usb", "nfc", "ble"];
    $transports = ["internal"];
    if (isset($response["transports"]) && is_array($response["transports"])) {
        $cleanT = [];
        foreach ($response["transports"] as $t) {
            if (is_string($t) && in_array($t, $allowedTransports, true)) {
                $cleanT[] = $t;
            }
        }
        if (!empty($cleanT)) {
            $transports = array_values(array_unique($cleanT));
        }
    }

    // Display label: valid UTF-8 without control or bidi characters, cut to 80 characters
    // (not bytes), so it can never break the JSON responses that list credentials.
    $label = sanitize_label($friendlyName, 80);
    if ($label === "") {
        $label = "macOS Touch ID";
    }
    $now = gmdate("Y-m-d\TH:i:s\Z");
    $maxCredentials = webauthn_max_credentials_per_user();

    // Before the transaction: the migration check must run outside one.
    $pdo = webauthn_db($storePath);

    // The duplicate check, the per-user limit (G1c-03, over all RP IDs, so another Host or
    // rpId does not reset it) and the INSERT run in one write transaction, so concurrent
    // registrations cannot pass the checks together. Callers that already hold a write
    // transaction (enrollment links, inline and portal enrollment) are joined.
    storage_write_transaction(
        $pdo,
        function (PDO $pdo) use (
            $credIdB64u,
            $user,
            $rpId,
            $label,
            $converted,
            $signCount,
            $transports,
            $aaguidHex,
            $now,
            $maxCredentials
        ): void {
            // Prevent credential ID overwrite across users/tenants!
            $chk = $pdo->prepare(
                "SELECT user_id FROM webauthn_credentials WHERE id = :id LIMIT 1"
            );
            $chk->execute([":id" => $credIdB64u]);
            $taken = $chk->fetchColumn() !== false;
            $chk->closeCursor();
            if ($taken) {
                throw new RuntimeException("This Touch ID credential is already registered");
            }

            $cnt = $pdo->prepare("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = :uid");
            $cnt->execute([":uid" => (string) $user["id"]]);
            $existing = (int) $cnt->fetchColumn();
            $cnt->closeCursor();
            if ($existing >= $maxCredentials) {
                throw webauthn_credential_limit_error($maxCredentials);
            }

            $ins = $pdo->prepare(
                "INSERT INTO webauthn_credentials (" .
                    "id, user_id, owner, rp_id, friendly_name, public_key_pem, cose_alg, sign_count, transports_json, aaguid, created_at" .
                ") VALUES (:id, :uid, :owner, :rp, :fn, :pem, :alg, :sc, :tr, :aa, :cat)"
            );
            $ins->execute([
                ":id" => $credIdB64u,
                ":uid" => $user["id"],
                ":owner" => $user["owner"],
                ":rp" => strtolower($rpId),
                ":fn" => $label,
                ":pem" => $converted["pem"],
                ":alg" => $converted["alg"],
                ":sc" => $signCount,
                ":tr" => json_encode($transports, JSON_UNESCAPED_SLASHES),
                ":aa" => $aaguidHex,
                ":cat" => $now,
            ]);
        }
    );

    return [
        "id" => $credIdB64u,
        "user_id" => $user["id"],
        "rp_id" => strtolower($rpId),
        "friendly_name" => $label,
        "cose_alg" => $converted["alg"],
        "created_at" => $now,
    ];
}

/**
 * Builds PublicKeyCredentialRequestOptions for passkey sign-in.
 *
 * $targetUser must be a user who has already passed the password step of this transaction
 * (MFA step 2); allowCredentials then lists that user's credentials for $rpId. In every
 * other case no allowCredentials are returned: the browser offers its discoverable
 * passkeys, and the response says nothing about which accounts exist or have passkeys.
 * $usernameHint is an unauthenticated claim and is never used to look anything up. When
 * it is non-empty, $targetUser is ignored as well, because the caller may have resolved
 * that user from the hint. $owner is kept for signature compatibility. allowCredentials
 * holds at most WEBAUTHN_OPTIONS_MAX_CREDENTIALS entries (the newest passkeys).
 */
function webauthn_build_assertion_options(
    string $storePath,
    string $owner,
    string $rpId,
    ?array $targetUser = null,
    string $usernameHint = ""
): array {
    $challenge = base64url_encode(random_bytes(32));
    $allowCredentials = [];

    if ($targetUser !== null && trim($usernameHint) === "") {
        $allowCredentials = webauthn_credential_descriptors(
            $storePath,
            (string) $targetUser["id"],
            $rpId
        );
    }

    $publicKey = [
        "challenge" => $challenge,
        "rpId" => strtolower($rpId),
        "timeout" => 60000,
        "userVerification" => "required",
    ];
    if (!empty($allowCredentials)) {
        $publicKey["allowCredentials"] = $allowCredentials;
    }

    return [
        "challenge" => $challenge,
        "publicKey" => $publicKey,
    ];
}

/**
 * Rejects a passkey assertion. The specific reason goes to the server log only; callers
 * get the one generic error that is safe to show to unauthenticated clients, so a failure
 * reveals nothing about accounts, their passkeys or their status.
 */
function webauthn_assertion_reject(string $reason, array $context = []): never
{
    $line = "webauthn assertion rejected: " . $reason;
    if ($context !== []) {
        $line .= " " . (string) json_encode(
            $context,
            JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
        );
    }
    error_log($line);
    throw new RuntimeException("Passkey sign-in failed");
}

/**
 * Records a sign-counter regression (a possibly cloned authenticator) as
 * webauthn_clone_suspected: always in the server log, and in the provider's audit log when
 * $auditProviderId is given and the credential belongs to $owner.
 */
function webauthn_report_clone_suspected(
    string $storePath,
    string $owner,
    array $cred,
    int $storedSignCount,
    int $presentedSignCount,
    ?string $auditProviderId = null
): void {
    $details = [
        "credential_id" => substr((string) ($cred["id"] ?? ""), 0, 64),
        "user_id" => (string) ($cred["user_id"] ?? ""),
        "stored_sign_count" => $storedSignCount,
        "presented_sign_count" => $presentedSignCount,
    ];
    error_log(
        "webauthn_clone_suspected " .
            (string) json_encode(
                $details,
                JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
            )
    );
    if (
        $auditProviderId === null ||
        $auditProviderId === "" ||
        (string) ($cred["owner"] ?? "") !== $owner
    ) {
        return;
    }
    try {
        $user = directory_get_user_by_id(
            $storePath,
            (string) ($cred["user_id"] ?? ""),
            $owner
        );
        audit_log_append(
            $storePath,
            $auditProviderId,
            "webauthn",
            "webauthn_clone_suspected",
            "error",
            "",
            (string) ($user["username"] ?? ""),
            [],
            $details
        );
    } catch (Throwable $e) {
        error_log(
            "webauthn_clone_suspected: audit log write failed (" . get_class($e) . ")"
        );
    }
}

/**
 * Verifies a navigator.credentials.get() passkey assertion and returns the authenticated
 * user.
 *
 * Everything that proves the assertion genuine runs first: clientData type, challenge and
 * origin, the rpIdHash, the UP and UV flags, the signature and the sign counter. Only then
 * are the owner, the expected user and the user's status checked. Every failure throws the
 * same RuntimeException("Passkey sign-in failed"); the specific reason goes to error_log
 * only. $expectedUserId must come from an authenticated step (the password step of this
 * transaction), never from an unauthenticated username hint.
 *
 * Sign counter (WebAuthn section 7.2): when the stored or the presented counter is non-zero,
 * the presented one must be greater. Otherwise the authenticator may have been cloned: the
 * assertion is rejected and logged as webauthn_clone_suspected (also in the audit log of
 * $auditProviderId, when given). Authenticators that always report 0 are unaffected.
 */
function webauthn_verify_assertion(
    string $storePath,
    string $owner,
    string $expectedChallenge,
    string $expectedOrigin,
    string $rpId,
    array $assertionPayload,
    ?string $expectedUserId = null,
    ?string $auditProviderId = null
): array {
    $asString = static fn(mixed $v): string => is_string($v) ? $v : "";
    $response = is_array($assertionPayload["response"] ?? null)
        ? $assertionPayload["response"]
        : [];
    $rawIdB64 = $asString($assertionPayload["rawId"] ?? null);
    if ($rawIdB64 === "") {
        $rawIdB64 = $asString($assertionPayload["id"] ?? null);
    }
    $clientDataB64 = $asString($response["clientDataJSON"] ?? null);
    $authDataB64 = $asString($response["authenticatorData"] ?? null);
    $signatureB64 = $asString($response["signature"] ?? null);

    if (
        $rawIdB64 === "" ||
        $clientDataB64 === "" ||
        $authDataB64 === "" ||
        $signatureB64 === "" ||
        strlen($rawIdB64) > 2048 ||
        strlen($clientDataB64) > 32768 ||
        strlen($authDataB64) > 32768 ||
        strlen($signatureB64) > 4096
    ) {
        webauthn_assertion_reject("incomplete or oversized assertion payload");
    }
    $decodedRawId = base64url_decode($rawIdB64);
    if ($decodedRawId === "") {
        webauthn_assertion_reject("invalid rawId");
    }
    $credIdNorm = base64url_encode($decodedRawId);

    // 1. Client data: ceremony type, this transaction's single-use challenge, origin.
    $clientDataRaw = base64url_decode($clientDataB64);
    $clientData = json_decode($clientDataRaw, true, 16);
    if (!is_array($clientData)) {
        webauthn_assertion_reject("invalid clientDataJSON");
    }
    if (($clientData["type"] ?? "") !== "webauthn.get") {
        webauthn_assertion_reject("unexpected ceremony type");
    }
    if (
        $expectedChallenge === "" ||
        !hash_equals(
            $expectedChallenge,
            $asString($clientData["challenge"] ?? null)
        )
    ) {
        webauthn_assertion_reject("challenge mismatch");
    }
    if (
        strcasecmp(
            rtrim($asString($clientData["origin"] ?? null), "/"),
            rtrim($expectedOrigin, "/")
        ) !== 0
    ) {
        webauthn_assertion_reject("origin mismatch");
    }

    // 2. Authenticator data: RP ID hash, user presence and user verification.
    $authDataBin = base64url_decode($authDataB64);
    if (strlen($authDataBin) < 37) {
        webauthn_assertion_reject("authenticatorData too short");
    }
    $expectedRpHash = hash("sha256", strtolower($rpId), true);
    if (!hash_equals($expectedRpHash, substr($authDataBin, 0, 32))) {
        webauthn_assertion_reject("rpIdHash mismatch");
    }
    $flags = ord($authDataBin[32]);
    if (($flags & 0x01) === 0 || ($flags & 0x04) === 0) {
        webauthn_assertion_reject("user presence or verification flag not set");
    }

    // 3. Signature over authenticatorData || SHA-256(clientDataJSON) with the stored key.
    $pdo = webauthn_db($storePath);
    $stmt = $pdo->prepare(
        "SELECT * FROM webauthn_credentials WHERE id = :id AND LOWER(rp_id) = LOWER(:rp) LIMIT 1"
    );
    $stmt->execute([":id" => $credIdNorm, ":rp" => $rpId]);
    $cred = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!is_array($cred)) {
        webauthn_assertion_reject("unknown credential");
    }
    $logCtx = ["credential_id" => substr($credIdNorm, 0, 64)];
    $pubKey = openssl_pkey_get_public((string) $cred["public_key_pem"]);
    if ($pubKey === false) {
        webauthn_assertion_reject("stored public key is invalid", $logCtx);
    }
    $keyDetails = openssl_pkey_get_details($pubKey);
    $keyType = is_array($keyDetails) ? (int) ($keyDetails["type"] ?? -1) : -1;
    $coseAlg = (int) ($cred["cose_alg"] ?? -7);
    if (
        !($coseAlg === -7 && $keyType === OPENSSL_KEYTYPE_EC) &&
        !($coseAlg === -257 && $keyType === OPENSSL_KEYTYPE_RSA)
    ) {
        webauthn_assertion_reject("stored key type does not match its algorithm", $logCtx);
    }
    $sigBin = base64url_decode($signatureB64);
    if (
        $sigBin === "" ||
        openssl_verify(
            $authDataBin . hash("sha256", $clientDataRaw, true),
            $sigBin,
            $pubKey,
            OPENSSL_ALGO_SHA256
        ) !== 1
    ) {
        webauthn_assertion_reject("signature verification failed", $logCtx);
    }

    // 4. Sign counter: a counter that did not advance points to a cloned authenticator.
    $newSignCount = (int) unpack("N", substr($authDataBin, 33, 4))[1];
    $oldSignCount = (int) ($cred["sign_count"] ?? 0);
    if (
        ($newSignCount !== 0 || $oldSignCount !== 0) &&
        $newSignCount <= $oldSignCount
    ) {
        webauthn_report_clone_suspected(
            $storePath,
            $owner,
            $cred,
            $oldSignCount,
            $newSignCount,
            $auditProviderId
        );
        webauthn_assertion_reject("sign counter did not advance", $logCtx);
    }

    // 5. Account checks, now that the assertion is known to be genuine.
    if ((string) $cred["owner"] !== $owner) {
        webauthn_assertion_reject("credential belongs to another directory", $logCtx);
    }
    if ($expectedUserId !== null && (string) $cred["user_id"] !== $expectedUserId) {
        webauthn_assertion_reject("credential belongs to a different user", $logCtx);
    }
    $user = directory_get_user_by_id(
        $storePath,
        (string) $cred["user_id"],
        $owner
    );
    if (!$user) {
        webauthn_assertion_reject("credential owner no longer exists", $logCtx);
    }
    if (($user["status"] ?? "active") !== "active") {
        webauthn_assertion_reject("user is not active", $logCtx);
    }

    // 6. Record the use. The WHERE clause re-applies the counter rule to the current row,
    //    so a concurrent assertion or a deletion in the meantime makes this one fail.
    $upd = $pdo->prepare(
        "UPDATE webauthn_credentials SET sign_count = :sc, last_used_at = :ts " .
            "WHERE id = :id AND (sign_count < :sc_gt OR (sign_count = 0 AND sign_count = :sc_eq))"
    );
    $upd->bindValue(":sc", $newSignCount, PDO::PARAM_INT);
    $upd->bindValue(":ts", gmdate("Y-m-d\TH:i:s\Z"), PDO::PARAM_STR);
    $upd->bindValue(":id", (string) $cred["id"], PDO::PARAM_STR);
    $upd->bindValue(":sc_gt", $newSignCount, PDO::PARAM_INT);
    $upd->bindValue(":sc_eq", $newSignCount, PDO::PARAM_INT);
    $upd->execute();
    if ($upd->rowCount() !== 1) {
        webauthn_assertion_reject("credential changed during verification", $logCtx);
    }

    directory_touch_last_login($storePath, $user["id"]);
    return $user;
}
