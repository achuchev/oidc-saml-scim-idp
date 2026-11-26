<?php
declare(strict_types=1);

// Longest RelayState accepted from a service provider (S02-03). SAML Bindings 3.4.3/3.5.3
// allow 80 bytes, but real SPs send longer return URLs; anything above this is refused before
// a transaction is stored.
const IDP_ROUTE_RELAY_STATE_MAX_BYTES = 4096;
// Longest value accepted for an authorization request parameter that is stored in a sign-in
// transaction (state, nonce, scope, redirect_uri, ...).
const IDP_ROUTE_AUTHZ_PARAM_MAX_BYTES = 4096;
// A passkey may be added from the portal only this many seconds after the sign-in that
// proves it (S05-02), and the registration ceremony must finish within its challenge lifetime.
const IDP_ROUTE_PASSKEY_STEP_UP_SECONDS = 300;
const IDP_ROUTE_PASSKEY_CHALLENGE_SECONDS = 120;
// Longest id_token_hint accepted at /oauth2/logout (an ID token with a large groups claim).
const IDP_ROUTE_ID_TOKEN_HINT_MAX_BYTES = 16384;
// Lifetime sso_set_session() gives SSO sessions. Used to bound SAML SessionNotOnOrAfter only
// when sso_get_session() does not report the session's expires_at (S06-03).
const IDP_ROUTE_SSO_SESSION_TTL = 28800;
// Password sign-in throttling (S06-04, S05-07; see idp_route_password_guard()). Browsers that
// are not known devices of the account: attempts per account and client network per 5 minutes,
// and per network while the account is under a distributed attack (per 15 minutes); failures
// per account (15 minutes) that start that strict allowance; failures per account (1 hour)
// after which such browsers are refused password sign-in to it for an hour, however many
// networks they use; failures per network across the owner's accounts (5 minutes) after which
// they are refused on it (the default of signin_network_password_failures, see
// idp_route_pw_net_max_failures()). Known devices: attempts per device (5 minutes), and by all
// known devices of the account together (15 minutes, since the last successful sign-in).
const IDP_ROUTE_PW_ACCT_NET_MAX = 8;
const IDP_ROUTE_PW_STRICT_MAX = 2;
const IDP_ROUTE_PW_ACCT_ALERT_FAILURES = 20;
const IDP_ROUTE_PW_ACCT_MAX_FAILURES = 100;
const IDP_ROUTE_PW_NET_MAX_FAILURES = 50;
const IDP_ROUTE_PW_DEVICE_MAX = 10;
const IDP_ROUTE_PW_DEVICES_MAX = 20;
// How long a browser stays a known device of an account after its last sign-in to it, and for
// how many accounts one browser keeps known-device cookies (the oldest are dropped).
const IDP_ROUTE_KNOWN_DEVICE_TTL = 7776000;
const IDP_ROUTE_KNOWN_DEVICES_PER_BROWSER = 5;
// Sign-in transactions that requests without an SSO session may create per minute: per client
// network and provider, and per client network across all providers. Browsers with an SSO
// session use a budget per user instead, which all its sessions and the owner's providers share.
// The SAML messages requests have this IdP decode get budgets of the same size, counted apart
// (G1c-01). All three are defaults (S06-04): signin_network_tx_per_minute replaces the first,
// signin_network_tx_per_minute_all the second (unset, it keeps its ratio to the first) and
// signin_user_tx_per_minute the third (idp_route_network_budgets(), idp_route_user_budget()).
const IDP_ROUTE_TX_BUDGET_PER_NETWORK = 300;
const IDP_ROUTE_TX_BUDGET_PER_NETWORK_ALL = 600;
const IDP_ROUTE_TX_BUDGET_PER_USER = 60;
// Largest value a whole-number limit setting takes (idp_route_limit_setting()); larger values
// are capped to it.
const IDP_ROUTE_LIMIT_SETTING_MAX = 1000000;
// Passkey registration ceremonies one user may start from the portal per hour (G1c-03).
const IDP_ROUTE_PORTAL_PASSKEY_PER_HOUR = 10;
// Protocol prefix of handoff transactions (idp_route_tx_create_handoff()). No handler that loads
// a transaction accepts such a protocol, so a handoff can only be redeemed, never advanced.
const IDP_ROUTE_HANDOFF_PROTOCOL_PREFIX = "handoff:";

/**
 * Handles public Identity Provider routes:
 *  - Self-service Touch ID enrollment (/enroll*)
 *  - OIDC 1.0 Discovery, JWKS, Authorize, Token, UserInfo, Logout
 *  - SAML 2.0 Hosted Metadata URL & Download, Cert export, SSO (SP & IdP-initiated), SP-initiated SLO
 *  - Hosted SSO Login Widget (Touch ID + Password + Step-Up MFA)
 *  - Okta-Style End-User App Portal (/{idpId}/portal)
 *  - Built-In Interactive OIDC & SAML Test Harness (/{idpId}/test/*, provider owner only)
 *
 * Cross-site POSTs (SAML HTTP-POST binding, POST /oauth2/authorize, an RP's logout form) carry
 * no SameSite=Lax cookies, so their handlers never read the SSO session, never start a PHP
 * session and never set the transaction-binding cookie: they store the request in a handoff
 * transaction (idp_route_tx_create_handoff()) and continue with a 303 to a same-site GET.
 */
function handle_idp_routes(
    string $method,
    string $path,
    string $PROVIDERS_FILE,
    string $KEYS_DIR,
    bool $isHttps,
    string $origin,
    string $baseUrl,
    string $rpId
): void {
    // ---------- Self-Service Touch ID Enrollment (/enroll) ----------
    if ($path === "/enroll" && $method === "GET") {
        $tok = idp_route_query_param("token");
        $user = directory_find_user_by_enrollment_token($PROVIDERS_FILE, $tok);
        if (!$user) {
            render_modern_status_page(
                400,
                "Enrollment Link Expired",
                "This Touch ID onboarding link is invalid, expired, or has already been used. Ask your administrator to generate a fresh invite link.",
                ["variant" => "error"]
            );
        }
        render_enrollment_page($user, $tok, $baseUrl);
    }

    if ($path === "/enroll/options" && $method === "POST") {
        verify_request_csrf($origin, true);
        $body = read_json_body();
        $tok = is_string($body["token"] ?? null) ? trim($body["token"]) : "";
        // S05-07: the link is checked first and only failures are counted, so a valid link
        // works even while this network is locked out. The bucket is per client IP (a /64 for
        // IPv6) as resolved by the proxy-aware client_ip_address().
        $user = directory_find_user_by_enrollment_token($PROVIDERS_FILE, $tok);
        if (!$user) {
            $rlBucket = rate_limit_bucket("enroll", client_ip_bucket());
            if (rate_limit_is_blocked($PROVIDERS_FILE, $rlBucket)) {
                json_response(429, ["error" => "Too many attempts; please wait"]);
            }
            rate_limit_record_failure($PROVIDERS_FILE, $rlBucket, 10, 300, 300);
            json_response(400, ["error" => "Invalid or expired enrollment token"]);
        }
        try {
            $reg = webauthn_build_registration_options(
                $PROVIDERS_FILE,
                $user,
                $rpId
            );
            session_ensure_started();
            $_SESSION["enroll_webauthn"] = [
                "user_id" => $user["id"],
                "challenge" => $reg["challenge"],
                "expires_at" => time() + 300,
            ];
            json_response(200, ["publicKey" => $reg["publicKey"]]);
        } catch (Throwable $e) {
            json_response(400, [
                "error" => idp_route_error_message($e, "Could not start passkey enrollment"),
            ]);
        }
    }

    if ($path === "/enroll/verify" && $method === "POST") {
        verify_request_csrf($origin, true);
        $body = read_json_body();
        $tok = is_string($body["token"] ?? null) ? trim($body["token"]) : "";
        $user = directory_find_user_by_enrollment_token($PROVIDERS_FILE, $tok);
        $pending = $_SESSION["enroll_webauthn"] ?? null;
        unset($_SESSION["enroll_webauthn"]);
        if (
            !$user ||
            !is_array($pending) ||
            ($pending["user_id"] ?? "") !== $user["id"] ||
            (int) ($pending["expires_at"] ?? 0) < time()
        ) {
            json_response(400, ["error" => "Enrollment session expired; try again"]);
        }
        if (!is_array($body["credential"] ?? null)) {
            json_response(400, ["error" => "Missing passkey registration data"]);
        }
        $credentialPayload = $body["credential"];
        $friendlyName = is_string($body["friendlyName"] ?? null)
            ? $body["friendlyName"]
            : "MacBook Touch ID";
        try {
            // S12-15: the single-use link is consumed in the write transaction that stores the
            // passkey, and only while it is still this active user's unexpired link. A failed
            // registration rolls back (the link keeps working), and of two concurrent requests
            // with one link only one registers a passkey.
            $cred = storage_write_transaction(
                storage_db($PROVIDERS_FILE),
                function (PDO $pdo) use (
                    $PROVIDERS_FILE,
                    $user,
                    $pending,
                    $origin,
                    $rpId,
                    $credentialPayload,
                    $friendlyName,
                    $tok
                ): array {
                    if (!directory_consume_enrollment_token($PROVIDERS_FILE, (string) $user["id"], $tok)) {
                        throw new RuntimeException(
                            "This enrollment link is invalid, expired or already used"
                        );
                    }
                    return webauthn_verify_and_store_registration(
                        $PROVIDERS_FILE,
                        $user,
                        (string) $pending["challenge"],
                        $origin,
                        $rpId,
                        $credentialPayload,
                        $friendlyName
                    );
                }
            );
            json_response(201, ["credential" => $cred]);
        } catch (Throwable $e) {
            json_response(400, [
                "error" => idp_route_error_message($e, "Passkey enrollment failed"),
            ]);
        }
    }

    // All remaining IdP routes are scoped under /{idpId}/...
    if (!preg_match('#^/([^/]+)(/.*)$#', $path, $pm)) {
        return;
    }
    $idpIdSegment = $pm[1];
    $subPath = $pm[2];

    if (in_array($idpIdSegment, ["api", "assets", "src", "samples"], true)) {
        return;
    }

    $provider = load_provider_by_idp_id($PROVIDERS_FILE, $idpIdSegment);
    if (!$provider) {
        return;
    }
    // Only this provider is handed on: token issuance and key rotation write back nothing else.
    $providers = [$provider];
    $issuer = $baseUrl . "/" . $provider["idp_id"];

    // ---------- SCIM 2.0 Inbound Identity Server & On-Premises Agent Relay ----------
    handle_scim_agent_routes(
        $method,
        $subPath,
        $PROVIDERS_FILE,
        $provider
    );
    handle_scim_inbound_routes(
        $method,
        $subPath,
        $PROVIDERS_FILE,
        $provider,
        $issuer
    );

    // Handle CORS preflight on OIDC endpoints
    if (
        $method === "OPTIONS" &&
        in_array(
            $subPath,
            [
                "/.well-known/openid-configuration",
                "/jwks",
                "/oauth2/token",
                "/oauth2/userinfo",
            ],
            true
        )
    ) {
        send_oidc_cors_headers();
        http_response_code(204);
        exit();
    }

    // ---------- OIDC Discovery & JWKS ----------
    if ($subPath === "/.well-known/openid-configuration" && $method === "GET") {
        send_oidc_cors_headers();
        header("Content-Type: application/json; charset=utf-8");
        echo json_encode(
            discovery_doc($provider, $baseUrl),
            JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT
        );
        exit();
    }

    if ($subPath === "/jwks" && $method === "GET") {
        send_oidc_cors_headers();
        $keys = filter_publishable_keys_for_provider($provider);
        $jwkset = [];
        foreach ($keys as $k) {
            // One unusable stored key must not take the whole key set down (S04-11).
            try {
                $jwkset[] = jwk_from_key($k);
            } catch (Throwable $e) {
                error_log(
                    "jwks: skipping key " .
                        sanitize_label((string) ($k["kid"] ?? "?"), 80) .
                        " of provider " .
                        $provider["id"] .
                        " (" .
                        get_class($e) .
                        ": " .
                        sanitize_label($e->getMessage(), 200) .
                        ")"
                );
            }
        }
        header("Content-Type: application/json; charset=utf-8");
        header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
        header("Pragma: no-cache");
        header("Expires: 0");
        echo json_encode(
            ["keys" => $jwkset],
            JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT
        );
        exit();
    }

    // ---------- SAML 2.0 Hosted Metadata URL, Export & Cert ----------
    if (
        ($subPath === "/saml/metadata" || $subPath === "/saml/metadata.xml") &&
        $method === "GET"
    ) {
        send_security_headers(false);
        $signMeta = isset($_GET["signed"]) && $_GET["signed"] !== "0";
        $download = isset($_GET["download"]) && $_GET["download"] !== "0";
        try {
            // The active certificate signs; every published one (a staged next certificate and
            // ones retired within the grace period) is listed, so SPs can roll over (G1a-04).
            $samlCert = ensure_provider_saml_cert($PROVIDERS_FILE, $provider);
            try {
                $publishedCerts = list_published_provider_saml_certs(
                    $PROVIDERS_FILE,
                    (string) $provider["id"]
                );
            } catch (Throwable $e) {
                error_log(
                    "saml metadata: published certificates unavailable for provider " .
                        $provider["id"] .
                        " (" .
                        get_class($e) .
                        ")"
                );
                $publishedCerts = [];
            }
            $xml = saml_build_idp_metadata(
                $provider,
                $baseUrl,
                $samlCert,
                $signMeta,
                $publishedCerts
            );
        } catch (Throwable $e) {
            error_log(
                "saml metadata: cannot build metadata for provider " .
                    $provider["id"] .
                    " (" .
                    get_class($e) .
                    ": " .
                    sanitize_label($e->getMessage(), 200) .
                    ")"
            );
            render_modern_status_page(
                503,
                "SAML Metadata Unavailable",
                "The SAML signing certificate of this identity provider could not be loaded. The administrator can find details in the server log.",
                ["variant" => "error"]
            );
        }

        $accept = (string) ($_SERVER["HTTP_ACCEPT"] ?? "");
        if ($download) {
            header("Content-Type: application/xml; charset=utf-8");
            header(
                'Content-Disposition: attachment; filename="' .
                    preg_replace('/[^A-Za-z0-9._-]/', "_", $provider["idp_id"]) .
                    '-idp-metadata.xml"'
            );
        } elseif (str_contains($accept, "application/samlmetadata+xml")) {
            header("Content-Type: application/samlmetadata+xml; charset=utf-8");
        } else {
            header("Content-Type: application/xml; charset=utf-8");
        }
        header("Access-Control-Allow-Origin: *");
        echo $xml;
        exit();
    }

    if (
        ($subPath === "/saml/cert.pem" || $subPath === "/saml/cert.cer") &&
        $method === "GET"
    ) {
        try {
            $samlCert = ensure_provider_saml_cert($PROVIDERS_FILE, $provider);
        } catch (Throwable $e) {
            error_log(
                "saml cert: cannot load the signing certificate of provider " .
                    $provider["id"] .
                    " (" .
                    get_class($e) .
                    ")"
            );
            send_security_headers(false);
            http_response_code(503);
            header("Content-Type: text/plain; charset=utf-8");
            echo "The SAML signing certificate is unavailable.";
            exit();
        }
        $download = isset($_GET["download"]) && $_GET["download"] !== "0";
        header("Content-Type: application/x-pem-file; charset=utf-8");
        if ($download) {
            $ext = str_ends_with($subPath, ".cer") ? "cer" : "pem";
            header(
                'Content-Disposition: attachment; filename="' .
                    preg_replace('/[^A-Za-z0-9._-]/', "_", $provider["idp_id"]) .
                    "-saml-signing.{$ext}\""
            );
        }
        echo $samlCert["cert_pem"];
        exit();
    }

    // ---------- SAML 2.0 Single Sign-On (SP-Initiated & IdP-Initiated) ----------
    if ($subPath === "/saml/sso" && in_array($method, ["GET", "POST"], true)) {
        $rawQuery = (string) ($_SERVER["QUERY_STRING"] ?? "");
        $app = null;
        $authnReq = null;
        $prelim = null;
        $relayState = "";

        try {
            if ($method === "POST") {
                $samlReqParam = idp_route_post_param("SAMLRequest");
                $relayState = idp_route_post_param("RelayState");
            } else {
                // S02-01: SAMLRequest and RelayState come from one parse of the raw query, the
                // one the Redirect signature is checked over; repeated or re-spelled parameters
                // are refused.
                $redirectParams = saml_redirect_binding_params($rawQuery);
                $samlReqParam = (string) ($redirectParams["SAMLRequest"] ?? "");
                $relayState = (string) ($redirectParams["RelayState"] ?? "");
            }
            // S02-03: bounded before anything is stored for this unauthenticated request.
            if (strlen($relayState) > IDP_ROUTE_RELAY_STATE_MAX_BYTES) {
                throw new InvalidArgumentException(
                    "RelayState is too long (at most " .
                        IDP_ROUTE_RELAY_STATE_MAX_BYTES .
                        " bytes)"
                );
            }

            if ($samlReqParam !== "") {
                // G1c-01: charged to a request budget before the message is decoded or parsed.
                // The cross-site POST never reads the SSO session (it counts against its client
                // network); a GET with one counts against its user, as transactions do.
                idp_route_require_saml_message_budget(
                    $PROVIDERS_FILE,
                    $provider,
                    $method === "GET" ? sso_get_session($PROVIDERS_FILE, $provider) : null
                );
                $binding =
                    $method === "POST" ? SAML_BINDING_POST : SAML_BINDING_REDIRECT;
                $decodedXml = saml_decode_binding_payload($samlReqParam, $binding);

                // Preliminary parse to identify SP Issuer
                $prelim = saml_parse_authn_request($decodedXml, $binding);
                $app = saml_find_app_by_entity_id(
                    $PROVIDERS_FILE,
                    $provider["id"],
                    $prelim["issuer"]
                );
                if (!$app) {
                    // S02-13: unauthenticated noise is throttled and kept apart from the
                    // security audit class; the claimed issuer goes into the details only and
                    // is not echoed back.
                    idp_route_audit_untrusted(
                        $PROVIDERS_FILE,
                        $provider,
                        "saml",
                        "unknown_sp_issuer",
                        "",
                        "",
                        ["sp_entity_id" => (string) $prelim["issuer"]]
                    );
                    throw new RuntimeException(
                        "This SAML service provider is not registered with this identity provider"
                    );
                }

                // Full parse, exactly once per request (S02-11): Destination, freshness, replay
                // and signature checks as required by the app.
                $authnReq = saml_parse_authn_request(
                    $decodedXml,
                    $binding,
                    $rawQuery,
                    $app,
                    $issuer . "/saml/sso",
                    $PROVIDERS_FILE
                );
                saml_resolve_acs_url($app, $authnReq);
            } else {
                // IdP-Initiated SSO (?app_id=... or ?sp_entity_id=...)
                $appId = idp_route_query_param("app_id");
                $spEid = idp_route_query_param("sp_entity_id");
                if ($appId !== "") {
                    $app = saml_get_app($PROVIDERS_FILE, $provider["id"], $appId);
                } elseif ($spEid !== "") {
                    $app = saml_find_app_by_entity_id(
                        $PROVIDERS_FILE,
                        $provider["id"],
                        $spEid
                    );
                }
                if (!$app) {
                    throw new RuntimeException(
                        "Missing SAMLRequest (for SP-initiated SSO) or valid app_id (for IdP-initiated SSO)"
                    );
                }
                if ($relayState === "" && $app["default_relay_state"] !== "") {
                    $relayState = $app["default_relay_state"];
                }
            }
        } catch (SamlStatusError $e) {
            // A valid request this IdP cannot meet (InvalidNameIDPolicy, NoAuthnContext) is
            // answered with a status response at the SP's ACS (S02-02, S02-11).
            if ($app !== null) {
                idp_route_saml_send_status(
                    $PROVIDERS_FILE,
                    $provider,
                    $baseUrl,
                    $app,
                    $e->authnRequest ?? $prelim,
                    $relayState,
                    $e->statusCode,
                    $e->subStatusCode,
                    $e->getMessage()
                );
            }
            idp_route_saml_request_error($issuer, $e);
        } catch (Throwable $e) {
            idp_route_saml_request_error($issuer, $e);
        }

        // A RequestedAuthnContext can raise the app's sign-on policy (S02-02).
        $minPolicy = saml_requested_min_auth_policy($authnReq ?? []);

        if ($method === "GET") {
            // Top-level GETs carry the SameSite=Lax SSO cookie: answer from the session here.
            $session = idp_route_saml_reusable_session(
                $PROVIDERS_FILE,
                $provider,
                $app,
                $authnReq,
                $minPolicy
            );
            if ($session !== null) {
                // S06-03: AuthnInstant and SessionNotOnOrAfter follow the reused session.
                idp_route_saml_send_assertion(
                    $PROVIDERS_FILE,
                    $provider,
                    $baseUrl,
                    $app,
                    $app,
                    $session["user"],
                    $session["amr"],
                    $authnReq,
                    $relayState,
                    (int) $session["auth_time"],
                    idp_route_session_expires_at($session),
                    false,
                    (string) $session["id"]
                );
            }
            if (!empty($authnReq["is_passive"])) {
                // Routine for SPs that probe for a session: not audited.
                idp_route_saml_send_status(
                    $PROVIDERS_FILE,
                    $provider,
                    $baseUrl,
                    $app,
                    $authnReq,
                    $relayState,
                    "Responder",
                    "NoPassive",
                    "The user is not signed in at the identity provider",
                    null,
                    [],
                    false
                );
                idp_route_saml_request_error(
                    $issuer,
                    new RuntimeException(
                        "The service provider asked for a passive sign-in, but you are not signed in"
                    )
                );
            }
        }

        // S02-04: a cross-site HTTP-POST AuthnRequest arrives without the SameSite=Lax SSO
        // cookie, so it is stored and GET /login, which receives the cookie, reuses the session
        // or answers IsPassive. GET requests without a usable session continue there too.
        $samlTxPayload = [
            "app_id" => $app["id"],
            "app_name" => $app["name"],
            "authn_req" => $authnReq,
            "relay_state" => $relayState,
            "min_auth_policy" => $minPolicy,
        ];
        if ($method === "POST") {
            idp_route_require_tx_budget($PROVIDERS_FILE, $provider);
            idp_route_redirect_to_handoff(
                $issuer . "/login?tx=",
                idp_route_tx_create_handoff(
                    $PROVIDERS_FILE,
                    $provider,
                    $issuer,
                    "saml",
                    $samlTxPayload
                )
            );
        }
        idp_route_require_tx_budget(
            $PROVIDERS_FILE,
            $provider,
            sso_get_session($PROVIDERS_FILE, $provider)
        );
        $txId = idp_route_tx_create_or_400(
            $PROVIDERS_FILE,
            $provider,
            $issuer,
            "saml",
            $samlTxPayload
        );
        header(
            "Location: " . $issuer . "/login?tx=" . rawurlencode($txId),
            true,
            303
        );
        exit();
    }

    // ---------- SAML 2.0 Single Logout (SP-initiated, SAML Profiles 4.4) ----------
    if ($subPath === "/saml/slo" && in_array($method, ["GET", "POST"], true)) {
        $rawQuery = (string) ($_SERVER["QUERY_STRING"] ?? "");
        $samlRequestParam = "";
        $samlResponseParam = "";
        $relayState = "";
        $binding = SAML_BINDING_POST;
        if ($method === "GET") {
            try {
                $sloParams = saml_redirect_binding_params($rawQuery);
            } catch (InvalidArgumentException $e) {
                render_modern_status_page(400, "SAML Logout Error", $e->getMessage(), [
                    "variant" => "error",
                    "link_url" => $issuer . "/portal",
                    "link_label" => "Open App Launchpad",
                ]);
            }
            $samlRequestParam = (string) ($sloParams["SAMLRequest"] ?? "");
            $samlResponseParam = (string) ($sloParams["SAMLResponse"] ?? "");
            $relayState = (string) ($sloParams["RelayState"] ?? "");
            $binding = SAML_BINDING_REDIRECT;
        } else {
            $samlRequestParam = idp_route_post_param("SAMLRequest");
            $samlResponseParam = idp_route_post_param("SAMLResponse");
            $relayState = idp_route_post_param("RelayState");
        }

        // A LogoutResponse answers a logout this IdP started (it starts none); it never ends a
        // session here (S02-05).
        if ($samlResponseParam !== "") {
            render_modern_status_page(
                200,
                "Sign-Out Response Received",
                "An application sent a sign-out response. Your Single Sign-On session with " .
                    $provider["friendly"] .
                    " was not changed.",
                [
                    "variant" => "info",
                    "link_url" => $issuer . "/portal",
                    "link_label" => "Open App Launchpad",
                ]
            );
        }

        if ($samlRequestParam !== "") {
            // G1c-01: charged before idp_route_parse_slo_request() decodes the message, like an
            // AuthnRequest at /saml/sso.
            idp_route_require_saml_message_budget(
                $PROVIDERS_FILE,
                $provider,
                $method === "GET" ? sso_get_session($PROVIDERS_FILE, $provider) : null
            );
            $pending = idp_route_parse_slo_request(
                $PROVIDERS_FILE,
                $provider,
                $issuer,
                $samlRequestParam,
                $binding,
                $rawQuery,
                $relayState
            );
            if ($pending === null) {
                // An unreadable, unknown or unverifiable request never ends a session by itself:
                // the user is asked (on a same-site GET, never in the cross-site POST).
                if ($method === "POST") {
                    header("Location: " . $issuer . "/saml/slo", true, 303);
                    exit();
                }
                idp_route_slo_confirm_page($provider, $issuer, null, null);
            }
            if ($method === "POST") {
                // The HTTP-POST binding arrives cross-site without the SameSite=Lax SSO cookie:
                // the validated request continues in a same-site GET, which redeems the handoff.
                idp_route_require_tx_budget($PROVIDERS_FILE, $provider);
                idp_route_redirect_to_handoff(
                    $issuer . "/saml/slo?slo_tx=",
                    idp_route_tx_create_handoff(
                        $PROVIDERS_FILE,
                        $provider,
                        $issuer,
                        "saml_slo",
                        $pending
                    )
                );
            }
            idp_route_continue_slo(
                $PROVIDERS_FILE,
                $provider,
                $baseUrl,
                $issuer,
                $isHttps,
                $pending,
                null
            );
        }

        $sloTx = null;
        $sloTxId = idp_route_query_param("slo_tx");
        $sloHandoff = idp_route_query_param("handoff");
        if ($method === "GET" && $sloTxId !== "" && $sloHandoff !== "") {
            // A LogoutRequest that arrived by cross-site POST continues here (used once).
            $handed = idp_route_tx_redeem_handoff(
                $PROVIDERS_FILE,
                $provider,
                $sloTxId,
                $sloHandoff,
                ["saml_slo"]
            );
            if ($handed !== null) {
                idp_route_continue_slo(
                    $PROVIDERS_FILE,
                    $provider,
                    $baseUrl,
                    $issuer,
                    $isHttps,
                    $handed["payload"],
                    null
                );
            }
            idp_route_slo_confirm_page($provider, $issuer, null, null);
        }
        if ($sloTxId !== "") {
            $loadedTx = tx_load($PROVIDERS_FILE, $sloTxId);
            if (
                $loadedTx &&
                $loadedTx["provider_id"] === $provider["id"] &&
                $loadedTx["protocol"] === "saml_slo"
            ) {
                $sloTx = $loadedTx;
            }
        }

        if ($method === "POST" && !idp_route_is_own_logout_post($origin)) {
            // Not this IdP's own confirmation (another site's form, or a page whose token is
            // stale): never a sign-out, the user is asked again on a same-site GET.
            header(
                "Location: " .
                    $issuer .
                    "/saml/slo" .
                    ($sloTx !== null ? "?slo_tx=" . rawurlencode((string) $sloTx["id"]) : ""),
                true,
                303
            );
            exit();
        }

        if ($method === "POST") {
            // Sign-out confirmed on this IdP's own page (S15-02: Origin and form token checked).
            idp_route_verify_logout_csrf($origin);
            $sloApp = null;
            $sloPayload = [];
            // Claimed atomically (G1c-05): a repeated confirmation answers the SP only once.
            if ($sloTx !== null && tx_consume_atomic($PROVIDERS_FILE, (string) $sloTx["id"]) === null) {
                $sloTx = null;
            }
            if ($sloTx !== null) {
                $sloPayload = $sloTx["payload"];
                $sloApp = saml_get_app(
                    $PROVIDERS_FILE,
                    $provider["id"],
                    (string) ($sloPayload["app_id"] ?? "")
                );
            }
            idp_route_end_sso_session(
                $PROVIDERS_FILE,
                $provider,
                $isHttps,
                "saml",
                (string) ($sloApp["name"] ?? ""),
                $sloApp !== null
                    ? [
                        "sp_entity_id" => (string) $sloApp["sp_entity_id"],
                        "slo_request_id" => (string) ($sloPayload["request_id"] ?? ""),
                        "confirmed_by_user" => true,
                    ]
                    : []
            );
            if ($sloTx !== null) {
                idp_route_send_logout_response(
                    $PROVIDERS_FILE,
                    $provider,
                    $baseUrl,
                    $sloApp,
                    (string) ($sloPayload["request_id"] ?? ""),
                    (string) ($sloPayload["relay_state"] ?? "")
                );
            }
            idp_route_signed_out_page($provider, $issuer);
        }

        if ($sloTx !== null) {
            idp_route_continue_slo(
                $PROVIDERS_FILE,
                $provider,
                $baseUrl,
                $issuer,
                $isHttps,
                $sloTx["payload"],
                $sloTx["id"]
            );
        }
        idp_route_slo_confirm_page($provider, $issuer, null, null);
    }

    // ---------- OIDC 1.0 Authorize, Token, UserInfo, Logout ----------
    if (
        $subPath === "/oauth2/authorize" &&
        in_array($method, ["GET", "POST"], true)
    ) {
        $params = $method === "POST" ? array_merge($_GET, $_POST) : $_GET;
        try {
            idp_route_check_authorize_params($params);
            $authReq = oidc_validate_authorize_request(
                $PROVIDERS_FILE,
                $provider,
                $params
            );
        } catch (Throwable $e) {
            render_modern_status_page(
                400,
                "OIDC Authorization Error",
                idp_route_error_message($e, "The authorization request is invalid"),
                [
                    "variant" => "error",
                    "link_url" => $issuer . "/portal",
                    "link_label" => "Open App Launchpad",
                ]
            );
        }

        $client = $authReq["client"];
        if ($method === "GET") {
            // Top-level GETs carry the SameSite=Lax SSO cookie: answer from the session here.
            $session = idp_route_oidc_reusable_session(
                $PROVIDERS_FILE,
                $provider,
                $client,
                $authReq
            );
            if ($session !== null) {
                oidc_issue_authorization_response(
                    $PROVIDERS_FILE,
                    $providers,
                    $provider,
                    $baseUrl,
                    $authReq,
                    $session["user"],
                    $session["amr"],
                    $KEYS_DIR,
                    (int) $session["auth_time"],
                    (string) $session["id"]
                );
            }

            if ($authReq["prompt"] === "none") {
                $errParams = ["error" => "login_required"];
                if ($authReq["state"] !== "") {
                    $errParams["state"] = $authReq["state"];
                }
                oidc_send_authorization_redirect(
                    $authReq["redirect_uri"],
                    $errParams,
                    $authReq["response_mode"]
                );
            }
        }

        // S02-04: a POST (form_post from another site) carries no SameSite=Lax cookies; it is
        // stored and GET /login reuses the SSO session or answers prompt=none there.
        $payloadToStore = $authReq;
        unset($payloadToStore["client"]);
        $payloadToStore["app_name"] = $client["name"];
        if ($method === "POST") {
            idp_route_require_tx_budget($PROVIDERS_FILE, $provider);
            idp_route_redirect_to_handoff(
                $issuer . "/login?tx=",
                idp_route_tx_create_handoff(
                    $PROVIDERS_FILE,
                    $provider,
                    $issuer,
                    "oidc",
                    $payloadToStore
                )
            );
        }
        idp_route_require_tx_budget(
            $PROVIDERS_FILE,
            $provider,
            sso_get_session($PROVIDERS_FILE, $provider)
        );

        $txId = idp_route_tx_create_or_400(
            $PROVIDERS_FILE,
            $provider,
            $issuer,
            "oidc",
            $payloadToStore
        );
        header(
            "Location: " . $issuer . "/login?tx=" . rawurlencode($txId),
            true,
            303
        );
        exit();
    }

    if ($subPath === "/oauth2/token" && $method === "POST") {
        oidc_handle_oauth2_token(
            $PROVIDERS_FILE,
            $providers,
            $provider,
            $baseUrl,
            $KEYS_DIR
        );
    }

    if (
        $subPath === "/oauth2/userinfo" &&
        in_array($method, ["GET", "POST"], true)
    ) {
        oidc_handle_userinfo($PROVIDERS_FILE, $provider);
    }

    if (
        $subPath === "/oauth2/logout" &&
        in_array($method, ["GET", "POST"], true)
    ) {
        // OIDC RP-Initiated Logout 1.0. A registered post_logout_redirect_uri is no proof of
        // anything (anyone can send one), so a GET ends the SSO session without asking only with
        // a verified ID token of the session's user (S02-06); otherwise the user confirms first.
        // Only this IdP's own confirmation POST ends a session directly. An RP's logout form
        // POST (section 2) carries neither the SameSite=Lax SSO cookie nor this IdP's CSRF
        // token: it is checked like a GET, in the same-site GET it is redirected to (S03-11).
        $confirmedHere = $method === "POST" && idp_route_is_own_logout_post($origin);
        $handedOff = null;
        $logoutTxId = $method === "GET" ? idp_route_query_param("logout_tx") : "";
        if ($logoutTxId !== "") {
            $handedOff = idp_route_tx_redeem_handoff(
                $PROVIDERS_FILE,
                $provider,
                $logoutTxId,
                idp_route_query_param("handoff"),
                ["oidc_logout"]
            );
        }
        if ($handedOff !== null) {
            // The RP's POST verified its id_token_hint; the outcome travelled in the handoff.
            [$logoutReq, $hint, $hintSent] = idp_route_oidc_logout_from_handoff(
                $handedOff["payload"]
            );
        } else {
            // The request's own parameters. A used or expired handoff URL has none, so it is
            // handled as a logout without parameters (the user is asked).
            $logoutReq = idp_route_oidc_logout_request();
            $hintSent = $logoutReq["id_token_hint"] !== "";
            $hint = $hintSent
                ? idp_route_verify_id_token_hint($provider, $issuer, $logoutReq["id_token_hint"])
                : null;
        }
        if ($method === "POST" && !$confirmedHere) {
            idp_route_require_tx_budget($PROVIDERS_FILE, $provider);
            idp_route_redirect_to_handoff(
                $issuer . "/oauth2/logout?logout_tx=",
                idp_route_tx_create_handoff(
                    $PROVIDERS_FILE,
                    $provider,
                    $issuer,
                    "oidc_logout",
                    [
                        "malformed" => $logoutReq["malformed"],
                        "post_logout_redirect_uri" => $logoutReq["post_logout_redirect_uri"],
                        "state" => $logoutReq["state"],
                        "client_id" => $logoutReq["client_id"],
                        "id_token_hint_sent" => $hintSent,
                        "hint" => $hint,
                    ]
                )
            );
        }
        $requestOk = !$logoutReq["malformed"];
        $logoutClientId = $logoutReq["client_id"];
        if ($hint !== null) {
            if ($logoutClientId !== "" && $logoutClientId !== $hint["client_id"]) {
                // client_id must name the client the ID token was issued to.
                $requestOk = false;
                $hint = null;
            } else {
                $logoutClientId = $hint["client_id"];
            }
        }
        // G1d-04, S03-11: only a URI registered by that client that still meets the endpoint
        // rules is ever redirected to; a request that names no client (neither a verified
        // id_token_hint nor client_id) is not redirected, unless legacy_logout_redirect is on.
        $redirect = $requestOk
            ? idp_route_oidc_logout_redirect(
                $PROVIDERS_FILE,
                $provider,
                $logoutReq["post_logout_redirect_uri"],
                $logoutClientId
            )
            : ["uri" => "", "client_name" => ""];
        $validatedRedirect = $redirect["uri"];
        // A request with an error (a malformed parameter, a mismatched client_id, a redirect
        // URI that is not allowed) is never redirected and never skips the confirmation.
        $requestOk =
            $requestOk &&
            ($logoutReq["post_logout_redirect_uri"] === "" || $validatedRedirect !== "");

        if ($confirmedHere) {
            // Sign-out confirmed on this IdP's own page (S15-02: Origin and form token checked).
            idp_route_verify_logout_csrf($origin);
        } else {
            // A GET, or an RP's form POST continued here. Without a session there is nothing
            // to end and nothing to protect.
            $session = sso_get_session($PROVIDERS_FILE, $provider);
            if (
                $session !== null &&
                !($requestOk && idp_route_logout_hint_matches_session($hint, $session))
            ) {
                // The confirmation carries the validated redirect, so the RP gets its user back.
                $carry = [];
                if ($validatedRedirect !== "") {
                    $carry["post_logout_redirect_uri"] = $validatedRedirect;
                    if ($logoutClientId !== "") {
                        $carry["client_id"] = $logoutClientId;
                    }
                    if ($logoutReq["state"] !== "") {
                        $carry["state"] = $logoutReq["state"];
                    }
                }
                // S02-05: other applications are not signed out, and the page says so.
                render_modern_status_page(
                    200,
                    "Sign out of " . $provider["friendly"] . "?",
                    "Confirm to end your Single Sign-On session with " .
                        $provider["friendly"] .
                        ". Applications you already signed in to keep their own sessions until you sign out of them." .
                        ($redirect["client_name"] !== ""
                            ? " You will then return to " . $redirect["client_name"] . "."
                            : ""),
                    [
                        "variant" => "confirm",
                        "post_action" =>
                            $issuer .
                            "/oauth2/logout" .
                            ($carry !== []
                                ? "?" . http_build_query($carry, "", "&", PHP_QUERY_RFC3986)
                                : ""),
                        "post_label" => "Sign Out",
                        "link_url" => $issuer . "/portal",
                        "link_label" => "Return to Launchpad",
                    ]
                );
            }
        }

        // X3-08: the session's OIDC tokens are revoked with it.
        idp_route_end_sso_session(
            $PROVIDERS_FILE,
            $provider,
            $isHttps,
            "oidc",
            $redirect["client_name"],
            [
                "confirmed_by_user" => $confirmedHere,
                "rp_form_post" => $handedOff !== null,
                "id_token_hint" =>
                    $hint !== null ? "verified" : ($hintSent ? "rejected" : "none"),
            ]
        );
        send_security_headers(false);
        if ($validatedRedirect !== "") {
            // G1d-04: state is merged into the query, never appended inside a fragment.
            header(
                "Location: " .
                    oidc_build_redirect_url(
                        $validatedRedirect,
                        $logoutReq["state"] !== "" ? ["state" => $logoutReq["state"]] : []
                    ),
                true,
                302
            );
            exit();
        }
        header("Location: " . $issuer . "/portal", true, 302);
        exit();
    }

    // ---------- Hosted SSO Login & Touch ID Ceremonies ----------
    if ($subPath === "/login" && $method === "GET") {
        $txId = idp_route_query_param("tx");
        $handoff = idp_route_query_param("handoff");
        if ($txId !== "" && $handoff !== "") {
            // A request that arrived by cross-site POST: from here on its transaction is bound
            // to this browser's own binding cookie, which this same-site GET carries (or gets
            // now, if the browser has none), and the URL no longer holds the handoff secret.
            // Only a handoff is redeemed, and the sign-in starts from its first step: no
            // progress of another browser's sign-in ever moves into this one (S14-03).
            $handed = idp_route_tx_redeem_handoff(
                $PROVIDERS_FILE,
                $provider,
                $txId,
                $handoff,
                ["saml", "oidc"]
            );
            if ($handed === null) {
                idp_route_tx_expired_page($issuer);
            }
            $txId = idp_route_tx_create_or_400(
                $PROVIDERS_FILE,
                $provider,
                $issuer,
                (string) $handed["protocol"],
                $handed["payload"],
                [],
                max(60, (int) $handed["expires_at"] - time())
            );
            header(
                "Location: " . $issuer . "/login?tx=" . rawurlencode($txId),
                true,
                303
            );
            exit();
        }
        if ($txId === "") {
            idp_route_require_tx_budget(
                $PROVIDERS_FILE,
                $provider,
                sso_get_session($PROVIDERS_FILE, $provider)
            );
            $txId = tx_create(
                $PROVIDERS_FILE,
                $provider["id"],
                $provider["owner"],
                "portal",
                []
            );
            header(
                "Location: " . $issuer . "/login?tx=" . rawurlencode($txId),
                true,
                302
            );
            exit();
        }
        $tx = tx_load($PROVIDERS_FILE, $txId);
        if (
            !$tx ||
            $tx["provider_id"] !== $provider["id"] ||
            !idp_route_is_login_protocol((string) $tx["protocol"])
        ) {
            idp_route_tx_expired_page($issuer);
        }
        // S02-04: requests that arrived by cross-site POST are answered from the SSO session
        // here, where the SameSite=Lax cookie is sent (so is a GET request whose user signed in
        // meanwhile). Forced re-authentication never reuses a session.
        if ($tx["protocol"] === "saml") {
            idp_route_resume_saml($PROVIDERS_FILE, $provider, $baseUrl, $issuer, $tx);
        } elseif ($tx["protocol"] === "oidc") {
            idp_route_resume_oidc(
                $PROVIDERS_FILE,
                $providers,
                $provider,
                $baseUrl,
                $KEYS_DIR,
                $issuer,
                $tx
            );
        }
        render_hosted_login_page($PROVIDERS_FILE, $provider, $baseUrl, $tx, $rpId);
    }

    if ($subPath === "/login/password" && $method === "POST") {
        verify_request_csrf($origin, true);
        $body = read_json_body();
        $tx = tx_load(
            $PROVIDERS_FILE,
            is_string($body["txId"] ?? null) ? $body["txId"] : ""
        );
        if (
            !$tx ||
            $tx["provider_id"] !== $provider["id"] ||
            !idp_route_is_login_protocol((string) $tx["protocol"])
        ) {
            json_response(400, ["error" => "Login session expired; please reload"]);
        }
        $ctx = tx_resolve_context($PROVIDERS_FILE, $provider, $tx);
        // X1-10: the effective policy ("inherit" is the provider default), raised by a SAML
        // RequestedAuthnContext.
        $policy = idp_route_tx_auth_policy($provider, $tx, $ctx);
        if ($policy === "touchid_only") {
            json_response(403, [
                "error" => "Password login is disabled; Touch ID is required",
            ]);
        }

        $ident = is_string($body["username"] ?? null) ? trim($body["username"]) : "";
        $pw = is_string($body["password"] ?? null) ? $body["password"] : "";

        $user =
            $ident !== "" && strlen($ident) <= 320
                ? directory_find_user_by_identifier(
                    $PROVIDERS_FILE,
                    $provider["owner"],
                    $ident
                )
                : null;
        // S06-04, S05-07: the attempt is throttled and reserved before bcrypt runs, per account
        // (username and email share it; unknown identifiers count as typed) and per client
        // network, so a lockout stays on the network that caused it, with a ceiling per account
        // that no number of networks lifts, while a browser that completed a sign-in to this
        // account with its current password keeps a budget of its own (idp_route_password_guard()).
        $knownDevice = $user !== null
            ? idp_route_known_device($PROVIDERS_FILE, $provider, $user, $isHttps)
            : null;
        $pwGuard = idp_route_password_guard(
            $PROVIDERS_FILE,
            $provider,
            $user !== null ? "uid:" . $user["id"] : "ident:" . strtolower($ident),
            $knownDevice
        );

        // S06-07: a hash with outdated parameters is upgraded after a successful check.
        $pwOk =
            strlen($pw) <= 4096 &&
            directory_verify_password($user, $pw, $PROVIDERS_FILE);
        if (!$user || ($user["status"] ?? "active") !== "active" || !$pwOk) {
            idp_route_password_attempt_done($PROVIDERS_FILE, $pwGuard, false);
            idp_route_audit_untrusted(
                $PROVIDERS_FILE,
                $provider,
                (string) $tx["protocol"],
                "password_login_failed",
                (string) $ctx["app_name"],
                $ident
            );
            json_response(401, ["error" => "Invalid username or password"]);
        }
        idp_route_password_attempt_done($PROVIDERS_FILE, $pwGuard, true);

        // No known-device cookie yet: the password alone does not complete an MFA sign-in.
        if ($policy === "mfa") {
            $step = $tx["step_state"] ?? [];
            $step["pwd_verified_user_id"] = $user["id"];
            // G1c-05: written only over the step state this request loaded.
            if (idp_route_tx_swap_step($PROVIDERS_FILE, $tx, $step) === null) {
                idp_route_tx_changed_response();
            }
            json_response(200, [
                "action" => "mfa_step2",
                "user" => [
                    "id" => $user["id"],
                    "username" => $user["username"],
                    "email" => $user["email"],
                    "touchid_count" => webauthn_count_user_credentials(
                        $PROVIDERS_FILE,
                        (string) $user["id"],
                        $rpId
                    ),
                ],
            ]);
        }

        try {
            $res = idp_route_complete_transaction(
                $PROVIDERS_FILE,
                $providers,
                $provider,
                $baseUrl,
                $isHttps,
                $tx,
                $user,
                ["pwd"],
                $KEYS_DIR
            );
        } catch (Throwable $e) {
            json_response(403, [
                "error" => idp_route_error_message($e, "Sign-in could not be completed"),
            ]);
        }
        // S06-04: the sign-in is complete, so this browser is now a known device of the account.
        idp_route_remember_device($PROVIDERS_FILE, $provider, $user, $isHttps, $knownDevice);
        json_response(200, $res);
    }

    if ($subPath === "/login/webauthn/options" && $method === "POST") {
        verify_request_csrf($origin, true);
        $body = read_json_body();
        $tx = tx_load(
            $PROVIDERS_FILE,
            is_string($body["txId"] ?? null) ? $body["txId"] : ""
        );
        if (
            !$tx ||
            $tx["provider_id"] !== $provider["id"] ||
            !idp_route_is_login_protocol((string) $tx["protocol"])
        ) {
            json_response(400, ["error" => "Login session expired; please reload"]);
        }
        // S05-07: no per-network lock here. A challenge proves nothing and costs little, and
        // refusing it would also refuse valid passkeys from a shared network; ceremonies per
        // transaction are capped below, and failed assertions are counted at /verify.
        $step = $tx["step_state"] ?? [];
        $attempts = (int) ($step["webauthn_options_count"] ?? 0) + 1;
        if ($attempts > 20) {
            json_response(429, [
                "error" => "Too many passkey attempts for this sign-in; reload the page to start again",
            ]);
        }
        $step["webauthn_options_count"] = $attempts;

        // S05-04: only a user who passed this transaction's password step is targeted. The
        // unauthenticated username hint is passed on as received and never looked up.
        $targetUser = null;
        if (!empty($step["pwd_verified_user_id"])) {
            $targetUser = directory_get_user_by_id(
                $PROVIDERS_FILE,
                (string) $step["pwd_verified_user_id"],
                $provider["owner"]
            );
        }
        $usernameHint = is_string($body["username"] ?? null) ? trim($body["username"]) : "";

        try {
            $opts = webauthn_build_assertion_options(
                $PROVIDERS_FILE,
                $provider["owner"],
                $rpId,
                $targetUser,
                $usernameHint
            );
            $step["webauthn_challenge"] = $opts["challenge"];
            unset($step["expected_user_id"]);
            // G1c-05: written only over the step state this request loaded, so a concurrent
            // request cannot restore a consumed challenge or lose the ceremony count.
            if (idp_route_tx_swap_step($PROVIDERS_FILE, $tx, $step) === null) {
                idp_route_tx_changed_response();
            }
            json_response(200, ["publicKey" => $opts["publicKey"]]);
        } catch (Throwable $e) {
            json_response(400, [
                "error" => idp_route_error_message($e, "Could not start passkey sign-in"),
            ]);
        }
    }

    if ($subPath === "/login/webauthn/verify" && $method === "POST") {
        verify_request_csrf($origin, true);
        $body = read_json_body();
        $tx = tx_load(
            $PROVIDERS_FILE,
            is_string($body["txId"] ?? null) ? $body["txId"] : ""
        );
        if (
            !$tx ||
            $tx["provider_id"] !== $provider["id"] ||
            !idp_route_is_login_protocol((string) $tx["protocol"])
        ) {
            json_response(400, ["error" => "Login session expired; please reload"]);
        }
        $step = $tx["step_state"] ?? [];
        $challenge = is_string($step["webauthn_challenge"] ?? null)
            ? $step["webauthn_challenge"]
            : "";
        if ($challenge === "") {
            json_response(400, ["error" => "No active Touch ID challenge"]);
        }
        // Single-use challenge, claimed before verification (G1c-05): the compare-and-swap
        // succeeds for one request only, so two concurrent requests cannot both redeem it.
        unset($step["webauthn_challenge"]);
        $tx = idp_route_tx_swap_step($PROVIDERS_FILE, $tx, $step);
        if ($tx === null) {
            json_response(400, ["error" => "No active Touch ID challenge"]);
        }

        if (!is_array($body["credential"] ?? null)) {
            json_response(400, ["error" => "Missing passkey credential"]);
        }
        // S05-04: the expected user comes only from this transaction's password step.
        $expectedUid = !empty($step["pwd_verified_user_id"])
            ? (string) $step["pwd_verified_user_id"]
            : null;

        try {
            // S05-05: a sign-counter regression is also written to this provider's audit log.
            $user = webauthn_verify_assertion(
                $PROVIDERS_FILE,
                $provider["owner"],
                $challenge,
                $origin,
                $rpId,
                $body["credential"],
                $expectedUid,
                (string) $provider["id"]
            );
        } catch (Throwable $e) {
            $ctx = tx_resolve_context($PROVIDERS_FILE, $provider, $tx);
            idp_route_audit_untrusted(
                $PROVIDERS_FILE,
                $provider,
                (string) $tx["protocol"],
                "touchid_failed",
                (string) $ctx["app_name"],
                "",
                ["reason" => idp_route_error_message($e, "Passkey sign-in failed")]
            );
            // S05-07: the per-network lock is consulted only after a failure, so a valid passkey
            // always works, also from a network where others failed.
            idp_route_webauthn_failure($PROVIDERS_FILE, $provider);
        }

        $amr = ["hwk", "user"];
        if (!empty($step["pwd_verified_user_id"])) {
            $amr = ["pwd", "hwk", "user", "mfa"];
        }
        $ctx = tx_resolve_context($PROVIDERS_FILE, $provider, $tx);
        if (
            idp_route_tx_auth_policy($provider, $tx, $ctx) === "mfa" &&
            !in_array("pwd", $amr, true)
        ) {
            json_response(403, [
                "error" => "This application requires Password + Touch ID MFA",
            ]);
        }
        try {
            $res = idp_route_complete_transaction(
                $PROVIDERS_FILE,
                $providers,
                $provider,
                $baseUrl,
                $isHttps,
                $tx,
                $user,
                $amr,
                $KEYS_DIR
            );
        } catch (Throwable $e) {
            json_response(403, [
                "error" => idp_route_error_message($e, "Sign-in could not be completed"),
            ]);
        }
        // S06-04: the sign-in is complete, so this browser is now a known device of the account:
        // its password attempts get a budget of their own.
        idp_route_remember_device($PROVIDERS_FILE, $provider, $user, $isHttps);
        json_response(200, $res);
    }

    // Inline Touch ID enrollment during MFA Step 2 (after password verified). S06-01: first-use
    // only, off unless allow_first_use_passkey_enrollment is on; see
    // idp_route_inline_enrollment_denial().
    if ($subPath === "/login/webauthn/register-options" && $method === "POST") {
        verify_request_csrf($origin, true);
        $body = read_json_body();
        $tx = tx_load(
            $PROVIDERS_FILE,
            is_string($body["txId"] ?? null) ? $body["txId"] : ""
        );
        $uid = (string) ($tx["step_state"]["pwd_verified_user_id"] ?? "");
        if (!$tx || $tx["provider_id"] !== $provider["id"] || $uid === "") {
            json_response(403, ["error" => "Password verification required first"]);
        }
        $user = directory_get_user_by_id($PROVIDERS_FILE, $uid, $provider["owner"]);
        $denied = idp_route_inline_enrollment_denial($PROVIDERS_FILE, $provider, $tx, $user);
        if ($denied !== null) {
            json_response($denied[0], ["error" => $denied[1]]);
        }
        try {
            $reg = webauthn_build_registration_options(
                $PROVIDERS_FILE,
                $user,
                $rpId,
                $provider["friendly"]
            );
            $step = $tx["step_state"];
            $step["reg_challenge"] = $reg["challenge"];
            // G1c-05: written only over the step state this request loaded.
            if (idp_route_tx_swap_step($PROVIDERS_FILE, $tx, $step) === null) {
                idp_route_tx_changed_response();
            }
            json_response(200, ["publicKey" => $reg["publicKey"]]);
        } catch (Throwable $e) {
            json_response(400, [
                "error" => idp_route_error_message($e, "Could not start passkey enrollment"),
            ]);
        }
    }

    if ($subPath === "/login/webauthn/register-verify" && $method === "POST") {
        verify_request_csrf($origin, true);
        $body = read_json_body();
        $tx = tx_load(
            $PROVIDERS_FILE,
            is_string($body["txId"] ?? null) ? $body["txId"] : ""
        );
        $uid = (string) ($tx["step_state"]["pwd_verified_user_id"] ?? "");
        $challenge = (string) ($tx["step_state"]["reg_challenge"] ?? "");
        if (!$tx || $tx["provider_id"] !== $provider["id"] || $uid === "" || $challenge === "") {
            json_response(400, ["error" => "Invalid enrollment state"]);
        }
        // Single-use challenge, claimed before verification (G1c-05): the compare-and-swap
        // succeeds for one request only.
        $step = $tx["step_state"];
        unset($step["reg_challenge"]);
        $tx = idp_route_tx_swap_step($PROVIDERS_FILE, $tx, $step);
        if ($tx === null) {
            json_response(400, ["error" => "Invalid enrollment state"]);
        }

        $user = directory_get_user_by_id($PROVIDERS_FILE, $uid, $provider["owner"]);
        // Status, existing passkeys, policy and group assignment are checked before anything
        // is stored, so a refused sign-in leaves no credential behind.
        $denied = idp_route_inline_enrollment_denial($PROVIDERS_FILE, $provider, $tx, $user);
        if ($denied !== null) {
            json_response($denied[0], ["error" => $denied[1]]);
        }
        if (!is_array($body["credential"] ?? null)) {
            json_response(400, ["error" => "Missing passkey registration data"]);
        }
        $credentialPayload = $body["credential"];
        $friendlyName = is_string($body["friendlyName"] ?? null)
            ? $body["friendlyName"]
            : "macOS Touch ID";
        try {
            $cred = storage_write_transaction(
                storage_db($PROVIDERS_FILE),
                function (PDO $pdo) use (
                    $PROVIDERS_FILE,
                    $user,
                    $challenge,
                    $origin,
                    $rpId,
                    $credentialPayload,
                    $friendlyName
                ): array {
                    // A passkey registered meanwhile (another tab) ends first-use enrollment.
                    if (webauthn_count_user_credentials($PROVIDERS_FILE, (string) $user["id"]) > 0) {
                        throw new RuntimeException(
                            "A passkey is already registered for this account. Use it to finish signing in."
                        );
                    }
                    return webauthn_verify_and_store_registration(
                        $PROVIDERS_FILE,
                        $user,
                        $challenge,
                        $origin,
                        $rpId,
                        $credentialPayload,
                        $friendlyName
                    );
                }
            );
        } catch (Throwable $e) {
            json_response(400, [
                "error" => idp_route_error_message($e, "Passkey enrollment failed"),
            ]);
        }
        $ctx = tx_resolve_context($PROVIDERS_FILE, $provider, $tx);
        audit_log_append(
            $PROVIDERS_FILE,
            $provider["id"],
            (string) $tx["protocol"],
            "webauthn_enrolled",
            "success",
            (string) $ctx["app_name"],
            (string) $user["username"],
            ["pwd"],
            [
                "via" => "inline_mfa",
                "credential_id" => substr((string) ($cred["id"] ?? ""), 0, 64),
                "rp_id" => (string) ($cred["rp_id"] ?? ""),
                "first_passkey" => true,
            ]
        );
        try {
            $res = idp_route_complete_transaction(
                $PROVIDERS_FILE,
                $providers,
                $provider,
                $baseUrl,
                $isHttps,
                $tx,
                $user,
                ["pwd", "hwk", "user", "mfa"],
                $KEYS_DIR
            );
        } catch (Throwable $e) {
            json_response(403, [
                "error" => idp_route_error_message($e, "Sign-in could not be completed"),
            ]);
        }
        // S06-04: password and the new passkey completed the sign-in (a known device from now on).
        idp_route_remember_device($PROVIDERS_FILE, $provider, $user, $isHttps);
        json_response(200, $res);
    }

    // Finalize top-level browser redirect / SAML POST after fetch-based login
    if ($subPath === "/login/complete" && $method === "GET") {
        $finId = idp_route_query_param("fin");
        $fin = tx_consume_atomic($PROVIDERS_FILE, $finId);
        if (
            !$fin ||
            $fin["provider_id"] !== $provider["id"] ||
            !in_array($fin["protocol"], ["oidc_finalize", "saml_finalize"], true)
        ) {
            html_response(400, "Completion token expired");
        }
        $payload = $fin["payload"];
        $user = directory_get_user_by_id(
            $PROVIDERS_FILE,
            (string) ($payload["user_id"] ?? ""),
            $provider["owner"]
        );
        if (!$user || ($user["status"] ?? "active") !== "active") {
            html_response(400, "User not found or not active");
        }
        $amr = is_array($payload["amr"] ?? null)
            ? array_values(array_filter($payload["amr"], "is_string"))
            : ["pwd"];
        // S06-03: the real sign-in time and SSO session (auth_time, AuthnInstant,
        // SessionNotOnOrAfter, and the session the tokens are revoked with).
        [$authTime, $sessionExpiresAt, $ssoSessionId] = idp_route_completed_sign_in(
            $PROVIDERS_FILE,
            $provider,
            $payload,
            $user
        );

        if ($fin["protocol"] === "oidc_finalize") {
            $authReq = is_array($payload["auth_req"] ?? null) ? $payload["auth_req"] : [];
            $client = oidc_find_client_by_client_id(
                $PROVIDERS_FILE,
                $provider["id"],
                (string) ($authReq["client_id"] ?? "")
            );
            if (!$client) {
                html_response(400, "OIDC client not found");
            }
            if (!directory_user_matches_assigned_groups($user, $client["assigned_groups"] ?? [])) {
                render_modern_status_page(
                    403,
                    "Access Denied",
                    "You are not assigned to " . $client["name"] . ".",
                    ["variant" => "error", "link_url" => $issuer . "/portal", "link_label" => "Open App Launchpad"]
                );
            }
            idp_route_require_policy_met($PROVIDERS_FILE, $provider, $issuer, $client, $user, $amr);
            $authReq["client"] = $client;
            oidc_issue_authorization_response(
                $PROVIDERS_FILE,
                $providers,
                $provider,
                $baseUrl,
                $authReq,
                $user,
                $amr,
                $KEYS_DIR,
                $authTime,
                $ssoSessionId
            );
        }

        $sReq = is_array($payload["saml_req"] ?? null) ? $payload["saml_req"] : [];
        $isTest = !empty($payload["is_test"]);
        $app = saml_get_app(
            $PROVIDERS_FILE,
            $provider["id"],
            (string) ($sReq["app_id"] ?? "")
        );
        if (!$app) {
            html_response(400, "SAML app not found");
        }
        if (!directory_user_matches_assigned_groups($user, $app["assigned_groups"] ?? [])) {
            render_modern_status_page(
                403,
                "Access Denied",
                "You are not assigned to " . $app["name"] . ".",
                ["variant" => "error", "link_url" => $issuer . "/portal", "link_label" => "Open App Launchpad"]
            );
        }
        // The RequestedAuthnContext is enforced by the response builder (NoAuthnContext).
        idp_route_require_policy_met($PROVIDERS_FILE, $provider, $issuer, $app, $user, $amr);

        // In Built-in Test Mode, route ACS POST to our local SAML Inspector while keeping real SP EntityID/mappings!
        $appForBuild = $app;
        if ($isTest) {
            $testAcs = $issuer . "/test/saml/acs?app_id=" . rawurlencode($app["id"]);
            $appForBuild["acs_url"] = $testAcs;
            $appForBuild["acs_endpoints"] = [
                [
                    "index" => 0,
                    "is_default" => true,
                    "binding" => SAML_BINDING_POST,
                    "location" => $testAcs,
                ],
            ];
        }

        idp_route_saml_send_assertion(
            $PROVIDERS_FILE,
            $provider,
            $baseUrl,
            $app,
            $appForBuild,
            $user,
            $amr,
            is_array($sReq["authn_req"] ?? null) ? $sReq["authn_req"] : null,
            is_string($sReq["relay_state"] ?? null) ? $sReq["relay_state"] : "",
            $authTime,
            $sessionExpiresAt,
            $isTest,
            $ssoSessionId
        );
    }

    // ---------- End-User App Portal ----------
    if ($subPath === "/portal" && $method === "GET") {
        // S05-02: the portal (and adding passkeys from it) needs a session that meets the
        // provider's default sign-on policy; a weaker one (say, password only, from a flexible
        // app) is sent through a sign-in that meets it.
        $session = sso_get_session($PROVIDERS_FILE, $provider);
        if ($session && auth_policy_satisfied(effective_auth_policy($provider), $session["amr"])) {
            render_end_user_portal(
                $PROVIDERS_FILE,
                $provider,
                $baseUrl,
                $session,
                $issuer . "/portal/sessions/revoke"
            );
        }
        idp_route_require_tx_budget($PROVIDERS_FILE, $provider, $session);
        $txId = tx_create(
            $PROVIDERS_FILE,
            $provider["id"],
            $provider["owner"],
            "portal",
            []
        );
        header(
            "Location: " . $issuer . "/login?tx=" . rawurlencode($txId),
            true,
            302
        );
        exit();
    }

    // "Sign Out Everywhere" on the portal (G2a-06): every SSO session of the user (with all of
    // the owner's providers) ends, the user's OIDC tokens, offline_access grants included, and
    // unredeemed codes are revoked, and this browser's SSO cookies expire
    // (sso_sign_out_everywhere()). A same-origin form POST, checked like the sign-out forms
    // (verify_request_csrf() form mode, S15-02); any session of the user may end them all.
    if ($subPath === "/portal/sessions/revoke" && $method === "POST") {
        verify_request_csrf($origin, true, true);
        $ended = sso_sign_out_everywhere($PROVIDERS_FILE, $provider, $isHttps);
        if ($ended === null) {
            // Without a session the user is unknown, so nothing beyond this browser's cookies
            // could be ended; the page must not claim otherwise.
            render_modern_status_page(
                200,
                "Already Signed Out",
                "Your Single Sign-On session with " .
                    $provider["friendly"] .
                    " had already ended, so sessions in other browsers were not changed. To end them, sign in again and choose Sign Out Everywhere.",
                [
                    "variant" => "info",
                    "link_url" => $issuer . "/portal",
                    "link_label" => "Sign In Again",
                ]
            );
        }
        audit_log_append(
            $PROVIDERS_FILE,
            (string) $provider["id"],
            "portal",
            "sso_logout_everywhere",
            "success",
            "",
            (string) $ended["user"]["username"],
            $ended["amr"]
        );
        render_modern_status_page(
            200,
            "Signed Out Everywhere",
            "You are signed out of " .
                $provider["friendly"] .
                " in every browser: your Single Sign-On sessions ended, and the tokens applications received for your account were revoked. Applications you already signed in to may keep their own sessions until you sign out of them.",
            [
                "variant" => "success",
                "link_url" => $issuer . "/portal",
                "link_label" => "Sign In Again",
            ]
        );
    }

    if ($subPath === "/portal/webauthn/options" && $method === "POST") {
        verify_request_csrf($origin, true);
        $session = sso_get_session($PROVIDERS_FILE, $provider);
        if (!$session || !auth_policy_satisfied(effective_auth_policy($provider), $session["amr"])) {
            json_response(401, ["error" => "Not authenticated"]);
        }
        $hasPasskey = webauthn_count_user_credentials($PROVIDERS_FILE, (string) $session["user"]["id"]) > 0;
        $denied = idp_route_portal_enrollment_denial(
            $session,
            $hasPasskey,
            IDP_ROUTE_PASSKEY_STEP_UP_SECONDS
        );
        if ($denied !== null) {
            json_response(403, idp_route_portal_denial_body($denied, $issuer));
        }
        // G1c-03: at most IDP_ROUTE_PORTAL_PASSKEY_PER_HOUR ceremonies per user and hour start
        // here (each sets one single-use challenge, which bounds /verify). Counted only for a
        // session the rules above allow to enroll, so attempts refused for a missing step-up do
        // not use it up. The passkey cap in webauthn_verify_and_store_registration() stays the
        // hard limit.
        $ceremonyBucket = rate_limit_bucket(
            "portal_passkey",
            (string) $provider["owner"],
            (string) $session["user"]["id"]
        );
        if (rate_limit_hit($PROVIDERS_FILE, $ceremonyBucket, IDP_ROUTE_PORTAL_PASSKEY_PER_HOUR, 3600, 3600)) {
            if (!headers_sent()) {
                header("Retry-After: 3600");
            }
            json_response(429, ["error" => "Too many passkey enrollment attempts; try again later"]);
        }
        try {
            $reg = webauthn_build_registration_options(
                $PROVIDERS_FILE,
                $session["user"],
                $rpId,
                $provider["friendly"]
            );
        } catch (Throwable $e) {
            json_response(400, [
                "error" => idp_route_error_message($e, "Could not start passkey enrollment"),
            ]);
        }
        session_ensure_started();
        $_SESSION["portal_webauthn_reg"] = [
            "provider_id" => $provider["id"],
            "user_id" => $session["user"]["id"],
            // Bound to the SSO session that met the step-up rule above.
            "session_ref" => hash("sha256", (string) $session["id"]),
            "first_passkey" => !$hasPasskey,
            "challenge" => $reg["challenge"],
            "expires_at" => time() + IDP_ROUTE_PASSKEY_CHALLENGE_SECONDS,
        ];
        json_response(200, ["publicKey" => $reg["publicKey"]]);
    }

    if ($subPath === "/portal/webauthn/verify" && $method === "POST") {
        verify_request_csrf($origin, true);
        $session = sso_get_session($PROVIDERS_FILE, $provider);
        $pending = $_SESSION["portal_webauthn_reg"] ?? null;
        unset($_SESSION["portal_webauthn_reg"]);
        if (
            !$session ||
            !is_array($pending) ||
            ($pending["provider_id"] ?? "") !== $provider["id"] ||
            ($pending["user_id"] ?? "") !== $session["user"]["id"] ||
            !hash_equals(
                (string) ($pending["session_ref"] ?? ""),
                hash("sha256", (string) $session["id"])
            ) ||
            (int) ($pending["expires_at"] ?? 0) < time()
        ) {
            json_response(400, ["error" => "Challenge expired"]);
        }
        // Checked again: the rule was met when the ceremony started (at most
        // IDP_ROUTE_PASSKEY_CHALLENGE_SECONDS ago) and nothing relevant may have changed.
        $firstPasskey = !empty($pending["first_passkey"]);
        $hasPasskey = webauthn_count_user_credentials($PROVIDERS_FILE, (string) $session["user"]["id"]) > 0;
        $denied = idp_route_portal_enrollment_denial(
            $session,
            $hasPasskey,
            IDP_ROUTE_PASSKEY_STEP_UP_SECONDS + IDP_ROUTE_PASSKEY_CHALLENGE_SECONDS
        );
        if ($denied !== null) {
            json_response(403, idp_route_portal_denial_body($denied, $issuer));
        }
        $body = read_json_body();
        if (!is_array($body["credential"] ?? null)) {
            json_response(400, ["error" => "Missing passkey registration data"]);
        }
        $credentialPayload = $body["credential"];
        $friendlyName = is_string($body["friendlyName"] ?? null)
            ? $body["friendlyName"]
            : "macOS Touch ID";
        $sessionUser = $session["user"];
        try {
            $cred = storage_write_transaction(
                storage_db($PROVIDERS_FILE),
                function (PDO $pdo) use (
                    $PROVIDERS_FILE,
                    $sessionUser,
                    $pending,
                    $origin,
                    $rpId,
                    $credentialPayload,
                    $friendlyName,
                    $firstPasskey
                ): array {
                    if (
                        $firstPasskey &&
                        webauthn_count_user_credentials($PROVIDERS_FILE, (string) $sessionUser["id"]) > 0
                    ) {
                        throw new RuntimeException(
                            "A passkey was registered for this account in the meantime; sign in with it to add another"
                        );
                    }
                    return webauthn_verify_and_store_registration(
                        $PROVIDERS_FILE,
                        $sessionUser,
                        (string) $pending["challenge"],
                        $origin,
                        $rpId,
                        $credentialPayload,
                        $friendlyName
                    );
                }
            );
        } catch (Throwable $e) {
            json_response(400, [
                "error" => idp_route_error_message($e, "Passkey enrollment failed"),
            ]);
        }
        audit_log_append(
            $PROVIDERS_FILE,
            $provider["id"],
            "webauthn",
            "webauthn_enrolled",
            "success",
            "",
            (string) $sessionUser["username"],
            $session["amr"],
            [
                "via" => "portal",
                "credential_id" => substr((string) ($cred["id"] ?? ""), 0, 64),
                "rp_id" => (string) ($cred["rp_id"] ?? ""),
                "first_passkey" => $firstPasskey,
            ]
        );
        json_response(201, ["credential" => $cred]);
    }

    // ---------- Built-In Interactive SAML & OIDC Test Playground ----------
    if ($subPath === "/test/saml/start" && $method === "GET") {
        if (current_user() !== $provider["owner"]) {
            html_response(
                403,
                "Admin sign-in as provider owner is required to launch SAML Dry-Run"
            );
        }
        $appId = idp_route_query_param("app_id");
        $app = $appId !== "" ? saml_get_app($PROVIDERS_FILE, $provider["id"], $appId) : null;
        if (!$app) {
            html_response(404, "SAML App not found");
        }
        $txId = tx_create(
            $PROVIDERS_FILE,
            $provider["id"],
            $provider["owner"],
            "test_saml",
            [
                "app_id" => $app["id"],
                "app_name" => $app["name"] . " (Built-In SAML Dry-Run)",
                "authn_req" => [
                    "id" => "_testreq_" . bin2hex(random_bytes(8)),
                    "requested_name_id_format" => $app["name_id_format"],
                ],
                "relay_state" => "test-relay-state",
            ]
        );
        header(
            "Location: " . $issuer . "/login?tx=" . rawurlencode($txId),
            true,
            302
        );
        exit();
    }

    if ($subPath === "/test/saml/acs" && $method === "POST") {
        if (current_user() !== $provider["owner"]) {
            html_response(
                403,
                "Admin sign-in as provider owner is required for SAML Dry-Run Inspector"
            );
        }
        $b64 = idp_route_post_param("SAMLResponse");
        $relay = idp_route_post_param("RelayState");

        try {
            if (strlen($relay) > IDP_ROUTE_RELAY_STATE_MAX_BYTES) {
                throw new RuntimeException(
                    "RelayState is too long (at most " .
                        IDP_ROUTE_RELAY_STATE_MAX_BYTES .
                        " bytes)"
                );
            }
            $samlCert = ensure_provider_saml_cert($PROVIDERS_FILE, $provider);
            $xml = base64_decode($b64, true);
            if ($xml === false || $xml === "") {
                throw new RuntimeException("Missing SAMLResponse");
            }
            $doc = saml_load_xml_safely($xml);
            $xp = saml_xpath($doc);

            $checks = [];
            $verifiedAnySignature = false;
            $respSigNode = $xp
                ->query("./ds:Signature", $doc->documentElement)
                ->item(0);
            if ($respSigNode) {
                $okResp = saml_verify_dom_element_signature(
                    $doc->documentElement,
                    $samlCert["cert_pem"]
                );
                $checks["Response XML-DSig (RSA-SHA256)"] = $okResp
                    ? "VALID"
                    : "INVALID";
                if ($okResp) {
                    $verifiedAnySignature = true;
                }
            }

            // Query direct child ./saml:Assertion (prevents XML Signature Wrapping)
            $assertEl = $xp
                ->query("./saml:Assertion", $doc->documentElement)
                ->item(0);
            $extractedAttrs = [];
            $nameIdVal = "";
            if ($assertEl instanceof DOMElement) {
                $aSig = $xp->query("./ds:Signature", $assertEl)->item(0);
                if ($aSig) {
                    $okAsrt = saml_verify_dom_element_signature(
                        $assertEl,
                        $samlCert["cert_pem"]
                    );
                    $checks["Assertion XML-DSig (RSA-SHA256)"] = $okAsrt
                        ? "VALID"
                        : "INVALID";
                    if ($okAsrt) {
                        $verifiedAnySignature = true;
                    }
                }
                $nidNode = $xp->query("./saml:Subject/saml:NameID", $assertEl)->item(0);
                if ($nidNode instanceof DOMElement) {
                    $nameIdVal =
                        $nidNode->textContent .
                        " (" .
                        $nidNode->getAttribute("Format") .
                        ")";
                }
                foreach (
                    $xp->query("./saml:AttributeStatement/saml:Attribute", $assertEl)
                    as $at
                ) {
                    if ($at instanceof DOMElement) {
                        $vals = [];
                        foreach ($xp->query("./saml:AttributeValue", $at) as $v) {
                            $vals[] = $v->textContent;
                        }
                        $extractedAttrs[
                            $at->getAttribute("Name") .
                                " [" .
                                $at->getAttribute("NameFormat") .
                                "]"
                        ] = $vals;
                    }
                }
            } elseif (
                $xp
                    ->query("./saml:EncryptedAssertion", $doc->documentElement)
                    ->item(0)
            ) {
                $checks["EncryptedAssertion"] =
                    "Present (encrypted for SP public key)";
            }

            if (!$verifiedAnySignature) {
                throw new RuntimeException(
                    "Neither SAML Response nor Assertion carried a valid XML-DSig signature"
                );
            }

            $prettyDoc = new DOMDocument("1.0", "UTF-8");
            $prettyDoc->preserveWhiteSpace = false;
            $prettyDoc->formatOutput = true;
            $prettyDoc->loadXML($xml, LIBXML_NONET);

            render_sso_inspector_result(
                "SAML 2.0 Assertion Verified",
                "Cryptographically verified against IdP X.509 certificate (" .
                    $samlCert["kid"] .
                    ")",
                true,
                [
                    [
                        "label" => "Signature & Subject Summary",
                        "content" => json_encode(
                            [
                                "signature_checks" => $checks,
                                "subject_name_id" => $nameIdVal,
                                "relay_state" => $relay,
                            ],
                            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
                        ),
                    ],
                    [
                        "label" => "Extracted SAML AttributeStatement",
                        "content" => json_encode(
                            $extractedAttrs,
                            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
                        ),
                    ],
                    [
                        "label" => "Formatted SAML 2.0 XML Payload",
                        "content" => (string) $prettyDoc->saveXML(),
                    ],
                ],
                $issuer . "/portal"
            );
        } catch (Throwable $e) {
            $shown = idp_route_error_message($e, "The SAML response could not be verified");
            render_sso_inspector_result(
                "SAML Verification Error",
                $shown,
                false,
                [["label" => "Error", "content" => $shown]],
                $issuer . "/portal"
            );
        }
    }

    if ($subPath === "/test/oidc/start" && $method === "GET") {
        // S03-02 / G1d-03: the playground rewrites its public client and shows raw tokens, so
        // only the provider owner may start it (the portal no longer links end users here).
        if (current_user() !== $provider["owner"]) {
            html_response(
                403,
                "Admin sign-in as provider owner is required to launch the OIDC Playground"
            );
        }
        $clientDbId = idp_route_query_param("client_db_id");
        $callbackUri = $issuer . "/test/oidc/callback";
        // A concrete policy (not "inherit"), so the hosted page shows what will be enforced.
        $targetPolicy = effective_auth_policy($provider);
        $targetGroups = [];
        $displayAppName = "Built-In OIDC Playground";

        if ($clientDbId !== "") {
            $selectedClient = oidc_get_client(
                $PROVIDERS_FILE,
                $provider["id"],
                $clientDbId
            );
            if ($selectedClient) {
                // G1e-02: the client's effective policy ("inherit" resolves to the provider default).
                $targetPolicy = effective_auth_policy($provider, $selectedClient);
                $targetGroups = $selectedClient["assigned_groups"] ?? [];
                $displayAppName =
                    $selectedClient["name"] . " (OIDC Playground)";
            }
        }

        // Always execute playground callback via dedicated public PKCE client — never mutate confidential client redirect_uris!
        // It may only use the authorization code grant: no refresh tokens (S03-03).
        $playgroundClientId = "builtin-oidc-playground-" . $provider["idp_id"];
        $playgroundFields = [
            "is_public" => true,
            "require_pkce" => true,
            "redirect_uris" => [$callbackUri],
            "grant_types" => ["authorization_code"],
            "auth_policy" => $targetPolicy,
            "assigned_groups" => $targetGroups,
        ];
        try {
            $client = oidc_find_client_by_client_id(
                $PROVIDERS_FILE,
                $provider["id"],
                $playgroundClientId
            );
            if (!$client) {
                $client = oidc_save_client(
                    $PROVIDERS_FILE,
                    $provider["id"],
                    array_merge(
                        [
                            "name" => "Built-In OIDC Playground",
                            "client_id" => $playgroundClientId,
                        ],
                        $playgroundFields
                    )
                );
            } else {
                $client = oidc_save_client(
                    $PROVIDERS_FILE,
                    $provider["id"],
                    $playgroundFields,
                    $client["id"]
                );
            }
        } catch (InvalidArgumentException $e) {
            // e.g. the callback URL is plain http on a non-loopback host (G1d-04).
            render_modern_status_page(400, "OIDC Playground Unavailable", $e->getMessage(), [
                "variant" => "error",
                "link_url" => $issuer . "/portal",
                "link_label" => "Open App Launchpad",
            ]);
        } catch (Throwable $e) {
            // S03-14: a storage error is reported, not leaked as an uncaught exception.
            error_log(
                "oidc playground: cannot save the playground client of provider " .
                    $provider["id"] .
                    " (" .
                    get_class($e) .
                    ": " .
                    sanitize_label($e->getMessage(), 200) .
                    ")"
            );
            render_modern_status_page(
                500,
                "OIDC Playground Unavailable",
                "The playground client could not be saved. The administrator can find details in the server log.",
                [
                    "variant" => "error",
                    "link_url" => $issuer . "/portal",
                    "link_label" => "Open App Launchpad",
                ]
            );
        }

        $verifier = base64url_encode(random_bytes(32));
        $challenge = base64url_encode(hash("sha256", $verifier, true));
        $state = base64url_encode(random_bytes(16));
        $nonce = base64url_encode(random_bytes(16));

        // S15-08: sessions start on demand; start it before writing the playground state.
        session_ensure_started();
        idp_route_prune_playground_state();
        $_SESSION[idp_route_playground_key((string) $provider["id"], $state)] = [
            "provider_id" => $provider["id"],
            "client_id" => $client["client_id"],
            "code_verifier" => $verifier,
            "redirect_uri" => $callbackUri,
            "nonce" => $nonce,
            "expires_at" => time() + 900,
        ];

        $authReq = [
            "client_id" => $client["client_id"],
            "redirect_uri" => $callbackUri,
            "response_type" => "code",
            "response_mode" => "query",
            "scope" => "openid profile email phone groups",
            "state" => $state,
            "nonce" => $nonce,
            "code_challenge" => $challenge,
            "code_challenge_method" => "S256",
            "prompt" => "login",
            "app_name" => $displayAppName,
        ];
        $txId = tx_create(
            $PROVIDERS_FILE,
            $provider["id"],
            $provider["owner"],
            "test_oidc",
            $authReq
        );
        header(
            "Location: " . $issuer . "/login?tx=" . rawurlencode($txId),
            true,
            302
        );
        exit();
    }

    if ($subPath === "/test/oidc/callback" && $method === "GET") {
        if (current_user() !== $provider["owner"]) {
            html_response(
                403,
                "Admin sign-in as provider owner is required for the OIDC Playground"
            );
        }
        $code = idp_route_query_param("code");
        $state = idp_route_query_param("state");
        $saved = null;
        if ($state !== "") {
            $stateKey = idp_route_playground_key((string) $provider["id"], $state);
            $saved = $_SESSION[$stateKey] ?? null;
            unset($_SESSION[$stateKey]);
        }

        if (
            $code === "" ||
            !is_array($saved) ||
            ($saved["provider_id"] ?? "") !== $provider["id"] ||
            (int) ($saved["expires_at"] ?? 0) < time()
        ) {
            render_sso_inspector_result(
                "OIDC Callback Error",
                "Missing code or expired playground state",
                false,
                [[
                    "label" => "Query",
                    "content" => json_encode(
                        $_GET,
                        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
                    ),
                ]],
                $issuer . "/portal"
            );
        }

        // S03-03: only a code issued to the playground client is matched and consumed, and it
        // is redeemed with the checks of the token endpoint.
        $codeRow = oidc_consume_auth_code_atomic(
            $PROVIDERS_FILE,
            $provider["id"],
            $code,
            (string) $saved["client_id"]
        );
        if (!$codeRow || (int) $codeRow["expires_at"] < time()) {
            render_sso_inspector_result(
                "OIDC Exchange Error",
                "Authorization code invalid or expired",
                false,
                [],
                $issuer . "/portal"
            );
        }
        $computedChallenge = base64url_encode(
            hash("sha256", (string) $saved["code_verifier"], true)
        );
        $client = oidc_find_client_by_client_id(
            $PROVIDERS_FILE,
            $provider["id"],
            (string) $saved["client_id"]
        );
        $user = directory_get_user_by_id(
            $PROVIDERS_FILE,
            (string) $codeRow["user_id"],
            $provider["owner"]
        );
        $problems = [];
        if (!$client) {
            $problems[] = "The playground client no longer exists";
        }
        if ((string) ($codeRow["redirect_uri"] ?? "") !== (string) $saved["redirect_uri"]) {
            $problems[] = "The code was issued for a different redirect_uri";
        }
        if (
            (string) ($codeRow["code_challenge_method"] ?? "") !== "S256" ||
            !hash_equals((string) ($codeRow["code_challenge"] ?? ""), $computedChallenge)
        ) {
            $problems[] = "PKCE (S256) verification failed";
        }
        if (!hash_equals((string) $saved["nonce"], (string) ($codeRow["nonce"] ?? ""))) {
            $problems[] = "The nonce does not match";
        }
        if (!$user || ($user["status"] ?? "active") !== "active") {
            $problems[] = "The user does not exist or is not active";
        }
        if ($problems !== []) {
            render_sso_inspector_result(
                "OIDC Exchange Error",
                "The authorization code was rejected; no tokens were issued",
                false,
                [["label" => "Checks Failed", "content" => implode("\n", $problems)]],
                $issuer . "/portal"
            );
        }
        $amr = json_decode((string) ($codeRow["amr_json"] ?? "[]"), true) ?: [];
        $authTime = (int) $codeRow["auth_time"];
        $sessionRef = (string) ($codeRow["sid"] ?? "");

        try {
            // No refresh token, and the tokens stay bound to the SSO session the code came from.
            $bundle = oidc_mint_token_bundle(
                $PROVIDERS_FILE,
                $providers,
                $provider,
                $baseUrl,
                $client,
                $user,
                (string) $codeRow["scope"],
                (string) ($codeRow["nonce"] ?? ""),
                $amr,
                $authTime,
                false,
                $KEYS_DIR,
                oidc_new_token_family($authTime, $sessionRef !== "" ? $sessionRef : null)
            );
        } catch (Throwable $e) {
            render_sso_inspector_result(
                "OIDC Exchange Error",
                idp_route_error_message($e, "Tokens could not be issued"),
                false,
                [],
                $issuer . "/portal"
            );
        }

        $parts = explode(".", $bundle["id_token"]);
        $idHeader = json_decode(base64url_decode($parts[0] ?? ""), true);
        $idPayload = json_decode(base64url_decode($parts[1] ?? ""), true);
        $userinfoClaims = oidc_build_user_profile_claims(
            $user,
            (string) $codeRow["scope"],
            $client["custom_claims"] ?? []
        );

        render_sso_inspector_result(
            "OIDC 1.0 + PKCE Flow Verified",
            "Authorization Code + S256 PKCE (Verified) completed for " .
                $user["email"],
            true,
            [
                [
                    "label" => "Decoded id_token Payload (Note amr & acr claims)",
                    "content" => json_encode(
                        $idPayload,
                        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
                    ),
                ],
                [
                    "label" => "Decoded id_token Header",
                    "content" => json_encode(
                        $idHeader,
                        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
                    ),
                ],
                [
                    "label" => "/userinfo Endpoint Claims",
                    "content" => json_encode(
                        $userinfoClaims,
                        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
                    ),
                ],
                [
                    "label" => "Raw Token Endpoint Response",
                    "content" => json_encode(
                        $bundle,
                        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
                    ),
                ],
            ],
            $issuer . "/portal"
        );
    }
}

// ---------- Request helpers ----------

/** A query parameter as a trimmed string; "" when absent or not a single value. */
function idp_route_query_param(string $name): string
{
    $value = $_GET[$name] ?? "";
    return is_string($value) ? trim($value) : "";
}

/** A POST form field as sent; "" when absent or not a single value. */
function idp_route_post_param(string $name): string
{
    $value = $_POST[$name] ?? "";
    return is_string($value) ? $value : "";
}

/**
 * Text of $e that is safe to show to a client: the message of domain errors
 * (RuntimeException and InvalidArgumentException, except database errors), else $fallback.
 * Other errors (TypeError, PDOException, ...) can carry file paths or SQL; they are logged.
 */
function idp_route_error_message(Throwable $e, string $fallback): string
{
    if (
        $e instanceof PDOException ||
        !($e instanceof RuntimeException || $e instanceof InvalidArgumentException)
    ) {
        error_log(
            "idp routes: " . get_class($e) . ": " . sanitize_label($e->getMessage(), 300)
        );
        return $fallback;
    }
    return $e->getMessage();
}

/** $value as a positive int (an int, or a string of digits); null otherwise. */
function idp_route_positive_int(mixed $value): ?int
{
    if (is_string($value) && preg_match('/^\d{1,18}$/D', $value) === 1) {
        $value = (int) $value;
    }
    return is_int($value) && $value > 0 ? $value : null;
}

/** Transaction protocols the hosted sign-in page completes. */
function idp_route_is_login_protocol(string $protocol): bool
{
    return in_array($protocol, ["portal", "oidc", "saml", "test_oidc", "test_saml"], true);
}

/**
 * The sign-on policy a hosted sign-in transaction must meet (X1-10): the effective policy of its
 * client or app ("inherit" resolves to the provider default, as for a portal sign-in), raised by
 * the RequestedAuthnContext stored with a SAML request (S02-02). Resolved here with
 * effective_auth_policy() whatever tx_resolve_context() reports, so an unresolved "inherit" can
 * never act as "flexible". Resolving an already effective policy again changes nothing.
 */
function idp_route_tx_auth_policy(array $provider, array $tx, array $ctx): string
{
    $minPolicy = $tx["payload"]["min_auth_policy"] ?? null;
    return effective_auth_policy(
        $provider,
        ["auth_policy" => $ctx["auth_policy"] ?? null],
        is_string($minPolicy) ? $minPolicy : null
    );
}

// ---------- SSO session facts (S06-03) ----------

/**
 * When the user of $session really authenticated (Unix time), or null when that cannot be told:
 * an unreadable authenticated_at, which sso_get_session() reports as "now". Such a session is
 * never reused, so max_age, auth_time and AuthnInstant are never based on a made-up time.
 */
function idp_route_session_auth_time(array $session): ?int
{
    $authTime = $session["auth_time"] ?? null;
    if (array_key_exists("authenticated_at", $session)) {
        $parsed = strtotime((string) $session["authenticated_at"]);
        $authTime = $parsed === false ? null : $parsed;
    }
    return is_int($authTime) && $authTime > 0 ? $authTime : null;
}

/**
 * When $session ends: the expires_at sso_get_session() reports, else its sign-in time plus the
 * lifetime sso_set_session() gives sessions. Null when neither is known. It bounds SAML
 * SessionNotOnOrAfter, so an SP session never outlives the IdP session it came from.
 */
function idp_route_session_expires_at(array $session): ?int
{
    $expiresAt = idp_route_positive_int($session["expires_at"] ?? null);
    if ($expiresAt !== null) {
        return $expiresAt;
    }
    $authTime = idp_route_session_auth_time($session);
    return $authTime !== null ? $authTime + IDP_ROUTE_SSO_SESSION_TTL : null;
}

/**
 * The sign-in a finalize transaction completes, for /login/complete: [auth time, SSO session
 * expiry, SSO session id]. Values the transaction recorded win; missing ones come from this
 * browser's SSO session, which the sign-in has just created, when it belongs to the same user.
 * Each is null when unknown; the token and assertion builders then use the current time.
 */
function idp_route_completed_sign_in(
    string $storePath,
    array $provider,
    array $payload,
    array $user
): array {
    $authTime = idp_route_positive_int($payload["auth_time"] ?? null);
    $expiresAt = idp_route_positive_int($payload["session_expires_at"] ?? null);
    $sessionId =
        is_string($payload["sso_session_id"] ?? null) && $payload["sso_session_id"] !== ""
            ? $payload["sso_session_id"]
            : null;
    if ($authTime === null || $expiresAt === null || $sessionId === null) {
        try {
            $session = sso_get_session($storePath, $provider);
        } catch (Throwable $e) {
            error_log("login complete: SSO session unavailable (" . get_class($e) . ")");
            $session = null;
        }
        if ($session !== null && (string) $session["user"]["id"] === (string) $user["id"]) {
            $authTime ??= idp_route_session_auth_time($session);
            $expiresAt ??= idp_route_session_expires_at($session);
            $sessionId ??= (string) $session["id"];
        }
    }
    return [$authTime, $expiresAt, $sessionId];
}

/**
 * Authorization request parameters that are read and stored in a sign-in transaction must be
 * single values of bounded size (S02-03). Throws InvalidArgumentException.
 */
function idp_route_check_authorize_params(array $params): void
{
    $stored = [
        "client_id",
        "redirect_uri",
        "response_type",
        "response_mode",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
        "prompt",
        "max_age",
    ];
    foreach ($stored as $name) {
        if (!array_key_exists($name, $params)) {
            continue;
        }
        if (!is_string($params[$name])) {
            throw new InvalidArgumentException(
                "Malformed authorization request: the $name parameter must be a single value"
            );
        }
        if (strlen($params[$name]) > IDP_ROUTE_AUTHZ_PARAM_MAX_BYTES) {
            throw new InvalidArgumentException(
                "The $name parameter is too long (at most " .
                    IDP_ROUTE_AUTHZ_PARAM_MAX_BYTES .
                    " bytes)"
            );
        }
    }
}

/**
 * Budget for the sign-in transactions requests create (S12-11, S02-03); renders 429 when it is
 * used up. A request without an SSO session of $provider counts against its client network
 * (client_ip_bucket(): an IPv4 address or an IPv6 /64): signin_network_tx_per_minute requests
 * per minute for this provider, so one tenant's flood leaves the network room for the others,
 * and signin_network_tx_per_minute_all per minute across all providers, so targeting many
 * providers does not multiply it (defaults IDP_ROUTE_TX_BUDGET_PER_NETWORK and
 * IDP_ROUTE_TX_BUDGET_PER_NETWORK_ALL, see idp_route_network_budgets()). A browser with an SSO
 * session ($session; only requests that carry cookies have one) uses signin_user_tx_per_minute
 * per minute for its user instead (default IDP_ROUTE_TX_BUDGET_PER_USER, see
 * idp_route_user_budget()), so signed-in users never share their network's budget; it is kept
 * per user, not per session, because every sign-in creates another session and collecting them
 * must not multiply it. A setting of 0 turns its budget off (S06-04).
 */
function idp_route_require_tx_budget(string $storePath, array $provider, ?array $session = null): void
{
    idp_route_require_request_budget(
        $storePath,
        $provider,
        $session,
        "tx_create",
        "sign-in transaction budget",
        "Too Many Sign-In Requests",
        "sign-in requests"
    );
}

/**
 * Budget for the SAML protocol messages (AuthnRequest, LogoutRequest) requests have this IdP
 * decode and parse (G1c-01): call it before the message is decoded; renders 429 when it is used
 * up. It has the allowances and keying of idp_route_require_tx_budget() (per client network for
 * this provider and across all providers, or per user for a browser with an SSO session),
 * counted apart: a network that stays within its transaction budget stays within this one,
 * unless it also sends messages that create no transaction (refused ones, passive requests,
 * logout requests). Pass $session only for requests that carry the SSO cookie (same-site GETs).
 */
function idp_route_require_saml_message_budget(
    string $storePath,
    array $provider,
    ?array $session = null
): void {
    idp_route_require_request_budget(
        $storePath,
        $provider,
        $session,
        "saml_msg",
        "SAML message budget",
        "Too Many Requests",
        "sign-in and sign-out requests"
    );
}

/**
 * Charges this request to the budgets of kind $purpose (a rate_limit_bucket() purpose; the
 * per-user and cross-provider buckets append "_user" and "_all") that
 * idp_route_require_tx_budget() describes. A used-up budget renders 429 titled $title, with a
 * message about too many $requests; $what names the budget in the proxy hint logged once per
 * lockout of a network budget. A budget whose setting is 0 is neither checked nor counted.
 */
function idp_route_require_request_budget(
    string $storePath,
    array $provider,
    ?array $session,
    string $purpose,
    string $what,
    string $title,
    string $requests
): void {
    $userId = is_array($session["user"] ?? null) ? (string) ($session["user"]["id"] ?? "") : "";
    if ($userId !== "") {
        $budgets = [
            [
                rate_limit_bucket($purpose . "_user", (string) $provider["owner"], $userId),
                idp_route_user_budget(),
                "",
            ],
        ];
    } else {
        [$perProvider, $allProviders] = idp_route_network_budgets();
        if ($perProvider === 0 && $allProviders === 0) {
            return;
        }
        $net = client_ip_bucket();
        $budgets = [
            [
                rate_limit_bucket($purpose, (string) $provider["id"], $net),
                $perProvider,
                $what . " of provider " . $provider["id"],
            ],
            [
                rate_limit_bucket($purpose . "_all", $net),
                $allProviders,
                $what . " across all providers",
            ],
        ];
    }
    foreach ($budgets as [$bucket, $max, $proxyHint]) {
        // 0: this budget is off (rate_limit_hit() would still allow one request per minute).
        if ($max === 0) {
            continue;
        }
        $wasBlocked = rate_limit_is_blocked($storePath, $bucket);
        if (!$wasBlocked && !rate_limit_hit($storePath, $bucket, $max, 60, 60)) {
            continue;
        }
        // Logged once per lockout: when this request used up a network's budget.
        if (!$wasBlocked && $proxyHint !== "") {
            idp_route_log_proxy_hint($proxyHint);
        }
        if (!headers_sent()) {
            header("Retry-After: 60");
        }
        render_modern_status_page(
            429,
            $title,
            $userId !== ""
                ? "Too many " . $requests . " were made for your account in a short time. Wait a minute, then try again."
                : "Too many " . $requests . " came from your network in a short time. Wait a minute, then try again.",
            ["variant" => "error"]
        );
    }
}

/**
 * The client-network allowances of idp_route_require_request_budget() per minute, as
 * [per provider, across all providers] (REGRESSION, S06-04): signin_network_tx_per_minute (env
 * OIDC_SIGNIN_NETWORK_TX_PER_MINUTE, default IDP_ROUTE_TX_BUDGET_PER_NETWORK) and
 * signin_network_tx_per_minute_all (env OIDC_SIGNIN_NETWORK_TX_PER_MINUTE_ALL). While the second
 * is unset (or invalid) it keeps its ratio to the first (IDP_ROUTE_TX_BUDGET_PER_NETWORK_ALL,
 * twice the per-provider one), so raising the first alone is not undone by the cross-provider
 * cap. 0 turns an allowance off; setting only the first to 0 turns off both (the second then
 * defaults to 0), for a deployment that limits these requests in front of PHP. Behind a reverse
 * proxy that trusted_proxies does not list, all clients share one network.
 */
function idp_route_network_budgets(): array
{
    $perProvider = idp_route_limit_setting(
        "signin_network_tx_per_minute",
        "OIDC_SIGNIN_NETWORK_TX_PER_MINUTE",
        IDP_ROUTE_TX_BUDGET_PER_NETWORK
    );
    $allProvidersDefault = intdiv(
        $perProvider * IDP_ROUTE_TX_BUDGET_PER_NETWORK_ALL,
        IDP_ROUTE_TX_BUDGET_PER_NETWORK
    );
    return [
        $perProvider,
        idp_route_limit_setting(
            "signin_network_tx_per_minute_all",
            "OIDC_SIGNIN_NETWORK_TX_PER_MINUTE_ALL",
            $allProvidersDefault
        ),
    ];
}

/**
 * The per-user allowance of idp_route_require_request_budget() per minute, for browsers with an
 * SSO session (S06-04): signin_user_tx_per_minute (env OIDC_SIGNIN_USER_TX_PER_MINUTE), default
 * IDP_ROUTE_TX_BUDGET_PER_USER. 0 turns it off: signed-in users are then not limited, since they
 * never use their network's budget.
 */
function idp_route_user_budget(): int
{
    return idp_route_limit_setting(
        "signin_user_tx_per_minute",
        "OIDC_SIGNIN_USER_TX_PER_MINUTE",
        IDP_ROUTE_TX_BUDGET_PER_USER
    );
}

/**
 * A whole-number limit setting read through config_value(): config.php key $key or environment
 * variable $env, from 0 (the limit is off) up to IDP_ROUTE_LIMIT_SETTING_MAX (larger values are
 * capped to it). Unset gives $default, and so does any other value (negative, fractional, not a
 * number), which is logged once per request.
 */
function idp_route_limit_setting(string $key, string $env, int $default): int
{
    static $logged = [];
    $value = config_value($key, $env);
    if ($value === null) {
        return $default;
    }
    if (is_string($value) && preg_match('/^\d{1,18}$/D', $value) === 1) {
        $value = (int) $value;
    }
    if (!is_int($value) || $value < 0) {
        if (!isset($logged[$key])) {
            $logged[$key] = true;
            error_log(
                "idp routes: " .
                    $key .
                    " (env " .
                    $env .
                    ") is not a whole number of 0 or more; using " .
                    $default
            );
        }
        return $default;
    }
    return min($value, IDP_ROUTE_LIMIT_SETTING_MAX);
}

/**
 * Logs (once per lockout, by the caller) that a per-network limit ran out for a request that
 * arrived with X-Forwarded-For from a private or loopback peer while trusted_proxies does not
 * list that peer: behind such a reverse proxy every client has the proxy's address, so they all
 * share one budget until trusted_proxies (OIDC_TRUSTED_PROXIES) names the proxy.
 */
function idp_route_log_proxy_hint(string $what): void
{
    $peer = trim((string) ($_SERVER["REMOTE_ADDR"] ?? ""));
    $forwarded = $_SERVER["HTTP_X_FORWARDED_FOR"] ?? "";
    if (
        !is_string($forwarded) ||
        trim($forwarded) === "" ||
        $peer === "" ||
        ip_is_public_unicast($peer) ||
        bootstrap_peer_is_trusted_proxy()
    ) {
        return;
    }
    error_log(
        "idp routes: the " .
            $what .
            " ran out for " .
            sanitize_label(client_ip_bucket(), 60) .
            ". Its requests arrive from " .
            sanitize_label($peer, 60) .
            " with X-Forwarded-For: if that is your reverse proxy, list it in trusted_proxies " .
            "(OIDC_TRUSTED_PROXIES); until then every client behind it shares one limit."
    );
}

/**
 * tx_create() for a request whose content another site chose (a SAML AuthnRequest or
 * LogoutRequest, an authorization request): a payload tx_create() refuses, because it is
 * larger than TX_PAYLOAD_MAX_BYTES or cannot be stored, is answered with a 400 page instead
 * of an uncaught 500 (S02-03).
 */
function idp_route_tx_create_or_400(
    string $storePath,
    array $provider,
    string $issuer,
    string $protocol,
    array $payload,
    array $stepState = [],
    int $ttlSeconds = 900
): string {
    try {
        return tx_create(
            $storePath,
            (string) $provider["id"],
            (string) $provider["owner"],
            $protocol,
            $payload,
            $stepState,
            $ttlSeconds
        );
    } catch (InvalidArgumentException $e) {
        render_modern_status_page(
            400,
            "Request Not Accepted",
            $e->getMessage() . ". Start again from the application.",
            [
                "variant" => "error",
                "link_url" => $issuer . "/portal",
                "link_label" => "Open App Launchpad",
            ]
        );
    }
}

/**
 * Audit row for a failure anyone can cause without authenticating (S02-13): written in the
 * 'untrusted' class, which never evicts security rows, and throttled to 30 rows per client IP
 * and provider per 5 minutes so one client cannot churn even that class. Request values belong
 * in $username or $details, never in $appName.
 */
function idp_route_audit_untrusted(
    string $storePath,
    array $provider,
    string $protocol,
    string $eventType,
    string $appName = "",
    string $username = "",
    array $details = []
): void {
    $bucket = rate_limit_bucket("audit_noise", (string) $provider["id"], client_ip_bucket());
    if (rate_limit_hit($storePath, $bucket, 30, 300, 300)) {
        return;
    }
    $details["client_ip"] = client_ip_address();
    audit_log_append(
        $storePath,
        (string) $provider["id"],
        $protocol,
        $eventType,
        "error",
        $appName,
        $username,
        [],
        $details,
        true
    );
}

/**
 * Backstop at /login/complete: the finished sign-in ($amr) must meet the effective sign-on
 * policy of the OIDC client or SAML app ($target; "inherit" resolves to the provider default),
 * whatever the hosted page offered for the transaction. Otherwise the attempt is audited and
 * refused with a 403 page.
 */
function idp_route_require_policy_met(
    string $storePath,
    array $provider,
    string $issuer,
    array $target,
    array $user,
    array $amr
): void {
    $policy = effective_auth_policy($provider, $target);
    if (auth_policy_satisfied($policy, $amr)) {
        return;
    }
    audit_log_append(
        $storePath,
        (string) $provider["id"],
        isset($target["client_id"]) ? "oidc" : "saml",
        "access_denied_policy",
        "error",
        (string) ($target["name"] ?? ""),
        (string) ($user["username"] ?? ""),
        $amr,
        ["required_policy" => $policy]
    );
    $how = match ($policy) {
        "mfa" => "your password and a passkey (Touch ID)",
        "touchid_only" => "a passkey (Touch ID)",
        default => "a password or a passkey",
    };
    render_modern_status_page(
        403,
        "Stronger Sign-In Required",
        (string) ($target["name"] ?? "This application") .
            " requires signing in with " .
            $how .
            ". Start the sign-in again from the application.",
        [
            "variant" => "error",
            "link_url" => $issuer . "/portal",
            "link_label" => "Open App Launchpad",
        ]
    );
}

function idp_route_tx_expired_page(string $issuer): never
{
    render_modern_status_page(
        400,
        "Sign-In Session Expired",
        "This authentication transaction has expired or was already completed.",
        [
            "variant" => "info",
            "link_url" => $issuer . "/portal",
            "link_label" => "Continue to App Launchpad",
        ]
    );
}

/**
 * Ends this browser's SSO session with $provider: the OIDC tokens and codes bound to it are
 * revoked first (X3-08; offline_access grants are kept), then the session row is deleted and
 * the cookie expired. With $protocol, an sso_logout audit row is written for the session's
 * user. Returns the session that ended, or null when there was none.
 */
function idp_route_end_sso_session(
    string $storePath,
    array $provider,
    bool $isHttps,
    string $protocol = "",
    string $appName = "",
    array $details = []
): ?array {
    $session = sso_get_session($storePath, $provider);
    $cookie = $_COOKIE[sso_cookie_name((string) $provider["id"])] ?? "";
    $sid = $session !== null
        ? (string) $session["id"]
        : (is_string($cookie) ? trim($cookie) : "");
    if ($sid !== "") {
        oidc_revoke_tokens_for_session($storePath, (string) $provider["id"], $sid);
    }
    sso_destroy_session($storePath, $provider, $isHttps);
    if ($session !== null && $protocol !== "") {
        audit_log_append(
            $storePath,
            (string) $provider["id"],
            $protocol,
            "sso_logout",
            "success",
            $appName,
            (string) $session["user"]["username"],
            $session["amr"],
            $details
        );
    }
    return $session;
}

/**
 * CSRF check for the sign-out form POSTs of /saml/slo and /oauth2/logout (S15-02, S02-06), in
 * verify_request_csrf()'s form mode: a same-origin Origin (or, without Origin, Referer) is
 * enough on its own, so a form whose PHP session, and with it the token, expired since it was
 * rendered still works, and so is "Origin: null" with "Sec-Fetch-Site: same-origin". The
 * session's CSRF token (hidden csrf_token field or X-CSRF-Token) is required for any other
 * "Origin: null" and when the browser sent neither Origin nor Referer; another origin is
 * refused. It runs only for POSTs idp_route_is_own_logout_post() accepts. Every other POST, such
 * as an RP's logout form or a confirmation whose token is no longer this session's, is answered
 * with a redirect to a same-site GET instead, which asks again with a fresh token (S03-11).
 */
function idp_route_verify_logout_csrf(string $origin): void
{
    $sourceSent =
        trim((string) ($_SERVER["HTTP_ORIGIN"] ?? "")) !== "" ||
        trim((string) ($_SERVER["HTTP_REFERER"] ?? "")) !== "";
    verify_request_csrf($origin, !$sourceSent, true);
}

// ---------- Cross-site POST continuation ----------
//
// A top-level POST from another site (SAML HTTP-POST binding, POST /oauth2/authorize, an RP's
// logout form) carries no SameSite=Lax cookie, so tx_create() would not see the browser's
// transaction-binding cookie and would mint and set a new one, replacing the cookie every other
// sign-in in progress in that browser is bound to. Such requests are stored in a transaction
// bound to a one-time handoff secret instead, which travels only in the 303 Location they are
// answered with; the same-site GET that follows (it carries the cookies) redeems it.
//
// A handoff secret has the form of a binding cookie value, so handoff transactions carry a
// protocol of their own (IDP_ROUTE_HANDOFF_PROTOCOL_PREFIX + the request's protocol): only they
// are redeemed, and no sign-in step accepts them. A sign-in bound to a browser's own cookie can
// therefore never be redeemed by someone who knows that cookie, and a handoff never carries
// sign-in progress into the browser that opens its link (S14-03).

/**
 * tx_create() for a request that arrived by cross-site POST: the transaction is bound to a new
 * handoff secret, no cookie is set, and its protocol is $protocol marked as a handoff (no step
 * state). Returns [transaction id, handoff secret]; redeem it with idp_route_tx_redeem_handoff().
 * A payload that cannot be stored gets the 400 page of idp_route_tx_create_or_400().
 */
function idp_route_tx_create_handoff(
    string $storePath,
    array $provider,
    string $issuer,
    string $protocol,
    array $payload
): array {
    $handoff = base64url_encode(random_bytes(32));
    $txId = idp_route_with_tx_binding(
        $handoff,
        fn(): string => idp_route_tx_create_or_400(
            $storePath,
            $provider,
            $issuer,
            IDP_ROUTE_HANDOFF_PROTOCOL_PREFIX . $protocol,
            $payload
        )
    );
    return [$txId, $handoff];
}

/**
 * Runs $fn as if this browser's transaction-binding cookie were $value (a well-formed binding
 * value, so tx_create() binds to it without sending a cookie, and tx_load() and
 * tx_consume_atomic() find what is bound to it), then restores the real cookie.
 */
function idp_route_with_tx_binding(string $value, callable $fn): mixed
{
    $name = tx_binding_cookie_name();
    $had = array_key_exists($name, $_COOKIE);
    $saved = $_COOKIE[$name] ?? null;
    $_COOKIE[$name] = $value;
    try {
        return $fn();
    } finally {
        if ($had) {
            $_COOKIE[$name] = $saved;
        } else {
            unset($_COOKIE[$name]);
        }
    }
}

/**
 * Redeems a handoff transaction of $provider for a request whose protocol is one of $protocols,
 * atomically, so it is used once. Only a transaction idp_route_tx_create_handoff() made
 * qualifies; any other transaction bound to the same value (a browser's own sign-in, when
 * $handoff is that browser's binding cookie) is left untouched. Returns the transaction with the
 * request's protocol and an empty step state (a handoff carries a request, never sign-in
 * progress), or null when the secret is malformed or the transaction is unknown, expired,
 * already used, not a handoff or of another kind.
 */
function idp_route_tx_redeem_handoff(
    string $storePath,
    array $provider,
    string $txId,
    string $handoff,
    array $protocols
): ?array {
    if ($txId === "" || preg_match('/^[A-Za-z0-9_-]{43}$/D', $handoff) !== 1) {
        return null;
    }
    $marked = array_map(
        static fn(string $protocol): string => IDP_ROUTE_HANDOFF_PROTOCOL_PREFIX . $protocol,
        $protocols
    );
    $isHandoff = static fn(?array $tx): bool => is_array($tx) &&
        $tx["provider_id"] === $provider["id"] &&
        in_array($tx["protocol"], $marked, true);
    // Checked before the claim, so nothing else is consumed; the protocol never changes, and
    // the claim itself decides which of concurrent requests redeems it.
    $tx = idp_route_with_tx_binding(
        $handoff,
        static fn(): ?array => $isHandoff(tx_load($storePath, $txId))
            ? tx_consume_atomic($storePath, $txId)
            : null
    );
    if (!$isHandoff($tx)) {
        return null;
    }
    $tx["protocol"] = substr((string) $tx["protocol"], strlen(IDP_ROUTE_HANDOFF_PROTOCOL_PREFIX));
    $tx["step_state"] = [];
    return $tx;
}

/**
 * Answers a cross-site POST with a 303 to $urlPrefix (ending in "tx=", "slo_tx=" or
 * "logout_tx=") followed by the handoff transaction id and secret ($handoff from
 * idp_route_tx_create_handoff()).
 */
function idp_route_redirect_to_handoff(string $urlPrefix, array $handoff): never
{
    [$txId, $secret] = $handoff;
    header(
        "Location: " . $urlPrefix . rawurlencode($txId) . "&handoff=" . rawurlencode($secret),
        true,
        303
    );
    exit();
}

// ---------- Atomic sign-in transaction steps (G1c-05) ----------

/**
 * Replaces the step state of transaction $tx (as loaded by this request) with $newStep, but only
 * while the stored step state is still the one $tx holds: a compare-and-swap in one write
 * transaction, so of concurrent requests that loaded the same state only one succeeds, and a
 * single-use value (a challenge) is redeemed once. Returns $tx with the new step state, or null
 * when another request changed, completed or removed the transaction first.
 */
function idp_route_tx_swap_step(string $storePath, array $tx, array $newStep): ?array
{
    $newJson = json_encode($newStep, JSON_UNESCAPED_SLASHES);
    if (!is_string($newJson)) {
        return null;
    }
    $expected = is_array($tx["step_state"] ?? null) ? $tx["step_state"] : [];
    try {
        $swapped = storage_write_transaction(
            storage_db($storePath),
            function (PDO $pdo) use ($tx, $expected, $newJson): bool {
                $sel = $pdo->prepare(
                    "SELECT step_state_json FROM auth_transactions WHERE id = :id AND expires_at > :now LIMIT 1"
                );
                storage_execute($sel, [":id" => (string) $tx["id"], ":now" => time()]);
                $raw = $sel->fetchColumn();
                $sel->closeCursor();
                if (!is_string($raw)) {
                    return false;
                }
                // Decoded as tx_load() does, so an unchanged row compares equal.
                $current = json_decode($raw, true) ?: [];
                if ($current !== $expected) {
                    return false;
                }
                $upd = $pdo->prepare(
                    "UPDATE auth_transactions SET step_state_json = :new WHERE id = :id AND step_state_json = :old"
                );
                storage_execute($upd, [":new" => $newJson, ":id" => (string) $tx["id"], ":old" => $raw]);
                return $upd->rowCount() === 1;
            }
        );
    } catch (Throwable $e) {
        error_log("login: transaction step not updated (" . get_class($e) . ")");
        return null;
    }
    if (!$swapped) {
        return null;
    }
    $tx["step_state"] = $newStep;
    return $tx;
}

/** The answer when another request changed a sign-in transaction first (G1c-05). */
function idp_route_tx_changed_response(): never
{
    json_response(409, [
        "error" => "This sign-in changed in another window or tab; reload the page and try again",
    ]);
}

/**
 * auth_complete_transaction() for a sign-in this request has verified, after claiming the
 * transaction atomically (G1c-05): tx_consume_atomic() removes it for exactly one request, so
 * the SSO session and the completion (fin) transaction are created once, whatever else races.
 * A claim that fails (completed, expired or removed meanwhile) is answered with 400. All callers
 * of auth_complete_transaction() are in this file and go through here. Its own tx_delete() of
 * the claimed row is then a no-op. Should it claim the transaction itself (G1c-05), it must take
 * the optional $txClaimed parameter requested from auth_flow.php, and is told here that the
 * claim was made; once that is merged, call it directly with txClaimed: true.
 * The checks auth_complete_transaction() makes before it creates a session run before the claim
 * too (idp_route_require_sign_in_allowed()): a refused sign-in (an account that is no longer
 * active, a user outside the app's assigned groups) throws as before and leaves the transaction
 * in place, so another account can still sign in with it. They run again after the claim.
 */
function idp_route_complete_transaction(
    string $storePath,
    array &$providers,
    array &$provider,
    string $baseUrl,
    bool $isHttps,
    array $tx,
    array $user,
    array $amr,
    string $keysDir
): array {
    idp_route_require_sign_in_allowed($storePath, $provider, $tx, $user, $amr);
    $claimed = tx_consume_atomic($storePath, (string) $tx["id"]);
    if ($claimed === null || $claimed["provider_id"] !== $provider["id"]) {
        json_response(400, ["error" => "Login session expired; please reload"]);
    }
    if (idp_route_function_has_param("auth_complete_transaction", "txClaimed")) {
        return auth_complete_transaction(
            $storePath,
            $providers,
            $provider,
            $baseUrl,
            $isHttps,
            $claimed,
            $user,
            $amr,
            $keysDir,
            txClaimed: true
        );
    }
    return auth_complete_transaction(
        $storePath,
        $providers,
        $provider,
        $baseUrl,
        $isHttps,
        $claimed,
        $user,
        $amr,
        $keysDir
    );
}

/**
 * The checks auth_complete_transaction() makes before it creates a session for $user in $tx
 * (S06-11), with the same audit row and exception, for idp_route_complete_transaction() to run
 * before it claims the transaction: throws a RuntimeException when the account no longer exists
 * or is not active, or when it is not a member of the groups assigned to the application.
 */
function idp_route_require_sign_in_allowed(
    string $storePath,
    array $provider,
    array $tx,
    array $user,
    array $amr
): void {
    $current = directory_get_user_by_id(
        $storePath,
        (string) ($user["id"] ?? ""),
        (string) $provider["owner"]
    );
    if (!$current || ($current["status"] ?? "") !== "active") {
        throw new RuntimeException("This account is not active");
    }
    $ctx = tx_resolve_context($storePath, $provider, $tx);
    $groups = is_array($ctx["assigned_groups"] ?? null) ? $ctx["assigned_groups"] : [];
    if (directory_user_matches_assigned_groups($current, $groups)) {
        return;
    }
    audit_log_append(
        $storePath,
        (string) $provider["id"],
        (string) $tx["protocol"],
        "access_denied_group",
        "error",
        (string) $ctx["app_name"],
        (string) $current["username"],
        $amr,
        ["required_groups" => $groups]
    );
    throw new RuntimeException(
        "Access denied: user '" .
            $current["username"] .
            "' is not a member of the groups assigned to " .
            $ctx["app_name"]
    );
}

/**
 * True when function $function declares a parameter named $param. Used to pass an optional
 * argument that another file adds in a later change only once it exists. Pending requests:
 * auth_complete_transaction(txClaimed) in auth_flow.php and saml_build_signed_response(
 * sessionIndex) in saml.php; when they are merged, replace each check with a direct call and
 * remove this function.
 */
function idp_route_function_has_param(string $function, string $param): bool
{
    static $cache = [];
    $key = $function . "\0" . $param;
    if (!array_key_exists($key, $cache)) {
        $cache[$key] = false;
        if (function_exists($function)) {
            foreach ((new ReflectionFunction($function))->getParameters() as $parameter) {
                if ($parameter->getName() === $param) {
                    $cache[$key] = true;
                    break;
                }
            }
        }
    }
    return $cache[$key];
}

// ---------- Sign-in throttling (S06-04, S05-07) ----------

/**
 * The client network password throttling counts per (S06-04): the IPv4 address, or the IPv6 /48.
 * client_ip_bucket() keeps an IPv6 /64, but one site, or one free tunnel-broker allocation, holds
 * 65,536 of those, and each would get the per-network allowances of idp_route_password_guard().
 */
function idp_route_pw_network(): string
{
    $bucket = client_ip_bucket();
    return str_starts_with($bucket, "v6:") ? "v6/48:" . substr($bucket, 3, 12) : $bucket;
}

/**
 * Password failures one client network may have across the owner's accounts within 5 minutes
 * before idp_route_password_guard() refuses it password sign-in for 5 minutes (REGRESSION,
 * S06-04): signin_network_password_failures (env OIDC_SIGNIN_NETWORK_PASSWORD_FAILURES), default
 * IDP_ROUTE_PW_NET_MAX_FAILURES; 0 turns this network budget off (the per-account limits stay).
 * Behind a reverse proxy that trusted_proxies does not list, all clients share one network.
 */
function idp_route_pw_net_max_failures(): int
{
    return idp_route_limit_setting(
        "signin_network_password_failures",
        "OIDC_SIGNIN_NETWORK_PASSWORD_FAILURES",
        IDP_ROUTE_PW_NET_MAX_FAILURES
    );
}

/**
 * Throttles one password attempt for account $acct ("uid:<id>", or "ident:<identifier>" when no
 * user matches) and reserves it before the password is checked. Renders 429 and exits when the
 * attempt must be refused; otherwise returns the state idp_route_password_attempt_done() settles.
 * All buckets belong to the owner, whose directory every one of its providers checks; a client
 * network is an IPv4 address or an IPv6 /48 (idp_route_pw_network()).
 *
 * - A known device of the account ($deviceId from idp_route_known_device(): this browser
 *   completed a sign-in to it with its current password) has IDP_ROUTE_PW_DEVICE_MAX attempts
 *   per 5 minutes of its own, and all known devices of the account together have
 *   IDP_ROUTE_PW_DEVICES_MAX per 15 minutes since its last successful sign-in. Within those it is
 *   not subject to the limits below, so lockouts that others cause never reach it. Once the
 *   shared allowance is used up (someone holding several of its cookies is guessing), known
 *   devices are checked like any other browser until it passes or a sign-in succeeds. Their
 *   failures count toward the account and network failures below.
 * - Any other browser has IDP_ROUTE_PW_ACCT_NET_MAX attempts per account and client network per
 *   5 minutes: the lock stays on the network that caused it.
 * - When the account collected IDP_ROUTE_PW_ACCT_ALERT_FAILURES failures within 15 minutes
 *   (guessing spread over many networks), every network also gets only IDP_ROUTE_PW_STRICT_MAX
 *   attempts for it per 15 minutes until that passes. A client without failures still gets its
 *   attempts.
 * - After IDP_ROUTE_PW_ACCT_MAX_FAILURES failures within an hour from browsers checked by these
 *   rules, all of them are refused password sign-in to the account for an hour: a ceiling that
 *   no number of networks lifts. Known devices and passkeys keep working; only a new browser
 *   without a passkey has to wait.
 * - A network with signin_network_password_failures failures across the owner's accounts within
 *   5 minutes (password spraying) is refused for such browsers for 5 minutes (default
 *   IDP_ROUTE_PW_NET_MAX_FAILURES, see idp_route_pw_net_max_failures()); 0 turns this budget off.
 * Every limit that refuses attempts is checked and counted in one atomic step before bcrypt
 * runs, so concurrent requests cannot overshoot it (S06-04): the per-device, account+network and
 * strict allowances are reserved and released by a success; the ceiling and the network budget,
 * which count failures, hold the attempt until it is settled and give it back when it succeeds
 * or the network budget refuses it. Counted only after a failure: the 15-minute account count
 * that starts the strict allowance, and the network budget for a known device (which it does
 * not hold back). Passkey sign-in is never affected.
 */
function idp_route_password_guard(
    string $storePath,
    array $provider,
    string $acct,
    ?string $deviceId
): array {
    $owner = (string) $provider["owner"];
    $net = idp_route_pw_network();
    $netBucket = rate_limit_bucket("sso_pw_net", $owner, $net);
    // 0: the network budget is off, so it is neither checked, held nor counted.
    $netMax = idp_route_pw_net_max_failures();
    $netFailures = $netMax > 0 ? [[$netBucket, $netMax, 300, 300]] : [];
    $acctBucket = rate_limit_bucket("sso_pw_acct", $owner, $acct);
    $alert = [$acctBucket, IDP_ROUTE_PW_ACCT_ALERT_FAILURES, 900, 900];
    $reserved = [];
    if ($deviceId !== null) {
        $reserved[] = rate_limit_bucket("sso_pw_dev", $owner, $acct, $deviceId);
        if (rate_limit_hit($storePath, $reserved[0], IDP_ROUTE_PW_DEVICE_MAX, 300, 300)) {
            idp_route_password_throttled(300);
        }
        // Reserved like the rest, so a successful sign-in also releases it.
        $reserved[] = rate_limit_bucket("sso_pw_devices", $owner, $acct);
        if (!rate_limit_hit($storePath, $reserved[1], IDP_ROUTE_PW_DEVICES_MAX, 900, 900)) {
            // Not held to the network budget, but a failure still counts toward it.
            return [
                "reserved" => $reserved,
                "held" => [],
                "since" => time(),
                "failures" => array_merge($netFailures, [$alert]),
            ];
        }
    }
    $ceilingBucket = rate_limit_bucket("sso_pw_acct_ceiling", $owner, $acct);
    $ceilingMessage = "Too many failed sign-in attempts for this account. Sign in with a passkey or on a device you signed in with before, or try again in an hour.";
    // Read-only checks first: while a lock holds, refused attempts write nothing.
    if ($netMax > 0 && rate_limit_is_blocked($storePath, $netBucket)) {
        idp_route_password_throttled(300);
    }
    if (rate_limit_is_blocked($storePath, $ceilingBucket)) {
        idp_route_password_throttled(3600, $ceilingMessage);
    }
    $acctNetBucket = rate_limit_bucket("sso_pw_acct_net", $owner, $acct, $net);
    $reserved[] = $acctNetBucket;
    if (rate_limit_hit($storePath, $acctNetBucket, IDP_ROUTE_PW_ACCT_NET_MAX, 300, 300)) {
        idp_route_password_throttled(300);
    }
    if (rate_limit_is_blocked($storePath, $acctBucket)) {
        $strictBucket = rate_limit_bucket("sso_pw_acct_strict", $owner, $acct, $net);
        $reserved[] = $strictBucket;
        if (rate_limit_hit($storePath, $strictBucket, IDP_ROUTE_PW_STRICT_MAX, 900, 900)) {
            idp_route_password_throttled(900);
        }
    }
    $since = time();
    if (rate_limit_hit($storePath, $ceilingBucket, IDP_ROUTE_PW_ACCT_MAX_FAILURES, 3600, 3600)) {
        if (!idp_route_rate_limit_locked($storePath, $ceilingBucket)) {
            // Not locked: the limiter could not count the attempt (it then refuses).
            idp_route_password_throttled(300);
        }
        // The typed identifier is never logged: it may be a password typed in the wrong field.
        error_log(
            "login: " .
                IDP_ROUTE_PW_ACCT_MAX_FAILURES .
                " failed password sign-ins within an hour for " .
                (str_starts_with($acct, "uid:")
                    ? "user " . sanitize_label(substr($acct, 4), 80)
                    : "an unknown identifier") .
                " of owner " .
                sanitize_label($owner, 120) .
                ": password sign-in from browsers that are not known devices of the account is refused for an hour"
        );
        idp_route_password_throttled(3600, $ceilingMessage);
    }
    if ($netMax > 0 && rate_limit_hit($storePath, $netBucket, $netMax, 300, 300)) {
        idp_route_rate_limit_release($storePath, [$ceilingBucket], $since);
        if (idp_route_rate_limit_locked($storePath, $netBucket)) {
            idp_route_log_proxy_hint("password failure budget");
        }
        idp_route_password_throttled(300);
    }
    return [
        "reserved" => $reserved,
        "held" => $netMax > 0 ? [$ceilingBucket, $netBucket] : [$ceilingBucket],
        "since" => $since,
        "failures" => [$alert],
    ];
}

/**
 * Settles a password attempt guarded by idp_route_password_guard(): a success releases the
 * attempts reserved for it and gives back the ones the ceiling and the network budget held; a
 * failure leaves those counted and counts toward the account's alert threshold (and, for a known
 * device, which the network budget did not hold, against the network). Counting is best effort;
 * a busy database never turns the answer into a 500.
 */
function idp_route_password_attempt_done(string $storePath, array $guard, bool $succeeded): void
{
    try {
        if ($succeeded) {
            foreach ($guard["reserved"] as $bucket) {
                rate_limit_clear($storePath, $bucket);
            }
            idp_route_rate_limit_release($storePath, $guard["held"], (int) $guard["since"]);
            return;
        }
        foreach ($guard["failures"] as [$bucket, $max, $window, $lock]) {
            rate_limit_record_failure($storePath, $bucket, $max, $window, $lock);
        }
    } catch (Throwable $e) {
        error_log("login: password attempt not counted (" . get_class($e) . ")");
    }
}

/**
 * Gives back one attempt reserved with rate_limit_hit() at time $since in each of $buckets, for
 * an attempt that must not count as a failure (S06-04): it succeeded, or a later limit refused
 * it before the password was checked. A count never drops below zero, a lock already set stays,
 * and a window that started after $since (a new count) is left alone. Best effort.
 */
function idp_route_rate_limit_release(string $storePath, array $buckets, int $since): void
{
    $keys = array_values(array_unique(array_map(
        static fn(string $bucket): string => rate_limit_storage_key($bucket),
        $buckets
    )));
    if ($keys === []) {
        return;
    }
    try {
        storage_execute(
            storage_db($storePath)->prepare(
                "UPDATE auth_rate_limits SET failures = failures - 1 " .
                    "WHERE failures > 0 AND window_started_at <= ? AND bucket IN (" .
                    implode(", ", array_fill(0, count($keys), "?")) .
                    ")"
            ),
            array_merge([$since], $keys)
        );
    } catch (Throwable $e) {
        error_log("login: password attempt not released (" . get_class($e) . ")");
    }
}

/** rate_limit_is_blocked() for log messages: false when the limiter cannot be read. */
function idp_route_rate_limit_locked(string $storePath, string $bucket): bool
{
    try {
        return rate_limit_is_blocked($storePath, $bucket);
    } catch (Throwable $e) {
        return false;
    }
}

/** The 429 answer of a throttled password attempt. */
function idp_route_password_throttled(int $retryAfterSeconds, string $message = ""): never
{
    if (!headers_sent()) {
        header("Retry-After: " . $retryAfterSeconds);
    }
    json_response(429, [
        "error" => $message !== ""
            ? $message
            : "Too many failed sign-in attempts. Please wait a few minutes, or sign in with a passkey.",
    ]);
}

/**
 * Answers a failed passkey assertion (S05-07): 429 while this network is locked out, otherwise
 * the failure is counted (20 per 5 minutes per provider and network lock it for 5 minutes) and
 * the answer is 401. The lock is consulted only here, after a failure, so a valid passkey always
 * signs in, also from a shared network where others failed.
 */
function idp_route_webauthn_failure(string $storePath, array $provider): never
{
    $bucket = rate_limit_bucket("webauthn_login", (string) $provider["id"], client_ip_bucket());
    if (rate_limit_is_blocked($storePath, $bucket)) {
        if (!headers_sent()) {
            header("Retry-After: 300");
        }
        json_response(429, [
            "error" => "Too many failed passkey attempts. Please wait a few minutes.",
        ]);
    }
    try {
        rate_limit_record_failure($storePath, $bucket, 20, 300, 300);
    } catch (Throwable $e) {
        error_log("login: passkey failure not counted (" . get_class($e) . ")");
    }
    json_response(401, ["error" => "Passkey sign-in failed"]);
}

/**
 * Key of the known-device cookies: an HMAC subkey of the vault master key. Null when that key is
 * unavailable (the vault logs why); sign-in then works without known devices.
 */
function idp_route_known_device_key(string $storePath): ?string
{
    static $keys = [];
    if (!array_key_exists($storePath, $keys)) {
        try {
            $keys[$storePath] = hash_hmac(
                "sha256",
                "login known-device cookie v1",
                vault_master_key($storePath),
                true
            );
        } catch (Throwable $e) {
            $keys[$storePath] = null;
        }
    }
    return $keys[$storePath];
}

/** Name of the known-device cookie for $user: one per account, so a shared browser keeps each. */
function idp_route_known_device_cookie_name(array $provider, array $user, bool $isHttps): string
{
    return ($isHttps ? "__Host-" : "") .
        "idp_kd_" .
        substr(hash("sha256", (string) $provider["owner"] . "\0" . (string) $user["id"]), 0, 16);
}

/**
 * MAC (base64url) of a known-device cookie for $user, issued at $issuedAt for $deviceId. It also
 * covers a digest of the user's stored password hash ($user["_password_hash"], as the directory
 * lookups return it), so changing or resetting the password invalidates every known-device
 * cookie of the account (S06-04). An automatic rehash on sign-in (S06-07) does so too, once.
 */
function idp_route_known_device_mac(
    string $key,
    array $provider,
    array $user,
    int $issuedAt,
    string $deviceId
): string {
    $passwordHash = $user["_password_hash"] ?? "";
    return base64url_encode(
        hash_hmac(
            "sha256",
            implode("|", [
                "v1",
                (string) $provider["owner"],
                (string) $user["id"],
                (string) $issuedAt,
                $deviceId,
                hash("sha256", is_string($passwordHash) ? $passwordHash : ""),
            ]),
            $key,
            true
        )
    );
}

/**
 * The device id of this browser's known-device cookie for $user (S06-04), or null when it has no
 * valid one: set by idp_route_remember_device() after a completed sign-in to that account, it
 * carries a random device id, its issue time and an HMAC bound to the account's current
 * password, and is valid for IDP_ROUTE_KNOWN_DEVICE_TTL seconds. $user must come from a directory
 * lookup (it needs "_password_hash"). It only relaxes password throttling
 * (idp_route_password_guard()); it is never an authentication factor.
 */
function idp_route_known_device(
    string $storePath,
    array $provider,
    array $user,
    bool $isHttps
): ?string {
    $raw = $_COOKIE[idp_route_known_device_cookie_name($provider, $user, $isHttps)] ?? null;
    if (
        !is_string($raw) ||
        preg_match('/^v1\.(\d{1,12})\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/D', $raw, $m) !== 1
    ) {
        return null;
    }
    $key = idp_route_known_device_key($storePath);
    $issuedAt = (int) $m[1];
    $age = time() - $issuedAt;
    if ($key === null || $age < -60 || $age > IDP_ROUTE_KNOWN_DEVICE_TTL) {
        return null;
    }
    return hash_equals(
        idp_route_known_device_mac($key, $provider, $user, $issuedAt, $m[2]),
        $m[3]
    )
        ? $m[2]
        : null;
}

/**
 * Marks this browser as a known device of $user (S06-04). Call it only for a completed sign-in,
 * once idp_route_complete_transaction() created the SSO session, never after a first factor
 * alone. Keeps the browser's device id: $deviceId when the caller checked the cookie before the
 * password was verified (a rehash may have changed the stored hash since), else from its current
 * cookie. The HttpOnly, SameSite=Strict cookie is renewed on every sign-in and bound to the
 * account's password as stored now; a browser keeps such cookies for at most
 * IDP_ROUTE_KNOWN_DEVICES_PER_BROWSER accounts (idp_route_prune_known_devices()). Best effort:
 * sends nothing when the key or the account is unavailable or output has started.
 */
function idp_route_remember_device(
    string $storePath,
    array $provider,
    array $user,
    bool $isHttps,
    ?string $deviceId = null
): void {
    $key = idp_route_known_device_key($storePath);
    if ($key === null || headers_sent()) {
        return;
    }
    try {
        $current = directory_get_user_by_id(
            $storePath,
            (string) ($user["id"] ?? ""),
            (string) $provider["owner"]
        );
    } catch (Throwable $e) {
        error_log("login: known device not recorded (" . get_class($e) . ")");
        return;
    }
    if ($current === null) {
        return;
    }
    $deviceId ??= idp_route_known_device($storePath, $provider, $current, $isHttps) ??
        base64url_encode(random_bytes(16));
    $name = idp_route_known_device_cookie_name($provider, $current, $isHttps);
    idp_route_prune_known_devices($isHttps, $name);
    $issuedAt = time();
    setcookie(
        $name,
        "v1." .
            $issuedAt .
            "." .
            $deviceId .
            "." .
            idp_route_known_device_mac($key, $provider, $current, $issuedAt, $deviceId),
        [
            "expires" => $issuedAt + IDP_ROUTE_KNOWN_DEVICE_TTL,
            "path" => "/",
            "secure" => $isHttps,
            "httponly" => true,
            "samesite" => "Strict",
        ]
    );
}

/**
 * Expires this browser's oldest known-device cookies (by issue time; unreadable ones first) so
 * that, with the one about to be set as $keepName, it keeps at most
 * IDP_ROUTE_KNOWN_DEVICES_PER_BROWSER. The __Host- prefix requires Path=/, so each is sent with
 * every request to this origin, and a shared browser that signs in to many accounts (a lab or
 * help-desk machine) would otherwise outgrow common request-header limits.
 */
function idp_route_prune_known_devices(bool $isHttps, string $keepName): void
{
    $pattern = '/^' . ($isHttps ? "__Host-" : "") . 'idp_kd_[0-9a-f]{16}$/D';
    $issued = [];
    foreach ($_COOKIE as $name => $value) {
        $name = (string) $name;
        if ($name === $keepName || preg_match($pattern, $name) !== 1) {
            continue;
        }
        $issued[$name] = is_string($value) && preg_match('/^v1\.(\d{1,12})\./', $value, $m) === 1
            ? (int) $m[1]
            : 0;
    }
    $excess = count($issued) - (IDP_ROUTE_KNOWN_DEVICES_PER_BROWSER - 1);
    if ($excess <= 0) {
        return;
    }
    asort($issued);
    foreach (array_slice(array_keys($issued), 0, $excess) as $name) {
        setcookie((string) $name, "", [
            "expires" => time() - 3600,
            "path" => "/",
            "secure" => $isHttps,
            "httponly" => true,
            "samesite" => "Strict",
        ]);
    }
}

// ---------- SAML SSO helpers ----------

/** The 400 page for a SAML request that cannot be processed. */
function idp_route_saml_request_error(string $issuer, Throwable $e): never
{
    render_modern_status_page(
        400,
        "SAML 2.0 Request Error",
        idp_route_error_message($e, "The SAML request could not be processed"),
        [
            "variant" => "error",
            "link_url" => $issuer . "/portal",
            "link_label" => "Open App Launchpad",
        ]
    );
}

/**
 * The browser's SSO session when it may answer this SAML request without a new sign-in
 * (S02-02): no ForceAuthn, and the session meets the app's effective sign-on policy (raised by
 * the RequestedAuthnContext), the RequestedAuthnContext itself and the app's group
 * assignment. Null otherwise; also when the session's sign-in time is unknown (S06-03), as
 * AuthnInstant must state it. "auth_time" of the returned session is that verified time. Only
 * call it in requests that carry the SSO cookie.
 */
function idp_route_saml_reusable_session(
    string $storePath,
    array $provider,
    array $app,
    ?array $authnReq,
    ?string $minPolicy
): ?array {
    if (!empty($authnReq["force_authn"])) {
        return null;
    }
    $session = sso_get_session($storePath, $provider);
    if (!$session) {
        return null;
    }
    $authTime = idp_route_session_auth_time($session);
    if ($authTime === null) {
        return null;
    }
    $session["auth_time"] = $authTime;
    if (
        !auth_policy_satisfied(
            effective_auth_policy($provider, $app, $minPolicy),
            $session["amr"]
        ) ||
        !saml_authn_context_satisfied($authnReq ?? [], $session["amr"]) ||
        !directory_user_matches_assigned_groups(
            $session["user"],
            $app["assigned_groups"] ?? []
        )
    ) {
        return null;
    }
    return $session;
}

/**
 * Answers a SAML request with a signed Response that carries only a non-success status
 * (Responder/NoPassive, Responder/NoAuthnContext, Requester/InvalidNameIDPolicy, ...), posted
 * to the ACS the request may use, with its RelayState. With $audit, the event is audited (as
 * unauthenticated noise when there is no $user). Returns only when the response cannot be built
 * (for example the ACS is not registered); the caller then shows an error page.
 */
function idp_route_saml_send_status(
    string $storePath,
    array $provider,
    string $baseUrl,
    array $app,
    ?array $authnReq,
    string $relayState,
    string $statusCode,
    string $subStatusCode = "",
    string $message = "",
    ?array $user = null,
    array $amr = [],
    bool $audit = true
): void {
    try {
        $samlCert = ensure_provider_saml_cert($storePath, $provider);
        $built = saml_build_status_response(
            $provider,
            $baseUrl,
            $samlCert,
            $app,
            $authnReq,
            $statusCode,
            $subStatusCode,
            $message
        );
    } catch (Throwable $e) {
        error_log(
            "saml: status response not sent (" .
                get_class($e) .
                ": " .
                sanitize_label($e->getMessage(), 200) .
                ")"
        );
        return;
    }
    $details = [
        "sp_entity_id" => (string) ($app["sp_entity_id"] ?? ""),
        "status" => $statusCode,
        "sub_status" => $subStatusCode,
        "in_response_to" => is_array($authnReq) ? (string) ($authnReq["id"] ?? "") : "",
    ];
    if ($audit && $user !== null) {
        audit_log_append(
            $storePath,
            (string) $provider["id"],
            "saml",
            "sso_status_response",
            "error",
            (string) ($app["name"] ?? ""),
            (string) ($user["username"] ?? ""),
            $amr,
            $details
        );
    } elseif ($audit) {
        idp_route_audit_untrusted(
            $storePath,
            $provider,
            "saml",
            "sso_status_response",
            (string) ($app["name"] ?? ""),
            "",
            $details
        );
    }
    saml_render_auto_post_form($built["acs_url"], $built["saml_response_b64"], $relayState);
}

/**
 * Builds the signed SAML Response for $user and posts it to the SP's ACS ($appForBuild is $app
 * with the test inspector's ACS in dry-run mode). A SamlStatusError (the sign-in does not meet
 * the RequestedAuthnContext, or the NameID policy cannot be met) is answered with a status
 * response (S02-02); any other failure (assertion encryption impossible, ACS no longer
 * registered, ...) is audited and shown as an error page instead of a bare 500 (S02-07).
 * $authTime and $sessionExpiresAt are the real sign-in time and SSO session end, when known.
 * $ssoSessionId is the SSO session the assertion comes from: its SessionIndex is then derived
 * from it (idp_route_saml_session_index()), so /saml/slo can recognize a LogoutRequest for it.
 */
function idp_route_saml_send_assertion(
    string $storePath,
    array $provider,
    string $baseUrl,
    array $app,
    array $appForBuild,
    array $user,
    array $amr,
    ?array $authnReq,
    string $relayState,
    ?int $authTime,
    ?int $sessionExpiresAt,
    bool $isTest = false,
    ?string $ssoSessionId = null
): never {
    $issuer = $baseUrl . "/" . $provider["idp_id"];
    try {
        $samlCert = ensure_provider_saml_cert($storePath, $provider);
        $buildArgs = [
            $provider,
            $baseUrl,
            $samlCert,
            $appForBuild,
            $user,
            $amr,
            $authnReq,
            $authTime,
            $sessionExpiresAt,
            $storePath,
        ];
        // S02-06: the response builder takes the session-derived SessionIndex once it accepts
        // one (requested from saml.php); until then it keeps its random value, which /saml/slo
        // never matches, so only the NameID proofs of idp_route_continue_slo() apply.
        if (
            !$isTest &&
            $ssoSessionId !== null &&
            $ssoSessionId !== "" &&
            idp_route_function_has_param("saml_build_signed_response", "sessionIndex")
        ) {
            $buildArgs["sessionIndex"] = idp_route_saml_session_index(
                $ssoSessionId,
                (string) $app["id"]
            );
        }
        $built = saml_build_signed_response(...$buildArgs);
    } catch (SamlStatusError $e) {
        idp_route_saml_send_status(
            $storePath,
            $provider,
            $baseUrl,
            $appForBuild,
            $e->authnRequest ?? $authnReq,
            $relayState,
            $e->statusCode,
            $e->subStatusCode,
            $e->getMessage(),
            $user,
            $amr
        );
        render_modern_status_page(403, "SAML Sign-In Error", $e->getMessage(), [
            "variant" => "error",
            "link_url" => $issuer . "/portal",
            "link_label" => "Open App Launchpad",
        ]);
    } catch (Throwable $e) {
        audit_log_append(
            $storePath,
            (string) $provider["id"],
            "saml",
            "sso_assertion_failed",
            "error",
            (string) $app["name"],
            (string) $user["username"],
            $amr,
            [
                "sp_entity_id" => (string) $app["sp_entity_id"],
                "error" => $e->getMessage(),
            ]
        );
        render_modern_status_page(
            500,
            "SAML Sign-In Error",
            idp_route_error_message($e, "The SAML response could not be created. The administrator can find details in the server log."),
            [
                "variant" => "error",
                "link_url" => $issuer . "/portal",
                "link_label" => "Open App Launchpad",
            ]
        );
    }

    audit_log_append(
        $storePath,
        (string) $provider["id"],
        "saml",
        $isTest ? "test_saml_assertion" : "sso_assertion_issued",
        "success",
        (string) $app["name"],
        (string) $user["username"],
        $amr,
        [
            "sp_entity_id" => (string) $app["sp_entity_id"],
            "acs_url" => $built["acs_url"],
            "in_response_to" => is_array($authnReq) ? ($authnReq["id"] ?? null) : null,
        ]
    );
    saml_render_auto_post_form(
        $built["acs_url"],
        $built["saml_response_b64"],
        $relayState
    );
}

/**
 * GET /login for a SAML transaction (S02-04): answers it from the SSO session when that
 * session may be reused, or with Responder/NoPassive for an IsPassive request without one.
 * Returns when the user has to sign in.
 */
function idp_route_resume_saml(
    string $storePath,
    array $provider,
    string $baseUrl,
    string $issuer,
    array $tx
): void {
    $payload = $tx["payload"];
    $app = saml_get_app($storePath, (string) $provider["id"], (string) ($payload["app_id"] ?? ""));
    if (!$app) {
        return;
    }
    $authnReq = is_array($payload["authn_req"] ?? null) ? $payload["authn_req"] : null;
    $relayState = is_string($payload["relay_state"] ?? null) ? $payload["relay_state"] : "";
    $minPolicy = is_string($payload["min_auth_policy"] ?? null) ? $payload["min_auth_policy"] : null;
    $session = idp_route_saml_reusable_session($storePath, $provider, $app, $authnReq, $minPolicy);
    $passive = !empty($authnReq["is_passive"]);
    if ($session === null && !$passive) {
        return;
    }
    // Single use, also against a concurrent load of the same page.
    if (tx_consume_atomic($storePath, (string) $tx["id"]) === null) {
        idp_route_tx_expired_page($issuer);
    }
    if ($session !== null) {
        idp_route_saml_send_assertion(
            $storePath,
            $provider,
            $baseUrl,
            $app,
            $app,
            $session["user"],
            $session["amr"],
            $authnReq,
            $relayState,
            (int) $session["auth_time"],
            idp_route_session_expires_at($session),
            false,
            (string) $session["id"]
        );
    }
    idp_route_saml_send_status(
        $storePath,
        $provider,
        $baseUrl,
        $app,
        $authnReq,
        $relayState,
        "Responder",
        "NoPassive",
        "The user is not signed in at the identity provider",
        null,
        [],
        false
    );
    idp_route_saml_request_error(
        $issuer,
        new RuntimeException(
            "The service provider asked for a passive sign-in, but you are not signed in"
        )
    );
}

// ---------- OIDC helpers ----------

/**
 * The browser's SSO session when it may answer this authorization request without a new
 * sign-in: no prompt=login/select_account, the session meets the client's effective sign-on
 * policy (G1e-02) and group assignment, and its sign-in is known and not older than max_age
 * (S06-03, OIDC Core 3.1.2.1; max_age=0 always signs in again). Null otherwise. "auth_time" of
 * the returned session is that verified sign-in time. Only call it in requests that carry the
 * SSO cookie.
 */
function idp_route_oidc_reusable_session(
    string $storePath,
    array $provider,
    array $client,
    array $authReq
): ?array {
    $prompt = (string) ($authReq["prompt"] ?? "");
    if (str_contains($prompt, "login") || str_contains($prompt, "select_account")) {
        return null;
    }
    $session = sso_get_session($storePath, $provider);
    if (!$session) {
        return null;
    }
    $authTime = idp_route_session_auth_time($session);
    if ($authTime === null) {
        return null;
    }
    $session["auth_time"] = $authTime;
    if (
        !auth_policy_satisfied(effective_auth_policy($provider, $client), $session["amr"]) ||
        !directory_user_matches_assigned_groups($session["user"], $client["assigned_groups"] ?? [])
    ) {
        return null;
    }
    $maxAge = idp_route_max_age($authReq["max_age"] ?? null);
    if ($maxAge !== null && time() - $authTime > $maxAge) {
        return null;
    }
    return $session;
}

/** A max_age value from a validated (or stored) authorization request; null when absent. */
function idp_route_max_age(mixed $value): ?int
{
    if (is_string($value) && preg_match('/^\d{1,10}$/D', $value) === 1) {
        $value = (int) $value;
    }
    return is_int($value) && $value >= 0 ? $value : null;
}

/**
 * GET /login for an OIDC transaction (S02-04): answers it from the SSO session when that
 * session may be reused, or with error=login_required for prompt=none without one. Returns
 * when the user has to sign in.
 */
function idp_route_resume_oidc(
    string $storePath,
    array &$providers,
    array &$provider,
    string $baseUrl,
    string $keysDir,
    string $issuer,
    array $tx
): void {
    $authReq = $tx["payload"];
    $client = oidc_find_client_by_client_id(
        $storePath,
        (string) $provider["id"],
        (string) ($authReq["client_id"] ?? "")
    );
    if (!$client) {
        return;
    }
    $authReq["client"] = $client;
    $session = idp_route_oidc_reusable_session($storePath, $provider, $client, $authReq);
    $promptNone = trim((string) ($authReq["prompt"] ?? "")) === "none";
    if ($session === null && !$promptNone) {
        return;
    }
    if (tx_consume_atomic($storePath, (string) $tx["id"]) === null) {
        idp_route_tx_expired_page($issuer);
    }
    if ($session !== null) {
        oidc_issue_authorization_response(
            $storePath,
            $providers,
            $provider,
            $baseUrl,
            $authReq,
            $session["user"],
            $session["amr"],
            $keysDir,
            (int) $session["auth_time"],
            (string) $session["id"]
        );
    }
    // prompt=none without a usable session; the redirect URI is checked against the client again.
    try {
        $redirectUri = oidc_check_redirect_uri(
            $client,
            (string) ($authReq["redirect_uri"] ?? ""),
            (string) ($authReq["response_type"] ?? "code"),
            (string) ($authReq["code_challenge"] ?? ""),
            (string) ($authReq["code_challenge_method"] ?? "")
        );
    } catch (InvalidArgumentException $e) {
        render_modern_status_page(400, "OIDC Authorization Error", $e->getMessage(), [
            "variant" => "error",
            "link_url" => $issuer . "/portal",
            "link_label" => "Open App Launchpad",
        ]);
    }
    $errParams = ["error" => "login_required"];
    $state = (string) ($authReq["state"] ?? "");
    if ($state !== "") {
        $errParams["state"] = $state;
    }
    oidc_send_authorization_redirect(
        $redirectUri,
        $errParams,
        (string) ($authReq["response_mode"] ?? "query")
    );
}

// ---------- OIDC RP-Initiated Logout helpers (S02-06) ----------

/**
 * Parameters of an RP-initiated logout request: post_logout_redirect_uri, state, client_id and
 * id_token_hint, each from the query or else the form, "" when absent. "malformed" is true when
 * one of them is repeated (sent as an array) or too long; such a request is served without a
 * redirect and always asks the user.
 */
function idp_route_oidc_logout_request(): array
{
    $limits = [
        "post_logout_redirect_uri" => IDP_ROUTE_AUTHZ_PARAM_MAX_BYTES,
        "state" => IDP_ROUTE_AUTHZ_PARAM_MAX_BYTES,
        "client_id" => IDP_ROUTE_AUTHZ_PARAM_MAX_BYTES,
        "id_token_hint" => IDP_ROUTE_ID_TOKEN_HINT_MAX_BYTES,
    ];
    $request = ["malformed" => false];
    foreach ($limits as $name => $maxBytes) {
        $raw = $_GET[$name] ?? null;
        if ($raw === null || $raw === "") {
            $raw = $_POST[$name] ?? "";
        }
        if (!is_string($raw)) {
            $request["malformed"] = true;
            $raw = "";
        }
        // state is opaque to the IdP and returned exactly as sent.
        $value = $name === "state" ? $raw : trim($raw);
        if (strlen($value) > $maxBytes) {
            $request["malformed"] = true;
            $value = "";
        }
        $request[$name] = $value;
    }
    return $request;
}

/**
 * The logout request an RP's form POST handed to the same-site GET (S03-11), from the payload
 * POST /oauth2/logout stored: [request as idp_route_oidc_logout_request() returns it, the
 * id_token_hint as idp_route_verify_id_token_hint() verified it there (or null), whether a hint
 * was sent]. The raw hint itself is not kept; "id_token_hint" is "".
 */
function idp_route_oidc_logout_from_handoff(array $payload): array
{
    $text = static fn(string $name): string => is_string($payload[$name] ?? null)
        ? $payload[$name]
        : "";
    $request = [
        "malformed" => !empty($payload["malformed"]),
        "post_logout_redirect_uri" => $text("post_logout_redirect_uri"),
        "state" => $text("state"),
        "client_id" => $text("client_id"),
        "id_token_hint" => "",
    ];
    $stored = $payload["hint"] ?? null;
    $hint = null;
    if (
        is_array($stored) &&
        is_string($stored["sub"] ?? null) &&
        $stored["sub"] !== "" &&
        is_string($stored["client_id"] ?? null) &&
        $stored["client_id"] !== ""
    ) {
        $hint = [
            "sub" => $stored["sub"],
            "client_id" => $stored["client_id"],
            "iat" => idp_route_positive_int($stored["iat"] ?? null),
        ];
    }
    return [$request, $hint, !empty($payload["id_token_hint_sent"])];
}

/**
 * True when a POST to a sign-out endpoint (/oauth2/logout, /saml/slo) is this IdP's own
 * confirmation, from the confirm page or the portal's Sign Out button (S03-11): it names this
 * origin in its Origin header (any CSRF token it sends must then be this session's), or sends no
 * other origin and carries this session's CSRF token (form field csrf_token or X-CSRF-Token). An
 * RP's form POST names its own origin or "null" and carries no token of this session. Never
 * starts a session.
 */
function idp_route_is_own_logout_post(string $origin): bool
{
    $token = trim((string) ($_SERVER["HTTP_X_CSRF_TOKEN"] ?? ""));
    if ($token === "" && is_string($_POST["csrf_token"] ?? null)) {
        $token = trim($_POST["csrf_token"]);
    }
    $reqOrigin = trim((string) ($_SERVER["HTTP_ORIGIN"] ?? ""));
    if ($reqOrigin !== "" && strtolower($reqOrigin) !== "null") {
        return strcasecmp(rtrim($reqOrigin, "/"), rtrim($origin, "/")) === 0 &&
            ($token === "" || csrf_session_token_matches($token));
    }
    return $token !== "" && csrf_session_token_matches($token);
}

/**
 * The post_logout_redirect_uri to send the browser to after sign-out, with the name of the client
 * that registered it: it must be registered exactly by the client $clientId (named by the
 * request's verified id_token_hint or its client_id) and still meet the endpoint rules (G1d-04:
 * https unless loopback, no fragment). ["uri" => "", "client_name" => ""] when there is none.
 * A request that names no client is never redirected (RP-Initiated Logout 1.0 section 3, S03-11:
 * nothing confirms that the target belongs to the RP that sent it); legacy_logout_redirect
 * (OIDC_LEGACY_LOGOUT_REDIRECT) restores accepting a URI registered by any client of this
 * provider for such requests.
 */
function idp_route_oidc_logout_redirect(
    string $storePath,
    array $provider,
    string $uri,
    string $clientId
): array {
    $none = ["uri" => "", "client_name" => ""];
    if (
        $uri === "" ||
        ($clientId === "" && !config_flag("legacy_logout_redirect", "OIDC_LEGACY_LOGOUT_REDIRECT"))
    ) {
        return $none;
    }
    $clients =
        $clientId !== ""
            ? array_filter([
                oidc_find_client_by_client_id($storePath, (string) $provider["id"], $clientId),
            ])
            : oidc_list_clients($storePath, (string) $provider["id"]);
    foreach ($clients as $c) {
        if (!in_array($uri, (array) ($c["post_logout_redirect_uris"] ?? []), true)) {
            continue;
        }
        try {
            return [
                "uri" => validate_endpoint_url($uri, true, "post_logout_redirect_uri"),
                "client_name" => (string) ($c["name"] ?? ""),
            ];
        } catch (InvalidArgumentException $e) {
            return $none;
        }
    }
    return $none;
}

/**
 * Checks an id_token_hint (OIDC RP-Initiated Logout 1.0 section 2): it must be a compact JWS with
 * typ JWT, signed by one of this provider's published keys (chosen by kid, with that key's own
 * algorithm, so "none" and algorithm substitution never verify), and carry iss = $issuer, a sub
 * and an aud naming exactly one client (azp picks it from a list). An expired ID token is
 * accepted, as the specification recommends; the caller binds the hint to the current session.
 * Returns ["sub" => ..., "client_id" => ..., "iat" => ?int], or null when any check fails.
 */
function idp_route_verify_id_token_hint(array $provider, string $issuer, string $jwt): ?array
{
    if ($jwt === "" || strlen($jwt) > IDP_ROUTE_ID_TOKEN_HINT_MAX_BYTES) {
        return null;
    }
    $parts = explode(".", $jwt);
    if (count($parts) !== 3) {
        return null;
    }
    foreach ($parts as $part) {
        if (preg_match('/^[A-Za-z0-9_-]+$/D', $part) !== 1) {
            return null;
        }
    }
    [$headerB64, $payloadB64, $signatureB64] = $parts;
    $header = json_decode(base64url_decode($headerB64), true);
    $claims = json_decode(base64url_decode($payloadB64), true);
    $signature = base64url_decode($signatureB64);
    if (!is_array($header) || !is_array($claims) || $signature === "") {
        return null;
    }
    $alg = $header["alg"] ?? null;
    $kid = $header["kid"] ?? null;
    $typ = $header["typ"] ?? "JWT";
    if (
        !is_string($alg) ||
        !is_string($kid) ||
        $kid === "" ||
        !is_string($typ) ||
        strcasecmp($typ, "JWT") !== 0 ||
        array_key_exists("crit", $header)
    ) {
        return null;
    }
    $key = null;
    foreach (filter_publishable_keys_for_provider($provider) as $candidate) {
        if (is_array($candidate) && (string) ($candidate["kid"] ?? "") === $kid) {
            $key = $candidate;
            break;
        }
    }
    if ($key === null || normalize_jwa_alg((string) ($key["alg"] ?? "RS256")) !== $alg) {
        return null;
    }
    try {
        $valid = idp_route_jws_signature_valid(
            $key,
            $alg,
            $headerB64 . "." . $payloadB64,
            $signature
        );
    } catch (Throwable $e) {
        error_log(
            "oidc logout: id_token_hint not verified with key " .
                sanitize_label($kid, 80) .
                " (" .
                get_class($e) .
                ")"
        );
        return null;
    }
    if (!$valid || ($claims["iss"] ?? null) !== $issuer) {
        return null;
    }
    $sub = $claims["sub"] ?? null;
    if (!is_string($sub) || $sub === "") {
        return null;
    }
    $aud = $claims["aud"] ?? null;
    $clientId = null;
    if (is_string($aud)) {
        $clientId = $aud;
    } elseif (is_array($aud) && $aud !== [] && array_is_list($aud)) {
        $azp = $claims["azp"] ?? null;
        if (is_string($azp) && in_array($azp, $aud, true)) {
            $clientId = $azp;
        } elseif (count($aud) === 1 && is_string($aud[0])) {
            $clientId = $aud[0];
        }
    }
    if ($clientId === null || $clientId === "") {
        return null;
    }
    return [
        "sub" => $sub,
        "client_id" => $clientId,
        "iat" => idp_route_positive_int($claims["iat"] ?? null),
    ];
}

/**
 * Verifies a JWS signature made with a provider signing key ($alg is the key's algorithm):
 * RS256/384/512 (PKCS#1 v1.5), ES256/384/512 (r||s, RFC 7518 3.4) or EdDSA (Ed25519). Throws
 * when the key material cannot be loaded.
 */
function idp_route_jws_signature_valid(
    array $key,
    string $alg,
    string $signingInput,
    string $signature
): bool {
    $material = is_array($key["material"] ?? null) ? $key["material"] : [];
    if ($alg === "EdDSA") {
        $publicKey = base64url_decode((string) ($material["ed_public"] ?? ""));
        return strlen($publicKey) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES &&
            strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES &&
            sodium_crypto_sign_verify_detached($signature, $signingInput, $publicKey);
    }
    if (preg_match('/^(RS|ES)(256|384|512)$/D', $alg, $m) !== 1) {
        return false;
    }
    $hash = match ($m[2]) {
        "256" => OPENSSL_ALGO_SHA256,
        "384" => OPENSSL_ALGO_SHA384,
        default => OPENSSL_ALGO_SHA512,
    };
    $details = signing_key_pkey_details($material);
    $publicKey = openssl_pkey_get_public((string) ($details["key"] ?? ""));
    if ($publicKey === false) {
        return false;
    }
    if ($m[1] === "RS") {
        return ($details["type"] ?? null) === OPENSSL_KEYTYPE_RSA &&
            openssl_verify($signingInput, $signature, $publicKey, $hash) === 1;
    }
    $coordLen = match ($m[2]) {
        "256" => 32,
        "384" => 48,
        default => 66,
    };
    if (($details["type"] ?? null) !== OPENSSL_KEYTYPE_EC || strlen($signature) !== 2 * $coordLen) {
        return false;
    }
    $derSignature = der_sequence(
        der_integer_unsigned(substr($signature, 0, $coordLen)) .
            der_integer_unsigned(substr($signature, $coordLen))
    );
    return openssl_verify($signingInput, $derSignature, $publicKey, $hash) === 1;
}

/**
 * True when a verified id_token_hint (from idp_route_verify_id_token_hint()) belongs to
 * $session: issued to the session's user (sub) during this session (iat not before its sign-in,
 * allowing 60 s of clock skew). Only then may an RP-initiated logout skip the confirmation.
 */
function idp_route_logout_hint_matches_session(?array $hint, array $session): bool
{
    if ($hint === null) {
        return false;
    }
    $authTime = idp_route_session_auth_time($session);
    return $authTime !== null &&
        $hint["iat"] !== null &&
        $hint["iat"] >= $authTime - 60 &&
        $hint["sub"] === oidc_subject_for_user($session["user"]);
}

// ---------- SAML Single Logout helpers ----------

/**
 * Validates an SP's LogoutRequest (S02-05) and returns what the logout needs: the app, the
 * request ID, NameID and format, the SessionIndex values, whether the SP's signature proved it,
 * the binding it came with and the RelayState. Null when it is unreadable, stale, from an
 * unknown SP, fails its signature check, or is a signed request whose ID that SP already used:
 * signed requests are recorded here (saml_record_request_id()), so a captured one cannot end
 * sessions again.
 */
function idp_route_parse_slo_request(
    string $storePath,
    array $provider,
    string $issuer,
    string $samlRequestParam,
    string $binding,
    string $rawQuery,
    string $relayState
): ?array {
    try {
        if (strlen($relayState) > IDP_ROUTE_RELAY_STATE_MAX_BYTES) {
            throw new InvalidArgumentException("RelayState is too long");
        }
        $query = $binding === SAML_BINDING_REDIRECT ? $rawQuery : "";
        $xml = saml_decode_binding_payload($samlRequestParam, $binding);
        $prelim = saml_parse_logout_request($xml, $binding, $query, null, $issuer . "/saml/slo");
        $app = saml_find_app_by_entity_id(
            $storePath,
            (string) $provider["id"],
            (string) $prelim["issuer"]
        );
        if (!$app) {
            idp_route_audit_untrusted(
                $storePath,
                $provider,
                "saml",
                "unknown_sp_issuer",
                "",
                "",
                ["sp_entity_id" => (string) $prelim["issuer"], "message" => "LogoutRequest"]
            );
            return null;
        }
        // With an SP signing certificate the signature is required and verified here.
        $lr = saml_parse_logout_request($xml, $binding, $query, $app, $issuer . "/saml/slo");
        if (!empty($lr["signature_verified"])) {
            // S02-05: throws when this SP already sent this request ID (a replay).
            saml_record_request_id(
                $storePath,
                (string) $provider["id"],
                (string) $app["sp_entity_id"],
                (string) $lr["id"]
            );
        }
    } catch (Throwable $e) {
        error_log(
            "saml slo: LogoutRequest not accepted (" .
                get_class($e) .
                ": " .
                sanitize_label($e->getMessage(), 300) .
                ")"
        );
        return null;
    }
    return [
        "app_id" => (string) $app["id"],
        "request_id" => (string) $lr["id"],
        "name_id" => (string) $lr["name_id"],
        "name_id_format" => (string) $lr["name_id_format"],
        "session_indexes" => array_values(array_filter((array) $lr["session_indexes"], "is_string")),
        "signature_verified" => !empty($lr["signature_verified"]),
        "binding" => $binding,
        "relay_state" => $relayState,
    ];
}

/**
 * The SessionIndex of assertions issued from SSO session $sessionId to app $appId (S02-06): an
 * HMAC of the app id keyed with the session id. It names one session at one SP, differs between
 * SPs, and cannot be computed without the session cookie, so a LogoutRequest that echoes it is
 * about the browser's current session.
 */
function idp_route_saml_session_index(string $sessionId, string $appId): string
{
    return "_sess_" .
        substr(hash_hmac("sha256", "saml session index v1\0" . $appId, $sessionId), 0, 40);
}

/** True when one of $sessionIndexes is the SessionIndex of $session at $app. */
function idp_route_slo_session_index_matches(
    array $session,
    array $app,
    array $sessionIndexes
): bool {
    $expected = idp_route_saml_session_index((string) $session["id"], (string) $app["id"]);
    foreach ($sessionIndexes as $sessionIndex) {
        if (is_string($sessionIndex) && hash_equals($expected, $sessionIndex)) {
            return true;
        }
    }
    return false;
}

/**
 * True when $nameId is $user's NameID at $app, computed as when assertions are issued (for the
 * request's NameID format, or the app's when none is given). A transient NameID never matches.
 */
function idp_route_saml_name_id_matches(
    string $storePath,
    array $provider,
    string $baseUrl,
    array $app,
    array $user,
    string $nameId,
    string $nameIdFormat
): bool {
    if ($nameId === "" || $nameIdFormat === SAML_NAMEID_TRANSIENT) {
        return false;
    }
    try {
        $computed = saml_compute_name_id(
            $user,
            $app,
            $baseUrl . "/" . $provider["idp_id"],
            $nameIdFormat !== "" ? $nameIdFormat : null,
            $storePath
        );
    } catch (Throwable $e) {
        return false;
    }
    $value = (string) ($computed["value"] ?? "");
    return ($computed["format"] ?? "") !== SAML_NAMEID_TRANSIENT &&
        $value !== "" &&
        hash_equals($value, $nameId);
}

/**
 * True when $nameId is $user's keyed pairwise persistent identifier at $app (scheme "hmac" of
 * saml_persistent_name_id()). Only that SP and this IdP know it, unlike an email address, a
 * username or a legacy (unkeyed) persistent identifier, which anyone may know or compute.
 */
function idp_route_saml_pairwise_name_id_matches(
    string $storePath,
    array $provider,
    string $baseUrl,
    array $app,
    array $user,
    string $nameId
): bool {
    if ($nameId === "" || ($app["persistent_id_scheme"] ?? "legacy") !== "hmac") {
        return false;
    }
    try {
        $pairwise = saml_persistent_name_id(
            $user,
            $app,
            $baseUrl . "/" . $provider["idp_id"],
            $storePath
        );
    } catch (Throwable $e) {
        return false;
    }
    return $pairwise !== "" && hash_equals($pairwise, $nameId);
}

/**
 * Records the ID of an unsigned LogoutRequest that is about to end a session without asking, so
 * that same message (say, a Redirect-binding URL left in the browser history) cannot do it again;
 * signed ones were recorded when parsed. It does not stop new unsigned requests with fresh IDs
 * (see idp_route_continue_slo()). False when it was already used, or cannot be recorded; the
 * user is then asked instead.
 */
function idp_route_slo_record_request(
    string $storePath,
    array $provider,
    array $app,
    array $pending
): bool {
    try {
        saml_record_request_id(
            $storePath,
            (string) $provider["id"],
            (string) $app["sp_entity_id"],
            (string) ($pending["request_id"] ?? "")
        );
        return true;
    } catch (Throwable $e) {
        error_log(
            "saml slo: LogoutRequest from " .
                sanitize_label((string) $app["sp_entity_id"], 200) .
                " not accepted without confirmation (" .
                get_class($e) .
                ")"
        );
        return false;
    }
}

/**
 * Completes an SP-initiated logout in a request that carries the SSO cookie (a top-level GET).
 * The session ends without asking only when the request is shown to be about it (S02-05,
 * S02-06): it echoes the SessionIndex this IdP issued for the session at that SP; or the SP
 * signed it and it names the session user's NameID there; or, unsigned, it names the user's
 * keyed pairwise NameID there. Only that SP and this IdP compute that NameID, but anyone who has
 * seen it (SP logs, a Redirect-binding URL in a browser history) can build new unsigned requests
 * with fresh IDs and so sign the user out of the IdP; recording an unsigned request's ID
 * (idp_route_slo_record_request()) only stops a replay of that same message. SPs that want
 * silent logout without this should have their signing certificate configured: their requests
 * must then be signed (idp_route_parse_slo_request()). Any other request is confirmed by the
 * user first: an unsigned one that names a NameID anyone may know (an email address, a
 * username), and a signed one about another user. A browser without a session has nothing to
 * end. A signed LogoutResponse then goes to the SP; confirming (POST /saml/slo?slo_tx=...) also
 * sends it. Other applications keep their sessions (no logout is propagated to them), and the
 * pages say so. Never returns.
 */
function idp_route_continue_slo(
    string $storePath,
    array $provider,
    string $baseUrl,
    string $issuer,
    bool $isHttps,
    array $pending,
    ?string $txId
): never {
    $app = saml_get_app($storePath, (string) $provider["id"], (string) ($pending["app_id"] ?? ""));
    $session = sso_get_session($storePath, $provider);
    $signed = !empty($pending["signature_verified"]);
    $proof = $session === null ? "no_session" : "";
    if ($session !== null && $app !== null) {
        $nameId = (string) ($pending["name_id"] ?? "");
        $sessionIndexes = is_array($pending["session_indexes"] ?? null)
            ? $pending["session_indexes"]
            : [];
        if (idp_route_slo_session_index_matches($session, $app, $sessionIndexes)) {
            $proof = "session_index";
        } elseif (
            $signed &&
            idp_route_saml_name_id_matches(
                $storePath,
                $provider,
                $baseUrl,
                $app,
                $session["user"],
                $nameId,
                (string) ($pending["name_id_format"] ?? "")
            )
        ) {
            $proof = "signed_name_id";
        } elseif (
            !$signed &&
            idp_route_saml_pairwise_name_id_matches(
                $storePath,
                $provider,
                $baseUrl,
                $app,
                $session["user"],
                $nameId
            )
        ) {
            $proof = "pairwise_name_id";
        }
        if ($proof !== "" && !$signed && !idp_route_slo_record_request($storePath, $provider, $app, $pending)) {
            $proof = "";
        }
    }
    if ($proof === "") {
        if ($txId === null) {
            idp_route_require_tx_budget($storePath, $provider, $session);
            $txId = idp_route_tx_create_or_400(
                $storePath,
                $provider,
                $issuer,
                "saml_slo",
                $pending
            );
        }
        idp_route_slo_confirm_page($provider, $issuer, $app, $txId);
    }
    // A stored request is claimed atomically (G1c-05), so the SP is answered once.
    $answer = $txId === null || tx_consume_atomic($storePath, $txId) !== null;
    if ($session !== null) {
        idp_route_end_sso_session(
            $storePath,
            $provider,
            $isHttps,
            "saml",
            (string) ($app["name"] ?? ""),
            [
                "sp_entity_id" => (string) ($app["sp_entity_id"] ?? ""),
                "slo_request_id" => (string) ($pending["request_id"] ?? ""),
                "signed" => $signed,
                "proof" => $proof,
            ]
        );
    }
    if ($answer) {
        idp_route_send_logout_response(
            $storePath,
            $provider,
            $baseUrl,
            $app,
            (string) ($pending["request_id"] ?? ""),
            (string) ($pending["relay_state"] ?? "")
        );
    }
    idp_route_signed_out_page($provider, $issuer);
}

/**
 * Sends a signed LogoutResponse (InResponseTo the SP's request, with its RelayState) to the app's
 * SLO endpoint (S02-05): to slo_response_url (the metadata ResponseLocation) when the app has
 * one, else to slo_url, with the binding stored for that endpoint (slo_binding): HTTP-POST, also
 * for apps without a stored binding (as before), or HTTP-Redirect (a signed query, see
 * idp_route_saml_redirect_binding_url()). An endpoint with any other binding (SOAP, Artifact)
 * cannot be answered through the browser and gets nothing. The URL is checked again with
 * validate_endpoint_url() first (S01-04). Returns when there is nothing to send or it cannot be
 * sent.
 */
function idp_route_send_logout_response(
    string $storePath,
    array $provider,
    string $baseUrl,
    ?array $app,
    string $inResponseTo,
    string $relayState
): void {
    if ($app === null) {
        return;
    }
    $sloUrl = trim((string) ($app["slo_response_url"] ?? ""));
    if ($sloUrl === "") {
        $sloUrl = trim((string) ($app["slo_url"] ?? ""));
    }
    if ($sloUrl === "") {
        return;
    }
    $sloBinding = trim((string) ($app["slo_binding"] ?? ""));
    if ($sloBinding === "") {
        $sloBinding = SAML_BINDING_POST;
    }
    if ($sloBinding !== SAML_BINDING_POST && $sloBinding !== SAML_BINDING_REDIRECT) {
        error_log(
            "saml slo: no LogoutResponse sent for app " .
                (string) ($app["id"] ?? "") .
                ": its SLO endpoint uses the binding " .
                sanitize_label($sloBinding, 120) .
                ", which a browser cannot carry"
        );
        return;
    }
    try {
        $sloUrl = validate_endpoint_url($sloUrl, false, "SLO URL");
        $samlCert = ensure_provider_saml_cert($storePath, $provider);
        $xml = saml_build_logout_response($provider, $baseUrl, $samlCert, $sloUrl, $inResponseTo);
        $location = $sloBinding === SAML_BINDING_REDIRECT
            ? idp_route_saml_redirect_binding_url($sloUrl, "SAMLResponse", $xml, $relayState, $samlCert)
            : "";
    } catch (Throwable $e) {
        error_log(
            "saml slo: no LogoutResponse sent for app " .
                (string) ($app["id"] ?? "") .
                " (" .
                get_class($e) .
                ": " .
                sanitize_label($e->getMessage(), 200) .
                ")"
        );
        return;
    }
    if ($location !== "") {
        if (!headers_sent()) {
            send_security_headers(false);
            header("Cache-Control: no-store, no-cache, must-revalidate");
        }
        header("Location: " . $location, true, 302);
        exit();
    }
    saml_render_auto_post_form($sloUrl, base64_encode($xml), $relayState);
}

/**
 * The HTTP-Redirect binding URL (SAML Bindings 3.4.4) that carries $xml as $param ("SAMLResponse"
 * or "SAMLRequest") to $destination: the enveloped ds:Signature is removed (3.4.4.1), the message
 * is DEFLATE-compressed and base64-encoded, and the query of $param, RelayState and SigAlg is
 * signed with the provider's SAML key (RSA-SHA256). Values are encoded with urlencode(), as the
 * common SP libraries do when they rebuild the signed query. Throws RuntimeException when the
 * message cannot be encoded or signed (the SAML key must be an RSA key).
 */
function idp_route_saml_redirect_binding_url(
    string $destination,
    string $param,
    string $xml,
    string $relayState,
    array $samlCert
): string {
    $doc = saml_load_xml_safely($xml);
    $root = $doc->documentElement;
    foreach (iterator_to_array(saml_xpath($doc)->query("./ds:Signature", $root)) as $sigNode) {
        $root->removeChild($sigNode);
    }
    $deflated = gzdeflate((string) $doc->saveXML($root));
    if ($deflated === false) {
        throw new RuntimeException("The SAML message could not be DEFLATE-encoded");
    }
    $query = $param . "=" . urlencode(base64_encode($deflated));
    if ($relayState !== "") {
        $query .= "&RelayState=" . urlencode($relayState);
    }
    $query .= "&SigAlg=" . urlencode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    $key = openssl_pkey_get_private((string) ($samlCert["private_key_pem"] ?? ""));
    $details = $key !== false ? openssl_pkey_get_details($key) : false;
    if ($key === false || !is_array($details) || ($details["type"] ?? null) !== OPENSSL_KEYTYPE_RSA) {
        throw new RuntimeException("The SAML signing key is not a usable RSA key");
    }
    if (!openssl_sign($query, $signature, $key, OPENSSL_ALGO_SHA256)) {
        throw new RuntimeException("The HTTP-Redirect SAML message could not be signed");
    }
    return $destination .
        (str_contains($destination, "?") ? "&" : "?") .
        $query .
        "&Signature=" .
        urlencode(base64_encode($signature));
}

/**
 * Sign-out confirmation for /saml/slo; with $txId, confirming answers that SP's LogoutRequest.
 * It says that other applications keep their sessions (S02-05).
 */
function idp_route_slo_confirm_page(
    array $provider,
    string $issuer,
    ?array $app,
    ?string $txId
): never {
    $action = $issuer . "/saml/slo";
    if ($txId !== null && $txId !== "") {
        $action .= "?slo_tx=" . rawurlencode($txId);
    }
    $message =
        ($app !== null
            ? $app["name"] . " asked to end your Single Sign-On session with this Identity Provider."
            : "This will end your active Single Sign-On session with this Identity Provider.") .
        " Other applications you signed in to keep their own sessions until you sign out of them.";
    render_modern_status_page(
        200,
        "Sign out of " . $provider["friendly"] . "?",
        $message,
        [
            "variant" => "confirm",
            "post_action" => $action,
            "post_label" => "Sign Out",
            "link_url" => $issuer . "/portal",
            "link_label" => "Cancel",
        ]
    );
}

/**
 * The page after a SAML sign-out. Single Logout ends only the IdP session (and answers the SP
 * that asked); it is not propagated to other applications, and the page says so (S02-05).
 */
function idp_route_signed_out_page(array $provider, string $issuer): never
{
    render_modern_status_page(
        200,
        "Signed Out",
        "Your Single Sign-On session with " .
            $provider["friendly"] .
            " has ended. Other applications you signed in to through it keep their own sessions: sign out of each of them as well.",
        [
            "variant" => "success",
            "link_url" => $issuer . "/portal",
            "link_label" => "Sign In Again",
        ]
    );
}

// ---------- Passkey enrollment rules (S05-02, S06-01) ----------

/**
 * Compatibility flag allow_first_use_passkey_enrollment (env
 * OIDC_ALLOW_FIRST_USE_PASSKEY_ENROLLMENT, default off), read on every use. When on, a user who
 * has no passkey may enroll the first one inline at MFA step 2 after the password (completing
 * the sign-in as before), or from the portal within IDP_ROUTE_PASSKEY_STEP_UP_SECONDS of a
 * sign-in. Users who already have a passkey are never affected.
 */
function idp_route_first_use_enrollment_allowed(): bool
{
    return config_flag(
        "allow_first_use_passkey_enrollment",
        "OIDC_ALLOW_FIRST_USE_PASSKEY_ENROLLMENT"
    );
}

/**
 * Why the user who passed this transaction's password step may not enroll a passkey inline at
 * MFA step 2, as [HTTP status, message], or null when they may (S06-01). A password alone must
 * never produce a second factor: inline enrollment needs allow_first_use_passkey_enrollment, an
 * active user without any passkey, an application that requires MFA and the user's group
 * assignment. Everyone else needs an admin-issued /enroll link.
 */
function idp_route_inline_enrollment_denial(
    string $storePath,
    array $provider,
    array $tx,
    ?array $user
): ?array {
    if ($user === null) {
        return [404, "User not found"];
    }
    if (($user["status"] ?? "active") !== "active") {
        return [403, "This account is not active"];
    }
    if (webauthn_count_user_credentials($storePath, (string) $user["id"]) > 0) {
        return [
            403,
            "A passkey is already registered for this account. Use it to finish signing in, or ask your administrator for an enrollment link.",
        ];
    }
    if (!idp_route_first_use_enrollment_allowed()) {
        return [
            403,
            "Passkeys can only be added with an enrollment link from your administrator.",
        ];
    }
    $ctx = tx_resolve_context($storePath, $provider, $tx);
    if (idp_route_tx_auth_policy($provider, $tx, $ctx) !== "mfa") {
        return [
            403,
            "Passkey enrollment during sign-in is only available for applications that require MFA",
        ];
    }
    if (!directory_user_matches_assigned_groups($user, $ctx["assigned_groups"] ?? [])) {
        return [
            403,
            "Access denied: user '" .
                $user["username"] .
                "' is not a member of the groups assigned to " .
                $ctx["app_name"],
        ];
    }
    return null;
}

/**
 * Why this SSO session may not add a passkey from the portal, or null when it may (S05-02).
 * Returns ["error" => message, "reauth" => whether signing in again would help]. A user who has
 * a passkey must have signed in with one (amr hwk) within $maxAge seconds. The first passkey is
 * added here only with allow_first_use_passkey_enrollment, within $maxAge seconds of a sign-in;
 * otherwise only through an admin-issued /enroll link.
 */
function idp_route_portal_enrollment_denial(array $session, bool $hasPasskey, int $maxAge): ?array
{
    if ((($session["user"]["status"] ?? "active")) !== "active") {
        return ["error" => "This account is not active", "reauth" => false];
    }
    $age = time() - (int) ($session["auth_time"] ?? 0);
    $fresh = $age >= -60 && $age <= $maxAge;
    if ($hasPasskey) {
        if (!$fresh || !in_array("hwk", (array) ($session["amr"] ?? []), true)) {
            return [
                "error" => "To add another passkey, sign in again with one of your existing passkeys, then add the new one within 5 minutes.",
                "reauth" => true,
            ];
        }
        return null;
    }
    if (!idp_route_first_use_enrollment_allowed()) {
        return [
            "error" => "Passkeys can only be added with an enrollment link from your administrator.",
            "reauth" => false,
        ];
    }
    if (!$fresh) {
        return [
            "error" => "To add your first passkey, sign in again, then add it within 5 minutes.",
            "reauth" => true,
        ];
    }
    return null;
}

/** JSON body of a refused portal passkey enrollment (adds reauth_url when signing in again helps). */
function idp_route_portal_denial_body(array $denied, string $issuer): array
{
    $body = ["error" => (string) $denied["error"]];
    if (!empty($denied["reauth"])) {
        $body["reauth_url"] = $issuer . "/login";
    }
    return $body;
}

// ---------- OIDC playground session state ----------

/** Session key of a playground run; it includes the provider so runs cannot cross providers. */
function idp_route_playground_key(string $providerId, string $state): string
{
    return "oidc_playground_" . hash("sha256", $providerId) . "_" . $state;
}

/** Drops expired playground runs from the session. */
function idp_route_prune_playground_state(): void
{
    if (!isset($_SESSION) || !is_array($_SESSION)) {
        return;
    }
    $now = time();
    foreach (array_keys($_SESSION) as $key) {
        if (
            is_string($key) &&
            str_starts_with($key, "oidc_playground_") &&
            (!is_array($_SESSION[$key]) || (int) ($_SESSION[$key]["expires_at"] ?? 0) < $now)
        ) {
            unset($_SESSION[$key]);
        }
    }
}
