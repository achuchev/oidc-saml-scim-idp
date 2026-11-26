<?php
// Copy this file to config.php and adjust. config.php is git-ignored.
//
// Precedence for each setting: environment variable > config.php > built-in default.
// An empty or whitespace-only environment variable counts as unset.
//
// Value formats:
// - Flags take true/false (or 1/0). As strings, "1", "true", "on" and "yes" mean true;
//   every other value ("0", "false", "off", "no", a typo) means false. A value that does
//   not parse never turns a legacy behavior on, and an environment value such as
//   OIDC_LEGACY_TOKEN_CLAIMS=0 overrides true in this file.
// - Lists take an array of strings or one string separated by commas or spaces.
// - Numbers take an integer; in an environment variable, digits only.
//
// Every compatibility flag below defaults to false, which is the secure behavior. The
// flags exist so that an existing deployment can keep an old behavior while it migrates:
// enable one only when you need it, and plan to turn it off again. The commented-out
// lines show each setting at its default. Some settings are not compatibility flags:
// max_passkeys_per_user and the sign-in rate limits are limits, and admin_require_mfa is
// opt-in hardening (true is the stricter behavior). OIDC_SCIM_ENCRYPTION_KEY is read only
// from the environment.
//
// Upgrade notes for this release:
// - Runtime data lives only in the data directory (config_dir below). See
//   KEY_STORAGE_MIGRATION.md, section 6, to move an old layout and for backups, and
//   htaccess.example for the web root .htaccess.
// - The admin console session cookie is now IDPSESSID (__Host-IDPSESSID over https), so
//   every admin signs in again once. Admin sessions end after 12 hours, after 30 minutes
//   without a request (sooner when session.gc_maxlifetime is shorter), and at once when
//   the admin's users.txt entry changes or is removed. PHP session files ("files" handler)
//   older than session.gc_maxlifetime are no longer resumed.
// - users.txt: an entry that starts with "$" is always a hash. bcrypt from any tool ($2y$,
//   $2a$, $2b$), SHA-crypt ($5$, $6$), MD5-crypt ($1$) and argon2 now verify. Apache $apr1$
//   does not (use htpasswd -nBC 12). A plaintext password that starts with "$" no longer
//   works and must be replaced by a hash. Other plaintext entries are now refused unless
//   allow_plaintext_admin_passwords is on; write hashes with
//   php index.php hash-admin-password <username> (see allow_plaintext_admin_passwords).
// - Over https the end-user SSO cookie is now __Host-idp_sso_<hash> (Secure, host-only,
//   Path=/), so users sign in to each provider again once. A request that carries more
//   than one cookie mapping to that name (duplicates or look-alikes such as
//   idp.sso_<hash>) is treated as having no SSO session. Logout deletes every SSO session
//   the browser sent. The sign-in transaction-binding cookie (__Host-idp_txb) is now
//   SameSite=None; Secure over https, so cross-site SAML and OIDC POST starts no longer
//   break other sign-ins in progress.
// - Outbound SCIM password push: deployments that push passwords with scim_master.key must
//   set allow_password_push_with_key_file, or OIDC_SCIM_ENCRYPTION_KEY, before upgrading.
//   Otherwise the stored password copies are cleared on the first web request, and each
//   password is pushed again only after its user sets a new one.
// - Existing Admin API clients lose can_mint_tokens: re-grant it per client in the
//   console, or set legacy_api_client_token_minting for a while.
// - End-user sign-in is now also rate-limited per client network (see "Sign-in rate
//   limits" below). Behind a reverse proxy, list it in trusted_proxies, otherwise every
//   client shares one network's allowance. Where many users really share one address (a
//   corporate NAT), raise the limits.
// - Directory user passwords set through the Admin API, the console or inbound SCIM must now
//   meet a minimum policy (see allow_weak_directory_passwords); weaker ones get 400.
// - Entries below with an "Upgrade note" describe further changes that existing
//   deployments notice: legacy_saml_persistent_ids, scim_ignore_if_match,
//   scim_outbound_omit_empty_attributes and allow_weak_directory_passwords.

return [
    // ---------- Storage ----------

    // config_dir (env OIDC_CONFIG_DIR, legacy alias CONFIG_DIR)
    // Directory where keys, users, providers, sessions and other runtime data are stored.
    // It must be outside the web root and writable by the PHP process.
    // Default: a sibling folder named "<project-folder>_config/".
    // The directory is created with mode 0700 when it is missing. Bootstrap refuses to
    // start (HTTP 500, reason in the error log) when it cannot be created, is not writable,
    // or lies inside the project folder or the web server's document root (see
    // allow_webroot_data_dir). Set it to a real path or leave the line commented out: an
    // unedited placeholder such as "/path/to/your/oidc_config/" cannot be created, so the
    // install would refuse to start.
    // With PHP's "files" session handler, sessions are kept in <config_dir>/sessions (mode
    // 0700) instead of php.ini's session.save_path. When php.ini points error_log inside the
    // web root, PHP's error log moves to <config_dir>/php-error.log.
    // The environment-only settings OIDC_USERS_FILE, OIDC_STORAGE_FILE, OIDC_KEYS_DIR and
    // OIDC_APIKEYS_FILE can move single files; the same web-root rule applies to them.
    // "config_dir" => "/path/to/your/oidc_config/",

    // allow_webroot_data_dir (env OIDC_ALLOW_WEBROOT_DATA_DIR; default: false)
    // Secure default: there is no fallback to <project-folder>/.data, users.txt,
    // providers.sqlite, keys/ and api_keys.sqlite are no longer looked up in the project
    // folder, and data paths inside the web root are refused. A "deny all" .htaccess is
    // written into every data and session directory the app creates. With the default,
    // leftovers of the old layout in the project folder (.data/, keys/, users.txt,
    // providers.sqlite, api_keys.sqlite, scim_master.key) are reported in the PHP error log
    // at most once an hour, and .data/ and keys/ get a deny-all .htaccess.
    // true restores: the silent fallback to <project-folder>/.data, the project-folder
    // lookups of users.txt, providers.sqlite, keys/ and api_keys.sqlite, and data paths
    // inside the web root (the deny .htaccess is still written). Meant only for existing
    // installs whose data still lives in <project-folder>/.data, until it is moved.
    // Risk: signing keys, the vault key and users.txt are downloadable if .htaccess is ignored.
    // "allow_webroot_data_dir" => false,

    // ---------- Base URL, hosts and proxies ----------

    // public_base_url (env OIDC_PUBLIC_BASE_URL, legacy alias PUBLIC_BASE_URL; default: unset)
    // Recommended for every production deployment. Fixes the scheme, host, port and path
    // of the issuer/base URL (and with it the SAML entity IDs and the WebAuthn rpId); the
    // Host header is then ignored. An https:// value also makes the session and SSO
    // cookies Secure (with the __Host- prefix), enables HSTS behind TLS-offloading proxies
    // and redirects or refuses requests that reach PHP over plain HTTP (see
    // allow_plain_http_requests). /api/https-ca uses its host.
    // It must be an absolute http:// or https:// URL without user name, password, query or
    // fragment. Any other value makes every request fail with HTTP 500 (the reason is in the
    // error log).
    // Unset: the base URL is derived from each request, restricted by allowed_hosts.
    // Risk (unset): the base URL follows the Host header, limited only by allowed_hosts.
    // "public_base_url" => null, // for example "https://idp.example.com"

    // allowed_hosts (env OIDC_ALLOWED_HOSTS; default: empty list)
    // Applies only when public_base_url is unset. The Host header (port ignored,
    // case-insensitive) must be localhost, 127.0.0.1, ::1 or match an entry: an exact host
    // name or IP address, or a wildcard such as "*.example.com", which matches subdomains at
    // any depth (a.example.com, a.b.example.com) but not example.com itself. Any other Host
    // gets 421 Misdirected Request before a session or other state is created, so the
    // issuer, entity IDs, playground redirect URIs and the WebAuthn rpId are never taken
    // from an arbitrary Host header. Command-line runs are exempt. Load-balancer health
    // checks that use an IP address or an internal host name also get 421: set
    // public_base_url, or list that host here.
    // "*" restores: the old behavior, where any syntactically valid Host header becomes
    // the base URL/issuer. Setting public_base_url is the recommended fix instead.
    // Risk ("*"): a forged Host header picks the issuer, entity IDs, redirect URIs and rpId.
    // "allowed_hosts" => [], // for example ["idp.example.com", "*.idp.example.com"]

    // trusted_proxies (env OIDC_TRUSTED_PROXIES; default: empty list)
    // IP addresses or CIDR ranges (IPv4 and IPv6) of your reverse proxies. Only when
    // REMOTE_ADDR is in this list is X-Forwarded-For used for the client IP: the
    // right-most hop that is not itself a trusted proxy; if a hop checked on the way is
    // not a valid IP address, REMOTE_ADDR is used. Listed peers are also trusted for
    // X-Forwarded-Proto. Rate limits and audit IPs then identify the real clients behind
    // the proxy.
    // Empty: REMOTE_ADDR stays the client IP, so behind a proxy every client shares one
    // rate-limit bucket, including the sign-in rate limits below.
    // Risk: a listed address that is not a proxy can forge X-Forwarded-For past rate limits.
    // "trusted_proxies" => [], // for example ["10.0.0.5", "fd00:1::/64"]

    // trust_proxy (env OIDC_TRUST_PROXY; default: false)
    // true trusts X-Forwarded-Proto from any peer, as before. It never enables
    // X-Forwarded-For; use trusted_proxies for that. Requests from a loopback peer are
    // trusted for X-Forwarded-Proto either way, but not for X-Forwarded-For.
    // Risk: any client that can reach PHP directly can claim that its request used HTTPS.
    // "trust_proxy" => false,

    // allow_plain_http_requests (env OIDC_ALLOW_PLAIN_HTTP_REQUESTS; default: false)
    // Secure default: when public_base_url is https, a request that reaches PHP over plain
    // HTTP is answered before any session or other state is created. GET and HEAD get a 301
    // to the same path and query on the https public base URL; every other method gets a
    // 403, so credentials sent over HTTP are not processed. Requests that show TLS ended at
    // a proxy in front of PHP are processed normally, also from peers outside
    // trusted_proxies, so TLS offloading cannot loop. The proxy signs are: X-Forwarded-Proto
    // https on any hop; X-Forwarded-Scheme, X-Url-Scheme or CloudFront-Forwarded-Proto
    // https; X-Forwarded-Ssl or Front-End-Https on; Forwarded proto=https; REQUEST_SCHEME
    // https. These headers never make a request count as HTTPS. Load-balancer health checks
    // over plain HTTP also get the 301. Command-line runs are exempt.
    // true restores: processing plain-HTTP requests, for TLS-terminating proxies that send
    // none of these headers (better: make the proxy send X-Forwarded-Proto: https).
    // Risk: passwords, tokens and session cookies are sent and accepted over unencrypted HTTP.
    // "allow_plain_http_requests" => false,

    // ---------- Protocol compatibility flags ----------

    // allow_insecure_http_endpoints (env OIDC_ALLOW_INSECURE_HTTP_ENDPOINTS; default: false)
    // Secure default: SAML ACS URLs, ACS endpoint locations and SLO URLs, and OIDC
    // redirect, post-logout and initiate-login URIs must use https://, unless the host is
    // localhost, in 127.0.0.0/8 or ::1. This is checked when an app is saved and again on
    // every request, so stored http:// endpoints stop receiving assertions, codes and
    // tokens; implicit, hybrid and form_post delivery to http:// hosts is impossible.
    // true restores: http:// endpoints on any host. Fragments stay forbidden.
    // Risk: assertions, authorization codes and tokens cross the network in clear text.
    // "allow_insecure_http_endpoints" => false,

    // legacy_admin_api_key (env OIDC_LEGACY_ADMIN_API_KEY; default: false)
    // Secure default: the plaintext per-admin legacy API key is retired. /api/login and
    // /api/me no longer create or return "apiKey". POST /api/token no longer accepts
    // legacy keys through "Authorization: ApiKey" or X-API-Key; it authenticates a console
    // session (with CSRF token) or a scoped Admin API client. Existing api_keys rows stay
    // but are unused.
    // true restores: creating and returning the legacy key in /api/login and /api/me, and
    // accepting it at /api/token. The key owner must still exist in users.txt, which is
    // re-checked on every use.
    // Risk: a key that never expires or rotates gives whoever holds it that admin's access.
    // "legacy_admin_api_key" => false,

    // legacy_token_claims (env OIDC_LEGACY_TOKEN_CLAIMS; default: false)
    // Secure default: ID tokens and userinfo release claims only for granted scopes:
    // openid gives sub; profile gives name, given_name, family_name and
    // preferred_username; email gives email and email_verified; phone gives phone_number;
    // groups gives groups. Custom directory attributes are not copied into tokens,
    // email_verified reflects the stored per-user flag, and attributes and client
    // custom_claims cannot override standard or reserved claims. Access tokens follow
    // RFC 9068: typ "at+jwt", aud = the provider issuer, a client_id claim, and minimal
    // claims with no profile data or PII. A client's admin-configured custom_claims (static
    // values set per client) are still added to its access tokens and ID tokens, but can
    // never override standard or protocol claims.
    // true restores: the old token contents. scope=openid alone, and every other token,
    // carries the full profile, groups and all custom attributes; email_verified is always
    // true; access tokens use typ "JWT", aud = client_id and the full identity claim set.
    // Risk: PII reaches every relying party regardless of scope; access tokens pass as ID tokens.
    // "legacy_token_claims" => false,

    // legacy_oauth_flows (env OIDC_LEGACY_OAUTH_FLOWS; default: false)
    // Secure default: each client's registered grant_types are enforced at /authorize and
    // /token. "authorization_code" is required for code and hybrid flows, "implicit" for
    // any response_type containing token or id_token, "refresh_token" to issue or redeem
    // refresh tokens (offline_access alone no longer forces one), and
    // "client_credentials" for that grant. PKCE: a code_verifier sent for a code issued
    // without a challenge is rejected, public and require_pkce clients must use S256,
    // challenge and verifier syntax is validated, and the API default for require_pkce
    // is true.
    // true restores: the old leniency. Any client may use implicit/hybrid, refresh tokens
    // and (if confidential) client_credentials regardless of grant_types; "plain" PKCE is
    // accepted for every client, and a verifier sent without a stored challenge is
    // ignored.
    // Not changed by the flag: the API default for require_pkce stays true (an explicit
    // false is still honored), and the client_credentials scope syntax (RFC 6749 section
    // 3.3, at most 1024 bytes) is always validated.
    // Risk: tokens in URL fragments, refresh tokens for any client, and PKCE downgrade.
    // "legacy_oauth_flows" => false,

    // legacy_logout_redirect (env OIDC_LEGACY_LOGOUT_REDIRECT; default: false)
    // Secure default: an RP-initiated logout (/oauth2/logout) returns the browser to its
    // post_logout_redirect_uri only when a verified id_token_hint or a client_id names the
    // client, and that client registered the URI exactly. A logout that names neither ends
    // on the App Launchpad: after the user confirms, or at once when there is no SSO
    // session.
    // true restores: the old fallback for such requests, where a URI registered by any
    // client of the provider is accepted.
    // Risk: one client's logout can send the user to another client's registered URI.
    // "legacy_logout_redirect" => false,

    // legacy_saml_compat (env OIDC_LEGACY_SAML_COMPAT; default: false)
    // Secure default: AuthnContextClassRef reflects how the user actually authenticated
    // (PasswordProtectedTransport for a password only, REFEDS MFA for password plus
    // passkey). RequestedAuthnContext is enforced: the IdP steps up or answers
    // Responder/NoAuthnContext. A NameIDPolicy Format is honored only if the app allows
    // it (an empty list means [configured format, unspecified]); otherwise the answer is
    // InvalidNameIDPolicy. NameID formats are matched by their exact URI, and a NameID
    // value that is not an email address is sent with the unspecified format, never
    // labelled emailAddress. AuthnRequests need an ID, Version="2.0" and an IssueInstant
    // within 5 minutes; signature-verified requests are replay-checked and must carry a
    // Destination. A non-POST ProtocolBinding or an unknown ACS index is an error.
    // true restores: the old interop behavior. A fixed PasswordProtectedTransport with
    // RequestedAuthnContext ignored, any requested NameIDPolicy Format honored when the
    // supported list is empty, a non-email NameID value keeping the emailAddress label,
    // the old substring matching of the transient and persistent formats, and no
    // ID-presence, Version, IssueInstant, replay, Destination-presence, ProtocolBinding or
    // ACS-index checks (an unknown index falls back to the default ACS).
    // Not changed by the flag: a Destination that is present but does not match is always
    // rejected, replay detection only ever applies to signature-verified AuthnRequests, and
    // the accurate AuthnInstant and SessionNotOnOrAfter are kept.
    // Risk: SPs cannot trust the reported MFA, and replayed or misdirected requests pass.
    // "legacy_saml_compat" => false,

    // legacy_saml_persistent_ids (env OIDC_LEGACY_SAML_PERSISTENT_IDS; default: false)
    // Secure default: every app's persistent (pairwise) SAML NameIDs are HMAC-SHA256 under a
    // per-provider key stored in the database (table saml_pairwise_secrets, so it is in
    // providers.sqlite backups). SCIM clients, outbound SCIM targets and SPs that learn a
    // user's internal id cannot compute that user's NameID at other SPs, and the value does
    // not depend on the Host header.
    // true restores: apps saved before this release (persistent_id_scheme "legacy") keep
    // the old unkeyed SHA-256 of IdP entity ID | SP entity ID | user id, so accounts their
    // SPs linked by NameID stay linked. To migrate an app, switch it to HMAC in the console
    // (or send persistent_id_scheme "hmac"); every user then gets a new NameID at that SP.
    // Turn the flag off once all apps are migrated.
    // Not changed by the flag: new apps default to "hmac". While the flag is off, "legacy"
    // cannot be chosen for an app that does not already have it.
    // Upgrade note: without the flag, SPs of existing apps that use persistent NameIDs see
    // a new NameID for every user at the first sign-in after the upgrade.
    // Risk: anyone who knows a user's internal id can compute that user's NameID at every
    // legacy app.
    // "legacy_saml_persistent_ids" => false,

    // legacy_attribute_split (env OIDC_LEGACY_ATTRIBUTE_SPLIT; default: false)
    // Secure default: a custom attribute stored as one string is one SAML AttributeValue,
    // even when it contains commas (for example "Director, Sales" or an LDAP DN). Store
    // multi-valued attributes as arrays.
    // true restores: a string that contains a comma is split on commas and line breaks,
    // the parts are trimmed and de-duplicated, and each becomes its own AttributeValue.
    // Meant for deployments that stored multi-valued attributes (such as roles) as
    // comma-separated strings through the API.
    // Risk: single values that contain commas reach SPs as several values.
    // "legacy_attribute_split" => false,

    // ---------- Account security flags and limits ----------

    // allow_first_use_passkey_enrollment (env OIDC_ALLOW_FIRST_USE_PASSKEY_ENROLLMENT;
    // default: false)
    // Secure default: a passkey can be added only through an admin-issued /enroll link, or
    // from the portal by a user who already has a passkey and re-authenticated with it in
    // the last 300 seconds. Inline enrollment at MFA step 2 is refused, so a password
    // alone can never satisfy the mfa or touchid_only policies.
    // true restores: self-service enrollment of the first passkey for users who have none,
    // inline at MFA step 2 after the password (completing the login as before) and from
    // the portal with a password session younger than 300 seconds. Users who already have
    // a passkey stay blocked.
    // Risk: a stolen password lets an attacker add their own passkey and pass MFA as the user.
    // "allow_first_use_passkey_enrollment" => false,

    // max_passkeys_per_user (env OIDC_MAX_PASSKEYS_PER_USER; default: 20)
    // A limit, not a compatibility flag: the most passkeys (WebAuthn credentials) one
    // directory user may have, counted over all RP IDs. Registration options and
    // verification refuse more with an error asking to remove an unused passkey; existing
    // passkeys keep working. Whole number, clamped to 1..50 (50 is the most credentials
    // listed in WebAuthn options); any other value is logged and the default of 20 is used.
    // Risk (higher values): every passkey is carried in the user's directory record and in
    // WebAuthn options, so each one makes user listings, syncs and sign-in options larger.
    // "max_passkeys_per_user" => 20,

    // allow_weak_directory_passwords (env OIDC_ALLOW_WEAK_DIRECTORY_PASSWORDS; default: false)
    // Secure default: a password given to a directory user through the Admin API, the console
    // or inbound SCIM (create, PUT, PATCH) must have at least 12 characters and must not be one
    // repeated character, a common password, or the user's username, email or the part of the
    // email before "@" (compared case-insensitively). Otherwise the request fails with 400,
    // also when a SCIM client resends the unchanged stored password with an update.
    // true restores: any non-empty password, for legacy imports and SCIM clients that sync
    // passwords from a directory with a weaker policy.
    // Upgrade note: provisioning clients and scripts that set or resend weak passwords get 400
    // for those users (including attribute-only PUTs) until the password is changed or this
    // flag is set.
    // Risk: weak directory passwords; the sign-in rate limits become the only protection
    // against guessing them.
    // "allow_weak_directory_passwords" => false,

    // ---------- Sign-in rate limits ----------
    // Limits, not compatibility flags. The hosted sign-in counts failed passwords and
    // sign-in requests per client network, so that one network can neither try a common
    // password against many accounts nor flood the IdP with sign-in requests. A refused
    // request gets HTTP 429 with Retry-After. The per-account password limits always apply
    // and are not configurable.
    // Each limit takes a whole number from 0 to 1000000 (larger values count as 1000000);
    // 0 turns that limit off. Any other value (negative, fractional, not a number) is
    // logged and the default is used.
    // Behind a reverse proxy, list the proxy in trusted_proxies so that these limits apply
    // per real client network. Until then every client has the proxy's address and all of
    // them share one allowance; the PHP error log says so when a limit runs out for
    // requests that a private or loopback address forwarded with X-Forwarded-For. Where
    // many users really share one address, such as a corporate NAT or an outbound web
    // proxy, raise the limits rather than turning them off.

    // signin_network_password_failures (env OIDC_SIGNIN_NETWORK_PASSWORD_FAILURES;
    // default: 50)
    // Failed password sign-ins that one client network (an IPv4 address or an IPv6 /48)
    // may have within 5 minutes across all accounts of one administrator's user directory
    // (unknown user names included), which all of that administrator's providers share.
    // Then password sign-in from that network is refused for 5 minutes, except in browsers
    // that signed in to the account before (known devices). This stops password spraying.
    // Passkey sign-in is not affected.
    // Risk (higher values or 0): one network can try common passwords against more
    // accounts before it is stopped.
    // "signin_network_password_failures" => 50,

    // signin_network_tx_per_minute (env OIDC_SIGNIN_NETWORK_TX_PER_MINUTE; default: 300)
    // Sign-in requests per minute that browsers without an SSO session may send from one
    // client network (an IPv4 address or an IPv6 /64) to one provider: requests that start
    // a sign-in, such as OIDC authorization requests, SAML AuthnRequests and opening the
    // sign-in page, and, counted apart with the same allowance, the SAML messages
    // (AuthnRequest, LogoutRequest) the IdP decodes. Beyond it, the network's requests to
    // that provider are refused for a minute. 0 turns it off, and while
    // signin_network_tx_per_minute_all is unset also the limit across providers, for a
    // deployment that limits these requests in front of PHP.
    // Risk (higher values or 0): one network can store more sign-in transactions and have
    // more SAML messages parsed, which slows sign-in for every provider.
    // "signin_network_tx_per_minute" => 300,

    // signin_network_tx_per_minute_all (env OIDC_SIGNIN_NETWORK_TX_PER_MINUTE_ALL;
    // default: twice signin_network_tx_per_minute, 600 with its default)
    // The same requests per minute per client network across all providers, so that
    // sending them to many providers does not multiply a network's allowance. A request
    // must stay within both limits; while this one is unset it follows
    // signin_network_tx_per_minute, so raising that one is enough. 0 turns it off.
    // Risk (higher values or 0): as for signin_network_tx_per_minute, with the requests
    // spread over many providers.
    // "signin_network_tx_per_minute_all" => 600,

    // signin_user_tx_per_minute (env OIDC_SIGNIN_USER_TX_PER_MINUTE; default: 60)
    // The same requests per minute from browsers that have an SSO session with the
    // provider, counted per user (across all of the user's sessions and the
    // administrator's providers) instead of per network, so that requests of signed-in
    // users do not count against their network's allowance. Beyond it, the user's requests
    // are refused for a minute. 0 turns it off, and signed-in users are then not limited.
    // Risk (higher values or 0): one signed-in user can store more sign-in transactions
    // and have more SAML messages parsed.
    // "signin_user_tx_per_minute" => 60,

    // ---------- Admin console flags ----------

    // allow_plaintext_admin_passwords (env OIDC_ALLOW_PLAINTEXT_ADMIN_PASSWORDS;
    // default: false)
    // Secure default: users.txt entries (one "username:hash" line per administrator) must
    // be password hashes. A value that starts with "$" is only ever checked with
    // password_verify() (bcrypt $2y$/$2a$/$2b$/$2x$, argon2, SHA-crypt $5$/$6$, MD5-crypt
    // $1$). A hash format PHP cannot verify, such as Apache $apr1$, is refused with an
    // error_log line and never compared as plaintext. A plaintext entry is refused, and the
    // error_log line names the admin. To write a users.txt line, run
    //   php index.php hash-admin-password <username>
    // as the web server user (like scim-sync): it reads the password (at least 12
    // characters) from standard input, on a terminal twice and without echo, and prints
    // "<username>:<hash>". A bare hash of a password typed on standard input:
    //   php -r 'echo password_hash(rtrim(fgets(STDIN), "\r\n"), PASSWORD_DEFAULT), PHP_EOL;'
    // true restores: plaintext entries of at least 12 characters (shorter ones stay
    // refused); every sign-in with one logs a warning.
    // Risk: a leaked users.txt gives working admin passwords.
    // "allow_plaintext_admin_passwords" => false,

    // admin_require_mfa (env OIDC_ADMIN_REQUIRE_MFA; default: false)
    // Opt-in hardening, not a compatibility flag. Default: administrators may set up an
    // authenticator app (TOTP, RFC 6238) through /api/admin-mfa; once it is confirmed, every
    // console sign-in of that admin needs its code ("otp" at POST /api/login).
    // true requires an app for every administrator: an admin without one gets a new secret
    // at the next sign-in (401 with mfa_enrollment_required) and signs in with its first
    // code. The console sign-in form asks for the code and, for an admin without an app, shows
    // the new secret and otpauth URI at that sign-in; admins can also set up or remove their
    // app from the console.
    // The app secrets are encrypted with the vault key (see OIDC_SCIM_ENCRYPTION_KEY below),
    // so back it up with the database. Lost app: the operator deletes the admin's row from
    // the admin_mfa_totp table (DELETE FROM admin_mfa_totp WHERE username = '<admin>').
    // Risk (false): administrators without an app sign in with a password alone.
    // "admin_require_mfa" => false,

    // allow_unverified_cdn_assets (env OIDC_ALLOW_UNVERIFIED_CDN_ASSETS; default: false)
    // Secure default: the admin console loads its third-party unpkg scripts only when every
    // one has a well-formed Subresource Integrity value in admin_spa_script_assets()
    // (src/admin_spa.php). While one is missing, none is loaded: the console page does not
    // start and says why, and the PHP error log says so at most once an hour. The public
    // API reference /api/docs does the same with its Swagger UI files
    // (openapi_docs_assets() in src/openapi.php): without them it offers only the raw
    // openapi.json.
    // true restores: loading files that have no integrity value, unchecked (the old
    // behavior), on both pages; that is still logged at most once an hour. Meant only until
    // the missing sha384 values are filled in.
    // Risk: a compromised CDN runs code with the session and CSRF token of every admin who
    // opens the console or /api/docs.
    // "allow_unverified_cdn_assets" => false,

    // ---------- Admin API flags ----------

    // legacy_api_client_token_minting (env OIDC_LEGACY_API_CLIENT_TOKEN_MINTING;
    // default: false)
    // Secure default: an Admin API client may mint JWTs at POST /api/token, import private
    // signing keys (keyMode "paste") and manage OIDC clients that can use the
    // client_credentials grant only with can_mint_tokens, which a console admin grants per
    // client. Clients that existed before this release are migrated with it off.
    // true restores: the old rule, where provider write permission alone allows all of this
    // and can_mint_tokens is ignored.
    // Upgrade note: re-grant can_mint_tokens in the console to automation that mints tokens.
    // Risk: any provider-write credential can forge tokens signed by the provider.
    // "legacy_api_client_token_minting" => false,

    // legacy_workload_tokens (env OIDC_LEGACY_WORKLOAD_TOKENS; default: false)
    // Secure default: workload JWTs from POST /api/token carry the JOSE typ "workload+jwt"
    // and live at most 24 hours (a longer ttl gets 400). Identity and access-token claims
    // in "extra" are dropped and listed in ignored_claims: client_id, scope, name,
    // given_name, family_name, preferred_username, email, email_verified, phone_number,
    // groups. An aud equal to the provider's issuer or to one of its OIDC client_ids is
    // refused with 400.
    // true restores: typ "JWT", TTLs up to 365 days, those claims and any audience.
    // Risk: a minted token can pass as one of the provider's ID or access tokens for up to
    // a year.
    // "legacy_workload_tokens" => false,

    // legacy_provider_id_format (env OIDC_LEGACY_PROVIDER_ID_FORMAT; default: false)
    // Secure default: a new provider's idpId (part of its issuer and endpoint URLs) is
    // <owner>-<name>, rawurlencoded, with every "-" of the name replaced by "_". The owner
    // is then always the part before the last "-", and no administrator can create the ID
    // that another administrator's provider name would produce. Existing providers keep
    // their IDs.
    // true restores: IDs that keep "-" in the name, so admin "acme" can again take
    // "acme-eu-prod", the ID admin "acme-eu" would get for "prod". The global uniqueness
    // check, which ignores case and percent-encoding, still applies.
    // Risk: cross-tenant pre-claiming of provider URLs.
    // "legacy_provider_id_format" => false,

    // ---------- Outbound SCIM password push ----------
    // A connector with push_passwords sends each directory user's password to its target,
    // so the IdP keeps a recoverable copy of the password (idp_users.password_enc),
    // encrypted with the vault key.
    //
    // OIDC_SCIM_ENCRYPTION_KEY (environment variable only, never read from this file;
    // default: unset)
    // Holds the vault key outside the data directory. The vault encrypts the outbound SCIM
    // connector tokens, the administrators' authenticator app secrets and the password
    // copies. Unset: the vault key is scim_master.key next to providers.sqlite, so a copy
    // of the data directory includes it. Set: new secrets are encrypted under a key derived
    // from the value, and scim_master.key still opens the secrets stored before. Use a long
    // random value (for example: openssl rand -base64 32) and keep it with your backups:
    // changing or losing it makes the secrets stored under it unreadable. Password push
    // needs it, unless allow_password_push_with_key_file is on. Give the web server and the
    // scim-sync cron job the same value.

    // allow_password_push_with_key_file (env OIDC_ALLOW_PASSWORD_PUSH_WITH_KEY_FILE;
    // default: false)
    // Secure default: password push needs OIDC_SCIM_ENCRYPTION_KEY. With only
    // scim_master.key, which sits next to providers.sqlite, push_passwords cannot be
    // enabled on a connector (400), no password copy is stored, and stored copies are not
    // pushed. Whatever the flag says, a copy is kept only while the owner has a
    // push_passwords connector, so only passwords set or changed while such a connector
    // exists are pushed; the copies are deleted when the owner's last such connector is
    // turned off or deleted.
    // true restores: password push, and the copies it needs, with the key file.
    // Upgrade note: without this flag and without OIDC_SCIM_ENCRYPTION_KEY, password push
    // is off, and the first web request after the upgrade deletes every stored password
    // copy (older releases kept one for every user). If connectors push passwords, set the
    // flag or OIDC_SCIM_ENCRYPTION_KEY before upgrading. With OIDC_SCIM_ENCRYPTION_KEY set,
    // the scim_master.key copies of owners with a push connector are re-encrypted under it.
    // Turning the flag off again, or changing OIDC_SCIM_ENCRYPTION_KEY to another value,
    // deletes the copies the new policy does not allow; copies under another environment
    // key cannot be opened. A deleted copy is pushed again only after its user sets a new
    // password.
    // Cron: php index.php scim-sync has its own environment. Give it the same
    // OIDC_SCIM_ENCRYPTION_KEY and flag, or set the flag in this file; a mismatch is logged.
    // Risk: a copy of the data directory (database plus scim_master.key) reveals every
    // pushed password.
    // "allow_password_push_with_key_file" => false,

    // allow_api_client_password_push (env OIDC_ALLOW_API_CLIENT_PASSWORD_PUSH; default: false)
    // Secure default: only an interactive console session may create an outbound SCIM
    // connector with push_passwords, enable push_passwords on one, or change a connector
    // that has or would get push_passwords. Such a connector sends every directory user's
    // plaintext password to the URL it names, which is more than user_scope grants. Admin
    // API clients get 403, even with provider write permission and user_scope "write".
    // true restores: Admin API clients with provider write permission and user_scope
    // "write" can create and change password-pushing connectors again.
    // Risk: a leaked automation credential can send every user's password to any host it
    // chooses.
    // "allow_api_client_password_push" => false,

    // ---------- Inbound SCIM (SCIM 2.0 server) flags ----------

    // scim_put_keeps_omitted_roles (env OIDC_SCIM_PUT_KEEPS_OMITTED_ROLES; default: false)
    // Secure default: a SCIM PUT /Users that omits roles, or sends roles: null, clears the
    // stored roles (a PUT replaces the resource, RFC 7644 section 3.5.1), so roles revoked
    // upstream leave the OIDC and SAML roles claims.
    // true restores: the old merge, where a PUT that omits roles keeps the stored roles (an
    // explicit roles: null still clears them). Use it only when roles are managed outside
    // SCIM.
    // Risk: a role revoked upstream stays in the roles claim.
    // "scim_put_keeps_omitted_roles" => false,

    // scim_put_keeps_omitted_attributes (env OIDC_SCIM_PUT_KEEPS_OMITTED_ATTRIBUTES;
    // default: false)
    // Secure default: a SCIM PUT replaces the resource (RFC 7644 section 3.5.1). PUT /Users
    // clears title, phoneNumbers and the enterprise fields (employeeNumber, costCenter,
    // organization, division, department, manager) that it leaves out or sends as null or
    // empty; an omitted or null enterprise extension clears all six. PUT /Groups without a
    // members attribute empties the group. Password, active, userName, emails, name,
    // displayName, externalId and admin-set custom attributes are kept when left out.
    // true restores: the old merge, where attributes left out keep their stored values and
    // PUT /Groups without members keeps the members. An explicit null still clears. Roles
    // keep their own flag, scim_put_keeps_omitted_roles, which this flag does not imply.
    // Risk: a title, department, manager, phone number or group membership revoked upstream
    // stays in claims, assertions and group-based access.
    // "scim_put_keeps_omitted_attributes" => false,

    // scim_ignore_if_match (env OIDC_SCIM_IGNORE_IF_MATCH; default: false)
    // Secure default: If-Match on PUT, PATCH and DELETE of /Users/{id} and /Groups/{id} is
    // enforced (weak comparison, "*" and lists accepted; 412 on mismatch, checked
    // atomically with the write), and If-None-Match on GET of a single user or group
    // answers 304.
    // true restores: ignoring both headers; /ServiceProviderConfig then reports
    // etag.supported=false.
    // Upgrade note: ETags are now content digests, so their values changed in this release.
    // A client that cached an ETag before the upgrade gets one 412 and must read the
    // resource again.
    // Risk: a client's conditional update built on a stale read silently overwrites a
    // concurrent change, for example re-adding a group member who was just removed.
    // "scim_ignore_if_match" => false,

    // ---------- Outbound SCIM flags ----------
    // Queued outbound syncs (direct-mode syncs that stopped at their 60-second budget)
    // continue on the next directory change, or from cron: run
    //   */5 * * * * php /path/to/index.php scim-sync
    // as the web server user, so the data directory and the vault key are readable. To push
    // stored password copies the job needs the web server's OIDC_SCIM_ENCRYPTION_KEY, and
    // allow_password_push_with_key_file when that is set in the environment.

    // scim_outbound_omit_empty_attributes (env OIDC_SCIM_OUTBOUND_OMIT_EMPTY_ATTRIBUTES;
    // default: false)
    // Secure default: outbound connector user payloads name every optional attribute,
    // sending roles: [], phoneNumbers: [], title: null and all six enterprise fields as
    // null, with the enterprise extension URN in schemas, so a target that merges on PUT
    // drops values removed in this IdP.
    // true restores: the old payloads, which leave empty attributes out, for targets that
    // reject null or empty values or the enterprise extension.
    // Upgrade note: the payload change alters each user's change hash, so after the upgrade
    // (and after each change of this flag) every connector PUTs all in-scope users once on
    // its next sync.
    // Risk: targets that merge on PUT keep roles and attributes that were removed here.
    // "scim_outbound_omit_empty_attributes" => false,

    // scim_allow_idp_host_targets (env OIDC_SCIM_ALLOW_IDP_HOST_TARGETS; default: false)
    // Secure default: an outbound SCIM connector may not target this IdP's own host name
    // (the host of public_base_url or of the request's base URL, Host header or
    // SERVER_NAME). This is checked when a connector is saved and again at every sync and
    // test.
    // true restores: connector URLs on the IdP's own host, for single-domain installs that
    // serve another SCIM application next to an IdP in a sub-path. The per-connector sync
    // lease and the 60-second budget still stop sync recursion. scim_allow_private_nets
    // implies this flag.
    // Risk: a connector can call the IdP itself and loop syncs.
    // "scim_allow_idp_host_targets" => false,

    // scim_allow_private_nets (env OIDC_SCIM_ALLOW_PRIVATE_NETS; default: false)
    // Lab and test networks only; it used to be environment-only and is now also read from
    // this file. Secure default: connector URLs must use https://, and every A and AAAA
    // answer for the host must be a public unicast address.
    // true allows: http:// connector URLs, private, loopback and reserved target addresses,
    // and the IdP's own host name. Never enable it in production.
    // Risk: server-side request forgery into internal networks and services.
    // "scim_allow_private_nets" => false,
];
