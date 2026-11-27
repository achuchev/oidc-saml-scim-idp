<?php
declare(strict_types=1);

/**
 * Third-party scripts of the admin console, pinned to exact versions so that a new npm
 * release is never picked up automatically (S14-05), in their order of loading. The page
 * CSP allows exactly the URLs that are loaded. "integrity" is the Subresource Integrity
 * value ("sha384-..."): the browser refuses a file that differs from the pinned one.
 * While any entry lacks a well-formed value, none of these scripts is loaded and the console
 * does not start (the page and the error log say why), unless allow_unverified_cdn_assets
 * restores loading them unchecked (render_admin_spa()).
 * Compute each value from the npm tarball, which npm checks against the registry's
 * dist.integrity, so the CDN is not trusted at that moment (the Babel value was computed
 * this way). The file is "package/" followed by the URL path after the version, e.g.
 *   npm pack react@18.3.1
 *   tar -xzOf react-18.3.1.tgz package/umd/react.production.min.js \
 *     | openssl dgst -sha384 -binary | openssl base64 -A
 * and prefix "sha384-".
 */
function admin_spa_script_assets(): array
{
    return [
        ["src" => "https://unpkg.com/react@18.3.1/umd/react.production.min.js", "integrity" => "sha384-DGyLxAyjq0f9SPpVevD6IgztCFlnMF6oW/XQGmfe+IsZ8TqEiDrcHkMLKI6fiB/Z"],
        ["src" => "https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js", "integrity" => "sha384-gTGxhz21lVGYNMcdJOyq01Edg0jhn/c22nsx0kyqP0TxaV5WVdsSH1fSDUf5YJj1"],
        ["src" => "https://unpkg.com/@babel/standalone@7.29.7/babel.min.js", "integrity" => "sha384-ezQ6HS3FLspd9te19o2McUV6FAK091+GG7KO54f/R8DKgCDi7fULhapNrd5LY+vG"],
        ["src" => "https://unpkg.com/@emotion/react@11.11.4/dist/emotion-react.umd.min.js", "integrity" => "sha384-CYVZQpDKfy7qnRQDs6nIwFRyC2Znf6G0o82AUG9bQ5PcR4AwAXSFZGjuLnsm2YNo"],
        ["src" => "https://unpkg.com/@emotion/styled@11.11.5/dist/emotion-styled.umd.min.js", "integrity" => "sha384-27HW+P9BGC+wKwxbt22bEhhKRPHVXHOgY47rrqL60BdQc217OFvJ806IHhYVogsW"],
        ["src" => "https://unpkg.com/@mui/material@5.15.14/umd/material-ui.production.min.js", "integrity" => "sha384-C1jZRQpcgcAFclz/eCOntp9Rs1moYZ1axTf9rL7aS3DQMSW3XESRolQKVUey9T3C"],
    ];
}

/**
 * True for a well-formed Subresource Integrity value: one or more whitespace-separated
 * sha256/sha384/sha512 hashes in base64 or base64url, each optionally followed by "?options"
 * (S14-05). A browser loads the file unchecked when the value holds no hash it can use, so
 * anything else counts as missing.
 */
function admin_spa_integrity_ok(string $integrity): bool
{
    $hash = 'sha(?:256|384|512)-[A-Za-z0-9+\/_-]+={0,2}(?:\?\S*)?';
    return preg_match('/^\s*' . $hash . '(?:\s+' . $hash . ')*\s*$/D', $integrity) === 1;
}

/**
 * Logs the console scripts that have no usable integrity value (S14-05), at most once an
 * hour (the mtime of a marker file in the data directory, as bootstrap.php does for legacy
 * data): GET / is public and often polled by health checks, so a line per request would
 * bury other errors. $loaded tells whether allow_unverified_cdn_assets let them load. Each
 * state has its own marker, so turning the flag on is logged at once even when the "cannot
 * start" line was logged a moment before.
 */
function admin_spa_warn_unchecked(array $urls, bool $loaded): void
{
    $configDir = $GLOBALS["CONFIG_DIR"] ?? null;
    if (is_string($configDir) && $configDir !== "") {
        $marker = path_join(
            $configDir,
            $loaded ? "admin-console-sri-unchecked.warned" : "admin-console-sri-withheld.warned"
        );
        $last = @filemtime($marker);
        if (is_int($last) && $last > time() - 3600) {
            return;
        }
        @touch($marker);
    }
    $list = implode(", ", $urls);
    error_log(
        $loaded
            ? "admin console: allow_unverified_cdn_assets (OIDC_ALLOW_UNVERIFIED_CDN_ASSETS) is on, so" .
                " browsers run these scripts without an integrity check: " . $list . ". Add their sha384" .
                " values to admin_spa_script_assets() in src/admin_spa.php."
            : "admin console cannot start: its CDN scripts are not loaded because these have no valid" .
                " Subresource Integrity value: " . $list . ". Add their sha384 values to" .
                " admin_spa_script_assets() in src/admin_spa.php, or set OIDC_ALLOW_UNVERIFIED_CDN_ASSETS" .
                " (allow_unverified_cdn_assets in config.php) to load them unchecked."
    );
}

/**
 * Content Security Policy of the console page (S14-05). Scripts run only from the pinned
 * URLs in $assets (those the page loads) or as inline scripts that carry this response's
 * nonce (the page bootstrap and the compiled console); no eval. Fetches go to this origin
 * only. Styles may be inline because MUI (Emotion) injects <style> elements at runtime.
 */
function admin_spa_csp(string $nonce, array $assets): string
{
    $scriptSources = ["'nonce-" . $nonce . "'"];
    foreach ($assets as $asset) {
        $scriptSources[] = (string) $asset["src"];
    }
    return implode("; ", [
        "default-src 'self'",
        "script-src " . implode(" ", $scriptSources),
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src https://fonts.gstatic.com",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]);
}

/**
 * Renders the admin console. $baseUrl is the public base URL of the install. Its path
 * prefixes the favicon link and is emitted as window.__BASE_PATH__ (S14-08). The console
 * normally takes its /api/... prefix from its own page path, because a proxy may add or strip
 * a prefix. It falls back to __BASE_PATH__ only for a page path of another form.
 */
function render_admin_spa(string $baseUrl = ""): never
{
    $basePath = rtrim((string) parse_url($baseUrl, PHP_URL_PATH), "/");
    $assets = admin_spa_script_assets();
    // S14-05: a script without a usable integrity value would run whatever the CDN serves,
    // with the session and CSRF token of the admin who opens the console. While any lacks
    // one, no third-party script is loaded at all (the console needs every one of them) and
    // the page says why, unless allow_unverified_cdn_assets restores the old, unchecked loading.
    $unchecked = [];
    foreach ($assets as $asset) {
        if (!admin_spa_integrity_ok((string) $asset["integrity"])) {
            $unchecked[] = (string) $asset["src"];
        }
    }
    $withheld = [];
    if ($unchecked !== []) {
        $loadUnchecked = config_flag("allow_unverified_cdn_assets", "OIDC_ALLOW_UNVERIFIED_CDN_ASSETS");
        admin_spa_warn_unchecked($unchecked, $loadUnchecked);
        if (!$loadUnchecked) {
            $withheld = $unchecked;
            $assets = [];
        }
    }
    $nonce = base64url_encode(random_bytes(18));
    send_security_headers(true);
    // Replaces the generic HTML policy sent above with the console's own.
    header("Content-Security-Policy: " . admin_spa_csp($nonce, $assets));
    header("Content-Type: text/html; charset=utf-8");
    header("Cache-Control: no-store, no-cache, must-revalidate");
    // The session's token while an admin is signed in, otherwise "" without starting a session
    // (G1c-06): an anonymous visit creates no session file. /api/login needs no token and
    // returns one, which apiFetch() adopts.
    $initialCsrf = safe_json_for_script(admin_console_csrf_token());
    $basePathJs = safe_json_for_script($basePath);
    $nonceJs = safe_json_for_script($nonce);
    $nonceAttr = html_escape($nonce);
    $withheldJs = safe_json_for_script($withheld);
    ?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Identity Cloud Console — OIDC 1.0, SAML 2.0 &amp; Touch ID</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <link rel="icon" type="image/x-icon" href="<?= html_escape($basePath) ?>/favicon.ico">
<?php foreach ($assets as $asset): ?>
  <script src="<?= html_escape((string) $asset["src"]) ?>" crossorigin="anonymous"<?= (string) $asset["integrity"] !== "" ? ' integrity="' . html_escape((string) $asset["integrity"]) . '"' : "" ?>></script>
<?php endforeach; ?>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap" />
  <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" />
  <style>
    * { box-sizing: border-box; }
    html, body { margin: 0; padding: 0; min-height: 100vh; -webkit-font-smoothing: antialiased; }
    code, pre, .mono { font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .mi {
      font-family: 'Material Icons Round';
      font-weight: normal;
      font-style: normal;
      font-size: 20px;
      line-height: 1;
      letter-spacing: normal;
      text-transform: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      white-space: nowrap;
      word-wrap: normal;
      direction: ltr;
      -webkit-font-smoothing: antialiased;
      user-select: none;
    }
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-thumb { background: rgba(148, 163, 184, 0.35); border-radius: 999px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(148, 163, 184, 0.55); }
    @keyframes fadeSlideUp {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .fade-in { animation: fadeSlideUp 0.22s cubic-bezier(0.16, 1, 0.3, 1) both; }
  </style>
</head>
<body>
<div id="app"></div>
<div id="diagnostics" style="color:#ef4444;font-family:monospace;margin:1em;display:none;"></div>
<script nonce="<?= $nonceAttr ?>">
window.__CSRF_TOKEN__ = <?= $initialCsrf ?>;
window.__BASE_PATH__ = <?= $basePathJs ?>;
window.onerror = function(msg, url, line, col) {
  var diag = document.getElementById('diagnostics');
  if (diag) {
    diag.style.display = 'block';
    diag.textContent = 'JS Error: ' + msg + ' at ' + url + ':' + line + ':' + col;
  }
};
function showDiagnostic(msg) {
  var diag = document.getElementById('diagnostics');
  if (diag) {
    diag.style.display = 'block';
    diag.textContent = msg;
  }
}
// A script that the page's security policy blocks never reaches window.onerror, so the page
// would stay blank with no hint (S14-05). Blocks are reported until the console has started.
// Blocked eval is left out (libraries probe for it and fall back), and so are browser
// extensions.
window.__ADMIN_CONSOLE_STARTED__ = false;
document.addEventListener('securitypolicyviolation', function (ev) {
  if (!ev || window.__ADMIN_CONSOLE_STARTED__ || (ev.disposition && ev.disposition !== 'enforce')) return;
  var directive = String(ev.effectiveDirective || ev.violatedDirective || '');
  var blocked = String(ev.blockedURI || '');
  var extension = /^[a-z-]*-extension:/i;
  if (directive.indexOf('script-src') !== 0 || blocked === 'eval' || blocked === 'wasm-eval' ||
      extension.test(blocked) || extension.test(String(ev.sourceFile || ''))) return;
  showDiagnostic('The page security policy (' + directive + ') blocked ' +
    (!blocked || blocked === 'inline' ? 'an inline script' : blocked) +
    '. Reload the page. If this keeps happening, check for a proxy or browser extension that rewrites the page.');
});
// Backstop for failed requests that nothing handled: shown as an error toast (S13-08).
window.addEventListener('unhandledrejection', function (ev) {
  var r = ev ? ev.reason : null;
  var msg = (r && (r.error || r.message)) || String(r || 'Unexpected error');
  window.dispatchEvent(new CustomEvent('idp:notify', { detail: { message: String(msg), severity: 'error' } }));
});
</script>
<!-- The console source. It is not run as it stands: the script after it compiles it with
     Babel and runs the result as a script that carries this page's CSP nonce (S14-05). -->
<script type="text/x-admin-console-jsx" id="admin-console-src">
const { useState, useEffect, useMemo } = React;
const {
  ThemeProvider, createTheme, CssBaseline, Link, Box, Button, TextField,
  Typography, Paper, Dialog, DialogTitle, DialogContent, DialogActions,
  MenuItem, Snackbar, Alert, Grid, IconButton, InputAdornment, Collapse,
  RadioGroup, FormControl, FormLabel, Radio, Tooltip, FormControlLabel,
  Checkbox, Tabs, Tab, Chip, Divider, Table, TableHead, TableRow, TableCell,
  TableBody, Drawer, Avatar, useMediaQuery
} = MaterialUI;

// Path prefix of the install (subdirectory or proxy prefix) (S14-08). The console is served at
// <prefix>/ and <prefix>/index.php with the API next to it, so the page's own path gives the
// prefix, also behind a proxy that adds or strips one. The path of the server's base URL
// (window.__BASE_PATH__) is used only for a page path of any other form.
const SCRIPT_DIR = (() => {
  const m = /^(.*?)\/(?:index\.php)?$/i.exec(window.location.pathname);
  return (m ? m[1] : String(window.__BASE_PATH__ || '')).replace(/\/+$/, '');
})();
const ABS_BASE   = window.location.origin + SCRIPT_DIR + '/';
const absUrl = (p) => new URL(p.replace(/^\/+/, ''), ABS_BASE).toString();

function Icon({ name, size = 20, style = {} }) {
  return <span className="mi" style={{ fontSize: size, ...style }}>{name}</span>;
}

function BrandMark({ size = 34 }) {
  return (
    <Box sx={{
      width: size, height: size, borderRadius: `${Math.round(size * 0.3)}px`,
      background: 'linear-gradient(135deg, #4f46e5 0%, #7c3aed 55%, #ec4899 100%)',
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      color: '#fff', boxShadow: '0 6px 18px -4px rgba(79, 70, 229, 0.55)', flexShrink: 0
    }}>
      <Icon name="shield" size={Math.round(size * 0.56)} />
    </Box>
  );
}

// One request with the session cookie and CSRF token. Resolves with { status, ok, body }; a
// body that is not JSON (a proxy error page, say) becomes {} or { error }.
function apiFetch(path, opts = {}) {
  const headers = Object.assign(
    { 'Content-Type': 'application/json', 'X-CSRF-Token': window.__CSRF_TOKEN__ || '' },
    opts.headers || {}
  );
  return fetch(absUrl(path), Object.assign({}, opts, { headers }))
    .then(r => r.text().then(text => {
      let j = null;
      if (text) {
        try { j = JSON.parse(text); } catch { j = null; }
      }
      if (j && typeof j.csrfToken === 'string' && j.csrfToken) {
        window.__CSRF_TOKEN__ = j.csrfToken;
      }
      // Every real API 404 has a JSON body; an empty one is the IP allowlist's refusal
      // (src/ip_allowlist.php), which is the same for every URL and says nothing else.
      if (r.status === 404 && text === '' && /(^|\/)api\//.test(path)) {
        j = { error: 'No answer from the server (empty 404). If your network address changed (VPN, Wi-Fi, mobile), it may be outside this IdP\'s IP allowlist: reconnect from an allowed network and reload.' };
      }
      if (!j || typeof j !== 'object' || Array.isArray(j)) {
        j = r.ok ? {} : { error: `Request failed (HTTP ${r.status}${r.statusText ? ' ' + r.statusText : ''})` };
      }
      return { status: r.status, ok: r.ok, body: j };
    }));
}

// The admin the console shows, kept by Shell from /api/me; null on the login screen.
let consoleUser = null;

// A rejection when the session behind an /api/me answer is not the admin the console shows:
// signed out, or signed in as another admin in another tab. Shell then shows the login
// screen or that account. Returns null when the session still belongs to the console's admin.
function sessionChangeFailure(me) {
  if (consoleUser === null || !me.ok || !me.body) return null;
  const nowUser = me.body.user || null;
  if (nowUser === consoleUser) return null;
  if (!nowUser) {
    window.dispatchEvent(new CustomEvent('idp:session-expired'));
    return { status: 401, error: 'Your session has expired. Please sign in again.' };
  }
  window.dispatchEvent(new CustomEvent('idp:session-switched', { detail: me.body }));
  return {
    status: 409,
    error: `Not done: this browser is now signed in as ${nowUser}, not ${consoleUser}. The console now shows ${nowUser}. Check the change and repeat it if it is still wanted.`,
  };
}

// Admin API call (S13-08). Rejects with an object that has an "error" text.
// - A 403 for a stale CSRF token (the admin signed in again in another tab) refreshes the
//   token from /api/me and retries once; the refused request changed nothing. The retry runs
//   only while the session still belongs to the admin the console shows, so a request is
//   never replayed under another account.
// - A 401 checks /api/me; when the session is gone, the login screen is shown.
function api(path, opts = {}, csrfRetried = false) {
  const isAuthCall = /^\/?api\/(login|me)(\?|$)/.test(path);
  return apiFetch(path, opts).then(res => {
    if (res.ok) return res.body;
    const failure = Object.assign({ status: res.status }, res.body);
    if (res.status === 403 && !csrfRetried && /csrf/i.test(String(res.body.error || ''))) {
      return apiFetch('/api/me').then(me => {
        if (!me.ok) return Promise.reject(failure);
        const changed = isAuthCall ? null : sessionChangeFailure(me);
        return changed ? Promise.reject(changed) : api(path, opts, true);
      }, () => Promise.reject(failure));
    }
    if (res.status === 401 && !isAuthCall) {
      return apiFetch('/api/me').then(me => {
        if (me.ok && me.body && !me.body.user) {
          window.dispatchEvent(new CustomEvent('idp:session-expired'));
          return Promise.reject({ status: 401, error: 'Your session has expired. Please sign in again.' });
        }
        return Promise.reject(sessionChangeFailure(me) || failure);
      }, () => Promise.reject(failure));
    }
    return Promise.reject(failure);
  });
}

// Text of an api() failure, a network error or anything else thrown.
function errText(e, fallback = 'Request failed') {
  if (e && typeof e.error === 'string' && e.error) return e.error;
  if (e && typeof e.message === 'string' && e.message) return e.message;
  return fallback;
}

// Seconds as the shortest exact duration the server accepts: 0s, 90m, 1h, 7d.
function formatDuration(secs) {
  const n = Number(secs);
  if (!Number.isFinite(n) || n < 0) return '';
  if (n === 0) return '0s';
  for (const [unit, size] of [['d', 86400], ['h', 3600], ['m', 60]]) {
    if (n % size === 0) return (n / size) + unit;
  }
  return n + 's';
}

// JSON with object keys sorted, to compare values regardless of key order.
function stableStringify(v) {
  if (Array.isArray(v)) return '[' + v.map(stableStringify).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + stableStringify(v[k])).join(',') + '}';
  }
  return JSON.stringify(v === undefined ? null : v);
}

// Shell-quotes a value for the single-quoted strings of the cURL examples.
function shellQuote(s) {
  return String(s).replace(/'/g, `'\\''`);
}

// PHP rawurlencode(): encodeURIComponent() that also escapes ! ' ( ) *.
function rawUrlEncode(s) {
  return encodeURIComponent(String(s)).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function b64uToBytes(b64u) {
  let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

function bytesToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function useCopyFeedback() {
  const [ok, setOk] = useState(false);
  const trigger = (text) => navigator.clipboard.writeText(text).then(() => {
    setOk(true);
    setTimeout(() => setOk(false), 1800);
  });
  return [ok, trigger];
}

function relativeTime(iso) {
  if (!iso) return '';
  const now = new Date();
  const dt = new Date(iso);
  const diffMs = dt - now;
  const past = diffMs < 0;
  let secs = Math.abs(Math.round(diffMs / 1000));
  const units = [["y",31536000],["mo",2592000],["d",86400],["h",3600],["m",60],["s",1]];
  const parts = [];
  for (const [l, s] of units) {
    const v = Math.floor(secs / s);
    if (v > 0) { parts.push(v + l); secs -= v * s; }
    if (parts.length >= 2) break;
  }
  if (parts.length === 0) parts.push('0s');
  return past ? parts.join(' ') + ' ago' : 'in ' + parts.join(' ');
}

function avatarGradient(seed = '') {
  const palettes = [
    'linear-gradient(135deg, #4f46e5, #06b6d4)',
    'linear-gradient(135deg, #7c3aed, #ec4899)',
    'linear-gradient(135deg, #059669, #14b8a6)',
    'linear-gradient(135deg, #ea580c, #f59e0b)',
    'linear-gradient(135deg, #2563eb, #8b5cf6)',
  ];
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  return palettes[h % palettes.length];
}

function initialsOf(name = '') {
  const parts = String(name).trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return String(name).slice(0, 2).toUpperCase() || 'U';
}

const POLICY_META = {
  inherit: { label: 'Inherit tenant default', short: 'Tenant default', icon: 'subdirectory_arrow_right', color: 'default' },
  flexible: { label: 'Flexible (Touch ID or Password)', short: 'Flexible', icon: 'lock_open', color: 'default' },
  touchid_only: { label: 'Touch ID Only (Passwordless)', short: 'Touch ID Only', icon: 'fingerprint', color: 'secondary' },
  mfa: { label: 'MFA (Password + Touch ID)', short: 'Step-Up MFA', icon: 'verified_user', color: 'primary' },
};

// The policy the server enforces for a stored value: unknown values fail closed to MFA.
function enforcedPolicy(policy) {
  return policy && policy !== 'inherit' && POLICY_META[policy] ? policy : 'mfa';
}

// An app or client set to "inherit" follows the provider's default sign-on policy, which
// is passed as `inherited` so the badge shows the policy that applies (S01-03, G1e-02).
function PolicyBadge({ policy, inherited }) {
  const isInherit = !policy || policy === 'inherit';
  const effective = isInherit ? (inherited ? enforcedPolicy(inherited) : null) : enforcedPolicy(policy);
  const m = effective ? POLICY_META[effective] : POLICY_META.inherit;
  const label = isInherit ? (effective ? `Inherits: ${m.short}` : POLICY_META.inherit.short) : m.short;
  return (
    <Chip
      size="small"
      icon={<Icon name={isInherit ? POLICY_META.inherit.icon : m.icon} size={14} />}
      label={label}
      color={m.color}
      variant={isInherit || m.color === 'default' ? 'outlined' : 'filled'}
      title={isInherit ? 'Follows the tenant default sign-on policy' : m.label}
      sx={{ fontWeight: 600 }}
    />
  );
}

/* ==================== SLEEK COPYABLE ENDPOINT ROW ==================== */
function CopyEndpointRow({ label, url, downloadUrl, openable = true }) {
  const [ok, trigger] = useCopyFeedback();
  return (
    <Box sx={{
      display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 1.5,
      py: 0.85, px: 1.5, borderRadius: 2, bgcolor: 'action.hover',
      border: '1px solid', borderColor: 'divider', mb: 0.85, flexWrap: 'wrap'
    }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25, minWidth: 0, flex: 1 }}>
        <Typography variant="caption" sx={{
          fontWeight: 700, color: 'text.secondary', textTransform: 'uppercase',
          letterSpacing: '0.04em', minWidth: 138, flexShrink: 0
        }}>
          {label}
        </Typography>
        <Typography variant="body2" className="mono" sx={{
          fontSize: 12.5, color: 'text.primary', overflow: 'hidden',
          textOverflow: 'ellipsis', whiteSpace: 'nowrap'
        }} title={url}>
          {url}
        </Typography>
      </Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.25, flexShrink: 0 }}>
        <Tooltip title={ok ? 'Copied!' : 'Copy URL'}>
          <IconButton size="small" onClick={() => trigger(url)} color={ok ? 'success' : 'default'}>
            <Icon name={ok ? 'check' : 'content_copy'} size={16} />
          </IconButton>
        </Tooltip>
        {openable && (
          <Tooltip title="Open in new tab">
            <IconButton size="small" component="a" href={url} target="_blank" rel="noreferrer">
              <Icon name="open_in_new" size={16} />
            </IconButton>
          </Tooltip>
        )}
        {downloadUrl && (
          <Tooltip title="Download XML file">
            <IconButton size="small" component="a" href={downloadUrl} target="_blank" rel="noreferrer" color="primary">
              <Icon name="download" size={17} />
            </IconButton>
          </Tooltip>
        )}
      </Box>
    </Box>
  );
}

/* ==================== KPI STAT CARD ==================== */
function StatCard({ label, value, subtitle, icon, gradient }) {
  return (
    <Paper variant="outlined" sx={{ p: 2.5, height: '100%', display: 'flex', alignItems: 'center', gap: 2 }}>
      <Box sx={{
        width: 46, height: 46, borderRadius: 3, background: gradient,
        display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', flexShrink: 0,
        boxShadow: '0 8px 18px -6px rgba(15, 23, 42, 0.28)'
      }}>
        <Icon name={icon} size={23} />
      </Box>
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {label}
        </Typography>
        <Typography variant="h5" sx={{ fontWeight: 800, lineHeight: 1.2, my: 0.2 }}>
          {value}
        </Typography>
        {subtitle && <Typography variant="caption" color="text.secondary">{subtitle}</Typography>}
      </Box>
    </Paper>
  );
}

/* ==================== CREATE PROVIDER DIALOG ==================== */
function CreateProviderDialog({ open, onClose, onCreated, existingNames, me }) {
  const [friendly, setFriendly] = useState('');
  const [keyMode, setKeyMode] = useState('generate');
  const [alg, setAlg] = useState('RS256');
  const [defaultPolicy, setDefaultPolicy] = useState('flexible');
  const [keyText, setKeyText] = useState('');
  const [err, setErr] = useState('');
  const [nameErr, setNameErr] = useState('');
  const [checking, setChecking] = useState(false);
  // The provider id the server reported for a name (check-name "idpId"): { name, idpId }.
  const [checkedId, setCheckedId] = useState(null);

  useEffect(() => {
    if (!open) {
      setFriendly(''); setKeyMode('generate'); setAlg('RS256');
      setDefaultPolicy('flexible'); setKeyText(''); setErr(''); setNameErr(''); setCheckedId(null);
    }
  }, [open]);

  useEffect(() => {
    if (!friendly) { setNameErr(''); setChecking(false); return; }
    if (existingNames.map(n => n.toLowerCase()).includes(friendly.toLowerCase())) {
      setNameErr('Name already exists');
    } else {
      setNameErr('');
    }
    const name = friendly;
    // An answer for a name the admin has since changed is dropped.
    let stale = false;
    const id = setTimeout(() => {
      setChecking(true);
      fetch(absUrl('/api/providers/check-name?name=' + encodeURIComponent(name)))
        .then(r => r.json())
        .then(j => {
          if (stale) return;
          setNameErr(j.exists ? 'Name already exists' : '');
          if (typeof j.idpId === 'string' && j.idpId) setCheckedId({ name, idpId: j.idpId });
          setChecking(false);
        })
        .catch(() => { if (!stale) setChecking(false); });
    }, 300);
    return () => { stale = true; clearTimeout(id); };
  }, [friendly, existingNames]);

  // The id the server reported for this exact name, else the server's rule applied here
  // (S10-03): rawurlencode(owner + '-' + name) with every '-' of the name written as '_'. A
  // deployment with legacy_provider_id_format keeps '-', which the server's answer then shows.
  const idpId = checkedId && checkedId.name === friendly
    ? checkedId.idpId
    : rawUrlEncode(me.user || 'user') + '-' + rawUrlEncode(friendly.replace(/-/g, '_'));
  const dashKept = friendly.includes('-') && idpId.endsWith('-' + rawUrlEncode(friendly));
  // The server's public base URL when it reports one (it may differ from the address in use).
  const issuer = String(me.baseUrl || ABS_BASE).replace(/\/+$/, '') + '/' + idpId;

  const submit = () => {
    setErr('');
    if (nameErr || checking) return;
    const body = keyMode === 'generate'
      ? { friendly, keyMode, alg, default_auth_policy: defaultPolicy }
      : { friendly, keyMode, keyText, default_auth_policy: defaultPolicy };
    api('/api/providers', { method: 'POST', body: JSON.stringify(body) })
      .then(p => { onCreated(p); onClose(); })
      .catch(e => setErr(errText(e, 'Create failed')));
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Icon name="add_moderator" size={22} />
        <span>New Identity Provider Tenant</span>
      </DialogTitle>
      <DialogContent dividers>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
          Provisions an isolated SAML 2.0 &amp; OpenID Connect 1.0 Identity Provider with dedicated signing keys, hosted metadata URL, and an End-User App Launchpad.
        </Typography>
        <TextField
          fullWidth label="Provider Slug / Name" placeholder="e.g. okta-staging, panw-lab"
          value={friendly} onChange={e => setFriendly(e.target.value)}
          error={!!nameErr} helperText={nameErr || (checking ? 'Checking availability…' : (dashKept ? 'Used in the public Issuer & SAML Entity ID URL' : "Used in the public Issuer & SAML Entity ID URL, where each '-' of the name becomes '_'"))}
          autoFocus
        />
        <Box sx={{ mt: 2, p: 1.5, borderRadius: 2, bgcolor: 'action.hover', border: '1px solid', borderColor: 'divider' }}>
          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, display: 'block', mb: 0.4 }}>
            PREVIEW ISSUER &amp; SAML ENTITY ID
          </Typography>
          <Typography variant="body2" className="mono" sx={{ fontSize: 12.5, wordBreak: 'break-all' }}>
            {issuer}
          </Typography>
        </Box>
        <TextField select fullWidth sx={{ mt: 2.5 }} label="Default Sign-On Policy" value={defaultPolicy} onChange={e => setDefaultPolicy(e.target.value)}>
          <MenuItem value="flexible">Flexible — macOS Touch ID or Password</MenuItem>
          <MenuItem value="touchid_only">Touch ID Only — Passwordless Biometric</MenuItem>
          <MenuItem value="mfa">Step-Up MFA — Password + macOS Touch ID</MenuItem>
        </TextField>
        <Grid container spacing={2} sx={{ mt: 0.5 }}>
          <Grid item xs={12} sm={keyMode === 'generate' ? 6 : 12}>
            <TextField select fullWidth label="OIDC Signing Key" value={keyMode} onChange={e => setKeyMode(e.target.value)} helperText="RSA-2048 SAML X.509 cert is also auto-generated">
              <MenuItem value="generate">Auto-generate keypair</MenuItem>
              <MenuItem value="paste">Import private key PEM</MenuItem>
            </TextField>
          </Grid>
          {keyMode === 'generate' && (
            <Grid item xs={12} sm={6}>
              <TextField select fullWidth label="JWA Algorithm" value={alg} onChange={e => setAlg(e.target.value)}>
                <MenuItem value="RS256">RS256 (RSA SHA-256)</MenuItem>
                <MenuItem value="RS384">RS384 (RSA SHA-384)</MenuItem>
                <MenuItem value="RS512">RS512 (RSA SHA-512)</MenuItem>
                <MenuItem value="ES256">ES256 (ECDSA P-256)</MenuItem>
                <MenuItem value="ES384">ES384 (ECDSA P-384)</MenuItem>
                <MenuItem value="ES512">ES512 (ECDSA P-521)</MenuItem>
                <MenuItem value="EdDSA">EdDSA (Ed25519)</MenuItem>
              </TextField>
            </Grid>
          )}
        </Grid>
        {keyMode === 'paste' && (
          <TextField multiline minRows={4} fullWidth sx={{ mt: 2 }} label="Private Key (PEM for RSA/EC, or Ed25519 Base64)" value={keyText} onChange={e => setKeyText(e.target.value)} InputProps={{ className: 'mono' }} />
        )}
        {err && <Alert sx={{ mt: 2 }} severity="error">{err}</Alert>}
      </DialogContent>
      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={submit} disabled={!!nameErr || checking || !friendly || (keyMode === 'paste' && !keyText.trim())}>
          Create Provider
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/* ==================== ISSUE RAW WORKLOAD JWT DIALOG ==================== */
function GetJwtDialog({ open, onClose, provider, apiKey }) {
  const [aud, setAud] = useState('');
  const [subMode, setSubMode] = useState('generic');
  const [sub, setSub] = useState('');
  const [ns, setNs] = useState('');
  const [sa, setSa] = useState('');
  const [ttl, setTtl] = useState('3600');
  const [extra, setExtra] = useState('');
  const [extraErr, setExtraErr] = useState('');
  const [token, setToken] = useState('');
  // Extra claims the server refused to put in the token (reserved claim names).
  const [ignoredClaims, setIgnoredClaims] = useState([]);
  const [err, setErr] = useState('');
  const [okCopy, triggerCopy] = useCopyFeedback();
  const [okCopyCurl, triggerCopyCurl] = useCopyFeedback();
  const [showDetails, setShowDetails] = useState(false);

  useEffect(() => {
    if (open) {
      setAud(''); setSubMode('generic'); setSub(''); setNs(''); setSa('');
      setTtl('3600'); setExtra(''); setExtraErr(''); setToken(''); setIgnoredClaims([]); setErr(''); setShowDetails(false);
    }
  }, [open, provider]);

  const craftSub = () => subMode === 'generic' ? sub : (`system:serviceaccount:${ns}:${sa}`);

  const issue = () => {
    setErr(''); setToken(''); setIgnoredClaims([]); setShowDetails(false);
    try { if (subMode === 'generic' && extra.trim()) JSON.parse(extra); setExtraErr(''); }
    catch { setExtraErr('Invalid JSON'); return; }
    const body = { idpId: provider.idpId, aud, sub: craftSub(), ttl: String(ttl || '3600').trim() };
    if (subMode === 'generic' && extra.trim()) body.extra = JSON.parse(extra);
    if (subMode === 'k8s') body.k8s = { namespace: ns, serviceAccount: sa };
    // The console session (cookie and CSRF token) authorizes the request. The legacy
    // per-admin key is added only while the server still hands it out (S10-04).
    const headers = apiKey ? { 'Authorization': 'ApiKey ' + apiKey } : {};
    api('/api/token', { method: 'POST', headers, body: JSON.stringify(body) })
      .then(j => {
        setToken(j.token || '');
        setIgnoredClaims(Array.isArray(j.ignored_claims) ? j.ignored_claims.map(String) : []);
      })
      .catch(e => setErr(errText(e, 'Failed')));
  };

  // Automation authenticates with a scoped Admin API client token, never a console secret.
  const curl = `curl -s -X POST '${shellQuote(absUrl('/api/token'))}' \\\n  -H 'Authorization: Bearer <ADMIN_API_CLIENT_TOKEN>' \\\n  -H 'Content-Type: application/json' \\\n  -H 'Accept: text/plain' \\\n  -d '${shellQuote(JSON.stringify({
    idpId: provider?.idpId,
    aud: [aud || '<audience>'],
    sub: craftSub() || '<subject>',
    ttl: ttl || '3600',
  }))}'`;

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
        <Icon name="token" size={22} />
        <span>Mint Workload / Machine JWT — {provider?.friendly}</span>
      </DialogTitle>
      <DialogContent dividers>
        <Grid container spacing={2}>
          <Grid item xs={12} md={8}>
            <TextField fullWidth label="Audience (aud)" placeholder="https://kubernetes.default.svc" value={aud} onChange={e => setAud(e.target.value)} helperText="Single audience URI or comma-separated list. This provider's issuer and the client_id of its OIDC clients are refused." />
          </Grid>
          <Grid item xs={12} md={4}>
            {/* Workload tokens last at most 24 hours unless OIDC_LEGACY_WORKLOAD_TOKENS=1 (G1a-02). */}
            <TextField fullWidth label="Validity (TTL)" value={ttl} onChange={e => setTtl(e.target.value)} helperText="e.g., 300, 15m, 1h, 24h" />
          </Grid>
          <Grid item xs={12}>
            <FormControl>
              <FormLabel sx={{ fontSize: 13, fontWeight: 600 }}>Subject Template</FormLabel>
              <RadioGroup row value={subMode} onChange={e => setSubMode(e.target.value)}>
                <FormControlLabel value="generic" control={<Radio size="small" />} label="Custom Subject" />
                <FormControlLabel value="k8s" control={<Radio size="small" />} label="Kubernetes ServiceAccount" />
              </RadioGroup>
            </FormControl>
          </Grid>
          {subMode === 'generic' ? (
            <>
              <Grid item xs={12}>
                <TextField fullWidth label="Subject (sub)" placeholder="ci-runner@example.internal" value={sub} onChange={e => setSub(e.target.value)} />
              </Grid>
              <Grid item xs={12}>
                <TextField fullWidth multiline minRows={2} label="Extra Claims (JSON)" placeholder='{"env": "production"}' value={extra} onChange={e => setExtra(e.target.value)} error={!!extraErr} helperText={extraErr || 'Merged into the signed JWT payload. Identity claims (email, email_verified, groups, preferred_username, name, client_id, scope, ...) and reserved claims (sub, exp, amr, nonce, ...) are dropped.'} InputProps={{ className: 'mono' }} />
              </Grid>
            </>
          ) : (
            <>
              <Grid item xs={12} md={6}><TextField fullWidth label="Kubernetes Namespace" placeholder="default" value={ns} onChange={e => setNs(e.target.value)} /></Grid>
              <Grid item xs={12} md={6}><TextField fullWidth label="ServiceAccount Name" placeholder="deployer" value={sa} onChange={e => setSa(e.target.value)} /></Grid>
            </>
          )}
        </Grid>
        <Box sx={{ mt: 2.5, display: 'flex', gap: 1.5 }}>
          <Button variant="contained" startIcon={<Icon name="bolt" size={18} />} onClick={issue} disabled={!aud || (subMode === 'generic' ? !sub : (!ns || !sa))}>
            Mint Signed JWT
          </Button>
          {token && (
            <Button variant="outlined" onClick={() => setShowDetails(!showDetails)}>
              {showDetails ? 'Hide Decoded Claims' : 'Inspect Decoded Claims'}
            </Button>
          )}
        </Box>
        {err && <Alert sx={{ mt: 2 }} severity="error">{err}</Alert>}
        {token && ignoredClaims.length > 0 && (
          <Alert sx={{ mt: 2 }} severity="warning">Not included in the token (reserved or identity claim names): {ignoredClaims.join(', ')}</Alert>
        )}
        {token && (
          <Paper variant="outlined" sx={{ position: 'relative', mt: 2, p: 2, bgcolor: '#0f172a', color: '#e2e8f0', borderColor: '#1e293b' }}>
            <Tooltip title={okCopy ? 'Copied!' : 'Copy JWT'}>
              <IconButton onClick={() => triggerCopy(token)} size="small" sx={{ position: 'absolute', top: 8, right: 8, color: '#94a3b8' }}>
                <Icon name={okCopy ? 'check' : 'content_copy'} size={17} />
              </IconButton>
            </Tooltip>
            <pre style={{ margin: 0, fontSize: 12.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', paddingRight: 32 }}><code>{token}</code></pre>
          </Paper>
        )}
        {token && showDetails && (() => {
          let decodedStr = '';
          try {
            const parts = token.split('.');
            const dec = (s) => new TextDecoder().decode(b64uToBytes(s));
            decodedStr = JSON.stringify({ header: JSON.parse(dec(parts[0])), payload: JSON.parse(dec(parts[1])) }, null, 2);
          } catch (e) { decodedStr = String(e); }
          return (
            <Paper variant="outlined" sx={{ mt: 1.5, p: 2, overflowX: 'auto', bgcolor: '#0f172a', color: '#a5f3fc', borderColor: '#1e293b' }}>
              <pre style={{ margin: 0, fontSize: 12.5 }}><code>{decodedStr}</code></pre>
            </Paper>
          );
        })()}
        <Box sx={{ mt: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="subtitle2">Headless CI / Automation cURL</Typography>
          <Button size="small" startIcon={<Icon name={okCopyCurl ? 'check' : 'content_copy'} size={15} />} onClick={() => triggerCopyCurl(curl)}>
            {okCopyCurl ? 'Copied' : 'Copy cURL'}
          </Button>
        </Box>
        <Paper variant="outlined" sx={{ mt: 1, p: 2, overflowX: 'auto', bgcolor: '#0f172a', color: '#cbd5e1', borderColor: '#1e293b' }}>
          <pre style={{ margin: 0, fontSize: 12.5 }}>{curl}</pre>
        </Paper>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.75 }}>
          Replace <code>{'<ADMIN_API_CLIENT_TOKEN>'}</code> with the token (idp_adm_...) of a scoped Admin API client that has "Can mint tokens" enabled (API Clients &amp; OpenAPI).
        </Typography>
      </DialogContent>
      <DialogActions sx={{ px: 3, py: 2 }}><Button onClick={onClose}>Close</Button></DialogActions>
    </Dialog>
  );
}

/* ==================== SAML APP CREATE / EDIT + DRAG-DROP XML IMPORT DIALOG ==================== */
// The algorithms saml_supported_encryption_algorithms() accepts (S02-08).
const SAML_ENCRYPTION_ALGS = [
  { value: 'http://www.w3.org/2009/xmlenc11#aes256-gcm', label: 'AES-256-GCM (recommended)' },
  { value: 'http://www.w3.org/2009/xmlenc11#aes128-gcm', label: 'AES-128-GCM' },
  { value: 'http://www.w3.org/2009/xmlenc11#aes192-gcm', label: 'AES-192-GCM' },
  { value: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc', label: 'AES-256-CBC (only for SPs without GCM)' },
  { value: 'http://www.w3.org/2001/04/xmlenc#aes128-cbc', label: 'AES-128-CBC (only for SPs without GCM)' },
  { value: 'http://www.w3.org/2001/04/xmlenc#aes192-cbc', label: 'AES-192-CBC (only for SPs without GCM)' },
];

// What a metadata import may change in an existing app: only facts the SP publishes (G1e-01).
const SAML_METADATA_REFRESH_FIELDS = ['acs_url', 'acs_endpoints', 'slo_url', 'supported_name_id_formats', 'raw_sp_metadata_xml'];

const SAML_NAMEID_PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

// True when an app (or the dialog's form) can send persistent NameIDs: its NameID format or
// value source is persistent, or its SP may request the persistent format (S02-10).
function samlAppCanIssuePersistent(app) {
  return !!app && (
    app.name_id_format === SAML_NAMEID_PERSISTENT ||
    app.name_id_source === 'persistent' ||
    (Array.isArray(app.supported_name_id_formats) && app.supported_name_id_formats.includes(SAML_NAMEID_PERSISTENT))
  );
}

function SamlAppDialog({ open, onClose, provider, editingApp, onSaved }) {
  const emptyForm = {
    name: '',
    org_display_name: '',
    sp_entity_id: '',
    acs_url: '',
    acs_endpoints: [],
    slo_url: '',
    name_id_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    name_id_source: 'email',
    sign_response: true,
    sign_assertion: true,
    verify_authn_request_sig: false,
    allow_weak_sha1: false,
    encrypt_assertion: false,
    encryption_alg: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    sp_signing_cert_pem: '',
    sp_encryption_cert_pem: '',
    attribute_mapping: [
      { name: 'firstName', friendly_name: 'First Name', name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', required: true, source: 'user.given_name' },
      { name: 'lastName', friendly_name: 'Last Name', name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', required: true, source: 'user.family_name' },
      { name: 'email', friendly_name: 'Email', name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', required: true, source: 'user.email' },
      { name: 'groups', friendly_name: 'Groups', name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', required: false, source: 'user.groups' },
    ],
    default_relay_state: '',
    auth_policy: 'inherit',
    assigned_groups_text: '',
    raw_sp_metadata_xml: '',
  };

  const [form, setForm] = useState(emptyForm);
  const [xmlPaste, setXmlPaste] = useState('');
  const [showImport, setShowImport] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [importMsg, setImportMsg] = useState('');
  const [err, setErr] = useState('');

  useEffect(() => {
    if (!open) return;
    setErr(''); setImportMsg(''); setXmlPaste(''); setDragOver(false);
    if (editingApp) {
      setForm({
        ...emptyForm,
        ...editingApp,
        assigned_groups_text: (editingApp.assigned_groups || []).join(', '),
      });
      setShowImport(false);
    } else {
      setForm(emptyForm);
      setShowImport(true);
    }
  }, [open, editingApp]);

  const parseMetadataXml = (xmlString) => {
    setErr(''); setImportMsg('');
    api('/api/saml/parse-sp-metadata', { method: 'POST', body: JSON.stringify({ xml: xmlString }) })
      .then(r => {
        const p = r.parsed || {};
        if (!editingApp) {
          setForm(prev => ({
            ...prev,
            ...p,
            auth_policy: prev.auth_policy || 'inherit',
            assigned_groups_text: prev.assigned_groups_text || '',
          }));
          setImportMsg(`Auto-configured "${p.name}" — ${p.attribute_mapping?.length || 0} attribute mappings & X.509 certificates imported.`);
          setShowImport(false);
          return;
        }
        // Metadata refresh of an existing app (G1e-01): only the endpoints, NameID formats and
        // certificates the SP publishes are taken. The name, NameID format and source, signing,
        // encryption and AuthnRequest settings, attribute mappings, policy and groups stay.
        const currentEntityId = String(form.sp_entity_id || '').trim();
        const newEntityId = String(p.sp_entity_id || '').trim();
        const switchEntityId = newEntityId !== '' && newEntityId !== currentEntityId;
        if (switchEntityId && !confirm(`This metadata is for SP Entity ID "${newEntityId}", but this application uses "${currentEntityId}". Use the metadata anyway and change the SP Entity ID?`)) {
          setErr(`Metadata not applied: its SP Entity ID "${newEntityId}" differs from this application's "${currentEntityId}". Import it as a new application instead.`);
          return;
        }
        setForm(prev => {
          const next = { ...prev };
          SAML_METADATA_REFRESH_FIELDS.forEach(k => { if (p[k] !== undefined) next[k] = p[k]; });
          ['sp_signing_cert_pem', 'sp_encryption_cert_pem'].forEach(k => {
            if (typeof p[k] === 'string' && p[k].trim() !== '') next[k] = p[k];
          });
          if (switchEntityId) next.sp_entity_id = newEntityId;
          return next;
        });
        setImportMsg(`Refreshed the ACS/SLO endpoints, NameID formats and certificates from the metadata${switchEntityId ? ' and changed the SP Entity ID' : ''}. Name, NameID, signing, encryption, attribute mapping, policy and group settings were kept. Save to apply.`);
        setShowImport(false);
      })
      .catch(e => setErr(errText(e, 'Failed to parse SP Metadata XML')));
  };

  const readXmlFile = (file) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const txt = String(reader.result || '');
      setXmlPaste(txt);
      parseMetadataXml(txt);
    };
    reader.readAsText(file);
  };

  const handleFileUpload = (e) => readXmlFile(e.target.files?.[0]);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer?.files?.[0];
    if (f) readXmlFile(f);
  };

  const updateMapping = (idx, field, val) => {
    setForm(prev => {
      const list = [...(prev.attribute_mapping || [])];
      list[idx] = { ...list[idx], [field]: val };
      return { ...prev, attribute_mapping: list };
    });
  };

  const addMapping = () => {
    setForm(prev => ({
      ...prev,
      attribute_mapping: [
        ...(prev.attribute_mapping || []),
        { name: '', friendly_name: '', name_format: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', required: false, source: 'attr:' }
      ]
    }));
  };

  const removeMapping = (idx) => {
    setForm(prev => ({
      ...prev,
      attribute_mapping: (prev.attribute_mapping || []).filter((_, i) => i !== idx)
    }));
  };

  const removeAcsEndpoint = (idx) => {
    setForm(prev => ({
      ...prev,
      acs_endpoints: (prev.acs_endpoints || []).filter((_, i) => i !== idx)
    }));
  };

  const save = () => {
    setErr('');
    const payload = {
      ...form,
      assigned_groups: form.assigned_groups_text.split(',').map(s => s.trim()).filter(Boolean),
    };
    delete payload.assigned_groups_text;
    // Read-only: the scheme assertions use now (S02-10).
    delete payload.persistent_id_scheme_effective;
    // Raw metadata is sent only when an import in this dialog provided it; the console never
    // has the stored copy to send back. That copy survives an edit without an import only if
    // the server keeps it when the key is absent (saml_save_app, SAML lane).
    if (!payload.raw_sp_metadata_xml) delete payload.raw_sp_metadata_xml;
    const path = editingApp
      ? `/api/providers/${provider.id}/saml-apps/${editingApp.id}`
      : `/api/providers/${provider.id}/saml-apps`;
    api(path, { method: editingApp ? 'PUT' : 'POST', body: JSON.stringify(payload) })
      .then(() => { onSaved(); onClose(); })
      .catch(e => setErr(errText(e, 'Save failed')));
  };

  const originalAcsUrl = editingApp ? String(editingApp.acs_url || '') : '';
  const encryptionAlgs = SAML_ENCRYPTION_ALGS.some(a => a.value === form.encryption_alg)
    ? SAML_ENCRYPTION_ALGS
    : [...SAML_ENCRYPTION_ALGS, { value: form.encryption_alg || '', label: `Unsupported: ${form.encryption_alg || '(none)'}` }];
  const inheritedPolicyLabel = (POLICY_META[enforcedPolicy(provider?.default_auth_policy || 'flexible')] || POLICY_META.flexible).short;
  // S02-10: a stored "legacy" scheme is used only while the legacy_saml_persistent_ids flag is
  // on; persistent_id_scheme_effective is the scheme the app's assertions use now. Choosing
  // "legacy" for an app that is not legacy is refused (400) while the flag is off.
  let persistentSchemeHelp = 'Changing this gives every user a new NameID at this SP';
  if (editingApp && editingApp.persistent_id_scheme === 'legacy') {
    if (!samlAppCanIssuePersistent(editingApp)) {
      // Every app saved before keyed NameIDs existed is "legacy", including apps that are only
      // now being switched to persistent NameIDs.
      persistentSchemeHelp = 'This app was saved before keyed NameIDs existed. Choose HMAC before it sends persistent NameIDs: legacy ones (used while legacy_saml_persistent_ids is on) can be computed by anyone who knows a user id.';
    } else if (editingApp.persistent_id_scheme_effective === 'hmac') {
      persistentSchemeHelp = 'Not in effect: the legacy_saml_persistent_ids flag is off, so this app already sends keyed NameIDs. Choose HMAC to make that permanent.';
    } else {
      persistentSchemeHelp = 'This app sends unkeyed NameIDs that anyone who knows a user id can compute. Choosing HMAC gives every user a new NameID at this SP.';
    }
  }

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25 }}>
          <Icon name="hub" size={22} />
          <span>{editingApp ? `Edit SAML 2.0 App — ${editingApp.name}` : 'Configure SAML 2.0 Service Provider'}</span>
        </Box>
        <Button size="small" variant="outlined" startIcon={<Icon name="upload_file" size={17} />} onClick={() => setShowImport(!showImport)}>
          {showImport ? 'Hide XML Importer' : 'Import SP Metadata XML'}
        </Button>
      </DialogTitle>
      <DialogContent dividers>
        {importMsg && <Alert sx={{ mb: 2 }} severity="success">{importMsg}</Alert>}
        {err && <Alert sx={{ mb: 2 }} severity="error">{err}</Alert>}

        <Collapse in={showImport}>
          <Paper
            variant="outlined"
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            sx={{
              p: 2.5, mb: 3, borderStyle: 'dashed', borderWidth: 2,
              borderColor: dragOver ? 'primary.main' : 'divider',
              bgcolor: dragOver ? 'action.selected' : 'action.hover',
              transition: 'all 0.15s ease'
            }}
          >
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1.5, flexWrap: 'wrap', gap: 1.5 }}>
              <Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                  Drop SP Metadata XML or Upload File
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Supports Okta CIAM, Palo Alto Networks, AWS IAM Identity Center, GitHub Enterprise, Cloudflare Zero Trust, etc.
                </Typography>
              </Box>
              <Button variant="contained" size="small" component="label" startIcon={<Icon name="file_upload" size={17} />}>
                Choose .xml File
                <input type="file" accept=".xml,text/xml,application/xml" hidden onChange={handleFileUpload} />
              </Button>
            </Box>
            <TextField
              fullWidth multiline minRows={3} maxRows={5}
              placeholder="Or paste <md:EntityDescriptor ...> SP Metadata XML directly…"
              value={xmlPaste}
              onChange={e => setXmlPaste(e.target.value)}
              InputProps={{ className: 'mono', sx: { fontSize: 12.5 } }}
            />
            {xmlPaste.trim() && (
              <Box sx={{ mt: 1.25 }}>
                <Button size="small" variant="outlined" onClick={() => parseMetadataXml(xmlPaste)}>
                  Parse Pasted XML
                </Button>
              </Box>
            )}
          </Paper>
        </Collapse>

        <Grid container spacing={2}>
          <Grid item xs={12} md={5}>
            <TextField fullWidth label="Application Name" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField select fullWidth label="Sign-On Policy" value={form.auth_policy || 'inherit'} onChange={e => setForm({ ...form, auth_policy: e.target.value })}>
              <MenuItem value="inherit">Inherit tenant default (currently {inheritedPolicyLabel})</MenuItem>
              <MenuItem value="flexible">Flexible (Touch ID or Password)</MenuItem>
              <MenuItem value="touchid_only">Touch ID Only (Passwordless)</MenuItem>
              <MenuItem value="mfa">Step-Up MFA (Password + Touch ID)</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12} md={3}>
            <TextField fullWidth label="Group Restriction" placeholder="e.g. secops, admins" value={form.assigned_groups_text} onChange={e => setForm({ ...form, assigned_groups_text: e.target.value })} helperText="Blank = all active users" />
          </Grid>

          <Grid item xs={12} md={6}>
            <TextField fullWidth label="SP Entity ID (Audience URI)" value={form.sp_entity_id} onChange={e => setForm({ ...form, sp_entity_id: e.target.value })} InputProps={{ className: 'mono', sx: { fontSize: 13 } }} />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField fullWidth label="Assertion Consumer Service (ACS) POST URL" value={form.acs_url} onChange={e => setForm({ ...form, acs_url: e.target.value })} InputProps={{ className: 'mono', sx: { fontSize: 13 } }} helperText="Default ACS endpoint; https:// required (http:// only for localhost)" />
          </Grid>
          <Grid item xs={12}>
            <TextField fullWidth label="Single Logout (SLO) URL (optional)" placeholder="https://sp.example.com/saml/slo" value={form.slo_url || ''} onChange={e => setForm({ ...form, slo_url: e.target.value })} InputProps={{ className: 'mono', sx: { fontSize: 13 } }} helperText="Where this SP's logout requests are answered (LogoutResponse). Single Logout ends the user's IdP session and answers the SP that asked; it does not sign the user out of other applications. Leave empty if the SP has no SLO endpoint." />
          </Grid>
          <Grid item xs={12}>
            <Paper variant="outlined" sx={{ px: 2, py: 1.25, bgcolor: 'action.hover' }}>
              <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: 'uppercase', display: 'block', mb: 0.75 }}>
                Accepted ACS endpoints (HTTP-POST) — assertions are only delivered to these
              </Typography>
              {(form.acs_endpoints || []).filter(ep => ep && ep.location).length === 0 && (
                <Typography variant="body2" color="text.secondary">Only the ACS URL above.</Typography>
              )}
              {(form.acs_endpoints || []).map((ep, idx) => {
                if (!ep || !ep.location) return null;
                const isAcsUrl = ep.location === form.acs_url;
                const isReplaced = !isAcsUrl && originalAcsUrl !== '' && ep.location === originalAcsUrl && form.acs_url !== originalAcsUrl;
                return (
                  <Box key={idx} sx={{ display: 'flex', alignItems: 'center', gap: 1, py: 0.25, flexWrap: 'wrap' }}>
                    <Chip size="small" variant="outlined" label={`index ${ep.index ?? '—'}`} className="mono" sx={{ fontSize: 11 }} />
                    <Typography variant="body2" className="mono" sx={{ fontSize: 12.5, wordBreak: 'break-all', flex: 1, minWidth: 200, textDecoration: isReplaced ? 'line-through' : 'none' }}>
                      {ep.location}
                    </Typography>
                    {isAcsUrl && <Chip size="small" color="primary" variant="outlined" label="ACS URL (default)" />}
                    {isReplaced && <Chip size="small" color="warning" variant="outlined" label="Replaced ACS URL: removed on save" />}
                    {!isAcsUrl && !isReplaced && (
                      <Tooltip title="Stop accepting this endpoint">
                        <IconButton size="small" color="error" onClick={() => removeAcsEndpoint(idx)}><Icon name="delete_outline" size={18} /></IconButton>
                      </Tooltip>
                    )}
                  </Box>
                );
              })}
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                The ACS URL above is always accepted. Other endpoints come from the SP metadata; remove any the SP no longer uses.
              </Typography>
            </Paper>
          </Grid>

          <Grid item xs={12} md={5}>
            <TextField select fullWidth label="Subject NameID Format" value={form.name_id_format} onChange={e => setForm({ ...form, name_id_format: e.target.value })}>
              <MenuItem value="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">emailAddress</MenuItem>
              <MenuItem value="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">unspecified</MenuItem>
              <MenuItem value="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">persistent</MenuItem>
              <MenuItem value="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">transient</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12} md={3}>
            <TextField select fullWidth label="NameID Value Source" value={form.name_id_source} onChange={e => setForm({ ...form, name_id_source: e.target.value })}>
              <MenuItem value="email">User Email</MenuItem>
              <MenuItem value="username">Username</MenuItem>
              <MenuItem value="persistent">Pairwise Hash</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField fullWidth label="Default RelayState (optional)" value={form.default_relay_state} onChange={e => setForm({ ...form, default_relay_state: e.target.value })} />
          </Grid>
          {samlAppCanIssuePersistent(form) && (
            <Grid item xs={12} md={6}>
              <TextField select fullWidth label="Pairwise NameID Derivation" value={form.persistent_id_scheme || 'hmac'} onChange={e => setForm({ ...form, persistent_id_scheme: e.target.value })} helperText={persistentSchemeHelp}>
                <MenuItem value="hmac">Keyed per provider (HMAC, recommended)</MenuItem>
                <MenuItem value="legacy">Legacy unkeyed hash (only while legacy_saml_persistent_ids is on)</MenuItem>
              </TextField>
            </Grid>
          )}

          <Grid item xs={12}>
            <Paper variant="outlined" sx={{ px: 2, py: 1, display: 'flex', gap: 2.5, flexWrap: 'wrap', bgcolor: 'action.hover' }}>
              <FormControlLabel control={<Checkbox size="small" checked={!!form.sign_assertion} onChange={e => setForm({ ...form, sign_assertion: e.target.checked })} />} label="Sign <Assertion> (RSA-SHA256)" />
              <FormControlLabel control={<Checkbox size="small" checked={!!form.sign_response} onChange={e => setForm({ ...form, sign_response: e.target.checked })} />} label="Sign Outer <Response>" />
              <FormControlLabel control={<Checkbox size="small" checked={!!form.verify_authn_request_sig} onChange={e => setForm({ ...form, verify_authn_request_sig: e.target.checked })} />} label="Require Signed <AuthnRequest>" />
              <FormControlLabel control={<Checkbox size="small" checked={!!form.allow_weak_sha1} onChange={e => setForm({ ...form, allow_weak_sha1: e.target.checked })} />} label="Allow Legacy SHA-1 Signatures" />
              {/* Without an SP encryption certificate the box can only be cleared (S02-07). */}
              <FormControlLabel control={<Checkbox size="small" checked={!!form.encrypt_assertion} onChange={e => setForm({ ...form, encrypt_assertion: e.target.checked })} disabled={!form.sp_encryption_cert_pem && !form.encrypt_assertion} />} label="XML Encrypt <EncryptedAssertion>" />
            </Paper>
            {/* S02-06: the SP signing certificate decides which LogoutRequests may end a session silently. */}
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.75 }}>
              {form.sp_signing_cert_pem ? 'SP signing certificate: present.' : 'SP signing certificate: none (it comes from the SP metadata).'}
              {' '}Recommended for single logout: with a certificate, only LogoutRequests the SP signed can sign users out without a confirmation page; without one, an unsigned request that names a user's pairwise NameID can do so too.
            </Typography>
            {form.encrypt_assertion && !form.sp_encryption_cert_pem && (
              <Alert severity="warning" sx={{ mt: 1 }}>
                Assertion encryption needs the SP's RSA encryption certificate, and this application has none. Import the SP metadata, or clear the encryption box to save.
              </Alert>
            )}
          </Grid>
          {form.encrypt_assertion && (
            <Grid item xs={12} md={6}>
              <TextField select fullWidth label="Assertion Encryption Algorithm" value={form.encryption_alg || ''} onChange={e => setForm({ ...form, encryption_alg: e.target.value })}>
                {encryptionAlgs.map(a => <MenuItem key={a.value} value={a.value}>{a.label}</MenuItem>)}
              </TextField>
            </Grid>
          )}
        </Grid>

        <Divider sx={{ my: 2.5 }} />
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1.5 }}>
          <Box>
            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>SAML Attribute Statements</Typography>
            <Typography variant="caption" color="text.secondary">Map directory fields (`user.email`, `user.groups`) or custom attributes (`attr:roleName`) into SAML assertions.</Typography>
          </Box>
          <Button size="small" variant="outlined" startIcon={<Icon name="add" size={16} />} onClick={addMapping}>Add Attribute</Button>
        </Box>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
          {(form.attribute_mapping || []).map((m, idx) => (
            <Grid container spacing={1.25} key={idx} alignItems="center">
              <Grid item xs={12} md={3}>
                <TextField size="small" fullWidth label="Attribute Name" value={m.name || ''} onChange={e => updateMapping(idx, 'name', e.target.value)} />
              </Grid>
              <Grid item xs={12} md={2.5}>
                <TextField size="small" fullWidth label="FriendlyName" value={m.friendly_name || ''} onChange={e => updateMapping(idx, 'friendly_name', e.target.value)} />
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField select size="small" fullWidth label="NameFormat" value={m.name_format || 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'} onChange={e => updateMapping(idx, 'name_format', e.target.value)}>
                  <MenuItem value="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">attrname-format:uri</MenuItem>
                  <MenuItem value="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">attrname-format:basic</MenuItem>
                  <MenuItem value="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified">attrname-format:unspecified</MenuItem>
                </TextField>
              </Grid>
              <Grid item xs={9} md={2.5}>
                <TextField size="small" fullWidth label="Source" placeholder="user.email or attr:role" value={m.source || ''} onChange={e => updateMapping(idx, 'source', e.target.value)} />
              </Grid>
              <Grid item xs={3} md={1} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 0.5 }}>
                <Tooltip title="Required attribute"><Checkbox size="small" checked={!!m.required} onChange={e => updateMapping(idx, 'required', e.target.checked)} /></Tooltip>
                <IconButton size="small" color="error" onClick={() => removeMapping(idx)}><Icon name="delete_outline" size={18} /></IconButton>
              </Grid>
            </Grid>
          ))}
        </Box>
      </DialogContent>
      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={save} disabled={!form.name || !form.sp_entity_id || !form.acs_url}>
          {editingApp ? 'Save SAML App' : 'Create SAML App'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/* ==================== OIDC CLIENT CREATE / EDIT DIALOG ==================== */
// Grant types the server enforces at /authorize and /token (S03-09).
const OIDC_GRANT_TYPES = [
  { value: 'authorization_code', label: 'Authorization Code' },
  { value: 'refresh_token', label: 'Refresh Token' },
  { value: 'implicit', label: 'Implicit / Hybrid' },
  { value: 'client_credentials', label: 'Client Credentials' },
];
const OIDC_DEFAULT_GRANT_TYPES = ['authorization_code', 'refresh_token'];

function OidcClientDialog({ open, onClose, provider, editingClient, onSaved }) {
  const empty = {
    name: '',
    client_id: '',
    is_public: false,
    require_pkce: true,
    auth_policy: 'inherit',
    grant_types: OIDC_DEFAULT_GRANT_TYPES,
    redirect_uris_text: '',
    post_logout_uris_text: '',
    assigned_groups_text: '',
    login_uri: '',
    access_token_ttl: '3600',
  };
  const [form, setForm] = useState(empty);
  const [err, setErr] = useState('');

  useEffect(() => {
    if (!open) return;
    setErr('');
    if (editingClient) {
      // Only grant types the server supports; it rejects others when grant_types is sent.
      const known = (Array.isArray(editingClient.grant_types) ? editingClient.grant_types : [])
        .filter(g => OIDC_GRANT_TYPES.some(o => o.value === g));
      const grants = known.length ? known : OIDC_DEFAULT_GRANT_TYPES;
      setForm({
        name: editingClient.name || '',
        client_id: editingClient.client_id || '',
        is_public: !!editingClient.is_public,
        require_pkce: !!editingClient.require_pkce,
        auth_policy: editingClient.auth_policy || 'inherit',
        grant_types: grants,
        redirect_uris_text: (editingClient.redirect_uris || []).join('\n'),
        post_logout_uris_text: (editingClient.post_logout_redirect_uris || []).join('\n'),
        assigned_groups_text: (editingClient.assigned_groups || []).join(', '),
        login_uri: editingClient.login_uri || '',
        access_token_ttl: String(editingClient.access_token_ttl || 3600),
      });
    } else {
      setForm(empty);
    }
  }, [open, editingClient]);

  // Public clients cannot use client_credentials.
  const effectiveGrants = form.grant_types.filter(g => !(form.is_public && g === 'client_credentials'));
  const toggleGrant = (grant, on) => setForm(prev => ({
    ...prev,
    grant_types: on
      ? (prev.grant_types.includes(grant) ? prev.grant_types : [...prev.grant_types, grant])
      : prev.grant_types.filter(g => g !== grant),
  }));

  const save = () => {
    setErr('');
    const payload = {
      name: form.name,
      client_id: form.client_id,
      is_public: form.is_public,
      require_pkce: form.require_pkce || form.is_public,
      auth_policy: form.auth_policy,
      grant_types: effectiveGrants,
      redirect_uris: form.redirect_uris_text.split(/\r?\n|,/).map(s => s.trim()).filter(Boolean),
      post_logout_redirect_uris: form.post_logout_uris_text.split(/\r?\n|,/).map(s => s.trim()).filter(Boolean),
      assigned_groups: form.assigned_groups_text.split(',').map(s => s.trim()).filter(Boolean),
      login_uri: form.login_uri.trim(),
      access_token_ttl: form.access_token_ttl,
    };
    const path = editingClient
      ? `/api/providers/${provider.id}/oidc-clients/${editingClient.id}`
      : `/api/providers/${provider.id}/oidc-clients`;
    api(path, { method: editingClient ? 'PUT' : 'POST', body: JSON.stringify(payload) })
      .then((res) => { onSaved(res.client); onClose(); })
      .catch(e => setErr(errText(e, 'Save failed')));
  };

  const inheritedPolicyLabel = (POLICY_META[enforcedPolicy(provider?.default_auth_policy || 'flexible')] || POLICY_META.flexible).short;

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.25 }}>
        <Icon name="integration_instructions" size={22} />
        <span>{editingClient ? `Edit OIDC Relying Party — ${editingClient.name}` : 'New OpenID Connect 1.0 Client'}</span>
      </DialogTitle>
      <DialogContent dividers>
        {err && <Alert sx={{ mb: 2 }} severity="error">{err}</Alert>}
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <TextField fullWidth label="Application Name" placeholder="e.g. Internal Dashboard" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField fullWidth label="Client ID" placeholder="Auto-generated if left blank" value={form.client_id} onChange={e => setForm({ ...form, client_id: e.target.value })} InputProps={{ className: 'mono', sx: { fontSize: 13 } }} />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField select fullWidth label="Sign-On Policy" value={form.auth_policy || 'inherit'} onChange={e => setForm({ ...form, auth_policy: e.target.value })}>
              <MenuItem value="inherit">Inherit tenant default (currently {inheritedPolicyLabel})</MenuItem>
              <MenuItem value="flexible">Flexible (Touch ID or Password)</MenuItem>
              <MenuItem value="touchid_only">Touch ID Only (Passwordless)</MenuItem>
              <MenuItem value="mfa">Step-Up MFA (Password + Touch ID)</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField fullWidth label="Restrict to Groups (optional)" placeholder="devs, admins" value={form.assigned_groups_text} onChange={e => setForm({ ...form, assigned_groups_text: e.target.value })} helperText="Blank allows all active directory users" />
          </Grid>
          <Grid item xs={12}>
            <Paper variant="outlined" sx={{ px: 2, py: 1, display: 'flex', gap: 3, flexWrap: 'wrap', bgcolor: 'action.hover' }}>
              <FormControlLabel control={<Checkbox size="small" checked={form.is_public} onChange={e => setForm({ ...form, is_public: e.target.checked })} />} label="Public Client (SPA / Native / CLI — no client_secret)" />
              <FormControlLabel control={<Checkbox size="small" checked={form.require_pkce || form.is_public} disabled={form.is_public} onChange={e => setForm({ ...form, require_pkce: e.target.checked })} />} label="Enforce PKCE (S256)" />
            </Paper>
          </Grid>
          <Grid item xs={12}>
            <Paper variant="outlined" sx={{ px: 2, py: 1, bgcolor: 'action.hover' }}>
              <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: 'uppercase', display: 'block' }}>
                Allowed Grant Types
              </Typography>
              <Box sx={{ display: 'flex', gap: 2.5, flexWrap: 'wrap' }}>
                {OIDC_GRANT_TYPES.map(g => {
                  const blocked = g.value === 'client_credentials' && form.is_public;
                  return (
                    <FormControlLabel
                      key={g.value}
                      control={<Checkbox size="small" checked={!blocked && form.grant_types.includes(g.value)} disabled={blocked} onChange={e => toggleGrant(g.value, e.target.checked)} />}
                      label={g.label}
                    />
                  );
                })}
              </Box>
              <Typography variant="caption" color={effectiveGrants.length === 0 ? 'error.main' : 'text.secondary'} sx={{ display: 'block' }}>
                {effectiveGrants.length === 0
                  ? 'Select at least one grant type.'
                  : 'Implicit / Hybrid allows an ID token in the redirect (response_type id_token or code id_token); access tokens come only from the token endpoint unless the operator sets legacy_implicit_access_tokens. Client Credentials is for confidential clients only.'}
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12}>
            <TextField fullWidth multiline minRows={2} label="Allowed Redirect URIs (one per line)" value={form.redirect_uris_text} onChange={e => setForm({ ...form, redirect_uris_text: e.target.value })} placeholder="https://app.example.com/oidc/callback" InputProps={{ className: 'mono', sx: { fontSize: 13 } }} />
          </Grid>
          <Grid item xs={12} md={8}>
            <TextField fullWidth label="Post-Logout Redirect URIs (optional)" value={form.post_logout_uris_text} onChange={e => setForm({ ...form, post_logout_uris_text: e.target.value })} InputProps={{ className: 'mono', sx: { fontSize: 13 } }} />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField fullWidth label="Access Token TTL" value={form.access_token_ttl} onChange={e => setForm({ ...form, access_token_ttl: e.target.value })} helperText="e.g. 3600, 15m, 1h" />
          </Grid>
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="Initiate Login URI (optional)"
              placeholder="https://app.example.com/oidc/login"
              value={form.login_uri}
              onChange={e => setForm({ ...form, login_uri: e.target.value })}
              InputProps={{ className: 'mono', sx: { fontSize: 13 } }}
              helperText="Where the end-user portal tile starts sign-in (OIDC third-party-initiated login). The portal appends iss=<issuer>. Leave empty to hide this app from the portal."
            />
          </Grid>
        </Grid>
      </DialogContent>
      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={save} disabled={!form.name.trim() || effectiveGrants.length === 0}>
          {editingClient ? 'Save OIDC Client' : 'Create OIDC Client'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/* ==================== SCIM 2.0 TOKEN & PUSH CONNECTOR DIALOGS ==================== */
function ScimTokenDialog({ open, onClose, provider, onCreated }) {
  const [name, setName] = useState('');
  const [permission, setPermission] = useState('read');
  const [filterGroups, setFilterGroups] = useState('');
  const [expiresIn, setExpiresIn] = useState('never');
  const [err, setErr] = useState('');

  useEffect(() => {
    if (open) {
      setName('');
      setPermission('read');
      setFilterGroups('');
      setExpiresIn('never');
      setErr('');
    }
  }, [open]);

  const save = () => {
    setErr('');
    api(`/api/providers/${provider.id}/scim/tokens`, {
      method: 'POST',
      body: JSON.stringify({
        name,
        permission,
        filter_groups: filterGroups,
        expires_in: expiresIn === 'never' ? null : expiresIn,
      }),
    })
      .then(r => {
        onCreated(r.token);
        onClose();
      })
      .catch(e => setErr(errText(e, 'Failed to generate SCIM token')));
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Icon name="vpn_key" size={21} />
        <span>Generate Inbound SCIM 2.0 Bearer Token</span>
      </DialogTitle>
      <DialogContent dividers>
        {err && <Alert severity="error" sx={{ mb: 2 }}>{err}</Alert>}
        <Grid container spacing={2}>
          <Grid item xs={12}>
            <TextField fullWidth size="small" label="Client / Integration Name *" placeholder="e.g. Palo Alto CIE Poller, Grafana SCIM, Custom Sync" value={name} onChange={e => setName(e.target.value)} autoFocus />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField select fullWidth size="small" label="SCIM Permission" value={permission} onChange={e => setPermission(e.target.value)}>
              <MenuItem value="read">Read-Only (Pull Users &amp; Groups)</MenuItem>
              <MenuItem value="write">Read &amp; Write (Full SCIM CRUD)</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField select fullWidth size="small" label="Token Expiration" value={expiresIn} onChange={e => setExpiresIn(e.target.value)}>
              <MenuItem value="never">No Expiration</MenuItem>
              <MenuItem value="30d">30 Days</MenuItem>
              <MenuItem value="90d">90 Days</MenuItem>
              <MenuItem value="365d">1 Year</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12}>
            <TextField fullWidth size="small" label="Restrict Exposed Groups (Optional)" placeholder="Leave blank to expose all directory users & groups, or comma-separate group names" value={filterGroups} onChange={e => setFilterGroups(e.target.value)} />
          </Grid>
        </Grid>
      </DialogContent>
      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={save}>Generate Token</Button>
      </DialogActions>
    </Dialog>
  );
}

// Comparable form of a direct connector URL, built like the server's scim_url_compare_key():
// scheme and host in ASCII lower case, default port explicit, trailing slashes removed. A value
// that is not an absolute URL compares as ''.
function scimUrlCompareKey(url) {
  const m = /^([a-z][a-z0-9+.-]*):\/\/(?:([^\/?#]*)@)?(\[[^\]\/?#]*\]|[^:\/?#]*)(?::(\d*))?(\/[^?#]*)?(?:\?([^#]*))?(?:#(.*))?$/i
    .exec(String(url || '').trim());
  if (!m || !m[3]) return '';
  const asciiLower = (s) => s.replace(/[A-Z]+/g, c => c.toLowerCase());
  const scheme = asciiLower(m[1]);
  const port = m[4] ? parseInt(m[4], 10) : (scheme === 'https' ? 443 : (scheme === 'http' ? 80 : 0));
  return scheme + '://' + (m[2] !== undefined ? m[2] + '@' : '') +
    asciiLower(m[3].replace(/^[\[\]]+|[\[\]]+$/g, '')) + ':' + port +
    (m[5] || '').replace(/\/+$/, '') +
    (m[6] !== undefined ? '?' + m[6] : '') +
    (m[7] !== undefined ? '#' + m[7] : '');
}

function ScimConnectorDialog({ open, onClose, provider, editingConnector, onSaved }) {
  const empty = {
    name: '',
    delivery_mode: 'direct',
    scim_base_url: '',
    bearer_token: '',
    sync_groups: true,
    push_passwords: false,
    auto_sync: true,
    deprovision_action: 'deactivate',
    assigned_groups_text: '',
    status: 'active',
    reset_remote_mappings: false,
  };
  const [form, setForm] = useState(empty);
  const [err, setErr] = useState('');
  // Whether the admin set the reset checkbox by hand; until then it follows the agent URL label.
  const [resetTouched, setResetTouched] = useState(false);

  const savedUrl = (c) => (c.scim_base_url === 'agent://on-premises' ? '' : (c.scim_base_url || ''));
  // The agent URL is only a label, stored without trailing slashes.
  const labelKey = (s) => String(s || '').trim().replace(/\/+$/, '');

  useEffect(() => {
    if (!open) return;
    setErr('');
    setResetTouched(false);
    if (editingConnector) {
      setForm({
        name: editingConnector.name || '',
        delivery_mode: editingConnector.delivery_mode || 'direct',
        scim_base_url: savedUrl(editingConnector),
        bearer_token: '',
        sync_groups: editingConnector.sync_groups !== false,
        push_passwords: !!editingConnector.push_passwords,
        auto_sync: editingConnector.auto_sync !== false,
        deprovision_action: editingConnector.deprovision_action || 'deactivate',
        assigned_groups_text: (editingConnector.assigned_groups || []).join(', '),
        status: editingConnector.status || 'active',
        reset_remote_mappings: false,
      });
    } else {
      setForm(empty);
    }
  }, [open, editingConnector]);

  const isAgent = form.delivery_mode === 'agent';
  // The stored bearer token is only ever sent to the URL it was saved with (S08-02): a new
  // URL or delivery mode needs it again, and the remote ID mappings are reset (S08-10).
  // Only a direct connector's URL is its target. It is compared the way the server compares
  // it, so a cosmetic edit (host case, default port, trailing slash) is not a new target.
  // An agent connector's URL is only a label: the agent's config.json decides the target.
  const modeChanged = !!editingConnector && form.delivery_mode !== (editingConnector.delivery_mode || 'direct');
  const urlChanged = !!editingConnector && !isAgent &&
    scimUrlCompareKey(form.scim_base_url) !== scimUrlCompareKey(savedUrl(editingConnector));
  const targetChanged = modeChanged || urlChanged;
  const agentLabelChanged = !!editingConnector && isAgent && !modeChanged &&
    labelKey(form.scim_base_url) !== labelKey(savedUrl(editingConnector));
  const tokenEntered = form.bearer_token.trim() !== '';
  const tokenMissing = !isAgent && targetChanged && !tokenEntered;
  // The server cannot see whether a new token for the same URL, or an agent whose config.json
  // changed, points at another tenant, so the admin decides. The checkbox starts ticked when
  // the agent URL label changed (S08-10).
  const offerReset = !!editingConnector && !targetChanged && (isAgent || tokenEntered);

  const savedAsAgent = !!editingConnector && editingConnector.delivery_mode === 'agent';
  // The checkbox state for a saved agent connector shown in agent mode with label `url`.
  const autoReset = (prev, mode, url) => (resetTouched || !savedAsAgent || mode !== 'agent'
    ? prev.reset_remote_mappings
    : labelKey(url) !== labelKey(savedUrl(editingConnector)));
  const setAgentUrl = (value) => {
    setForm(prev => ({ ...prev, scim_base_url: value, reset_remote_mappings: autoReset(prev, prev.delivery_mode, value) }));
  };
  const setDeliveryMode = (mode) => {
    setForm(prev => ({ ...prev, delivery_mode: mode, reset_remote_mappings: autoReset(prev, mode, prev.scim_base_url) }));
  };

  const save = () => {
    setErr('');
    if (tokenMissing) {
      setErr('Re-enter the SCIM Bearer token: the stored token is only sent to the URL it was saved with.');
      return;
    }
    const url = editingConnector
      ? `/api/providers/${provider.id}/scim/connectors/${editingConnector.id}`
      : `/api/providers/${provider.id}/scim/connectors`;
    const payload = {
      name: form.name,
      delivery_mode: form.delivery_mode,
      scim_base_url: form.scim_base_url,
      sync_groups: !!form.sync_groups,
      push_passwords: !!form.push_passwords,
      auto_sync: !!form.auto_sync,
      deprovision_action: form.deprovision_action,
      assigned_groups: form.assigned_groups_text,
      status: form.status,
    };
    if (!isAgent && (tokenEntered || !editingConnector)) {
      payload.bearer_token = form.bearer_token;
    }
    // Sent explicitly for a target change too, so the reset the dialog announces always
    // happens, even if the server's own comparison found no change.
    if (editingConnector && (targetChanged || (offerReset && form.reset_remote_mappings))) {
      payload.reset_remote_mappings = true;
    }
    api(url, { method: editingConnector ? 'PUT' : 'POST', body: JSON.stringify(payload) })
      .then(r => {
        onSaved(r.connector);
        onClose();
      })
      .catch(e => setErr(errText(e, 'Failed to save SCIM connector')));
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Icon name="sync" size={22} />
        <span>{editingConnector ? `Edit Outbound SCIM Connector — ${editingConnector.name}` : 'Add Outbound SCIM 2.0 Push Connector'}</span>
      </DialogTitle>
      <DialogContent dividers>
        {err && <Alert severity="error" sx={{ mb: 2 }}>{err}</Alert>}
        <Grid container spacing={2}>
          <Grid item xs={12} sm={5}>
            <TextField fullWidth size="small" label="Target Application Name *" placeholder="e.g. On-Prem ERP, Palo Alto CIE, Nextcloud" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} autoFocus />
          </Grid>
          <Grid item xs={12} sm={4}>
            <TextField select fullWidth size="small" label="Delivery Mode" value={form.delivery_mode} onChange={e => setDeliveryMode(e.target.value)}>
              <MenuItem value="direct">Direct HTTPS Push (Cloud Reachable)</MenuItem>
              <MenuItem value="agent">Via On-Prem Windows SCIM Agent</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12} sm={3}>
            <TextField select fullWidth size="small" label="Connector Status" value={form.status} onChange={e => setForm({ ...form, status: e.target.value })}>
              <MenuItem value="active">Active</MenuItem>
              <MenuItem value="paused">Paused</MenuItem>
            </TextField>
          </Grid>
          {isAgent ? (
            <>
              <Grid item xs={12}>
                <Alert severity="info">
                  <strong>On-Premises Windows SCIM Proxy Agent:</strong> Run <code>scim-agent.exe</code> on your internal Windows machine. It connects outbound-only over HTTPS 443 to <code>{provider.issuer}</code> (no inbound firewall ports needed) and pushes SCIM requests locally to your internal application. Your internal SCIM URL and secret stay in <code>config.json</code> on Windows.
                </Alert>
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth size="small"
                  label="Internal On-Premises SCIM URL (Optional label / pre-fill for config.json)"
                  placeholder="http://127.0.0.1:8080/scim/v2 or https://internal-app.corp.local/scim/v2"
                  value={form.scim_base_url}
                  onChange={e => setAgentUrl(e.target.value)}
                  InputProps={{ className: 'mono' }}
                  helperText="Only a label: the agent sends requests to the URL in its config.json. Changing it here does not repoint the agent."
                />
              </Grid>
            </>
          ) : (
            <>
              <Grid item xs={12}>
                <TextField fullWidth size="small" label="Target SCIM 2.0 Base URL *" placeholder="https://sp.example.com/scim/v2" value={form.scim_base_url} onChange={e => setForm({ ...form, scim_base_url: e.target.value })} InputProps={{ className: 'mono' }} helperText="Base URL where /Users and /Groups will be provisioned via HTTPS" />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth size="small" type="password"
                  required={!editingConnector || targetChanged}
                  error={tokenMissing}
                  label={!editingConnector
                    ? 'SCIM Bearer Token'
                    : (targetChanged ? 'SCIM Bearer Token (re-enter for the new target)' : `SCIM Bearer Token (leave blank to keep ${editingConnector.token_preview})`)}
                  placeholder="Secret OAuth / SCIM Bearer token issued by target Service Provider"
                  value={form.bearer_token}
                  onChange={e => setForm({ ...form, bearer_token: e.target.value })}
                  InputProps={{ className: 'mono' }}
                  helperText={editingConnector
                    ? 'The stored token is only sent to the URL it was saved with; a new URL or delivery mode needs it again. Encrypted at rest using AES-256-GCM.'
                    : 'Encrypted at rest using AES-256-GCM'}
                />
              </Grid>
            </>
          )}
          {targetChanged && (
            <Grid item xs={12}>
              <Alert severity="info">
                The target changes, so the links to remote users and groups (remote ID mappings) are reset when you save, and the next sync matches users and groups again.
              </Alert>
            </Grid>
          )}
          {offerReset && (
            <Grid item xs={12}>
              <FormControlLabel
                control={<Checkbox size="small" checked={!!form.reset_remote_mappings} onChange={e => { setResetTouched(true); setForm({ ...form, reset_remote_mappings: e.target.checked }); }} />}
                label="Different target system or tenant: reset remote ID mappings"
              />
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', ml: 4 }}>
                {isAgent
                  ? (agentLabelChanged
                    ? `You changed the URL label. If the agent's config.json now points at another application or tenant, ${form.reset_remote_mappings ? 'keep this ticked' : 'tick this'}: otherwise the next sync updates, deactivates or deletes accounts there by the old remote IDs.${form.reset_remote_mappings ? ' Untick it if only the label changed.' : ''}`
                    : 'Tick this if the agent\'s config.json now points at another application or tenant, so the next sync does not update, deactivate or delete accounts there by the old remote IDs.')
                  : 'Tick this if the new token belongs to another tenant at the same URL, so the next sync does not update, deactivate or delete accounts there by the old remote IDs.'}
              </Typography>
            </Grid>
          )}
          <Grid item xs={12} sm={6}>
            <TextField select fullWidth size="small" label="Deprovisioning Action" value={form.deprovision_action} onChange={e => setForm({ ...form, deprovision_action: e.target.value })}>
              <MenuItem value="deactivate">Deactivate User (PATCH active=false)</MenuItem>
              <MenuItem value="delete">Delete Remote User (DELETE /Users/id)</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField fullWidth size="small" label="Scope to Assigned Groups (Optional)" placeholder="All users if empty, or e.g. Engineering, Admins" value={form.assigned_groups_text} onChange={e => setForm({ ...form, assigned_groups_text: e.target.value })} />
          </Grid>
          <Grid item xs={12}>
            <Paper variant="outlined" sx={{ px: 2, py: 1.25, display: 'flex', flexDirection: 'column', gap: 0.5, bgcolor: 'action.hover' }}>
              <Box sx={{ display: 'flex', gap: 2.5, flexWrap: 'wrap' }}>
                <FormControlLabel control={<Checkbox size="small" checked={!!form.sync_groups} onChange={e => setForm({ ...form, sync_groups: e.target.checked })} />} label="Push Groups & Memberships (/Groups)" />
                <FormControlLabel control={<Checkbox size="small" checked={!!form.auto_sync} onChange={e => setForm({ ...form, auto_sync: e.target.checked })} />} label="Auto-Sync on Directory Changes" />
                <FormControlLabel control={<Checkbox size="small" checked={!!form.push_passwords} onChange={e => setForm({ ...form, push_passwords: e.target.checked })} />} label="Push User Passwords (Optional)" />
              </Box>
              {form.push_passwords && (
                <Typography variant="caption" color="warning.main" sx={{ fontWeight: 600 }}>
                  When enabled, outbound SCIM User payloads include the user's password (`password` attribute) for target SPs that require local password sync. Push needs the vault key in OIDC_SCIM_ENCRYPTION_KEY (or the allow_password_push_with_key_file setting), and only passwords set or changed while one of your connectors pushes passwords are sent: users who set theirs earlier must set it again. Keep disabled when the SP delegates authentication via SAML/OIDC.
                </Typography>
              )}
            </Paper>
          </Grid>
        </Grid>
      </DialogContent>
      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={save} disabled={tokenMissing}>{editingConnector ? 'Save Changes' : 'Create Connector'}</Button>
      </DialogActions>
    </Dialog>
  );
}

/* ==================== FULL-PAGE PROVIDER WORKSPACE VIEW ==================== */
// Settings form values for a provider (S13-11, S04-03, G1e-03). A retention or key TTL the
// provider never set follows the server default (EXPIRED_KEY_RETENTION, SIGNING_KEY_TTL, else
// one hour). It is shown as the effective value the server reports, or left empty when the
// server reports none, and is only sent when the admin changes it.
function providerSettingsFromProvider(p) {
  const secs = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null);
  const retention = secs(p.expired_key_retention_seconds) ?? secs(p.effective_expired_key_retention_seconds) ?? 3600;
  // A stored TTL of 0 is not used by the server: it follows the default as well.
  const ttl = secs(p.key_ttl_seconds) || secs(p.effective_key_ttl_seconds);
  return {
    policy: p.default_auth_policy || 'flexible',
    retention: formatDuration(retention),
    lead: formatDuration(secs(p.key_rotation_lead_time_seconds) ?? 0),
    ttl: ttl ? formatDuration(ttl) : '',
  };
}

const SAML_CERT_GRACE_MS = 30 * 86400 * 1000;
// SAML_CERT_EXPIRY_WARNING_SECONDS of crypto.php.
const SAML_CERT_EXPIRY_WARNING_MS = 30 * 86400 * 1000;

// Expiry status of a SAML signing certificate (G1a-04): the server's expired, expires_soon and
// expires_in_days (provider_saml_cert_row()), computed from expires_at the same way only when
// they are missing (a warning 30 days ahead, or for the last third of a shorter validity).
function samlCertExpiry(c) {
  const cert = c || {};
  const expTs = cert.expires_at ? new Date(cert.expires_at).getTime() : NaN;
  const left = Number.isFinite(expTs) ? expTs - Date.now() : null;
  const expired = typeof cert.expired === 'boolean' ? cert.expired : (left !== null && left <= 0);
  let soon;
  if (typeof cert.expires_soon === 'boolean') {
    soon = cert.expires_soon;
  } else {
    const createdTs = cert.created_at ? new Date(cert.created_at).getTime() : NaN;
    let warn = SAML_CERT_EXPIRY_WARNING_MS;
    if (Number.isFinite(expTs) && Number.isFinite(createdTs) && expTs > createdTs) {
      warn = Math.min(warn, Math.floor((expTs - createdTs) / 3));
    }
    soon = left !== null && left > 0 && left < warn;
  }
  const days = typeof cert.expires_in_days === 'number'
    ? cert.expires_in_days
    : (left !== null ? Math.floor(left / 86400000) : null);
  return { expired, soon: !expired && soon, days };
}

// "in 3 days", "in 1 day" or "in less than a day".
function inDaysText(days) {
  if (typeof days !== 'number' || days < 1) return 'in less than a day';
  return `in ${days} day${days === 1 ? '' : 's'}`;
}

function ProviderWorkspaceView({ provider, onBack, refreshProviders, onOpenJwt, onNotify }) {
  const [tab, setTab] = useState(0);
  const [samlApps, setSamlApps] = useState([]);
  const [samlInfo, setSamlInfo] = useState(null);
  const [showMetaXml, setShowMetaXml] = useState(false);
  const [editSamlApp, setEditSamlApp] = useState(null);
  const [openSamlDialog, setOpenSamlDialog] = useState(false);

  const [oidcClients, setOidcClients] = useState([]);
  const [editOidc, setEditOidc] = useState(null);
  const [openOidcDialog, setOpenOidcDialog] = useState(false);
  const [mintedSecretClient, setMintedSecretClient] = useState(null);
  const [okCopySecret, copySecret] = useCopyFeedback();

  const [scimInfo, setScimInfo] = useState(null);
  const [openScimTokenDialog, setOpenScimTokenDialog] = useState(false);
  const [mintedScimToken, setMintedScimToken] = useState(null);
  const [okCopyScimToken, copyScimToken] = useCopyFeedback();
  const [openScimConnDialog, setOpenScimConnDialog] = useState(false);
  const [editScimConn, setEditScimConn] = useState(null);
  const [mintedAgentConn, setMintedAgentConn] = useState(null);
  const [okCopyAgentTok, copyAgentTok] = useCopyFeedback();
  const [okCopyAgentCfg, copyAgentCfg] = useCopyFeedback();
  const [busyConnId, setBusyConnId] = useState(null);

  const [keys, setKeys] = useState([]);
  const [activeKid, setActiveKid] = useState(null);
  const [keyMode, setKeyMode] = useState('generate');
  const [alg, setAlg] = useState('RS256');
  const [keyText, setKeyText] = useState('');
  // Lifetime of the next added key only; empty means the provider's key TTL (G1e-03).
  const [keyTtl, setKeyTtl] = useState('');
  const [applyTtlToProvider, setApplyTtlToProvider] = useState(false);
  // The provider's key TTL: the lifetime of automatically rotated keys.
  const [providerKeyTtl, setProviderKeyTtl] = useState('');
  const [expiredRetention, setExpiredRetention] = useState('1h');
  const [keyRotationLeadTime, setKeyRotationLeadTime] = useState('0s');
  const [defaultPolicy, setDefaultPolicy] = useState('flexible');
  const [savedSettings, setSavedSettings] = useState({ policy: 'flexible', retention: '1h', lead: '0s', ttl: '' });
  const [keyErr, setKeyErr] = useState('');
  const [pubKeyModal, setPubKeyModal] = useState(null);
  const [okCopyPub, copyPub] = useCopyFeedback();

  const [logs, setLogs] = useState([]);
  const [logFilter, setLogFilter] = useState('');
  const [okCopyMetaUrl, copyMetaUrl] = useCopyFeedback();
  const [okCopyMetaXml, copyMetaXml] = useCopyFeedback();
  const [okCopyCert, copyCert] = useCopyFeedback();

  const loadAll = () => {
    if (!provider) return;
    const fail = (what) => (e) => onNotify(errText(e, `Failed to load ${what}`), 'error');
    api(`/api/providers/${provider.id}/saml-apps`).then(r => setSamlApps(r.apps || [])).catch(fail('SAML apps'));
    api(`/api/providers/${provider.id}/saml-certs`).then(setSamlInfo).catch(fail('SAML certificates'));
    api(`/api/providers/${provider.id}/oidc-clients`).then(r => setOidcClients(r.clients || [])).catch(fail('OIDC clients'));
    api(`/api/providers/${provider.id}/scim`).then(setScimInfo).catch(fail('SCIM settings'));
    api(`/api/providers/${provider.id}/keys`).then(j => { setKeys(j.keys || []); setActiveKid(j.active_kid || null); }).catch(fail('signing keys'));
    api(`/api/providers/${provider.id}/audit-logs`).then(r => setLogs(r.logs || [])).catch(fail('audit log'));
  };

  useEffect(() => {
    if (provider) {
      const seeded = providerSettingsFromProvider(provider);
      setDefaultPolicy(seeded.policy);
      setExpiredRetention(seeded.retention);
      setKeyRotationLeadTime(seeded.lead);
      setProviderKeyTtl(seeded.ttl);
      setKeyTtl('');
      setApplyTtlToProvider(false);
      setSavedSettings(seeded);
      loadAll();
    }
  }, [provider?.id]);

  if (!provider) return null;

  // activate = false stages the certificate: published in the metadata, not yet signing (G1a-04).
  const rotateSamlCert = (activate = true) => {
    const question = activate
      ? 'Generate a new SAML 2.0 signing certificate and sign with it immediately? SPs that have not refreshed the IdP metadata will reject assertions until they do. The current certificate stays published for 30 days and can be re-activated.'
      : 'Stage a new SAML 2.0 signing certificate? It is published in the IdP metadata right away but is not used for signing until you activate it, so SPs can pick it up first.';
    if (!confirm(question)) return;
    api(`/api/providers/${provider.id}/saml-certs/rotate`, { method: 'POST', body: JSON.stringify({ activate }) })
      .then(r => {
        loadAll();
        const state = r && r.cert ? r.cert.state : null;
        if (!activate && state === 'active') {
          onNotify('The server activated the new certificate immediately (staging is not available): update the IdP metadata at your SPs now.', 'warning');
        } else {
          onNotify(activate ? 'Rotated SAML 2.0 X.509 signing certificate' : 'Staged a new SAML signing certificate; activate it once your SPs have refreshed the IdP metadata');
        }
      })
      .catch(e => onNotify(errText(e, 'SAML certificate rotation failed'), 'error'));
  };

  const activateSamlCert = (cert) => {
    if (!confirm(`Sign with certificate ${cert.kid} from now on? SPs that do not have it yet will reject assertions until they refresh the IdP metadata.`)) return;
    api(`/api/providers/${provider.id}/saml-certs/${encodeURIComponent(cert.id)}/activate`, { method: 'POST', body: '{}' })
      .then(() => { loadAll(); onNotify('Activated SAML signing certificate'); })
      .catch(e => onNotify(errText(e, 'Activating the certificate failed'), 'error'));
  };

  const deleteSamlCert = (cert) => {
    if (!confirm(`Delete certificate ${cert.kid}? It leaves the IdP metadata and can no longer be activated.`)) return;
    api(`/api/providers/${provider.id}/saml-certs/${encodeURIComponent(cert.id)}`, { method: 'DELETE' })
      .then(() => { loadAll(); onNotify('Deleted SAML signing certificate'); })
      .catch(e => onNotify(errText(e, 'Deleting the certificate failed'), 'error'));
  };

  const addOidcKey = () => {
    setKeyErr('');
    const ttlText = keyTtl.trim();
    const body = keyMode === 'generate' ? { keyMode: 'generate', alg } : { keyMode: 'paste', keyText };
    // Without a Key TTL the server gives the key the provider's key TTL. A typed one applies to
    // this key only, unless the admin also makes it the provider's key TTL (G1e-03).
    if (ttlText !== '') {
      body.keyTtl = ttlText;
      if (applyTtlToProvider) body.applyTtlToProvider = true;
    }
    api(`/api/providers/${provider.id}/keys`, { method: 'POST', body: JSON.stringify(body) })
      .then(r => {
        // Show the lifetime the server actually applied (S13-11).
        const secs = typeof r.valid_for_seconds === 'number' && r.valid_for_seconds > 0 ? r.valid_for_seconds : null;
        const lifetime = secs ? formatDuration(secs) : '';
        if (ttlText !== '' && lifetime) setKeyTtl(lifetime);
        const appliedToProvider = !!body.applyTtlToProvider && lifetime !== '';
        if (appliedToProvider) {
          setProviderKeyTtl(lifetime);
          setSavedSettings(s => ({ ...s, ttl: lifetime }));
          setApplyTtlToProvider(false);
        }
        loadAll(); refreshProviders();
        // Expired keys that had left the JWKS may be removed while the key is added.
        const pruned = Array.isArray(r.pruned) ? r.pruned.length : 0;
        onNotify(
          'Added OIDC signing key' + (lifetime ? ` (valid for ${lifetime})` : '') +
          (appliedToProvider ? `; the provider key TTL is now ${lifetime}` : '') +
          (pruned > 0 ? `; removed ${pruned} expired key${pruned === 1 ? '' : 's'}` : '')
        );
      })
      .catch(e => setKeyErr(errText(e, 'Add key failed')));
  };

  const setActiveKey = (kid) => {
    api(`/api/providers/${provider.id}/active-key`, { method: 'PATCH', body: JSON.stringify({ kid }) })
      .then(() => { setActiveKid(kid); refreshProviders(); onNotify('Updated active signing key'); })
      .catch(e => onNotify(errText(e, 'Changing the active signing key failed'), 'error'));
  };

  // Only changed settings are sent, so a retention or key TTL the provider never set keeps
  // following the server default (S04-03). Saved fields are re-seeded from the seconds the
  // server stored, and a refused value (HTTP 400) is reported instead of a success toast
  // (S13-11). The rotation lead time must stay below the key TTL, and each single-setting
  // route checks against the other's stored value. So the two go together in one provider
  // PATCH, which checks the new values against each other, whichever way they change (G1e-03).
  const saveProviderSettings = () => {
    const ttlText = providerKeyTtl.trim();
    const leadText = keyRotationLeadTime.trim();
    const retentionText = expiredRetention.trim();
    const ttlChanged = ttlText !== savedSettings.ttl;
    const leadChanged = leadText !== savedSettings.lead;
    const missing = [];
    if (ttlChanged && ttlText === '') missing.push('key TTL (e.g. 1h, 12h or 7d; at least 5m)');
    if (leadChanged && leadText === '') missing.push('rotation lead time (e.g. 0s or 5m)');
    if (missing.length) {
      onNotify('Not saved: enter a ' + missing.join(' and a '), 'error');
      return;
    }
    const jobs = [];
    if (defaultPolicy !== savedSettings.policy) {
      jobs.push({ field: 'policy', label: 'default sign-on policy', req: api(`/api/providers/${provider.id}/policy`, { method: 'PATCH', body: JSON.stringify({ default_auth_policy: defaultPolicy }) }) });
    }
    if (retentionText !== savedSettings.retention) {
      jobs.push({ field: 'retention', label: 'expired JWKS retention', req: api(`/api/providers/${provider.id}/expired-retention`, { method: 'PATCH', body: JSON.stringify({ retention: retentionText }) }) });
    }
    if (ttlChanged || leadChanged) {
      const timing = {};
      if (ttlChanged) timing.key_ttl = ttlText;
      if (leadChanged) timing.key_rotation_lead_time = leadText;
      jobs.push({
        field: 'timing',
        label: ttlChanged && leadChanged ? 'key TTL and rotation lead time' : (ttlChanged ? 'key TTL' : 'rotation lead time'),
        ttlChanged,
        leadChanged,
        req: api(`/api/providers/${provider.id}`, { method: 'PATCH', body: JSON.stringify(timing) }),
      });
    }
    if (jobs.length === 0) {
      onNotify('No settings changed', 'info');
      return;
    }
    Promise.allSettled(jobs.map(j => j.req)).then(results => {
      // Only the saved fields change; a key TTL applied by Add Key meanwhile is kept.
      const next = {};
      const errors = [];
      results.forEach((res, i) => {
        const job = jobs[i];
        if (res.status === 'rejected') {
          errors.push(`${job.label}: ${errText(res.reason, 'not saved')}`);
          return;
        }
        const r = res.value || {};
        if (job.field === 'policy') {
          next.policy = r.default_auth_policy || defaultPolicy;
          setDefaultPolicy(next.policy);
        } else if (job.field === 'retention') {
          next.retention = typeof r.expired_key_retention_seconds === 'number' ? formatDuration(r.expired_key_retention_seconds) : retentionText;
          setExpiredRetention(next.retention);
        } else if (job.field === 'timing') {
          const p = r.provider || {};
          if (job.ttlChanged) {
            next.ttl = typeof p.key_ttl_seconds === 'number' && p.key_ttl_seconds > 0 ? formatDuration(p.key_ttl_seconds) : ttlText;
            setProviderKeyTtl(next.ttl);
          }
          if (job.leadChanged) {
            next.lead = typeof p.key_rotation_lead_time_seconds === 'number' ? formatDuration(p.key_rotation_lead_time_seconds) : leadText;
            setKeyRotationLeadTime(next.lead);
          }
        }
      });
      setSavedSettings(prev => ({ ...prev, ...next }));
      if (results.some(res => res.status === 'fulfilled')) refreshProviders();
      if (errors.length) {
        onNotify('Not saved: ' + errors.join(' • '), 'error');
      } else {
        onNotify('Saved provider policy & key rotation settings');
      }
    });
  };

  const filteredLogs = logs.filter(l => {
    if (!logFilter.trim()) return true;
    const q = logFilter.toLowerCase();
    return (l.app_name || '').toLowerCase().includes(q) ||
      (l.username || '').toLowerCase().includes(q) ||
      (l.event_type || '').toLowerCase().includes(q) ||
      (l.protocol || '').toLowerCase().includes(q);
  });

  // G1a-04: the active certificate's expiry, from the server's fields on active_cert or on its
  // row in certs (state "active"); computed from expires_at only when both lack them.
  const activeCert = samlInfo?.active_cert || null;
  const activeCertRow = activeCert
    ? (samlInfo.certs || []).find(c => c.state === 'active' && (!activeCert.id || c.id === activeCert.id)) || null
    : null;
  const activeCertExpiry = activeCert ? samlCertExpiry({ ...(activeCertRow || {}), ...activeCert }) : null;
  const stagedCert = (samlInfo?.certs || []).find(c => c.state === 'next' && !samlCertExpiry(c).expired) || null;
  const rolloverAdvice = stagedCert
    ? 'A staged certificate is already published: activate it once the SPs have imported the IdP metadata.'
    : 'Use Stage Next, let the SPs import the IdP metadata, then activate the new certificate.';

  return (
    <Box className="fade-in">
      {/* Breadcrumb & Hero Header */}
      <Box sx={{ mb: 3 }}>
        <Button
          size="small"
          startIcon={<Icon name="arrow_back" size={17} />}
          onClick={onBack}
          sx={{ mb: 1.5, color: 'text.secondary', px: 1 }}
        >
          All Identity Providers
        </Button>

        <Paper variant="outlined" sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Box sx={{
                width: 52, height: 52, borderRadius: 3.5, background: avatarGradient(provider.friendly),
                display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontWeight: 800, fontSize: 20
              }}>
                {initialsOf(provider.friendly)}
              </Box>
              <Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25, flexWrap: 'wrap' }}>
                  <Typography variant="h5" sx={{ fontWeight: 800 }}>{provider.friendly}</Typography>
                  <PolicyBadge policy={provider.default_auth_policy} />
                  <Chip size="small" variant="outlined" label={`OIDC ${provider.alg || 'RS256'}`} className="mono" />
                </Box>
                <Typography variant="body2" color="text.secondary" className="mono" sx={{ mt: 0.5, fontSize: 12.5 }}>
                  {provider.issuer}
                </Typography>
              </Box>
            </Box>

            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Button size="small" variant="outlined" startIcon={<Icon name="apps" size={17} />} component="a" href={provider.portal_url} target="_blank">
                User Portal
              </Button>
              <Button size="small" variant="outlined" startIcon={<Icon name="play_arrow" size={18} />} component="a" href={`${provider.issuer}/test/oidc/start`} target="_blank">
                OIDC Playground
              </Button>
              <Button size="small" variant="outlined" startIcon={<Icon name="download" size={17} />} component="a" href={provider.saml_metadata_download} target="_blank">
                Export SAML XML
              </Button>
              <Button size="small" variant="contained" startIcon={<Icon name="token" size={17} />} onClick={() => onOpenJwt(provider)}>
                Mint JWT
              </Button>
            </Box>
          </Box>

          <Tabs
            value={tab}
            onChange={(_, v) => setTab(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ mt: 2.5, borderBottom: 1, borderColor: 'divider', minHeight: 42 }}
          >
            <Tab icon={<Icon name="hub" size={18} />} iconPosition="start" label={`SAML 2.0 Apps & Metadata (${samlApps.length})`} sx={{ minHeight: 42 }} />
            <Tab icon={<Icon name="integration_instructions" size={18} />} iconPosition="start" label={`OIDC 1.0 Clients (${oidcClients.length})`} sx={{ minHeight: 42 }} />
            <Tab icon={<Icon name="sync" size={18} />} iconPosition="start" label={`SCIM 2.0 Provisioning (${(scimInfo?.connectors?.length || 0) + (scimInfo?.tokens?.length || 0)})`} sx={{ minHeight: 42 }} />
            <Tab icon={<Icon name="vpn_key" size={18} />} iconPosition="start" label={`Keys, Certs & Policy (${keys.length})`} sx={{ minHeight: 42 }} />
            <Tab icon={<Icon name="receipt_long" size={18} />} iconPosition="start" label={`SSO Audit Stream (${logs.length})`} sx={{ minHeight: 42 }} />
          </Tabs>
        </Paper>
      </Box>

      {/* TAB 0: SAML 2.0 APPS & LIVE METADATA */}
      {tab === 0 && (
        <Box className="fade-in">
          {samlInfo && (
            <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2, mb: 2 }}>
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Icon name="cloud_done" size={20} />
                    Hosted SAML 2.0 Identity Provider Metadata
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Point external Service Providers (Okta, Palo Alto Networks, AWS) directly to the live Metadata URL or download the XML descriptor.
                  </Typography>
                </Box>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  <Button size="small" variant="contained" startIcon={<Icon name={okCopyMetaUrl ? 'check' : 'link'} size={17} />} onClick={() => copyMetaUrl(samlInfo.metadata_url)}>
                    {okCopyMetaUrl ? 'Copied Metadata URL!' : 'Copy Metadata URL'}
                  </Button>
                  <Button size="small" variant="outlined" startIcon={<Icon name="download" size={17} />} component="a" href={samlInfo.metadata_download_url} target="_blank">
                    Metadata .xml
                  </Button>
                  <Button size="small" variant="outlined" startIcon={<Icon name="workspace_premium" size={17} />} component="a" href={samlInfo.cert_download_url} target="_blank">
                    Signing Cert .pem
                  </Button>
                  <Button size="small" variant="text" onClick={() => setShowMetaXml(!showMetaXml)}>
                    {showMetaXml ? 'Hide XML' : 'Inspect XML'}
                  </Button>
                </Box>
              </Box>

              <CopyEndpointRow label="Live Metadata URL" url={samlInfo.metadata_url} downloadUrl={samlInfo.metadata_download_url} />
              <CopyEndpointRow label="IdP Entity ID" url={samlInfo.entity_id} openable={false} />
              <CopyEndpointRow label="SAML SSO URL" url={samlInfo.sso_url} openable={false} />
              <CopyEndpointRow label="SAML SLO URL" url={samlInfo.slo_url} openable={false} />
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: -0.25, mb: 0.85, px: 1.5 }}>
                Single Logout ends the user's IdP session and answers the SP that asked; it does not sign the user out of other applications.
              </Typography>

              <Collapse in={showMetaXml}>
                <Paper variant="outlined" sx={{ position: 'relative', mt: 2, p: 2, maxHeight: 260, overflow: 'auto', bgcolor: '#0f172a', color: '#e2e8f0', borderColor: '#1e293b' }}>
                  <Button size="small" variant="outlined" sx={{ position: 'absolute', top: 8, right: 8, color: '#e2e8f0', borderColor: '#334155' }} onClick={() => copyMetaXml(samlInfo.metadata_xml)}>
                    {okCopyMetaXml ? 'Copied!' : 'Copy XML'}
                  </Button>
                  <pre style={{ margin: 0, fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}><code>{samlInfo.metadata_xml}</code></pre>
                </Paper>
              </Collapse>
            </Paper>
          )}

          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1.5 }}>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 700 }}>SAML 2.0 Service Providers</Typography>
              <Typography variant="body2" color="text.secondary">Connected SPs supporting SP-Initiated &amp; IdP-Initiated SSO</Typography>
            </Box>
            <Button variant="contained" startIcon={<Icon name="add" size={18} />} onClick={() => { setEditSamlApp(null); setOpenSamlDialog(true); }}>
              Add SAML App / Import XML
            </Button>
          </Box>

          {samlApps.length === 0 ? (
            <Paper variant="outlined" sx={{ p: 5, textAlign: 'center' }}>
              <Icon name="hub" size={38} style={{ opacity: 0.4, marginBottom: 8 }} />
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>No SAML 2.0 Service Providers configured</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 460, mx: 'auto', mt: 0.5, mb: 2.5 }}>
                Import a Service Provider XML metadata file (such as Palo Alto Networks or Okta SP XML) to auto-configure endpoints, certificates, and attribute mappings.
              </Typography>
              <Button variant="contained" startIcon={<Icon name="upload_file" size={18} />} onClick={() => { setEditSamlApp(null); setOpenSamlDialog(true); }}>
                Import SP Metadata XML
              </Button>
            </Paper>
          ) : (
            <Grid container spacing={2}>
              {samlApps.map(app => (
                <Grid item xs={12} key={app.id}>
                  <Paper variant="outlined" sx={{ p: 2.5, transition: 'border-color 0.15s', '&:hover': { borderColor: 'primary.main' } }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2 }}>
                      <Box sx={{ flex: 1, minWidth: 280 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1, flexWrap: 'wrap' }}>
                          <Chip size="small" label="SAML 2.0" sx={{ fontWeight: 700, bgcolor: 'rgba(245, 158, 11, 0.14)', color: '#d97706' }} />
                          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{app.name}</Typography>
                          <PolicyBadge policy={app.auth_policy} inherited={provider.default_auth_policy} />
                          {app.verify_authn_request_sig && <Chip size="small" variant="outlined" icon={<Icon name="verified" size={14} />} label="Signed AuthnRequest" />}
                          {app.allow_weak_sha1 && <Chip size="small" variant="outlined" color="warning" label="Legacy SHA-1" />}
                          {app.encrypt_assertion && app.sp_encryption_cert_pem && <Chip size="small" variant="outlined" icon={<Icon name="enhanced_encryption" size={14} />} label="Encrypted Assertion" />}
                          {app.encrypt_assertion && !app.sp_encryption_cert_pem && <Chip size="small" color="error" variant="outlined" label="Encryption on, no SP certificate" />}
                          {/* S02-10: unkeyed persistent NameIDs are sent only while legacy_saml_persistent_ids is on. */}
                          {samlAppCanIssuePersistent(app) && app.persistent_id_scheme === 'legacy' && (
                            app.persistent_id_scheme_effective === 'legacy'
                              ? <Chip size="small" variant="outlined" color="warning" label="Legacy persistent NameIDs" />
                              : <Chip size="small" variant="outlined" label="Legacy NameID setting (not in effect)" />
                          )}
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 0.4 }}>
                          <strong>Entity ID:</strong> <span className="mono" style={{ fontSize: 12.5 }}>{app.sp_entity_id}</span>
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 0.4 }}>
                          <strong>ACS POST:</strong> <span className="mono" style={{ fontSize: 12.5 }}>{app.acs_url}</span>
                        </Typography>
                        {(app.acs_endpoints || []).filter(ep => ep && ep.location && ep.location !== app.acs_url).length > 0 && (
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 0.4 }}>
                            <strong>Other accepted ACS endpoints:</strong>{' '}
                            <span className="mono" style={{ fontSize: 12 }}>
                              {(app.acs_endpoints || []).filter(ep => ep && ep.location && ep.location !== app.acs_url).map(ep => `[${ep.index ?? '—'}] ${ep.location}`).join(', ')}
                            </span>
                          </Typography>
                        )}
                        {app.slo_url && (
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 0.4 }}>
                            <strong>SLO:</strong> <span className="mono" style={{ fontSize: 12.5 }}>{app.slo_url}</span>
                          </Typography>
                        )}
                        <Box sx={{ mb: 1 }} />
                        <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
                          {(app.attribute_mapping || []).map((m, i) => (
                            <Chip key={i} size="small" variant="outlined" label={`${m.name} ← ${m.source}`} className="mono" sx={{ fontSize: 11.5 }} />
                          ))}
                        </Box>
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                        <Button size="small" variant="contained" color="secondary" startIcon={<Icon name="science" size={17} />} component="a" href={`${provider.issuer}/test/saml/start?app_id=${encodeURIComponent(app.id)}`} target="_blank">
                          Dry-Run &amp; Verify
                        </Button>
                        <Button size="small" variant="outlined" startIcon={<Icon name="launch" size={16} />} component="a" href={`${provider.issuer}/saml/sso?app_id=${encodeURIComponent(app.id)}`} target="_blank">
                          Launch SSO
                        </Button>
                        <IconButton size="small" onClick={() => { setEditSamlApp(app); setOpenSamlDialog(true); }}><Icon name="edit" size={18} /></IconButton>
                        <IconButton size="small" color="error" onClick={() => {
                          if (!confirm(`Delete SAML app "${app.name}"?`)) return;
                          api(`/api/providers/${provider.id}/saml-apps/${app.id}`, { method: 'DELETE' })
                            .then(() => { loadAll(); refreshProviders(); onNotify('Deleted SAML app'); })
                            .catch(e => onNotify(errText(e, 'Delete failed'), 'error'));
                        }}><Icon name="delete_outline" size={19} /></IconButton>
                      </Box>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          )}
        </Box>
      )}

      {/* TAB 1: OIDC 1.0 CLIENTS */}
      {tab === 1 && (
        <Box className="fade-in">
          <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1.5, display: 'flex', alignItems: 'center', gap: 1 }}>
              <Icon name="travel_explore" size={20} />
              OpenID Connect 1.0 Discovery &amp; Endpoints
            </Typography>
            <CopyEndpointRow label="OIDC Discovery" url={provider.discovery} />
            <CopyEndpointRow label="Authorize URL" url={provider.authorize_endpoint} openable={false} />
            <CopyEndpointRow label="Token URL" url={provider.token_endpoint} openable={false} />
            <CopyEndpointRow label="UserInfo URL" url={provider.userinfo_endpoint} openable={false} />
            <CopyEndpointRow label="JWKS Keys URI" url={provider.jwks} />
          </Paper>

          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1.5 }}>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 700 }}>OIDC Relying Party Clients</Typography>
              <Typography variant="body2" color="text.secondary">OAuth 2.0 / OIDC applications with S256 PKCE &amp; Touch ID AMR/ACR claims</Typography>
            </Box>
            <Button variant="contained" startIcon={<Icon name="add" size={18} />} onClick={() => { setEditOidc(null); setOpenOidcDialog(true); }}>
              New OIDC Client
            </Button>
          </Box>

          {oidcClients.length === 0 ? (
            <Paper variant="outlined" sx={{ p: 5, textAlign: 'center' }}>
              <Icon name="integration_instructions" size={38} style={{ opacity: 0.4, marginBottom: 8 }} />
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>No OIDC clients registered yet</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 440, mx: 'auto', mt: 0.5, mb: 2.5 }}>
                Create a confidential web client or public PKCE SPA/CLI client to authenticate users via Authorization Code + S256 PKCE.
              </Typography>
              <Button variant="contained" startIcon={<Icon name="add" size={18} />} onClick={() => { setEditOidc(null); setOpenOidcDialog(true); }}>
                Create OIDC Client
              </Button>
            </Paper>
          ) : (
            <Grid container spacing={2}>
              {oidcClients.map(c => (
                <Grid item xs={12} key={c.id}>
                  <Paper variant="outlined" sx={{ p: 2.5, transition: 'border-color 0.15s', '&:hover': { borderColor: 'primary.main' } }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2 }}>
                      <Box sx={{ flex: 1, minWidth: 280 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1, flexWrap: 'wrap' }}>
                          <Chip size="small" label="OIDC 1.0" sx={{ fontWeight: 700, bgcolor: 'rgba(59, 130, 246, 0.14)', color: '#2563eb' }} />
                          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{c.name}</Typography>
                          <Chip size="small" variant="outlined" label={c.is_public ? 'Public + PKCE' : 'Confidential'} />
                          <PolicyBadge policy={c.auth_policy} inherited={provider.default_auth_policy} />
                          {(c.grant_types || []).includes('implicit') && <Chip size="small" color="warning" variant="outlined" label="Implicit / Hybrid" />}
                          {(c.grant_types || []).includes('client_credentials') && <Chip size="small" variant="outlined" label="Client Credentials" />}
                        </Box>
                        <Typography variant="body2" sx={{ mb: 0.4 }}>
                          <strong>client_id:</strong> <code style={{ fontSize: 12.5 }}>{c.client_id}</code>
                        </Typography>
                        {!c.is_public && (
                          <Typography variant="body2" sx={{ mb: 0.4 }}>
                            <strong>client_secret:</strong> <code style={{ fontSize: 12.5 }}>{c.client_secret_preview || 'sec_••••••••'}</code>{' '}
                            <Chip size="small" label="Hashed at rest" sx={{ height: 20, fontSize: 11, ml: 0.5 }} />
                          </Typography>
                        )}
                        <Typography variant="body2" color="text.secondary">
                          <strong>Redirect URIs:</strong> <span className="mono" style={{ fontSize: 12 }}>{(c.redirect_uris || []).join(', ') || '—'}</span>
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                        <Button size="small" variant="contained" color="secondary" startIcon={<Icon name="play_arrow" size={17} />} component="a" href={`${provider.issuer}/test/oidc/start?client_db_id=${encodeURIComponent(c.id)}`} target="_blank">
                          Test Flow
                        </Button>
                        {!c.is_public && (
                          <Button size="small" variant="outlined" startIcon={<Icon name="autorenew" size={16} />} onClick={() => {
                            if (!confirm(`Rotate client_secret for "${c.name}"? Existing integrations using the old secret will need updating.`)) return;
                            // The dedicated route changes only the secret; it does not re-submit
                            // (and re-validate) the rest of the stored client.
                            api(`/api/providers/${provider.id}/oidc-clients/${c.id}/rotate-secret`, { method: 'POST', body: '{}' })
                              .then(res => {
                                loadAll();
                                if (res.client?.client_secret) setMintedSecretClient(res.client);
                                else onNotify('Rotated client_secret');
                              })
                              .catch(e => onNotify(errText(e, 'Secret rotation failed'), 'error'));
                          }}>
                            Rotate Secret
                          </Button>
                        )}
                        <IconButton size="small" onClick={() => { setEditOidc(c); setOpenOidcDialog(true); }}><Icon name="edit" size={18} /></IconButton>
                        <IconButton size="small" color="error" onClick={() => {
                          if (!confirm(`Delete OIDC client "${c.name}"?`)) return;
                          api(`/api/providers/${provider.id}/oidc-clients/${c.id}`, { method: 'DELETE' })
                            .then(() => { loadAll(); refreshProviders(); onNotify('Deleted OIDC client'); })
                            .catch(e => onNotify(errText(e, 'Delete failed'), 'error'));
                        }}><Icon name="delete_outline" size={19} /></IconButton>
                      </Box>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          )}
        </Box>
      )}

      {/* TAB 2: SCIM 2.0 INBOUND SERVER & OUTBOUND PUSH PROVISIONING */}
      {tab === 2 && (
        <Box className="fade-in">
          <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2, mb: 2 }}>
              <Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Icon name="cloud_sync" size={20} />
                  Hosted Inbound SCIM 2.0 Server (RFC 7643 / RFC 7644)
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  External clients can pull or manage directory users and groups from this Identity Provider using a scoped SCIM Bearer Token.
                </Typography>
              </Box>
              <Button size="small" variant="contained" startIcon={<Icon name="add" size={17} />} onClick={() => setOpenScimTokenDialog(true)}>
                Generate SCIM Token
              </Button>
            </Box>

            <CopyEndpointRow label="SCIM 2.0 Base URL" url={scimInfo?.scim_base_url || `${provider.issuer}/scim/v2`} openable={false} />
            <CopyEndpointRow label="SCIM Users URL" url={scimInfo?.users_endpoint || `${provider.issuer}/scim/v2/Users`} openable={false} />
            <CopyEndpointRow label="SCIM Groups URL" url={scimInfo?.groups_endpoint || `${provider.issuer}/scim/v2/Groups`} openable={false} />
            <CopyEndpointRow label="ServiceProviderConfig" url={scimInfo?.service_provider_config_url || `${provider.issuer}/scim/v2/ServiceProviderConfig`} openable={false} />

            <Divider sx={{ my: 2 }} />
            <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: 'uppercase', display: 'block', mb: 1.25 }}>
              Inbound SCIM Bearer Tokens ({scimInfo?.tokens?.length || 0})
            </Typography>
            {(scimInfo?.tokens || []).length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                No dedicated SCIM Bearer tokens issued yet. Click <strong>Generate SCIM Token</strong> (or use a scoped Admin API Client token with <code>user_scope</code>).
              </Typography>
            ) : (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                {(scimInfo?.tokens || []).map(t => (
                  <Paper key={t.id} variant="outlined" sx={{ p: 1.5, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 1 }}>
                    <Box>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                        <Typography variant="body2" sx={{ fontWeight: 700 }}>{t.name}</Typography>
                        <Chip size="small" color={t.permission === 'write' ? 'warning' : 'success'} variant="outlined" label={t.permission === 'write' ? 'Read & Write' : 'Read-Only (Pull)'} />
                        <code style={{ fontSize: 12 }}>{t.secret_preview}</code>
                        {(t.filter_groups || []).length > 0 && (
                          <Chip size="small" variant="outlined" label={`Groups: ${t.filter_groups.join(', ')}`} />
                        )}
                      </Box>
                      <Typography variant="caption" color="text.secondary">
                        Created {t.created_at}{t.last_used_at ? ` • Last used ${relativeTime(t.last_used_at)} (${t.last_used_ip || ''})` : ' • Never used'}
                        {t.expires_at ? ` • Expires ${t.expires_at}` : ''}
                      </Typography>
                    </Box>
                    <IconButton size="small" color="error" onClick={() => {
                      if (!confirm(`Revoke SCIM token "${t.name}"?`)) return;
                      api(`/api/providers/${provider.id}/scim/tokens/${t.id}`, { method: 'DELETE' })
                        .then(() => { loadAll(); refreshProviders(); onNotify('Revoked SCIM token'); })
                        .catch(e => onNotify('SCIM token NOT revoked: ' + errText(e, 'request failed'), 'error'));
                    }}>
                      <Icon name="delete_outline" size={18} />
                    </IconButton>
                  </Paper>
                ))}
              </Box>
            )}
          </Paper>

          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1.5 }}>
            <Box>
              <Typography variant="h6" sx={{ fontWeight: 700 }}>Outbound SCIM 2.0 Push Connectors</Typography>
              <Typography variant="body2" color="text.secondary">
                Automatically push directory users, groups, and optional passwords to downstream Service Providers (Palo Alto CIE, Nextcloud, Slack, AWS)
              </Typography>
            </Box>
            <Button variant="contained" startIcon={<Icon name="add" size={18} />} onClick={() => { setEditScimConn(null); setOpenScimConnDialog(true); }}>
              Add Push Connector
            </Button>
          </Box>

          {(scimInfo?.connectors || []).length === 0 ? (
            <Paper variant="outlined" sx={{ p: 5, textAlign: 'center' }}>
              <Icon name="sync" size={38} style={{ opacity: 0.4, marginBottom: 8 }} />
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>No Outbound SCIM Push Connectors configured</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 480, mx: 'auto', mt: 0.5, mb: 2.5 }}>
                Connect external applications that expect an Identity Provider to push SCIM 2.0 Users &amp; Groups to their SCIM endpoint.
              </Typography>
              <Button variant="contained" startIcon={<Icon name="add" size={18} />} onClick={() => { setEditScimConn(null); setOpenScimConnDialog(true); }}>
                Configure SCIM Push Connector
              </Button>
            </Paper>
          ) : (
            <Grid container spacing={2}>
              {(scimInfo?.connectors || []).map(conn => (
                <Grid item xs={12} key={conn.id}>
                  <Paper variant="outlined" sx={{ p: 2.5, transition: 'border-color 0.15s', '&:hover': { borderColor: 'primary.main' } }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2 }}>
                      <Box sx={{ flex: 1, minWidth: 280 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1, flexWrap: 'wrap' }}>
                          <Chip
                            size="small"
                            label={conn.delivery_mode === 'agent' ? 'WINDOWS AGENT' : 'SCIM 2.0 PUSH'}
                            sx={{
                              fontWeight: 700,
                              bgcolor: conn.delivery_mode === 'agent' ? 'rgba(99, 102, 241, 0.15)' : 'rgba(16, 185, 129, 0.14)',
                              color: conn.delivery_mode === 'agent' ? '#4f46e5' : '#059669'
                            }}
                          />
                          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{conn.name}</Typography>
                          <Chip size="small" color={conn.status === 'active' ? 'success' : 'default'} variant="outlined" label={conn.status} />
                          {conn.delivery_mode === 'agent' && (
                            <Chip
                              size="small"
                              color={conn.agent_online ? 'success' : 'default'}
                              icon={<Icon name={conn.agent_online ? 'check_circle' : 'schedule'} size={14} />}
                              label={conn.agent_online ? `Agent Online (${conn.agent_hostname || 'Windows'})` : 'Agent Offline'}
                            />
                          )}
                          {conn.sync_running && <Chip size="small" color="info" icon={<Icon name="sync" size={14} />} label="Sync running" />}
                          {conn.sync_queued && <Chip size="small" color="warning" variant="outlined" icon={<Icon name="schedule" size={14} />} label="Changes queued" />}
                          {conn.sync_groups && <Chip size="small" variant="outlined" label="Groups Sync" />}
                          {conn.auto_sync && <Chip size="small" variant="outlined" label="Auto-Sync" />}
                          {conn.push_passwords && <Chip size="small" color="warning" variant="outlined" icon={<Icon name="password" size={14} />} label="Password Sync Enabled" />}
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 0.4 }}>
                          <strong>{conn.delivery_mode === 'agent' ? 'On-Prem Target:' : 'SCIM Base URL:'}</strong>{' '}
                          <span className="mono" style={{ fontSize: 12.5 }}>{conn.scim_base_url}</span>
                          {conn.delivery_mode === 'agent' && conn.agent_last_seen_at && (
                            <span> • Agent heartbeat {relativeTime(conn.agent_last_seen_at)} ({conn.agent_last_ip || ''})</span>
                          )}
                        </Typography>
                        {(conn.assigned_groups || []).length > 0 && (
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 0.4 }}>
                            <strong>Scoped Groups:</strong> {conn.assigned_groups.join(', ')}
                          </Typography>
                        )}
                        {conn.last_sync_at && (
                          <Typography variant="caption" color={conn.last_sync_status === 'success' ? 'success.main' : 'warning.main'} sx={{ display: 'block', mt: 0.6, fontWeight: 600, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                            Last Sync ({conn.last_sync_at}): {conn.last_sync_summary}
                          </Typography>
                        )}
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                        {conn.delivery_mode === 'agent' && (
                          <Button
                            size="small"
                            variant="outlined"
                            startIcon={<Icon name="autorenew" size={16} />}
                            onClick={() => {
                              if (!confirm(`Rotate Windows Agent Token for "${conn.name}"? You will need to update config.json on your Windows server.`)) return;
                              api(`/api/providers/${provider.id}/scim/connectors/${conn.id}`, {
                                method: 'PUT',
                                body: JSON.stringify({ rotate_agent_token: true }),
                              }).then(r => {
                                loadAll();
                                if (r.connector?.agent_token) setMintedAgentConn(r.connector);
                                else onNotify('Rotated the agent token');
                              }).catch(e => onNotify('Agent token NOT rotated: ' + errText(e, 'request failed'), 'error'));
                            }}
                          >
                            Agent Token
                          </Button>
                        )}
                        <Button
                          size="small"
                          variant="outlined"
                          disabled={busyConnId === conn.id}
                          startIcon={<Icon name="network_check" size={16} />}
                          onClick={() => {
                            setBusyConnId(conn.id);
                            api(`/api/providers/${provider.id}/scim/connectors/${conn.id}/test`, { method: 'POST' })
                              .then(r => onNotify(r.message || 'SCIM connection verified', r.ok === false ? 'warning' : 'success'))
                              .catch(e => onNotify('SCIM Test Failed: ' + errText(e, 'Error'), 'error'))
                              .finally(() => setBusyConnId(null));
                          }}
                        >
                          Test
                        </Button>
                        <Button
                          size="small"
                          variant="contained"
                          disabled={busyConnId === conn.id}
                          startIcon={<Icon name="sync" size={17} />}
                          onClick={() => {
                            setBusyConnId(conn.id);
                            api(`/api/providers/${provider.id}/scim/connectors/${conn.id}/sync`, {
                              method: 'POST',
                              body: JSON.stringify({ force: true }),
                            })
                              .then(r => {
                                loadAll();
                                // 'deferred': a sync is already running and this one follows it;
                                // 'skipped': paused (circuit open, agent offline). Neither completed.
                                if (r.status === 'deferred') onNotify(r.summary || 'A sync is already running; this one runs when it finishes', 'info');
                                else if (r.status === 'skipped') onNotify(r.summary || 'Sync skipped', 'warning');
                                else if (r.ok === false) onNotify(r.summary || 'SCIM sync finished with errors', 'warning');
                                else onNotify(r.summary || 'SCIM sync completed');
                              })
                              .catch(e => onNotify('SCIM Sync Failed: ' + errText(e, 'Error'), 'error'))
                              .finally(() => setBusyConnId(null));
                          }}
                        >
                          {busyConnId === conn.id ? 'Syncing…' : 'Sync Now'}
                        </Button>
                        <IconButton size="small" onClick={() => { setEditScimConn(conn); setOpenScimConnDialog(true); }}><Icon name="edit" size={18} /></IconButton>
                        <IconButton size="small" color="error" onClick={() => {
                          if (!confirm(`Delete SCIM push connector "${conn.name}"?`)) return;
                          api(`/api/providers/${provider.id}/scim/connectors/${conn.id}`, { method: 'DELETE' })
                            .then(() => { loadAll(); refreshProviders(); onNotify('Deleted SCIM connector'); })
                            .catch(e => onNotify(errText(e, 'Delete failed'), 'error'));
                        }}><Icon name="delete_outline" size={19} /></IconButton>
                      </Box>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          )}
        </Box>
      )}

      {/* TAB 3: SIGNING KEYS, SAML X.509 CERT & DEFAULT POLICY */}
      {tab === 3 && (
        <Grid container spacing={3} className="fade-in">
          <Grid item xs={12}>
            <Paper variant="outlined" sx={{ p: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <Icon name="tune" size={20} />
                Tenant Default Sign-On Policy &amp; Key Rotation Window
              </Typography>
              <Grid container spacing={2} alignItems="flex-start">
                <Grid item xs={12} md={4}>
                  <TextField select fullWidth size="small" label="Default Sign-On Policy" value={defaultPolicy} onChange={e => setDefaultPolicy(e.target.value)}>
                    <MenuItem value="flexible">Flexible (Touch ID or Password)</MenuItem>
                    <MenuItem value="touchid_only">Touch ID Only (Passwordless)</MenuItem>
                    <MenuItem value="mfa">Step-Up MFA (Password + Touch ID)</MenuItem>
                  </TextField>
                </Grid>
                <Grid item xs={12} sm={6} md={4}>
                  <TextField
                    fullWidth size="small"
                    label="Key TTL (automatic rotation)"
                    value={providerKeyTtl}
                    onChange={e => setProviderKeyTtl(e.target.value)}
                    placeholder="Server default"
                    InputLabelProps={{ shrink: true }}
                    helperText={savedSettings.ttl
                      ? 'Lifetime of rotated keys and the default for added keys, at least 5m: e.g. 1h, 12h, 7d'
                      : 'Follows the server default (SIGNING_KEY_TTL, else 1h). Enter e.g. 12h or 7d to set it.'}
                  />
                </Grid>
                <Grid item xs={12} sm={6} md={4}>
                  <TextField fullWidth size="small" label="Rotation Lead Time" value={keyRotationLeadTime} onChange={e => setKeyRotationLeadTime(e.target.value)} helperText="Rotate this long before the active key expires: 0, or at least 5 minutes shorter than the key TTL (e.g. 0s, 5m, 15m)." />
                </Grid>
                <Grid item xs={12} sm={6} md={4}>
                  <TextField fullWidth size="small" label="Expired JWKS Retention" value={expiredRetention} onChange={e => setExpiredRetention(e.target.value)} helperText="How long expired keys stay published, e.g. 30m, 2h, 1d (seconds, s/m/h/d/w)" />
                </Grid>
                <Grid item xs={12} sm={6} md={2}>
                  <Button variant="contained" fullWidth onClick={saveProviderSettings}>Save Settings</Button>
                </Grid>
              </Grid>
            </Paper>
          </Grid>

          <Grid item xs={12} md={5}>
            <Paper variant="outlined" sx={{ p: 3, height: '100%' }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1.5 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Icon name="workspace_premium" size={20} />
                  SAML 2.0 X.509 Certificate
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  <Tooltip title="Publish a new certificate now and activate it later, after SPs refreshed the metadata">
                    <Button size="small" variant="outlined" startIcon={<Icon name="schedule" size={16} />} onClick={() => rotateSamlCert(false)}>
                      Stage Next
                    </Button>
                  </Tooltip>
                  <Button size="small" variant="outlined" startIcon={<Icon name="autorenew" size={16} />} onClick={() => rotateSamlCert(true)}>
                    Rotate Now
                  </Button>
                </Box>
              </Box>
              {samlInfo?.active_cert && (
                <Box>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: 'action.hover', border: '1px solid', borderColor: 'divider', mb: 1.5 }}>
                    <Typography variant="body2" sx={{ mb: 0.5 }}><strong>Key ID:</strong> <code style={{ fontSize: 12.5 }}>{samlInfo.active_cert.kid}</code></Typography>
                    <Typography variant="body2" sx={{ mb: 0.5 }}><strong>Valid Until:</strong> {samlInfo.active_cert.expires_at}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', wordBreak: 'break-all' }}>
                      <strong>SHA-256:</strong> <span className="mono">{samlInfo.active_cert.fingerprint_sha256}</span>
                    </Typography>
                  </Box>
                  {activeCertExpiry && activeCertExpiry.expired && (
                    <Alert severity="error" sx={{ mb: 1.5 }}>
                      This certificate expired on {samlInfo.active_cert.expires_at} and still signs every SAML response; SPs that check certificate validity reject it. {rolloverAdvice}
                    </Alert>
                  )}
                  {activeCertExpiry && activeCertExpiry.soon && (
                    <Alert severity="warning" sx={{ mb: 1.5 }}>
                      Expires {inDaysText(activeCertExpiry.days)}. {stagedCert ? rolloverAdvice : 'Stage the next certificate now (Stage Next), let the SPs import the IdP metadata, then activate it.'}
                    </Alert>
                  )}
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Button size="small" variant="outlined" startIcon={<Icon name={okCopyCert ? 'check' : 'content_copy'} size={16} />} onClick={() => copyCert(samlInfo.active_cert.cert_pem)}>
                      {okCopyCert ? 'Copied PEM!' : 'Copy PEM'}
                    </Button>
                    <Button size="small" variant="outlined" startIcon={<Icon name="download" size={16} />} component="a" href={samlInfo.cert_download_url} target="_blank">
                      Download .pem
                    </Button>
                  </Box>
                </Box>
              )}
              {(samlInfo?.certs || []).length > 1 && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: 'uppercase', display: 'block', mb: 1 }}>
                    All Signing Certificates
                  </Typography>
                  {(samlInfo.certs || []).map(c => {
                    const now = Date.now();
                    // The server's expiry fields (G1a-04); computed here only when missing.
                    const expiry = samlCertExpiry(c);
                    const expired = expiry.expired;
                    const retiredAt = c.retired_at ? new Date(c.retired_at).getTime() : NaN;
                    const inGrace = c.state === 'retired' && Number.isFinite(retiredAt) && now - retiredAt < SAML_CERT_GRACE_MS;
                    const canActivate = !expired && (c.state === 'next' || inGrace);
                    // Only a certificate that signs or is published can still matter to the SPs.
                    const warnSoon = expiry.soon && (c.state === 'active' || c.state === 'next' || inGrace);
                    let stateLabel = 'Retired (not published)';
                    let stateColor = 'default';
                    if (c.state === 'active') {
                      stateLabel = expired ? 'Active (signing, expired)' : 'Active (signing)';
                      stateColor = expired ? 'error' : (expiry.soon ? 'warning' : 'success');
                    }
                    else if (expired) { stateLabel = 'Expired'; stateColor = 'error'; }
                    else if (c.state === 'next') { stateLabel = 'Staged (published, not signing)'; stateColor = 'info'; }
                    else if (inGrace) { stateLabel = 'Retired (still published)'; stateColor = 'warning'; }
                    return (
                      <Paper key={c.id || c.kid} variant="outlined" sx={{ p: 1.25, mb: 1, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                        <Box sx={{ minWidth: 0 }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                            <Chip size="small" color={stateColor} variant={c.state === 'active' ? 'filled' : 'outlined'} label={stateLabel} />
                            {warnSoon && <Chip size="small" color="warning" variant="outlined" label={`Expires ${inDaysText(expiry.days)}`} />}
                            <code style={{ fontSize: 12 }}>{c.kid}</code>
                          </Box>
                          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.4 }}>
                            Valid until {c.expires_at || '—'}
                            {c.retired_at ? ` • Retired ${relativeTime(c.retired_at)}` : ''}
                            {inGrace && !expired ? ` • Can be re-activated until ${new Date(retiredAt + SAML_CERT_GRACE_MS).toISOString().slice(0, 10)}` : ''}
                          </Typography>
                        </Box>
                        {c.state !== 'active' && (
                          <Box sx={{ display: 'flex', gap: 0.5, alignItems: 'center' }}>
                            {canActivate && (
                              <Button size="small" variant="outlined" onClick={() => activateSamlCert(c)}>Activate</Button>
                            )}
                            <Tooltip title="Delete this certificate">
                              <IconButton size="small" color="error" onClick={() => deleteSamlCert(c)}><Icon name="delete_outline" size={18} /></IconButton>
                            </Tooltip>
                          </Box>
                        )}
                      </Paper>
                    );
                  })}
                </Box>
              )}
            </Paper>
          </Grid>

          <Grid item xs={12} md={7}>
            <Paper variant="outlined" sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Icon name="key" size={20} />
                  OIDC / JWT Signing Keyring ({keys.length})
                </Typography>
                <Button size="small" color="error" variant="outlined" onClick={() => {
                  if (!confirm('Prune all expired non-active keys outside retention window?')) return;
                  api(`/api/providers/${provider.id}/keys/prune-expired`, { method: 'POST' })
                    .then(() => { loadAll(); refreshProviders(); onNotify('Pruned expired signing keys'); })
                    .catch(e => onNotify(errText(e, 'Pruning keys failed'), 'error'));
                }}>
                  Prune Expired
                </Button>
              </Box>

              {keys.map(k => (
                <Paper key={k.kid} variant="outlined" sx={{ p: 1.75, mb: 1.25, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 1.5, bgcolor: activeKid === k.kid ? 'action.selected' : 'transparent' }}>
                  <Box>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Chip size="small" label={k.alg} className="mono" sx={{ fontWeight: 700 }} />
                      <Typography variant="body2" className="mono" sx={{ fontSize: 12.5 }}>{k.kid}</Typography>
                      {activeKid === k.kid && <Chip size="small" color="success" label="Active Signer" />}
                    </Box>
                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.4 }}>
                      Expires: {k.expires_at || '—'} ({relativeTime(k.expires_at)})
                    </Typography>
                  </Box>
                  <Box sx={{ display: 'flex', gap: 0.75 }}>
                    {activeKid !== k.kid && (
                      <Button size="small" variant="outlined" onClick={() => setActiveKey(k.kid)}>Make Active</Button>
                    )}
                    <Button size="small" variant="text" onClick={() => {
                      api(`/api/providers/${provider.id}/keys/${encodeURIComponent(k.kid)}/public`)
                        .then(r => setPubKeyModal({ kid: k.kid, alg: k.alg, public_key: r.public_key }))
                        .catch(e => setKeyErr(errText(e, 'Failed to load public key')));
                    }}>Public PEM</Button>
                    <IconButton size="small" color="error" disabled={activeKid === k.kid || keys.length <= 1} onClick={() => {
                      if (!confirm('Delete this signing key?')) return;
                      api(`/api/providers/${provider.id}/keys/bulk-delete`, { method: 'POST', body: JSON.stringify({ kids: [k.kid] }) })
                        .then(() => { loadAll(); refreshProviders(); })
                        .catch(e => setKeyErr(errText(e, 'Delete failed')));
                    }}><Icon name="delete_outline" size={18} /></IconButton>
                  </Box>
                </Paper>
              ))}

              <Divider sx={{ my: 2 }} />
              <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: 'uppercase', display: 'block', mb: 1.25 }}>
                Add Rotation Key to JWKS
              </Typography>
              <Grid container spacing={1.5} alignItems="center">
                <Grid item xs={12} sm={3}>
                  <TextField select fullWidth size="small" label="Source" value={keyMode} onChange={e => setKeyMode(e.target.value)}>
                    <MenuItem value="generate">Generate</MenuItem>
                    <MenuItem value="paste">Paste PEM</MenuItem>
                  </TextField>
                </Grid>
                {keyMode === 'generate' && (
                  <Grid item xs={12} sm={3}>
                    <TextField select fullWidth size="small" label="Algorithm" value={alg} onChange={e => setAlg(e.target.value)}>
                      {['RS256','RS384','RS512','ES256','ES384','ES512','EdDSA'].map(a => <MenuItem key={a} value={a}>{a}</MenuItem>)}
                    </TextField>
                  </Grid>
                )}
                <Grid item xs={12} sm={3}>
                  <TextField
                    fullWidth size="small"
                    label="Key TTL"
                    value={keyTtl}
                    onChange={e => setKeyTtl(e.target.value)}
                    placeholder={savedSettings.ttl ? `Provider TTL (${savedSettings.ttl})` : 'Provider TTL'}
                    InputLabelProps={{ shrink: true }}
                    helperText="Empty: the provider key TTL. Or 90m, 12h, 7d, 1w, 2h30m"
                  />
                </Grid>
                <Grid item xs={12} sm={3}>
                  <Button variant="contained" fullWidth onClick={addOidcKey}>+ Add Key</Button>
                </Grid>
                {keyTtl.trim() !== '' && (
                  <Grid item xs={12}>
                    <FormControlLabel
                      control={<Checkbox size="small" checked={applyTtlToProvider} onChange={e => setApplyTtlToProvider(e.target.checked)} />}
                      label="Also make this the provider's key TTL (used for automatic rotation)"
                    />
                  </Grid>
                )}
                {keyMode === 'paste' && (
                  <Grid item xs={12}>
                    <TextField fullWidth multiline minRows={3} label="Private Key PEM" value={keyText} onChange={e => setKeyText(e.target.value)} InputProps={{ className: 'mono' }} />
                  </Grid>
                )}
              </Grid>
              {keyErr && <Alert sx={{ mt: 1.5 }} severity="error">{keyErr}</Alert>}
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* TAB 4: SSO AUDIT STREAM */}
      {tab === 4 && (
        <Paper variant="outlined" sx={{ p: 3 }} className="fade-in">
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1.5 }}>
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>Authentication &amp; Assertion Audit Log</Typography>
              <Typography variant="body2" color="text.secondary">Real-time trace of SAML assertions, OIDC token exchanges, and Touch ID verifications</Typography>
            </Box>
            <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center' }}>
              <TextField
                size="small"
                placeholder="Filter user, app, event…"
                value={logFilter}
                onChange={e => setLogFilter(e.target.value)}
                InputProps={{
                  startAdornment: <InputAdornment position="start"><Icon name="search" size={18} /></InputAdornment>
                }}
              />
              <Button size="small" variant="outlined" startIcon={<Icon name="refresh" size={17} />} onClick={loadAll}>Refresh</Button>
            </Box>
          </Box>

          {filteredLogs.length === 0 ? (
            <Box sx={{ py: 5, textAlign: 'center' }}>
              <Icon name="history" size={36} style={{ opacity: 0.35 }} />
              <Typography color="text.secondary" sx={{ mt: 1 }}>No matching SSO events recorded yet.</Typography>
            </Box>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 700 }}>Timestamp (UTC)</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Protocol</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Event</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Application</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>User</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>AMR Factors</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Result</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredLogs.map(l => (
                    <TableRow key={l.id} hover>
                      <TableCell className="mono" sx={{ whiteSpace: 'nowrap', fontSize: 12 }}>{l.created_at}</TableCell>
                      <TableCell><Chip size="small" variant="outlined" label={l.protocol.toUpperCase()} sx={{ fontWeight: 700, fontSize: 11 }} /></TableCell>
                      <TableCell className="mono" sx={{ fontSize: 12.5 }}>{l.event_type}</TableCell>
                      <TableCell sx={{ fontSize: 13, fontWeight: 500 }}>{l.app_name || '—'}</TableCell>
                      <TableCell sx={{ fontSize: 13 }}>{l.username || '—'}</TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                          {(l.amr || []).length === 0 ? '—' : (l.amr || []).map((m, idx) => (
                            <Chip
                              key={idx}
                              size="small"
                              icon={m === 'hwk' ? <Icon name="fingerprint" size={13} /> : undefined}
                              label={m}
                              color={m === 'hwk' ? 'secondary' : 'default'}
                              sx={{ height: 21, fontSize: 11 }}
                            />
                          ))}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip size="small" color={l.status === 'success' ? 'success' : 'error'} label={l.status} sx={{ fontWeight: 700, fontSize: 11 }} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Box>
          )}
        </Paper>
      )}

      {/* Sub-Dialogs */}
      <SamlAppDialog open={openSamlDialog} onClose={() => setOpenSamlDialog(false)} provider={provider} editingApp={editSamlApp} onSaved={() => { loadAll(); refreshProviders(); onNotify('Saved SAML 2.0 application'); }} />
      <OidcClientDialog open={openOidcDialog} onClose={() => setOpenOidcDialog(false)} provider={provider} editingClient={editOidc} onSaved={(savedClient) => {
        loadAll(); refreshProviders();
        if (savedClient?.client_secret) setMintedSecretClient(savedClient);
        else onNotify('Saved OIDC client');
      }} />
      <ScimTokenDialog open={openScimTokenDialog} onClose={() => setOpenScimTokenDialog(false)} provider={provider} onCreated={(tok) => {
        loadAll(); refreshProviders();
        setMintedScimToken(tok);
      }} />
      <ScimConnectorDialog open={openScimConnDialog} onClose={() => setOpenScimConnDialog(false)} provider={provider} editingConnector={editScimConn} onSaved={(savedConn) => {
        loadAll(); refreshProviders();
        if (savedConn?.agent_token) setMintedAgentConn(savedConn);
        else onNotify('Saved SCIM 2.0 push connector');
      }} />

      <Dialog open={!!mintedAgentConn} onClose={() => setMintedAgentConn(null)} fullWidth maxWidth="md">
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Icon name="dns" size={22} />
          <span>On-Premises Windows SCIM Proxy Agent Configuration</span>
        </DialogTitle>
        <DialogContent dividers>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Copy this <code>agent_token</code> or download <code>config.json</code> now: save it as <code>C:\ProgramData\IdentityCloudScimAgent\config.json</code> (or next to <code>scim-agent.exe</code>) and install the service from an elevated prompt with <code>{'scim-agent.exe -install -config <path>'}</code>. Create that folder from an elevated prompt and restrict it to SYSTEM and Administrators first (agent README, "Where to put the files"): <code>-install</code> refuses program, config or log folders that other users can change. <code>-install</code> runs the service as <code>NT SERVICE\IdentityCloudScimAgent</code> and restricts <code>config.json</code> to Administrators and the service account. Only the token hash is stored in SQLite.
          </Alert>
          <TextField fullWidth size="small" label="Agent Registration Token" value={mintedAgentConn?.agent_token || ''} InputProps={{ readOnly: true, className: 'mono' }} sx={{ mb: 2 }} />
          {(() => {
            const sampleCfg = JSON.stringify({
              cloud_idp_url: provider.issuer,
              agent_token: mintedAgentConn?.agent_token || '',
              local_scim_base_url: (mintedAgentConn?.scim_base_url && mintedAgentConn.scim_base_url !== 'agent://on-premises')
                ? mintedAgentConn.scim_base_url
                : 'http://127.0.0.1:8080/scim/v2',
              local_scim_bearer_token: 'REPLACE_WITH_YOUR_ONPREM_APP_SCIM_TOKEN',
              local_insecure_skip_tls_verify: false,
              poll_wait_seconds: 12,
              // Resolved against the folder of config.json; the service may write only there (agent 1.1.0).
              log_file: 'logs/scim-agent.log',
            }, null, 2);
            return (
              <>
                <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, display: 'block', mb: 0.75 }}>
                  config.json (recommended location: C:\ProgramData\IdentityCloudScimAgent\config.json):
                </Typography>
                <Paper variant="outlined" sx={{ p: 2, overflowX: 'auto', bgcolor: '#0f172a', color: '#e2e8f0' }}>
                  <pre style={{ margin: 0, fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}><code>{sampleCfg}</code></pre>
                </Paper>
                <Box sx={{ display: 'flex', gap: 1, mt: 2, flexWrap: 'wrap' }}>
                  <Button variant="outlined" startIcon={<Icon name={okCopyAgentTok ? 'check' : 'content_copy'} size={17} />} onClick={() => copyAgentTok(mintedAgentConn?.agent_token || '')}>
                    {okCopyAgentTok ? 'Copied Agent Token!' : 'Copy Agent Token'}
                  </Button>
                  <Button variant="outlined" startIcon={<Icon name={okCopyAgentCfg ? 'check' : 'content_copy'} size={17} />} onClick={() => copyAgentCfg(sampleCfg)}>
                    {okCopyAgentCfg ? 'Copied config.json!' : 'Copy config.json'}
                  </Button>
                  <Button
                    variant="contained"
                    startIcon={<Icon name="download" size={17} />}
                    onClick={() => {
                      const blob = new Blob([sampleCfg + '\n'], { type: 'application/json' });
                      const u = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = u;
                      a.download = 'config.json';
                      a.click();
                      URL.revokeObjectURL(u);
                    }}
                  >
                    Download config.json
                  </Button>
                </Box>
              </>
            );
          })()}
        </DialogContent>
        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button variant="contained" onClick={() => setMintedAgentConn(null)}>Done</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!mintedScimToken} onClose={() => setMintedScimToken(null)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Icon name="vpn_key" size={22} />
          <span>Copy SCIM 2.0 Bearer Token</span>
        </DialogTitle>
        <DialogContent dividers>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Copy this SCIM Bearer token now. Only its cryptographic hash is stored in SQLite—it cannot be viewed in plaintext again.
          </Alert>
          <Typography variant="body2" sx={{ mb: 1 }}>
            <strong>SCIM Base URL:</strong> <code className="mono">{provider.issuer}/scim/v2</code>
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            <strong>Permission:</strong> {mintedScimToken?.permission === 'write' ? 'Read & Write' : 'Read-Only (Pull)'}
          </Typography>
          <TextField fullWidth label="Authorization Bearer Token" value={mintedScimToken?.bearer_token || ''} InputProps={{ readOnly: true, className: 'mono' }} />
        </DialogContent>
        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button startIcon={<Icon name={okCopyScimToken ? 'check' : 'content_copy'} size={17} />} onClick={() => copyScimToken(mintedScimToken?.bearer_token || '')}>
            {okCopyScimToken ? 'Copied Token!' : 'Copy Token'}
          </Button>
          <Button variant="contained" onClick={() => setMintedScimToken(null)}>Done</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!pubKeyModal} onClose={() => setPubKeyModal(null)} fullWidth maxWidth="sm">
        <DialogTitle>Public Key PEM — {pubKeyModal?.alg}</DialogTitle>
        <DialogContent dividers>
          <Typography variant="caption" className="mono" sx={{ display: 'block', mb: 1 }}>kid: {pubKeyModal?.kid}</Typography>
          <Paper variant="outlined" sx={{ p: 2, overflowX: 'auto', bgcolor: '#0f172a', color: '#e2e8f0' }}>
            <pre style={{ margin: 0, fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}><code>{pubKeyModal?.public_key}</code></pre>
          </Paper>
        </DialogContent>
        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button onClick={() => copyPub(pubKeyModal?.public_key || '')}>{okCopyPub ? 'Copied!' : 'Copy PEM'}</Button>
          <Button variant="contained" onClick={() => setPubKeyModal(null)}>Close</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!mintedSecretClient} onClose={() => setMintedSecretClient(null)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Icon name="key" size={22} />
          <span>Copy OIDC Client Secret</span>
        </DialogTitle>
        <DialogContent dividers>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Save this <code>client_secret</code> now. Only its cryptographic hash is stored in SQLite—it cannot be viewed in plaintext again.
          </Alert>
          <Typography variant="body2" sx={{ mb: 1.5 }}><strong>client_id:</strong> <code className="mono">{mintedSecretClient?.client_id}</code></Typography>
          <TextField fullWidth label="client_secret" value={mintedSecretClient?.client_secret || ''} InputProps={{ readOnly: true, className: 'mono' }} />
        </DialogContent>
        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button startIcon={<Icon name={okCopySecret ? 'check' : 'content_copy'} size={17} />} onClick={() => copySecret(mintedSecretClient?.client_secret || '')}>
            {okCopySecret ? 'Copied Secret!' : 'Copy Secret'}
          </Button>
          <Button variant="contained" onClick={() => setMintedSecretClient(null)}>Done</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

/* ==================== SHARED DIRECTORY USER DIALOG ==================== */
// Text shown in a schema attribute field for a stored value, or null when the value cannot be
// edited as text (objects, nested lists, null): those stay in the JSON box (S13-10).
function attrToText(v) {
  const scalar = (x) => typeof x === 'string' || typeof x === 'number' || typeof x === 'boolean';
  if (scalar(v)) return String(v);
  if (Array.isArray(v) && v.every(scalar)) return v.join(', ');
  return null;
}

// Edited field text back to a value of the type it replaces: numbers and booleans stay numbers
// and booleans, and only a value that was a list is split on commas, so "Director, Sales"
// stays one string (S13-10, S12-16).
function textToAttr(text, original) {
  const coerce = (s, like) => {
    if (typeof like === 'number' && s !== '' && Number.isFinite(Number(s))) return Number(s);
    if (typeof like === 'boolean' && (s === 'true' || s === 'false')) return s === 'true';
    return s;
  };
  if (Array.isArray(original)) {
    return text.split(',').map(x => x.trim()).filter(Boolean).map(x => coerce(x, original[0]));
  }
  return coerce(text.trim(), original);
}

// The display name a user gets when none is set: "First Last", else the username.
function derivedDisplayName(u) {
  return `${u.given_name || ''} ${u.family_name || ''}`.trim() || u.username || '';
}

// The Display Name field of a stored user: empty while the display name follows the names.
function displayNameField(u) {
  const current = u.display_name || '';
  return current === derivedDisplayName(u) ? '' : current;
}

function DirectoryUserDialog({ open, onClose, editingUser, customSchema, onSaved }) {
  const empty = {
    username: '',
    email: '',
    password: '',
    given_name: '',
    family_name: '',
    display_name: '',
    mobile_phone: '',
    groups_text: '',
    status: 'active',
    email_verified: false,
    schemaAttrs: {},
    extraJson: '',
  };
  const [form, setForm] = useState(empty);
  // Until the admin edits the username, a new user's username follows the email (S13-09).
  const [usernameTouched, setUsernameTouched] = useState(false);
  const [err, setErr] = useState('');

  const parseGroups = (text) => text.split(',').map(s => s.trim()).filter(Boolean);
  // The stored attribute map; PHP sends an empty map as [], which counts as {}.
  const storedAttrs = (editingUser && editingUser.attributes && typeof editingUser.attributes === 'object' && !Array.isArray(editingUser.attributes))
    ? editingUser.attributes
    : {};

  useEffect(() => {
    if (!open) return;
    setErr('');
    setUsernameTouched(false);
    if (editingUser) {
      const attrs = { ...storedAttrs };
      const schemaVals = {};
      (customSchema || []).forEach(s => {
        if (attrs[s.key] === undefined) return;
        const text = attrToText(attrs[s.key]);
        if (text === null) return; // structured value: stays in the JSON box
        schemaVals[s.key] = text;
        delete attrs[s.key];
      });
      setForm({
        username: editingUser.username || '',
        email: editingUser.email || '',
        password: '',
        given_name: editingUser.given_name || '',
        family_name: editingUser.family_name || '',
        display_name: displayNameField(editingUser),
        mobile_phone: editingUser.mobile_phone || '',
        groups_text: (editingUser.groups || []).join(', '),
        status: editingUser.status || 'active',
        email_verified: !!editingUser.email_verified,
        schemaAttrs: schemaVals,
        extraJson: Object.keys(attrs).length ? JSON.stringify(attrs, null, 2) : '',
      });
    } else {
      setForm(empty);
    }
  }, [open, editingUser, customSchema]);

  const onEmailChange = (email) => {
    setForm(prev => {
      const next = { ...prev, email };
      if (!editingUser && !usernameTouched) next.username = email;
      if (editingUser) {
        // A new address is not verified; going back to the stored one restores its flag.
        const same = email.trim().toLowerCase() === String(editingUser.email || '').trim().toLowerCase();
        next.email_verified = same ? !!editingUser.email_verified : false;
      }
      return next;
    });
  };

  const save = () => {
    setErr('');
    let extra = {};
    if (form.extraJson.trim()) {
      try {
        extra = JSON.parse(form.extraJson);
      } catch {
        setErr('Additional Custom Claims must be valid JSON');
        return;
      }
      if (!extra || typeof extra !== 'object' || Array.isArray(extra)) {
        setErr('Additional Custom Claims must be a JSON object');
        return;
      }
    }
    // Schema fields keep the stored value (and its type) unless the admin changed the text; a
    // key set in the JSON box wins over an untouched or cleared field.
    const mergedAttrs = { ...extra };
    Object.entries(form.schemaAttrs || {}).forEach(([k, value]) => {
      const text = String(value ?? '');
      const original = storedAttrs[k];
      const originalText = original === undefined ? null : attrToText(original);
      if (originalText !== null && text === originalText) {
        if (!(k in extra)) mergedAttrs[k] = original;
        return;
      }
      if (text.trim() === '') {
        if (!(k in extra)) delete mergedAttrs[k];
        return;
      }
      mergedAttrs[k] = textToAttr(text, original);
    });

    const groups = parseGroups(form.groups_text);
    const displayName = form.display_name.trim();
    let payload;
    if (!editingUser) {
      payload = {
        // An empty username is derived from the email by the server.
        username: form.username.trim(),
        email: form.email.trim(),
        given_name: form.given_name,
        family_name: form.family_name,
        mobile_phone: form.mobile_phone,
        groups,
        status: form.status,
        attributes: mergedAttrs,
        email_verified: !!form.email_verified,
      };
      if (displayName) payload.display_name = displayName;
    } else {
      // Only what the admin changed is sent: the API writes just the fields present, so values
      // SCIM or another admin changed meanwhile are not overwritten with this copy (S12-14).
      payload = {};
      const sendIfChanged = (key, value, stored) => {
        if (String(value ?? '').trim() !== String(stored ?? '').trim()) payload[key] = value;
      };
      sendIfChanged('username', form.username, editingUser.username);
      sendIfChanged('email', form.email, editingUser.email);
      sendIfChanged('given_name', form.given_name, editingUser.given_name);
      sendIfChanged('family_name', form.family_name, editingUser.family_name);
      sendIfChanged('mobile_phone', form.mobile_phone, editingUser.mobile_phone);
      sendIfChanged('status', form.status, editingUser.status || 'active');
      // Display name (S13-10): an empty field means "First Last" (else the username), which
      // the server computes; it follows renames unless a custom display name is set.
      const initialDisplay = displayNameField(editingUser);
      const namesChanged = ['username', 'given_name', 'family_name'].some(k => k in payload);
      if (displayName !== initialDisplay) {
        payload.display_name = displayName;
      } else if (initialDisplay === '' && namesChanged) {
        payload.display_name = '';
      }
      if ('email' in payload || !!form.email_verified !== !!editingUser.email_verified) {
        payload.email_verified = !!form.email_verified;
      }
      // Groups and attributes go with the copy they were edited from, so the server applies only
      // what the admin added, removed or changed to the values it holds now: a group or role that
      // SCIM or another admin removed meanwhile is not added back (S12-14).
      if (stableStringify([...groups].sort()) !== stableStringify([...(editingUser.groups || [])].sort())) {
        payload.groups = groups;
        payload.groups_base = editingUser.groups || [];
      }
      if (stableStringify(mergedAttrs) !== stableStringify(storedAttrs)) {
        payload.attributes = mergedAttrs;
        payload.attributes_base = storedAttrs;
      }
    }
    if (form.password) payload.password = form.password;

    const path = editingUser ? `/api/users/${editingUser.id}` : '/api/users';
    api(path, { method: editingUser ? 'PUT' : 'POST', body: JSON.stringify(payload) })
      .then(() => { onSaved(); onClose(); })
      .catch(e => setErr(errText(e, 'Failed to save user')));
  };

  const displayPlaceholder = derivedDisplayName({
    given_name: form.given_name.trim(),
    family_name: form.family_name.trim(),
    username: form.username.trim() || form.email.trim(),
  });

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.25 }}>
        <Icon name="person_add" size={22} />
        <span>{editingUser ? `Edit Directory User — ${editingUser.username}` : 'Create Shared Directory User'}</span>
      </DialogTitle>
      <DialogContent dividers>
        {err && <Alert sx={{ mb: 2 }} severity="error">{err}</Alert>}
        <Grid container spacing={2}>
          <Grid item xs={12} md={5}>
            <TextField fullWidth label="Email Address" placeholder="alice@company.example" value={form.email} onChange={e => onEmailChange(e.target.value)} />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth label="Username"
              placeholder={editingUser ? 'alice' : 'Defaults to the email address'}
              value={form.username}
              onChange={e => { setUsernameTouched(true); setForm({ ...form, username: e.target.value }); }}
            />
          </Grid>
          <Grid item xs={12} md={3}>
            <TextField select fullWidth label="Account Status" value={form.status} onChange={e => setForm({ ...form, status: e.target.value })}>
              <MenuItem value="active">Active</MenuItem>
              <MenuItem value="suspended">Suspended</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12} sx={{ pt: '8px !important' }}>
            <FormControlLabel
              control={<Checkbox size="small" checked={!!form.email_verified} onChange={e => setForm({ ...form, email_verified: e.target.checked })} />}
              label="Email address verified (tokens carry email_verified=true)"
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField fullWidth label="First Name (given_name)" value={form.given_name} onChange={e => setForm({ ...form, given_name: e.target.value })} />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField fullWidth label="Last Name (family_name)" value={form.family_name} onChange={e => setForm({ ...form, family_name: e.target.value })} />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth label="Display Name"
              placeholder={displayPlaceholder}
              value={form.display_name}
              onChange={e => setForm({ ...form, display_name: e.target.value })}
              helperText="Blank = First + Last name"
            />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField fullWidth label="Mobile Phone" placeholder="+1 555 0100" value={form.mobile_phone} onChange={e => setForm({ ...form, mobile_phone: e.target.value })} />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField fullWidth type="password" label={editingUser ? 'Reset Password (blank = unchanged)' : 'Password (optional for Touch ID-only users)'} value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField fullWidth label="Groups (comma-separated)" value={form.groups_text} onChange={e => setForm({ ...form, groups_text: e.target.value })} placeholder="admins, netops, secops" />
          </Grid>

          {(customSchema || []).length > 0 && (
            <Grid item xs={12}>
              <Divider sx={{ my: 1 }} />
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                Auto-Discovered SAML Application Role Attributes
              </Typography>
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1.5 }}>
                Detected automatically from `attr:*` mappings across your SAML 2.0 Service Providers.
              </Typography>
              <Grid container spacing={2}>
                {customSchema.map(field => {
                  const original = storedAttrs[field.key];
                  const structured = original !== undefined && attrToText(original) === null;
                  const kind = structured
                    ? 'Structured value: edit it in the JSON box below'
                    : (Array.isArray(original) ? 'Comma-separated list' : 'Single value (for a list, use the JSON box below)');
                  return (
                    <Grid item xs={12} md={6} key={field.key}>
                      <TextField
                        fullWidth size="small"
                        label={`${field.friendly_name} (${field.key})`}
                        value={structured ? '' : (form.schemaAttrs[field.key] ?? '')}
                        disabled={structured}
                        onChange={e => setForm({ ...form, schemaAttrs: { ...form.schemaAttrs, [field.key]: e.target.value } })}
                        helperText={`${kind} • Used by: ${(field.apps || []).join(', ')}`}
                      />
                    </Grid>
                  );
                })}
              </Grid>
            </Grid>
          )}

          <Grid item xs={12}>
            <TextField fullWidth multiline minRows={2} label="Additional Custom OIDC/SAML Attributes (JSON)" value={form.extraJson} onChange={e => setForm({ ...form, extraJson: e.target.value })} placeholder='{"department": "Platform Security"}' InputProps={{ className: 'mono', sx: { fontSize: 13 } }} />
          </Grid>
        </Grid>
      </DialogContent>
      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={save} disabled={!form.email.trim() && !form.username.trim()}>
          {editingUser ? 'Save User' : 'Create User'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/* ==================== DIRECTORY & TOUCH ID VIEW ==================== */
function DirectoryPanel({ onNotify }) {
  const [users, setUsers] = useState([]);
  const [schema, setSchema] = useState([]);
  const [search, setSearch] = useState('');
  const [openDialog, setOpenDialog] = useState(false);
  const [editUser, setEditUser] = useState(null);
  const [enrollUrlDialog, setEnrollUrlDialog] = useState(null);
  const [err, setErr] = useState('');
  const [okCopyEnroll, copyEnroll] = useCopyFeedback();

  const load = () => {
    api('/api/users').then(r => {
      setUsers(r.users || []);
      setSchema(r.custom_attribute_schema || []);
    }).catch(e => setErr(errText(e, 'Failed to load directory users')));
  };

  useEffect(() => { load(); }, []);

  const enrollTouchIdOnThisMac = async (user) => {
    setErr('');
    if (!window.PublicKeyCredential) {
      setErr('WebAuthn Touch ID requires https:// or http://localhost in a modern macOS browser.');
      return;
    }
    try {
      const r1 = await api(`/api/users/${user.id}/webauthn/register-options`, { method: 'POST' });
      const pk = r1.publicKey;
      pk.challenge = b64uToBytes(pk.challenge);
      pk.user.id = b64uToBytes(pk.user.id);
      if (Array.isArray(pk.excludeCredentials)) {
        pk.excludeCredentials = pk.excludeCredentials.map(c => ({ ...c, id: b64uToBytes(c.id) }));
      }
      const cred = await navigator.credentials.create({ publicKey: pk });
      await api(`/api/users/${user.id}/webauthn/register-verify`, {
        method: 'POST',
        body: JSON.stringify({
          friendlyName: 'MacBook Touch ID',
          credential: {
            id: cred.id,
            rawId: bytesToB64u(cred.rawId),
            type: cred.type,
            response: {
              clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
              attestationObject: bytesToB64u(cred.response.attestationObject),
              transports: cred.response.getTransports ? cred.response.getTransports() : ['internal']
            }
          }
        })
      });
      onNotify(`macOS Touch ID enrolled for ${user.username}!`);
      load();
    } catch (e) {
      if (e?.name !== 'NotAllowedError') {
        setErr(e.error || e.message || String(e));
      }
    }
  };

  const generateEnrollLink = (user) => {
    api(`/api/users/${user.id}/enrollment-link`, { method: 'POST' })
      .then(r => setEnrollUrlDialog({ user, url: r.enrollment_url }))
      .catch(e => setErr(errText(e, 'Failed')));
  };

  // Ends the user's sessions without suspending or deleting the account (G2a-06).
  const signOutEverywhere = (user) => {
    if (!confirm(`Sign "${user.username}" out everywhere? This ends all of the user's single sign-on sessions and revokes the OIDC access and refresh tokens and unused authorization codes issued to them, at every provider. The account stays active; the user must sign in again.`)) return;
    api(`/api/users/${encodeURIComponent(user.id)}/sessions/revoke`, { method: 'POST', body: '{}' })
      .then(() => onNotify(`Signed ${user.username} out everywhere`))
      .catch(e => onNotify('Sessions NOT ended: ' + errText(e, 'request failed'), 'error'));
  };

  const totalPasskeys = users.reduce((acc, u) => acc + (u.touchid_count || 0), 0);
  const filteredUsers = users.filter(u => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (u.display_name || '').toLowerCase().includes(q) ||
      (u.email || '').toLowerCase().includes(q) ||
      (u.username || '').toLowerCase().includes(q) ||
      (u.groups || []).some(g => g.toLowerCase().includes(q));
  });

  return (
    <Box className="fade-in">
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2, mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800 }}>Shared User Directory &amp; Touch ID</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Test identities shared across all your SAML 2.0 &amp; OIDC Providers with native Apple macOS Touch ID (WebAuthn Platform Passkeys).
          </Typography>
        </Box>
        <Button variant="contained" startIcon={<Icon name="person_add" size={18} />} onClick={() => { setEditUser(null); setOpenDialog(true); }}>
          Add Directory User
        </Button>
      </Box>

      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={4}>
          <StatCard label="Directory Users" value={users.length} subtitle="Shared across your tenants" icon="group" gradient="linear-gradient(135deg, #4f46e5, #6366f1)" />
        </Grid>
        <Grid item xs={12} sm={4}>
          <StatCard label="Touch ID Passkeys" value={totalPasskeys} subtitle="Platform UV=1 credentials" icon="fingerprint" gradient="linear-gradient(135deg, #e11d48, #ec4899)" />
        </Grid>
        <Grid item xs={12} sm={4}>
          <StatCard label="Role Schema Fields" value={schema.length} subtitle="Auto-detected from SAML apps" icon="schema" gradient="linear-gradient(135deg, #059669, #10b981)" />
        </Grid>
      </Grid>

      {!window.isSecureContext && (
        <Alert sx={{ mb: 2.5 }} severity="warning">
          <strong>Secure Context Required for Touch ID:</strong> Viewing over <code>{window.location.origin}</code>. Open via <code>https://</code> or <code>http://localhost</code> to enroll macOS Touch ID.
        </Alert>
      )}
      {err && <Alert sx={{ mb: 2.5 }} severity="error">{err}</Alert>}

      <Paper variant="outlined" sx={{ p: 2.5 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, gap: 2, flexWrap: 'wrap' }}>
          <TextField
            size="small"
            placeholder="Search users by name, email, username, or group…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            sx={{ minWidth: 300, flex: 1, maxWidth: 440 }}
            InputProps={{
              startAdornment: <InputAdornment position="start"><Icon name="search" size={18} /></InputAdornment>
            }}
          />
          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
            Showing {filteredUsers.length} of {users.length} users
          </Typography>
        </Box>

        {filteredUsers.length === 0 ? (
          <Box sx={{ py: 6, textAlign: 'center' }}>
            <Icon name="fingerprint" size={42} style={{ opacity: 0.35 }} />
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mt: 1 }}>
              {users.length === 0 ? 'No test users in your directory yet' : 'No users match your search'}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 420, mx: 'auto', mt: 0.5, mb: 2.5 }}>
              Create a test user and bind your MacBook's Touch ID sensor in one click to test passwordless SAML 2.0 and OIDC flows.
            </Typography>
            {users.length === 0 && (
              <Button variant="contained" startIcon={<Icon name="person_add" size={18} />} onClick={() => { setEditUser(null); setOpenDialog(true); }}>
                Create First Test User
              </Button>
            )}
          </Box>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            {filteredUsers.map(u => (
              <Paper key={u.id} variant="outlined" sx={{ p: 2.25, transition: 'border-color 0.15s', '&:hover': { borderColor: 'primary.main' } }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2 }}>
                  <Box sx={{ display: 'flex', gap: 2, flex: 1, minWidth: 280 }}>
                    <Avatar sx={{ width: 44, height: 44, background: avatarGradient(u.email || u.username), fontWeight: 800, fontSize: 15 }}>
                      {initialsOf(u.display_name || u.username)}
                    </Avatar>
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', mb: 0.4 }}>
                        <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{u.display_name}</Typography>
                        <Typography variant="body2" color="text.secondary">{u.email}</Typography>
                        {u.status !== 'active' && <Chip size="small" color="error" label="Suspended" />}
                        <Chip
                          size="small"
                          icon={<Icon name="fingerprint" size={15} />}
                          color={u.touchid_count > 0 ? 'success' : 'default'}
                          variant={u.touchid_count > 0 ? 'filled' : 'outlined'}
                          label={u.touchid_count > 0 ? `${u.touchid_count} Touch ID` : 'No Touch ID'}
                        />
                        {u.has_password && <Chip size="small" variant="outlined" icon={<Icon name="password" size={14} />} label="Password" />}
                      </Box>

                      <Typography variant="body2" color="text.secondary" sx={{ fontSize: 13 }}>
                        <strong>Username:</strong> <code className="mono">{u.username}</code>
                        {(u.groups || []).length > 0 && <> • <strong>Groups:</strong> {(u.groups || []).join(', ')}</>}
                      </Typography>

                      {Object.keys(u.attributes || {}).length > 0 && (
                        <Box sx={{ mt: 1, display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
                          {Object.entries(u.attributes || {}).map(([k, v]) => (
                            <Chip
                              key={k}
                              size="small"
                              variant="outlined"
                              className="mono"
                              sx={{ fontSize: 11.5 }}
                              label={`${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`}
                            />
                          ))}
                        </Box>
                      )}

                      {(u.credentials || []).length > 0 && (
                        <Box sx={{ mt: 1, display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
                          {u.credentials.map(c => (
                            <Chip
                              key={c.id}
                              size="small"
                              icon={<Icon name="laptop_mac" size={14} />}
                              label={`${c.friendly_name} (${c.rp_id})`}
                              onDelete={() => {
                                if (!confirm('Remove this Touch ID credential?')) return;
                                api(`/api/webauthn/credentials/${encodeURIComponent(c.id)}`, { method: 'DELETE' })
                                  .then(() => { load(); onNotify('Removed Touch ID credential'); })
                                  .catch(e => onNotify('Credential NOT removed: ' + errText(e, 'request failed'), 'error'));
                              }}
                            />
                          ))}
                        </Box>
                      )}
                    </Box>
                  </Box>

                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                    <Button
                      size="small"
                      variant="contained"
                      color="secondary"
                      startIcon={<Icon name="fingerprint" size={17} />}
                      onClick={() => enrollTouchIdOnThisMac(u)}
                    >
                      Enroll Touch ID
                    </Button>
                    <Button size="small" variant="outlined" startIcon={<Icon name="link" size={17} />} onClick={() => generateEnrollLink(u)}>
                      Invite Link
                    </Button>
                    <Button size="small" variant="outlined" color="warning" startIcon={<Icon name="logout" size={17} />} onClick={() => signOutEverywhere(u)}>
                      Sign Out Everywhere
                    </Button>
                    <IconButton size="small" onClick={() => { setEditUser(u); setOpenDialog(true); }}><Icon name="edit" size={18} /></IconButton>
                    <IconButton size="small" color="error" onClick={() => {
                      if (!confirm(`Delete user "${u.username}"?`)) return;
                      api(`/api/users/${u.id}`, { method: 'DELETE' })
                        .then(() => { load(); onNotify('Deleted directory user'); })
                        .catch(e => onNotify(errText(e, 'Delete failed'), 'error'));
                    }}><Icon name="delete_outline" size={19} /></IconButton>
                  </Box>
                </Box>
              </Paper>
            ))}
          </Box>
        )}
      </Paper>

      <DirectoryUserDialog open={openDialog} onClose={() => setOpenDialog(false)} editingUser={editUser} customSchema={schema} onSaved={() => { load(); onNotify('Saved directory user'); }} />

      <Dialog open={!!enrollUrlDialog} onClose={() => setEnrollUrlDialog(null)} fullWidth maxWidth="sm">
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Icon name="link" size={22} />
          <span>Self-Service Touch ID Enrollment Link</span>
        </DialogTitle>
        <DialogContent dividers>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Open this single-use link on any macOS device (valid for 24 hours) to enroll Touch ID for <strong>{enrollUrlDialog?.user?.email}</strong>:
          </Typography>
          <TextField fullWidth value={enrollUrlDialog?.url || ''} InputProps={{ readOnly: true, className: 'mono', sx: { fontSize: 13 } }} />
        </DialogContent>
        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button startIcon={<Icon name={okCopyEnroll ? 'check' : 'content_copy'} size={17} />} onClick={() => copyEnroll(enrollUrlDialog?.url || '')}>
            {okCopyEnroll ? 'Copied Link!' : 'Copy Link'}
          </Button>
          <Button variant="contained" onClick={() => setEnrollUrlDialog(null)}>Done</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

/* ==================== ADMIN API CLIENT CREATE / EDIT DIALOG ==================== */
function AdminApiClientDialog({ open, onClose, providers, editingClient, onSaved }) {
  const empty = {
    name: '',
    description: '',
    provider_scope: 'selected',
    allowed_provider_ids: [],
    can_create_providers: false,
    // Off by default (G1a-02): minting JWTs (/api/token), importing private keys and managing
    // client_credentials clients need it.
    can_mint_tokens: false,
    // Off by default: reading the owner's administrator audit log (GET /api/admin-audit-logs).
    can_read_admin_audit: false,
    // One address or CIDR block per line (or comma separated); empty allows any address.
    allowed_ips_text: '',
    provider_permission: 'write',
    user_scope: 'none',
    status: 'active',
    expires_in: '',
  };
  const [form, setForm] = useState(empty);
  const [err, setErr] = useState('');

  useEffect(() => {
    if (!open) return;
    setErr('');
    if (editingClient) {
      setForm({
        name: editingClient.name || '',
        description: editingClient.description || '',
        provider_scope: editingClient.provider_scope || 'selected',
        allowed_provider_ids: [...(editingClient.allowed_provider_ids || [])],
        can_create_providers: !!editingClient.can_create_providers,
        can_mint_tokens: editingClient.can_mint_tokens === true,
        can_read_admin_audit: editingClient.can_read_admin_audit === true,
        allowed_ips_text: (editingClient.allowed_ips || []).join('\n'),
        provider_permission: editingClient.provider_permission || 'write',
        user_scope: editingClient.user_scope || 'none',
        status: editingClient.status || 'active',
        expires_in: '',
      });
    } else {
      setForm({
        ...empty,
        allowed_provider_ids: providers.length === 1 ? [providers[0].id] : [],
        provider_scope: providers.length === 0 ? 'all' : 'selected',
      });
    }
  }, [open, editingClient, providers]);

  const toggleProv = (pid) => {
    setForm(prev => {
      const has = prev.allowed_provider_ids.includes(pid);
      const next = has
        ? prev.allowed_provider_ids.filter(x => x !== pid)
        : [...prev.allowed_provider_ids, pid];
      return { ...prev, allowed_provider_ids: next };
    });
  };

  const save = () => {
    setErr('');
    const payload = {
      name: form.name,
      description: form.description,
      provider_scope: form.provider_scope,
      allowed_provider_ids: form.provider_scope === 'all' ? [] : form.allowed_provider_ids,
      can_create_providers: form.provider_scope === 'all' ? true : !!form.can_create_providers,
      can_mint_tokens: form.can_mint_tokens === true,
      can_read_admin_audit: form.can_read_admin_audit === true,
      allowed_ips: form.allowed_ips_text.split(/[\s,]+/).map(s => s.trim()).filter(Boolean),
      provider_permission: form.provider_permission,
      user_scope: form.user_scope,
      status: form.status,
    };
    if (form.expires_in !== '') {
      payload.expires_in = form.expires_in;
    }
    const path = editingClient ? `/api/admin-clients/${editingClient.id}` : '/api/admin-clients';
    api(path, { method: editingClient ? 'PATCH' : 'POST', body: JSON.stringify(payload) })
      .then(res => { onSaved(res.client); onClose(); })
      .catch(e => setErr(errText(e, 'Failed to save API client')));
  };

  const invalidScope =
    form.provider_scope === 'selected' &&
    form.allowed_provider_ids.length === 0 &&
    !form.can_create_providers;

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.25 }}>
        <Icon name="api" size={22} />
        <span>{editingClient ? `Edit Admin API Client — ${editingClient.name}` : 'Create Programmatic Admin API Client'}</span>
      </DialogTitle>
      <DialogContent dividers>
        {err && <Alert sx={{ mb: 2 }} severity="error">{err}</Alert>}
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <TextField fullWidth label="API Client Name" placeholder="e.g. Terraform Staging Provisioner" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} autoFocus />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField fullWidth label="Description (optional)" placeholder="CI/CD or external configuration sync" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
          </Grid>

          <Grid item xs={12} md={4}>
            <TextField select fullWidth label="Provider Access Scope" value={form.provider_scope} onChange={e => setForm({ ...form, provider_scope: e.target.value })}>
              <MenuItem value="selected">Selected Providers (1 or more)</MenuItem>
              <MenuItem value="all">All Providers (Full Tenant)</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField select fullWidth label="Provider Permission" value={form.provider_permission} onChange={e => setForm({ ...form, provider_permission: e.target.value })}>
              <MenuItem value="write">Read &amp; Write (Create / Modify)</MenuItem>
              <MenuItem value="read">Read-Only (Inspect Config &amp; Logs)</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField select fullWidth label="Shared User Directory" value={form.user_scope} onChange={e => setForm({ ...form, user_scope: e.target.value })}>
              <MenuItem value="none">No Directory Access</MenuItem>
              <MenuItem value="read">Read-Only Users</MenuItem>
              <MenuItem value="write">Read &amp; Write Users</MenuItem>
            </TextField>
          </Grid>

          {form.provider_scope === 'selected' && (
            <Grid item xs={12}>
              <Paper variant="outlined" sx={{ p: 2, bgcolor: 'action.hover' }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1, flexWrap: 'wrap', gap: 1 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                    Allowed Identity Providers ({form.allowed_provider_ids.length} selected)
                  </Typography>
                  {providers.length > 0 && (
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Button size="small" onClick={() => setForm(prev => ({ ...prev, allowed_provider_ids: providers.map(p => p.id) }))}>Select All</Button>
                      <Button size="small" onClick={() => setForm(prev => ({ ...prev, allowed_provider_ids: [] }))}>Clear</Button>
                    </Box>
                  )}
                </Box>
                {providers.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">
                    No providers exist yet—enable "Allow creating new providers" below or switch scope to "All Providers".
                  </Typography>
                ) : (
                  <Grid container spacing={1}>
                    {providers.map(p => {
                      const checked = form.allowed_provider_ids.includes(p.id);
                      return (
                        <Grid item xs={12} sm={6} key={p.id}>
                          <Paper
                            variant="outlined"
                            onClick={() => toggleProv(p.id)}
                            sx={{
                              px: 1.5, py: 0.75, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 1,
                              borderColor: checked ? 'primary.main' : 'divider',
                              bgcolor: checked ? 'action.selected' : 'background.paper'
                            }}
                          >
                            <Checkbox size="small" checked={checked} sx={{ p: 0.5 }} />
                            <Box sx={{ minWidth: 0 }}>
                              <Typography variant="body2" sx={{ fontWeight: 700 }}>{p.friendly}</Typography>
                              <Typography variant="caption" color="text.secondary" className="mono">{p.idpId}</Typography>
                            </Box>
                          </Paper>
                        </Grid>
                      );
                    })}
                  </Grid>
                )}
                <Box sx={{ mt: 1.5 }}>
                  <FormControlLabel
                    control={<Checkbox size="small" checked={!!form.can_create_providers} onChange={e => setForm({ ...form, can_create_providers: e.target.checked })} />}
                    label="Allow creating new providers (POST /api/providers — newly created providers are automatically added to this client)"
                  />
                </Box>
              </Paper>
            </Grid>
          )}

          <Grid item xs={12}>
            <FormControlLabel
              control={<Checkbox size="small" checked={form.can_mint_tokens === true} onChange={e => setForm({ ...form, can_mint_tokens: e.target.checked })} />}
              label="Can mint tokens: POST /api/token workload JWTs, private key import (keyMode paste) and creating, changing or rotating OIDC clients with the client_credentials grant"
            />
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', ml: 4 }}>
              API clients created before this capability existed do not have it: they cannot mint tokens until an administrator ticks this box.
            </Typography>
          </Grid>

          <Grid item xs={12}>
            <FormControlLabel
              control={<Checkbox size="small" checked={form.can_read_admin_audit === true} onChange={e => setForm({ ...form, can_read_admin_audit: e.target.checked })} />}
              label="Can read the administrator audit log: GET /api/admin-audit-logs (for example to collect it into a SIEM)"
            />
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', ml: 4 }}>
              The log covers all of your administrative activity: console sign-ins, every API client's actions, source addresses and user agents. Secrets are never recorded.
            </Typography>
          </Grid>

          <Grid item xs={12}>
            <TextField
              fullWidth multiline minRows={2} maxRows={8}
              label="Allowed IP addresses (optional)"
              placeholder={'203.0.113.0/24\n2001:db8::/48'}
              value={form.allowed_ips_text}
              onChange={e => setForm({ ...form, allowed_ips_text: e.target.value })}
              inputProps={{ className: 'mono', spellCheck: false }}
              helperText="One IPv4 or IPv6 address or CIDR block per line, at most 50. Empty allows any address. A request with this client's credentials from another address is refused like an invalid credential and recorded in the audit log."
            />
          </Grid>

          <Grid item xs={12} md={editingClient ? 6 : 12}>
            <TextField
              select fullWidth
              label={editingClient ? 'Update Token Expiration (leave unchanged or reset)' : 'Token Expiration'}
              value={form.expires_in}
              onChange={e => setForm({ ...form, expires_in: e.target.value })}
            >
              {editingClient && <MenuItem value="">Keep existing expiration</MenuItem>}
              <MenuItem value="never">Never expires</MenuItem>
              <MenuItem value="7d">7 days</MenuItem>
              <MenuItem value="30d">30 days</MenuItem>
              <MenuItem value="90d">90 days</MenuItem>
              <MenuItem value="365d">1 year</MenuItem>
            </TextField>
          </Grid>

          {editingClient && (
            <Grid item xs={12} md={6}>
              <TextField select fullWidth label="Client Status" value={form.status} onChange={e => setForm({ ...form, status: e.target.value })}>
                <MenuItem value="active">Active</MenuItem>
                <MenuItem value="revoked">Revoked (blocks all API requests)</MenuItem>
              </TextField>
            </Grid>
          )}
        </Grid>
      </DialogContent>
      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" onClick={save} disabled={!form.name.trim() || invalidScope}>
          {editingClient ? 'Save API Client' : 'Create API Client'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

/* ==================== DEVELOPER API CLIENTS, OPENAPI & TLS VIEW ==================== */
function DeveloperApiPanel({ me, providers, onOpenJwt, onNotify }) {
  const [adminClients, setAdminClients] = useState([]);
  const [openClientDialog, setOpenClientDialog] = useState(false);
  const [editClient, setEditClient] = useState(null);
  const [mintedClient, setMintedClient] = useState(null);
  const [okCopyToken, copyToken] = useCopyFeedback();
  const [okCopyCid, copyCid] = useCopyFeedback();
  const [okCopyCurl, copyCurl] = useCopyFeedback();

  const [apiKeyShown, setApiKeyShown] = useState(false);
  const [okCopyApi, triggerCopyApi] = useCopyFeedback();
  const [rootPem, setRootPem] = useState('');
  const [chainPem, setChainPem] = useState('');
  const [okCopyRoot, copyRoot] = useCopyFeedback();
  const [okCopyChain, copyChain] = useCopyFeedback();

  const openApiUrl = absUrl('/api/openapi.json');
  const openApiDownloadUrl = absUrl('/api/openapi.json?download=1');
  const openApiDocsUrl = absUrl('/api/docs');

  const loadClients = () => {
    api('/api/admin-clients')
      .then(r => setAdminClients(r.clients || []))
      .catch(e => onNotify && onNotify(errText(e, 'Failed to load Admin API clients'), 'error'));
  };

  useEffect(() => {
    loadClients();
    fetch(absUrl('/api/https-ca?mode=root')).then(r => r.ok ? r.text() : '').then(setRootPem).catch(() => {});
    fetch(absUrl('/api/https-ca?mode=ca')).then(r => r.ok ? r.text() : '').then(setChainPem).catch(() => {});
  }, []);

  const providerNameById = useMemo(() => {
    const map = {};
    providers.forEach(p => { map[p.id] = p.friendly; });
    return map;
  }, [providers]);

  const sampleProviderSlug = providers[0]?.idpId || '<providerId>';
  const quickstartCurl = mintedClient ? `curl -s '${absUrl('/api/providers')}' \\\n  -H 'Authorization: Bearer ${mintedClient.api_token}'\n\n# Modify provider policy or apps:\ncurl -s -X PATCH '${absUrl('/api/providers/' + sampleProviderSlug)}' \\\n  -H 'Authorization: Bearer ${mintedClient.api_token}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"default_auth_policy": "touchid_only"}'` : '';

  return (
    <Box className="fade-in">
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2, mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800 }}>Programmatic Admin API &amp; OpenAPI 3.1</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Create provider-scoped API clients so external tools, CI/CD, and Terraform scripts can create and modify SAML 2.0 &amp; OIDC configurations.
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Button variant="outlined" startIcon={<Icon name="menu_book" size={18} />} component="a" href={openApiDocsUrl} target="_blank">
            Interactive OpenAPI Docs
          </Button>
          <Button variant="contained" startIcon={<Icon name="add" size={18} />} onClick={() => { setEditClient(null); setOpenClientDialog(true); }}>
            Create API Client
          </Button>
        </Box>
      </Box>

      {/* OpenAPI 3.1 Specification Card */}
      <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 2, mb: 1.5 }}>
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
              <Icon name="description" size={20} />
              OpenAPI 3.1.0 Specification &amp; Reference Portal
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Import <code>openapi.json</code> into Postman, Insomnia, OpenAPI Generator, or explore &amp; execute live API requests in Swagger UI.
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button size="small" variant="contained" startIcon={<Icon name="open_in_new" size={16} />} component="a" href={openApiDocsUrl} target="_blank">
              Open /api/docs
            </Button>
            <Button size="small" variant="outlined" startIcon={<Icon name="download" size={16} />} component="a" href={openApiDownloadUrl} target="_blank">
              Download openapi.json
            </Button>
          </Box>
        </Box>
        <CopyEndpointRow label="OpenAPI 3.1 JSON" url={openApiUrl} downloadUrl={openApiDownloadUrl} />
        <CopyEndpointRow label="OAuth2 Token URL" url={absUrl('/api/oauth2/token')} openable={false} />
      </Paper>

      {/* Scoped Admin API Clients List */}
      <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, flexWrap: 'wrap', gap: 1.5 }}>
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
              <Icon name="api" size={20} />
              Scoped Administration API Clients ({adminClients.length})
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Authenticate with <code>Authorization: Bearer idp_adm_…</code>, <code>X-API-Key</code>, HTTP Basic, or OAuth2 <code>client_credentials</code>.
            </Typography>
          </Box>
          <Button size="small" variant="contained" startIcon={<Icon name="add" size={17} />} onClick={() => { setEditClient(null); setOpenClientDialog(true); }}>
            New API Client
          </Button>
        </Box>

        {adminClients.length === 0 ? (
          <Box sx={{ py: 5, textAlign: 'center' }}>
            <Icon name="vpn_key" size={38} style={{ opacity: 0.35 }} />
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mt: 1 }}>No programmatic API clients yet</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 460, mx: 'auto', mt: 0.5, mb: 2.5 }}>
              Create an API client restricted to one or more specific providers (or all providers) to automate SAML 2.0 apps, OIDC clients, signing keys, and policies.
            </Typography>
            <Button variant="contained" startIcon={<Icon name="add" size={18} />} onClick={() => { setEditClient(null); setOpenClientDialog(true); }}>
              Create First API Client
            </Button>
          </Box>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            {adminClients.map(c => (
              <Paper key={c.id} variant="outlined" sx={{ p: 2.25, opacity: c.status === 'revoked' || c.is_expired ? 0.72 : 1 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2 }}>
                  <Box sx={{ flex: 1, minWidth: 280 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', mb: 0.75 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{c.name}</Typography>
                      <Chip
                        size="small"
                        color={c.status !== 'active' || c.is_expired ? 'error' : 'success'}
                        label={c.status !== 'active' ? 'Revoked' : (c.is_expired ? 'Expired' : 'Active')}
                      />
                      <Chip
                        size="small"
                        color={c.provider_permission === 'write' ? 'primary' : 'default'}
                        variant="outlined"
                        label={c.provider_permission === 'write' ? 'Providers: Read & Write' : 'Providers: Read-Only'}
                      />
                      {c.user_scope !== 'none' && (
                        <Chip size="small" variant="outlined" label={`Users: ${c.user_scope}`} />
                      )}
                      {c.can_mint_tokens === true && (
                        <Chip size="small" color="warning" variant="outlined" label="Can Mint Tokens" />
                      )}
                      {c.can_read_admin_audit === true && (
                        <Chip size="small" variant="outlined" label="Reads Audit Log" />
                      )}
                      {(c.allowed_ips || []).length > 0 && (
                        <Chip size="small" color="info" variant="outlined" label="IP-Restricted" />
                      )}
                    </Box>

                    {c.description && (
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 0.75 }}>{c.description}</Typography>
                    )}

                    <Typography variant="body2" sx={{ mb: 0.5 }}>
                      <strong>client_id:</strong> <code className="mono">{c.client_id}</code> • <strong>token:</strong> <code className="mono">{c.secret_preview}</code>
                    </Typography>

                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, flexWrap: 'wrap', mt: 1 }}>
                      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700 }}>
                        ALLOWED PROVIDERS:
                      </Typography>
                      {c.provider_scope === 'all' ? (
                        <Chip size="small" color="secondary" label="All Providers (Current & Future)" sx={{ height: 22, fontSize: 11.5 }} />
                      ) : (
                        <>
                          {(c.allowed_provider_ids || []).map(pid => (
                            <Chip key={pid} size="small" variant="outlined" label={providerNameById[pid] || pid} sx={{ height: 22, fontSize: 11.5 }} />
                          ))}
                          {c.can_create_providers && (
                            <Chip size="small" color="info" variant="outlined" label="+ Can Create Providers" sx={{ height: 22, fontSize: 11.5 }} />
                          )}
                        </>
                      )}
                    </Box>

                    {(c.allowed_ips || []).length > 0 && (
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, flexWrap: 'wrap', mt: 1 }}>
                        <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700 }}>
                          ALLOWED IPS:
                        </Typography>
                        {c.allowed_ips.map(ip => (
                          <Chip key={ip} size="small" variant="outlined" className="mono" label={ip} sx={{ height: 22, fontSize: 11.5 }} />
                        ))}
                      </Box>
                    )}

                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                      Created {relativeTime(c.created_at)}
                      {c.expires_at ? ` • Expires ${c.expires_at}` : ' • No expiration'}
                      {c.last_used_at ? ` • Last used ${relativeTime(c.last_used_at)} (${c.last_used_ip || ''})` : ' • Never used yet'}
                    </Typography>
                  </Box>

                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                    <Button size="small" variant="outlined" startIcon={<Icon name="autorenew" size={16} />} onClick={() => {
                      if (!confirm(`Rotate API token for "${c.name}"? Any scripts using the previous token will stop working immediately.`)) return;
                      api(`/api/admin-clients/${c.id}/rotate-secret`, { method: 'POST' })
                        .then(res => {
                          loadClients();
                          if (res.client?.api_token) setMintedClient(res.client);
                          else if (onNotify) onNotify('Rotated API token');
                        })
                        .catch(e => onNotify && onNotify('API token NOT rotated: ' + errText(e, 'request failed'), 'error'));
                    }}>
                      Rotate Token
                    </Button>
                    <Button size="small" variant="outlined" onClick={() => { setEditClient(c); setOpenClientDialog(true); }}>
                      Edit Scopes
                    </Button>
                    <IconButton size="small" color="error" onClick={() => {
                      if (!confirm(`Delete Admin API Client "${c.name}"?`)) return;
                      api(`/api/admin-clients/${c.id}`, { method: 'DELETE' })
                        .then(() => {
                          loadClients();
                          if (onNotify) onNotify('Deleted Admin API Client');
                        })
                        .catch(e => onNotify && onNotify('Admin API Client NOT deleted: ' + errText(e, 'request failed'), 'error'));
                    }}><Icon name="delete_outline" size={19} /></IconButton>
                  </Box>
                </Box>
              </Paper>
            ))}
          </Box>
        )}
      </Paper>

      {/* Legacy Workload JWT Key: only while the server still issues it (legacy_admin_api_key, S10-04) */}
      {me.apiKey && (
      <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2, mb: 2 }}>
          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
              <Icon name="terminal" size={20} />
              Legacy Workload JWT Key (POST /api/token only)
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Backward-compatible key for minting raw workload JWTs via <code>POST /api/token</code>, enabled by the <code>legacy_admin_api_key</code> setting. Prefer a scoped Admin API client above with "Can mint tokens" enabled, which can be rotated and revoked.
            </Typography>
          </Box>
          {providers.length > 0 && (
            <Button size="small" variant="outlined" startIcon={<Icon name="bolt" size={17} />} onClick={() => onOpenJwt(providers[0])}>
              Open JWT Minter
            </Button>
          )}
        </Box>
        <TextField
          fullWidth
          value={me.apiKey || ''}
          type={apiKeyShown ? 'text' : 'password'}
          InputProps={{
            readOnly: true,
            className: 'mono',
            endAdornment: (
              <InputAdornment position="end" sx={{ display: 'flex', gap: 0.5 }}>
                <Tooltip title={okCopyApi ? 'Copied!' : 'Copy API Key'}>
                  <IconButton onClick={() => triggerCopyApi(me.apiKey || '')} size="small">
                    <Icon name={okCopyApi ? 'check' : 'content_copy'} size={18} />
                  </IconButton>
                </Tooltip>
                <IconButton onClick={() => setApiKeyShown(!apiKeyShown)} size="small">
                  <Icon name={apiKeyShown ? 'visibility_off' : 'visibility'} size={18} />
                </IconButton>
              </InputAdornment>
            )
          }}
        />
      </Paper>
      )}

      {/* HTTPS Root & CA Bundle */}
      <Paper variant="outlined" sx={{ p: 3 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5, display: 'flex', alignItems: 'center', gap: 1 }}>
          <Icon name="security" size={20} />
          HTTPS Root &amp; Intermediate CA Bundle Export
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2.5 }}>
          Inspect or copy the TLS certificate chain served by this host when running behind a custom or internal PKI.
        </Typography>
        <Grid container spacing={2.5}>
          <Grid item xs={12} md={6}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="caption" sx={{ fontWeight: 700, textTransform: 'uppercase', color: 'text.secondary' }}>Root CA Certificate</Typography>
              <Button size="small" disabled={!rootPem} onClick={() => rootPem && copyRoot(rootPem)}>
                {okCopyRoot ? 'Copied!' : 'Copy PEM'}
              </Button>
            </Box>
            <Paper variant="outlined" sx={{ p: 2, maxHeight: 220, overflow: 'auto', bgcolor: '#0f172a', color: '#cbd5e1' }}>
              <pre style={{ margin: 0, fontSize: 12 }}><code>{rootPem || 'Not running behind public HTTPS or no custom root CA detected.'}</code></pre>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="caption" sx={{ fontWeight: 700, textTransform: 'uppercase', color: 'text.secondary' }}>Intermediate CA Chain</Typography>
              <Button size="small" disabled={!chainPem} onClick={() => chainPem && copyChain(chainPem)}>
                {okCopyChain ? 'Copied!' : 'Copy PEM'}
              </Button>
            </Box>
            <Paper variant="outlined" sx={{ p: 2, maxHeight: 220, overflow: 'auto', bgcolor: '#0f172a', color: '#cbd5e1' }}>
              <pre style={{ margin: 0, fontSize: 12 }}><code>{chainPem || '—'}</code></pre>
            </Paper>
          </Grid>
        </Grid>
      </Paper>

      <AdminApiClientDialog
        open={openClientDialog}
        onClose={() => setOpenClientDialog(false)}
        providers={providers}
        editingClient={editClient}
        onSaved={(saved) => {
          loadClients();
          if (saved?.api_token) setMintedClient(saved);
          else if (onNotify) onNotify('Updated Admin API Client');
        }}
      />

      {/* One-Time API Token Display Modal */}
      <Dialog open={!!mintedClient} onClose={() => setMintedClient(null)} fullWidth maxWidth="md">
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Icon name="vpn_key" size={22} />
          <span>Copy Admin API Client Credentials — {mintedClient?.name}</span>
        </DialogTitle>
        <DialogContent dividers>
          <Alert severity="warning" sx={{ mb: 2.5 }}>
            Copy this <strong>API Token / Client Secret</strong> now. Only its salted hash is stored in SQLite—it cannot be viewed again.
          </Alert>
          <Grid container spacing={2}>
            <Grid item xs={12} md={5}>
              <TextField
                fullWidth size="small" label="Client ID (for Basic / OAuth2)"
                value={mintedClient?.client_id || ''}
                InputProps={{
                  readOnly: true, className: 'mono',
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton size="small" onClick={() => copyCid(mintedClient?.client_id || '')}>
                        <Icon name={okCopyCid ? 'check' : 'content_copy'} size={17} />
                      </IconButton>
                    </InputAdornment>
                  )
                }}
              />
            </Grid>
            <Grid item xs={12} md={7}>
              <TextField
                fullWidth size="small" label="Bearer API Token / Client Secret"
                value={mintedClient?.api_token || ''}
                InputProps={{
                  readOnly: true, className: 'mono',
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton size="small" onClick={() => copyToken(mintedClient?.api_token || '')}>
                        <Icon name={okCopyToken ? 'check' : 'content_copy'} size={17} />
                      </IconButton>
                    </InputAdornment>
                  )
                }}
              />
            </Grid>
          </Grid>
          <Box sx={{ mt: 2.5, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>Quickstart cURL Example</Typography>
            <Button size="small" startIcon={<Icon name={okCopyCurl ? 'check' : 'content_copy'} size={15} />} onClick={() => copyCurl(quickstartCurl)}>
              {okCopyCurl ? 'Copied!' : 'Copy cURL'}
            </Button>
          </Box>
          <Paper variant="outlined" sx={{ mt: 1, p: 2, overflowX: 'auto', bgcolor: '#0f172a', color: '#e2e8f0' }}>
            <pre style={{ margin: 0, fontSize: 12.5 }}><code>{quickstartCurl}</code></pre>
          </Paper>
        </DialogContent>
        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button onClick={() => copyToken(mintedClient?.api_token || '')}>{okCopyToken ? 'Copied Token!' : 'Copy API Token'}</Button>
          <Button variant="contained" onClick={() => setMintedClient(null)}>Done</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

/* ==================== ADMIN AUTHENTICATOR APP (TOTP, G2a-07) ==================== */
// The account to add to an authenticator app: the base32 secret and the otpauth:// URI the
// server returned. The console has no QR code library, so both are shown as text to copy.
function TotpSetupInfo({ totp }) {
  const [okSecret, copySecret] = useCopyFeedback();
  const [okUri, copyUri] = useCopyFeedback();
  if (!totp || !totp.secret) return null;
  const secret = String(totp.secret);
  const minutes = typeof totp.expires_in === 'number' && totp.expires_in > 0 ? Math.max(1, Math.floor(totp.expires_in / 60)) : null;
  return (
    <Paper variant="outlined" sx={{ p: 1.75, bgcolor: 'action.hover' }}>
      <Typography variant="body2" sx={{ mb: 1 }}>
        Add this account to your authenticator app: enter the secret key as a time-based key (6 digits, 30 seconds) or import the otpauth URI. Then enter the code the app shows{minutes ? `, within ${minutes} minutes` : ''}.
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, display: 'block' }}>SECRET KEY</Typography>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: totp.otpauth_uri ? 1 : 0 }}>
        <Typography className="mono" sx={{ fontSize: 13.5, wordBreak: 'break-all', flex: 1 }}>
          {secret.replace(/(.{4})/g, '$1 ').trim()}
        </Typography>
        <Tooltip title={okSecret ? 'Copied!' : 'Copy secret key'}>
          <IconButton size="small" onClick={() => copySecret(secret)}><Icon name={okSecret ? 'check' : 'content_copy'} size={16} /></IconButton>
        </Tooltip>
      </Box>
      {totp.otpauth_uri && (
        <>
          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, display: 'block' }}>OTPAUTH URI</Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography className="mono" sx={{ fontSize: 11.5, wordBreak: 'break-all', flex: 1 }}>{String(totp.otpauth_uri)}</Typography>
            <Tooltip title={okUri ? 'Copied!' : 'Copy URI'}>
              <IconButton size="small" onClick={() => copyUri(String(totp.otpauth_uri))}><Icon name={okUri ? 'check' : 'content_copy'} size={16} /></IconButton>
            </Tooltip>
          </Box>
        </>
      )}
    </Paper>
  );
}

// The signed-in administrator's authenticator app: once confirmed, every console sign-in asks
// for its code. Setting one up or removing it needs the current password, and removing an
// active app also a current code; the server answers 403 when either is wrong.
function AdminMfaCard({ onNotify }) {
  const [status, setStatus] = useState(null); // { totp: { enrolled, pending, confirmed_at }, required }
  const [loadErr, setLoadErr] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [setup, setSetup] = useState(null); // { secret, otpauth_uri, expires_in } until confirmed
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const otpCode = otp.replace(/\s+/g, '');

  const load = () => api('/api/admin-mfa')
    .then(r => { setStatus(r || {}); setLoadErr(''); })
    .catch(e => setLoadErr(errText(e, 'Failed to load the authenticator app status')));
  useEffect(() => { load(); }, []);

  const run = (request, onDone) => {
    setBusy(true);
    setErr('');
    request()
      .then(onDone)
      .catch(e => setErr(errText(e, 'Request failed')))
      .finally(() => setBusy(false));
  };

  const startSetup = () => run(
    () => api('/api/admin-mfa/totp', { method: 'POST', body: JSON.stringify({ password }) }),
    r => {
      setPassword(''); setOtp('');
      if (r && r.totp && r.totp.secret) setSetup(r.totp);
      else setErr('The server returned no secret; start the setup again.');
    }
  );

  const confirmSetup = () => run(
    () => api('/api/admin-mfa/totp/confirm', { method: 'POST', body: JSON.stringify({ otp: otpCode }) }),
    r => {
      setSetup(null); setOtp('');
      setStatus(s => ({ ...(s || {}), totp: (r && r.totp) || { enrolled: true, pending: false, confirmed_at: null } }));
      onNotify('Authenticator app set up: console sign-ins now ask for its code');
    }
  );

  const removeApp = () => {
    const required = !!(status && status.required);
    if (!confirm('Remove your authenticator app? ' + (required
      ? 'This console requires one (OIDC_ADMIN_REQUIRE_MFA), so your next sign-in will set up a new one.'
      : 'Console sign-ins will then need only your password.'))) return;
    run(
      () => api('/api/admin-mfa/totp', { method: 'DELETE', body: JSON.stringify({ password, otp: otpCode }) }),
      () => { setPassword(''); setOtp(''); load(); onNotify('Authenticator app removed'); }
    );
  };

  const totp = (status && status.totp) || {};
  const enrolled = totp.enrolled === true;
  const passwordField = (
    <TextField
      fullWidth size="small" type="password" label="Current password" value={password}
      onChange={e => setPassword(e.target.value)} autoComplete="current-password"
    />
  );
  const codeField = (
    <TextField
      fullWidth size="small" label="Authentication code" placeholder="123456" value={otp}
      onChange={e => setOtp(e.target.value)}
      inputProps={{ inputMode: 'numeric', autoComplete: 'one-time-code', maxLength: 8, className: 'mono' }}
    />
  );

  return (
    <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 1.5, mb: 1.5 }}>
        <Box>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
            <Icon name="phonelink_lock" size={20} />
            Authenticator App
          </Typography>
          <Typography variant="body2" color="text.secondary">
            A second sign-in step for your console account: after your password, the 6-digit code from an authenticator app (TOTP).
          </Typography>
        </Box>
        {status && (
          <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
            <Chip size="small" color={enrolled ? 'success' : 'default'} variant={enrolled ? 'filled' : 'outlined'} label={enrolled ? 'On' : 'Off'} />
            {status.required && <Chip size="small" color="info" variant="outlined" label="Required for all administrators" />}
          </Box>
        )}
      </Box>

      {loadErr && <Alert severity="error" sx={{ mb: 1.5 }}>{loadErr}</Alert>}
      {err && <Alert severity="error" sx={{ mb: 1.5 }}>{err}</Alert>}

      {status && enrolled && (
        <Box>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            Every console sign-in asks for a code from your app{totp.confirmed_at ? ` (set up ${totp.confirmed_at})` : ''}. To remove it, enter your password and a current code.
          </Typography>
          <Grid container spacing={1.5} alignItems="center">
            <Grid item xs={12} md={5}>{passwordField}</Grid>
            <Grid item xs={12} md={4}>{codeField}</Grid>
            <Grid item xs={12} md={3}>
              <Button fullWidth color="error" variant="outlined" onClick={removeApp} disabled={busy || !password || !/^\d{6}$/.test(otpCode)}>
                Remove App
              </Button>
            </Grid>
          </Grid>
        </Box>
      )}

      {status && !enrolled && !setup && (
        <Box>
          {status.required && (
            <Alert severity="warning" sx={{ mb: 1.5 }}>
              This console requires an authenticator app for every administrator: set one up now, or your next sign-in will ask you to.
            </Alert>
          )}
          {totp.pending && (
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              A setup was started but not confirmed. Set it up again to get a new secret.
            </Typography>
          )}
          <Grid container spacing={1.5} alignItems="center">
            <Grid item xs={12} md={6}>{passwordField}</Grid>
            <Grid item xs={12} md={3}>
              <Button fullWidth variant="contained" onClick={startSetup} disabled={busy || !password}>
                Set Up App
              </Button>
            </Grid>
          </Grid>
        </Box>
      )}

      {status && !enrolled && setup && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          <TotpSetupInfo totp={setup} />
          <Grid container spacing={1.5} alignItems="center">
            <Grid item xs={12} md={5}>{codeField}</Grid>
            <Grid item xs={6} md={3}>
              <Button fullWidth variant="contained" onClick={confirmSetup} disabled={busy || !/^\d{6}$/.test(otpCode)}>
                Confirm
              </Button>
            </Grid>
            <Grid item xs={6} md={2}>
              <Button fullWidth onClick={() => { setSetup(null); setOtp(''); setErr(''); load(); }} disabled={busy}>
                Cancel
              </Button>
            </Grid>
          </Grid>
        </Box>
      )}
    </Paper>
  );
}

function AccountSecurityPanel({ me, onNotify }) {
  return (
    <Box className="fade-in">
      <Box sx={{ mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 800 }}>Account Security</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          How <strong>{me.user}</strong> signs in to this console.
        </Typography>
      </Box>
      <AdminMfaCard onNotify={onNotify} />
    </Box>
  );
}

/* ==================== ADMIN AUDIT LOG (G1a-01) ==================== */
// Actions of this administrator's console sessions and API clients, failed sign-ins with the
// administrator's name and sign-in alerts, newest first (GET /api/admin-audit-logs).
const ADMIN_AUDIT_CLASS_META = {
  security: { label: 'Security', color: 'primary' },
  routine: { label: 'Routine', color: 'default' },
  untrusted: { label: 'Untrusted', color: 'warning' },
};

function adminAuditIsAlert(l) {
  return l.action === 'admin.login_alert' || l.actor_type === 'system';
}

function adminAuditIsFailedSignIn(l) {
  return l.action === 'admin.login' && l.outcome === 'failure';
}

function AdminAuditLogPanel({ onNotify }) {
  const [logs, setLogs] = useState([]);
  const [loaded, setLoaded] = useState(false);
  const [filter, setFilter] = useState('');
  const [classFilter, setClassFilter] = useState('all');

  const load = () => api('/api/admin-audit-logs?limit=200')
    .then(r => { setLogs(Array.isArray(r.logs) ? r.logs : []); setLoaded(true); })
    .catch(e => { setLoaded(true); onNotify(errText(e, 'Failed to load the admin audit log'), 'error'); });
  useEffect(() => { load(); }, []);

  const detailsText = (d) => (d && typeof d === 'object' && Object.keys(d).length ? JSON.stringify(d) : '');
  const q = filter.trim().toLowerCase();
  const filtered = logs.filter(l => {
    if (classFilter !== 'all' && (l.audit_class || 'security') !== classFilter) return false;
    if (!q) return true;
    return [l.action, l.outcome, l.actor_type, l.actor_name, l.actor_id, l.source_ip, l.user_agent, l.target, l.provider_id, detailsText(l.details)]
      .some(v => String(v || '').toLowerCase().includes(q));
  });
  const alertCount = logs.filter(adminAuditIsAlert).length;
  const failedCount = logs.filter(adminAuditIsFailedSignIn).length;

  return (
    <Box className="fade-in">
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2, mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800 }}>Admin Audit Log</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Sign-ins and changes made with your console account and your Admin API clients, failed sign-ins with your username and sign-in alerts. Newest first, last 200 entries.
          </Typography>
        </Box>
        <Button variant="outlined" startIcon={<Icon name="refresh" size={18} />} onClick={load}>Refresh</Button>
      </Box>

      {(alertCount > 0 || failedCount > 0) && (
        <Alert severity={alertCount > 0 ? 'error' : 'warning'} sx={{ mb: 2.5 }}>
          {alertCount > 0 ? `${alertCount} sign-in alert${alertCount === 1 ? '' : 's'}` : ''}
          {alertCount > 0 && failedCount > 0 ? ' and ' : ''}
          {failedCount > 0 ? `${failedCount} failed sign-in${failedCount === 1 ? '' : 's'}` : ''}
          {' '}among the entries below (highlighted). A failed sign-in that was not you means someone tried your username; an alert means many failed console sign-ins in a short time.
        </Alert>
      )}

      <Paper variant="outlined" sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center', flexWrap: 'wrap', mb: 2 }}>
          <TextField
            size="small"
            placeholder="Filter action, actor, IP, target…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            sx={{ minWidth: 280, flex: 1, maxWidth: 440 }}
            InputProps={{
              startAdornment: <InputAdornment position="start"><Icon name="search" size={18} /></InputAdornment>
            }}
          />
          <TextField select size="small" label="Class" value={classFilter} onChange={e => setClassFilter(e.target.value)} sx={{ minWidth: 160 }}>
            <MenuItem value="all">All classes</MenuItem>
            <MenuItem value="security">Security</MenuItem>
            <MenuItem value="routine">Routine</MenuItem>
            <MenuItem value="untrusted">Untrusted</MenuItem>
          </TextField>
          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
            Showing {filtered.length} of {logs.length}
          </Typography>
        </Box>

        {filtered.length === 0 ? (
          <Box sx={{ py: 5, textAlign: 'center' }}>
            <Icon name="policy" size={36} style={{ opacity: 0.35 }} />
            <Typography color="text.secondary" sx={{ mt: 1 }}>
              {loaded ? 'No matching admin events recorded yet.' : 'Loading…'}
            </Typography>
          </Box>
        ) : (
          <Box sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Time (UTC)</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Action</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Outcome</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Actor</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Source</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Target</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Class</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Details</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filtered.map(l => {
                  const alert = adminAuditIsAlert(l);
                  const failedSignIn = adminAuditIsFailedSignIn(l);
                  const cls = ADMIN_AUDIT_CLASS_META[l.audit_class] || { label: l.audit_class || 'Security', color: 'default' };
                  const details = detailsText(l.details);
                  return (
                    <TableRow
                      key={l.id}
                      hover
                      sx={alert
                        ? { bgcolor: 'rgba(239, 68, 68, 0.10)' }
                        : (failedSignIn ? { bgcolor: 'rgba(245, 158, 11, 0.10)' } : undefined)}
                    >
                      <TableCell className="mono" sx={{ whiteSpace: 'nowrap', fontSize: 12 }} title={relativeTime(l.created_at)}>{l.created_at}</TableCell>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, flexWrap: 'wrap' }}>
                          <span className="mono" style={{ fontSize: 12.5 }}>{l.action}</span>
                          {alert && <Chip size="small" color="error" label="Alert" sx={{ height: 20, fontSize: 11, fontWeight: 700 }} />}
                          {failedSignIn && <Chip size="small" color="warning" label="Failed sign-in" sx={{ height: 20, fontSize: 11, fontWeight: 700 }} />}
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip size="small" color={l.outcome === 'success' ? 'success' : 'error'} label={l.outcome || '—'} sx={{ fontWeight: 700, fontSize: 11 }} />
                      </TableCell>
                      <TableCell sx={{ fontSize: 12.5 }}>
                        <Box className="mono" sx={{ fontSize: 11.5, color: 'text.secondary' }}>{l.actor_type}</Box>
                        {l.actor_name && <Box sx={{ fontWeight: 600 }}>{l.actor_name}</Box>}
                        {l.actor_id && <Box className="mono" sx={{ fontSize: 11.5 }}>{l.actor_id}</Box>}
                      </TableCell>
                      <TableCell sx={{ fontSize: 12.5, maxWidth: 220 }}>
                        <Box className="mono">{l.source_ip || '—'}</Box>
                        {l.user_agent && (
                          <Box sx={{ fontSize: 11, color: 'text.secondary', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={l.user_agent}>
                            {l.user_agent}
                          </Box>
                        )}
                      </TableCell>
                      <TableCell sx={{ fontSize: 12, maxWidth: 220, wordBreak: 'break-all' }}>
                        {l.target ? <Box className="mono">{l.target}</Box> : null}
                        {l.provider_id ? <Box sx={{ fontSize: 11, color: 'text.secondary' }}>Provider <span className="mono">{l.provider_id}</span></Box> : null}
                        {!l.target && !l.provider_id ? '—' : null}
                      </TableCell>
                      <TableCell>
                        <Chip size="small" variant="outlined" color={cls.color} label={cls.label} sx={{ fontSize: 11 }} />
                      </TableCell>
                      <TableCell className="mono" sx={{ fontSize: 11.5, maxWidth: 320, wordBreak: 'break-all' }}>
                        {details || '—'}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Box>
        )}
      </Paper>
    </Box>
  );
}

/* ==================== BLOCKED REQUESTS (IP ALLOWLIST) ==================== */
// The operator's IP allowlist (ip_allowlist in config.php or OIDC_IP_ALLOWLIST; this page only
// reads it) and the requests it refused: GET /api/ip-allowlist, GET and DELETE
// /api/ip-allowlist/blocked-requests. The logged values (addresses, paths, Host headers, user
// agents) come from the refused clients: they are shown as text only, never as HTML or links.
const BLOCKED_REASON_META = {
  not_listed: { label: 'Not in allowlist', color: 'error' },
  bad_forwarded_for: { label: 'Bad X-Forwarded-For', color: 'warning' },
  unknown_address: { label: 'Unknown address', color: 'warning' },
  config_error: { label: 'Configuration error', color: 'error' },
  check_failed: { label: 'Check failed', color: 'error' },
};

const BLOCKED_PAGE_SIZE = 100;
const BLOCKED_RANGES_SHOWN = 50;
// The filters as entered: ip, since and until (datetime-local values in the browser's time
// zone) and reason ('' for all, one of the reasons, or 'report_only').
const BLOCKED_EMPTY_FILTERS = { ip: '', since: '', until: '', reason: '' };

const BLOCKED_ADDRESS_BUTTON_SX = {
  p: 0, m: 0, border: 0, bgcolor: 'transparent', cursor: 'pointer', textAlign: 'left',
  fontSize: 12.5, fontWeight: 700, lineHeight: 1.5, color: 'primary.main', wordBreak: 'break-all',
  '&:hover': { textDecoration: 'underline' },
};

// Server values as React text and shapes: null becomes '', and a value that is not the
// expected object or list becomes an empty one, so an unexpected answer cannot break the page.
function blockedText(v) {
  return v === null || v === undefined ? '' : String(v);
}

function blockedObject(v) {
  return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
}

function blockedList(v) {
  return Array.isArray(v) ? v : [];
}

function blockedEntries(v) {
  return blockedList(v).filter(e => e && typeof e === 'object' && !Array.isArray(e));
}

function blockedCursor(v) {
  const s = blockedText(v);
  return /^\d{1,18}$/.test(s) ? s : null;
}

// The label and chip color of a reason; an unknown value is shown as it is.
function blockedReasonMeta(reason) {
  const key = blockedText(reason);
  return Object.prototype.hasOwnProperty.call(BLOCKED_REASON_META, key)
    ? BLOCKED_REASON_META[key]
    : { label: key || 'unknown', color: 'default' };
}

function blockedReasonLabel(reason) {
  return blockedReasonMeta(reason).label;
}

function blockedSeverity(level) {
  return ['error', 'warning', 'info', 'success'].includes(level) ? level : 'info';
}

function blockedCount(n) {
  const v = Number(n);
  return Number.isFinite(v) ? v.toLocaleString() : '0';
}

function blockedFormatBytes(n) {
  let v = Number(n);
  if (!Number.isFinite(v) || v < 0) return '?';
  if (v < 1024) return `${v} B`;
  const units = ['KiB', 'MiB', 'GiB'];
  let i = -1;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 10 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

// A datetime-local value (the browser's time zone) as ISO 8601 UTC: '' when empty, null when
// it is not a date and time.
function blockedLocalToIso(localValue) {
  const v = String(localValue || '').trim();
  if (!v) return '';
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

// Query parameters for the applied filters f. The list, the CSV export and a filtered purge
// all use them, so all three cover the same rows. "Report-only" sends enforced=0. A time that
// does not parse is sent as typed: the server refuses it (400) instead of the filter being
// dropped, which would widen an export or a purge.
function blockedRequestsQuery(f) {
  const q = new URLSearchParams();
  const ip = String(f.ip || '').trim();
  if (ip) q.set('ip', ip);
  for (const key of ['since', 'until']) {
    const typed = String(f[key] || '').trim();
    if (typed) q.set(key, blockedLocalToIso(typed) || typed);
  }
  if (f.reason === 'report_only') q.set('enforced', '0');
  else if (f.reason) q.set('reason', f.reason);
  return q;
}

// The state chip of the status card. Report-only wins over the state: nothing is refused.
function blockedStateMeta(status) {
  if (status.state === 'disabled') return { label: 'Off', color: 'default', text: 'every address is served' };
  if (status.report_only) return { label: 'Report-only', color: 'warning', text: 'nothing is refused; would-be refusals are listed' };
  if (status.state === 'deny_all') return { label: 'Refusing every request', color: 'error', text: '' };
  if (status.state === 'active') return { label: 'Enforcing', color: 'success', text: '' };
  return { label: blockedText(status.state) || 'Unknown', color: 'default', text: '' };
}

function blockedSourceText(status) {
  if (status.source === 'env') return 'Source: the OIDC_IP_ALLOWLIST environment variable, which replaces ip_allowlist in config.php (entries from it have no labels).';
  if (status.source === 'config') return 'Source: ip_allowlist in config.php.';
  if (status.state === 'deny_all') return 'Source: config.php, which does not load (see the problems below).';
  return 'Source: none (ip_allowlist is empty or not set).';
}

// GET /api/ip-allowlist: the state, warnings, the viewer's own address and decision, the
// ranges and the log size. Nothing here changes the configuration.
function BlockedStatusCard({ status }) {
  const [okEntry, copyEntry] = useCopyFeedback();
  const [okSnippet, copySnippet] = useCopyFeedback();
  const [allRanges, setAllRanges] = useState(false);
  const meta = blockedStateMeta(status);
  const viewer = blockedObject(status.viewer);
  // The web answer always has the viewer section (the command line's has none).
  const hasViewer = Object.keys(viewer).length > 0;
  const matched = blockedObject(viewer.matched);
  const log = blockedObject(status.log);
  const ranges = blockedList(status.ranges);
  const problems = blockedList(status.problems);
  const warnings = blockedList(status.warnings);
  const proxies = blockedList(status.trusted_proxies);
  const viewerIp = blockedText(viewer.ip);
  const viewerPeer = blockedText(viewer.peer);
  const suggested = blockedText(viewer.suggested_entry);
  // Report-only first, so that nothing is refused while the list is checked here.
  const snippet = status.state === 'disabled' && suggested
    ? '"ip_allowlist" => ["' + suggested + '" => "My address"], "ip_allowlist_report_only" => true,'
    : '';
  let decision = { text: 'The allowlist is off', color: 'text.secondary' };
  if (viewer.decision === 'allowed') {
    const label = blockedText(matched.label);
    decision = { text: 'Allowed by ' + blockedText(matched.cidr) + (label ? ' (' + label + ')' : ''), color: 'success.main' };
  } else if (viewer.decision === 'refused') {
    decision = { text: 'Would be refused: ' + blockedReasonLabel(viewer.reason), color: 'error.main' };
  }
  const rows = Number(log.rows) || 0;
  const hits = Number(log.hits) || 0;
  const shownRanges = allRanges ? ranges : ranges.slice(0, BLOCKED_RANGES_SHOWN);
  const headingSx = { fontWeight: 700, display: 'block', textTransform: 'uppercase', letterSpacing: '0.04em', mb: 0.5 };

  return (
    <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25, flexWrap: 'wrap', mb: 2 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 1 }}>
          <Icon name="shield" size={20} />
          IP Allowlist
        </Typography>
        <Chip size="small" color={meta.color} label={meta.label} sx={{ fontWeight: 700 }} />
        {meta.text && <Typography variant="body2" color="text.secondary">{meta.text}</Typography>}
      </Box>

      {snippet && (
        <Box sx={{ mb: 2 }}>
          <Typography variant="body2" sx={{ mb: 0.75 }}>
            To turn it on, add this to config.php. It starts in report-only mode: nothing is refused until ip_allowlist_report_only is removed.
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, py: 1, px: 1.5, borderRadius: 2, bgcolor: 'action.hover', border: '1px solid', borderColor: 'divider' }}>
            <Typography className="mono" sx={{ fontSize: 12.5, flex: 1, minWidth: 0, wordBreak: 'break-all' }}>{snippet}</Typography>
            <Tooltip title={okSnippet ? 'Copied!' : 'Copy'}>
              <IconButton size="small" onClick={() => copySnippet(snippet)} color={okSnippet ? 'success' : 'default'}>
                <Icon name={okSnippet ? 'check' : 'content_copy'} size={16} />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
      )}

      {warnings.map((w, i) => {
        const item = blockedObject(w);
        return (
          <Alert key={i} severity={blockedSeverity(item.level)} sx={{ mb: 1 }}>
            {blockedText(item.message) || blockedText(item.code)}
          </Alert>
        );
      })}

      {hasViewer && (
        <Box sx={{ mt: warnings.length ? 2 : 0, mb: 2.5 }}>
          <Typography variant="caption" color="text.secondary" sx={headingSx}>Your address</Typography>
          <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, flexWrap: 'wrap' }}>
            <Typography className="mono" sx={{ fontWeight: 700, fontSize: 14 }}>{viewerIp || 'Unknown'}</Typography>
            {viewer.via_proxy === true && viewerPeer && (
              <Typography variant="body2" color="text.secondary">via proxy <span className="mono">{viewerPeer}</span></Typography>
            )}
            {viewer.via_proxy !== true && !viewerIp && viewerPeer && (
              <Typography variant="body2" color="text.secondary">connection from <span className="mono">{viewerPeer}</span></Typography>
            )}
          </Box>
          <Typography variant="body2" sx={{ color: decision.color, fontWeight: 600, mt: 0.25 }}>{decision.text}</Typography>
          {viewer.problem && viewer.decision !== 'refused' && (
            <Typography variant="body2" color="warning.main" sx={{ mt: 0.25 }}>
              Your address could not be determined ({blockedReasonLabel(viewer.problem)}): once the allowlist is on, requests like this one are refused.
            </Typography>
          )}
          {suggested && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 0.5, flexWrap: 'wrap' }}>
              <Typography variant="body2" color="text.secondary">Suggested entry</Typography>
              <Typography className="mono" sx={{ fontSize: 13, fontWeight: 600 }}>{suggested}</Typography>
              <Tooltip title={okEntry ? 'Copied!' : 'Copy entry'}>
                <IconButton size="small" onClick={() => copyEntry(suggested)} color={okEntry ? 'success' : 'default'}>
                  <Icon name={okEntry ? 'check' : 'content_copy'} size={16} />
                </IconButton>
              </Tooltip>
            </Box>
          )}
          {proxies.length > 0 && (
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
              Trusted proxies: <span className="mono">{proxies.map(blockedText).join(', ')}</span>
            </Typography>
          )}
        </Box>
      )}

      <Typography variant="caption" color="text.secondary" sx={headingSx}>Active ranges</Typography>
      {ranges.length === 0 ? (
        <Typography variant="body2" color="text.secondary">None.</Typography>
      ) : (
        <Box sx={{ overflowX: 'auto' }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell sx={{ fontWeight: 700 }}>Label</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Entry</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>CIDR</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {shownRanges.map((r, i) => {
                const range = blockedObject(r);
                const notes = blockedList(range.notes).map(blockedText).join('; ');
                return (
                  <TableRow key={i}>
                    <TableCell sx={{ fontSize: 12.5 }}>{blockedText(range.label) || '—'}</TableCell>
                    <TableCell className="mono" sx={{ fontSize: 12, wordBreak: 'break-all' }}>{blockedText(range.entry)}</TableCell>
                    <TableCell className="mono" sx={{ fontSize: 12, wordBreak: 'break-all' }}>{blockedText(range.cidr)}</TableCell>
                    <TableCell sx={{ fontSize: 12, color: notes ? 'warning.main' : 'text.secondary' }}>{notes || '—'}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Box>
      )}
      {ranges.length > BLOCKED_RANGES_SHOWN && (
        <Button size="small" sx={{ mt: 0.5 }} onClick={() => setAllRanges(!allRanges)}>
          {allRanges ? 'Show fewer' : `Show all ${ranges.length} ranges`}
        </Button>
      )}
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.75 }}>{blockedSourceText(status)}</Typography>

      {problems.length > 0 && (
        <Box sx={{ mt: 1.5 }}>
          <Typography variant="body2" sx={{ fontWeight: 700, color: 'error.main' }}>Problems</Typography>
          <Box component="ul" sx={{ m: 0, mt: 0.5, pl: 2.5 }}>
            {problems.map((p, i) => <Typography key={i} component="li" variant="body2">{blockedText(p)}</Typography>)}
          </Box>
        </Box>
      )}

      <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
        <strong>Log</strong>
        {log.file_name ? <> (<span className="mono">{blockedText(log.file_name)}</span>)</> : null}
        {': '}{blockedCount(rows)} {rows === 1 ? 'row' : 'rows'}, {blockedCount(hits)} {hits === 1 ? 'request' : 'requests'}
        {log.oldest ? <>, oldest <span className="mono" title={relativeTime(log.oldest)}>{blockedText(log.oldest)}</span></> : null}
        {' · '}{blockedFormatBytes(log.size_bytes)} of {blockedFormatBytes(log.max_bytes)}
        {' · '}kept {blockedText(log.retention_days)} {Number(log.retention_days) === 1 ? 'day' : 'days'}
      </Typography>

      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1.5 }}>
        Ranges are set in config.php (ip_allowlist) or the OIDC_IP_ALLOWLIST environment variable; this page cannot change them.
      </Typography>
    </Paper>
  );
}

// One row of the log: an address (an IPv6 /64), a reason and an hour.
function BlockedRequestRow({ entry, onFilterAddress }) {
  const reason = blockedReasonMeta(entry.reason);
  const key = blockedText(entry.address_key);
  const address = blockedText(entry.address);
  const peer = blockedText(entry.peer_address);
  const forwardedFor = blockedText(entry.forwarded_for);
  const firstRequest = blockedText(entry.first_request);
  const lastRequest = blockedText(entry.last_request);
  const userAgent = blockedText(entry.user_agent);
  const small = { fontSize: 11.5, color: 'text.secondary' };
  const chipSx = { height: 20, fontSize: 11, fontWeight: 700 };
  return (
    <TableRow hover>
      <TableCell className="mono" sx={{ whiteSpace: 'nowrap', fontSize: 12 }} title={relativeTime(entry.hour_start)}>
        {blockedText(entry.hour_start)}
      </TableCell>
      <TableCell sx={{ fontSize: 12.5 }}>
        {key && key !== 'unknown' ? (
          <Box component="button" type="button" className="mono" title="Show only this address" onClick={() => onFilterAddress(key)} sx={BLOCKED_ADDRESS_BUTTON_SX}>
            {key}
          </Box>
        ) : (
          <Box className="mono" sx={{ color: 'text.secondary' }}>{key || 'unknown'}</Box>
        )}
        {address && address !== key && <Box className="mono" sx={{ ...small, wordBreak: 'break-all' }}>{address}</Box>}
        {peer && <Box sx={small}>via <span className="mono">{peer}</span></Box>}
        {forwardedFor && (
          <Box className="mono" title={'X-Forwarded-For: ' + forwardedFor} sx={{ ...small, fontSize: 11, maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            XFF: {forwardedFor}
          </Box>
        )}
      </TableCell>
      <TableCell align="right" sx={{ fontWeight: 700, fontSize: 12.5 }}>{blockedCount(entry.hits)}</TableCell>
      <TableCell className="mono" sx={{ fontSize: 11.5, whiteSpace: 'nowrap' }}>
        <Box title={relativeTime(entry.first_seen)}>{blockedText(entry.first_seen)}</Box>
        <Box title={relativeTime(entry.last_seen)} sx={{ color: 'text.secondary' }}>{blockedText(entry.last_seen)}</Box>
      </TableCell>
      <TableCell className="mono" sx={{ fontSize: 11.5, minWidth: 160, maxWidth: 300, wordBreak: 'break-all' }}>
        <Box>{firstRequest || '—'}</Box>
        {lastRequest && lastRequest !== firstRequest && <Box sx={{ color: 'text.secondary' }}>{lastRequest}</Box>}
      </TableCell>
      <TableCell className="mono" sx={{ fontSize: 11.5, maxWidth: 180, wordBreak: 'break-all' }}>{blockedText(entry.host) || '—'}</TableCell>
      <TableCell sx={{ fontSize: 11.5 }}>
        <Box title={userAgent} sx={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{userAgent || '—'}</Box>
      </TableCell>
      <TableCell>
        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
          <Chip size="small" color={reason.color} label={reason.label} sx={chipSx} />
          {!entry.enforced && <Chip size="small" variant="outlined" color="warning" label="Report-only" sx={chipSx} />}
        </Box>
      </TableCell>
    </TableRow>
  );
}

// Deletes the log, or the rows the applied filters cover, after the administrator's current
// password (DELETE /api/ip-allowlist/blocked-requests), so a borrowed session cannot wipe the
// record. The server records it in the admin audit log (ip_allowlist.log_purged).
function PurgeBlockedRequestsDialog({ open, onClose, filters, hasFilters, onDone }) {
  const [scope, setScope] = useState('filtered');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => {
    if (!open) return;
    // The narrower choice is preselected when there is one.
    setScope(hasFilters ? 'filtered' : 'all');
    setPassword('');
    setErr('');
  }, [open]);

  const all = !hasFilters || scope === 'all';
  const summary = Object.entries(filters).map(([k, v]) => `${k}=${v}`).join(', ');

  const submit = () => {
    if (busy || !password) return;
    setBusy(true);
    setErr('');
    const body = all ? { password, all: true } : { ...filters, password };
    api('/api/ip-allowlist/blocked-requests', { method: 'DELETE', body: JSON.stringify(body) })
      .then(r => {
        setPassword('');
        onDone(Number(r && r.deleted) || 0);
      })
      .catch(e => setErr(errText(e, 'Delete failed')))
      .finally(() => setBusy(false));
  };

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.25 }}>
        <Icon name="delete_sweep" size={22} />
        <span>Purge Blocked Requests</span>
      </DialogTitle>
      <DialogContent dividers>
        {err && <Alert severity="error" sx={{ mb: 2 }}>{err}</Alert>}
        <RadioGroup value={all ? 'all' : 'filtered'} onChange={e => setScope(e.target.value)} aria-label="Entries to delete">
          <FormControlLabel value="filtered" disabled={!hasFilters || busy} control={<Radio size="small" />} label="Entries matching the current filters" />
          {hasFilters && (
            <Typography variant="caption" className="mono" color="text.secondary" sx={{ display: 'block', ml: 4, mt: -0.5, mb: 0.5, wordBreak: 'break-all' }}>
              {summary}
            </Typography>
          )}
          <FormControlLabel value="all" disabled={busy} control={<Radio size="small" />} label="All entries" />
        </RadioGroup>
        <TextField
          fullWidth size="small" type="password" label="Current password" value={password}
          onChange={e => setPassword(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') submit(); }}
          autoComplete="current-password" autoFocus sx={{ mt: 2 }}
        />
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          This cannot be undone. The deletion is recorded in the Admin Audit Log.
        </Typography>
      </DialogContent>
      <DialogActions sx={{ px: 3, py: 2 }}>
        <Button onClick={onClose} disabled={busy}>Cancel</Button>
        <Button color="error" variant="contained" onClick={submit} disabled={busy || !password}>Delete</Button>
      </DialogActions>
    </Dialog>
  );
}

function BlockedRequestsPanel({ onNotify }) {
  const [status, setStatus] = useState(null);
  const [statusErr, setStatusErr] = useState('');
  const [entries, setEntries] = useState([]);
  const [total, setTotal] = useState(0);
  const [nextCursor, setNextCursor] = useState(null);
  const [listErr, setListErr] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [draft, setDraft] = useState(BLOCKED_EMPTY_FILTERS);
  const [applied, setApplied] = useState(BLOCKED_EMPTY_FILTERS);
  const [filterErr, setFilterErr] = useState('');
  const [purgeOpen, setPurgeOpen] = useState(false);
  // Answers to superseded requests are dropped: a slow first page must not replace the one for
  // newer filters, and "Load more" must not append rows of the previous filters.
  const statusSeq = React.useRef(0);
  const listSeq = React.useRef(0);

  const loadStatus = () => {
    const seq = ++statusSeq.current;
    api('/api/ip-allowlist')
      .then(r => {
        if (seq !== statusSeq.current) return;
        setStatus(blockedObject(r));
        setStatusErr('');
      })
      .catch(e => {
        if (seq !== statusSeq.current) return;
        setStatus(null);
        setStatusErr(errText(e, 'Failed to load the IP allowlist status'));
      });
  };

  const pageUrl = (filters, cursor) => {
    const q = blockedRequestsQuery(filters);
    q.set('limit', String(BLOCKED_PAGE_SIZE));
    if (cursor) q.set('cursor', cursor);
    return '/api/ip-allowlist/blocked-requests?' + q.toString();
  };

  const loadList = (filters) => {
    const seq = ++listSeq.current;
    setLoadingMore(false);
    api(pageUrl(filters, null))
      .then(r => {
        if (seq !== listSeq.current) return;
        setEntries(blockedEntries(r.entries));
        setNextCursor(blockedCursor(r.next_cursor));
        setTotal(Number(r.total) || 0);
        setListErr('');
        setLoaded(true);
      })
      .catch(e => {
        if (seq !== listSeq.current) return;
        setEntries([]);
        setNextCursor(null);
        setTotal(0);
        setListErr(errText(e, 'Failed to load the blocked requests'));
        setLoaded(true);
      });
  };

  const loadMore = () => {
    if (!nextCursor || loadingMore) return;
    const seq = listSeq.current;
    setLoadingMore(true);
    api(pageUrl(applied, nextCursor))
      .then(r => {
        if (seq !== listSeq.current) return;
        const more = blockedEntries(r.entries);
        setEntries(prev => {
          const seen = new Set(prev.map(x => x.id));
          return prev.concat(more.filter(x => !seen.has(x.id)));
        });
        setNextCursor(blockedCursor(r.next_cursor));
        setTotal(Number(r.total) || 0);
      })
      .catch(e => {
        if (seq === listSeq.current) onNotify(errText(e, 'Failed to load more blocked requests'), 'error');
      })
      .finally(() => {
        if (seq === listSeq.current) setLoadingMore(false);
      });
  };

  const refresh = () => {
    loadStatus();
    loadList(applied);
  };
  useEffect(() => { refresh(); }, []);

  const runFilters = (next) => {
    setFilterErr('');
    setDraft(next);
    setApplied(next);
    loadList(next);
  };

  const apply = (e) => {
    if (e && e.preventDefault) e.preventDefault();
    for (const [key, label] of [['since', 'From'], ['until', 'To']]) {
      if (blockedLocalToIso(draft[key]) === null) {
        setFilterErr(`${label} is not a valid date and time.`);
        return;
      }
    }
    runFilters({ ...draft, ip: draft.ip.trim() });
  };

  const reset = () => runFilters(BLOCKED_EMPTY_FILTERS);

  // An address in the table narrows the rows shown to it (an IPv6 address to its /64).
  const filterAddress = (key) => runFilters({ ...applied, ip: key });

  const purged = (n) => {
    setPurgeOpen(false);
    onNotify(`Deleted ${n} ${n === 1 ? 'entry' : 'entries'}`);
    refresh();
  };

  // The export and a filtered purge cover exactly the rows the applied filters select.
  const purgeFilters = Object.fromEntries(blockedRequestsQuery(applied).entries());
  const hasFilters = Object.keys(purgeFilters).length > 0;
  const csvQuery = blockedRequestsQuery(applied);
  csvQuery.set('format', 'csv');
  const csvHref = absUrl('/api/ip-allowlist/blocked-requests?' + csvQuery.toString());

  return (
    <Box className="fade-in">
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2, mb: 3 }}>
        <Box>
          <Typography variant="h5" sx={{ fontWeight: 800 }}>Blocked Requests</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Requests from addresses outside the IP allowlist. They were answered with an empty 404.
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Button variant="outlined" startIcon={<Icon name="refresh" size={18} />} onClick={refresh}>Refresh</Button>
          <Button variant="outlined" startIcon={<Icon name="download" size={18} />} component="a" href={csvHref} download>
            Export CSV
          </Button>
          <Button variant="outlined" color="error" startIcon={<Icon name="delete_sweep" size={18} />} onClick={() => setPurgeOpen(true)}>
            Purge…
          </Button>
        </Box>
      </Box>

      {statusErr && <Alert severity="error" sx={{ mb: 3 }}>{statusErr}</Alert>}
      {status && <BlockedStatusCard status={status} />}
      {!status && !statusErr && (
        <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
          <Typography variant="body2" color="text.secondary">Loading the IP allowlist status…</Typography>
        </Paper>
      )}

      <Paper variant="outlined" sx={{ p: 3 }}>
        <Box component="form" onSubmit={apply} sx={{ display: 'flex', gap: 1.5, alignItems: 'center', flexWrap: 'wrap', mb: 2 }}>
          <TextField
            size="small" label="IP or CIDR" placeholder="203.0.113.7 or 203.0.113.0/24"
            value={draft.ip} onChange={e => setDraft({ ...draft, ip: e.target.value })}
            InputLabelProps={{ shrink: true }}
            inputProps={{ className: 'mono', spellCheck: false, autoCapitalize: 'off', autoCorrect: 'off' }}
            sx={{ minWidth: 230, flex: 1, maxWidth: 320 }}
          />
          <TextField
            size="small" type="datetime-local" label="From (your local time)"
            value={draft.since} onChange={e => setDraft({ ...draft, since: e.target.value })}
            InputLabelProps={{ shrink: true }} sx={{ minWidth: 210 }}
          />
          <TextField
            size="small" type="datetime-local" label="To (your local time)"
            value={draft.until} onChange={e => setDraft({ ...draft, until: e.target.value })}
            InputLabelProps={{ shrink: true }} sx={{ minWidth: 210 }}
          />
          <TextField
            select size="small" label="Reason" value={draft.reason}
            onChange={e => setDraft({ ...draft, reason: e.target.value })}
            InputLabelProps={{ shrink: true }} SelectProps={{ displayEmpty: true }} sx={{ minWidth: 190 }}
          >
            <MenuItem value="">All</MenuItem>
            {Object.keys(BLOCKED_REASON_META).map(k => (
              <MenuItem key={k} value={k}>{BLOCKED_REASON_META[k].label}</MenuItem>
            ))}
            <MenuItem value="report_only">Report-only</MenuItem>
          </TextField>
          <Button type="submit" variant="contained">Apply</Button>
          <Button onClick={reset}>Reset</Button>
        </Box>
        {filterErr && <Alert severity="error" sx={{ mb: 2 }}>{filterErr}</Alert>}
        {listErr && <Alert severity="error" sx={{ mb: 2 }}>{listErr}</Alert>}

        {!listErr && entries.length === 0 && (
          <Box sx={{ py: 5, textAlign: 'center' }}>
            <Icon name="block" size={36} style={{ opacity: 0.35 }} />
            <Typography color="text.secondary" sx={{ mt: 1 }}>
              {loaded ? 'No blocked requests for these filters.' : 'Loading…'}
            </Typography>
          </Box>
        )}

        {entries.length > 0 && (
          <Box sx={{ overflowX: 'auto' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Hour (UTC)</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Address</TableCell>
                  <TableCell sx={{ fontWeight: 700 }} align="right">Hits</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>First / last seen</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>First / last request</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Host</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>User agent</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Reason</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {entries.map((r, i) => (
                  <BlockedRequestRow key={blockedText(r.id) || 'row-' + i} entry={r} onFilterAddress={filterAddress} />
                ))}
              </TableBody>
            </Table>
          </Box>
        )}

        {entries.length > 0 && (
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 1.5, flexWrap: 'wrap', mt: 2 }}>
            <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
              Showing {blockedCount(entries.length)} of {blockedCount(total)}
            </Typography>
            {nextCursor && (
              <Button size="small" variant="outlined" onClick={loadMore} disabled={loadingMore}>
                {loadingMore ? 'Loading…' : 'Load more'}
              </Button>
            )}
          </Box>
        )}
      </Paper>

      <PurgeBlockedRequestsDialog
        open={purgeOpen}
        onClose={() => setPurgeOpen(false)}
        filters={purgeFilters}
        hasFilters={hasFilters}
        onDone={purged}
      />
    </Box>
  );
}

/* ==================== MODERN ADMIN SIGN-IN SCREEN ==================== */
function Login({ onLogin, mode, onToggleMode }) {
  const [username, setU] = useState('');
  const [password, setP] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');
  // Second step (G2a-07): set when POST /api/login answered 401 with mfa_required. It holds the
  // server's prompt and, while a new authenticator app must be set up first
  // (mfa_enrollment_required), the secret to add to the app ({ secret, otpauth_uri, expires_in }).
  const [mfa, setMfa] = useState(null);
  const [otp, setOtp] = useState('');
  const otpCode = otp.replace(/\s+/g, '');

  const backToPassword = () => { setMfa(null); setOtp(''); setErr(''); };

  // restart: sign in again without a code, which gets a new secret while setting up an app.
  const submit = (e, restart = false) => {
    if (e && e.preventDefault) e.preventDefault();
    setErr('');
    setLoading(true);
    const body = { username, password };
    const sentCode = !!mfa && !restart;
    if (sentCode) body.otp = otpCode;
    api('/api/login', { method: 'POST', body: JSON.stringify(body) })
      .then(u => onLogin(u))
      .catch(e2 => {
        const msg = errText(e2, 'Authentication failed');
        if (e2 && e2.status === 401 && e2.mfa_required) {
          const totp = e2.totp && typeof e2.totp === 'object' && typeof e2.totp.secret === 'string' && e2.totp.secret
            ? e2.totp
            : null;
          setMfa(prev => ({
            enrolling: !!e2.mfa_enrollment_required,
            // A wrong code during setup comes back without a secret: the one shown stays valid
            // until it expires, and "Get a new secret" replaces it.
            totp: totp || (e2.mfa_enrollment_required && prev ? prev.totp : null),
            prompt: sentCode ? (prev ? prev.prompt : '') : msg,
          }));
          setOtp('');
          if (sentCode) setErr(msg);
        } else {
          // The password itself was refused (changed meanwhile, say): start over.
          if (e2 && e2.status === 401 && mfa) setMfa(null);
          setErr(msg);
        }
      })
      .finally(() => setLoading(false));
  };

  return (
    <Box sx={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', p: 2.5,
      position: 'relative', overflow: 'hidden',
      background: mode === 'dark'
        ? 'radial-gradient(circle at 15% 15%, rgba(79, 70, 229, 0.22) 0%, transparent 45%), radial-gradient(circle at 85% 80%, rgba(236, 72, 153, 0.14) 0%, transparent 45%), #090d16'
        : 'radial-gradient(circle at 15% 15%, rgba(79, 70, 229, 0.12) 0%, transparent 45%), radial-gradient(circle at 85% 80%, rgba(14, 165, 233, 0.12) 0%, transparent 45%), #f6f8fb'
    }}>
      <Tooltip title={`Switch to ${mode === 'dark' ? 'Light' : 'Dark'} Mode`}>
        <IconButton onClick={onToggleMode} sx={{ position: 'fixed', top: 20, right: 20, border: '1px solid', borderColor: 'divider', bgcolor: 'background.paper' }}>
          <Icon name={mode === 'dark' ? 'light_mode' : 'dark_mode'} size={20} />
        </IconButton>
      </Tooltip>

      <Paper
        component="form"
        onSubmit={submit}
        variant="outlined"
        className="fade-in"
        sx={{
          width: '100%', maxWidth: 430, p: { xs: 3.5, sm: 4.5 }, borderRadius: 4,
          boxShadow: mode === 'dark'
            ? '0 24px 60px -12px rgba(0, 0, 0, 0.65)'
            : '0 24px 60px -15px rgba(15, 23, 42, 0.12)'
        }}
      >
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', mb: 3.5 }}>
          <BrandMark size={48} />
          <Typography variant="h5" sx={{ mt: 2, fontWeight: 800, letterSpacing: '-0.02em' }}>
            Identity Cloud Console
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Sign in with your administrator credentials
          </Typography>
          {/* Admin sign-in uses a password and, when set up, an authenticator app; no Touch ID (G2a-07). */}
          <Box sx={{ display: 'flex', gap: 0.75, mt: 1.75, flexWrap: 'wrap', justifyContent: 'center' }}>
            <Chip size="small" variant="outlined" label="SAML 2.0 IdP" sx={{ fontSize: 11, height: 22 }} />
            <Chip size="small" variant="outlined" label="OIDC 1.0 + PKCE" sx={{ fontSize: 11, height: 22 }} />
          </Box>
        </Box>

        <TextField
          fullWidth label="Admin Username" value={username} onChange={e => setU(e.target.value)}
          sx={{ mb: 2 }} autoFocus required disabled={!!mfa} autoComplete="username"
          InputProps={{
            startAdornment: <InputAdornment position="start"><Icon name="person" size={19} style={{ opacity: 0.6 }} /></InputAdornment>
          }}
        />
        <TextField
          fullWidth label="Password" type={showPw ? 'text' : 'password'} value={password} onChange={e => setP(e.target.value)}
          required disabled={!!mfa} autoComplete="current-password"
          InputProps={{
            startAdornment: <InputAdornment position="start"><Icon name="lock" size={19} style={{ opacity: 0.6 }} /></InputAdornment>,
            endAdornment: (
              <InputAdornment position="end">
                <IconButton size="small" onClick={() => setShowPw(!showPw)} edge="end" disabled={!!mfa}>
                  <Icon name={showPw ? 'visibility_off' : 'visibility'} size={19} />
                </IconButton>
              </InputAdornment>
            )
          }}
        />

        {mfa && (
          <Box sx={{ mt: 2.5, display: 'flex', flexDirection: 'column', gap: 1.5 }}>
            {mfa.prompt && <Alert severity="info">{mfa.prompt}</Alert>}
            {mfa.enrolling && mfa.totp && <TotpSetupInfo totp={mfa.totp} />}
            <TextField
              fullWidth label="Authentication code" value={otp} onChange={e => setOtp(e.target.value)}
              placeholder="123456" autoFocus required
              inputProps={{ inputMode: 'numeric', autoComplete: 'one-time-code', maxLength: 8, className: 'mono' }}
              helperText="The 6-digit code your authenticator app shows for this account"
              InputProps={{
                startAdornment: <InputAdornment position="start"><Icon name="phonelink_lock" size={19} style={{ opacity: 0.6 }} /></InputAdornment>
              }}
            />
          </Box>
        )}

        {err && <Alert sx={{ mt: 2 }} severity="error">{err}</Alert>}

        <Button
          type="submit"
          variant="contained"
          size="large"
          fullWidth
          disabled={loading || (!!mfa && !/^\d{6}$/.test(otpCode))}
          sx={{
            mt: 3, py: 1.35, fontWeight: 700,
            background: 'linear-gradient(135deg, #4f46e5 0%, #6366f1 100%)',
            '&:hover': { background: 'linear-gradient(135deg, #4338ca 0%, #4f46e5 100%)' }
          }}
        >
          {loading ? 'Signing in…' : (mfa ? 'Verify Code and Sign In' : 'Sign In to Console')}
        </Button>
        {mfa && (
          <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 1, mt: 1.5, flexWrap: 'wrap' }}>
            <Button size="small" startIcon={<Icon name="arrow_back" size={16} />} onClick={backToPassword} disabled={loading}>
              Back
            </Button>
            {mfa.enrolling && (
              <Button size="small" startIcon={<Icon name="autorenew" size={16} />} onClick={() => submit(null, true)} disabled={loading}>
                Get a new secret
              </Button>
            )}
          </Box>
        )}
      </Paper>
    </Box>
  );
}

/* ==================== MAIN SAAS SIDEBAR + WORKSPACE DASHBOARD ==================== */
const SIDEBAR_WIDTH = 264;

function Dashboard({ me, onLogout, mode, onToggleMode, notify }) {
  const isMobile = useMediaQuery('(max-width:960px)');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [navSection, setNavSection] = useState('providers'); // 'providers' | 'directory' | 'api' | 'audit' | 'blocked' | 'account'
  const [providers, setProviders] = useState([]);
  const [activeProviderId, setActiveProviderId] = useState(null);
  const [openCreate, setOpenCreate] = useState(false);
  const [jwtProv, setJwtProv] = useState(null);
  const [delProv, setDelProv] = useState(null);

  const reloadProviders = () => api('/api/providers').then(r => {
    setProviders(r.providers || []);
  }).catch(e => notify(errText(e, 'Failed to load providers'), 'error'));

  useEffect(() => { reloadProviders(); }, []);

  const selectedProvider = useMemo(
    () => providers.find(p => p.id === activeProviderId) || null,
    [providers, activeProviderId]
  );

  const deleteProvider = (prov) => {
    api('/api/providers/' + prov.id, { method: 'DELETE' })
      .then(() => {
        notify('Provider deleted');
        if (activeProviderId === prov.id) setActiveProviderId(null);
        setDelProv(null);
        reloadProviders();
      })
      .catch(e => notify(errText(e, 'Delete failed'), 'error'));
  };

  const signOut = () => {
    Promise.resolve()
      .then(onLogout)
      .catch(e => notify('Sign-out failed: ' + errText(e, 'request failed') + '. Reload the page to check your session.', 'error'));
  };

  const totalSamlApps = providers.reduce((s, p) => s + (p.saml_app_count || 0), 0);
  const totalOidcApps = providers.reduce((s, p) => s + (p.oidc_app_count || 0), 0);

  const navItemSx = (active) => ({
    display: 'flex', alignItems: 'center', gap: 1.5, width: '100%',
    px: 1.75, py: 1.15, borderRadius: 2.5, cursor: 'pointer', border: 'none',
    textAlign: 'left', font: 'inherit', fontSize: 14, fontWeight: active ? 700 : 500,
    bgcolor: active ? (mode === 'dark' ? 'rgba(99, 102, 241, 0.16)' : 'rgba(79, 70, 229, 0.09)') : 'transparent',
    color: active ? 'primary.main' : 'text.secondary',
    transition: 'all 0.14s ease',
    '&:hover': {
      bgcolor: active
        ? (mode === 'dark' ? 'rgba(99, 102, 241, 0.22)' : 'rgba(79, 70, 229, 0.13)')
        : 'action.hover',
      color: active ? 'primary.main' : 'text.primary'
    }
  });

  const sidebarContent = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', p: 2 }}>
      {/* Brand */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, px: 1, py: 1, mb: 2 }}>
        <BrandMark size={36} />
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 800, lineHeight: 1.15, letterSpacing: '-0.02em' }}>
            Identity Cloud
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
            SAML 2.0 • OIDC • Touch ID
          </Typography>
        </Box>
      </Box>

      {/* Main Nav */}
      <Typography variant="caption" color="text.secondary" sx={{ px: 1.5, mb: 0.75, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        Platform
      </Typography>
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
        <Box component="button" sx={navItemSx(navSection === 'providers' && !selectedProvider)} onClick={() => { setNavSection('providers'); setActiveProviderId(null); setMobileOpen(false); }}>
          <Icon name="dns" size={20} />
          <span style={{ flex: 1 }}>Identity Providers</span>
          <Chip size="small" label={providers.length} sx={{ height: 20, fontSize: 11, fontWeight: 700 }} />
        </Box>
        <Box component="button" sx={navItemSx(navSection === 'directory')} onClick={() => { setNavSection('directory'); setMobileOpen(false); }}>
          <Icon name="fingerprint" size={20} />
          <span style={{ flex: 1 }}>Directory &amp; Touch ID</span>
        </Box>
        <Box component="button" sx={navItemSx(navSection === 'api')} onClick={() => { setNavSection('api'); setMobileOpen(false); }}>
          <Icon name="api" size={20} />
          <span style={{ flex: 1 }}>API Clients &amp; OpenAPI</span>
        </Box>
        <Box component="button" sx={navItemSx(navSection === 'audit')} onClick={() => { setNavSection('audit'); setMobileOpen(false); }}>
          <Icon name="policy" size={20} />
          <span style={{ flex: 1 }}>Admin Audit Log</span>
        </Box>
        {/* IP allowlist status and refused requests: hidden for administrators outside
            ip_allowlist_admins (/api/me can_view_blocked_requests); the server checks again. */}
        {me.can_view_blocked_requests !== false && (
          <Box component="button" sx={navItemSx(navSection === 'blocked')} onClick={() => { setNavSection('blocked'); setMobileOpen(false); }}>
            <Icon name="block" size={20} />
            <span style={{ flex: 1 }}>Blocked Requests</span>
          </Box>
        )}
        <Box component="button" sx={navItemSx(navSection === 'account')} onClick={() => { setNavSection('account'); setMobileOpen(false); }}>
          <Icon name="phonelink_lock" size={20} />
          <span style={{ flex: 1 }}>Account Security</span>
        </Box>
      </Box>

      {/* Quick Tenant Jump List */}
      <Box sx={{ mt: 3, flex: 1, overflowY: 'auto' }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', px: 1.5, mb: 0.75 }}>
          <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Tenants
          </Typography>
          <Tooltip title="Create Identity Provider">
            <IconButton size="small" onClick={() => setOpenCreate(true)} sx={{ p: 0.25 }}>
              <Icon name="add" size={17} />
            </IconButton>
          </Tooltip>
        </Box>
        {providers.length === 0 ? (
          <Typography variant="caption" color="text.secondary" sx={{ px: 1.5, display: 'block' }}>
            No providers created yet
          </Typography>
        ) : (
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.35 }}>
            {providers.map(p => {
              const isSelected = navSection === 'providers' && activeProviderId === p.id;
              return (
                <Box
                  key={p.id}
                  component="button"
                  sx={navItemSx(isSelected)}
                  onClick={() => { setNavSection('providers'); setActiveProviderId(p.id); setMobileOpen(false); }}
                >
                  <Box sx={{
                    width: 8, height: 8, borderRadius: '50%',
                    bgcolor: isSelected ? 'primary.main' : 'success.main', flexShrink: 0
                  }} />
                  <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {p.friendly}
                  </span>
                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: 11 }}>
                    {(p.saml_app_count || 0) + (p.oidc_app_count || 0)}
                  </Typography>
                </Box>
              );
            })}
          </Box>
        )}
      </Box>

      <Divider sx={{ my: 1.5 }} />

      {/* Admin Footer */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 1, px: 0.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25, minWidth: 0 }}>
          <Avatar sx={{ width: 32, height: 32, fontSize: 13, fontWeight: 800, background: avatarGradient(me.user || 'A') }}>
            {initialsOf(me.user || 'A')}
          </Avatar>
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="body2" sx={{ fontWeight: 700, lineHeight: 1.2, overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {me.user}
            </Typography>
            <Typography variant="caption" color="text.secondary">Admin</Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Tooltip title={`Switch to ${mode === 'dark' ? 'Light' : 'Dark'} Mode`}>
            <IconButton size="small" onClick={onToggleMode}>
              <Icon name={mode === 'dark' ? 'light_mode' : 'dark_mode'} size={19} />
            </IconButton>
          </Tooltip>
          <Tooltip title="Sign Out">
            <IconButton size="small" color="error" onClick={signOut}>
              <Icon name="logout" size={19} />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      {/* Sidebar */}
      {isMobile ? (
        <Drawer open={mobileOpen} onClose={() => setMobileOpen(false)} PaperProps={{ sx: { width: SIDEBAR_WIDTH } }}>
          {sidebarContent}
        </Drawer>
      ) : (
        <Box component="aside" sx={{
          width: SIDEBAR_WIDTH, flexShrink: 0, borderRight: '1px solid', borderColor: 'divider',
          bgcolor: 'background.paper', position: 'sticky', top: 0, height: '100vh'
        }}>
          {sidebarContent}
        </Box>
      )}

      {/* Main Content Area */}
      <Box component="main" sx={{ flex: 1, minWidth: 0, pb: 6 }}>
        {isMobile && (
          <Box sx={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            px: 2, py: 1.5, borderBottom: '1px solid', borderColor: 'divider', bgcolor: 'background.paper',
            position: 'sticky', top: 0, zIndex: 20
          }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25 }}>
              <IconButton size="small" onClick={() => setMobileOpen(true)}><Icon name="menu" /></IconButton>
              <BrandMark size={28} />
              <Typography variant="subtitle2" sx={{ fontWeight: 800 }}>Identity Cloud</Typography>
            </Box>
            <IconButton size="small" onClick={onToggleMode}>
              <Icon name={mode === 'dark' ? 'light_mode' : 'dark_mode'} size={19} />
            </IconButton>
          </Box>
        )}

        <Box sx={{ maxWidth: 1180, mx: 'auto', px: { xs: 2, sm: 4 }, pt: { xs: 3, sm: 4 } }}>
          {/* VIEW 1: PROVIDERS OVERVIEW OR FULL-PAGE PROVIDER WORKSPACE */}
          {navSection === 'providers' && selectedProvider && (
            <ProviderWorkspaceView
              provider={selectedProvider}
              onBack={() => setActiveProviderId(null)}
              refreshProviders={reloadProviders}
              onOpenJwt={setJwtProv}
              onNotify={notify}
            />
          )}

          {navSection === 'providers' && !selectedProvider && (
            <Box className="fade-in">
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2, mb: 3 }}>
                <Box>
                  <Typography variant="h5" sx={{ fontWeight: 800 }}>Identity Providers</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                    Multi-tenant OIDC 1.0 &amp; SAML 2.0 Identity Providers with live hosted metadata URLs, Touch ID policies, and End-User Portals.
                  </Typography>
                </Box>
                <Button variant="contained" startIcon={<Icon name="add" size={19} />} onClick={() => setOpenCreate(true)}>
                  Create Provider
                </Button>
              </Box>

              {/* KPI Strip */}
              <Grid container spacing={2} sx={{ mb: 3.5 }}>
                <Grid item xs={12} sm={4}>
                  <StatCard label="Active Tenants" value={providers.length} subtitle="Isolated Issuer & Entity IDs" icon="dns" gradient="linear-gradient(135deg, #4f46e5, #6366f1)" />
                </Grid>
                <Grid item xs={12} sm={4}>
                  <StatCard label="SAML 2.0 Apps" value={totalSamlApps} subtitle="SP- & IdP-Initiated SSO" icon="hub" gradient="linear-gradient(135deg, #f59e0b, #ea580c)" />
                </Grid>
                <Grid item xs={12} sm={4}>
                  <StatCard label="OIDC 1.0 Clients" value={totalOidcApps} subtitle="Auth Code + S256 PKCE" icon="integration_instructions" gradient="linear-gradient(135deg, #0ea5e9, #2563eb)" />
                </Grid>
              </Grid>

              {/* Provider Cards */}
              {providers.length === 0 ? (
                <Paper variant="outlined" sx={{ p: 6, textAlign: 'center' }}>
                  <BrandMark size={48} />
                  <Typography variant="h6" sx={{ fontWeight: 800, mt: 2 }}>Create your first Identity Provider</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 460, mx: 'auto', mt: 0.75, mb: 3 }}>
                    Spin up an Okta-style testing Identity Provider in seconds with live SAML 2.0 Metadata URLs, OpenID Connect Discovery, and macOS Touch ID authentication.
                  </Typography>
                  <Button variant="contained" size="large" startIcon={<Icon name="add" size={19} />} onClick={() => setOpenCreate(true)}>
                    Create Identity Provider
                  </Button>
                </Paper>
              ) : (
                <Grid container spacing={2.5}>
                  {providers.map(p => (
                    <Grid item xs={12} key={p.id}>
                      <Paper
                        variant="outlined"
                        sx={{
                          p: 3, transition: 'border-color 0.16s ease, transform 0.16s ease',
                          '&:hover': { borderColor: 'primary.main' }
                        }}
                      >
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2, mb: 2 }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.75 }}>
                            <Box
                              onClick={() => setActiveProviderId(p.id)}
                              sx={{
                                width: 44, height: 44, borderRadius: 3, background: avatarGradient(p.friendly),
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                                color: '#fff', fontWeight: 800, fontSize: 16, cursor: 'pointer'
                              }}
                            >
                              {initialsOf(p.friendly)}
                            </Box>
                            <Box>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                                <Typography
                                  variant="h6"
                                  onClick={() => setActiveProviderId(p.id)}
                                  sx={{ fontSize: 17.5, fontWeight: 800, cursor: 'pointer', '&:hover': { color: 'primary.main' } }}
                                >
                                  {p.friendly}
                                </Typography>
                                <Chip size="small" label={`${p.saml_app_count || 0} SAML`} sx={{ fontWeight: 600 }} />
                                <Chip size="small" label={`${p.oidc_app_count || 0} OIDC`} sx={{ fontWeight: 600 }} />
                                <Chip size="small" label={`${(p.scim_connector_count || 0) + (p.scim_token_count || 0)} SCIM`} sx={{ fontWeight: 600 }} />
                                <PolicyBadge policy={p.default_auth_policy} />
                              </Box>
                              <Typography variant="caption" color="text.secondary">
                                Signing: <code>{p.alg || 'RS256'}</code> ({p.key_count || 1} JWKS key{(p.key_count || 1) === 1 ? '' : 's'})
                                {p.last_issued_at ? ` • Last active ${relativeTime(p.last_issued_at)}` : ''}
                              </Typography>
                            </Box>
                          </Box>

                          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                            <Button variant="contained" startIcon={<Icon name="settings_applications" size={18} />} onClick={() => setActiveProviderId(p.id)}>
                              Open Workspace
                            </Button>
                            <Button size="small" variant="outlined" startIcon={<Icon name="apps" size={17} />} component="a" href={p.portal_url} target="_blank">
                              Portal
                            </Button>
                            <Button size="small" variant="outlined" startIcon={<Icon name="download" size={17} />} component="a" href={p.saml_metadata_download} target="_blank">
                              SAML XML
                            </Button>
                            <Button size="small" variant="outlined" startIcon={<Icon name="token" size={17} />} onClick={() => setJwtProv(p)}>
                              Mint JWT
                            </Button>
                            <Tooltip title="Delete Provider">
                              <IconButton size="small" color="error" onClick={() => setDelProv(p)}>
                                <Icon name="delete_outline" size={19} />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </Box>

                        <Grid container spacing={1}>
                          <Grid item xs={12} md={4}>
                            <CopyEndpointRow label="SAML Metadata URL" url={p.saml_metadata} downloadUrl={p.saml_metadata_download} />
                          </Grid>
                          <Grid item xs={12} md={4}>
                            <CopyEndpointRow label="OIDC Discovery" url={p.discovery} />
                          </Grid>
                          <Grid item xs={12} md={4}>
                            <CopyEndpointRow label="SCIM 2.0 Base URL" url={p.scim_base_url || `${p.issuer}/scim/v2`} openable={false} />
                          </Grid>
                        </Grid>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              )}
            </Box>
          )}

          {/* VIEW 2: SHARED DIRECTORY & TOUCH ID */}
          {navSection === 'directory' && <DirectoryPanel onNotify={notify} />}

          {/* VIEW 3: DEVELOPER API & TLS CERTIFICATES */}
          {navSection === 'api' && <DeveloperApiPanel me={me} providers={providers} onOpenJwt={setJwtProv} onNotify={notify} />}

          {/* VIEW 4: ADMIN AUDIT LOG (G1a-01) */}
          {navSection === 'audit' && <AdminAuditLogPanel onNotify={notify} />}

          {/* VIEW 4b: IP ALLOWLIST & BLOCKED REQUESTS (loaded only while it is open) */}
          {navSection === 'blocked' && <BlockedRequestsPanel onNotify={notify} />}

          {/* VIEW 5: ACCOUNT SECURITY: AUTHENTICATOR APP (G2a-07) */}
          {navSection === 'account' && <AccountSecurityPanel me={me} onNotify={notify} />}
        </Box>
      </Box>

      {/* Global Dialogs */}
      <CreateProviderDialog
        open={openCreate}
        onClose={() => setOpenCreate(false)}
        onCreated={(created) => {
          reloadProviders();
          notify('Identity Provider created');
          if (created?.id) setActiveProviderId(created.id);
        }}
        existingNames={providers.map(p => p.friendly)}
        me={me}
      />
      <GetJwtDialog open={!!jwtProv} onClose={() => setJwtProv(null)} provider={jwtProv} apiKey={me.apiKey} />

      <Dialog open={!!delProv} onClose={() => setDelProv(null)} maxWidth="xs" fullWidth>
        <DialogTitle>Delete Identity Provider?</DialogTitle>
        <DialogContent dividers>
          <Typography variant="body2">
            Permanently delete <strong>{delProv?.friendly}</strong> along with all of its SAML 2.0 applications, OIDC clients, and signing certificates?
          </Typography>
        </DialogContent>
        <DialogActions sx={{ px: 3, py: 2 }}>
          <Button onClick={() => setDelProv(null)}>Cancel</Button>
          <Button color="error" variant="contained" onClick={() => deleteProvider(delProv)}>Delete Tenant</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function Shell() {
  const getInitialMode = () => {
    try {
      const saved = localStorage.getItem('idp_ui_theme');
      if (saved === 'light' || saved === 'dark') return saved;
    } catch {}
    return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  };

  const [mode, setMode] = useState(getInitialMode);
  const toggleMode = () => {
    setMode(prev => {
      const next = prev === 'dark' ? 'light' : 'dark';
      try { localStorage.setItem('idp_ui_theme', next); } catch {}
      return next;
    });
  };

  const theme = useMemo(() => createTheme({
    palette: {
      mode,
      primary: { main: mode === 'dark' ? '#818cf8' : '#4f46e5' },
      secondary: { main: mode === 'dark' ? '#f472b6' : '#db2777' },
      success: { main: mode === 'dark' ? '#34d399' : '#059669' },
      background: {
        default: mode === 'dark' ? '#090d16' : '#f6f8fb',
        paper: mode === 'dark' ? '#101726' : '#ffffff',
      },
      divider: mode === 'dark' ? 'rgba(148, 163, 184, 0.14)' : '#e5e9f2',
    },
    shape: { borderRadius: 12 },
    typography: {
      fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
      h4: { fontFamily: "'Plus Jakarta Sans', 'Inter', sans-serif", letterSpacing: '-0.025em' },
      h5: { fontFamily: "'Plus Jakarta Sans', 'Inter', sans-serif", letterSpacing: '-0.02em' },
      h6: { fontFamily: "'Plus Jakarta Sans', 'Inter', sans-serif", letterSpacing: '-0.015em' },
      button: { textTransform: 'none', fontWeight: 600 },
    },
    components: {
      MuiButton: {
        defaultProps: { disableElevation: true },
        styleOverrides: {
          root: { borderRadius: 10, paddingLeft: 16, paddingRight: 16 },
          sizeSmall: { borderRadius: 8, paddingLeft: 12, paddingRight: 12 },
        },
      },
      MuiPaper: {
        styleOverrides: {
          root: { backgroundImage: 'none' },
          outlined: {
            borderRadius: 16,
            boxShadow: mode === 'dark'
              ? '0 1px 2px rgba(0, 0, 0, 0.3)'
              : '0 1px 3px rgba(15, 23, 42, 0.03), 0 8px 24px -14px rgba(15, 23, 42, 0.06)',
          },
        },
      },
      MuiDialog: {
        styleOverrides: {
          paper: {
            borderRadius: 18,
            border: mode === 'dark' ? '1px solid rgba(148, 163, 184, 0.16)' : '1px solid #e5e9f2',
          },
        },
      },
      MuiOutlinedInput: {
        styleOverrides: {
          root: { borderRadius: 10 },
        },
      },
      MuiChip: {
        styleOverrides: {
          root: { borderRadius: 8 },
        },
      },
      MuiTab: {
        styleOverrides: {
          root: { textTransform: 'none', fontWeight: 600 },
        },
      },
    },
  }), [mode]);

  const [me, setMe] = useState({ user: null, apiKey: null });
  // Every change of the signed-in admin goes through here, so api() knows which account the
  // console shows and never replays a request for another one.
  const applyMe = (body) => {
    const next = body && typeof body === 'object' && !Array.isArray(body) ? body : { user: null, apiKey: null };
    consoleUser = next.user || null;
    setMe(next);
  };
  const refreshMe = () => api('/api/me').then(applyMe).catch(() => applyMe(null));
  useEffect(() => { refreshMe(); }, []);

  // One toast for the whole console, with the severity of the outcome (S13-08).
  const [snack, setSnack] = useState(null);
  const notify = (message, severity = 'success') => {
    setSnack({ message: String(message || ''), severity, open: true, at: Date.now() });
  };
  const closeSnack = (_, reason) => {
    if (reason === 'clickaway') return;
    setSnack(s => (s ? { ...s, open: false } : s));
  };

  useEffect(() => {
    // Toasts from outside React (the unhandled-rejection backstop).
    const onNotifyEvent = (ev) => notify(ev.detail && ev.detail.message, (ev.detail && ev.detail.severity) || 'error');
    // api() saw a 401 and /api/me confirmed the session is gone: back to the login screen.
    const onSessionExpired = () => {
      applyMe(null);
      notify('Your session has expired. Please sign in again.', 'warning');
    };
    // api() found the session signed in as another admin (in another tab): show that account
    // instead of acting for it under the previous one.
    const onSessionSwitched = (ev) => {
      const body = ev.detail || {};
      if (!body.user) {
        onSessionExpired();
        return;
      }
      applyMe(body);
      notify(`This browser is now signed in as ${body.user}. The console switched to that account.`, 'warning');
    };
    window.addEventListener('idp:notify', onNotifyEvent);
    window.addEventListener('idp:session-expired', onSessionExpired);
    window.addEventListener('idp:session-switched', onSessionSwitched);
    return () => {
      window.removeEventListener('idp:notify', onNotifyEvent);
      window.removeEventListener('idp:session-expired', onSessionExpired);
      window.removeEventListener('idp:session-switched', onSessionSwitched);
    };
  }, []);

  // Back on an idle tab: check the session (and refresh the CSRF token) before the admin acts,
  // so an expired console shows the login screen instead of failing on the next click.
  useEffect(() => {
    if (!me.user) return undefined;
    const onVisible = () => {
      if (document.visibilityState !== 'visible') return;
      apiFetch('/api/me').then(res => {
        if (!res.ok || !res.body) return;
        if (!res.body.user) window.dispatchEvent(new CustomEvent('idp:session-expired'));
        else if (res.body.user !== me.user) applyMe(res.body); // another admin signed in in this browser
      }).catch(() => {});
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => document.removeEventListener('visibilitychange', onVisible);
  }, [me.user]);

  // A stale CSRF token is refreshed and retried inside api(); any other failure is reported
  // by the caller instead of leaving the admin on a live session (S13-08).
  const logout = () => api('/api/logout', { method: 'POST' }).then(() => location.reload());

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {me.user
        ? <Dashboard key={me.user} me={me} onLogout={logout} mode={mode} onToggleMode={toggleMode} notify={notify} />
        : <Login onLogin={refreshMe} mode={mode} onToggleMode={toggleMode} />}
      <Snackbar
        key={snack ? snack.at : 0}
        open={!!(snack && snack.open)}
        autoHideDuration={snack && snack.severity === 'success' ? 2800 : 8000}
        onClose={closeSnack}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity={(snack && snack.severity) || 'success'} variant="filled" onClose={() => closeSnack(null, 'close')} sx={{ borderRadius: 2.5, fontWeight: 600, maxWidth: 560 }}>
          {snack ? snack.message : ''}
        </Alert>
      </Snackbar>
    </ThemeProvider>
  );
}

try {
  ReactDOM.createRoot(document.getElementById('app')).render(<Shell />);
} catch (e) {
  showDiagnostic('Render error: ' + (e && e.message ? e.message : e));
}
</script>
<script nonce="<?= $nonceAttr ?>">
(function () {
  // Scripts the server did not load because they have no integrity value (S14-05).
  var withheld = <?= $withheldJs ?>;
  if (withheld.length) {
    showDiagnostic('The console cannot start. Its libraries were not loaded because these have no ' +
      'Subresource Integrity value (without one, a changed CDN file would run with your session): ' +
      withheld.join(', ') + '. An administrator must add their sha384 values to admin_spa_script_assets() ' +
      'in src/admin_spa.php, or set OIDC_ALLOW_UNVERIFIED_CDN_ASSETS (allow_unverified_cdn_assets in ' +
      'config.php) to load them unchecked.');
    return;
  }
  if (!window.React || !window.ReactDOM || !window.MaterialUI || !window.Babel) {
    showDiagnostic('The console libraries could not be loaded (network error, blocked CDN or failed integrity check). Reload the page.');
    return;
  }
  var source = document.getElementById('admin-console-src');
  var compiled;
  try {
    compiled = window.Babel.transform(source ? source.textContent : '', {
      presets: ['env', 'react'],
      filename: 'admin-console.jsx'
    }).code;
  } catch (e) {
    showDiagnostic('Console compile error: ' + (e && e.message ? e.message : e));
    return;
  }
  // Inline scripts run only with this response's nonce: no 'unsafe-inline' or 'unsafe-eval'.
  // An inserted inline script runs during appendChild(), so the flag its first statement sets
  // shows right away whether the browser let it run. The flag goes after a "use strict"
  // directive, so the code keeps running in strict mode.
  var prologue = /^\s*(["'])use strict\1;?/.exec(compiled);
  var head = prologue ? prologue[0] : '';
  var el = document.createElement('script');
  el.nonce = <?= $nonceJs ?>;
  el.text = head + '\nwindow.__ADMIN_CONSOLE_STARTED__ = true;\n' + compiled.slice(head.length);
  document.body.appendChild(el);
  if (!window.__ADMIN_CONSOLE_STARTED__) {
    var diag = document.getElementById('diagnostics');
    if (!diag || !diag.textContent) {
      showDiagnostic('The console script did not run: the browser blocked it (Content-Security-Policy). Reload the page. If this keeps happening, check for a proxy or browser extension that rewrites the page.');
    }
  }
})();
</script>
</body>
</html>
<?php exit();
}
