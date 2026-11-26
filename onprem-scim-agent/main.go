package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	AgentVersion       = "1.1.0"
	DefaultServiceName = "IdentityCloudScimAgent"
	DefaultDisplayName = "Identity Cloud On-Premises SCIM 2.0 Proxy Agent"
	DefaultDescription = "Outbound-only HTTPS relay agent that receives SCIM 2.0 provisioning operations from Identity Cloud and applies them to an internal on-premises SCIM application."

	// MaxResponseBytes caps the local SCIM response body relayed per job (body_raw).
	MaxResponseBytes = 512 * 1024
	// MaxPollResponseBytes caps one cloud poll response (a batch of jobs).
	MaxPollResponseBytes = 8 * 1024 * 1024
	// MaxEndpointPathBytes caps an IdP-supplied endpoint_path.
	MaxEndpointPathBytes = 8192
	// MaxLogFieldChars caps every remote-supplied value written to the log.
	MaxLogFieldChars = 256
	// MaxCloudErrorChars caps cloud error bodies and job errors in messages, logs
	// and relayed job results.
	MaxCloudErrorChars = 512
	// MaxResponseHeaderBytes caps the response headers read from the IdP and
	// from the local SCIM application (net/http allows 10 MB by default).
	MaxResponseHeaderBytes = 64 * 1024
	// MaxLogBytes is the size at which the log file is rotated.
	MaxLogBytes = 10 * 1024 * 1024
	// LogGenerations is the number of rotated log files kept (log.1 ... log.5).
	LogGenerations = 5
	// DefaultMaxJobs is how many jobs the agent asks for per poll (max_jobs).
	DefaultMaxJobs = 5
	// HardMaxJobsPerPoll is the most jobs run from one poll response. IdP
	// versions that ignore max_jobs hand out at most 10 per poll.
	HardMaxJobsPerPoll = 10
	// minIdlePollInterval spaces out polls that return without a runnable job.
	minIdlePollInterval = time.Second
)

type Config struct {
	CloudIdpURL                string            `json:"cloud_idp_url"`
	AgentToken                 string            `json:"agent_token"`
	LocalScimBaseURL           string            `json:"local_scim_base_url"`
	LocalScimBearerToken       string            `json:"local_scim_bearer_token"`
	LocalBasicAuthUser         string            `json:"local_basic_auth_user,omitempty"`
	LocalBasicAuthPassword     string            `json:"local_basic_auth_password,omitempty"`
	LocalExtraHeaders          map[string]string `json:"local_extra_headers,omitempty"`
	LocalCACertFile            string            `json:"local_ca_cert_file,omitempty"`
	LocalInsecureSkipTLSVerify bool              `json:"local_insecure_skip_tls_verify"`
	CloudCACertFile            string            `json:"cloud_ca_cert_file,omitempty"`
	PollWaitSeconds            int               `json:"poll_wait_seconds"`
	LocalTimeoutSeconds        int               `json:"local_timeout_seconds"`
	MaxJobs                    int               `json:"max_jobs,omitempty"`
	LogFile                    string            `json:"log_file"`
	ServiceName                string            `json:"service_name,omitempty"`
	// AllowInsecureFilePermissions lets -install and an unattended agent go
	// ahead (with warnings) although other accounts can change the agent's
	// files or read config.json. Off by default.
	AllowInsecureFilePermissions bool `json:"allow_insecure_file_permissions,omitempty"`
}

type PollRequest struct {
	Hostname            string `json:"hostname"`
	Version             string `json:"version"`
	WaitSeconds         int    `json:"wait_seconds"`
	MaxJobs             int    `json:"max_jobs"`
	LocalTimeoutSeconds int    `json:"local_timeout_seconds"`
}

type AgentJob struct {
	ID           string  `json:"id"`
	Method       string  `json:"method"`
	EndpointPath string  `json:"endpoint_path"`
	BodyRaw      *string `json:"body_raw"`
}

type PollResponse struct {
	ConnectorID   string     `json:"connector_id"`
	ConnectorName string     `json:"connector_name"`
	Jobs          []AgentJob `json:"jobs"`
	Error         string     `json:"error"`
}

type JobResult struct {
	JobID     string `json:"job_id"`
	Status    int    `json:"status"`
	BodyRaw   string `json:"body_raw,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

type ResultBatch struct {
	Results []JobResult `json:"results"`
}

// ---------- Log output ----------

type rotatingFileWriter struct {
	mu          sync.Mutex
	path        string
	file        *os.File
	size        int64
	maxBytes    int64
	generations int
	closed      bool
}

func newRotatingFileWriter(path string) (*rotatingFileWriter, error) {
	w := &rotatingFileWriter{path: path, maxBytes: MaxLogBytes, generations: LogGenerations}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotatingFileWriter) open() error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	w.size = 0
	if info, err := f.Stat(); err == nil {
		w.size = info.Size()
	}
	w.file = f
	return nil
}

// generation returns the name of rotated log file number i (1 = newest).
func (w *rotatingFileWriter) generation(i int) string {
	return w.path + "." + strconv.Itoa(i)
}

// rotate drops the oldest generation, shifts log.1 ... log.(N-1) up by one and
// moves the current file to log.1, so a burst of output cannot wipe the
// history in one go.
func (w *rotatingFileWriter) rotate() {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	_ = os.Remove(w.generation(w.generations))
	for i := w.generations - 1; i >= 1; i-- {
		_ = os.Rename(w.generation(i), w.generation(i+1))
	}
	_ = os.Rename(w.path, w.generation(1))
	w.size = 0
}

func (w *rotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, errors.New("log file closed")
	}
	if w.file != nil && w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		w.rotate()
	}
	if w.file == nil {
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

// safeLineWriter escapes control characters inside every log entry and keeps
// only the trailing newline. log.Logger issues one Write per entry, so no
// logged text (remote error bodies included) can start a forged line, erase
// earlier lines with terminal escape sequences or hide text with bidi
// controls. Remote values are additionally quoted at each log call.
type safeLineWriter struct {
	w io.Writer
}

func (s safeLineWriter) Write(p []byte) (int, error) {
	line := string(p)
	newline := strings.HasSuffix(line, "\n")
	if newline {
		line = line[:len(line)-1]
	}
	out := escapeControlChars(line)
	if newline {
		out += "\n"
	}
	if _, err := io.WriteString(s.w, out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// needsLogEscape reports whether r must not appear verbatim in a log line:
// C0/C1 controls, DEL, Unicode line/paragraph separators and format (bidi)
// characters.
func needsLogEscape(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029 || unicode.Is(unicode.Cf, r)
}

// escapeControlChars rewrites characters that needsLogEscape reports, and
// invalid UTF-8 bytes, as visible \xNN / \uNNNN escapes.
func escapeControlChars(s string) string {
	clean := true
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || needsLogEscape(r) {
			clean = false
			break
		}
		i += size
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r < 0x100 && needsLogEscape(r):
			fmt.Fprintf(&b, `\x%02x`, r)
		case r > 0xffff && needsLogEscape(r):
			fmt.Fprintf(&b, `\U%08x`, r)
		case needsLogEscape(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// clipText shortens s to at most max characters, marking the cut.
func clipText(s string, max int) string {
	n := 0
	for i := range s {
		if n == max {
			return s[:i] + "...(truncated)"
		}
		n++
	}
	return s
}

// quoteText clips s to max characters and quotes it with Go %q rules, so
// newlines, control characters and invalid UTF-8 appear as escapes.
func quoteText(s string, max int) string {
	return strconv.Quote(clipText(s, max))
}

// quoteLogField quotes a remote-supplied value for a log line.
func quoteLogField(s string) string {
	return quoteText(s, MaxLogFieldChars)
}

// ---------- Configuration ----------

func defaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(filepath.Dir(exe), "config.json")
}

// resolveRelativeTo makes a relative file path absolute against dir.
func resolveRelativeTo(dir, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// parseLocalScimBaseURL validates local_scim_base_url: an absolute http(s)
// URL without query string or fragment (endpoint paths are appended to it).
func parseLocalScimBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Opaque != "" {
		return nil, errors.New("local_scim_base_url must be an absolute http:// or https:// URL")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, errors.New("local_scim_base_url must not contain a query string or fragment")
	}
	return u, nil
}

// validServiceName reports whether name is safe as a Windows service name and
// as part of the NT SERVICE\<name> virtual account.
func validServiceName(name string) bool {
	if len(name) < 1 || len(name) > 80 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// serviceSID returns the SID of the NT SERVICE\<name> virtual account (the
// service SID): S-1-5-80 followed by the SHA-1 of the upper-cased UTF-16LE
// service name as five little-endian 32-bit values. Using the SID keeps ACL
// grants independent of name resolution and of localized account names.
func serviceSID(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	buf := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[2*i:], u)
	}
	sum := sha1.Sum(buf)
	var b strings.Builder
	b.WriteString("S-1-5-80")
	for i := 0; i < 5; i++ {
		b.WriteString("-")
		b.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(sum[4*i:])), 10))
	}
	return b.String()
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("invalid JSON in %s: %w", path, err)
	}

	cfg.CloudIdpURL = strings.TrimRight(strings.TrimSpace(cfg.CloudIdpURL), "/")
	cfg.AgentToken = strings.TrimSpace(cfg.AgentToken)
	cfg.LocalScimBaseURL = strings.TrimRight(strings.TrimSpace(cfg.LocalScimBaseURL), "/")

	if cfg.CloudIdpURL == "" {
		return nil, errors.New("cloud_idp_url is required in config.json")
	}
	if !strings.HasPrefix(strings.ToLower(cfg.CloudIdpURL), "https://") &&
		!strings.HasPrefix(strings.ToLower(cfg.CloudIdpURL), "http://") {
		return nil, errors.New("cloud_idp_url must start with https:// (or http:// for local lab)")
	}
	if !strings.HasPrefix(cfg.AgentToken, "idp_sagt_") {
		return nil, errors.New("agent_token must be a valid Identity Cloud SCIM Agent token starting with idp_sagt_")
	}
	if cfg.LocalScimBaseURL == "" {
		return nil, errors.New("local_scim_base_url is required in config.json")
	}
	if _, err := parseLocalScimBaseURL(cfg.LocalScimBaseURL); err != nil {
		return nil, err
	}
	if cfg.PollWaitSeconds <= 0 || cfg.PollWaitSeconds > 15 {
		cfg.PollWaitSeconds = 12
	}
	if cfg.LocalTimeoutSeconds <= 0 || cfg.LocalTimeoutSeconds > 120 {
		cfg.LocalTimeoutSeconds = 20
	}
	if cfg.MaxJobs <= 0 {
		cfg.MaxJobs = DefaultMaxJobs
	}
	if cfg.MaxJobs > HardMaxJobsPerPoll {
		cfg.MaxJobs = HardMaxJobsPerPoll
	}
	cfg.ServiceName = strings.TrimSpace(cfg.ServiceName)
	if cfg.ServiceName == "" {
		cfg.ServiceName = DefaultServiceName
	}
	// Relative file paths are resolved against the folder holding config.json
	// (the executable's folder in the default layout), so config.json and its
	// log can live together under %ProgramData%.
	configDir := filepath.Dir(path)
	cfg.LogFile = resolveRelativeTo(configDir, strings.TrimSpace(cfg.LogFile))
	cfg.LocalCACertFile = resolveRelativeTo(configDir, strings.TrimSpace(cfg.LocalCACertFile))
	cfg.CloudCACertFile = resolveRelativeTo(configDir, strings.TrimSpace(cfg.CloudCACertFile))
	return &cfg, nil
}

func buildHTTPClient(caCertFile string, insecureSkipVerify bool, timeout time.Duration) (*http.Client, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkipVerify,
	}
	if caPath := strings.TrimSpace(caCertFile); caPath != "" {
		pemBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate file %s: %w", caPath, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no valid PEM certificates found in %s", caPath)
		}
		tlsCfg.RootCAs = pool
	}
	tr := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		TLSClientConfig:        tlsCfg,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           10,
		IdleConnTimeout:        60 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: MaxResponseHeaderBytes,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// ---------- endpoint_path confinement ----------

// scimResourceRoots are the SCIM 2.0 endpoints (RFC 7644 section 3.2) that
// the IdP may address below local_scim_base_url, in lower case.
var scimResourceRoots = map[string]bool{
	"users":                 true,
	"groups":                true,
	"serviceproviderconfig": true,
	"resourcetypes":         true,
	"schemas":               true,
	"bulk":                  true,
	"me":                    true,
	".search":               true,
}

// scimEndpoint is an endpoint_path accepted by validateScimEndpointPath.
type scimEndpoint struct {
	segments []string // percent-decoded path segments: Resource or Resource/{id}
	rawQuery string   // validated query string without the leading '?'
}

// escapedPath re-encodes the decoded segments like PHP's rawurlencode (every
// byte except RFC 3986 unreserved characters is percent-encoded), which is
// the form the IdP sends, so encoded dots or separators never reach the wire.
func (e scimEndpoint) escapedPath() string {
	parts := make([]string, len(e.segments))
	for i, s := range e.segments {
		parts[i] = escapePathSegment(s)
	}
	return strings.Join(parts, "/")
}

// String returns the canonical relative form of the endpoint, for logging.
func (e scimEndpoint) String() string {
	if e.rawQuery == "" {
		return e.escapedPath()
	}
	return e.escapedPath() + "?" + e.rawQuery
}

func isUnreservedByte(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func isHexByte(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func escapePathSegment(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreservedByte(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
}

// validQueryString reports whether q (without '?') uses only RFC 3986 query
// characters with well-formed percent escapes. ';' is refused because some
// servers treat it as a parameter separator.
func validQueryString(q string) bool {
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case isUnreservedByte(c):
		case strings.IndexByte("!$&'()*+,=:@/?", c) >= 0:
		case c == '%':
			if i+2 >= len(q) || !isHexByte(q[i+1]) || !isHexByte(q[i+2]) {
				return false
			}
			i += 2
		default:
			return false
		}
	}
	return true
}

// allowedSegmentText reports whether a decoded path segment is acceptable:
// valid UTF-8, no path or parameter separators, no '%' (double encoding), no
// '?' or '#', no control characters, and outside ASCII only letters, marks
// and digits, so look-alike dots and slashes that a server might normalize
// (such as U+FF0E or U+2215) are refused as well.
func allowedSegmentText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x80 {
			if r < 0x20 || r == 0x7f || strings.ContainsRune(`/\;%?#`, r) {
				return false
			}
			continue
		}
		if !unicode.IsLetter(r) && !unicode.IsMark(r) && !unicode.IsNumber(r) {
			return false
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// validateScimEndpointPath confines an IdP-supplied endpoint_path to the SCIM
// 2.0 endpoint root: <Resource> or <Resource>/<id>, with an allowed resource,
// optionally followed by a query string. Each path segment is percent-decoded
// before it is checked, so encoded dot segments ("%2e%2e"), encoded slashes
// or backslashes, ';' path parameters ("..;") and double encoding are refused.
func validateScimEndpointPath(ep string) (scimEndpoint, error) {
	trimmed := strings.TrimLeft(strings.TrimSpace(ep), "/")
	if trimmed == "" {
		return scimEndpoint{}, errors.New("empty SCIM endpoint_path")
	}
	if len(trimmed) > MaxEndpointPathBytes {
		return scimEndpoint{}, errors.New("endpoint_path is too long")
	}
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if c <= 0x20 || c >= 0x7f {
			return scimEndpoint{}, errors.New("endpoint_path contains a control, space or non-ASCII character")
		}
		if c == '#' || c == ';' || c == '\\' {
			return scimEndpoint{}, fmt.Errorf("endpoint_path contains a forbidden %q character", rune(c))
		}
	}
	pathOnly, rawQuery, _ := strings.Cut(trimmed, "?")
	if !validQueryString(rawQuery) {
		return scimEndpoint{}, errors.New("endpoint_path has an invalid query string")
	}
	rawSegs := strings.Split(pathOnly, "/")
	if len(rawSegs) > 2 {
		return scimEndpoint{}, errors.New("endpoint_path must be <Resource> or <Resource>/<id>")
	}
	segs := make([]string, len(rawSegs))
	for i, raw := range rawSegs {
		dec, err := url.PathUnescape(raw)
		if err != nil {
			return scimEndpoint{}, errors.New("endpoint_path has an invalid percent-encoding")
		}
		if strings.Trim(dec, ". ") == "" {
			return scimEndpoint{}, errors.New("empty or dot-segment in endpoint_path")
		}
		if !allowedSegmentText(dec) {
			return scimEndpoint{}, errors.New("forbidden character in an endpoint_path segment")
		}
		segs[i] = dec
	}
	if !isASCII(segs[0]) || !scimResourceRoots[strings.ToLower(segs[0])] {
		return scimEndpoint{}, fmt.Errorf("disallowed SCIM resource root %s", quoteLogField(segs[0]))
	}
	return scimEndpoint{segments: segs, rawQuery: rawQuery}, nil
}

// buildLocalScimURL resolves a validated endpoint below the local SCIM base
// URL. Path holds the decoded segments and RawPath their canonical encoding;
// the serialized URL is parsed again (as net/http will) and must keep the
// base scheme, host and path prefix, the expected encoding and query.
func buildLocalScimURL(base *url.URL, ep scimEndpoint) (*url.URL, error) {
	basePath := strings.TrimRight(base.Path, "/")
	wantRaw := strings.TrimRight(base.EscapedPath(), "/") + "/" + ep.escapedPath()
	u := &url.URL{
		Scheme:   base.Scheme,
		User:     base.User,
		Host:     base.Host,
		Path:     basePath + "/" + strings.Join(ep.segments, "/"),
		RawPath:  wantRaw,
		RawQuery: ep.rawQuery,
	}
	parsed, err := url.Parse(u.String())
	if err != nil {
		return nil, errors.New("cannot build the local SCIM URL for endpoint_path")
	}
	prefix := path.Clean("/" + basePath)
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	if parsed.Scheme != base.Scheme || parsed.Host != base.Host || parsed.EscapedPath() != wantRaw ||
		parsed.RawQuery != ep.rawQuery || parsed.Fragment != "" ||
		!strings.HasPrefix(path.Clean(parsed.Path), prefix) {
		return nil, errors.New("endpoint_path escapes local_scim_base_url")
	}
	return parsed, nil
}

// normalizeMethod returns the upper-cased method if it is one the IdP uses.
func normalizeMethod(m string) (string, bool) {
	switch u := strings.ToUpper(strings.TrimSpace(m)); u {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return u, true
	}
	return "", false
}

// isUUID reports whether s has the canonical 8-4-4-4-12 hex form the IdP
// uses for job ids.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexByte(s[i]) {
				return false
			}
		}
	}
	return true
}

// truncateUTF8 cuts b to at most max bytes without splitting a UTF-8 sequence.
func truncateUTF8(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	cut := max
	for i := 0; i < utf8.UTFMax-1 && cut > 0 && !utf8.RuneStart(b[cut]); i++ {
		cut--
	}
	if !utf8.RuneStart(b[cut]) {
		cut = max
	}
	return b[:cut]
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ---------- Relay ----------

type AgentRunner struct {
	cfg         *Config
	localBase   *url.URL
	cloudClient *http.Client
	localClient *http.Client
	hostname    string
	logger      *log.Logger
}

func newAgentRunner(cfg *Config, logger *log.Logger) (*AgentRunner, error) {
	localBase, err := parseLocalScimBaseURL(cfg.LocalScimBaseURL)
	if err != nil {
		return nil, err
	}
	cloudTimeout := time.Duration(cfg.PollWaitSeconds+15) * time.Second
	cloudClient, err := buildHTTPClient(cfg.CloudCACertFile, false, cloudTimeout)
	if err != nil {
		return nil, err
	}
	localTimeout := time.Duration(cfg.LocalTimeoutSeconds) * time.Second
	localClient, err := buildHTTPClient(cfg.LocalCACertFile, cfg.LocalInsecureSkipTLSVerify, localTimeout)
	if err != nil {
		return nil, err
	}
	hn, err := os.Hostname()
	if err != nil || strings.TrimSpace(hn) == "" {
		hn = "windows-scim-agent"
	}
	return &AgentRunner{
		cfg:         cfg,
		localBase:   localBase,
		cloudClient: cloudClient,
		localClient: localClient,
		hostname:    hn,
		logger:      logger,
	}, nil
}

// executeLocalScimJob validates one IdP job and runs it against the local SCIM
// application. The second result describes the job for the log: the
// normalized method and endpoint when they are valid, otherwise the quoted,
// clipped values the IdP sent.
func (a *AgentRunner) executeLocalScimJob(ctx context.Context, job AgentJob) (JobResult, string) {
	label := quoteLogField(job.Method) + " " + quoteLogField(job.EndpointPath)
	ep, err := validateScimEndpointPath(job.EndpointPath)
	if err != nil {
		return JobResult{JobID: job.ID, Error: err.Error()}, label
	}
	method, ok := normalizeMethod(job.Method)
	if !ok {
		return JobResult{JobID: job.ID, Error: "unsupported HTTP method " + quoteLogField(job.Method)}, label
	}
	label = method + " " + quoteLogField("/"+ep.String())
	target, err := buildLocalScimURL(a.localBase, ep)
	if err != nil {
		return JobResult{JobID: job.ID, Error: err.Error()}, label
	}

	var bodyReader io.Reader
	if job.BodyRaw != nil && *job.BodyRaw != "" {
		bodyReader = strings.NewReader(*job.BodyRaw)
	}

	req, err := http.NewRequestWithContext(ctx, method, target.String(), bodyReader)
	if err != nil {
		return JobResult{JobID: job.ID, Error: err.Error()}, label
	}
	req.Header.Set("Accept", "application/scim+json, application/json")
	req.Header.Set("User-Agent", "IdentityCloud-OnPrem-SCIM-Agent/"+AgentVersion)
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/scim+json; charset=utf-8")
	}

	if strings.TrimSpace(a.cfg.LocalScimBearerToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(a.cfg.LocalScimBearerToken))
	} else if strings.TrimSpace(a.cfg.LocalBasicAuthUser) != "" {
		cred := a.cfg.LocalBasicAuthUser + ":" + a.cfg.LocalBasicAuthPassword
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
	}
	for k, v := range a.cfg.LocalExtraHeaders {
		if strings.TrimSpace(k) != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := a.localClient.Do(req)
	if err != nil {
		return JobResult{JobID: job.ID, Error: err.Error()}, label
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return JobResult{JobID: job.ID, Error: "failed reading local SCIM response: " + err.Error()}, label
	}
	truncated := len(respBytes) > MaxResponseBytes
	if truncated {
		respBytes = truncateUTF8(respBytes, MaxResponseBytes)
	}

	return JobResult{
		JobID:     job.ID,
		Status:    resp.StatusCode,
		BodyRaw:   string(respBytes),
		Truncated: truncated,
	}, label
}

// pollOnce long-polls the IdP for jobs, runs them one by one and reports each
// result as soon as its job has finished. It returns the number of jobs run.
func (a *AgentRunner) pollOnce(ctx context.Context) (int, error) {
	pollURL := a.cfg.CloudIdpURL + "/scim/agent/poll"
	reqPayload, _ := json.Marshal(PollRequest{
		Hostname:            a.hostname,
		Version:             AgentVersion,
		WaitSeconds:         a.cfg.PollWaitSeconds,
		MaxJobs:             a.cfg.MaxJobs,
		LocalTimeoutSeconds: a.cfg.LocalTimeoutSeconds,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pollURL, bytes.NewReader(reqPayload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.AgentToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "IdentityCloud-OnPrem-SCIM-Agent/"+AgentVersion)

	resp, err := a.cloudClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxPollResponseBytes+1))
	if err != nil {
		return 0, err
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return 0, fmt.Errorf("authentication rejected by Cloud IdP (HTTP %d): %s", resp.StatusCode,
			quoteText(strings.TrimSpace(string(rawBody)), MaxCloudErrorChars))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("cloud poll returned HTTP %d: %s", resp.StatusCode,
			quoteText(strings.TrimSpace(string(rawBody)), MaxCloudErrorChars))
	}
	if len(rawBody) > MaxPollResponseBytes {
		return 0, fmt.Errorf("cloud poll response is larger than %d bytes", MaxPollResponseBytes)
	}

	var pollResp PollResponse
	if err := json.Unmarshal(rawBody, &pollResp); err != nil {
		return 0, fmt.Errorf("invalid JSON from cloud poll: %w", err)
	}

	executed := 0
	for i, job := range pollResp.Jobs {
		if ctx.Err() != nil {
			break
		}
		if i >= HardMaxJobsPerPoll {
			a.logger.Printf("Ignoring %d job(s) beyond the per-poll limit of %d", len(pollResp.Jobs)-i, HardMaxJobsPerPoll)
			break
		}
		if !isUUID(job.ID) {
			a.logger.Printf("[JOB %s] rejected: job id is not a UUID (method %s, endpoint_path %s)",
				quoteLogField(job.ID), quoteLogField(job.Method), quoteLogField(job.EndpointPath))
			continue
		}
		t0 := time.Now()
		res, label := a.executeLocalScimJob(ctx, job)
		dur := time.Since(t0).Round(time.Millisecond)
		executed++
		if res.Error != "" {
			a.logger.Printf("[JOB %s] %s -> ERROR (%v): %s", job.ID, label, dur, quoteText(res.Error, MaxCloudErrorChars))
		} else {
			note := ""
			if res.Truncated {
				note = fmt.Sprintf(" (response body truncated to %d bytes)", len(res.BodyRaw))
			}
			a.logger.Printf("[JOB %s] %s -> HTTP %d (%v)%s", job.ID, label, res.Status, dur, note)
		}
		if err := a.reportJobResult(ctx, res); err != nil {
			return executed, fmt.Errorf("failed posting result of job %s: %w", job.ID, err)
		}
	}
	return executed, nil
}

// httpStatusError is a non-2xx answer from the IdP result endpoint.
type httpStatusError struct {
	StatusCode int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("result endpoint returned HTTP %d", e.StatusCode)
}

// reportJobResult posts one job's result right after the job ran, in the
// {"results":[...]} envelope every IdP version accepts. If the IdP refuses the
// body as too large (HTTP 413), the job is reported as failed instead, so the
// IdP does not keep waiting for it.
func (a *AgentRunner) reportJobResult(ctx context.Context, res JobResult) error {
	// Local transport errors can be long (they quote the request URL); the IdP
	// only needs the gist.
	res.Error = clipText(res.Error, MaxCloudErrorChars)
	err := a.reportResults(ctx, []JobResult{res})
	var se *httpStatusError
	if err != nil && res.Error == "" && errors.As(err, &se) && se.StatusCode == http.StatusRequestEntityTooLarge {
		failed := JobResult{
			JobID: res.JobID,
			Error: fmt.Sprintf("local SCIM response (HTTP %d, %d bytes) is too large for the IdP to accept", res.Status, len(res.BodyRaw)),
		}
		err = a.reportResults(ctx, []JobResult{failed})
	}
	return err
}

func (a *AgentRunner) reportResults(ctx context.Context, results []JobResult) error {
	resURL := a.cfg.CloudIdpURL + "/scim/agent/result"
	var payload bytes.Buffer
	enc := json.NewEncoder(&payload)
	enc.SetEscapeHTML(false) // keeps '<', '>' and '&' in relayed bodies at one byte each
	if err := enc.Encode(ResultBatch{Results: results}); err != nil {
		return err
	}

	reportCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if ctx.Err() == nil {
		reportCtx = ctx
	}

	req, err := http.NewRequestWithContext(reportCtx, http.MethodPost, resURL, bytes.NewReader(payload.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.AgentToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "IdentityCloud-OnPrem-SCIM-Agent/"+AgentVersion)

	resp, err := a.cloudClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 65536))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &httpStatusError{StatusCode: resp.StatusCode}
	}
	return nil
}

func (a *AgentRunner) RunLoop(ctx context.Context) {
	a.logger.Printf("Starting Identity Cloud On-Premises SCIM 2.0 Proxy Agent v%s on host %s", AgentVersion, a.hostname)
	a.logger.Printf("Cloud IdP : %s", a.cfg.CloudIdpURL)
	a.logger.Printf("Local SCIM: %s", a.localBase.Redacted())
	if cu, err := url.Parse(a.cfg.CloudIdpURL); err == nil && cu.Scheme == "http" && !isLoopbackHost(cu.Hostname()) {
		a.logger.Printf("WARNING: cloud_idp_url uses plain http://, so the agent token and provisioning data cross the network unencrypted. Use https:// outside a local lab.")
	}

	backoff := time.Second
	connectedLogged := false

	for {
		if ctx.Err() != nil {
			a.logger.Printf("Shutting down SCIM proxy agent cleanly.")
			return
		}

		started := time.Now()
		count, err := a.pollOnce(ctx)
		if err != nil {
			if ctx.Err() != nil {
				a.logger.Printf("Shutting down SCIM proxy agent cleanly.")
				return
			}
			connectedLogged = false
			jitter := time.Duration(rand.Intn(400)) * time.Millisecond
			sleepDur := backoff + jitter
			// The error can carry long server-supplied text (net/http quotes a
			// malformed status line in full, for example), so it is clipped like
			// a cloud error body; safeLineWriter escapes control characters.
			a.logger.Printf("Relay poll error: %s (retrying in %v)", clipText(err.Error(), MaxCloudErrorChars), sleepDur.Round(100*time.Millisecond))

			select {
			case <-time.After(sleepDur):
			case <-ctx.Done():
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
				if backoff > 30*time.Second {
					backoff = 30 * time.Second
				}
			}
			continue
		}

		backoff = time.Second
		if !connectedLogged {
			a.logger.Printf("Connected to Identity Cloud relay (%s) — awaiting SCIM provisioning jobs", a.cfg.CloudIdpURL)
			connectedLogged = true
		}
		if count > 0 {
			// Immediately re-poll without delay when active sync batch is in flight
			continue
		}
		// The IdP holds an empty poll open for wait_seconds; do not spin if a
		// poll comes back early without a job that could run.
		if wait := minIdlePollInterval - time.Since(started); wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				a.logger.Printf("Shutting down SCIM proxy agent cleanly.")
				return
			}
		}
	}
}

func main() {
	var (
		configFlag    = flag.String("config", defaultConfigPath(), "Path to config.json")
		consoleFlag   = flag.Bool("console", false, "Run interactively in foreground console")
		installFlag   = flag.Bool("install", false, "Install as an automatic Windows Service (runs as NT SERVICE\\<service_name>)")
		uninstallFlag = flag.Bool("uninstall", false, "Uninstall the Windows Service")
		startFlag     = flag.Bool("start", false, "Start the Windows Service")
		stopFlag      = flag.Bool("stop", false, "Stop the Windows Service")
		testLocalFlag = flag.Bool("test-local", false, "Test connectivity to local_scim_base_url and exit")
	)
	flag.Parse()

	absConfigPath, err := filepath.Abs(*configFlag)
	if err != nil {
		absConfigPath = *configFlag
	}

	cfg, cfgErr := loadConfig(absConfigPath)
	svcName := DefaultServiceName
	if cfg != nil && cfg.ServiceName != "" {
		svcName = cfg.ServiceName
	}

	if *installFlag {
		if cfgErr != nil {
			fmt.Fprintf(os.Stderr, "Error validating %s before service install: %v\n", absConfigPath, cfgErr)
			os.Exit(1)
		}
		if !validServiceName(svcName) {
			fmt.Fprintf(os.Stderr, "service_name %q is invalid: use 1-80 characters from A-Z, a-z, 0-9, '_', '.' and '-'\n", svcName)
			os.Exit(1)
		}
		exePath, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to resolve executable path: %v\n", err)
			os.Exit(1)
		}
		if err := installWindowsService(svcName, DefaultDisplayName, DefaultDescription, exePath, absConfigPath, cfg.LogFile,
			cfg.AllowInsecureFilePermissions, cfg.LocalCACertFile, cfg.CloudCACertFile); err != nil {
			fmt.Fprintf(os.Stderr, "Service install failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Installed Windows Service %q running as NT SERVICE\\%s using config %s\nRun `scim-agent.exe -start` or `sc start %s` to start.\n", svcName, svcName, absConfigPath, svcName)
		return
	}

	if *uninstallFlag {
		if err := uninstallWindowsService(svcName); err != nil {
			fmt.Fprintf(os.Stderr, "Service uninstall failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Uninstalled Windows Service %q\n", svcName)
		return
	}

	if *startFlag {
		if err := startWindowsService(svcName); err != nil {
			fmt.Fprintf(os.Stderr, "Service start failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Started Windows Service %q\n", svcName)
		return
	}

	if *stopFlag {
		if err := stopWindowsService(svcName); err != nil {
			fmt.Fprintf(os.Stderr, "Service stop failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Stopped Windows Service %q\n", svcName)
		return
	}

	if cfgErr != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", cfgErr)
		os.Exit(1)
	}

	isSvc := !*consoleFlag && !*testLocalFlag && isWindowsServiceProcess()

	var logWriters []io.Writer
	if cfg.LogFile != "" {
		rotFile, err := newRotatingFileWriter(cfg.LogFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open log file %s: %v\n", cfg.LogFile, err)
			if isSvc {
				// A service has no console, so running on would leave no record
				// of what it did. Fail visibly instead (the SCM reports the stop).
				os.Exit(1)
			}
		} else {
			defer rotFile.Close()
			logWriters = append(logWriters, rotFile)
		}
	}

	if !isSvc || len(logWriters) == 0 {
		logWriters = append(logWriters, os.Stdout)
	}
	logger := log.New(safeLineWriter{w: io.MultiWriter(logWriters...)}, "", log.LstdFlags|log.LUTC)
	if isSvc && runningAsLocalSystem() {
		logger.Printf("WARNING: the service runs as LocalSystem. Run scim-agent.exe -uninstall and then -install to switch it to the least-privileged NT SERVICE\\%s account.", svcName)
	}
	// config.json holds the agent token and the local SCIM credentials. Its
	// permissions can be wrong although -install restricted them once: 1.0.x
	// installs upgraded by replacing the executable, -console runs and service
	// wrappers, or an editor that re-created the file. An unattended agent (a
	// service, or any process in session 0 such as one started by a service
	// wrapper) refuses to run then, unless allow_insecure_file_permissions is
	// set; interactive runs only warn.
	if problems := configPermissionProblems(svcName, absConfigPath); len(problems) > 0 {
		for _, p := range problems {
			logger.Printf("WARNING: insecure file permissions: %s", p)
		}
		if !*testLocalFlag && isWindowsServiceProcess() && !cfg.AllowInsecureFilePermissions {
			logger.Fatalf("Refusing to start because of the permission problems above: %s holds the agent token, so only SYSTEM, Administrators and NT SERVICE\\%s may read or change it. "+
				"Restrict it by running scim-agent.exe -uninstall and -install from an elevated prompt (or with the icacls commands in README.md), "+
				"or set \"allow_insecure_file_permissions\": true in config.json to start anyway.", absConfigPath, svcName)
		}
	}

	runner, err := newAgentRunner(cfg, logger)
	if err != nil {
		logger.Fatalf("Failed to initialize SCIM agent: %v", err)
	}

	if *testLocalFlag {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		res, _ := runner.executeLocalScimJob(ctx, AgentJob{
			ID:           "local-self-test",
			Method:       "GET",
			EndpointPath: "Users?startIndex=1&count=1",
		})
		if res.Error != "" {
			fmt.Fprintf(os.Stderr, "LOCAL SCIM TEST FAILED: %s\n", res.Error)
			os.Exit(1)
		}
		fmt.Printf("LOCAL SCIM TEST HTTP %d:\n%s\n", res.Status, res.BodyRaw)
		if res.Status < 200 || res.Status >= 300 {
			os.Exit(1)
		}
		return
	}

	if isSvc {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		err := runAsWindowsService(
			svcName,
			func() {
				go func() {
					defer close(done)
					runner.RunLoop(ctx)
				}()
			},
			func() {
				cancel()
				<-done
			},
		)
		if err != nil {
			logger.Fatalf("Windows Service dispatcher error: %v", err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runner.RunLoop(ctx)
}
