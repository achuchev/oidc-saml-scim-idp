package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

const testJobID = "2819c223-7f76-453a-919d-413861904646"

func TestValidateScimEndpointPathAcceptsIdpShapes(t *testing.T) {
	cases := map[string]string{
		"Users?startIndex=1&count=1":                       "Users?startIndex=1&count=1",
		"Users?filter=userName%20eq%20%22a%40b.example%22": "Users?filter=userName%20eq%20%22a%40b.example%22",
		"Users":                                    "Users",
		"/Users/abc":                               "Users/abc",
		"Users/alice%40example.com":                "Users/alice%40example.com",
		"Users/alice%2Btest%40example.com":         "Users/alice%2Btest%40example.com",
		"Users/" + testJobID:                       "Users/" + testJobID,
		"Users/j%C3%BCrgen":                        "Users/j%C3%BCrgen",
		"Users/John%20Doe":                         "Users/John%20Doe",
		"Users/.search":                            "Users/.search",
		"Groups?filter=displayName%20eq%20%22S%22": "Groups?filter=displayName%20eq%20%22S%22",
		"Groups/g-1":                               "Groups/g-1",
		"ServiceProviderConfig":                    "ServiceProviderConfig",
		"Schemas/urn:ietf:params:scim:schemas:core:2.0:User": "Schemas/urn%3Aietf%3Aparams%3Ascim%3Aschemas%3Acore%3A2.0%3AUser",
		"users/ABC": "users/ABC",
	}
	for in, want := range cases {
		ep, err := validateScimEndpointPath(in)
		if err != nil {
			t.Errorf("validateScimEndpointPath(%q) rejected a valid path: %v", in, err)
			continue
		}
		if got := ep.String(); got != want {
			t.Errorf("validateScimEndpointPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateScimEndpointPathRejectsBypasses(t *testing.T) {
	cases := []string{
		"",
		"/",
		"Users/%2e%2e",
		"Users/.%2E",
		"Users/%2E.",
		"Users/%2e",
		"Users/..",
		"Users/...",
		"Users/.%20.",
		"Users/%2e%2e/%2e%2e/actuator/env",
		"Users/..;",
		"Users/..;/..;/manager/html",
		"Users/x;jsessionid=1",
		"Users/..%2f..%2fadmin",
		"Users/a%2Fb",
		"Users/a%5Cb",
		"Users/a\\b",
		"Users/%252e%252e",
		"Users/a%00",
		"Users/a%0d%0aX-Injected:1",
		"Users/%C0%AE%C0%AE",
		"Users/%EF%BC%8E%EF%BC%8E",
		"Users/a%E2%88%95b",
		"Users/%E2%80%AEx",
		"Users/%",
		"Users/abc%2",
		"Users/%zz",
		"Users/",
		"Users//x",
		"Users/x/y",
		"Users#frag",
		"Users?x=1#f",
		"Users?a=b;c",
		"Users?a=%zz",
		"Users?a b",
		"Users?a=\"b\"",
		"Users\x1b[1A",
		"Users\nX",
		"Users/ü",
		"http://evil.example/Users",
		"//evil.example/Users",
		"Users@evil.example",
		"actuator/env",
		"%2e%2e/admin",
		"BUL%E2%84%AA",
		strings.Repeat("a", MaxEndpointPathBytes+1),
	}
	for _, in := range cases {
		if ep, err := validateScimEndpointPath(in); err == nil {
			t.Errorf("validateScimEndpointPath(%q) accepted %q", in, ep.String())
		}
	}
}

// localRecorder is a local SCIM server that records the raw request targets.
type localRecorder struct {
	mu       sync.Mutex
	uris     []string
	auth     []string
	respBody []byte
}

func (l *localRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	l.uris = append(l.uris, r.RequestURI)
	l.auth = append(l.auth, r.Header.Get("Authorization"))
	body := l.respBody
	l.mu.Unlock()
	w.Header().Set("Content-Type", "application/scim+json")
	if body == nil {
		body = []byte(`{"ok":true}`)
	}
	_, _ = w.Write(body)
}

func (l *localRecorder) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.uris...)
}

func newTestRunner(t *testing.T, cloudURL, localURL string, logs io.Writer) *AgentRunner {
	t.Helper()
	cfg := &Config{
		CloudIdpURL:          cloudURL,
		AgentToken:           "idp_sagt_0123456789abcdef_secret",
		LocalScimBaseURL:     localURL,
		LocalScimBearerToken: "local-secret",
		PollWaitSeconds:      1,
		LocalTimeoutSeconds:  5,
		MaxJobs:              DefaultMaxJobs,
	}
	r, err := newAgentRunner(cfg, log.New(safeLineWriter{w: logs}, "", 0))
	if err != nil {
		t.Fatalf("newAgentRunner: %v", err)
	}
	return r
}

func TestExecuteLocalScimJobWireForm(t *testing.T) {
	rec := &localRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	cases := []struct{ base, ep, want string }{
		{"/scim/v2", "Users?startIndex=1&count=1", "/scim/v2/Users?startIndex=1&count=1"},
		{"/scim/v2", "Users/alice%40example.com", "/scim/v2/Users/alice%40example.com"},
		{"/scim/v2", "Users/alice%2Btest%40example.com", "/scim/v2/Users/alice%2Btest%40example.com"},
		{"/scim/v2", "Groups?filter=displayName%20eq%20%22Staff%22", "/scim/v2/Groups?filter=displayName%20eq%20%22Staff%22"},
		{"/scim/v2", "Users/j%C3%BCrgen", "/scim/v2/Users/j%C3%BCrgen"},
		{"/scim/v2", "Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "/scim/v2/Schemas/urn%3Aietf%3Aparams%3Ascim%3Aschemas%3Acore%3A2.0%3AUser"},
		{"", "Users/abc", "/Users/abc"},
		{"/sc%20im", "Groups", "/sc%20im/Groups"},
	}
	for _, c := range cases {
		r := newTestRunner(t, "https://idp.example/x", srv.URL+c.base, io.Discard)
		before := len(rec.seen())
		res, label := r.executeLocalScimJob(context.Background(), AgentJob{ID: testJobID, Method: "get", EndpointPath: c.ep})
		if res.Error != "" || res.Status != http.StatusOK {
			t.Errorf("%s + %s: unexpected result %+v", c.base, c.ep, res)
			continue
		}
		seen := rec.seen()
		if len(seen) != before+1 || seen[len(seen)-1] != c.want {
			t.Errorf("%s + %s: request target %v, want %q", c.base, c.ep, seen[before:], c.want)
		}
		if !strings.HasPrefix(label, "GET \"/") {
			t.Errorf("label %q does not show the normalized method and quoted path", label)
		}
	}
	if rec.auth[0] != "Bearer local-secret" {
		t.Errorf("Authorization = %q", rec.auth[0])
	}
}

func TestExecuteLocalScimJobRejectsTraversalWithoutRequest(t *testing.T) {
	rec := &localRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	r := newTestRunner(t, "https://idp.example/x", srv.URL+"/scim/v2", io.Discard)
	for _, ep := range []string{
		"Users/%2e%2e/%2e%2e/%2e%2e/actuator/env",
		"Users/..;/..;/manager/html",
		"Users/..%2f..%2fadmin",
		"Users/%2e%2e",
	} {
		res, _ := r.executeLocalScimJob(context.Background(), AgentJob{ID: testJobID, Method: "GET", EndpointPath: ep})
		if res.Error == "" {
			t.Errorf("%q was executed: %+v", ep, res)
		}
	}
	res, _ := r.executeLocalScimJob(context.Background(), AgentJob{ID: testJobID, Method: "PROPFIND", EndpointPath: "Users"})
	if res.Error == "" {
		t.Errorf("PROPFIND was executed: %+v", res)
	}
	if seen := rec.seen(); len(seen) != 0 {
		t.Fatalf("local server received %v", seen)
	}
}

func TestExecuteLocalScimJobTruncatesLargeBodies(t *testing.T) {
	big := []byte(strings.Repeat("ü", MaxResponseBytes)) // 2 bytes per character
	rec := &localRecorder{respBody: big}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	r := newTestRunner(t, "https://idp.example/x", srv.URL+"/scim/v2", io.Discard)
	res, _ := r.executeLocalScimJob(context.Background(), AgentJob{ID: testJobID, Method: "GET", EndpointPath: "Groups/g"})
	if !res.Truncated || len(res.BodyRaw) > MaxResponseBytes || !utf8.ValidString(res.BodyRaw) {
		t.Fatalf("truncated=%v len=%d valid=%v", res.Truncated, len(res.BodyRaw), utf8.ValidString(res.BodyRaw))
	}
	small := &localRecorder{}
	srv2 := httptest.NewServer(small)
	defer srv2.Close()
	r2 := newTestRunner(t, "https://idp.example/x", srv2.URL, io.Discard)
	if res, _ := r2.executeLocalScimJob(context.Background(), AgentJob{ID: testJobID, Method: "GET", EndpointPath: "Users"}); res.Truncated {
		t.Fatalf("small body flagged as truncated: %+v", res)
	}
}

// fakeCloud is a minimal IdP relay: it serves one batch of jobs and records
// the poll requests and every result POST.
type fakeCloud struct {
	mu          sync.Mutex
	jobs        []map[string]any
	polls       []map[string]any
	results     [][]JobResult
	rawResult   []string
	rejectAbove int // answer 413 for result bodies larger than this (0 = never)
	served      bool
}

func (f *fakeCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/x/scim/agent/poll":
		var p map[string]any
		_ = json.Unmarshal(body, &p)
		f.polls = append(f.polls, p)
		jobs := []map[string]any{}
		if !f.served {
			jobs = f.jobs
			f.served = true
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"connector_id": "c1", "jobs": jobs})
	case "/x/scim/agent/result":
		if f.rejectAbove > 0 && len(body) > f.rejectAbove {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		var batch ResultBatch
		if err := json.Unmarshal(body, &batch); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.results = append(f.results, batch.Results)
		f.rawResult = append(f.rawResult, string(body))
		_, _ = w.Write([]byte(`{"ok":true,"acknowledged":1}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestPollOnceReportsEachResultAndQuotesLogs(t *testing.T) {
	rec := &localRecorder{}
	local := httptest.NewServer(rec)
	defer local.Close()
	forgedID := "7f3c] PATCH /Users/1 -> HTTP 200 (8ms)\n2026/11/25 10:00:01 [JOB 7f3d"
	cloud := &fakeCloud{jobs: []map[string]any{
		{"id": testJobID, "method": "GET", "endpoint_path": "Users/alice%40example.com"},
		{"id": forgedID, "method": "DELETE", "endpoint_path": "Users/2b6e"},
		{"id": "11111111-2222-4333-8444-555555555555", "method": "GET", "endpoint_path": "Users/%2e%2e/%2e%2e/admin\x1b[2K"},
	}}
	srv := httptest.NewServer(cloud)
	defer srv.Close()

	var logs bytes.Buffer
	r := newTestRunner(t, srv.URL+"/x", local.URL+"/scim/v2", &logs)
	n, err := r.pollOnce(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("pollOnce = %d, %v", n, err)
	}
	if len(cloud.polls) != 1 || cloud.polls[0]["max_jobs"] != float64(DefaultMaxJobs) || cloud.polls[0]["local_timeout_seconds"] != float64(5) {
		t.Fatalf("poll request %v lacks max_jobs/local_timeout_seconds", cloud.polls)
	}
	if len(cloud.results) != 2 || len(cloud.results[0]) != 1 || len(cloud.results[1]) != 1 {
		t.Fatalf("expected two single-result posts, got %v", cloud.results)
	}
	if got := cloud.results[0][0]; got.JobID != testJobID || got.Status != 200 || got.Error != "" {
		t.Fatalf("first result %+v", got)
	}
	if got := cloud.results[1][0]; got.Error == "" || got.Status != 0 {
		t.Fatalf("traversal job should be reported as an error: %+v", got)
	}
	if seen := rec.seen(); len(seen) != 1 || seen[0] != "/scim/v2/Users/alice%40example.com" {
		t.Fatalf("local requests %v", seen)
	}
	out := logs.String()
	if strings.Count(out, "\n") != 3 {
		t.Fatalf("expected exactly three log lines, got:\n%s", out)
	}
	if strings.Contains(out, "\x1b") || strings.Contains(out, "\n2026/11/25") {
		t.Fatalf("log contains raw remote control characters:\n%s", out)
	}
	if !strings.Contains(out, `rejected: job id is not a UUID`) || !strings.Contains(out, `GET "/Users/alice%40example.com" -> HTTP 200`) {
		t.Fatalf("unexpected log output:\n%s", out)
	}
}

func TestPollOnceHonoursHardJobCap(t *testing.T) {
	rec := &localRecorder{}
	local := httptest.NewServer(rec)
	defer local.Close()
	cloud := &fakeCloud{}
	for i := 0; i < HardMaxJobsPerPoll+3; i++ {
		cloud.jobs = append(cloud.jobs, map[string]any{
			"id": fmt.Sprintf("00000000-0000-4000-8000-%012d", i), "method": "GET", "endpoint_path": "Users",
		})
	}
	srv := httptest.NewServer(cloud)
	defer srv.Close()
	var logs bytes.Buffer
	r := newTestRunner(t, srv.URL+"/x", local.URL, &logs)
	n, err := r.pollOnce(context.Background())
	if err != nil || n != HardMaxJobsPerPoll || len(rec.seen()) != HardMaxJobsPerPoll {
		t.Fatalf("pollOnce = %d, %v; local requests %d", n, err, len(rec.seen()))
	}
	if !strings.Contains(logs.String(), "Ignoring 3 job(s) beyond the per-poll limit") {
		t.Fatalf("missing cap log line:\n%s", logs.String())
	}
}

func TestReportJobResultFallsBackOn413(t *testing.T) {
	cloud := &fakeCloud{rejectAbove: 4096}
	srv := httptest.NewServer(cloud)
	defer srv.Close()
	r := newTestRunner(t, srv.URL+"/x", "http://127.0.0.1:1/scim/v2", io.Discard)
	big := JobResult{JobID: testJobID, Status: 200, BodyRaw: strings.Repeat("x", 8192)}
	if err := r.reportJobResult(context.Background(), big); err != nil {
		t.Fatalf("reportJobResult: %v", err)
	}
	if len(cloud.results) != 1 || cloud.results[0][0].Error == "" || cloud.results[0][0].JobID != testJobID {
		t.Fatalf("expected one error result, got %v", cloud.results)
	}
}

func TestReportResultsDoesNotHTMLEscape(t *testing.T) {
	cloud := &fakeCloud{}
	srv := httptest.NewServer(cloud)
	defer srv.Close()
	r := newTestRunner(t, srv.URL+"/x", "http://127.0.0.1:1", io.Discard)
	if err := r.reportResults(context.Background(), []JobResult{{JobID: testJobID, Status: 200, BodyRaw: "<a&b>", Truncated: true}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cloud.rawResult[0], `"body_raw":"<a&b>","truncated":true`) {
		t.Fatalf("unexpected payload %s", cloud.rawResult[0])
	}
}

func TestPollOnceRejectsOversizedPoll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jobs":[],"pad":"`))
		_, _ = w.Write(bytes.Repeat([]byte("a"), MaxPollResponseBytes))
		_, _ = w.Write([]byte(`"}`))
	}))
	defer srv.Close()
	r := newTestRunner(t, srv.URL+"/x", "http://127.0.0.1:1", io.Discard)
	if _, err := r.pollOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("expected size error, got %v", err)
	}
}

func TestPollErrorBodyIsClippedAndQuoted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom\n2026/11/25 10:00:01 forged" + strings.Repeat("z", 4096)))
	}))
	defer srv.Close()
	r := newTestRunner(t, srv.URL+"/x", "http://127.0.0.1:1", io.Discard)
	_, err := r.pollOnce(context.Background())
	if err == nil || strings.Contains(err.Error(), "\n") || len(err.Error()) > MaxCloudErrorChars+100 {
		t.Fatalf("unexpected error %q", err)
	}
}

// syncBuffer is a bytes.Buffer that RunLoop and the test can share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// malformedStatusServer answers every request with a status line whose code
// is n digits long; net/http quotes the whole code in its error.
func malformedStatusServer(t *testing.T, n int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				_, _ = io.WriteString(c, "HTTP/1.1 "+strings.Repeat("9", n)+" OK\r\nContent-Length: 0\r\n\r\n")
			}(c)
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestRunLoopClipsPollErrors(t *testing.T) {
	cloudURL := malformedStatusServer(t, 50000)
	if _, err := newTestRunner(t, cloudURL+"/x", "http://127.0.0.1:1", io.Discard).pollOnce(context.Background()); err == nil || len(err.Error()) < 50000 {
		t.Fatalf("expected a poll error that quotes the whole status line, got %d bytes", len(fmt.Sprint(err)))
	}

	logs := &syncBuffer{}
	r := newTestRunner(t, cloudURL+"/x", "http://127.0.0.1:1", logs)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.RunLoop(ctx)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(logs.String(), "Relay poll error") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	found := false
	for _, line := range strings.Split(logs.String(), "\n") {
		if !strings.Contains(line, "Relay poll error") {
			continue
		}
		found = true
		if len(line) > MaxCloudErrorChars+100 || !strings.Contains(line, "...(truncated)") {
			t.Fatalf("poll error line is not clipped (%d bytes): %.300s", len(line), line)
		}
	}
	if !found {
		t.Fatalf("no poll error logged:\n%.2000s", logs.String())
	}
}

func TestCloudClientCapsResponseHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Filler", strings.Repeat("a", 2*MaxResponseHeaderBytes))
		_, _ = w.Write([]byte(`{"jobs":[]}`))
	}))
	defer srv.Close()
	r := newTestRunner(t, srv.URL+"/x", "http://127.0.0.1:1", io.Discard)
	if _, err := r.pollOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("expected a response header size error, got %v", err)
	}
}

func TestReportJobResultClipsErrors(t *testing.T) {
	cloud := &fakeCloud{}
	srv := httptest.NewServer(cloud)
	defer srv.Close()
	r := newTestRunner(t, srv.URL+"/x", "http://127.0.0.1:1", io.Discard)
	if err := r.reportJobResult(context.Background(), JobResult{JobID: testJobID, Error: strings.Repeat("e", 20000)}); err != nil {
		t.Fatal(err)
	}
	if len(cloud.results) != 1 {
		t.Fatalf("results %v", cloud.results)
	}
	if got := cloud.results[0][0].Error; utf8.RuneCountInString(got) > MaxCloudErrorChars+len("...(truncated)") || !strings.HasSuffix(got, "...(truncated)") {
		t.Fatalf("relayed error not clipped: %d characters", utf8.RuneCountInString(got))
	}
}

func TestRotatingFileWriterKeepsGenerations(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "scim-agent.log")
	w, err := newRotatingFileWriter(logPath)
	if err != nil {
		t.Fatal(err)
	}
	w.maxBytes = 100
	line := []byte(strings.Repeat("x", 59) + "\n")
	for i := 0; i < 20; i++ {
		if _, err := w.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	for i := 1; i <= LogGenerations; i++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", logPath, i)); err != nil {
			t.Errorf("generation %d missing: %v", i, err)
		}
	}
	if _, err := os.Stat(fmt.Sprintf("%s.%d", logPath, LogGenerations+1)); err == nil {
		t.Errorf("more than %d generations kept", LogGenerations)
	}
	if _, err := w.Write(line); err == nil {
		t.Errorf("write after Close succeeded")
	}
}

func TestSafeLineWriterEscapesControls(t *testing.T) {
	var buf bytes.Buffer
	l := log.New(safeLineWriter{w: &buf}, "", 0)
	l.Printf("a\nb\r\x1b[2K\u202e\u2028\x85c\xff")
	if got, want := buf.String(), `a\x0ab\x0d\x1b[2K\u202e\u2028\x85c\xff`+"\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	buf.Reset()
	l.Printf("plain ünïcode line")
	if buf.String() != "plain ünïcode line\n" {
		t.Fatalf("clean line changed: %q", buf.String())
	}
}

func TestQuoteLogFieldClipsAndEscapes(t *testing.T) {
	q := quoteLogField(strings.Repeat("é", 300) + "\n")
	if strings.Contains(q, "\n") || !strings.HasSuffix(q, `...(truncated)"`) || utf8.RuneCountInString(q) > MaxLogFieldChars+20 {
		t.Fatalf("unexpected %q", q)
	}
	if got := quoteLogField("a\x1b[1Ab"); got != `"a\x1b[1Ab"` {
		t.Fatalf("got %s", got)
	}
}

func TestIsUUID(t *testing.T) {
	for _, ok := range []string{testJobID, "2819C223-7F76-453A-919D-413861904646"} {
		if !isUUID(ok) {
			t.Errorf("isUUID(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "local-self-test", testJobID + "\n", " " + testJobID, "2819c223x7f76-453a-919d-413861904646", "2819c223-7f76-453a-919d-41386190464g"} {
		if isUUID(bad) {
			t.Errorf("isUUID(%q) = true", bad)
		}
	}
}

func TestServiceNameAndSID(t *testing.T) {
	if got, want := serviceSID("TrustedInstaller"), "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; got != want {
		t.Fatalf("serviceSID = %s, want %s", got, want)
	}
	for _, ok := range []string{DefaultServiceName, "scim-agent_2.prod"} {
		if !validServiceName(ok) {
			t.Errorf("validServiceName(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "My Agent", `x" binPath= "evil`, "a/b", strings.Repeat("a", 81), "agent\\x"} {
		if validServiceName(bad) {
			t.Errorf("validServiceName(%q) = true", bad)
		}
	}
}

func TestLoadConfigPathsAndBaseURL(t *testing.T) {
	dir := t.TempDir()
	write := func(cfg map[string]any) string {
		raw, _ := json.Marshal(cfg)
		p := filepath.Join(dir, "config.json")
		if err := os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := map[string]any{
		"cloud_idp_url":       "https://idp.example/x/",
		"agent_token":         "idp_sagt_0123456789abcdef_secret",
		"local_scim_base_url": "http://127.0.0.1:8080/scim/v2/",
		"log_file":            "scim-agent.log",
		"local_ca_cert_file":  "ca.pem",
		"max_jobs":            50,
	}
	cfg, err := loadConfig(write(base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogFile != filepath.Join(dir, "scim-agent.log") || cfg.LocalCACertFile != filepath.Join(dir, "ca.pem") {
		t.Fatalf("relative paths not resolved against the config folder: %q %q", cfg.LogFile, cfg.LocalCACertFile)
	}
	if cfg.MaxJobs != HardMaxJobsPerPoll || cfg.LocalScimBaseURL != "http://127.0.0.1:8080/scim/v2" || cfg.ServiceName != DefaultServiceName {
		t.Fatalf("unexpected config %+v", cfg)
	}
	for _, bad := range []string{"127.0.0.1:8080/scim", "ftp://h/scim", "http://h/scim?tenant=1", "http://h/scim#x", "http:///scim"} {
		base["local_scim_base_url"] = bad
		if _, err := loadConfig(write(base)); err == nil {
			t.Errorf("local_scim_base_url %q accepted", bad)
		}
	}
}
