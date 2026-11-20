package web

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jeessy2/ddns-go/v6/util"
)

func resetLoginStatesForTest() {
	ipLoginMu.Lock()
	defer ipLoginMu.Unlock()
	ipLoginStates = map[string]*ipLoginState{}
}

func TestLoginLockAfterFiveFailures(t *testing.T) {
	resetLoginStatesForTest()
	defer resetLoginStatesForTest()

	const ip = "192.0.2.10"
	for i := 0; i < maxLoginFailures-1; i++ {
		recordLoginFailure(ip)
		if loginLocked(ip) {
			t.Fatalf("IP locked after %d failures, want %d", i+1, maxLoginFailures)
		}
	}
	recordLoginFailure(ip)
	if !loginLocked(ip) {
		t.Fatalf("IP not locked after %d failures", maxLoginFailures)
	}
}

func TestResetLoginUnlocks(t *testing.T) {
	resetLoginStatesForTest()
	defer resetLoginStatesForTest()

	const ip = "192.0.2.11"
	for i := 0; i < maxLoginFailures; i++ {
		recordLoginFailure(ip)
	}
	if !loginLocked(ip) {
		t.Fatal("IP should be locked before reset")
	}
	resetLogin(ip)
	if loginLocked(ip) {
		t.Fatal("IP still locked after reset")
	}
	// A fresh sequence from zero must be required again.
	for i := 0; i < maxLoginFailures-1; i++ {
		recordLoginFailure(ip)
	}
	if loginLocked(ip) {
		t.Fatal("failures not reset by resetLogin")
	}
}

func TestLoginLockExpires(t *testing.T) {
	resetLoginStatesForTest()
	defer resetLoginStatesForTest()

	const ip = "192.0.2.12"
	ipLoginMu.Lock()
	ipLoginStates[ip] = &ipLoginState{
		failures:    maxLoginFailures,
		lockedUntil: time.Now().Add(-time.Minute),
		lastSeen:    time.Now(),
	}
	ipLoginMu.Unlock()

	if loginLocked(ip) {
		t.Fatal("expired lock still reports locked")
	}
	ipLoginMu.Lock()
	st := ipLoginStates[ip]
	expiredStateReset := st != nil && st.failures == 0 && st.lockedUntil.IsZero()
	ipLoginMu.Unlock()
	if !expiredStateReset {
		t.Fatal("expired lock state was not cleared")
	}
}

func TestRecordLoginFailurePrunesStaleStates(t *testing.T) {
	resetLoginStatesForTest()
	defer resetLoginStatesForTest()

	ipLoginMu.Lock()
	for i := 0; i < maxLoginTrackedIPs; i++ {
		ipLoginStates[ipForTest(i)] = &ipLoginState{
			lastSeen: time.Now().Add(-2 * loginLockDuration),
		}
	}
	ipLoginMu.Unlock()

	recordLoginFailure("192.0.2.200")
	ipLoginMu.Lock()
	size := len(ipLoginStates)
	_, added := ipLoginStates["192.0.2.200"]
	ipLoginMu.Unlock()
	if size > maxLoginTrackedIPs {
		t.Fatalf("tracked IP map grew beyond cap: %d", size)
	}
	if !added {
		t.Fatal("new IP was not recorded after pruning")
	}
}

func ipForTest(i int) string {
	return "192.0.2." + string(rune('1'+i%9)) + "." + string(rune('1'+i/9%100))
}

func TestLoginRateLimitConcurrent(t *testing.T) {
	resetLoginStatesForTest()
	defer resetLoginStatesForTest()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ip := "198.51.100.1"
			recordLoginFailure(ip)
			loginLocked(ip)
		}()
	}
	wg.Wait()
	ipLoginMu.Lock()
	st := ipLoginStates["198.51.100.1"]
	failures := 0
	if st != nil {
		failures = st.failures
	}
	ipLoginMu.Unlock()
	if failures != goroutines {
		t.Fatalf("lost concurrent failures: got %d, want %d", failures, goroutines)
	}
}

func TestClientIPForRateLimit(t *testing.T) {
	t.Setenv(proxyTrustEnv, "")

	r := httptest.NewRequest(http.MethodPost, "/loginFunc", nil)
	r.RemoteAddr = "203.0.113.5:40404"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	if got := clientIPForRateLimit(r); got != "203.0.113.5" {
		t.Fatalf("untrusted proxy: got %q, want 203.0.113.5", got)
	}

	t.Setenv(proxyTrustEnv, "true")
	r.RemoteAddr = "127.0.0.1:8080"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := clientIPForRateLimit(r); got != "203.0.113.9" {
		t.Fatalf("trusted proxy: got %q, want 203.0.113.9", got)
	}

	r.RemoteAddr = "203.0.113.5:8080"
	if got := clientIPForRateLimit(r); got != "203.0.113.5" {
		t.Fatalf("non-private peer: got %q, want 203.0.113.5", got)
	}
}

func TestValidCsrfWithOrigin(t *testing.T) {
	const token = "csrf-token-value"
	newRequest := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://example.com/loginFunc", nil)
		r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})
		r.Header.Set(csrfHeaderName, token)
		return r
	}

	t.Setenv(proxyTrustEnv, "")

	r := newRequest()
	r.Header.Set("Origin", "https://evil.example")
	if validCsrfWithOrigin(r) {
		t.Fatal("cross-site Origin accepted")
	}

	r = newRequest()
	r.Header.Set("Origin", "http://example.com")
	if !validCsrfWithOrigin(r) {
		t.Fatal("same-site Origin rejected")
	}

	r = newRequest()
	r.Header.Set("Origin", "https://example.com")
	if validCsrfWithOrigin(r) {
		t.Fatal("scheme mismatch accepted")
	}

	r = newRequest()
	r.Header.Set("Referer", "http://example.com/login")
	if !validCsrfWithOrigin(r) {
		t.Fatal("same-site Referer rejected")
	}

	r = newRequest()
	r.Header.Set("Referer", "https://evil.example/phish")
	if validCsrfWithOrigin(r) {
		t.Fatal("cross-site Referer accepted")
	}

	// No Origin/Referer: fall back to the double-submit cookie check.
	r = newRequest()
	if !validCsrfWithOrigin(r) {
		t.Fatal("valid cookie+header without Origin/Referer rejected")
	}
	r = newRequest()
	r.Header.Del(csrfHeaderName)
	if validCsrfWithOrigin(r) {
		t.Fatal("missing CSRF header accepted")
	}
}

func TestRotateAndClearCsrfCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	newToken := rotateCsrfCookie(rec)
	if newToken == "" {
		t.Fatal("rotateCsrfCookie returned empty token")
	}
	var rotateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			rotateCookie = c
		}
	}
	if rotateCookie == nil || rotateCookie.Value != newToken {
		t.Fatal("rotated cookie not written to response")
	}

	rec = httptest.NewRecorder()
	clearCsrfCookie(rec)
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName && c.MaxAge < 0 {
			return
		}
	}
	t.Fatal("csrf cookie was not cleared")
}

func TestTrustedOriginHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "[::1]", "192.168.1.1"} {
		if !trustedOriginHost(host) {
			t.Errorf("%q should be trusted", host)
		}
	}
	if trustedOriginHost("evil.example") {
		t.Error("public host should not be trusted")
	}
}

func TestPrivateNetworkHelperUsedByRateLimit(t *testing.T) {
	if !util.IsPrivateNetwork("10.0.0.1:1234") {
		t.Fatal("expected private network helper to recognize 10/8")
	}
}
