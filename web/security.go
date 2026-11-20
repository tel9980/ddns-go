package web

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jeessy2/ddns-go/v6/util"
)

const (
	csrfHeaderName = "X-CSRF-Token"
	csrfCookieName = "csrf_token"
)

// proxyTrustEnv enables X-Forwarded-For handling for rate limiting. It should
// only be set when ddns-go sits behind a trusted reverse proxy.
const proxyTrustEnv = "DDNS_TRUST_PROXY"

func generateCsrfToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	// Extremely unlikely fallback: time-based value, still unique enough per request.
	return hex.EncodeToString([]byte(time.Now().Format("20060102150405.000000000")))
}

func setCsrfCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		Expires:  time.Now().AddDate(0, 0, 30),
		HttpOnly: false, // JS reads this value to send the CSRF header.
		SameSite: http.SameSiteLaxMode,
	})
}

// rotateCsrfCookie issues a fresh CSRF token, invalidating the previous one.
// Called after a successful login so a token issued on the public login page
// cannot be replayed against the now authenticated session.
func rotateCsrfCookie(w http.ResponseWriter) string {
	token := generateCsrfToken()
	setCsrfCookie(w, token)
	return token
}

func clearCsrfCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
}

// ensureCsrfCookie returns the existing CSRF cookie value or issues a new one.
func ensureCsrfCookie(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	token := generateCsrfToken()
	setCsrfCookie(w, token)
	return token
}

func validCsrf(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	return r.Header.Get(csrfHeaderName) == c.Value
}

// requestScheme returns the scheme seen by the service. X-Forwarded-Proto is
// only considered when reverse-proxy support has been explicitly enabled.
func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if r.URL != nil && r.URL.Scheme != "" {
		return strings.ToLower(r.URL.Scheme)
	}
	if strings.EqualFold(os.Getenv(proxyTrustEnv), "true") {
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			// The left-most value is the original scheme chosen by the client.
			return strings.ToLower(strings.TrimSpace(strings.Split(proto, ",")[0]))
		}
	}
	return "http"
}

// trustedOriginHost reports whether an Origin host is local to the server.
// This allows reverse proxies / tunnels to use their own (private) host name
// while still rejecting cross-site origins.
func trustedOriginHost(originHost string) bool {
	host := strings.ToLower(strings.TrimSpace(originHost))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	// net.ParseIP does not accept IPv6 zone identifiers.
	if i := strings.IndexByte(host, '%'); i != -1 {
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return host == "localhost" || host == "localhost.localdomain" || strings.HasSuffix(host, ".localhost")
}

func originMatchesRequest(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Opaque != "" {
		return false
	}

	requestHost := r.Host
	if h, _, err := net.SplitHostPort(requestHost); err == nil {
		// Compare host names only: browsers omit the default port (80/443) in
		// Origin, and reverse proxies may expose a different public port.
		requestHost = h
	}
	originHost := u.Host
	if h, _, err := net.SplitHostPort(originHost); err == nil {
		originHost = h
	}

	if strings.EqualFold(strings.Trim(originHost, "[]"), strings.Trim(requestHost, "[]")) {
		if originURLScheme, requestURLScheme := strings.ToLower(u.Scheme), requestScheme(r); originURLScheme != requestURLScheme {
			// Allow a public HTTPS terminator forwarding plain HTTP internally,
			// but only when proxy support was explicitly enabled.
			if !(originURLScheme == "https" && requestURLScheme == "http" && strings.EqualFold(os.Getenv(proxyTrustEnv), "true")) {
				return false
			}
		}
		return true
	}
	// A trusted reverse proxy may present its own host in Origin; only accept
	// loopback/private hosts when proxy support has been explicitly enabled.
	return strings.EqualFold(os.Getenv(proxyTrustEnv), "true") && trustedOriginHost(originHost)
}

// validCsrfWithOrigin adds Origin/Referer checks on top of the double-submit
// cookie check. It is used for state-changing requests (login and write
// endpoints behind Auth); when neither header is present it falls back to the
// original cookie+header validation.
func validCsrfWithOrigin(r *http.Request) bool {
	if !isWriteMethod(r) {
		return validCsrf(r)
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		return originMatchesRequest(r, origin) && validCsrf(r)
	}
	if referer := r.Header.Get("Referer"); referer != "" {
		u, err := url.Parse(referer)
		if err != nil || !originMatchesRequest(r, u.Scheme+"://"+u.Host) {
			return false
		}
	}
	return validCsrf(r)
}

func isWriteMethod(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

// Per-IP login failure limiter (5 failures => 30 minute lock).
const (
	maxLoginFailures   = 5
	loginLockDuration  = 30 * time.Minute
	maxLoginTrackedIPs = 10000
)

type ipLoginState struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

var (
	ipLoginMu     sync.Mutex
	ipLoginStates = map[string]*ipLoginState{}
)

// clientIPForRateLimit returns the host portion of RemoteAddr by default.
// When DDNS_TRUST_PROXY=true and the immediate peer is private/loopback, the
// left-most (client) entry of X-Forwarded-For is used instead.
func clientIPForRateLimit(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !strings.EqualFold(os.Getenv(proxyTrustEnv), "true") || !util.IsPrivateNetwork(r.RemoteAddr) {
		return host
	}
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded == "" {
		return host
	}
	first := strings.TrimSpace(strings.Split(forwarded, ",")[0])
	if first == "" {
		return host
	}
	if parsed := net.ParseIP(first); parsed != nil {
		return first
	}
	return host
}

// pruneStaleLoginStatesLocked removes entries that have not been seen for the
// duration of a lock (including expired locks). Caller holds ipLoginMu.
func pruneStaleLoginStatesLocked(now time.Time) {
	for ip, st := range ipLoginStates {
		if st.lockedUntil.IsZero() && now.Sub(st.lastSeen) >= loginLockDuration {
			delete(ipLoginStates, ip)
			continue
		}
		if !st.lockedUntil.IsZero() && now.After(st.lockedUntil) {
			delete(ipLoginStates, ip)
		}
	}
}

func loginLocked(ip string) bool {
	ipLoginMu.Lock()
	defer ipLoginMu.Unlock()
	st := ipLoginStates[ip]
	if st == nil {
		return false
	}
	st.lastSeen = time.Now()
	if !st.lockedUntil.IsZero() {
		if time.Now().Before(st.lockedUntil) {
			return true
		}
		st.failures = 0
		st.lockedUntil = time.Time{}
	}
	return false
}

func recordLoginFailure(ip string) {
	ipLoginMu.Lock()
	defer ipLoginMu.Unlock()
	st := ipLoginStates[ip]
	if st == nil {
		// Bound map growth even if an attacker spins up many source IPs.
		if len(ipLoginStates) >= maxLoginTrackedIPs {
			pruneStaleLoginStatesLocked(time.Now())
		}
		if len(ipLoginStates) >= maxLoginTrackedIPs {
			// Still full: drop the oldest unused state to make room.
			var oldestIP string
			var oldest time.Time
			for candidateIP, candidate := range ipLoginStates {
				if !candidate.lockedUntil.IsZero() {
					continue // never drop an actively locked IP
				}
				if oldestIP == "" || candidate.lastSeen.Before(oldest) {
					oldestIP, oldest = candidateIP, candidate.lastSeen
				}
			}
			if oldestIP != "" {
				delete(ipLoginStates, oldestIP)
			}
		}
		st = &ipLoginState{lastSeen: time.Now()}
		ipLoginStates[ip] = st
	}
	st.lastSeen = time.Now()
	st.failures++
	if st.failures >= maxLoginFailures {
		st.lockedUntil = time.Now().Add(loginLockDuration)
	}
}

func resetLogin(ip string) {
	ipLoginMu.Lock()
	defer ipLoginMu.Unlock()
	delete(ipLoginStates, ip)
}
