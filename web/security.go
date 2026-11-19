package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const (
	csrfHeaderName = "X-CSRF-Token"
	csrfCookieName = "csrf_token"
)

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

func isWriteMethod(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
		return true
	}
	return false
}

// Per-IP login failure limiter (5 failures => 30 minute lock).
const (
	maxLoginFailures  = 5
	loginLockDuration = 30 * time.Minute
)

type ipLoginState struct {
	failures    int
	lockedUntil time.Time
}

var (
	ipLoginMu     sync.Mutex
	ipLoginStates = map[string]*ipLoginState{}
)

func loginLocked(ip string) bool {
	ipLoginMu.Lock()
	defer ipLoginMu.Unlock()
	st := ipLoginStates[ip]
	if st == nil {
		return false
	}
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
		st = &ipLoginState{}
		ipLoginStates[ip] = st
	}
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
