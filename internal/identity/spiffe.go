// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	spiffeBundleRefreshDefault = 5 * time.Minute
	spiffeBundleRefreshMax     = 5 * time.Minute
	spiffeBundleRequestTimeout = 10 * time.Second
	spiffeBundleMaxBytes       = 1 << 20
	spiffeJWTLeeway            = 30 * time.Second
)

var spiffeJWTAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// SPIFFETrustDomainFromJWT reads only an unverified sub claim to select an
// explicitly configured trust domain. The returned domain is not trusted
// until the token signature has been verified against that domain's bundle.
func SPIFFETrustDomainFromJWT(raw string) (string, bool, error) {
	claims := jwt.MapClaims{}
	if _, _, err := new(jwt.Parser).ParseUnverified(raw, claims); err != nil {
		return "", false, nil
	}
	sub, ok := claims["sub"].(string)
	if !ok || !strings.HasPrefix(sub, "spiffe://") {
		return "", false, nil
	}
	domain, err := SPIFFETrustDomainFromID(sub)
	return domain, true, err
}

// SPIFFETrustDomainFromID validates the SPIFFE URI shape and returns its
// trust-domain authority.
func SPIFFETrustDomainFromID(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid SPIFFE ID: %w", err)
	}
	if u.Scheme != "spiffe" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Host == "" || u.Host != u.Hostname() || u.Port() != "" || !strings.HasPrefix(u.Path, "/") || u.Path == "" {
		return "", fmt.Errorf("invalid SPIFFE ID %q: expected spiffe://trust-domain/path", raw)
	}
	domain := u.Hostname()
	if domain != strings.ToLower(domain) || !validSPIFFETrustDomain(domain) {
		return "", fmt.Errorf("invalid SPIFFE ID %q: invalid trust domain", raw)
	}
	return domain, nil
}

func validSPIFFETrustDomain(domain string) bool {
	if net.ParseIP(domain) != nil {
		return true
	}
	if domain == "" || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || !spiffeAlphaNumeric(label[0]) || !spiffeAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !spiffeAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func spiffeAlphaNumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

type spiffeBundleEndpoint struct {
	url        string
	mu         sync.Mutex
	bundle     *spiffeJWTBundle
	refreshAt time.Time
}

type SPIFFEBundleManager struct {
	endpoints map[string]*spiffeBundleEndpoint
	client    *http.Client
}

// NewSPIFFEBundleManager accepts repeated "<trust-domain>=<https-url>" values.
// Endpoints are configured out of band and are never derived from JWT data.
func NewSPIFFEBundleManager(values []string) (*SPIFFEBundleManager, error) {
	if len(values) == 0 {
		return nil, nil
	}
	m := &SPIFFEBundleManager{
		endpoints: make(map[string]*spiffeBundleEndpoint, len(values)),
		client: &http.Client{
			Timeout: spiffeBundleRequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.Hostname() == "" ||
					req.URL.User != nil || req.URL.Fragment != "" {
					return errors.New("SPIFFE bundle redirect must remain HTTPS and contain no userinfo or fragment")
				}
				return nil
			},
		},
	}
	for _, value := range values {
		domain, endpoint, ok := strings.Cut(strings.TrimSpace(value), "=")
		domain, endpoint = strings.TrimSpace(domain), strings.TrimSpace(endpoint)
		if !ok || domain != strings.ToLower(domain) || !validSPIFFETrustDomain(domain) {
			return nil, fmt.Errorf("invalid --spiffe-bundle-endpoint %q: expected <lowercase-trust-domain>=<https-url>", value)
		}
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return nil, fmt.Errorf("invalid SPIFFE bundle endpoint for %q: expected an HTTPS URL without userinfo or fragment", domain)
		}
		if _, exists := m.endpoints[domain]; exists {
			return nil, fmt.Errorf("duplicate SPIFFE bundle endpoint for trust domain %q", domain)
		}
		m.endpoints[domain] = &spiffeBundleEndpoint{url: u.String()}
	}
	return m, nil
}

type spiffeJWTBundle struct {
	keys         []spiffeJWTKey
	sequence     uint64
	hasSequence  bool
	refreshHint  time.Duration
	contentHash  [32]byte
}

type spiffeJWTKey struct {
	kid string
	key any
	alg string
}

// VerifyJWT verifies a JWT-SVID against only the bundle configured for the
// subject's trust domain. A refresh failure is fail-closed once the refresh
// hint expires; stale keys are never used indefinitely.
func (m *SPIFFEBundleManager) VerifyJWT(ctx context.Context, raw, domain string, audiences []string) (jwt.MapClaims, time.Time, error) {
	if m == nil {
		return nil, time.Time{}, errors.New("no SPIFFE bundle endpoints are configured")
	}
	if len(audiences) == 0 {
		return nil, time.Time{}, errors.New("no allowed audience is configured for JWT-SVID verification")
	}
	state, ok := m.endpoints[domain]
	if !ok {
		return nil, time.Time{}, fmt.Errorf("SPIFFE trust domain %q is not configured", domain)
	}
	bundle, err := m.getBundle(ctx, state)
	if err != nil {
		return nil, time.Time{}, err
	}
	return verifySPIFFEJWT(raw, domain, audiences, bundle.keys)
}

func (m *SPIFFEBundleManager) getBundle(ctx context.Context, state *spiffeBundleEndpoint) (*spiffeJWTBundle, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.bundle != nil && time.Now().Before(state.refreshAt) {
		return state.bundle, nil
	}
	next, err := m.fetchBundle(ctx, state.url)
	if err != nil {
		return nil, fmt.Errorf("refresh SPIFFE bundle: %w", err)
	}
	if state.bundle != nil && state.bundle.hasSequence {
		if !next.hasSequence || next.sequence < state.bundle.sequence {
			return nil, fmt.Errorf("SPIFFE bundle sequence rollback or removal for trust domain %q", state.url)
		}
		if next.sequence == state.bundle.sequence && next.contentHash != state.bundle.contentHash {
			return nil, fmt.Errorf("SPIFFE bundle changed without advancing spiffe_sequence for %q", state.url)
		}
	}
	state.bundle = next
	state.refreshAt = time.Now().Add(next.refreshHint)
	return next, nil
}

func (m *SPIFFEBundleManager) fetchBundle(ctx context.Context, endpoint string) (*spiffeJWTBundle, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, spiffeBundleMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > spiffeBundleMaxBytes {
		return nil, fmt.Errorf("SPIFFE bundle exceeds %d bytes", spiffeBundleMaxBytes)
	}
	return parseSPIFFEJWTBundle(body)
}

func parseSPIFFEJWTBundle(body []byte) (*spiffeJWTBundle, error) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	var set map[string]json.RawMessage
	if err := dec.Decode(&set); err != nil {
		return nil, fmt.Errorf("decode SPIFFE JWK set: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("SPIFFE JWK set contains trailing JSON data")
		}
		return nil, fmt.Errorf("read trailing SPIFFE JWK set data: %w", err)
	}
	keysRaw, ok := set["keys"]
	if !ok {
		return nil, errors.New("SPIFFE JWK set has no keys member")
	}
	var rawKeys []json.RawMessage
	if err := json.Unmarshal(keysRaw, &rawKeys); err != nil || rawKeys == nil {
		return nil, errors.New("SPIFFE JWK set keys member must be an array")
	}
	bundle := &spiffeJWTBundle{refreshHint: spiffeBundleRefreshDefault, contentHash: sha256.Sum256(body)}
	if raw, ok := set["spiffe_sequence"]; ok {
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("invalid spiffe_sequence: %w", err)
		}
		seq, err := strconv.ParseUint(n.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid spiffe_sequence %q: %w", n.String(), err)
		}
		bundle.sequence, bundle.hasSequence = seq, true
	}
	if raw, ok := set["spiffe_refresh_hint"]; ok {
		var n json.Number
		if err := json.Unmarshal(raw, &n); err != nil {
			return nil, fmt.Errorf("invalid spiffe_refresh_hint: %w", err)
		}
		seconds, err := strconv.ParseInt(n.String(), 10, 64)
		if err != nil || seconds <= 0 {
			return nil, errors.New("spiffe_refresh_hint must be a positive integer")
		}
		if seconds > int64(spiffeBundleRefreshMax/time.Second) {
			seconds = int64(spiffeBundleRefreshMax / time.Second)
		}
		bundle.refreshHint = time.Duration(seconds) * time.Second
	}
	seen := make(map[string]bool)
	for i, raw := range rawKeys {
		var jwk struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			N string `json:"n"`
			E string `json:"e"`
			Crv string `json:"crv"`
			X string `json:"x"`
			Y string `json:"y"`
		}
		if err := json.Unmarshal(raw, &jwk); err != nil {
			return nil, fmt.Errorf("decode SPIFFE JWK %d: %w", i, err)
		}
		if jwk.Use != "jwt-svid" {
			continue
		}
		if jwk.Kid == "" || seen[jwk.Kid] {
			return nil, fmt.Errorf("SPIFFE JWT-SVID JWK %d has an empty or duplicate kid", i)
		}
		key, err := parseSPIFFEJWK(jwk.Kty, jwk.Alg, jwk.N, jwk.E, jwk.Crv, jwk.X, jwk.Y)
		if err != nil {
			return nil, fmt.Errorf("invalid SPIFFE JWK %q: %w", jwk.Kid, err)
		}
		seen[jwk.Kid] = true
		bundle.keys = append(bundle.keys, spiffeJWTKey{kid: jwk.Kid, key: key, alg: jwk.Alg})
	}
	return bundle, nil
}

func parseSPIFFEJWK(kty, alg, n, e, crv, x, y string) (any, error) {
	switch kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(n)
		if err != nil || len(nb) == 0 {
			return nil, errors.New("invalid RSA modulus")
		}
		eb, err := base64.RawURLEncoding.DecodeString(e)
		if err != nil || len(eb) == 0 || len(eb) > 4 {
			return nil, errors.New("invalid RSA exponent")
		}
		exponent := new(big.Int).SetBytes(eb)
		if !exponent.IsInt64() || exponent.Int64() < 3 || exponent.Int64()%2 == 0 {
			return nil, errors.New("invalid RSA exponent")
		}
		modulus := new(big.Int).SetBytes(nb)
		if modulus.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA modulus is too small: %d bits", modulus.BitLen())
		}
		if alg != "" && !containsSPIFFEString([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}, alg) {
			return nil, fmt.Errorf("algorithm %q is not supported for RSA", alg)
		}
		return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		var expected string
		switch crv {
		case "P-256":
			curve, expected = elliptic.P256(), "ES256"
		case "P-384":
			curve, expected = elliptic.P384(), "ES384"
		case "P-521":
			curve, expected = elliptic.P521(), "ES512"
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil {
			return nil, errors.New("invalid EC x coordinate")
		}
		yb, err := base64.RawURLEncoding.DecodeString(y)
		if err != nil {
			return nil, errors.New("invalid EC y coordinate")
		}
		xi, yi := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
		if !curve.IsOnCurve(xi, yi) || (alg != "" && alg != expected) {
			return nil, errors.New("invalid EC point or algorithm/curve mismatch")
		}
		return &ecdsa.PublicKey{Curve: curve, X: xi, Y: yi}, nil
	default:
		return nil, fmt.Errorf("unsupported JWK key type %q", kty)
	}
}

func verifySPIFFEJWT(raw, trustDomain string, audiences []string, keys []spiffeJWTKey) (jwt.MapClaims, time.Time, error) {
	if len(keys) == 0 {
		return nil, time.Time{}, fmt.Errorf("SPIFFE trust domain %q has no JWT-SVID keys", trustDomain)
	}
	unverifiedClaims := jwt.MapClaims{}
	unverified, _, err := new(jwt.Parser).ParseUnverified(raw, unverifiedClaims)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse JWT-SVID: %w", err)
	}
	for name := range unverified.Header {
		if name != "alg" && name != "kid" && name != "typ" {
			return nil, time.Time{}, fmt.Errorf("unsupported JWT-SVID JOSE header %q", name)
		}
	}
	alg, ok := unverified.Header["alg"].(string)
	if !ok || !containsSPIFFEString(spiffeJWTAlgorithms, alg) {
		return nil, time.Time{}, fmt.Errorf("unsupported JWT-SVID algorithm %q", alg)
	}
	if typ, ok := unverified.Header["typ"].(string); ok && typ != "JWT" && typ != "JOSE" {
		return nil, time.Time{}, fmt.Errorf("unsupported JWT-SVID typ %q", typ)
	}
	kid, hasKid := unverified.Header["kid"].(string)
	if rawKid, exists := unverified.Header["kid"]; exists && (!hasKid || rawKid == "") {
		return nil, time.Time{}, errors.New("invalid JWT-SVID kid")
	}
	sub, _ := unverifiedClaims["sub"].(string)
	domain, err := SPIFFETrustDomainFromID(sub)
	if err != nil || domain != trustDomain {
		return nil, time.Time{}, fmt.Errorf("JWT-SVID subject does not belong to trust domain %q", trustDomain)
	}

	var lastErr error
	for _, candidate := range keys {
		if (hasKid && candidate.kid != kid) || (candidate.alg != "" && candidate.alg != alg) || !spiffeKeySupportsAlg(candidate.key, alg) {
			continue
		}
		claims := jwt.MapClaims{}
		parsed, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
			return candidate.key, nil
		}, jwt.WithValidMethods(spiffeJWTAlgorithms), jwt.WithAudience(audiences...), jwt.WithExpirationRequired(), jwt.WithLeeway(spiffeJWTLeeway))
		if err != nil {
			lastErr = err
			continue
		}
		if parsed == nil || !parsed.Valid {
			lastErr = errors.New("JWT-SVID signature or claims are invalid")
			continue
		}
		verifiedSub, _ := claims["sub"].(string)
		verifiedDomain, err := SPIFFETrustDomainFromID(verifiedSub)
		if err != nil || verifiedDomain != trustDomain {
			return nil, time.Time{}, fmt.Errorf("verified JWT-SVID subject is outside trust domain %q", trustDomain)
		}
		aud, err := claims.GetAudience()
		if err != nil || !hasSPIFFEAudience(aud, audiences) {
			return nil, time.Time{}, errors.New("JWT-SVID audience does not match configured audiences")
		}
		exp, err := claims.GetExpirationTime()
		if err != nil || exp == nil {
			return nil, time.Time{}, errors.New("JWT-SVID is missing exp")
		}
		return claims, exp.Time, nil
	}
	if lastErr == nil && hasKid {
		lastErr = fmt.Errorf("JWT-SVID kid %q is not in the configured bundle", kid)
	}
	if lastErr == nil {
		lastErr = errors.New("no bundle key supports the JWT-SVID algorithm")
	}
	return nil, time.Time{}, fmt.Errorf("JWT-SVID verification failed: %w", lastErr)
}

func spiffeKeySupportsAlg(key any, alg string) bool {
	switch publicKey := key.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case *ecdsa.PublicKey:
		switch publicKey.Curve.Params().Name {
		case "P-256":
			return alg == "ES256"
		case "P-384":
			return alg == "ES384"
		case "P-521":
			return alg == "ES512"
		}
	}
	return false
}

func containsSPIFFEString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func hasSPIFFEAudience(tokenAud, allowed []string) bool {
	for _, got := range tokenAud {
		for _, want := range allowed {
			if got == want {
				return true
			}
		}
	}
	return false
}
