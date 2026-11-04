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
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSPIFFETrustDomainFromID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want string
		ok   bool
	}{
		{name: "valid", id: "spiffe://example.org/ns/app", want: "example.org", ok: true},
		{name: "valid root path", id: "spiffe://example.org/", want: "example.org", ok: true},
		{name: "wrong scheme", id: "https://example.org/ns/app"},
		{name: "missing path", id: "spiffe://example.org"},
		{name: "query", id: "spiffe://example.org/ns/app?x=y"},
		{name: "fragment", id: "spiffe://example.org/ns/app#part"},
		{name: "userinfo", id: "spiffe://user@example.org/ns/app"},
		{name: "port", id: "spiffe://example.org:8080/ns/app"},
		{name: "uppercase domain", id: "spiffe://Example.org/ns/app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SPIFFETrustDomainFromID(tt.id)
			if tt.ok {
				if err != nil || got != tt.want {
					t.Fatalf("SPIFFETrustDomainFromID(%q) = %q, %v; want %q, nil", tt.id, got, err, tt.want)
				}
			} else if err == nil {
				t.Fatalf("SPIFFETrustDomainFromID(%q) = %q, nil; want an error", tt.id, got)
			}
		})
	}
}

func TestNewSPIFFEBundleManagerValidatesEndpoints(t *testing.T) {
	tests := []struct {
		name  string
		value []string
		want  bool
	}{
		{name: "empty", value: nil, want: true},
		{name: "valid", value: []string{"example.org=https://spire.example.org/bundle"}, want: true},
		{name: "http rejected", value: []string{"example.org=http://spire.example.org/bundle"}},
		{name: "missing domain", value: []string{"=https://spire.example.org/bundle"}},
		{name: "userinfo rejected", value: []string{"example.org=https://user@spire.example.org/bundle"}},
		{name: "duplicate domain", value: []string{"example.org=https://one.example.org/bundle", "example.org=https://two.example.org/bundle"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewSPIFFEBundleManager(tt.value)
			if tt.want && err != nil {
				t.Fatalf("NewSPIFFEBundleManager(%v) failed: %v", tt.value, err)
			}
			if !tt.want && err == nil {
				t.Fatalf("NewSPIFFEBundleManager(%v) succeeded, want error", tt.value)
			}
			if tt.name == "empty" && manager != nil {
				t.Fatalf("empty endpoint list returned manager %v, want nil", manager)
			}
		})
	}
}

func TestParseSPIFFEJWTBundle(t *testing.T) {
	key := newSPIFFETestRSAKey(t)
	body := spiffeTestBundle(t, key, 7)
	bundle, err := parseSPIFFEJWTBundle(body)
	if err != nil {
		t.Fatalf("parseSPIFFEJWTBundle failed: %v", err)
	}
	if !bundle.hasSequence || bundle.sequence != 7 {
		t.Fatalf("bundle sequence = (%d, %v), want (7, true)", bundle.sequence, bundle.hasSequence)
	}
	if bundle.refreshHint != 5*time.Minute {
		t.Fatalf("bundle refresh hint = %s, want 5m", bundle.refreshHint)
	}
	if len(bundle.keys) != 1 || bundle.keys[0].kid != "key-1" {
		t.Fatalf("bundle JWT-SVID keys = %+v, want only key-1", bundle.keys)
	}

	for name, invalid := range map[string][]byte{
		"missing keys":  []byte(`{"spiffe_sequence":1}`),
		"keys not array": []byte(`{"keys":{}}`),
		"invalid sequence": []byte(`{"keys":[],"spiffe_sequence":-1}`),
		"invalid refresh hint": []byte(`{"keys":[],"spiffe_refresh_hint":0}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSPIFFEJWTBundle(invalid); err == nil {
				t.Fatalf("parseSPIFFEJWTBundle(%s) succeeded, want error", name)
			}
		})
	}
}

func TestVerifySPIFFEJWT(t *testing.T) {
	key := newSPIFFETestRSAKey(t)
	bundle, err := parseSPIFFEJWTBundle(spiffeTestBundle(t, key, 1))
	if err != nil {
		t.Fatalf("parse test bundle: %v", err)
	}
	valid := mintSPIFFETestJWT(t, key, "spiffe://example.org/ns/agent", "agentmesh", time.Now().Add(time.Hour), true)
	tests := []struct {
		name      string
		token     string
		domain    string
		audiences []string
		wantError bool
	}{
		{name: "valid", token: valid, domain: "example.org", audiences: []string{"agentmesh"}},
		{name: "wrong trust domain", token: valid, domain: "other.example.org", audiences: []string{"agentmesh"}, wantError: true},
		{name: "wrong audience", token: valid, domain: "example.org", audiences: []string{"other"}, wantError: true},
		{name: "expired", token: mintSPIFFETestJWT(t, key, "spiffe://example.org/ns/agent", "agentmesh", time.Now().Add(-time.Hour), true), domain: "example.org", audiences: []string{"agentmesh"}, wantError: true},
		{name: "missing exp", token: mintSPIFFETestJWT(t, key, "spiffe://example.org/ns/agent", "agentmesh", time.Time{}, false), domain: "example.org", audiences: []string{"agentmesh"}, wantError: true},
		{name: "no allowed audience", token: valid, domain: "example.org", audiences: nil, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, _, err := verifySPIFFEJWT(tt.token, tt.domain, tt.audiences, bundle.keys)
			if tt.wantError && err == nil {
				t.Fatal("verifySPIFFEJWT succeeded, want error")
			}
			if !tt.wantError && (err != nil || claims == nil) {
				t.Fatalf("verifySPIFFEJWT returned claims=%v, err=%v; want verified claims", claims, err)
			}
		})
	}
}

func TestSPIFFEBundleManagerRefreshAndSequenceRollback(t *testing.T) {
	oldKey := newSPIFFETestRSAKey(t)
	newKey := newSPIFFETestRSAKey(t)
	var mu sync.Mutex
	sequence := uint64(1)
	currentKey := oldKey
	fail := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(spiffeTestBundle(t, currentKey, sequence))
	}))
	defer server.Close()

	manager := &SPIFFEBundleManager{
		endpoints: map[string]*spiffeBundleEndpoint{
			"example.org": {url: server.URL},
		},
		client: server.Client(),
	}
	oldToken := mintSPIFFETestJWT(t, oldKey, "spiffe://example.org/ns/agent", "agentmesh", time.Now().Add(time.Hour), true)
	if _, _, err := manager.VerifyJWT(t.Context(), oldToken, "example.org", []string{"agentmesh"}); err != nil {
		t.Fatalf("initial JWT-SVID verification failed: %v", err)
	}

	mu.Lock()
	sequence = 2
	currentKey = newKey
	mu.Unlock()
	manager.endpoints["example.org"].mu.Lock()
	manager.endpoints["example.org"].refreshAt = time.Time{}
	manager.endpoints["example.org"].mu.Unlock()

	newToken := mintSPIFFETestJWT(t, newKey, "spiffe://example.org/ns/agent", "agentmesh", time.Now().Add(time.Hour), true)
	if _, _, err := manager.VerifyJWT(t.Context(), newToken, "example.org", []string{"agentmesh"}); err != nil {
		t.Fatalf("JWT-SVID with rotated key was rejected: %v", err)
	}
	if _, _, err := manager.VerifyJWT(t.Context(), oldToken, "example.org", []string{"agentmesh"}); err == nil {
		t.Fatal("JWT-SVID signed by removed key was accepted after bundle rotation")
	}

	mu.Lock()
	sequence = 1
	mu.Unlock()
	manager.endpoints["example.org"].mu.Lock()
	manager.endpoints["example.org"].refreshAt = time.Time{}
	manager.endpoints["example.org"].mu.Unlock()
	if _, _, err := manager.VerifyJWT(t.Context(), newToken, "example.org", []string{"agentmesh"}); err == nil {
		t.Fatal("bundle sequence rollback was accepted")
	}

	mu.Lock()
	fail = true
	mu.Unlock()
	manager.endpoints["example.org"].mu.Lock()
	manager.endpoints["example.org"].refreshAt = time.Time{}
	manager.endpoints["example.org"].mu.Unlock()
	if _, _, err := manager.VerifyJWT(t.Context(), newToken, "example.org", []string{"agentmesh"}); err == nil {
		t.Fatal("unavailable bundle endpoint was accepted after refresh was due")
	}
}

func newSPIFFETestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test RSA key: %v", err)
	}
	return key
}

func spiffeTestBundle(t *testing.T, key *rsa.PrivateKey, sequence uint64) []byte {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
	body := fmt.Sprintf(`{"spiffe_sequence":%d,"spiffe_refresh_hint":300,"keys":[{"kty":"RSA","use":"jwt-svid","kid":"key-1","alg":"RS256","n":"%s","e":"%s"},{"kty":"RSA","use":"x509-svid","kid":"ignored","n":"%s","e":"%s"}]}`, sequence, n, e, n, e)
	return []byte(body)
}

func mintSPIFFETestJWT(t *testing.T, key *rsa.PrivateKey, subject, audience string, expiry time.Time, includeExpiry bool) string {
	t.Helper()
	claims := jwt.MapClaims{"sub": subject, "aud": []string{audience}}
	if includeExpiry {
		claims["exp"] = expiry.Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "key-1"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign JWT-SVID test token: %v", err)
	}
	if !json.Valid([]byte(`"` + raw + `"`)) {
		t.Fatal("generated JWT-SVID is not valid compact JSON text")
	}
	return raw
}
