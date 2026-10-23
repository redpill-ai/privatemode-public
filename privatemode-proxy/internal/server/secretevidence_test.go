// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/edgelesssys/continuum/internal/oss/auth"
	"github.com/edgelesssys/continuum/internal/oss/constants"
	"github.com/edgelesssys/continuum/internal/oss/encbody"
	"github.com/edgelesssys/continuum/internal/oss/forwarder"
	"github.com/edgelesssys/continuum/internal/oss/secretevidence"
	"github.com/edgelesssys/continuum/internal/oss/secretmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretEvidenceEndpoint(t *testing.T) {
	hash := sha256.Sum256([]byte("public key"))
	id := base64.StdEncoding.EncodeToString(hash[:])
	encoded := base64.RawURLEncoding.EncodeToString(hash[:])
	manager := secretmanager.New(func(context.Context, auth.Credential) (string, []byte, error) {
		return id, []byte("private secret"), nil
	}, false).WithEvidence(&secretevidence.Bundle{Attestation: secretevidence.Attestation{Manifest: []byte("manifest")}})
	require.NoError(t, manager.OfferCredential(t.Context(), auth.APIKey("private credential")))
	manager.SetCredential(auth.Credential{}) // Reads must not require credentials or refresh the secret.
	s := New(http.DefaultClient, manager, Opts{SecretEvidence: manager.SecretEvidence}, slog.New(slog.DiscardHandler))
	for name, tc := range map[string]struct {
		method, id string
		status     int
	}{
		"known":        {http.MethodGet, encoded, http.StatusOK},
		"unknown":      {http.MethodGet, base64.RawURLEncoding.EncodeToString(make([]byte, 32)), http.StatusNotFound},
		"malformed":    {http.MethodGet, "bad!", http.StatusBadRequest},
		"wrong length": {http.MethodGet, "YWJj", http.StatusBadRequest},
		"padding":      {http.MethodGet, encoded + "=", http.StatusBadRequest},
		"write":        {http.MethodPost, encoded, http.StatusMethodNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(t.Context(), tc.method, "/privatemode/v1/secret-evidence/"+tc.id, nil)
			r.Header.Set("Authorization", "Bearer ignored")
			s.GetHandler().ServeHTTP(w, r)
			assert.Equal(t, tc.status, w.Code)
			if tc.status != http.StatusOK {
				return
			}
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
			assert.NotContains(t, w.Body.String(), "private")
			var b secretevidence.Bundle
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &b))
			assert.Equal(t, id, b.SecretID)
			assert.Equal(t, []byte("manifest"), b.Manifest)
		})
	}
}

func TestSecretIDBeforeStreamingBody(t *testing.T) {
	secret := secretmanager.Secret{ID: "stream-secret", Data: bytes.Repeat([]byte{0x42}, 32)}
	const events = "data: synthetic\n\ndata: [DONE]\n\n"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		se, err := encbody.InitializeServerExchange(secret.Data, r)
		if !assert.NoError(t, err) {
			return
		}
		if !assert.NoError(t, se.DecryptRequest(r)) {
			return
		}
		response := &forwarder.StreamingResponse{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}},
			Body: io.NopCloser(strings.NewReader(events)),
		}
		if !assert.NoError(t, se.EncryptSSEResponse(response, 1024)) {
			return
		}
		defer response.Body.Close()
		assert.NoError(t, forwarder.SendResponse(w, response))
	}))
	defer backend.Close()
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			s := newTestServer(nil, secret, backend.Listener.Addr().String(), "")
			wantID := ""
			if enabled {
				s.secretEvidence = (&stubSecretManager{}).SecretEvidence
				wantID = secret.ID
			}
			proxy := httptest.NewServer(s.GetHandler())
			defer proxy.Close()
			req := prepareChatRequest(t.Context(), require.New(t), "synthetic", nil, "")
			req.URL.Scheme = "http"
			req.URL.Host = proxy.Listener.Addr().String()
			resp, err := proxy.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, wantID, resp.Header.Get(constants.PrivatemodeSecretIDHeader))
			assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, events, string(body))
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestSecretEvidenceRouteDisabled(t *testing.T) {
	s := New(http.DefaultClient, nil, Opts{}, slog.New(slog.DiscardHandler))
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		w := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), method, "/privatemode/v1/secret-evidence/bad!", nil)
		s.GetHandler().ServeHTTP(w, r)
		assert.Equal(t, http.StatusNotFound, w.Code)
	}
}
