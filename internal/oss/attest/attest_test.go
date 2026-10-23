// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

package attest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/edgelesssys/continuum/internal/oss/auth"
	"github.com/edgelesssys/continuum/internal/oss/httpapi"
	"github.com/edgelesssys/continuum/internal/oss/secretevidence"
	contrastsdk "github.com/edgelesssys/contrast/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAttestedMeshCA(t *testing.T) {
	manifest := []byte(`{"manifest":"expected"}`)
	doc := []byte("Coordinator attestation document")
	var nonce []byte
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/privatemode/v1/attest", r.URL.Path)
		var req httpapi.AttestReq
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&req)) {
			return
		}
		nonce = req.Nonce
		assert.Len(t, nonce, 32)
		assert.NoError(t, json.NewEncoder(w).Encode(httpapi.AttestResp{AttestationDoc: doc}))
	}))
	defer api.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})
	for name, tc := range map[string]struct {
		manifests [][]byte
		disabled  bool
		err       string
	}{
		"valid":              {manifests: [][]byte{manifest}},
		"disabled":           {manifests: [][]byte{manifest}, disabled: true},
		"different manifest": {manifests: [][]byte{[]byte("other")}, err: "does not match"},
		"multiple manifests": {manifests: [][]byte{manifest, manifest}, err: "exactly one"},
	} {
		t.Run(name, func(t *testing.T) {
			getter := Getter{
				httpClient: api.Client(), endpoint: api.Listener.Addr().String(),
				contrastClient: testValidator{t: t, nonce: &nonce, doc: doc, state: &contrastsdk.CoordinatorState{Manifests: tc.manifests, MeshCA: caPEM}},
			}
			var evidence secretevidence.Bundle
			if !tc.disabled {
				getter = getter.WithEvidence(&evidence)
			}
			ca, err := getter.GetAttestedMeshCA(t.Context(), manifest, auth.Credential{})
			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
				assert.Nil(t, ca)
				assert.Empty(t, evidence)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, api.Certificate().Raw, ca.Raw)
			if tc.disabled {
				assert.Empty(t, evidence)
				assert.Nil(t, getter.evidence)
				return
			}
			assert.Equal(t, string(caPEM), evidence.MeshCAPEM)
			assert.Equal(t, nonce, evidence.CoordinatorAttestation.Nonce)
			assert.Equal(t, doc, evidence.CoordinatorAttestation.Document)
			assert.False(t, evidence.CoordinatorAttestation.AttestedAt.IsZero())
			digest := sha256.Sum256(manifest)
			assert.Equal(t, hex.EncodeToString(digest[:]), evidence.ManifestSHA256)
			assert.Equal(t, manifest, evidence.Manifest)
			evidence.Manifest[0] ^= 1
			assert.Equal(t, byte('{'), manifest[0])
		})
	}
}

type testValidator struct {
	t     *testing.T
	nonce *[]byte
	doc   []byte
	state *contrastsdk.CoordinatorState
}

func (v testValidator) ValidateAttestation(_ context.Context, nonce, doc []byte) (*contrastsdk.CoordinatorState, error) {
	assert.Equal(v.t, *v.nonce, nonce)
	assert.Equal(v.t, v.doc, doc)
	return v.state, nil
}
