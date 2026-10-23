// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

package secretmanager

import (
	"context"
	"fmt"
	"testing"

	"github.com/edgelesssys/continuum/internal/oss/auth"
	"github.com/edgelesssys/continuum/internal/oss/secretevidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvidenceRecordingAndEviction(t *testing.T) {
	var count int
	var fail bool
	manifest := []byte("original manifest")
	recorder := secretevidence.Bundle{Attestation: secretevidence.Attestation{Manifest: manifest}}
	sm := New(func(context.Context, auth.Credential) (string, []byte, error) {
		count++
		id := fmt.Sprint(count)
		if fail {
			return id, nil, assert.AnError
		}
		return id, []byte("private secret"), nil
	}, false).WithEvidence(&recorder)
	require.NoError(t, sm.OfferCredential(t.Context(), auth.APIKey("private credential")))
	secret, err := sm.LatestSecret(t.Context())
	require.NoError(t, err)
	b, ok := sm.SecretEvidence(secret.ID)
	require.True(t, ok)
	assert.Equal(t, secret.ExpirationDate.UTC(), b.ExpiresAt)
	manifest[0] = 'X'
	b.Manifest[1] = 'X'
	b, ok = sm.SecretEvidence(secret.ID)
	require.True(t, ok)
	assert.Equal(t, "original manifest", string(b.Manifest))

	fail = true
	require.Error(t, sm.ForceUpdate(t.Context()))
	_, ok = sm.SecretEvidence("2")
	assert.False(t, ok)
	stillCurrent, err := sm.LatestSecret(t.Context())
	require.NoError(t, err)
	assert.Equal(t, secret, stillCurrent)
	fail = false
	for range maxEvidenceBundles {
		require.NoError(t, sm.ForceUpdate(t.Context()))
	}
	_, ok = sm.SecretEvidence("1")
	assert.False(t, ok)
	_, ok = sm.SecretEvidence("3")
	assert.True(t, ok)
	latest, err := sm.LatestSecret(t.Context())
	require.NoError(t, err)
	b, ok = sm.SecretEvidence(latest.ID)
	assert.True(t, ok)
	assert.Equal(t, latest.ExpirationDate.UTC(), b.ExpiresAt)
	assert.Len(t, sm.evidence, maxEvidenceBundles)
}

func TestEvidenceDisabled(t *testing.T) {
	sm := New(func(context.Context, auth.Credential) (string, []byte, error) {
		return "id", []byte("secret"), nil
	}, false)
	require.NoError(t, sm.OfferCredential(t.Context(), auth.APIKey("credential")))
	require.NoError(t, sm.ForceUpdate(t.Context()))
	_, ok := sm.SecretEvidence("id")
	assert.False(t, ok)
	assert.Nil(t, sm.recorder)
	assert.Nil(t, sm.evidence)
}
