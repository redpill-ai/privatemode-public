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

func TestEvidenceEvictionAndFailure(t *testing.T) {
	var count int
	var fail bool
	var recorder secretevidence.Bundle
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

	fail = true
	require.Error(t, sm.ForceUpdate(t.Context()))
	_, ok := sm.SecretEvidence("2")
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
}
