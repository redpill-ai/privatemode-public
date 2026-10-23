// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

package updater

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"testing"

	"github.com/edgelesssys/continuum/internal/oss/auth"
	"github.com/edgelesssys/continuum/internal/oss/secretevidence"
	"github.com/edgelesssys/continuum/internal/oss/secretmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvidenceUsesExchangedCA(t *testing.T) {
	var recorder secretevidence.Bundle
	getter := &recordingCAGetter{recorder: &recorder}
	client := &recordingSecretClient{recorder: &recorder}
	u := New(client, getter, slog.New(slog.DiscardHandler))
	sm := secretmanager.New(u.UpdateSecret, false).WithEvidence(&recorder)
	require.NoError(t, sm.OfferCredential(t.Context(), auth.APIKey("credential")))
	for _, rotate := range []bool{false, true} {
		client.rejectOldCA = rotate
		require.NoError(t, sm.ForceUpdate(t.Context()))
		secret, err := sm.LatestSecret(t.Context())
		require.NoError(t, err)
		bundle, ok := sm.SecretEvidence(secret.ID)
		require.True(t, ok)
		assert.Equal(t, getter.calls, int(bundle.Manifest[0]))
		assert.Equal(t, bundle.Manifest, bundle.SecretServiceCert)
	}
	assert.Equal(t, 2, getter.calls)
	first, ok := sm.SecretEvidence("1")
	require.True(t, ok)
	assert.Equal(t, []byte{1}, first.Manifest)
	assert.Equal(t, first.Manifest, first.SecretServiceCert)
}

type recordingCAGetter struct {
	recorder *secretevidence.Bundle
	calls    int
}

func (g *recordingCAGetter) GetMeshCA(context.Context, auth.Credential) (*x509.Certificate, error) {
	g.calls++
	g.recorder.Attestation = secretevidence.Attestation{Manifest: []byte{byte(g.calls)}}
	return &x509.Certificate{Raw: []byte{byte(g.calls)}}, nil
}

type recordingSecretClient struct {
	recorder    *secretevidence.Bundle
	rejectOldCA bool
	calls       int
}

func (c *recordingSecretClient) ExchangeSecret(_ context.Context, ca *x509.Certificate, _ auth.Credential) (string, []byte, error) {
	if c.rejectOldCA && ca.Raw[0] == 1 {
		return "", nil, assert.AnError
	}
	c.calls++
	c.recorder.Exchange = secretevidence.Exchange{SecretServiceCert: ca.Raw}
	return fmt.Sprint(c.calls), []byte("secret"), nil
}
