// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

package updater

import (
	"context"
	"crypto/x509"
	"log/slog"
	"testing"

	"github.com/edgelesssys/continuum/internal/oss/attest"
	"github.com/edgelesssys/continuum/internal/oss/auth"
	"github.com/edgelesssys/continuum/internal/oss/secretevidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvidenceUsesExchangedCA(t *testing.T) {
	getter := &rotatingCAGetter{}
	client := &rotatingSecretClient{}
	u := New(client, getter, slog.New(slog.DiscardHandler))
	_, _, first, err := u.UpdateSecretWithEvidence(t.Context(), auth.Credential{})
	require.NoError(t, err)
	_, _, cached, err := u.UpdateSecretWithEvidence(t.Context(), auth.Credential{})
	require.NoError(t, err)
	assert.Equal(t, 1, getter.calls)
	assert.Equal(t, "manifest-1", string(cached.Manifest))
	client.rejectOldCA = true
	_, _, rotated, err := u.UpdateSecretWithEvidence(t.Context(), auth.Credential{})
	require.NoError(t, err)
	assert.Equal(t, 2, getter.calls)
	assert.Equal(t, "manifest-2", string(rotated.Manifest))
	assert.Equal(t, "manifest-1", string(first.Manifest))
	assert.Equal(t, []byte{1}, first.SecretServiceCert)
	assert.Equal(t, []byte{2}, rotated.SecretServiceCert)
}

type rotatingCAGetter struct{ calls int }

func (g *rotatingCAGetter) GetMeshCA(context.Context, auth.Credential) (attest.MeshCA, error) {
	g.calls++
	name := "manifest-1"
	if g.calls > 1 {
		name = "manifest-2"
	}
	return attest.MeshCA{
		Certificate: &x509.Certificate{Raw: []byte{byte(g.calls)}},
		Evidence:    secretevidence.Attestation{Manifest: []byte(name)},
	}, nil
}

type rotatingSecretClient struct{ rejectOldCA bool }

func (c *rotatingSecretClient) ExchangeSecretWithEvidence(_ context.Context, ca *x509.Certificate, _ auth.Credential) (string, []byte, secretevidence.Exchange, error) {
	if c.rejectOldCA && ca.Raw[0] == 1 {
		return "", nil, secretevidence.Exchange{}, assert.AnError
	}
	return "id", []byte("secret"), secretevidence.Exchange{SecretServiceCert: ca.Raw}, nil
}
