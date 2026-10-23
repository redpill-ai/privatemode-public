// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

package updater

import (
	"context"
	"crypto/x509"
	"log/slog"
	"testing"
	"time"

	"github.com/avast/retry-go/v5"
	"github.com/edgelesssys/continuum/internal/oss/attest"
	"github.com/edgelesssys/continuum/internal/oss/auth"
	"github.com/edgelesssys/continuum/internal/oss/logging"
	"github.com/edgelesssys/continuum/internal/oss/secretevidence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateSecret(t *testing.T) {
	testCases := map[string]struct {
		wantErr   bool
		customize func(*Updater)
	}{
		"exchanges with fetched Mesh CA": {},
		"propagates Mesh CA failure": {
			customize: func(sut *Updater) {
				sut.caGetter = &stubCAGetter{
					err: assert.AnError,
				}
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			log := logging.NewLogger(logging.DefaultFlagValue)
			secretClient := &stubSecretClient{}
			sut := &Updater{
				ssClient:  secretClient,
				caGetter:  &stubCAGetter{},
				log:       log,
				retryOpts: []retry.Option{retry.Delay(time.Millisecond), retry.Attempts(2)},
			}
			if tc.customize != nil {
				tc.customize(sut)
			}

			id, data, _, err := sut.UpdateSecret(t.Context(), auth.APIKey(""))
			assert := assert.New(t)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal("id", id)
			assert.EqualValues("data", data)
		})
	}
}

func TestEvidenceUsesExchangedCA(t *testing.T) {
	getter := &stubCAGetter{}
	client := &stubSecretClient{}
	u := New(client, getter, slog.New(slog.DiscardHandler))
	_, _, first, err := u.UpdateSecret(t.Context(), auth.Credential{})
	require.NoError(t, err)
	_, _, cached, err := u.UpdateSecret(t.Context(), auth.Credential{})
	require.NoError(t, err)
	assert.Equal(t, 1, getter.calls)
	assert.Equal(t, first.Attestation, cached.Attestation)
	client.rejectOldCA = true
	_, _, rotated, err := u.UpdateSecret(t.Context(), auth.Credential{})
	require.NoError(t, err)
	assert.Equal(t, 2, getter.calls)
	assert.Equal(t, []byte{1}, first.Manifest)
	assert.Equal(t, []byte{2}, rotated.Manifest)
	assert.Equal(t, first.Manifest, first.SecretServiceCert)
	assert.Equal(t, rotated.Manifest, rotated.SecretServiceCert)
}

type stubCAGetter struct {
	calls int
	err   error
}

func (c *stubCAGetter) GetMeshCA(context.Context, auth.Credential) (attest.MeshCA, error) {
	c.calls++
	return attest.MeshCA{
		Certificate: &x509.Certificate{Raw: []byte{byte(c.calls)}},
		Evidence:    secretevidence.Attestation{Manifest: []byte{byte(c.calls)}},
	}, c.err
}

type stubSecretClient struct{ rejectOldCA bool }

func (s *stubSecretClient) ExchangeSecret(_ context.Context, meshCA *x509.Certificate, _ auth.Credential) (string, []byte, secretevidence.Exchange, error) {
	if s.rejectOldCA && meshCA.Raw[0] == 1 {
		return "", nil, secretevidence.Exchange{}, assert.AnError
	}
	return "id", []byte("data"), secretevidence.Exchange{SecretServiceCert: meshCA.Raw}, nil
}
