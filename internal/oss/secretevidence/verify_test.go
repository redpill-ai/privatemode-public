// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

package secretevidence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/edgelesssys/continuum/internal/oss/secretexchange"
	contrastsdk "github.com/edgelesssys/contrast/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	bundle := newTestBundle(t)
	for name, tc := range map[string]struct {
		mutate func(*Bundle, *contrastsdk.CoordinatorState)
		accept []string
		err    string
	}{
		"valid":               {},
		"accepted manifest":   {accept: []string{bundle.ManifestSHA256}},
		"unaccepted manifest": {accept: []string{hex.EncodeToString(make([]byte, 32))}, err: "not accepted"},
		"invalid allowlist":   {accept: []string{"bad"}, err: "lowercase hexadecimal"},
		"version":             {mutate: func(b *Bundle, _ *contrastsdk.CoordinatorState) { b.Version++ }, err: "version"},
		"manifest":            {mutate: func(b *Bundle, _ *contrastsdk.CoordinatorState) { b.Manifest[0] ^= 1 }, err: "SHA-256 mismatch"},
		"attested manifest":   {mutate: func(_ *Bundle, s *contrastsdk.CoordinatorState) { s.Manifests = [][]byte{[]byte("other")} }, err: "exactly the bundle manifest"},
		"manifest history":    {mutate: func(b *Bundle, s *contrastsdk.CoordinatorState) { s.Manifests = append(s.Manifests, b.Manifest) }, err: "exactly the bundle manifest"},
		"tampered policy":     {mutate: func(_ *Bundle, s *contrastsdk.CoordinatorState) { s.Policies[0][0] ^= 1 }, err: "policy 0 SHA-256 is not present in manifest"},
		"unexpected policy": {mutate: func(_ *Bundle, s *contrastsdk.CoordinatorState) {
			s.Policies = append(s.Policies, []byte("other policy"))
		}, err: "policy 1 SHA-256 is not present in manifest"},
		"mesh CA": {mutate: func(b *Bundle, _ *contrastsdk.CoordinatorState) { b.MeshCAPEM += "\n" }, err: "attested Mesh CA"},
		"SS certificate": {mutate: func(b *Bundle, _ *contrastsdk.CoordinatorState) {
			b.SecretServiceCert = newTestBundle(t).SecretServiceCert
		}, err: "verifying Secret Service certificate"},
		"signature":          {mutate: func(b *Bundle, _ *contrastsdk.CoordinatorState) { b.Signature[0] ^= 1 }, err: "signature"},
		"request public key": {mutate: func(b *Bundle, _ *contrastsdk.CoordinatorState) { b.RequestPublicKey[0] ^= 1 }, err: "signature"},
		"encapsulated key":   {mutate: func(b *Bundle, _ *contrastsdk.CoordinatorState) { b.EncapsulatedKey[0] ^= 1 }, err: "signature"},
		"secret ID":          {mutate: func(b *Bundle, _ *contrastsdk.CoordinatorState) { b.SecretID = "wrong" }, err: "secret ID"},
		"nonce":              {mutate: func(b *Bundle, _ *contrastsdk.CoordinatorState) { b.CoordinatorAttestation.Nonce[0] ^= 1 }, err: "attestation transcript differs"},
		"document":           {mutate: func(b *Bundle, _ *contrastsdk.CoordinatorState) { b.CoordinatorAttestation.Document[0] ^= 1 }, err: "attestation transcript differs"},
	} {
		t.Run(name, func(t *testing.T) {
			b := bundle.Clone()
			state := &contrastsdk.CoordinatorState{
				Manifests: [][]byte{bytes.Clone(bundle.Manifest)}, MeshCA: []byte(bundle.MeshCAPEM),
				Policies: [][]byte{testPolicy()},
			}
			if tc.mutate != nil {
				tc.mutate(&b, state)
			}
			// Only the hardware-attestation seam is stubbed; the CA chain, HPKE public key,
			// ECDSA signature, manifest digest and secret ID use real cryptography.
			validator := testValidator{expected: bundle.CoordinatorAttestation, state: state}
			digest, err := verify(t.Context(), b, tc.accept, validator)
			if tc.err != "" {
				assert.ErrorContains(t, err, tc.err)
				assert.Empty(t, digest)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, bundle.ManifestSHA256, digest)
		})
	}
}

func TestVerifyRejectsInvalidHardwareAttestation(t *testing.T) {
	_, err := Verify(t.Context(), newTestBundle(t), nil)
	assert.ErrorContains(t, err, "validating Coordinator attestation")
}

type testValidator struct {
	expected CoordinatorAttestation
	state    *contrastsdk.CoordinatorState
}

func (v testValidator) ValidateAttestation(_ context.Context, nonce, doc []byte) (*contrastsdk.CoordinatorState, error) {
	if !bytes.Equal(nonce, v.expected.Nonce) || !bytes.Equal(doc, v.expected.Document) {
		return nil, errors.New("attestation transcript differs")
	}
	return v.state, nil
}

func newTestBundle(t *testing.T) Bundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caRaw, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caRaw)
	require.NoError(t, err)
	ssKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ssTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	ssCert, err := x509.CreateCertificate(rand.Reader, ssTemplate, ca, &ssKey.PublicKey, key)
	require.NoError(t, err)
	priv, err := hpke.MLKEM768X25519().GenerateKey()
	require.NoError(t, err)
	encap, _, err := hpke.NewSender(priv.PublicKey(), hpke.HKDFSHA256(), hpke.ExportOnly(), nil)
	require.NoError(t, err)
	pub := priv.PublicKey().Bytes()
	sig, err := ecdsa.SignASN1(rand.Reader, ssKey, secretexchange.Hash(pub, encap))
	require.NoError(t, err)
	policyDigest := sha256.Sum256(testPolicy())
	manifest := []byte(fmt.Sprintf(`{"Policies":{"%x":{}}}`, policyDigest))
	digest := sha256.Sum256(manifest)
	return Bundle{
		Version: 1, SecretID: secretexchange.ID(pub), ExpiresAt: now.Add(45 * time.Minute),
		Attestation: Attestation{
			Manifest: manifest, ManifestSHA256: hex.EncodeToString(digest[:]),
			MeshCAPEM:              string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caRaw})),
			CoordinatorAttestation: CoordinatorAttestation{Nonce: make([]byte, 32), Document: []byte("hardware attestation"), AttestedAt: now},
		},
		Exchange: Exchange{SecretServiceCert: ssCert, RequestPublicKey: pub, EncapsulatedKey: encap, Signature: sig, ExchangedAt: now},
	}
}

func testPolicy() []byte {
	return []byte("package policy\nallow := true\n")
}
