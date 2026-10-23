// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

package secretevidence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"

	"github.com/edgelesssys/continuum/internal/oss/secretexchange"
	contrastsdk "github.com/edgelesssys/contrast/sdk"
)

type attestationValidator interface {
	ValidateAttestation(context.Context, []byte, []byte) (*contrastsdk.CoordinatorState, error)
}

// Verify checks the exchange transcript and returns the manifest digest.
// Supply trusted manifest hashes to establish deployment identity. Without an allowlist,
// success proves only consistency with self-declared reference values (including insecure
// platforms), not Privatemode identity. The SDK may fetch AMD/Intel certificate collateral.
func Verify(ctx context.Context, bundle Bundle, acceptedManifestSHA256 []string) (string, error) {
	return verify(ctx, bundle, acceptedManifestSHA256, contrastsdk.New())
}

func verify(ctx context.Context, b Bundle, accepted []string, validator attestationValidator) (string, error) {
	if b.Version != 1 {
		return "", fmt.Errorf("unsupported evidence version: %d", b.Version)
	}
	for _, digest := range accepted {
		raw, err := hex.DecodeString(digest)
		if err != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != digest {
			return "", errors.New("accepted manifest SHA-256 must be 64 lowercase hexadecimal characters")
		}
	}
	digest := sha256.Sum256(b.Manifest)
	manifestSHA256 := hex.EncodeToString(digest[:])
	if manifestSHA256 != b.ManifestSHA256 {
		return "", errors.New("manifest SHA-256 mismatch")
	}
	if len(accepted) > 0 && !slices.Contains(accepted, manifestSHA256) {
		return "", errors.New("manifest SHA-256 is not accepted")
	}
	if len(b.CoordinatorAttestation.Nonce) != 32 {
		return "", errors.New("attestation nonce must be 32 bytes")
	}
	state, err := validator.ValidateAttestation(ctx, b.CoordinatorAttestation.Nonce, b.CoordinatorAttestation.Document)
	if err != nil {
		return "", fmt.Errorf("validating Coordinator attestation: %w", err)
	}
	if len(state.Manifests) != 1 || !bytes.Equal(state.Manifests[0], b.Manifest) {
		return "", errors.New("attested state must contain exactly the bundle manifest")
	}
	// Policies are outside report data; Contrast keys them by SHA-256 of raw policy bytes.
	var manifest struct {
		Policies map[string]json.RawMessage
	}
	if err := json.Unmarshal(b.Manifest, &manifest); err != nil {
		return "", fmt.Errorf("parsing manifest policy hashes: %w", err)
	}
	for i, policy := range state.Policies {
		digest := sha256.Sum256(policy)
		if _, ok := manifest.Policies[hex.EncodeToString(digest[:])]; !ok {
			return "", fmt.Errorf("policy %d SHA-256 is not present in manifest", i)
		}
	}
	if !bytes.Equal(state.MeshCA, []byte(b.MeshCAPEM)) {
		return "", errors.New("Mesh CA differs from attested Mesh CA")
	}
	block, rest := pem.Decode([]byte(b.MeshCAPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", errors.New("invalid Mesh CA PEM")
	}
	meshCA, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing Mesh CA: %w", err)
	}
	cert, err := x509.ParseCertificate(b.SecretServiceCert)
	if err != nil {
		return "", fmt.Errorf("parsing Secret Service certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(meshCA)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		return "", fmt.Errorf("verifying Secret Service certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(pub, secretexchange.Hash(b.RequestPublicKey, b.EncapsulatedKey), b.Signature) {
		return "", errors.New("invalid Secret Service signature")
	}
	if _, err := hpke.MLKEM768X25519().NewPublicKey(b.RequestPublicKey); err != nil {
		return "", fmt.Errorf("invalid request HPKE public key: %w", err)
	}
	if b.SecretID != secretexchange.ID(b.RequestPublicKey) {
		return "", errors.New("secret ID differs from request public key hash")
	}
	return manifestSHA256, nil
}
