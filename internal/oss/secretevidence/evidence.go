// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

// Package secretevidence describes the public evidence authenticating an inference secret exchange.
package secretevidence

import (
	"bytes"
	"time"
)

// CoordinatorAttestation records the challenge and response validated by Contrast.
type CoordinatorAttestation struct {
	Nonce      []byte    `json:"nonce"`
	Document   []byte    `json:"document"`
	AttestedAt time.Time `json:"attested_at"`
}

// Attestation authenticates the Mesh CA against the expected manifest.
type Attestation struct {
	ManifestSHA256         string                 `json:"manifest_sha256"`
	Manifest               []byte                 `json:"manifest"`
	CoordinatorAttestation CoordinatorAttestation `json:"coordinator_attestation"`
	MeshCAPEM              string                 `json:"mesh_ca_pem"`
}

// Exchange contains only the public transcript of a successful secret exchange.
type Exchange struct {
	SecretServiceCert []byte    `json:"secret_service_cert"`
	RequestPublicKey  []byte    `json:"request_public_key"`
	EncapsulatedKey   []byte    `json:"encapsulated_key"`
	Signature         []byte    `json:"signature"`
	ExchangedAt       time.Time `json:"exchanged_at"`
}

// Bundle binds the attestation used for an exchange to the resulting secret ID.
// It never contains the secret or any authentication or inference data.
type Bundle struct {
	Version  int    `json:"version"`
	SecretID string `json:"secret_id"`
	Attestation
	Exchange
	ExpiresAt time.Time `json:"expires_at"`
}

// Clone returns a bundle with independent byte slices.
func (b Bundle) Clone() Bundle {
	b.Manifest = bytes.Clone(b.Manifest)
	b.CoordinatorAttestation.Nonce = bytes.Clone(b.CoordinatorAttestation.Nonce)
	b.CoordinatorAttestation.Document = bytes.Clone(b.CoordinatorAttestation.Document)
	b.SecretServiceCert = bytes.Clone(b.SecretServiceCert)
	b.RequestPublicKey = bytes.Clone(b.RequestPublicKey)
	b.EncapsulatedKey = bytes.Clone(b.EncapsulatedKey)
	b.Signature = bytes.Clone(b.Signature)
	return b
}
