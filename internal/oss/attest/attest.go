// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

// Package attest provides a Getter to get the mesh CA verified via remote attestation.
package attest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/edgelesssys/continuum/internal/oss/auth"
	"github.com/edgelesssys/continuum/internal/oss/httpapi"
	"github.com/edgelesssys/continuum/internal/oss/secretevidence"
	contrastsdk "github.com/edgelesssys/contrast/sdk"
)

// ErrManifestMismatch is returned when the manifest obtained from Coordinator attestation
// does not match the expected manifest.
var ErrManifestMismatch = errors.New("active manifest does not match expected manifest")

// MeshCA pairs a certificate with the exact attestation that authenticated it.
type MeshCA struct {
	Certificate *x509.Certificate
	Evidence    secretevidence.Attestation
}

// Getter is a client that gets the mesh CA of the Privatemode deployment.
type Getter struct {
	httpClient       *http.Client
	contrastClient   attestationValidator
	endpoint         string
	extraHTTPHeaders http.Header
}

type attestationValidator interface {
	ValidateAttestation(context.Context, []byte, []byte) (*contrastsdk.CoordinatorState, error)
}

// NewGetter creates a new Getter.
func NewGetter(httpClient *http.Client, endpoint string, contrastClient *contrastsdk.Client, extraHTTPHeaders http.Header) Getter {
	return Getter{
		httpClient:       httpClient,
		contrastClient:   contrastClient,
		endpoint:         endpoint,
		extraHTTPHeaders: extraHTTPHeaders,
	}
}

// GetAttestedMeshCA gets the mesh CA of the Privatemode deployment.
func (c Getter) GetAttestedMeshCA(ctx context.Context, expectedMfBytes []byte, cred auth.Credential) (*x509.Certificate, error) {
	ca, err := c.GetAttestedMeshCAWithEvidence(ctx, expectedMfBytes, cred)
	return ca.Certificate, err
}

// GetAttestedMeshCAWithEvidence also returns the public attestation transcript.
func (c Getter) GetAttestedMeshCAWithEvidence(ctx context.Context, expectedMfBytes []byte, cred auth.Credential) (MeshCA, error) {
	// Get the attestation
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return MeshCA{}, fmt.Errorf("generating nonce: %w", err)
	}
	attestReq, err := json.Marshal(httpapi.AttestReq{Nonce: nonce})
	if err != nil {
		return MeshCA{}, fmt.Errorf("marshaling attest request: %w", err)
	}
	attestResp, err := httpapi.Do(ctx, c.httpClient, http.MethodPost, "https://"+c.endpoint+"/privatemode/v1/attest", attestReq, cred, c.extraHTTPHeaders)
	if err != nil {
		return MeshCA{}, fmt.Errorf("doing attest request: %w", err)
	}
	var att httpapi.AttestResp
	if err := json.Unmarshal(attestResp, &att); err != nil {
		return MeshCA{}, fmt.Errorf("unmarshaling attest response: %w", err)
	}

	// Validate the attestation against the expected manifest
	coordinatorState, err := c.contrastClient.ValidateAttestation(ctx, nonce, att.AttestationDoc)
	if err != nil {
		return MeshCA{}, fmt.Errorf("validating attestation: %w", err)
	}
	if len(coordinatorState.Manifests) != 1 {
		return MeshCA{}, errors.New("expected exactly one manifest")
	}
	if !bytes.Equal(coordinatorState.Manifests[0], expectedMfBytes) {
		return MeshCA{}, ErrManifestMismatch
	}

	// Parse the certificate
	block, _ := pem.Decode(coordinatorState.MeshCA)
	if block == nil {
		return MeshCA{}, errors.New("decoding mesh CA certificate failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return MeshCA{}, fmt.Errorf("parsing mesh CA certificate: %w", err)
	}

	digest := sha256.Sum256(expectedMfBytes)
	return MeshCA{
		Certificate: cert,
		Evidence: secretevidence.Attestation{
			Manifest:       bytes.Clone(expectedMfBytes),
			ManifestSHA256: hex.EncodeToString(digest[:]),
			MeshCAPEM:      string(coordinatorState.MeshCA),
			CoordinatorAttestation: secretevidence.CoordinatorAttestation{
				Nonce: nonce, Document: att.AttestationDoc, AttestedAt: time.Now().UTC(),
			},
		},
	}, nil
}
