// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

// Command verify-evidence independently verifies an active secret evidence bundle.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/edgelesssys/continuum/internal/oss/secretevidence"
	"github.com/spf13/cobra"
)

func main() {
	var evidencePath string
	var accepted []string
	cmd := &cobra.Command{
		Use:          "verify-evidence --evidence <file> [--accept-manifest-sha256 <hex>]...",
		Short:        "Verify the attestation and public transcript for an inference secret",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := os.ReadFile(evidencePath)
			if err != nil {
				return fmt.Errorf("reading evidence: %w", err)
			}
			var bundle secretevidence.Bundle
			if err := json.Unmarshal(raw, &bundle); err != nil {
				return fmt.Errorf("decoding evidence: %w", err)
			}
			if len(accepted) == 0 {
				if _, err := fmt.Fprintln(cmd.ErrOrStderr(), "Warning: no trusted manifest allowlist supplied. PASS proves only internal consistency against self-declared reference values, not Privatemode deployment identity. Match the printed SHA-256 to a trusted Privatemode CDN/release manifest and use --accept-manifest-sha256."); err != nil {
					return fmt.Errorf("writing manifest trust warning: %w", err)
				}
			}
			digest, err := secretevidence.Verify(cmd.Context(), bundle, accepted)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), digest)
			return err
		},
	}
	cmd.Flags().StringVar(&evidencePath, "evidence", "", "Path to the JSON evidence bundle")
	cmd.Flags().StringArrayVar(&accepted, "accept-manifest-sha256", nil, "Trusted Privatemode CDN/release manifest SHA-256 (repeatable; lowercase hex); without it PASS checks only consistency with self-declared reference values")
	if err := cmd.MarkFlagRequired("evidence"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
