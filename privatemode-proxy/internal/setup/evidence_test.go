// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

package setup

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExposeSecretEvidence(t *testing.T) {
	for _, static := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("static=%t/enabled=%t", static, enabled), func(t *testing.T) {
				flags := Flags{Workspace: t.TempDir(), ExposeSecretEvidence: enabled}
				if static {
					flags.ManifestPath = filepath.Join(flags.Workspace, "manifest.json")
					require.NoError(t, os.WriteFile(flags.ManifestPath, []byte("manifest"), 0o600))
				}
				log := slog.New(slog.DiscardHandler)
				manager, _, err := SecretManager(t.Context(), flags, log)
				require.NoError(t, err)
				w := httptest.NewRecorder()
				r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/privatemode/v1/secret-evidence/bad!", nil)
				NewServer(flags, manager, log).GetHandler().ServeHTTP(w, r)
				want := http.StatusNotFound
				if enabled {
					want = http.StatusBadRequest
				}
				assert.Equal(t, want, w.Code)
			})
		}
	}
}
