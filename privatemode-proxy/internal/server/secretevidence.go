// Copyright (c) Edgeless Systems GmbH
// SPDX-License-Identifier: MIT

package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

func (s *Server) secretEvidenceHandler(w http.ResponseWriter, r *http.Request) {
	encoded := r.PathValue("id")
	id, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(id) != sha256.Size || base64.RawURLEncoding.EncodeToString(id) != encoded {
		http.Error(w, "malformed secret ID", http.StatusBadRequest)
		return
	}
	if s.secretEvidence == nil {
		http.NotFound(w, r)
		return
	}
	bundle, ok := s.secretEvidence.SecretEvidence(base64.StdEncoding.EncodeToString(id))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(bundle); err != nil {
		s.log.ErrorContext(r.Context(), "Writing secret evidence response", "error", err)
	}
}
