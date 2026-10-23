# Active secret evidence

**Off by default, with zero impact when off.** Enable `--expose-secret-evidence` to capture and expose evidence.
With the flag off, there is no evidence capture, retention, route or added response
header; proxy behavior and SDK APIs remain unchanged.

When enabled, the proxy retains public evidence for the latest eight successful secret exchanges
in memory (cleared on restart). Each bundle is installed atomically with its secret,
using the attestation of the Mesh CA that authenticated that exchange, even when
cached. Static and dynamic manifest modes share this path. Failed exchanges publish
nothing; secret bytes, credentials, prompts and responses are never included or logged.

## Contract

Forwarded inference responses carry `Privatemode-Secret-ID`: standard padded base64
of `SHA256(request_public_key)` for the final attempt, set before streaming body bytes.
This includes unencrypted upstream errors; local rejects and model discovery omit it.
`GET /privatemode/v1/secret-evidence/{id}` uses **unpadded base64url** of those same
32 bytes. It returns 200 `application/json`, 400 for malformed IDs, or 404 for unknown
or evicted IDs. Reads never refresh secrets or require authentication beyond the
listener's network/TLS boundary.

Version 1 JSON (byte fields: standard padded base64; times: RFC 3339 UTC):

```json
{
  "version": 1, "secret_id": "<base64 SHA256(request_public_key)>",
  "manifest_sha256": "<lowercase hex SHA256(manifest bytes)>", "manifest": "<base64>",
  "coordinator_attestation": {
    "nonce": "<base64 32 bytes>", "document": "<base64 Contrast document>",
    "attested_at": "<time>"
  },
  "mesh_ca_pem": "<PEM>", "secret_service_cert": "<base64 DER>",
  "request_public_key": "<base64 HPKE MLKEM768X25519 public key>",
  "encapsulated_key": "<base64>", "signature": "<base64 ASN.1 ECDSA>",
  "exchanged_at": "<time>", "expires_at": "<time>"
}
```

## Verification and trust

```sh
go build -tags contrast_unstable_api -o verify-evidence ./privatemode-proxy/cmd/verify-evidence
./verify-evidence --evidence evidence.json --accept-manifest-sha256 <64-lowercase-hex>
```

The allowlist flag is repeatable. Success prints only the verified digest and exits 0;
failure exits nonzero with a reason. Checks cover Contrast `ValidateAttestation(nonce,
document)`, exactly one byte-equal manifest, each policy's raw-byte SHA-256 against
manifest keys, the attested Mesh CA, the Secret Service certificate chain (at current
verification time), its signature over `SHA256(request_public_key || encapsulated_key)`,
and the HPKE key and derived secret ID. No proxy/inference connection is needed, but
AMD/Intel certificate collateral may be fetched online; this is not air-gapped.

**Use an allowlist from a trusted Privatemode CDN/release manifest.** Contrast derives
validators from the supplied manifest: without an allowlist, PASS proves only internal
consistency and, for SNP/TDX, hardware matching self-declared reference values. A
self-made Coordinator and manifest can pass; insecure platforms can also pass without
hardware attestation. The CLI warns on stderr without an allowlist. The printed digest
establishes identity only after matching a trusted manifest. Compare the ID with your
response: its association depends on trusting the proxy; the bundle alone cannot prove
an arbitrary response used that secret. Times/expiry are local, not attested freshness.
No GPU, OS or model claims follow.

The document is not an opaque signed JSON string. Report data binds nonce, manifest
transition digest, root CA and Mesh CA; policy hashes authenticate supplied policy bytes,
but not their ordering, duplicates or completeness. `version`, unknown fields and JSON
serialization are unauthenticated. `attestation_type` is also unauthenticated and ignored
by Contrast v1.25.1's fixed-OID wrappers; validators come from the manifest. Neither
metadata field should be treated as a verified claim.
