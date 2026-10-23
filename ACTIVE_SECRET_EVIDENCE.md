# Active secret evidence (prototype)

The proxy retains the public attestation and secret exchange transcript for each
inference secret. It captures the attestation that authenticated that exchange's
Mesh CA, including when the CA is cached across exchanges. Recording happens
under the secret manager lock together with installing the successful secret.
Static (`--manifest-path`) and dynamic manifest modes use the same evidence path.
The eight latest successful exchanges are retained in memory; restarts clear them.
Failed exchanges never publish evidence. Secret bytes, credentials, prompts and
responses are not included or logged by this feature.

## HTTP contract

Every forwarded inference response includes `Privatemode-Secret-ID`, containing
standard padded base64 of `SHA256(request_public_key)`. It identifies the attempt
that produced the response, including after retries, and is set before streaming
body bytes. Unencrypted upstream error responses also carry the attempted ID.
Locally rejected requests and unencrypted model discovery do not identify an
inference secret.

`GET /privatemode/v1/secret-evidence/{id}` returns `application/json`. Decode the
response header's standard base64 value and re-encode those same 32 bytes as
**unpadded base64url** for `{id}`. Malformed IDs return 400; unknown or evicted IDs
return 404. This read does not authenticate, attest, exchange or refresh a secret.
It uses the proxy listener's existing network/TLS access boundary.

Version 1 schema (all byte fields use standard padded base64; times use RFC 3339 UTC):

```json
{
  "version": 1,
  "secret_id": "<standard base64 SHA256(request_public_key)>",
  "manifest_sha256": "<lowercase hex SHA256(manifest bytes)>",
  "manifest": "<base64 manifest bytes>",
  "coordinator_attestation": {
    "nonce": "<base64 32-byte nonce>",
    "document": "<base64 document passed to Contrast ValidateAttestation>",
    "attested_at": "<RFC 3339 UTC>"
  },
  "mesh_ca_pem": "<PEM string>",
  "secret_service_cert": "<base64 DER certificate>",
  "request_public_key": "<base64 HPKE MLKEM768X25519 public key>",
  "encapsulated_key": "<base64 encapsulated key>",
  "signature": "<base64 ASN.1 ECDSA signature>",
  "exchanged_at": "<RFC 3339 UTC>",
  "expires_at": "<RFC 3339 UTC>"
}
```

## Independent verifier

Build with the same Contrast SDK tag as the proxy:

```sh
go build -tags contrast_unstable_api -o verify-evidence ./privatemode-proxy/cmd/verify-evidence
./verify-evidence --evidence evidence.json --accept-manifest-sha256 <64-lowercase-hex>
```

The optional allowlist flag is repeatable. Success exits 0 and prints only the
verified manifest SHA-256. Failure exits nonzero with a reason. The verifier checks
Contrast `ValidateAttestation(nonce, document)`, exactly one byte-equal manifest,
the attested Mesh CA, the Secret Service certificate chain, its signature over
`SHA256(request_public_key || encapsulated_key)`, and the public-key-derived ID.
Certificate validity uses the verifier's current time, as the live exchange does.
The input can be verified without contacting the proxy or inference API; the
Contrast SDK may fetch AMD/Intel certificate collateral from public services.

The bundle authenticates a secret exchange to a manifest. The response header
associates a request with that secret through the trusted proxy; the bundle alone
does not prove that an arbitrary response used it. Timestamps and proxy expiration
are local metadata, not independently attested claims of freshness. A verifier
should compare the ID with its response and apply its own manifest policy. An
empty allowlist authenticates the manifest without endorsing its contents or
making GPU, OS or model claims.

## Container build

The Dockerfile pins Go 1.26.10 and the runtime base by digest, includes both
binaries, runs without root, and uses the existing proxy arguments. Build from
the repository root:

```sh
docker build -f privatemode-proxy/Dockerfile \
  --build-arg REVISION="$(git rev-parse HEAD)" \
  --build-arg VERSION="v1.60.0+active-secret-evidence.$(git rev-parse --short HEAD)" \
  -t ghcr.io/redpill-ai/privatemode-proxy:active-secret-evidence-<shortsha> .
docker run --rm --entrypoint /bin/verify-evidence \
  -v "$PWD/evidence.json:/evidence.json:ro" <image> --evidence /evidence.json
```

For a test key, mount a read-only key file and use `--api-key @/path/to/key` rather
than passing the key on the command line. This is a fork prototype for testing.
The Contrast SDK's BUSL-1.1 licensing must be resolved with Edgeless before using
a self-built image in production.
