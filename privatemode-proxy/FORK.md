# Fork image

This fork image is a testing prototype. The Contrast SDK's BUSL-1.1 licensing must
be resolved with Edgeless before using a self-built image in production.

The Dockerfile pins Go 1.26.10 and the runtime base by digest, includes the proxy
and verifier, and runs without root. Build and publish from the repository root:

```sh
revision=$(git rev-parse HEAD)
shortsha=$(git rev-parse --short HEAD)
image=ghcr.io/redpill-ai/privatemode-proxy:active-secret-evidence-$shortsha
docker build -f privatemode-proxy/Dockerfile --build-arg REVISION="$revision" \
  --build-arg VERSION="v1.60.0+active-secret-evidence.$shortsha" -t "$image" .
docker push "$image"
docker run --rm --entrypoint /bin/verify-evidence \
  -v "$PWD/evidence.json:/evidence.json:ro" "$image" --evidence /evidence.json \
  --accept-manifest-sha256 <trusted-manifest-sha256>
```

Evidence is off by default. Add `--expose-secret-evidence` to the proxy arguments
to enable capture, the response header and evidence endpoint. Existing arguments
remain supported; the Go/wasm SDK does not capture evidence. Mount test keys read-only and use
`--api-key @/path/to/key`; never pass the key itself on the command line.
