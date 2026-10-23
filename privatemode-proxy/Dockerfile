# Copyright (c) Edgeless Systems GmbH
# SPDX-License-Identifier: MIT

FROM golang:1.26.10-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/oss ./internal/oss
COPY privatemode-proxy ./privatemode-proxy
ARG VERSION=v1.60.0+active-secret-evidence
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -p 2 -mod=readonly -trimpath -buildvcs=false -tags contrast_unstable_api \
    -ldflags="-s -w -X github.com/edgelesssys/continuum/internal/oss/constants.version=${VERSION}" \
    -o /out/ ./privatemode-proxy ./privatemode-proxy/cmd/verify-evidence
RUN mkdir /workspace

FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
ARG REVISION
LABEL org.opencontainers.image.source="https://github.com/redpill-ai/privatemode-public" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /out/ /bin/
COPY --from=build --chown=65532:65532 /workspace /workspace
WORKDIR /workspace
ENTRYPOINT ["/bin/privatemode-proxy"]
