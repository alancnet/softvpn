# softvpn server image: a single static binary on an empty filesystem.
# It needs no capabilities, no TUN device and no root.
# The build stage runs natively and cross-compiles, so multi-arch builds
# need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/softvpn ./cmd/softvpn \
 && mkdir -p /out/pki /out/tmp

FROM scratch
COPY --from=build /out/softvpn /usr/local/bin/softvpn
# Owned by "nobody" so named volumes mounted here start out writable for it.
COPY --from=build --chown=65534:65534 /out/pki /pki
COPY --from=build --chown=65534:65534 --chmod=1777 /out/tmp /tmp
USER 65534:65534
EXPOSE 1194/udp 1194/tcp
ENTRYPOINT ["/usr/local/bin/softvpn"]
CMD ["server", "--config", "/etc/softvpn/server.conf"]
