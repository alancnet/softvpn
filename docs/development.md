# Development

## Building

```sh
go build ./cmd/softvpn
docker build -t softvpn .
```

Go 1.22 or newer. The binary is pure Go (`CGO_ENABLED=0`) and the image is a
single static binary on `scratch`. The Dockerfile cross-compiles, so
`docker buildx build --platform linux/amd64,linux/arm64 .` needs no
emulation.

## Tests

```sh
go vet ./...
go test -race ./...
test/run.sh
```

`test/run.sh` is the end-to-end suite. It builds the images and starts
[test/docker-compose.yml](../test/docker-compose.yml): several softvpn
servers, locked down exactly as in production, and stock OpenVPN clients
from Alpine's packages (2.6, 2.5, 2.3) in different configurations. Then it
checks that the clients connect and that their traffic arrives with the
server's address. It takes a few minutes.

The clients sit on Docker `internal` networks that can't reach anything, so
everything they reach went through the VPN. A `probe` container on the same
network, without a VPN, confirms that. The client containers need
`NET_ADMIN` and `/dev/net/tun` because the stock OpenVPN client always
creates a TUN interface; the servers need neither.

Options:

```sh
KEEP=1 test/run.sh                       # leave everything running afterwards
SVT_ID=-2 SVT_NET=10.232 test/run.sh     # separate names and subnets, for parallel runs
```

The suite also drives the web UI's API, and runs a headless Chromium
(Playwright) against the UI, saving screenshots to `test/artifacts/`. One
check needs real IPv6 internet access from Docker, and only warns without
it.

## Releases

GitHub Actions runs the unit and end-to-end tests on every push and pull
request. When they pass on `main`, it publishes `alancnet/softvpn:latest`
(and `:sha-…`) for amd64 and arm64 to Docker Hub. A tag `vX.Y.Z` publishes
`X.Y.Z`, `X.Y` and `X`.
