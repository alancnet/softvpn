# Test-only image: the stock OpenVPN client from Alpine plus network tools.
# Also used for the "web" target and the no-VPN "probe" container.
ARG ALPINE=3.20
FROM alpine:${ALPINE}
RUN apk add --no-cache openvpn curl bind-tools iputils socat
COPY client-entrypoint.sh web.sh http-reply.sh dhcp-script.sh /usr/local/bin/
ENTRYPOINT []
