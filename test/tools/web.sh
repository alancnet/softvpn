#!/bin/sh
# A stand-in for "the internet": HTTP that reports the caller's address,
# a bulk-download endpoint, and a UDP echo service, over IPv4 and IPv6.
socat TCP4-LISTEN:80,fork,reuseaddr EXEC:"http-reply.sh hello" &
socat TCP6-LISTEN:80,ipv6only=1,fork,reuseaddr EXEC:"http-reply.sh hello" &
socat TCP4-LISTEN:81,fork,reuseaddr EXEC:"http-reply.sh bulk 50000000" &
socat UDP4-RECVFROM:7,fork EXEC:cat &
socat UDP6-RECVFROM:7,ipv6only=1,fork EXEC:cat &
wait
