package ovpn

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPushReplyTAP(t *testing.T) {
	s := &Session{srv: &Server{opt: Options{PushPing: 10 * time.Second, PushPingRestart: 60 * time.Second}}, cipher: "AES-256-GCM", pi: peerInfo{}}
	a := &Assignment{IP: netip.MustParseAddr("10.9.0.100"), Netmask: "255.255.255.0", Gateway: netip.MustParseAddr("10.9.0.1"), TAP: true}
	msg := strings.Join(s.pushReply(a), "")
	if !strings.Contains(msg, ",route-gateway 10.9.0.1,") || !strings.Contains(msg, ",ifconfig 10.9.0.100 255.255.255.0") ||
		strings.Contains(msg, "topology") {
		t.Fatalf("tap push: %s", msg)
	}
	a.DHCP = true
	msg = strings.Join(s.pushReply(a), "")
	if !strings.Contains(msg, ",route-gateway dhcp,") || strings.Contains(msg, "ifconfig") {
		t.Fatalf("dhcp push: %s", msg)
	}
	a.Gateway = netip.Addr{}
	if msg = strings.Join(s.pushReply(a), ""); strings.Contains(msg, "route-gateway") {
		t.Fatalf("nogw push: %s", msg)
	}
}
