package server

import (
	"net/netip"
	"testing"
)

func TestPool(t *testing.T) {
	subnet := netip.MustParsePrefix("10.8.0.0/29") // hosts .2 - .6
	gw := netip.MustParseAddr("10.8.0.1")
	p := newPool(subnet, gw, map[string]netip.Addr{"fixed": netip.MustParseAddr("10.8.0.6")})

	a, _ := p.alloc("alice", netip.Addr{}, true)
	if a.String() != "10.8.0.2" {
		t.Fatalf("first address %s", a)
	}
	p.release(a)
	b, _ := p.alloc("bob", netip.Addr{}, true)
	if b == a {
		t.Fatal("alice's remembered address given to bob while others are free")
	}
	if again, _ := p.alloc("alice", netip.Addr{}, true); again != a {
		t.Fatalf("alice did not get her address back: %s", again)
	}
	if f, _ := p.alloc("fixed", netip.Addr{}, true); f.String() != "10.8.0.6" {
		t.Fatalf("static address %s", f)
	}
	if _, err := p.alloc("fixed", netip.Addr{}, true); err == nil {
		t.Fatal("static address handed out twice")
	}
	c, _ := p.alloc("carol", netip.Addr{}, true)
	d, _ := p.alloc("dave", netip.Addr{}, true)
	for _, ip := range []netip.Addr{c, d} {
		if ip == gw || ip.String() == "10.8.0.7" || ip.String() == "10.8.0.6" || !subnet.Contains(ip) {
			t.Fatalf("bad dynamic address %s", ip)
		}
	}
	if _, err := p.alloc("erin", netip.Addr{}, true); err != errPoolExhausted {
		t.Fatalf("expected exhaustion, got %v", err)
	}
}
