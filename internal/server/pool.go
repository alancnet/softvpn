package server

import (
	"errors"
	"fmt"
	"net/netip"
)

var errPoolExhausted = errors.New("address pool exhausted")

// pool hands out virtual addresses. A common name keeps its address across
// reconnects (like OpenVPN's ifconfig-pool-persist, in memory), so TCP
// connections running through a client's stack survive a brief reconnect.
type pool struct {
	subnet  netip.Prefix
	gateway netip.Addr
	first   netip.Addr // dynamic range, inclusive
	last    netip.Addr
	static  map[string]netip.Addr
	owner   map[netip.Addr]string // static reservations
	sticky  map[string]netip.Addr // remembered dynamic address per client
	held    map[netip.Addr]string // reverse of sticky
	inUse   map[netip.Addr]bool
}

func newPool(subnet netip.Prefix, gateway netip.Addr, static map[string]netip.Addr) *pool {
	p := &pool{
		subnet:  subnet,
		gateway: gateway,
		static:  static,
		owner:   map[netip.Addr]string{},
		sticky:  map[string]netip.Addr{},
		held:    map[netip.Addr]string{},
		inUse:   map[netip.Addr]bool{},
	}
	// Usable hosts: gateway+1 .. broadcast-1.
	p.first, p.last = gateway.Next(), lastAddr(subnet).Prev()
	for cn, ip := range static {
		p.owner[ip] = cn
	}
	return p
}

// alloc returns an address for cn: want if valid (a client-config-dir
// ifconfig-push), otherwise a remembered or fresh dynamic address. With
// sticky=false (duplicate-cn) dynamic addresses are not remembered.
func (p *pool) alloc(cn string, want netip.Addr, sticky bool) (netip.Addr, error) {
	if !want.IsValid() {
		want = p.static[cn]
	}
	if want.IsValid() {
		if p.inUse[want] {
			return netip.Addr{}, fmt.Errorf("address %s is already in use", want)
		}
		p.inUse[want] = true
		return want, nil
	}
	if sticky {
		if ip, ok := p.sticky[cn]; ok && !p.inUse[ip] {
			p.inUse[ip] = true
			return ip, nil
		}
	}
	for ip := p.first; !p.last.Less(ip); ip = ip.Next() {
		if ip == p.gateway || p.inUse[ip] || p.owner[ip] != "" || p.held[ip] != "" {
			continue
		}
		p.take(cn, ip, sticky)
		return ip, nil
	}
	// Every address is either in use or remembered for an offline client;
	// reclaim the first remembered one.
	for ip := p.first; !p.last.Less(ip); ip = ip.Next() {
		if ip == p.gateway || p.inUse[ip] || p.owner[ip] != "" {
			continue
		}
		delete(p.sticky, p.held[ip])
		delete(p.held, ip)
		p.take(cn, ip, sticky)
		return ip, nil
	}
	return netip.Addr{}, errPoolExhausted
}

func (p *pool) take(cn string, ip netip.Addr, sticky bool) {
	p.inUse[ip] = true
	if sticky {
		if old, ok := p.sticky[cn]; ok {
			delete(p.held, old)
		}
		p.sticky[cn] = ip
		p.held[ip] = cn
	}
}

func (p *pool) release(ip netip.Addr) { delete(p.inUse, ip) }
