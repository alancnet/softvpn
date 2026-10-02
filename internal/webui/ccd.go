package webui

import (
	"net"
	"net/netip"
	"strings"

	"github.com/softvpn/softvpn/internal/config"
)

// CCDSettings are the directives of a client-config-dir file that the
// structured editor manages.
type CCDSettings struct {
	IP        string   `json:"ip"`        // ifconfig-push: a static IPv4 address
	IP6       string   `json:"ip6"`       // ifconfig-ipv6-push ADDR/BITS
	IRoutes   []string `json:"iroutes"`   // iroute / iroute-ipv6, as prefixes
	Push      []string `json:"push"`      // extra options pushed to this client
	PushReset bool     `json:"pushReset"` // don't push the server's options
	Disabled  bool     `json:"disabled"`  // refuse the client
}

var ccdManaged = [][]string{
	{"ifconfig-push", "ifconfig-ipv6-push"},
	{"iroute", "iroute-ipv6"},
	{"push-reset", "push"},
	{"disable"},
}

func extractCCD(text string) CCDSettings {
	s := CCDSettings{IRoutes: []string{}, Push: []string{}}
	for _, l := range config.SplitLines(text) {
		arg := func(i int) string {
			if i < len(l.Args) {
				return l.Args[i]
			}
			return ""
		}
		switch l.Name {
		case "ifconfig-push":
			s.IP = arg(0)
		case "ifconfig-ipv6-push":
			s.IP6 = arg(0)
		case "iroute":
			s.IRoutes = append(s.IRoutes, routeString(arg(0), arg(1)))
		case "iroute-ipv6":
			s.IRoutes = append(s.IRoutes, arg(0))
		case "push":
			s.Push = append(s.Push, arg(0))
		case "push-reset":
			s.PushReset = true
		case "disable":
			s.Disabled = true
		}
	}
	return s
}

// directives renders the settings; subnet is the server's IPv4 subnet, for
// ifconfig-push's netmask.
func (s CCDSettings) directives(subnet netip.Prefix) map[string][][]string {
	d := map[string][][]string{}
	for _, g := range ccdManaged {
		for _, n := range g {
			d[n] = nil
		}
	}
	if ip := strings.TrimSpace(s.IP); ip != "" {
		mask := "255.255.255.0"
		if subnet.IsValid() {
			mask = net.IP(net.CIDRMask(subnet.Bits(), 32)).String()
		}
		d["ifconfig-push"] = one(ip, mask)
	}
	d["ifconfig-ipv6-push"] = opt(s.IP6)
	for _, r := range s.IRoutes {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if p, err := netip.ParsePrefix(r); err == nil && p.Addr().Is4() {
			d["iroute"] = append(d["iroute"], netmask4(p))
		} else if err == nil {
			d["iroute-ipv6"] = append(d["iroute-ipv6"], []string{r})
		} else {
			d["iroute"] = append(d["iroute"], strings.Fields(r))
		}
	}
	d["push"] = each(s.Push)
	d["push-reset"] = flag(s.PushReset)
	d["disable"] = flag(s.Disabled)
	return d
}

// applyCCD rewrites the managed directives of a client-config-dir file.
func applyCCD(text string, s CCDSettings, subnet netip.Prefix) string {
	oldD, newD := extractCCD(text).directives(subnet), s.directives(subnet)
	changes := map[string][][]string{}
	for name, v := range newD {
		if !equalArgs(oldD[name], v) {
			changes[name] = v
		}
	}
	return mergeDirectives(text, changes, ccdManaged, nil)
}
