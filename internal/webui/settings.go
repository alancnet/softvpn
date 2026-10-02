package webui

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"github.com/softvpn/softvpn/internal/config"
)

// Settings are the server.conf directives the structured editor manages.
// Everything else in the file - comments, other directives, inline blocks -
// is kept as it is.
type Settings struct {
	Port       string   `json:"port"`
	Proto      []string `json:"proto"`
	Dev        string   `json:"dev"`        // "tun" or "tap"
	Server     string   `json:"server"`     // IPv4 subnet, 10.8.0.0/24
	ServerIPv6 string   `json:"serverIPv6"` // fd00:8::/64, "" for none
	Routes     []string `json:"routes"`     // route / route-ipv6, as prefixes

	ClientToClient    bool     `json:"clientToClient"`
	DuplicateCN       bool     `json:"duplicateCN"`
	MaxClients        string   `json:"maxClients"`
	KeepaliveInterval string   `json:"keepaliveInterval"`
	KeepaliveTimeout  string   `json:"keepaliveTimeout"`
	Push              []string `json:"push"`

	DataCiphers      []string `json:"dataCiphers"` // empty: the default list
	CipherFallback   string   `json:"cipherFallback"`
	Auth             string   `json:"auth"`
	Compression      string   `json:"compression"` // a whole directive: "compress lz4-v2", "comp-lzo no", ""
	AllowCompression string   `json:"allowCompression"`

	VerifyClientCert     string `json:"verifyClientCert"`
	AuthUserPassFile     string `json:"authUserPassFile"`
	UsernameAsCommonName bool   `json:"usernameAsCommonName"`
	AuthUserPassOptional bool   `json:"authUserPassOptional"`
	AuthGenToken         bool   `json:"authGenToken"`
	AuthGenTokenLifetime string `json:"authGenTokenLifetime"`
	CRLVerify            string `json:"crlVerify"`
	ClientConfigDir      string `json:"clientConfigDir"`

	TLSWrap       string `json:"tlsWrap"`       // "", tls-auth, tls-crypt, tls-crypt-v2
	TLSWrapFile   string `json:"tlsWrapFile"`   // "" with TLSWrapInline: an inline block
	TLSWrapInline bool   `json:"tlsWrapInline"` // the key is an inline block in server.conf
	KeyDirection  string `json:"keyDirection"`  // tls-auth: "0", "1" or ""

	UpstreamDNS string   `json:"upstreamDNS"`
	NATAllow    []string `json:"natAllow"`
	NATDeny     []string `json:"natDeny"`
	Verb        string   `json:"verb"`
	TunMTU      string   `json:"tunMTU"`
}

// managed are the directive names Settings owns, in groups that belong
// together: a directive that is new to the file goes next to the others of
// its group.
var managed = [][]string{
	{"port", "proto"},
	{"dev", "dev-type", "server", "server-ipv6"},
	{"route", "route-ipv6"},
	{"client-to-client", "duplicate-cn", "max-clients", "keepalive"},
	{"push"},
	{"data-ciphers", "ncp-ciphers", "data-ciphers-fallback", "auth"},
	{"compress", "comp-lzo", "allow-compression"},
	{"crl-verify", "auth-user-pass-file", "verify-client-cert", "username-as-common-name", "auth-user-pass-optional", "auth-gen-token"},
	{"client-config-dir"},
	{"tls-auth", "tls-crypt", "tls-crypt-v2", "key-direction"},
	{"upstream-dns", "nat-allow", "nat-deny"},
	{"tun-mtu", "verb"},
}

var wrapModes = []string{"tls-auth", "tls-crypt", "tls-crypt-v2"}

// extractSettings reads the managed directives from server.conf text. Only
// the file is looked at, not the command line.
func extractSettings(text string) Settings {
	s := Settings{Dev: "tun", Proto: []string{}, Routes: []string{}, Push: []string{}, DataCiphers: []string{},
		NATAllow: []string{}, NATDeny: []string{}}
	blocks := map[string]bool{}
	for _, l := range config.SplitLines(text) {
		if l.Block != "" {
			blocks[l.Block] = true
			continue
		}
		a := l.Args
		arg := func(i int) string {
			if i < len(a) {
				return a[i]
			}
			return ""
		}
		switch l.Name {
		case "port":
			s.Port = arg(0)
		case "proto":
			s.Proto = append(s.Proto, strings.ToLower(arg(0)))
		case "dev":
			if strings.HasPrefix(arg(0), "tap") {
				s.Dev = "tap"
			} else if strings.HasPrefix(arg(0), "tun") {
				s.Dev = "tun"
			}
		case "dev-type":
			if arg(0) == "tap" || arg(0) == "tun" {
				s.Dev = arg(0)
			}
		case "server":
			s.Server = subnetString(a)
		case "server-ipv6":
			s.ServerIPv6 = arg(0)
		case "route":
			s.Routes = append(s.Routes, routeString(arg(0), arg(1)))
		case "route-ipv6":
			s.Routes = append(s.Routes, arg(0))
		case "client-to-client":
			s.ClientToClient = true
		case "duplicate-cn":
			s.DuplicateCN = true
		case "max-clients":
			s.MaxClients = arg(0)
		case "keepalive":
			s.KeepaliveInterval, s.KeepaliveTimeout = arg(0), arg(1)
		case "push":
			s.Push = append(s.Push, arg(0))
		case "data-ciphers", "ncp-ciphers":
			s.DataCiphers = []string{}
			for _, c := range strings.Split(arg(0), ":") {
				if c != "" {
					s.DataCiphers = append(s.DataCiphers, strings.ToUpper(c))
				}
			}
		case "data-ciphers-fallback":
			s.CipherFallback = strings.ToUpper(arg(0))
		case "auth":
			s.Auth = strings.ToUpper(arg(0))
		case "compress", "comp-lzo":
			s.Compression = strings.TrimSpace(l.Name + " " + strings.ToLower(arg(0)))
		case "allow-compression":
			s.AllowCompression = strings.ToLower(arg(0))
		case "verify-client-cert":
			s.VerifyClientCert = strings.ToLower(arg(0))
		case "auth-user-pass-file":
			s.AuthUserPassFile = arg(0)
		case "username-as-common-name":
			s.UsernameAsCommonName = true
		case "auth-user-pass-optional":
			s.AuthUserPassOptional = true
		case "auth-gen-token":
			s.AuthGenToken, s.AuthGenTokenLifetime = true, arg(0)
		case "crl-verify":
			s.CRLVerify = arg(0)
		case "client-config-dir":
			s.ClientConfigDir = arg(0)
		case "tls-auth", "tls-crypt", "tls-crypt-v2":
			s.TLSWrap, s.TLSWrapFile, s.TLSWrapInline = l.Name, arg(0), false
			if arg(0) == "[inline]" {
				s.TLSWrapFile, s.TLSWrapInline = "", true
			}
			if l.Name == "tls-auth" && arg(1) != "" {
				s.KeyDirection = arg(1)
			}
		case "key-direction":
			s.KeyDirection = arg(0)
		case "upstream-dns":
			s.UpstreamDNS = arg(0)
		case "nat-allow":
			s.NATAllow = append(s.NATAllow, a...)
		case "nat-deny":
			s.NATDeny = append(s.NATDeny, a...)
		case "verb":
			s.Verb = arg(0)
		case "tun-mtu":
			s.TunMTU = arg(0)
		}
	}
	if s.TLSWrap == "" {
		for _, m := range wrapModes {
			if blocks[m] {
				s.TLSWrap, s.TLSWrapInline = m, true
			}
		}
	}
	return s
}

func subnetString(a []string) string {
	switch len(a) {
	case 1:
		return a[0]
	case 2:
		if ip := net.ParseIP(a[1]).To4(); ip != nil {
			if ones, bits := net.IPMask(ip).Size(); bits == 32 {
				return fmt.Sprintf("%s/%d", a[0], ones)
			}
		}
	}
	return strings.Join(a, " ")
}

func routeString(network, netmask string) string {
	if netmask == "" || strings.Contains(network, "/") {
		if strings.Contains(network, "/") {
			return network
		}
		return network + "/32"
	}
	return subnetString([]string{network, netmask})
}

// netmask4 renders an IPv4 prefix as NETWORK NETMASK.
func netmask4(p netip.Prefix) []string {
	return []string{p.Addr().String(), net.IP(net.CIDRMask(p.Bits(), 32)).String()}
}

func one(args ...string) [][]string { return [][]string{args} }

func flag(on bool) [][]string {
	if on {
		return [][]string{{}}
	}
	return nil
}

func opt(v string, args ...string) [][]string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return one(append([]string{strings.TrimSpace(v)}, args...)...)
}

func each(vs []string) [][]string {
	var out [][]string
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, []string{v})
		}
	}
	return out
}

// directives renders the settings as directive arguments, by name. A nil
// entry removes the directive.
func (s Settings) directives() map[string][][]string {
	d := map[string][][]string{}
	for _, g := range managed {
		for _, n := range g {
			d[n] = nil
		}
	}
	d["port"] = opt(s.Port)
	d["proto"] = each(s.Proto)
	if s.Dev != "" {
		d["dev"] = one(s.Dev)
	}
	if p, err := netip.ParsePrefix(strings.TrimSpace(s.Server)); err == nil && p.Addr().Is4() {
		d["server"] = one(netmask4(p)...)
	} else if strings.TrimSpace(s.Server) != "" {
		d["server"] = [][]string{strings.Fields(s.Server)} // the server reports what is wrong
	}
	d["server-ipv6"] = opt(s.ServerIPv6)
	for _, r := range s.Routes {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if p, err := netip.ParsePrefix(r); err == nil && p.Addr().Is4() {
			d["route"] = append(d["route"], netmask4(p))
		} else if err == nil {
			d["route-ipv6"] = append(d["route-ipv6"], []string{r})
		} else {
			d["route"] = append(d["route"], strings.Fields(r))
		}
	}
	d["client-to-client"] = flag(s.ClientToClient)
	d["duplicate-cn"] = flag(s.DuplicateCN)
	if m := strings.TrimSpace(s.MaxClients); m != "0" {
		d["max-clients"] = opt(m)
	}
	if strings.TrimSpace(s.KeepaliveInterval+s.KeepaliveTimeout) != "" {
		d["keepalive"] = one(strings.TrimSpace(s.KeepaliveInterval), strings.TrimSpace(s.KeepaliveTimeout))
	}
	d["push"] = each(s.Push)
	var ciphers []string
	for _, c := range s.DataCiphers {
		if c = strings.TrimSpace(c); c != "" {
			ciphers = append(ciphers, c)
		}
	}
	if len(ciphers) > 0 {
		d["data-ciphers"] = one(strings.Join(ciphers, ":"))
	}
	d["data-ciphers-fallback"] = opt(s.CipherFallback)
	d["auth"] = opt(s.Auth)
	if f := strings.Fields(s.Compression); len(f) > 0 && (f[0] == "compress" || f[0] == "comp-lzo") {
		d[f[0]] = one(f[1:]...)
	}
	d["allow-compression"] = opt(s.AllowCompression)
	d["verify-client-cert"] = opt(s.VerifyClientCert)
	d["auth-user-pass-file"] = opt(s.AuthUserPassFile)
	d["username-as-common-name"] = flag(s.UsernameAsCommonName)
	d["auth-user-pass-optional"] = flag(s.AuthUserPassOptional)
	if s.AuthGenToken {
		d["auth-gen-token"] = one()
		if l := strings.TrimSpace(s.AuthGenTokenLifetime); l != "" {
			d["auth-gen-token"] = one(l)
		}
	}
	d["crl-verify"] = opt(s.CRLVerify)
	d["client-config-dir"] = opt(s.ClientConfigDir)
	switch {
	case s.TLSWrap == "":
	case s.TLSWrapInline && strings.TrimSpace(s.TLSWrapFile) == "":
		// The inline block carries the key; key-direction goes with it.
		if s.TLSWrap == "tls-auth" {
			d["key-direction"] = opt(s.KeyDirection)
		}
	case s.TLSWrap == "tls-auth":
		d["tls-auth"] = opt(s.TLSWrapFile, strings.Fields(s.KeyDirection)...)
	default:
		d[s.TLSWrap] = opt(s.TLSWrapFile)
	}
	d["upstream-dns"] = opt(s.UpstreamDNS)
	if len(each(s.NATAllow)) > 0 {
		d["nat-allow"] = [][]string{flatten(each(s.NATAllow))}
	}
	if len(each(s.NATDeny)) > 0 {
		d["nat-deny"] = [][]string{flatten(each(s.NATDeny))}
	}
	d["verb"] = opt(s.Verb)
	d["tun-mtu"] = opt(s.TunMTU)
	return d
}

func flatten(vs [][]string) []string {
	var out []string
	for _, v := range vs {
		out = append(out, v...)
	}
	return out
}

// applySettings rewrites the managed directives in text to match s. Lines
// for settings that did not change are left exactly as they were (including
// their comments); a directive that is new goes after the others of its
// group, or at the end.
func applySettings(text string, s Settings) (string, error) {
	old := extractSettings(text)
	inline := func(s Settings) bool { return s.TLSWrapInline && strings.TrimSpace(s.TLSWrapFile) == "" }
	switch {
	case s.TLSWrap != "" && !contains(wrapModes, s.TLSWrap):
		return "", fmt.Errorf("unknown control-channel protection %q", s.TLSWrap)
	case s.TLSWrap != "" && strings.TrimSpace(s.TLSWrapFile) == "" && !(inline(s) && inline(old) && s.TLSWrap == old.TLSWrap):
		return "", fmt.Errorf("%s needs a key file (generate one, or give its path)", s.TLSWrap)
	}
	oldD, newD := old.directives(), s.directives()
	changes := map[string][][]string{}
	for name, v := range newD {
		if !equalArgs(oldD[name], v) {
			changes[name] = v
		}
	}
	// dev-type is never written; a changed mode replaces it with dev.
	delete(changes, "dev-type")
	if _, ok := changes["dev"]; ok {
		changes["dev-type"] = nil
	}
	// Inline keys go when the mode changes or a key file replaces them.
	var drop []string
	if s.TLSWrap != old.TLSWrap || inline(s) != inline(old) {
		for _, m := range wrapModes {
			if m != s.TLSWrap || !inline(s) {
				drop = append(drop, m)
			}
		}
	}
	return mergeDirectives(text, changes, managed, drop), nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func equalArgs(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

// mergeDirectives replaces every line of each directive in set with the
// given argument lists, in place: the k-th existing line becomes the k-th
// new one (unchanged if its arguments already match), extra existing lines
// are removed and extra new ones inserted after the last existing one, or
// after the last line of another directive in its group, or at the end.
// Inline blocks named in dropBlocks are removed.
func mergeDirectives(text string, set map[string][][]string, groups [][]string, dropBlocks []string) string {
	lines := config.SplitLines(text)
	drop := make([]bool, len(lines))
	after := map[int][]string{} // inserted after line i; -1: at the end
	groupIndex := map[string]int{}
	for i, g := range groups {
		for _, n := range g {
			groupIndex[n] = i
		}
	}
	last := map[string]int{}
	for i, l := range lines {
		if l.Name != "" {
			last[l.Name] = i
		}
		for _, b := range dropBlocks {
			if l.Block == b {
				drop[i] = true
			}
		}
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		want := set[name]
		k := 0
		for i, l := range lines {
			if l.Name != name {
				continue
			}
			if k < len(want) {
				if !equalArgs([][]string{l.Args}, want[k:k+1]) {
					lines[i].Raw = config.FormatDirective(name, want[k]...)
				}
			} else {
				drop[i] = true
			}
			k++
		}
		if k >= len(want) {
			continue
		}
		at := -1
		if i, ok := last[name]; ok {
			at = i
		} else {
			// After its group, or else after the nearest earlier group
			// that is in the file.
			for g := groupIndex[name]; g >= 0 && at < 0; g-- {
				for _, n := range groups[g] {
					if i, ok := last[n]; ok && i > at {
						at = i
					}
				}
			}
		}
		for _, w := range want[k:] {
			after[at] = append(after[at], config.FormatDirective(name, w...))
		}
	}
	var b strings.Builder
	for i, l := range lines {
		if !drop[i] {
			b.WriteString(l.Raw + "\n")
		}
		for _, ins := range after[i] {
			b.WriteString(ins + "\n")
		}
	}
	for _, ins := range after[-1] {
		b.WriteString(ins + "\n")
	}
	return b.String()
}
