package webui

import (
	"net/netip"
	"strings"
	"testing"
)

const sample = `# My server
port 1194
proto udp            # main
dev tun
server 10.8.0.0 255.255.255.0
keepalive 10 60      # keep this comment

push "redirect-gateway def1"
push "dhcp-option DNS 10.8.0.1"
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
abc
-----END OpenVPN Static key V1-----
</tls-crypt>
<ca>
-----BEGIN CERTIFICATE-----
port 9999
-----END CERTIFICATE-----
</ca>
verb 3
`

func TestSettingsRoundTrip(t *testing.T) {
	s := extractSettings(sample)
	if s.Port != "1194" || s.Server != "10.8.0.0/24" || s.KeepaliveInterval != "10" || len(s.Push) != 2 ||
		s.TLSWrap != "tls-crypt" || !s.TLSWrapInline || s.Verb != "3" {
		t.Fatalf("extracted %+v", s)
	}
	// Unchanged settings leave the text alone, byte for byte.
	if got, err := applySettings(sample, s); err != nil || got != sample {
		t.Fatalf("unchanged settings rewrote the file (%v):\n%s", err, got)
	}
}

func TestSettingsEdit(t *testing.T) {
	s := extractSettings(sample)
	s.KeepaliveInterval, s.KeepaliveTimeout = "5", "30"
	s.Push = append(s.Push, "route 10.20.0.0 255.255.0.0")
	s.Proto = []string{"udp", "tcp"}
	s.ClientToClient = true
	s.Verb = ""
	s.Routes = []string{"192.168.10.0/24", "fd00:10::/64"}
	got, err := applySettings(sample, s)
	if err != nil {
		t.Fatal(err)
	}
	want := `# My server
port 1194
proto udp            # main
proto tcp
dev tun
server 10.8.0.0 255.255.255.0
route 192.168.10.0 255.255.255.0
route-ipv6 fd00:10::/64
keepalive 5 30
client-to-client

push "redirect-gateway def1"
push "dhcp-option DNS 10.8.0.1"
push "route 10.20.0.0 255.255.0.0"
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
abc
-----END OpenVPN Static key V1-----
</tls-crypt>
<ca>
-----BEGIN CERTIFICATE-----
port 9999
-----END CERTIFICATE-----
</ca>
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSettingsWrapChange(t *testing.T) {
	s := extractSettings(sample)
	s.TLSWrap, s.TLSWrapFile, s.TLSWrapInline = "tls-auth", "ta.key", false
	s.KeyDirection = "0"
	got, err := applySettings(sample, s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "<tls-crypt>") || !strings.Contains(got, "\ntls-auth ta.key 0\n") || !strings.Contains(got, "<ca>\n") {
		t.Fatalf("wrap change:\n%s", got)
	}
	// A mode without a key file is refused.
	s.TLSWrapFile = ""
	if _, err := applySettings(sample, s); err == nil {
		t.Error("tls-auth without a key accepted")
	}
	// Turning protection off removes the inline key.
	s = extractSettings(sample)
	s.TLSWrap = ""
	got, _ = applySettings(sample, s)
	if strings.Contains(got, "tls-crypt") || strings.Contains(got, "Static key") {
		t.Fatalf("wrap off:\n%s", got)
	}
}

func TestSettingsCompressionAndDev(t *testing.T) {
	text := "dev tun0\ncomp-lzo no\nproto udp\n"
	s := extractSettings(text)
	if s.Dev != "tun" || s.Compression != "comp-lzo no" {
		t.Fatalf("%+v", s)
	}
	s.Compression = "compress lz4-v2"
	s.Dev = "tap"
	got, _ := applySettings(text, s)
	if got != "dev tap\ncompress lz4-v2\nproto udp\n" {
		t.Fatalf("got %q", got)
	}
	// Unchanged dev keeps the device name.
	s = extractSettings(text)
	s.Port = "1195"
	got, _ = applySettings(text, s)
	if got != "dev tun0\ncomp-lzo no\nproto udp\nport 1195\n" {
		t.Fatalf("got %q", got)
	}
}

func TestCCDSettings(t *testing.T) {
	text := "# alice's laptop\nifconfig-push 10.8.0.20 255.255.255.0\npush \"route 10.1.0.0 255.255.0.0\"\n"
	s := extractCCD(text)
	if s.IP != "10.8.0.20" || len(s.Push) != 1 || s.Disabled {
		t.Fatalf("%+v", s)
	}
	subnet := netip.MustParsePrefix("10.8.0.0/24")
	if got := applyCCD(text, s, subnet); got != text {
		t.Fatalf("unchanged: %q", got)
	}
	s.Disabled = true
	s.IRoutes = []string{"192.168.1.0/24"}
	s.IP = ""
	got := applyCCD(text, s, subnet)
	want := "# alice's laptop\niroute 192.168.1.0 255.255.255.0\npush \"route 10.1.0.0 255.255.0.0\"\ndisable\n"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
