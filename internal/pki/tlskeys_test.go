package pki

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/ovpn"
)

func TestWrapProfiles(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	if err := d.Init("server", nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := d.Issue("laptop", RoleClient, nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GenTLSCryptV2ClientKey("laptop", nil); err == nil {
		t.Fatal("client key without a server key")
	}
	for _, w := range []Wrap{WrapTLSAuth, WrapTLSCrypt, WrapTLSCryptV2} {
		if made, err := d.GenKey(w); err != nil || !made {
			t.Fatalf("%s: GenKey: %v", w, err)
		}
		before, _ := d.Read(w.KeyFile())
		if made, err := d.GenKey(w); err != nil || made {
			t.Fatalf("%s: second GenKey must keep the key: %v", w, err)
		}
		if after, _ := d.Read(w.KeyFile()); !bytes.Equal(before, after) {
			t.Fatal("key replaced")
		}
	}
	if made, err := d.GenTLSCryptV2ClientKey("laptop", []byte("laptop of alice")); err != nil || !made {
		t.Fatal(err)
	}
	if _, err := d.GenTLSCryptV2ClientKey("../x", nil); err == nil {
		t.Fatal("path in client name accepted")
	}

	for _, c := range []struct {
		w    Wrap
		want []string
	}{
		{WrapNone, nil},
		{WrapTLSAuth, []string{"<tls-auth>\n#\n# 2048 bit OpenVPN static key", "</tls-auth>\nkey-direction 1\n"}},
		{WrapTLSCrypt, []string{"<tls-crypt>\n#\n# 2048 bit OpenVPN static key", "</tls-crypt>\n"}},
		{WrapTLSCryptV2, []string{"<tls-crypt-v2>\n-----BEGIN OpenVPN tls-crypt-v2 client key-----\n"}},
	} {
		d.Wrap = c.w
		p, err := d.Profile("laptop", "vpn.example.com", 1194, "udp")
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range c.want {
			if !strings.Contains(p, s) {
				t.Fatalf("%s profile lacks %q:\n%s", c.w, s, p)
			}
		}
		cfg, err := config.ParseString(p)
		if err != nil {
			t.Fatal(err)
		}
		if c.w == WrapNone {
			if strings.Contains(p, "tls-") {
				t.Fatal("unwrapped profile mentions tls-*")
			}
			continue
		}
		key, err := cfg.Material(string(c.w))
		if err != nil {
			t.Fatal(err)
		}
		if c.w == WrapTLSCryptV2 {
			// The embedded client key must unwrap under the server key.
			srvPEM, _ := d.Read(TLSCryptV2ServerKeyFile)
			srv, _ := ovpn.ParseTLSCryptV2ServerKey(srvPEM)
			ck, wkc, err := ovpn.ParseTLSCryptV2ClientKey(key)
			if err != nil {
				t.Fatal(err)
			}
			got, md, err := srv.UnwrapClientKey(wkc)
			if err != nil || *got != *ck || string(md) != "\x00laptop of alice" {
				t.Fatalf("client key: %q %v", md, err)
			}
		} else if _, err := ovpn.ParseStaticKey(key); err != nil {
			t.Fatal(err)
		}
	}
	d.Wrap = "bogus"
	if _, err := d.Profile("laptop", "x", 1, "udp"); err == nil {
		t.Fatal("bogus wrap accepted")
	}
	if _, err := ParseWrap("TLS-Crypt"); err != nil {
		t.Fatal(err)
	}
}
