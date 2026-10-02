package server

import (
	"strings"
	"testing"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/ovpn"
)

func TestControlWrapConfig(t *testing.T) {
	static := string(ovpn.GenerateStaticKey().Marshal())
	v2 := string(ovpn.GenerateTLSCryptV2ServerKey().Marshal())
	v2client, _ := ovpn.GenerateTLSCryptV2ServerKey().NewTLSCryptV2ClientKey(nil)
	block := func(name, body string) string { return "<" + name + ">\n" + body + "</" + name + ">\n" }

	for _, c := range []struct {
		conf string
		want ovpn.ControlWrap // Key fields not compared
		err  string
	}{
		{conf: "", want: ovpn.ControlWrap{}},
		{conf: block("tls-auth", static) + "key-direction 0\n", want: ovpn.ControlWrap{Mode: ovpn.WrapTLSAuth, Direction: ovpn.KeyDirNormal, Digest: "SHA1"}},
		{conf: block("tls-auth", static) + "auth SHA256\n", want: ovpn.ControlWrap{Mode: ovpn.WrapTLSAuth, Direction: ovpn.KeyDirBidi, Digest: "SHA256"}},
		{conf: "tls-auth [inline] 1\n" + block("tls-auth", static), want: ovpn.ControlWrap{Mode: ovpn.WrapTLSAuth, Direction: ovpn.KeyDirInverse, Digest: "SHA1"}},
		{conf: block("tls-auth", static) + "key-direction 2\n", err: "key direction"},
		{conf: block("tls-auth", static) + "auth MD4\n", err: "unsupported digest"},
		{conf: block("tls-crypt", static) + "auth MD4\n", want: ovpn.ControlWrap{Mode: ovpn.WrapTLSCrypt}},
		{conf: block("tls-crypt-v2", v2), want: ovpn.ControlWrap{Mode: ovpn.WrapTLSCryptV2}},
		{conf: block("tls-crypt-v2", string(v2client)), err: "server key"},
		{conf: block("tls-crypt", "junk\n"), err: "static key"},
		{conf: block("tls-crypt", static) + block("tls-auth", static), err: "only one"},
	} {
		cfg, err := config.ParseString(c.conf)
		if err != nil {
			t.Fatal(err)
		}
		w, err := controlWrap(cfg)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Fatalf("%q: want error %q, got %v", c.conf, c.err, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", c.conf, err)
		}
		if w == nil {
			if c.want.Mode != ovpn.WrapNone {
				t.Fatalf("%q: no wrap", c.conf)
			}
			continue
		}
		if w.Mode != c.want.Mode || w.Direction != c.want.Direction || w.Digest != c.want.Digest && c.want.Mode == ovpn.WrapTLSAuth {
			t.Fatalf("%q: got %+v", c.conf, w)
		}
		if (w.Key == nil) != (w.Mode == ovpn.WrapTLSCryptV2) || (w.V2Key == nil) != (w.Mode != ovpn.WrapTLSCryptV2) {
			t.Fatalf("%q: keys %+v", c.conf, w)
		}
	}
}
