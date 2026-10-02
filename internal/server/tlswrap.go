package server

import (
	"fmt"
	"strings"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/ovpn"
)

// controlWrap reads tls-auth, tls-crypt or tls-crypt-v2 (at most one), each
// given as a file or an inline block, like OpenVPN:
//
//	tls-auth ta.key 0         # or <tls-auth> + "key-direction 0"; "auth" picks the HMAC
//	tls-crypt tc.key
//	tls-crypt-v2 tls-crypt-v2.key
//
// It returns nil when none is configured.
func controlWrap(c *config.Config) (*ovpn.ControlWrap, error) {
	var set []string
	for _, n := range []string{"tls-auth", "tls-crypt", "tls-crypt-v2"} {
		if c.HasMaterial(n) {
			set = append(set, n)
		}
	}
	switch len(set) {
	case 0:
		return nil, nil
	case 1:
	default:
		return nil, fmt.Errorf("%s: only one of these can be used", strings.Join(set, ", "))
	}

	switch set[0] {
	case "tls-auth":
		b, args, err := c.MaterialArgs("tls-auth", 1)
		if err != nil {
			return nil, err
		}
		k, err := ovpn.ParseStaticKey(b)
		if err != nil {
			return nil, fmt.Errorf("tls-auth: %v", err)
		}
		w := &ovpn.ControlWrap{Mode: ovpn.WrapTLSAuth, Key: k, Direction: ovpn.KeyDirBidi, Digest: c.String("auth", "SHA1")}
		dir := ""
		if d, ok := c.Last("key-direction"); ok {
			dir = d.Arg(0)
		}
		if len(args) > 0 {
			dir = args[0]
		}
		switch dir {
		case "":
		case "0":
			w.Direction = ovpn.KeyDirNormal
		case "1":
			w.Direction = ovpn.KeyDirInverse
		default:
			return nil, fmt.Errorf("tls-auth: key direction must be 0 or 1, not %q", dir)
		}
		if _, err := ovpn.DigestFunc(w.Digest); err != nil {
			return nil, fmt.Errorf("auth: %v", err)
		}
		return w, nil
	case "tls-crypt":
		b, err := c.Material("tls-crypt")
		if err != nil {
			return nil, err
		}
		k, err := ovpn.ParseStaticKey(b)
		if err != nil {
			return nil, fmt.Errorf("tls-crypt: %v", err)
		}
		return &ovpn.ControlWrap{Mode: ovpn.WrapTLSCrypt, Key: k}, nil
	default:
		b, err := c.Material("tls-crypt-v2")
		if err != nil {
			return nil, err
		}
		k, err := ovpn.ParseTLSCryptV2ServerKey(b)
		if err != nil {
			return nil, fmt.Errorf("tls-crypt-v2: %v (the server needs the server key, not a client key)", err)
		}
		return &ovpn.ControlWrap{Mode: ovpn.WrapTLSCryptV2, V2Key: k}, nil
	}
}
