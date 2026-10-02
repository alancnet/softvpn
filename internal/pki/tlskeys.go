package pki

import (
	"fmt"
	"os"
	"strings"

	"github.com/softvpn/softvpn/internal/ovpn"
)

// Wrap is the control-channel protection (tls-auth, tls-crypt or
// tls-crypt-v2) that profiles are made for. The key files are in OpenVPN's
// formats, so "openvpn --genkey" keys work too.
type Wrap string

const (
	WrapNone       Wrap = ""
	WrapTLSAuth    Wrap = "tls-auth"     // server: tls-auth ta.key 0
	WrapTLSCrypt   Wrap = "tls-crypt"    // server: tls-crypt tc.key
	WrapTLSCryptV2 Wrap = "tls-crypt-v2" // server: tls-crypt-v2 tls-crypt-v2.key
)

// Key file names in a Dir.
const (
	TLSAuthKeyFile            = "ta.key"
	TLSCryptKeyFile           = "tc.key"
	TLSCryptV2ServerKeyFile   = "tls-crypt-v2.key"
	tlsCryptV2ClientKeySuffix = "-tls-crypt-v2.key"
)

// TLSCryptV2ClientKeyFile is the file holding a client's tls-crypt-v2 key.
func TLSCryptV2ClientKeyFile(name string) string { return name + tlsCryptV2ClientKeySuffix }

// ParseWrap validates a wrap mode name ("" or "none" for none).
func ParseWrap(s string) (Wrap, error) {
	switch w := Wrap(strings.ToLower(s)); w {
	case WrapNone, WrapTLSAuth, WrapTLSCrypt, WrapTLSCryptV2:
		return w, nil
	case "none":
		return WrapNone, nil
	}
	return "", fmt.Errorf("unknown control-channel wrap %q (use tls-auth, tls-crypt or tls-crypt-v2)", s)
}

// KeyFile is the shared (tls-auth, tls-crypt) or server (tls-crypt-v2) key
// file for the mode.
func (w Wrap) KeyFile() string {
	switch w {
	case WrapTLSAuth:
		return TLSAuthKeyFile
	case WrapTLSCrypt:
		return TLSCryptKeyFile
	case WrapTLSCryptV2:
		return TLSCryptV2ServerKeyFile
	}
	return ""
}

// NewKey returns a fresh key file for the mode: an OpenVPN static key for
// tls-auth and tls-crypt ("openvpn --genkey secret"), or a tls-crypt-v2
// server key ("openvpn --genkey tls-crypt-v2-server").
func NewKey(w Wrap) ([]byte, error) {
	switch w {
	case WrapTLSAuth, WrapTLSCrypt:
		return ovpn.GenerateStaticKey().Marshal(), nil
	case WrapTLSCryptV2:
		return ovpn.GenerateTLSCryptV2ServerKey().Marshal(), nil
	}
	return nil, fmt.Errorf("no key for control-channel wrap %q", w)
}

// NewTLSCryptV2ClientKey returns a client key wrapped by the server key, as
// "openvpn --tls-crypt-v2 SERVERKEY --genkey tls-crypt-v2-client" would.
// metadata (at most 733 bytes) is passed to the server as user data; when nil
// the key records its creation time instead, like openvpn's default.
func NewTLSCryptV2ClientKey(serverKey, metadata []byte) ([]byte, error) {
	k, err := ovpn.ParseTLSCryptV2ServerKey(serverKey)
	if err != nil {
		return nil, err
	}
	if metadata != nil {
		metadata = append([]byte{ovpn.MetadataUser}, metadata...)
	}
	return k.NewTLSCryptV2ClientKey(metadata)
}

// GenKey creates the mode's shared or server key in the directory unless it
// already exists, and reports whether it did.
func (d Dir) GenKey(w Wrap) (bool, error) {
	if w == WrapNone || d.Exists(w.KeyFile()) {
		return false, nil
	}
	k, err := NewKey(w)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(d.Path, 0o755); err != nil {
		return false, err
	}
	return true, d.write(w.KeyFile(), k, d.privateMode())
}

// GenTLSCryptV2ClientKey creates a client's tls-crypt-v2 key, wrapped by the
// directory's server key, unless it already exists, and reports whether it
// did.
func (d Dir) GenTLSCryptV2ClientKey(name string, metadata []byte) (bool, error) {
	if err := validName(name); err != nil {
		return false, err
	}
	file := TLSCryptV2ClientKeyFile(name)
	if d.Exists(file) {
		return false, nil
	}
	srv, err := d.Read(TLSCryptV2ServerKeyFile)
	if err != nil {
		return false, fmt.Errorf("tls-crypt-v2 server key: %w", err)
	}
	return d.GenTLSCryptV2ClientKeyFrom(name, srv, metadata)
}

// GenTLSCryptV2ClientKeyFrom is GenTLSCryptV2ClientKey with the server key
// given (for a server key kept outside the directory).
func (d Dir) GenTLSCryptV2ClientKeyFrom(name string, serverKey, metadata []byte) (bool, error) {
	if err := validName(name); err != nil {
		return false, err
	}
	file := TLSCryptV2ClientKeyFile(name)
	if d.Exists(file) {
		return false, nil
	}
	k, err := NewTLSCryptV2ClientKey(serverKey, metadata)
	if err != nil {
		return false, err
	}
	return true, d.write(file, k, d.privateMode())
}

// wrapBlock is the profile section for the control-channel protection in
// opt.
func (d Dir) wrapBlock(name string, opt ProfileOptions) (string, error) {
	var file, tag, extra string
	switch opt.Wrap {
	case WrapNone:
		return "", nil
	case WrapTLSAuth:
		file, tag, extra = TLSAuthKeyFile, "tls-auth", "key-direction 1\n"
		switch opt.KeyDirection {
		case "", "1":
		case "0":
			extra = "key-direction 0\n"
		case "none":
			extra = ""
		default:
			return "", fmt.Errorf("invalid key direction %q", opt.KeyDirection)
		}
	case WrapTLSCrypt:
		file, tag = TLSCryptKeyFile, "tls-crypt"
	case WrapTLSCryptV2:
		file, tag = TLSCryptV2ClientKeyFile(name), "tls-crypt-v2"
	default:
		return "", fmt.Errorf("unknown control-channel wrap %q", opt.Wrap)
	}
	k := opt.WrapKey
	if k == nil {
		var err error
		if k, err = d.Read(file); err != nil {
			return "", fmt.Errorf("%s key: %w", tag, err)
		}
	}
	return fmt.Sprintf("<%s>\n%s</%s>\n%s", tag, k, tag, extra), nil
}
