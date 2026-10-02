package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/softvpn/softvpn/internal/config"
	"github.com/softvpn/softvpn/internal/ovpn"
	"github.com/softvpn/softvpn/internal/pki"
)

func loadConf(t *testing.T, extra string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	if err := (pki.Dir{Path: dir}).Init("server", nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	c, err := config.ParseString("ca " + dir + "/ca.crt\ncert " + dir + "/server.crt\nkey " + dir + "/server.key\n" + extra)
	if err != nil {
		t.Fatal(err)
	}
	return Load(c)
}

func TestLoadCiphers(t *testing.T) {
	cfg, err := loadConf(t, "")
	if err != nil || cfg.Auth != "SHA1" || cfg.CipherFallback != "" || cfg.Compress != ovpn.CompressUnset {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	// "cipher" not in data-ciphers becomes the fallback (OpenVPN 2.6).
	cfg, err = loadConf(t, "data-ciphers AES-256-GCM:aes-256-cbc\ncipher BF-CBC\nauth sha256\n")
	if err != nil || cfg.CipherFallback != "BF-CBC" || cfg.Auth != "SHA256" || cfg.Ciphers[1] != "AES-256-CBC" {
		t.Fatalf("got %+v %v", cfg, err)
	}
	cfg, err = loadConf(t, "data-ciphers AES-256-GCM:AES-256-CBC\ncipher AES-256-CBC\n")
	if err != nil || cfg.CipherFallback != "" {
		t.Fatalf("cipher in data-ciphers must not be a fallback: %q %v", cfg.CipherFallback, err)
	}
	cfg, err = loadConf(t, "cipher BF-CBC\ndata-ciphers-fallback AES-128-CBC\n")
	if err != nil || cfg.CipherFallback != "AES-128-CBC" {
		t.Fatalf("data-ciphers-fallback: %q %v", cfg.CipherFallback, err)
	}
	for _, bad := range []string{"cipher DES-CBC", "data-ciphers AES-256-GCM:CAMELLIA-128-CBC", "auth MD4", "data-ciphers-fallback none"} {
		if _, err := loadConf(t, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLoadCompression(t *testing.T) {
	for _, c := range []struct {
		conf  string
		mode  ovpn.Compress
		allow ovpn.AllowCompression
		bad   bool
	}{
		{"comp-lzo", ovpn.CompressLZO, ovpn.AllowCompressionAsym, false},
		{"comp-lzo no\ncompress lz4-v2", ovpn.CompressLZ4V2, ovpn.AllowCompressionAsym, false},
		{"compress lz4\nallow-compression yes", ovpn.CompressLZ4, ovpn.AllowCompressionYes, false},
		{"compress stub-v2\nallow-compression no", ovpn.CompressStubV2, ovpn.AllowCompressionNo, false},
		{"compress lz4\nallow-compression no", 0, 0, true},
		{"allow-compression maybe", 0, 0, true},
		{"compress zstd", 0, 0, true},
	} {
		cfg, err := loadConf(t, c.conf)
		if c.bad {
			if err == nil {
				t.Errorf("%q accepted", c.conf)
			}
			continue
		}
		if err != nil || cfg.Compress != c.mode || cfg.AllowCompression != c.allow {
			t.Errorf("%q: %v %v %v", c.conf, cfg.Compress, cfg.AllowCompression, err)
		}
	}

	cfg, err := loadConf(t, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.CCDDir = t.TempDir()
	os.WriteFile(filepath.Join(cfg.CCDDir, "old"), []byte("comp-lzo yes\n"), 0o644)
	cc, err := cfg.loadCCD("old")
	if err != nil || cc.Compress != ovpn.CompressLZO {
		t.Fatalf("client-config-dir comp-lzo: %+v %v", cc, err)
	}
	cfg.AllowCompression = ovpn.AllowCompressionNo
	if _, err := cfg.loadCCD("old"); err == nil || !strings.Contains(err.Error(), "allow-compression") {
		t.Fatalf("allow-compression no must reject comp-lzo yes in client-config-dir: %v", err)
	}
}
