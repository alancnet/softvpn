package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	c, err := ParseString(`
# comment
; also a comment
port 1194
push "redirect-gateway def1"   # trailing comment
push "route 10.0.0.0 255.0.0.0"
client-to-client
<ca>
-----BEGIN CERTIFICATE-----
abc
-----END CERTIFICATE-----
</ca>
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.String("port", "") != "1194" || !c.Has("client-to-client") {
		t.Fatal("simple directives")
	}
	push := c.All("push")
	if len(push) != 2 || push[0].Args[0] != "redirect-gateway def1" {
		t.Fatalf("quoted args: %+v", push)
	}
	ca, err := c.Material("ca")
	if err != nil || string(ca) != "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n" {
		t.Fatalf("inline block: %q %v", ca, err)
	}
	if err := c.Check("port", "push"); err == nil {
		t.Fatal("unknown directive accepted")
	}
	if _, err := ParseString("<key>\nnever closed\n"); err == nil {
		t.Fatal("unterminated inline block accepted")
	}
}

func TestArgsOverrideFile(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "server.conf")
	os.WriteFile(conf, []byte("port 1194\nca ca.crt\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("PEM"), 0o644)
	c, err := ParseArgs([]string{"--config", conf, "--port", "443", "--verb", "4"})
	if err != nil {
		t.Fatal(err)
	}
	if c.String("port", "") != "443" {
		t.Fatal("command line should override the file")
	}
	if n, _ := c.Int("verb", 0); n != 4 {
		t.Fatal("verb")
	}
	if b, err := c.Material("ca"); err != nil || string(b) != "PEM" {
		t.Fatalf("file paths in a config resolve relative to it: %q %v", b, err)
	}
	if _, err := ParseArgs([]string{"stray"}); err == nil {
		t.Fatal("stray argument accepted")
	}
}
