package fsutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "server.conf")
	if err := os.WriteFile(p, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(p)
	if err := WriteFile(p, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(p)
	if b, _ := os.ReadFile(p); string(b) != "new\n" {
		t.Fatalf("contents %q", b)
	}
	if after.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want the old file's 0640", after.Mode().Perm())
	}
	if os.SameFile(before, after) {
		t.Error("expected a new inode (rename)")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".server.conf.tmp*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

// A file bind-mounted into a container cannot be renamed over (EBUSY);
// WriteFile then rewrites it in place.
func TestWriteFileBindMountFallback(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EBUSY, syscall.EXDEV} {
		p := filepath.Join(t.TempDir(), "server.conf")
		if err := os.WriteFile(p, []byte("a much longer old content\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		before, _ := os.Stat(p)
		rename = func(oldpath, newpath string) error {
			return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: errno}
		}
		err := WriteFile(p, []byte("new\n"), 0o644)
		rename = os.Rename
		if err != nil {
			t.Fatalf("%v: %v", errno, err)
		}
		after, _ := os.Stat(p)
		if b, _ := os.ReadFile(p); string(b) != "new\n" {
			t.Fatalf("%v: contents %q", errno, b)
		}
		if !os.SameFile(before, after) {
			t.Errorf("%v: expected the same inode (written in place)", errno)
		}
		if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".server.conf.tmp*")); len(left) != 0 {
			t.Errorf("temporary files left: %v", left)
		}
	}
}

func TestWritable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if why := Writable(p); why != "" {
		t.Errorf("missing file in a writable dir: %q", why)
	}
	os.WriteFile(p, nil, 0o644)
	if why := Writable(p); why != "" {
		t.Errorf("writable file: %q", why)
	}
	if os.Geteuid() == 0 {
		t.Skip("root can write read-only files")
	}
	os.Chmod(p, 0o444)
	if why := Writable(p); why == "" {
		t.Error("read-only file reported writable")
	}
	os.Chmod(dir, 0o555)
	defer os.Chmod(dir, 0o755)
	if why := DirWritable(dir); why == "" {
		t.Error("read-only directory reported writable")
	}
}
