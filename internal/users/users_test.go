package users

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func init() { Cost = bcrypt.MinCost }

func TestManageAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users")
	if err := Add(path, "alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := Add(path, "bob", "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := Add(path, "alice", "x"); err == nil {
		t.Fatal("adding an existing user succeeded")
	}
	if err := SetPassword(path, "carol", "x"); err == nil {
		t.Fatal("changing the password of a missing user succeeded")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
	names, err := List(path)
	if err != nil || !reflect.DeepEqual(names, []string{"alice", "bob"}) {
		t.Fatalf("List = %v, %v", names, err)
	}

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Verify("alice", "secret"); err != nil {
		t.Fatalf("correct password: %v", err)
	}
	for _, c := range [][2]string{{"alice", "wrong"}, {"alice", ""}, {"nobody", "secret"}, {"bob", "secret"}} {
		if err := db.Verify(c[0], c[1]); !errors.Is(err, ErrBadCredentials) {
			t.Errorf("Verify(%q, %q) = %v, want ErrBadCredentials", c[0], c[1], err)
		}
	}

	// Edits are picked up without reopening.
	stamp, _ := db.Stamp("alice")
	if err := SetPassword(path, "alice", "new"); err != nil {
		t.Fatal(err)
	}
	if err := db.Verify("alice", "new"); err != nil {
		t.Fatalf("after passwd: %v", err)
	}
	if err := db.Verify("alice", "secret"); err == nil {
		t.Fatal("old password still works")
	}
	if s, _ := db.Stamp("alice"); string(s) == string(stamp) {
		t.Fatal("stamp did not change with the password")
	}
	if err := Delete(path, "bob"); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.Exists("bob"); ok || err != nil {
		t.Fatalf("deleted user: Exists = %v, %v", ok, err)
	}
	if err := Delete(path, "bob"); err == nil {
		t.Fatal("deleting a missing user succeeded")
	}
}

func TestHtpasswdFile(t *testing.T) {
	// As written by "htpasswd -B": comments and other users are preserved
	// across edits; non-bcrypt entries are reported and skipped.
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	h := strings.Replace(string(hash), "$2a$", "$2y$", 1)
	path := filepath.Join(t.TempDir(), "htpasswd")
	content := "# managed by hand\nalice:" + h + "\nold:$apr1$abc$def\n\n"
	os.WriteFile(path, []byte(content), 0o640)

	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "only bcrypt") {
		t.Fatalf("Open = %v, want a bcrypt-only error", err)
	}
	db := &DB{path: path}
	if _, err := db.Reload(); err == nil {
		t.Fatal("Reload reported no problem")
	}
	if err := db.Verify("alice", "pw"); err != nil {
		t.Fatalf("$2y$ hash: %v", err)
	}
	if err := db.Verify("old", "pw"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("apr1 user: %v", err)
	}

	if err := Set(path, "bob", "pw2"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(b), "# managed by hand\nalice:"+h+"\nold:$apr1$abc$def\n\nbob:$2a$") {
		t.Fatalf("file not preserved:\n%s", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %v", fi.Mode().Perm())
	}
}

func TestUnreadableFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users")
	if _, err := Open(path); err == nil {
		t.Fatal("Open of a missing file succeeded")
	}
	Add(path, "alice", "pw")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(path)
	if err := db.Verify("alice", "pw"); err == nil || errors.Is(err, ErrBadCredentials) {
		t.Fatalf("missing file: Verify = %v, want a file error", err)
	}
	time.Sleep(10 * time.Millisecond)
	Add(path, "alice", "pw")
	if err := db.Verify("alice", "pw"); err != nil {
		t.Fatalf("restored file: %v", err)
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"alice", "a.b@example.com", "Jane Doe"} {
		if err := ValidName(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	for _, n := range []string{"", "a:b", "a\nb", " lead", "#x"} {
		if ValidName(n) == nil {
			t.Errorf("%q accepted", n)
		}
	}
	if err := Add(filepath.Join(t.TempDir(), "u"), "x", strings.Repeat("p", 73)); err == nil {
		t.Error("password over bcrypt's 72-byte limit accepted")
	}
}
