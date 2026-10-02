// Package users is softvpn's built-in username/password database: an
// htpasswd-compatible file of bcrypt hashes, one "name:hash" per line. It
// replaces OpenVPN's auth-user-pass-verify scripts and plugins, which a
// static binary in an empty container cannot run.
//
// The file can be edited while the server runs (by "softvpn user", a web UI,
// or "htpasswd -B"); DB notices changes and re-reads it.
package users

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// ErrBadCredentials is returned for an unknown user or a wrong password.
// The two are deliberately indistinguishable.
var ErrBadCredentials = errors.New("wrong username or password")

// Cost is the bcrypt cost of new hashes.
var Cost = bcrypt.DefaultCost

// dummyHash is compared against for unknown users, so that a lookup takes as
// long as a real password check and does not reveal which names exist.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("softvpn"), bcrypt.MinCost)

// ValidName reports whether name can be stored in a users file.
func ValidName(name string) error {
	if name == "" {
		return errors.New("empty user name")
	}
	if len(name) > 256 {
		return errors.New("user name too long")
	}
	for _, r := range name {
		if r == ':' || r < ' ' || r == 0x7f {
			return fmt.Errorf("invalid user name %q (no colons or control characters)", name)
		}
	}
	if strings.TrimSpace(name) != name || name[0] == '#' {
		return fmt.Errorf("invalid user name %q", name)
	}
	return nil
}

// HashPassword returns a bcrypt hash of password.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("empty password")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), Cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func isBcrypt(hash string) bool {
	for _, p := range []string{"$2a$", "$2b$", "$2y$"} {
		if strings.HasPrefix(hash, p) {
			return true
		}
	}
	return false
}

// line is one line of a users file. Comments and blank lines have no name
// and are kept verbatim when the file is rewritten.
type line struct {
	name, hash, raw string
}

func readLines(path string) ([]line, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []line
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		raw := strings.TrimRight(sc.Text(), "\r")
		l := line{raw: raw}
		if t := strings.TrimSpace(raw); t != "" && t[0] != '#' {
			l.name, l.hash, _ = strings.Cut(t, ":")
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

// parse builds the name -> hash map. Lines it cannot use are skipped and
// reported in the returned error; the remaining users still work.
func parse(lines []line) (map[string]string, error) {
	users := map[string]string{}
	var problems []string
	for i, l := range lines {
		if l.name == "" && l.hash == "" {
			continue
		}
		switch {
		case ValidName(l.name) != nil:
			problems = append(problems, fmt.Sprintf("line %d: invalid user name", i+1))
		case !isBcrypt(l.hash):
			problems = append(problems, fmt.Sprintf("line %d: user %q: only bcrypt hashes are supported (htpasswd -B)", i+1, l.name))
		default:
			if _, dup := users[l.name]; dup {
				problems = append(problems, fmt.Sprintf("line %d: duplicate user %q", i+1, l.name))
			}
			users[l.name] = l.hash
		}
	}
	if len(problems) > 0 {
		return users, errors.New(strings.Join(problems, "; "))
	}
	return users, nil
}

// List returns the user names in a users file, sorted.
func List(path string) ([]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	users, _ := parse(lines)
	names := make([]string, 0, len(users))
	for n := range users {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// Add adds a user to a users file, creating the file if needed. It fails if
// the user already exists.
func Add(path, name, password string) error {
	return update(path, name, password, true, false)
}

// SetPassword changes an existing user's password.
func SetPassword(path, name, password string) error {
	return update(path, name, password, false, true)
}

// Set adds a user or changes its password.
func Set(path, name, password string) error {
	return update(path, name, password, true, true)
}

// Delete removes a user.
func Delete(path, name string) error {
	return edit(path, func(lines []line) ([]line, error) {
		out := lines[:0]
		found := false
		for _, l := range lines {
			if l.name == name {
				found = true
				continue
			}
			out = append(out, l)
		}
		if !found {
			return nil, fmt.Errorf("no user %q in %s", name, path)
		}
		return out, nil
	})
}

func update(path, name, password string, create, replace bool) error {
	if err := ValidName(name); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return edit(path, func(lines []line) ([]line, error) {
		found := false
		for i, l := range lines {
			if l.name == name {
				if !replace {
					return nil, fmt.Errorf("user %q already exists in %s", name, path)
				}
				lines[i] = line{name: name, hash: hash}
				found = true
			}
		}
		if !found {
			if !create {
				return nil, fmt.Errorf("no user %q in %s", name, path)
			}
			lines = append(lines, line{name: name, hash: hash})
		}
		return lines, nil
	})
}

// edit rewrites a users file atomically (write to a temporary file, then
// rename), so a running server never reads a half-written file. A missing
// file counts as empty and is created with mode 0600.
func edit(path string, fn func([]line) ([]line, error)) error {
	mode := os.FileMode(0o600)
	lines, err := readLines(path)
	switch {
	case err == nil:
		if fi, err := os.Stat(path); err == nil {
			mode = fi.Mode().Perm()
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return err
	}
	if lines, err = fn(lines); err != nil {
		return err
	}
	var b strings.Builder
	for _, l := range lines {
		if l.name != "" {
			b.WriteString(l.name + ":" + l.hash + "\n")
		} else {
			b.WriteString(l.raw + "\n")
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// DB is a users file loaded for authentication. Every lookup checks whether
// the file changed and re-reads it if so.
type DB struct {
	path string

	mu    sync.Mutex
	stamp os.FileInfo
	users map[string]string
	err   error // the file could not be read: every login fails
}

// Open loads a users file. Unlike Reload, it also fails on unusable lines,
// so mistakes are caught at startup.
func Open(path string) (*DB, error) {
	db := &DB{path: path}
	if _, err := db.Reload(); err != nil {
		return nil, err
	}
	return db, nil
}

// Path is the users file.
func (db *DB) Path() string { return db.path }

// Reload re-reads the file if it changed since the last load. It reports
// whether it did, and any problem found. If the file has become unreadable,
// all logins fail until it is fixed.
func (db *DB) Reload() (changed bool, err error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.reload()
}

func (db *DB) reload() (bool, error) {
	fi, err := os.Stat(db.path)
	if err == nil && db.stamp != nil && db.err == nil && sameFile(db.stamp, fi) {
		return false, nil
	}
	if err == nil {
		var lines []line
		if lines, err = readLines(db.path); err == nil {
			db.stamp, db.err = fi, nil
			db.users, err = parse(lines)
			if err != nil {
				err = fmt.Errorf("%s: %w", db.path, err)
			}
			return true, err
		}
	}
	changed := db.err == nil
	db.stamp, db.users, db.err = nil, nil, err
	return changed, err
}

func sameFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

// hash returns the stored hash of a user, re-reading the file if needed.
func (db *DB) hash(name string) (string, bool, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.reload()
	if db.err != nil {
		return "", false, db.err
	}
	h, ok := db.users[name]
	return h, ok, nil
}

// Verify checks a user's password. It returns ErrBadCredentials if the user
// does not exist or the password is wrong.
func (db *DB) Verify(name, password string) error {
	h, ok, err := db.hash(name)
	if err != nil {
		return err
	}
	if !ok {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return ErrBadCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) != nil {
		return ErrBadCredentials
	}
	return nil
}

// Exists reports whether a user is in the file. It returns an error if the
// file cannot be read.
func (db *DB) Exists(name string) (bool, error) {
	_, ok, err := db.hash(name)
	return ok, err
}

// Stamp returns a value that changes whenever the user's password does
// (it is derived from the stored hash), or false if the user does not exist.
// Auth tokens are bound to it, so changing a password invalidates them.
func (db *DB) Stamp(name string) ([]byte, bool) {
	h, ok, err := db.hash(name)
	if err != nil || !ok {
		return nil, false
	}
	return []byte(h), true
}
