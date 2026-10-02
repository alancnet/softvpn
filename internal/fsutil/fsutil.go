// Package fsutil writes configuration files that a running server reads:
// atomically where the file system allows it, in place where it does not
// (a file bind-mounted into a container cannot be renamed over).
package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// rename is os.Rename; tests replace it to simulate a bind-mounted file.
var rename = os.Rename

// WriteFile replaces the contents of path. It writes a temporary file in the
// same directory and renames it over path, so readers see either the old or
// the new contents. When that is impossible - the directory is not
// writable, or path is a mount point (Docker bind-mounts a single file;
// rename then fails with EBUSY or EXDEV) - it truncates and rewrites path in
// place. An existing file keeps its permissions; a new one gets mode.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	err := writeAtomic(path, data, mode)
	if err == nil {
		return nil
	}
	if !canFallBack(err) {
		return err
	}
	return writeInPlace(path, data, mode)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return rename(tmp.Name(), path)
}

// canFallBack reports whether an atomic write failed for a reason that a
// write in place avoids.
func canFallBack(err error) bool {
	return errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.EXDEV) ||
		errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS)
}

func writeInPlace(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Writable explains why path cannot be written, or returns "" if it can.
// A missing file counts as writable if its directory is.
func Writable(path string) string {
	fi, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		dir := filepath.Dir(path)
		if err := access(dir); err != nil {
			return fmt.Sprintf("%s does not exist and its directory %s is not writable (%v)", path, dir, err)
		}
		return ""
	case err != nil:
		return err.Error()
	case fi.IsDir():
		return path + " is a directory"
	}
	if err := access(path); err != nil {
		return fmt.Sprintf("%s is not writable (%v)", path, err)
	}
	return ""
}

// DirWritable explains why files cannot be created in dir, or returns "".
func DirWritable(dir string) string {
	fi, err := os.Stat(dir)
	if err != nil {
		return err.Error()
	}
	if !fi.IsDir() {
		return dir + " is not a directory"
	}
	if err := access(dir); err != nil {
		return fmt.Sprintf("%s is not writable (%v)", dir, err)
	}
	return ""
}

// access checks write permission the way the kernel will, including
// read-only mounts (EROFS).
func access(path string) error {
	const wOK = 2
	return syscall.Access(path, wOK)
}
