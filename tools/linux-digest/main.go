// Checks the Linux approval-digest fixture against the Go reference.
// Digest is copied from internal/plugin/plugin.go at tag go-final, with
// only the UI-thread assertion removed. Run by the Linux CI, not locally.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func Digest(dir string) (string, error) {
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		info, err := d.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%q %o\n", rel, info.Mode())
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			t, err := os.Readlink(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "-> %q\n", t)
		case info.Mode().IsRegular():
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "%d\n", info.Size())
			_, err = io.Copy(h, f)
			f.Close()
			return err
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	dir, err := os.MkdirTemp("", "rush-go-digest-")
	must(err)
	defer os.RemoveAll(dir)
	must(os.Chmod(dir, 0o755))
	file := func(name, body string, mode fs.FileMode) {
		path := filepath.Join(dir, name)
		must(os.WriteFile(path, []byte(body), 0o600))
		must(os.Chmod(path, mode))
	}
	file("plugin.json", "{}", 0o644)
	must(os.Symlink("plugin.json", filepath.Join(dir, "link")))
	must(os.Mkdir(filepath.Join(dir, "sub"), 0o700))
	must(os.Chmod(filepath.Join(dir, "sub"), 0o700))
	file("sub/a b\"c\té", "x", 0o600)
	file("Z", "zz", fs.ModeSetuid|0o711)
	got, err := Digest(dir)
	must(err)
	const want = "e4934c548213257be8808cd91de5e0e60e52ba97ade627d5d316053bdd48208d"
	if got != want {
		panic(fmt.Sprintf("Linux Go digest: got %s, want %s", got, want))
	}
	fmt.Printf("Linux Go approval digest: %s\n", got)
}
