// Package lock records SHA-256 hashes of agent files so that silent changes
// to an approved skill, rules file, or MCP server script (a "rug pull") are
// caught by `decloak verify`.
package lock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/dorgrn/decloak/internal/model"
)

// Version is the lock file format version.
const Version = 1

// File is the on-disk lock file.
type File struct {
	Version int               `json:"version"`
	Files   map[string]string `json:"files"` // slash path -> "sha256:<hex>"
}

// Drift describes one file that differs from the lock.
type Drift struct {
	Kind string // "changed", "added", "removed"
	Path string
}

// Build hashes every target. Unreadable files are skipped so a partial
// permission problem does not invalidate the whole lock.
func Build(targets []model.TargetFile) *File {
	lf := &File{Version: Version, Files: make(map[string]string, len(targets))}
	for _, t := range targets {
		sum, err := hashFile(t.Path)
		if err != nil {
			continue
		}
		lf.Files[filepath.ToSlash(filepath.Clean(t.Path))] = sum
	}
	return lf
}

// Diff reports how current differs from the locked state, sorted by path.
func (lf *File) Diff(current *File) []Drift {
	var out []Drift
	for path, want := range lf.Files {
		got, ok := current.Files[path]
		switch {
		case !ok:
			out = append(out, Drift{"removed", path})
		case got != want:
			out = append(out, Drift{"changed", path})
		}
	}
	for path := range current.Files {
		if _, ok := lf.Files[path]; !ok {
			out = append(out, Drift{"added", path})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Write saves the lock file with sorted keys for stable diffs.
func (lf *File) Write(path string) error {
	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// Read loads a lock file.
func Read(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read lock file (run `decloak lock` first): %w", err)
	}
	var lf File
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("parse lock file %s: %w", path, err)
	}
	if lf.Version != Version {
		return nil, fmt.Errorf("lock file %s has version %d, want %d", path, lf.Version, Version)
	}
	if lf.Files == nil {
		lf.Files = map[string]string{}
	}
	return &lf, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
