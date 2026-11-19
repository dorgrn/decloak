package judge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const cacheVersion = "2"

// Cache persists verdicts on disk. It is keyed by the endpoint, model, full
// judge prompt, and file content, so a prompt change, model change, or file
// edit invalidates the entry automatically.
type Cache struct {
	dir string
}

type cacheEntry struct {
	Version  string  `json:"version"`
	Model    string  `json:"model"`
	Endpoint string  `json:"endpoint"`
	Path     string  `json:"path"`
	Verdict  Verdict `json:"verdict"`
	Created  string  `json:"created"`
}

// NewCache creates dir if needed and returns a cache. An empty dir disables
// caching and returns a nil cache.
func NewCache(dir string) (*Cache, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create judge cache %q: %w", dir, err)
	}
	return &Cache{dir: dir}, nil
}

// Dir returns the cache directory, or an empty string when disabled.
func (c *Cache) Dir() string {
	if c == nil {
		return ""
	}
	return c.dir
}

func (c *Cache) lookup(endpoint, model string, file File, limits string) (Verdict, bool) {
	if c == nil {
		return Verdict{}, false
	}
	data, err := os.ReadFile(c.path(c.key(endpoint, model, file, limits)))
	if err != nil {
		return Verdict{}, false
	}
	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil || entry.Version != cacheVersion {
		return Verdict{}, false
	}
	v, err := normalize(entry.Verdict)
	if err != nil {
		return Verdict{}, false
	}
	return v, true
}

func (c *Cache) store(endpoint, model string, file File, limits string, v Verdict) {
	if c == nil {
		return
	}
	key := c.key(endpoint, model, file, limits)
	entry := cacheEntry{
		Version:  cacheVersion,
		Model:    model,
		Endpoint: endpoint,
		Path:     file.Path,
		Verdict:  v,
		Created:  time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	dir := filepath.Join(c.dir, key[:2])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, ".judge-*")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return
	}
	_ = os.Rename(tmpName, filepath.Join(dir, key+".json"))
}

func (c *Cache) path(key string) string {
	return filepath.Join(c.dir, key[:2], key+".json")
}

func (c *Cache) key(endpoint, model string, file File, limits string) string {
	h := sha256.New()
	write := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}
	write(cacheVersion)
	write(endpoint)
	write(model)
	write(SystemPrompt)
	write(file.Path)
	write(string(file.Language))
	write(limits)
	for _, hint := range file.StaticFindings {
		write(hint)
	}
	write(file.Content)
	return hex.EncodeToString(h.Sum(nil))
}
