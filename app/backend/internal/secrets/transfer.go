package secrets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Moving secrets to another OpenBao (Settings → OpenBao), ported from
// Umbrella Monitoring: check that the target mount is KV v2, list every
// secret under the current mount and copy them as they are.

// CheckKV2 checks that the mount exists and is a KV version 2 engine.
func (c *Client) CheckKV2(ctx context.Context) error {
	if !c.Enabled() {
		return ErrNotConfigured
	}
	mount := c.conf().Mount
	var out struct {
		Data struct {
			Type    string            `json:"type"`
			Options map[string]string `json:"options"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/sys/internal/ui/mounts/"+escapePath(mount), nil, &out); err != nil {
		return fmt.Errorf("the mount %s is missing or not accessible: %w", mount, err)
	}
	if out.Data.Type != "kv" || out.Data.Options["version"] != "2" {
		kind := out.Data.Type
		if v := out.Data.Options["version"]; v != "" {
			kind += " v" + v
		}
		return fmt.Errorf("the mount %s is %s, not KV version 2", mount, kind)
	}
	return nil
}

// List returns the paths of every secret under the mount.
func (c *Client) List(ctx context.Context) ([]string, error) {
	if !c.Enabled() {
		return nil, ErrNotConfigured
	}
	return c.listUnder(ctx, c.conf().Mount, "", 0)
}

func (c *Client) listUnder(ctx context.Context, mount, prefix string, depth int) ([]string, error) {
	if depth > 16 {
		return nil, fmt.Errorf("list %s/%s: nested too deep", mount, prefix)
	}
	var out struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/"+mount+"/metadata/"+escapePath(prefix)+"?list=true", nil, &out)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list %s/%s: %w", mount, prefix, err)
	}
	var paths []string
	for _, k := range out.Data.Keys {
		if !strings.HasSuffix(k, "/") {
			paths = append(paths, prefix+k)
			continue
		}
		nested, err := c.listUnder(ctx, mount, prefix+k, depth+1)
		if err != nil {
			return nil, err
		}
		paths = append(paths, nested...)
	}
	return paths, nil
}

// CopyTo copies every secret of the mount to the mount of dst (same paths,
// same keys) and returns the copied paths. Existing secrets at dst with the
// same path are replaced.
func (c *Client) CopyTo(ctx context.Context, dst *Client) ([]string, error) {
	paths, err := c.List(ctx)
	if err != nil {
		return nil, err
	}
	src, to := c.conf().Mount, dst.conf().Mount
	var copied []string
	for _, p := range paths {
		data, err := c.readRaw(ctx, p)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return copied, fmt.Errorf("read %s/%s: %w", src, p, err)
		}
		if err := dst.writeRaw(ctx, p, data); err != nil {
			return copied, fmt.Errorf("write %s/%s: %w", to, p, err)
		}
		copied = append(copied, p)
	}
	return copied, nil
}

func (c *Client) readRaw(ctx context.Context, path string) (map[string]any, error) {
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/"+c.conf().Mount+"/data/"+escapePath(path), nil, &out); err != nil {
		return nil, err
	}
	if out.Data.Data == nil {
		return nil, ErrNotFound // deleted (soft) latest version
	}
	return out.Data.Data, nil
}

func (c *Client) writeRaw(ctx context.Context, path string, data map[string]any) error {
	mount := c.conf().Mount
	err := c.do(ctx, http.MethodPost, "/v1/"+mount+"/data/"+escapePath(path), map[string]any{"data": data}, nil)
	c.mu.Lock()
	delete(c.cache, mount+"/"+path)
	c.mu.Unlock()
	return err
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// MoveRef rewrites a reference to mount from so it points to mount to.
func MoveRef(ref, from, to string) (string, bool) {
	mount, path, key, err := ParseRef(ref)
	if err != nil || mount != from || from == to {
		return ref, false
	}
	return Scheme + to + "/" + path + "#" + key, true
}
