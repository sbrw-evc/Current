package secrets

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"time"
)

// Check is the result of Verify: the status plus a write / delete probe.
type Check struct {
	OK         bool   `json:"ok"`
	Status     Status `json:"status"`
	WriteOK    bool   `json:"write_ok"`
	WriteError string `json:"write_error,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Verify checks that OpenBao is reachable, the token works and secrets can be
// written to and deleted from the mount.
func (c *Client) Verify(ctx context.Context) Check {
	rep := Check{Status: c.Status(ctx)}
	if !rep.Status.TokenOK || !rep.Status.MountOK {
		rep.Error = rep.Status.Error
		return rep
	}
	probe := "flow-probe-" + strings.ToLower(rand.Text()[:8])
	if err := c.Put(ctx, probe, map[string]string{"probe": time.Now().UTC().Format(time.RFC3339)}); err != nil {
		rep.WriteError = err.Error()
		rep.Error = "cannot write secrets: " + err.Error()
		if errors.Is(err, ErrNotFound) {
			rep.Error = "the mount " + c.cfg.Mount + " does not exist or is not a KV version 2 secrets engine"
		}
		return rep
	}
	if err := c.Delete(ctx, probe); err != nil {
		rep.WriteError = err.Error()
		rep.Error = "cannot delete secrets: " + err.Error()
		return rep
	}
	rep.WriteOK, rep.OK = true, true
	return rep
}
