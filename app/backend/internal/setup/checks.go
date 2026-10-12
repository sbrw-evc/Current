package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/sbrw-evc/network/app/backend/internal/config"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
	"github.com/sbrw-evc/network/app/backend/internal/store"
)

// CheckResult is the reply of a step check: {ok, error?, details?}.
type CheckResult struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Details any    `json:"details,omitempty"`
}

func failed(err error) CheckResult { return CheckResult{Error: err.Error()} }

var httpClient = &http.Client{Timeout: 20 * time.Second}

// CheckOpenBao verifies the connection, the token and writing to the mount.
func CheckOpenBao(ctx context.Context, o config.OpenBao) (*secrets.Client, CheckResult) {
	o, err := o.Normalize()
	if err != nil {
		return nil, failed(err)
	}
	c, err := o.Client()
	if err != nil {
		return nil, failed(err)
	}
	rep := c.Verify(ctx)
	res := CheckResult{OK: rep.OK, Error: rep.Error, Details: map[string]any{"version": rep.Status.Version, "mount": rep.Status.Mount,
		"auth": rep.Status.Auth, "mount_ok": rep.Status.MountOK, "write_ok": rep.WriteOK}}
	if !rep.OK {
		return nil, res
	}
	return c, res
}

// PostgresDetails is what CheckPostgres finds.
type PostgresDetails struct {
	Version  string `json:"version"`
	HasState bool   `json:"has_state"` // the database already has Flow users
	Users    int    `json:"users"`
	Schema   int64  `json:"schema"`
}

// CheckPostgres connects with the DSN and looks for existing Flow state.
func CheckPostgres(ctx context.Context, dsn string) CheckResult {
	st, err := store.Open(ctx, dsn)
	if err != nil {
		return failed(err)
	}
	defer st.Close()
	d, err := postgresDetails(ctx, st)
	if err != nil {
		return failed(err)
	}
	return CheckResult{OK: true, Details: d}
}

func postgresDetails(ctx context.Context, st *store.Store) (PostgresDetails, error) {
	var d PostgresDetails
	if err := st.Pool().QueryRow(ctx, "SHOW server_version").Scan(&d.Version); err != nil {
		return d, err
	}
	empty, err := st.IsEmpty(ctx)
	if err != nil {
		return d, err
	}
	d.HasState = !empty
	if d.HasState {
		d.Users, _ = st.CountUsers(ctx)
		d.Schema, _ = st.Version(ctx)
	}
	return d, nil
}

// CheckClickHouse pings the server and reports its version and whether the database exists.
func CheckClickHouse(ctx context.Context, c config.ClickHouse, password string) CheckResult {
	c, err := c.Normalize()
	if err != nil {
		return failed(err)
	}
	conn, err := c.Open(ctx, password, "")
	if err != nil {
		return failed(err)
	}
	defer conn.Close()
	details := map[string]any{}
	if v, err := conn.ServerVersion(); err == nil && v != nil {
		details["version"] = v.Version.String()
	}
	var n uint64
	if err := conn.QueryRow(ctx, "SELECT count() FROM system.databases WHERE name = ?", c.Database).Scan(&n); err != nil {
		return failed(err)
	}
	details["database_exists"] = n > 0
	return CheckResult{OK: true, Details: details}
}

// CheckNATS connects to the server and checks JetStream. An empty URL is the
// in-process bus and always passes.
func CheckNATS(ctx context.Context, rawURL, token string) CheckResult {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return CheckResult{OK: true, Details: map[string]any{"bus": "in-process"}}
	}
	if err := checkNATSURL(rawURL); err != nil {
		return failed(err)
	}
	opts := []nats.Option{nats.Name("umbrella-flow-setup"), nats.Timeout(5 * time.Second), nats.MaxReconnects(0)}
	if token != "" {
		opts = append(opts, nats.Token(token))
	}
	nc, err := nats.Connect(rawURL, opts...)
	if err != nil {
		return failed(fmt.Errorf("NATS: %w", err))
	}
	defer nc.Close()
	details := map[string]any{"version": nc.ConnectedServerVersion(), "jetstream": false}
	js, err := jetstream.New(nc)
	if err != nil {
		return CheckResult{Error: err.Error(), Details: details}
	}
	jctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := js.AccountInfo(jctx); err != nil {
		return CheckResult{Error: "JetStream is not available: " + err.Error(), Details: details}
	}
	details["jetstream"] = true
	return CheckResult{OK: true, Details: details}
}

func checkNATSURL(raw string) error {
	for _, one := range strings.Split(raw, ",") {
		u, err := url.Parse(strings.TrimSpace(one))
		if err != nil || u.Host == "" || (u.Scheme != "nats" && u.Scheme != "tls" && u.Scheme != "ws" && u.Scheme != "wss") {
			return errors.New("NATS address must look like nats://nats:4222")
		}
		if u.User != nil {
			return errors.New("put NATS credentials into the token field, not into the address: they are kept in OpenBao")
		}
	}
	return nil
}

// CheckInventory asks Inventory DB for one device and returns the device count.
func CheckInventory(ctx context.Context, baseURL, token string) CheckResult {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return failed(errors.New("Inventory DB address must look like https://inventory.example"))
	}
	if token == "" {
		return failed(errors.New("the Inventory DB token is required"))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/dcim/devices/?limit=1", nil)
	if err != nil {
		return failed(err)
	}
	req.Header.Set("xc-token", token)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return failed(fmt.Errorf("Inventory DB is unreachable: %w", err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return failed(fmt.Errorf("Inventory DB rejected the token (%d)", resp.StatusCode))
	case resp.StatusCode/100 != 2:
		return failed(fmt.Errorf("Inventory DB answered %d", resp.StatusCode))
	}
	var page struct {
		Count *int `json:"count"`
	}
	if err := json.Unmarshal(body, &page); err != nil || page.Count == nil {
		return failed(errors.New("the answer is not a NetBox-style list: is this the Inventory DB address?"))
	}
	return CheckResult{OK: true, Details: map[string]any{"devices": *page.Count}}
}

// UmbrellaTestEvent is sent by CheckUmbrella (network-flow connector format;
// the title is a user-facing Russian string, as specified in docs/api.md).
var UmbrellaTestEvent = map[string]any{"id": "flow-setup-test", "status": "resolved", "signal": "flow.setup.test", "severity": "info",
	"title": "Umbrella Flow: проверка подключения", "ci": "umbrella-flow", "labels": map[string]string{"umbrella_test": "true"}}

// CheckUmbrella posts a resolved test event to the Umbrella ingest URL.
func CheckUmbrella(ctx context.Context, ingestURL, token string) CheckResult {
	ingestURL = strings.TrimSpace(ingestURL)
	u, err := url.Parse(ingestURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || !strings.Contains(u.Path, "/api/ingest/") {
		return failed(errors.New("the ingest address must look like https://umbrella.example/api/ingest/network-flow"))
	}
	if token == "" {
		return failed(errors.New("the Umbrella token is required"))
	}
	b, _ := json.Marshal(UmbrellaTestEvent)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ingestURL, bytes.NewReader(b))
	if err != nil {
		return failed(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return failed(fmt.Errorf("Umbrella is unreachable: %w", err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		msg := fmt.Sprintf("Umbrella answered %d", resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			msg += ": check the token and that the connector is published"
		}
		return CheckResult{Error: msg, Details: map[string]any{"status": resp.StatusCode}}
	}
	return CheckResult{OK: true, Details: map[string]any{"status": resp.StatusCode}}
}

// CheckGeoIP opens every MaxMind database file.
func CheckGeoIP(paths []string) CheckResult {
	if len(paths) == 0 {
		return failed(errors.New("no database files"))
	}
	var out []map[string]any
	for _, p := range paths {
		p = strings.TrimSpace(p)
		r, err := maxminddb.Open(p)
		if err != nil {
			return CheckResult{Error: fmt.Sprintf("%s: %v", p, err), Details: out}
		}
		out = append(out, map[string]any{"path": p, "type": r.Metadata.DatabaseType,
			"built": r.Metadata.BuildTime().UTC().Format(time.RFC3339)})
		r.Close()
	}
	return CheckResult{OK: true, Details: out}
}

// checkUDPAddr validates a collector listen address like ":2055".
func checkUDPAddr(a string) error {
	if _, err := net.ResolveUDPAddr("udp", a); err != nil {
		return fmt.Errorf("listen address %q: %w", a, err)
	}
	return nil
}
