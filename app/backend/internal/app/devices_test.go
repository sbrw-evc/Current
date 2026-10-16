package app

import (
	"context"
	"strings"
	"testing"

	"github.com/sbrw-evc/network/app/backend/internal/access"
	"github.com/sbrw-evc/network/app/backend/internal/devices"
	"github.com/sbrw-evc/network/app/backend/internal/devices/drivers"
	"github.com/sbrw-evc/network/app/backend/internal/secrets"
)

type apiFakeDriver struct{}

func (apiFakeDriver) Collect(context.Context) (*drivers.Snapshot, error) {
	return &drivers.Snapshot{Facts: drivers.Facts{Hostname: "r1"},
		Endpoints: []drivers.Endpoint{{MAC: "de:ad:be:ef:00:01", IP: "10.0.0.50", Source: "dhcp"}}}, nil
}
func (apiFakeDriver) Apply(_ context.Context, action string, _ drivers.Params) (string, error) {
	return "ok " + action, nil
}
func (apiFakeDriver) Backup(context.Context) (string, error) { return "config", nil }
func (apiFakeDriver) HostKey() string                        { return "" }
func (apiFakeDriver) Close()                                 {}

func TestDevicesAPIPermissions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Without the device manager every route answers 501.
	admin := e.client()
	admin.login("admin")
	if code, _ := admin.do("GET", "/api/devices", nil); code != 501 {
		t.Fatalf("no service: %d", code)
	}
	svc := devices.New(devices.Config{Store: e.st, Vault: e.app.deps.Vault,
		Driver: func(*drivers.Platform, drivers.Target, drivers.Credentials) (drivers.Driver, error) {
			return apiFakeDriver{}, nil
		}})
	t.Cleanup(svc.Close)
	e.app.deps.Devices = svc

	// An operator role: view + operate, no edit, no admin.
	role, err := e.st.CreateRole(ctx, "netops", "", []string{access.DevicesView, access.DevicesOperate})
	if err != nil {
		t.Fatal(err)
	}
	legacyUser(t, e.st, "netops", role.ID)
	e.spa.Users = append(e.spa.Users, spaUser("netops", role.Ident))
	ops := e.client()
	ops.login("netops")
	viewer := e.client()
	viewer.login("viewer")

	code, created := admin.do("POST", "/api/devices", map[string]any{"platform": "mikrotik", "host": "10.0.0.1",
		"credentials": map[string]any{"username": "admin", "password": "pw-secret"}})
	if code != 201 {
		t.Fatal(code, created)
	}
	id := itoa(int(created["id"].(float64)))
	if strings.Contains(toJSON(created), "pw-secret") || created["credentials"].(map[string]any)["set"].(map[string]any)["password"] != true {
		t.Fatalf("credentials view %v", created["credentials"])
	}
	if v, err := secrets.Value(e.app.deps.Vault, e.app.deps.Vault.Ref(devices.SecretPath(int64(created["id"].(float64))), "password")); err != nil || v != "pw-secret" {
		t.Fatalf("OpenBao: %q %v", v, err)
	}
	svc.Wait()

	// Viewer (no devices permission): 403 everywhere.
	for _, r := range [][2]string{{"GET", "/api/devices"}, {"GET", "/api/devices/" + id}, {"GET", "/api/endpoints"},
		{"GET", "/api/topology"}, {"GET", "/api/devices/platforms"}, {"POST", "/api/devices/" + id + "/poll"}} {
		if code, _ := viewer.do(r[0], r[1], nil); code != 403 {
			t.Errorf("viewer %s %s: %d", r[0], r[1], code)
		}
	}
	// Operator: reads, polls and non-admin actions; no edits, no admin actions.
	for path, want := range map[string]int{"/api/devices": 200, "/api/devices/" + id: 200, "/api/endpoints": 200,
		"/api/topology": 200, "/api/devices/platforms": 200, "/api/settings/devices": 200, "/api/devices/" + id + "/backup": 403} {
		if code, out := ops.do("GET", path, nil); code != want {
			t.Errorf("operator GET %s: %d %v, want %d", path, code, out, want)
		}
	}
	if code, out := ops.do("POST", "/api/devices/"+id+"/poll", nil); code != 200 || out["ok"] != true {
		t.Fatalf("operator poll %d %v", code, out)
	}
	if code, out := ops.do("POST", "/api/devices/"+id+"/actions", map[string]any{"action": "dns", "params": map[string]any{"servers": []string{"1.1.1.1"}}}); code != 200 || out["output"] != "ok dns" {
		t.Fatalf("operator dns %d %v", code, out)
	}
	for _, act := range []string{"reboot", "command", "backup"} {
		if code, _ := ops.do("POST", "/api/devices/"+id+"/actions", map[string]any{"action": act, "params": map[string]any{"command": "/system resource print"}}); code != 403 {
			t.Errorf("operator %s: %d", act, code)
		}
	}
	if code, _ := ops.do("PATCH", "/api/devices/"+id, map[string]any{"note": "x"}); code != 403 {
		t.Errorf("operator patch: %d", code)
	}
	if code, _ := ops.do("DELETE", "/api/devices/"+id, nil); code != 403 {
		t.Errorf("operator delete: %d", code)
	}
	if code, _ := ops.do("PATCH", "/api/endpoints/de:ad:be:ef:00:01", map[string]any{"alias": "x"}); code != 403 {
		t.Errorf("operator endpoint patch: %d", code)
	}
	// Admin: everything.
	if code, out := admin.do("POST", "/api/devices/"+id+"/actions", map[string]any{"action": "reboot"}); code != 200 {
		t.Fatalf("admin reboot %d %v", code, out)
	}
	if code, out := admin.do("GET", "/api/devices/"+id+"/backup", nil); code != 200 || out["_raw"] != "config" {
		t.Fatalf("backup %d %v", code, out)
	}
	if code, out := admin.do("POST", "/api/devices/"+id+"/actions", map[string]any{"action": "hostname", "params": map[string]any{"name": "bad;name"}}); code != 400 {
		t.Fatalf("invalid params %d %v", code, out)
	}
	if code, out := admin.do("PATCH", "/api/endpoints/DE-AD-BE-EF-00-01", map[string]any{"alias": "printer"}); code != 200 || out["name"] != "printer" {
		t.Fatalf("endpoint alias %d %v", code, out)
	}
	if code, out := admin.do("GET", "/api/endpoints?q=printer", nil); code != 200 || len(out["results"].([]any)) != 1 {
		t.Fatalf("endpoint search %d %v", code, out)
	}
	if code, _ := admin.do("PUT", "/api/topology/positions", map[string]any{"dev:" + id: []float64{1, 2}}); code != 204 {
		t.Fatalf("positions %d", code)
	}
	if code, out := admin.do("POST", "/api/devices", map[string]any{"platform": "mikrotik", "host": "10.0.0.1"}); code != 409 || out["error"] != "duplicate_device" {
		t.Fatalf("duplicate %d %v", code, out)
	}
	if code, out := admin.do("POST", "/api/devices", map[string]any{"platform": "mikrotik", "host": "10.0.0.2", "bogus": 1}); code != 400 {
		t.Fatalf("unknown field %d %v", code, out)
	}
	if code, _ := admin.do("DELETE", "/api/devices/"+id, nil); code != 204 {
		t.Fatalf("delete %d", code)
	}
	_, audit := admin.do("GET", "/api/audit", nil)
	if s := toJSON(audit); !strings.Contains(s, "device.created") || !strings.Contains(s, "device.reboot") || !strings.Contains(s, "device.deleted") ||
		strings.Contains(s, "pw-secret") {
		t.Fatalf("audit %s", s)
	}
}
