package app

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/sbrw-evc/current/app/backend/internal/access"
	"github.com/sbrw-evc/current/app/backend/internal/devices"
	"github.com/sbrw-evc/current/app/backend/internal/devices/drivers"
	"github.com/sbrw-evc/current/app/backend/internal/httpx"
)

// ---- network devices, clients and the network map (internal/devices, docs/devices.md)

func (a *App) deviceRoutes(h func(string, func(http.ResponseWriter, *http.Request))) {
	view, edit := perms(access.DevicesView), perms(access.DevicesEdit)
	operate := perms(access.DevicesOperate, access.DevicesAdmin)
	h("GET /api/devices/platforms", a.guard(view, a.devicePlatforms))
	h("GET /api/devices", a.guard(view, a.listDevices))
	h("POST /api/devices", a.guard(edit, a.createDevice))
	h("POST /api/devices/test", a.guard(edit, a.testDevice))
	h("POST /api/devices/discover", a.guard(edit, a.discoverDevices))
	h("GET /api/devices/inventory-candidates", a.guard(view, a.deviceCandidates))
	h("GET /api/devices/{id}", a.guard(view, a.getDevice))
	h("PATCH /api/devices/{id}", a.guard(edit, a.updateDevice))
	h("DELETE /api/devices/{id}", a.guard(edit, a.deleteDevice))
	h("POST /api/devices/{id}/poll", a.guard(operate, a.pollDevice))
	h("POST /api/devices/{id}/actions", a.guard(operate, a.deviceAction))
	h("GET /api/devices/{id}/backup", a.guard(perms(access.DevicesAdmin), a.deviceBackup))
	h("POST /api/devices/{id}/reset-host-key", a.guard(edit, a.resetDeviceHostKey))
	h("GET /api/endpoints", a.guard(view, a.listEndpoints))
	h("GET /api/endpoints/{mac}", a.guard(view, a.getEndpoint))
	h("PATCH /api/endpoints/{mac}", a.guard(edit, a.updateEndpoint))
	h("DELETE /api/endpoints/{mac}", a.guard(edit, a.forgetEndpoint))
	h("POST /api/endpoints/{mac}/block", a.guard(operate, a.blockEndpoint))
	h("GET /api/topology", a.guard(view, a.topology))
	h("PUT /api/topology/positions", a.guard(edit, a.topologyPositions))
	h("GET /api/settings/devices", a.guard(view, a.getDeviceSettings))
	h("PUT /api/settings/devices", a.guard(edit, a.putDeviceSettings))
}

// devicesOn answers 501 when the device manager is not in this process.
func (a *App) devicesOn(w http.ResponseWriter) *devices.Service {
	if a.deps.Devices == nil {
		notImplemented(w, "device management")
	}
	return a.deps.Devices
}

func (a *App) devicePlatforms(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	titles := map[string]string{}
	for k, v := range drivers.ActionTitles {
		titles[k] = v
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"platforms": s.Platforms(), "actions": drivers.Actions, "action_titles": titles,
		"admin_actions": devices.AdminActions, "secret_fields": drivers.SecretFields, "roles": devices.Roles,
		"flow_protocols": drivers.FlowProtocols, "snmp_auth_protocols": drivers.SNMPAuthProtocols,
		"snmp_priv_protocols": drivers.SNMPPrivProtocols})
}

func (a *App) listDevices(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	out, err := s.List(r.Context())
	reply(w, map[string]any{"results": out}, err)
}

func (a *App) getDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	id, ok := pathID(w, r)
	if s == nil || !ok {
		return
	}
	out, err := s.Get(r.Context(), id)
	reply(w, out, err)
}

// credentialAudit lists what changed in the credentials, never the values.
func credentialAudit(in devices.Input) []string {
	var out []string
	for k := range in.Credentials {
		out = append(out, k)
	}
	out = append(out, in.ClearCredentials...)
	slices.Sort(out)
	return slices.Compact(out)
}

func (a *App) createDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	var in devices.Input
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := s.Create(r.Context(), p.User.Username, in)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(r.Context(), p, "device.created", "device:"+strconv.FormatInt(v.ID, 10), map[string]any{"name": v.Name,
		"platform": v.Platform, "host": v.Host, "source_ref": v.SourceRef, "credentials": credentialAudit(in)})
	a.reload(r.Context(), ReloadSNMP) // its SNMP credentials name its interfaces
	httpx.JSON(w, http.StatusCreated, v)
}

func (a *App) updateDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	id, ok := pathID(w, r)
	if s == nil || !ok {
		return
	}
	var in devices.Input
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, changed, err := s.Update(r.Context(), id, in)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(r.Context(), p, "device.updated", "device:"+strconv.FormatInt(id, 10), map[string]any{"name": v.Name,
		"host": v.Host, "secrets_changed": changed})
	a.reload(r.Context(), ReloadSNMP)
	httpx.JSON(w, http.StatusOK, v)
}

func (a *App) deleteDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	id, ok := pathID(w, r)
	if s == nil || !ok {
		return
	}
	v, err := s.Delete(r.Context(), id)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	a.reload(r.Context(), ReloadSNMP)
	a.audit(r.Context(), p, "device.deleted", "device:"+strconv.FormatInt(id, 10), map[string]any{"name": v.Name, "host": v.Host})
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) testDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	var in devices.Input
	if !httpx.Decode(w, r, &in) {
		return
	}
	out, err := s.Test(r.Context(), in)
	reply(w, out, err)
}

func (a *App) discoverDevices(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	var in struct {
		Target    string `json:"target"`
		Community string `json:"community"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if in.Community == "" {
		in.Community = "public"
	}
	out, err := s.Discover(r.Context(), in.Target, in.Community)
	if err == nil {
		a.audit(r.Context(), p, "device.discover", in.Target, map[string]any{"found": len(out)})
	}
	reply(w, map[string]any{"results": out}, err)
}

func (a *App) deviceCandidates(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	out, err := s.InventoryCandidates(r.Context(), r.URL.Query().Get("q"))
	reply(w, out, err)
}

func (a *App) pollDevice(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	id, ok := pathID(w, r)
	if s == nil || !ok {
		return
	}
	out, err := s.Poll(r.Context(), id)
	reply(w, out, err)
}

func (a *App) deviceAction(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	id, ok := pathID(w, r)
	if s == nil || !ok {
		return
	}
	var in struct {
		Action string         `json:"action"`
		Params drivers.Params `json:"params"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	if slices.Contains(devices.AdminActions, in.Action) && !p.Perms.Has(access.DevicesAdmin) {
		httpx.Error(w, http.StatusForbidden, "forbidden", "you do not have the permission "+access.DevicesAdmin)
		return
	}
	out, err := s.Apply(r.Context(), id, in.Action, in.Params)
	detail := map[string]any{"action": in.Action, "ok": err == nil}
	if in.Action == drivers.ActionCommand {
		detail["command"] = truncateStr(in.Params.Command, 300)
	} else {
		detail["params"] = in.Params
	}
	if err != nil {
		detail["error"] = err.Error()
	}
	a.audit(r.Context(), p, "device."+in.Action, "device:"+strconv.FormatInt(id, 10), detail)
	reply(w, out, err)
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (a *App) deviceBackup(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	id, ok := pathID(w, r)
	if s == nil || !ok {
		return
	}
	out, err := s.Backup(r.Context(), id)
	a.audit(r.Context(), p, "device.backup", "device:"+strconv.FormatInt(id, 10), map[string]any{"ok": err == nil})
	if err != nil {
		httpx.Err(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="device-`+strconv.FormatInt(id, 10)+`.cfg"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(out))
}

func (a *App) resetDeviceHostKey(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	id, ok := pathID(w, r)
	if s == nil || !ok {
		return
	}
	v, err := s.ResetHostKey(r.Context(), id)
	if err == nil {
		a.audit(r.Context(), p, "device.host_key_reset", "device:"+strconv.FormatInt(id, 10), map[string]any{"name": v.Name})
	}
	reply(w, v, err)
}

func (a *App) listEndpoints(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	q := r.URL.Query()
	in := devices.EndpointQuery{Q: q.Get("q")}
	switch q.Get("online") {
	case "true", "1":
		t := true
		in.Online = &t
	case "false", "0":
		f := false
		in.Online = &f
	}
	if v := q.Get("device_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			httpx.Error(w, http.StatusBadRequest, "bad_request", "invalid device_id")
			return
		}
		in.DeviceID = id
	}
	if v := q.Get("limit"); v != "" {
		in.Limit, _ = strconv.Atoi(v)
	}
	out, err := s.Endpoints(r.Context(), in)
	reply(w, map[string]any{"results": out}, err)
}

func (a *App) getEndpoint(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	out, err := s.Endpoint(r.Context(), r.PathValue("mac"))
	reply(w, out, err)
}

func (a *App) updateEndpoint(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	var in struct {
		Alias *string `json:"alias"`
		Note  *string `json:"note"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	out, err := s.UpdateEndpoint(r.Context(), r.PathValue("mac"), in.Alias, in.Note)
	if err == nil {
		a.audit(r.Context(), p, "endpoint.updated", "endpoint:"+out.MAC, map[string]any{"alias": out.Alias})
	}
	reply(w, out, err)
}

func (a *App) forgetEndpoint(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	mac := strings.ToLower(r.PathValue("mac"))
	if err := s.ForgetEndpoint(r.Context(), mac); err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(r.Context(), p, "endpoint.deleted", "endpoint:"+drivers.NormMAC(mac), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) blockEndpoint(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	var in struct {
		Blocked *bool `json:"blocked"`
	}
	if !httpx.Decode(w, r, &in) {
		return
	}
	blocked := in.Blocked == nil || *in.Blocked
	dev, out, err := s.BlockEndpoint(r.Context(), r.PathValue("mac"), blocked)
	if dev.ID > 0 {
		a.audit(r.Context(), p, "endpoint.blocked", "endpoint:"+drivers.NormMAC(r.PathValue("mac")),
			map[string]any{"blocked": blocked, "device": dev.ID, "ok": err == nil})
	}
	reply(w, map[string]any{"ok": out.OK, "output": out.Output, "device_id": dev.ID, "device_name": dev.Name}, err)
}

func (a *App) topology(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	q := r.URL.Query()
	out, err := s.Topology(r.Context(), q.Get("offline") == "true", q.Get("endpoints") != "false")
	reply(w, out, err)
}

func (a *App) topologyPositions(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	var in map[string]*[2]float64
	if !httpx.Decode(w, r, &in) {
		return
	}
	if err := s.SetPositions(r.Context(), in); err != nil {
		httpx.Err(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) getDeviceSettings(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	set, err := s.Settings(r.Context())
	reply(w, map[string]any{"settings": set, "collector": s.Collector(r.Context())}, err)
}

func (a *App) putDeviceSettings(w http.ResponseWriter, r *http.Request, p *Principal) {
	s := a.devicesOn(w)
	if s == nil {
		return
	}
	var in devices.Settings
	if !httpx.Decode(w, r, &in) {
		return
	}
	set, err := s.PutSettings(r.Context(), in)
	if err != nil {
		httpx.Err(w, err)
		return
	}
	a.audit(r.Context(), p, "settings.devices", "devices", set)
	httpx.JSON(w, http.StatusOK, map[string]any{"settings": set, "collector": s.Collector(r.Context())})
}
