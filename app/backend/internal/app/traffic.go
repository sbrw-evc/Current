package app

import (
	"net/http"
	"strconv"

	"github.com/sbrw-evc/current/app/backend/internal/httpx"
)

// Handlers that pass the request to the traffic packages (Deps).

func reply(w http.ResponseWriter, out any, err error) {
	if err != nil {
		httpx.Err(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (a *App) visualize(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Visualizer == nil {
		notImplemented(w, "visualize")
		return
	}
	req, ok := httpx.Raw(w, r)
	if !ok {
		return
	}
	out, err := a.deps.Visualizer.Visualize(r.Context(), req)
	reply(w, out, err)
}

func (a *App) filterValidate(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Filter == nil {
		notImplemented(w, "filter validation")
		return
	}
	req, ok := httpx.Raw(w, r)
	if !ok {
		return
	}
	out, err := a.deps.Filter.Validate(r.Context(), req)
	reply(w, out, err)
}

func (a *App) filterComplete(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Filter == nil {
		notImplemented(w, "filter completion")
		return
	}
	req, ok := httpx.Raw(w, r)
	if !ok {
		return
	}
	out, err := a.deps.Filter.Complete(r.Context(), req)
	reply(w, out, err)
}

func (a *App) flowsSearch(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Flows == nil {
		notImplemented(w, "flow search")
		return
	}
	req, ok := httpx.Raw(w, r)
	if !ok {
		return
	}
	out, err := a.deps.Flows.SearchFlows(r.Context(), req)
	reply(w, out, err)
}

func (a *App) exporters(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Exporters == nil {
		notImplemented(w, "exporters")
		return
	}
	out, err := a.deps.Exporters.Exporters(r.Context())
	reply(w, out, err)
}

func (a *App) widgetSummary(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Widgets == nil {
		notImplemented(w, "widgets")
		return
	}
	out, err := a.deps.Widgets.Summary(r.Context())
	reply(w, out, err)
}

var topWidgets = map[string]bool{"src-as": true, "dst-as": true, "src-country": true, "dst-country": true, "app": true,
	"exporter": true, "src-port": true, "dst-port": true}

func (a *App) widgetTop(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Widgets == nil {
		notImplemented(w, "widgets")
		return
	}
	what := r.PathValue("what")
	if !topWidgets[what] {
		httpx.Error(w, http.StatusNotFound, "not_found", "unknown widget "+what)
		return
	}
	out, err := a.deps.Widgets.Top(r.Context(), what)
	reply(w, out, err)
}

func (a *App) widgetGraph(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Widgets == nil {
		notImplemented(w, "widgets")
		return
	}
	points := 200
	if s := r.URL.Query().Get("points"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 2 || n > 2000 {
			httpx.Error(w, http.StatusBadRequest, "invalid_points", "points must be 2-2000")
			return
		}
		points = n
	}
	out, err := a.deps.Widgets.Graph(r.Context(), points)
	reply(w, out, err)
}

func (a *App) widgetLastFlow(w http.ResponseWriter, r *http.Request, p *Principal) {
	if a.deps.Widgets == nil {
		notImplemented(w, "widgets")
		return
	}
	out, err := a.deps.Widgets.LastFlow(r.Context())
	reply(w, out, err)
}
