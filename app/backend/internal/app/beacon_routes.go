package app

import (
	"net/http"

	"github.com/sbrw-evc/current/app/backend/internal/access"
)

// umbrellaRoutes registers the Beacon API endpoints (visibility scope,
// connection settings, dependency discovery).
func (a *App) umbrellaRoutes(h func(pattern string, handler func(http.ResponseWriter, *http.Request))) {
	h("GET /api/umbrella/scope", a.guard(nil, a.myScope))
	h("GET /api/settings/umbrella/api", a.guard(perms(access.UmbrellaView), a.getUmbrellaAPI))
	h("PUT /api/settings/umbrella/api", a.guard(perms(access.UmbrellaEdit), a.putUmbrellaAPI))
	h("POST /api/settings/umbrella/api/test", a.guard(perms(access.UmbrellaEdit), a.testUmbrellaAPI))

	h("GET /api/dependencies", a.guard(perms(access.DependenciesView), a.getDependencies))
	h("PUT /api/dependencies/settings", a.guard(perms(access.UmbrellaEdit), a.putDependencySettings))
	h("POST /api/dependencies/run", a.guard(perms(access.DependenciesRun), a.runDependenciesNow))
}
