package access

import (
	"slices"
	"testing"
)

func TestCatalog(t *testing.T) {
	want := []string{VisualizeView, FlowsView, ExportersView, ExportersEdit, InventoryView, InventoryEdit, InventorySync,
		ClassifiersView, ClassifiersEdit, UsersView, UsersEdit, RolesView, RolesEdit, StatusView,
		GeneralView, GeneralEdit, UmbrellaView, UmbrellaEdit, OpenBaoView, OpenBaoTest, DetectorView, DetectorEdit,
		OpenBaoMigrate, TokensView, TokensEdit, IntegrationsInventoryRead, ScopeUmbrella,
		GNMIView, GNMIEdit, SNMPView, SNMPEdit, BMPView, BMPEdit,
		RDNSView, RDNSEdit, ThreatView, ThreatEdit, FlowLogsView, FlowLogsEdit,
		DevicesView, DevicesEdit, DevicesOperate, DevicesAdmin}
	for _, p := range want {
		if !Valid(p) {
			t.Errorf("%s missing", p)
		}
	}
	// Several features add permissions: check the listed ones exist and none is duplicated.
	if all := All(); len(all) < len(want) || len(NewSet(all)) != len(all) {
		t.Fatalf("catalog has %d permissions: %v", len(all), all)
	}
	got := Normalize([]string{"settings.inventory:sync", "bogus:x", "flows:view"})
	if !slices.Equal(got, []string{FlowsView, InventoryView, InventorySync}) {
		t.Fatal(got)
	}
	roles := BuiltinRoles()
	if roles[0].Name != RoleAdministrator || len(roles[0].Permissions) != len(All())-1 || NewSet(roles[0].Permissions).Has(ScopeUmbrella) {
		t.Fatal(roles[0])
	}
	s := NewSet(roles[1].Permissions)
	if !s.Has(VisualizeView) || s.Has(UsersView) || !s.Any(UsersView, FlowsView) {
		t.Fatal(roles[1])
	}
}
