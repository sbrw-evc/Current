package access

import (
	"slices"
	"testing"
)

func TestCatalog(t *testing.T) {
	want := []string{VisualizeView, FlowsView, ExportersView, ExportersEdit, InventoryView, InventoryEdit, InventorySync,
		ClassifiersView, ClassifiersEdit, UsersView, UsersEdit, RolesView, RolesEdit, StatusView,
		GeneralView, GeneralEdit, UmbrellaView, UmbrellaEdit, OpenBaoView, OpenBaoTest, DetectorView, DetectorEdit}
	for _, p := range want {
		if !Valid(p) {
			t.Errorf("%s missing", p)
		}
	}
	if len(All()) != len(want) {
		t.Fatalf("catalog has %d permissions: %v", len(All()), All())
	}
	got := Normalize([]string{"settings.inventory:sync", "bogus:x", "flows:view"})
	if !slices.Equal(got, []string{FlowsView, InventoryView, InventorySync}) {
		t.Fatal(got)
	}
	roles := BuiltinRoles()
	if roles[0].Name != RoleAdministrator || len(roles[0].Permissions) != len(want) {
		t.Fatal(roles[0])
	}
	s := NewSet(roles[1].Permissions)
	if !s.Has(VisualizeView) || s.Has(UsersView) || !s.Any(UsersView, FlowsView) {
		t.Fatal(roles[1])
	}
}
