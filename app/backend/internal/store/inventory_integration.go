package store

import "context"

// InventoryIntegration is the Flow side of the Inventory DB integration
// (docs/integrations.md §2): openbao:// references of the hook secret
// (x-inventory-signature) and of the optional editor token used to create
// IPAM addresses from the Unknown lists.
type InventoryIntegration struct {
	HookSecretRef string
	WriteTokenRef string
}

// InventoryIntegration reads the integration secrets' references.
func (s *Store) InventoryIntegration(ctx context.Context) (InventoryIntegration, error) {
	var c InventoryIntegration
	err := s.pool.QueryRow(ctx, `SELECT hook_secret_ref, write_token_ref FROM inventory_db WHERE id = 1`).
		Scan(&c.HookSecretRef, &c.WriteTokenRef)
	return c, pgErr(err)
}

// SetInventoryIntegration stores the references. It does not touch
// updated_at, so the synchronization loops do not treat it as a connection
// change.
func (s *Store) SetInventoryIntegration(ctx context.Context, c InventoryIntegration) error {
	_, err := s.pool.Exec(ctx, `UPDATE inventory_db SET hook_secret_ref = $1, write_token_ref = $2 WHERE id = 1`,
		c.HookSecretRef, c.WriteTokenRef)
	return pgErr(err)
}
