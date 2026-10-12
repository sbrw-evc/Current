// Types and helpers of the Inventory DB integration settings (GET/PUT /api/inventory-db/integration).

export type InventoryIntegration = {
  hook_secret_set: boolean
  write_token_set: boolean
  hook_url: string // to enter in Inventory DB's "flow" integration
  inventory_url: string // Inventory DB address, for links to its UI
}

// Omitted = keep, '' = remove.
export type InventoryIntegrationUpdate = { hook_secret?: string; write_token?: string }

// deviceCreateUrl is Inventory DB's device creation form (the device list with the "new" panel open).
export function deviceCreateUrl(inventoryUrl: string): string | null {
  const base = inventoryUrl.trim().replace(/\/+$/, '').replace(/\/api\/v1$/, '')
  if (!/^https?:\/\/[^/\s]+/i.test(base)) return null
  return `${base}/dcim/devices?_sel=new`
}

// canCreateAddresses: the "Create in Inventory DB" action is shown only with an editor token and
// the permission to edit the Inventory DB settings.
export function canCreateAddresses(v: InventoryIntegration | undefined, canEdit: boolean): boolean {
  return Boolean(v && v.write_token_set && canEdit)
}
