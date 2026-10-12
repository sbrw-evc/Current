path "flow/data/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "flow/metadata/*" {
  capabilities = ["read", "delete", "list"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
