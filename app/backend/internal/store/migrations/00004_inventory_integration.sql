-- +goose Up

-- Flow side of the Inventory DB integration (docs/integrations.md §2): the
-- shared secret of the change-notification hook and the optional token of an
-- Inventory DB editor used by "Create in Inventory DB". Both columns hold
-- openbao:// references only.
ALTER TABLE inventory_db
    ADD COLUMN hook_secret_ref text NOT NULL DEFAULT '',
    ADD COLUMN write_token_ref text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE inventory_db
    DROP COLUMN write_token_ref,
    DROP COLUMN hook_secret_ref;
