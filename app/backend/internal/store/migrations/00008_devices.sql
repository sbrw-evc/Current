-- +goose Up

-- Managed network devices (internal/devices, docs/devices.md). Flow keeps
-- only management data and live state: the name, site and role of a device
-- bound to Inventory DB come from there (inventory_id / source_ref; the
-- name, site and role columns are a cache), a standalone device keeps them
-- here. Secrets live in OpenBao (devices/<id>); `secrets` lists the fields
-- that are set.
CREATE TABLE network_devices (
    id               bigserial PRIMARY KEY,
    platform         text NOT NULL,
    host             text NOT NULL,
    port             integer CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    transport        text NOT NULL DEFAULT '',
    verify_tls       boolean NOT NULL DEFAULT false,
    controller_site  text NOT NULL DEFAULT '', -- controllers: site / organisation
    inventory_id     integer,                  -- Inventory DB dcim.device id
    source_ref       text NOT NULL DEFAULT '', -- inventory-db:dcim.device:<id>
    name             text NOT NULL DEFAULT '',
    site             text NOT NULL DEFAULT '',
    role             text NOT NULL DEFAULT '',
    tags             text[] NOT NULL DEFAULT '{}',
    note             text NOT NULL DEFAULT '',
    enabled          boolean NOT NULL DEFAULT true,
    poll_seconds     integer NOT NULL DEFAULT 300 CHECK (poll_seconds BETWEEN 60 AND 86400),
    flow_exporter_ip text NOT NULL DEFAULT '',
    credentials      jsonb NOT NULL DEFAULT '{}', -- non-secret fields (username, SNMP version / user / protocols, snmp_source)
    secrets          text[] NOT NULL DEFAULT '{}',
    ssh_host_key     text NOT NULL DEFAULT '',
    status           text NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'up', 'error', 'down')),
    failures         integer NOT NULL DEFAULT 0,
    last_poll_at     timestamptz,
    last_ok_at       timestamptz,
    last_error       text NOT NULL DEFAULT '',
    down_since       timestamptz,
    alerted_since    timestamptz, -- a firing event of the down episode that started then went to Umbrella
    facts            jsonb NOT NULL DEFAULT '{}',
    interfaces       jsonb NOT NULL DEFAULT '[]',
    neighbors        jsonb NOT NULL DEFAULT '[]',
    children         jsonb NOT NULL DEFAULT '[]',
    map_x            double precision,
    map_y            double precision,
    created_by       text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
-- One managed record per Inventory DB device, and per address (and controller site).
CREATE UNIQUE INDEX network_devices_inventory_key ON network_devices (inventory_id) WHERE inventory_id IS NOT NULL;
CREATE UNIQUE INDEX network_devices_host_key ON network_devices (lower(host), coalesce(port, 0), lower(controller_site));

-- Where a device last saw a MAC: an ARP entry, a DHCP lease, a Wi-Fi
-- association, a port of a switch, a client of a controller.
CREATE TABLE device_endpoint_sightings (
    mac         text NOT NULL,
    device_id   bigint NOT NULL REFERENCES network_devices (id) ON DELETE CASCADE,
    source      text NOT NULL,
    ip          text NOT NULL DEFAULT '',
    hostname    text NOT NULL DEFAULT '',
    interface   text NOT NULL DEFAULT '',
    ssid        text NOT NULL DEFAULT '',
    signal      integer,
    vlan        integer,
    attached_to text NOT NULL DEFAULT '',
    port        text NOT NULL DEFAULT '',
    blocked     boolean NOT NULL DEFAULT false,
    seen_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (mac, device_id, source)
);
CREATE INDEX device_endpoint_sightings_device_idx ON device_endpoint_sightings (device_id);
CREATE INDEX device_endpoint_sightings_seen_idx ON device_endpoint_sightings (seen_at);

-- A client of the network merged from its sightings by MAC: the most
-- specific attachment point wins (Wi-Fi > controller > bridge > DHCP > ARP).
CREATE TABLE network_endpoints (
    mac         text PRIMARY KEY,
    ip          text NOT NULL DEFAULT '',
    hostname    text NOT NULL DEFAULT '',
    alias       text NOT NULL DEFAULT '',
    note        text NOT NULL DEFAULT '',
    vendor      text NOT NULL DEFAULT '',
    device_id   bigint REFERENCES network_devices (id) ON DELETE SET NULL,
    interface   text NOT NULL DEFAULT '',
    source      text NOT NULL DEFAULT '',
    attached_to text NOT NULL DEFAULT '',
    port        text NOT NULL DEFAULT '',
    ssid        text NOT NULL DEFAULT '',
    signal      integer,
    vlan        integer,
    blocked     boolean NOT NULL DEFAULT false,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX network_endpoints_ip_idx ON network_endpoints (ip);
CREATE INDEX network_endpoints_device_idx ON network_endpoints (device_id);
CREATE INDEX network_endpoints_seen_idx ON network_endpoints (last_seen);

-- +goose Down
DROP TABLE network_endpoints;
DROP TABLE device_endpoint_sightings;
DROP TABLE network_devices;
