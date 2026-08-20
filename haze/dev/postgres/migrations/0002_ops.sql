create table if not exists haze_idempotency (
    idempotency_key text primary key,
    request_hash bytea not null,
    response_hash bytea not null,
    created_at timestamptz not null default now()
);

create table if not exists haze_checkpoints (
    replica_id text not null,
    block_number bigint not null,
    block_hash bytea not null,
    log_position bigint not null,
    primary key (replica_id)
);

create table if not exists haze_retention (
    object_key text primary key,
    body bytea not null,
    created_at timestamptz not null default now()
);

create table if not exists haze_compat (
    product_id text primary key,
    schema_version integer not null,
    api_version text not null,
    circuit_version text not null,
    contract_family text not null
);
