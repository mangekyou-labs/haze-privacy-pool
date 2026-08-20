create table if not exists haze_schema_migrations (
    version text primary key,
    applied_at timestamptz not null default now()
);

create table if not exists haze_access_log (
    id bigserial primary key,
    application_id bytea not null,
    actor text not null,
    action text not null,
    created_at timestamptz not null default now()
);

create table if not exists haze_audit_records (
    id bigserial primary key,
    application_id bytea not null,
    ciphertext bytea not null,
    commitment bytea not null,
    created_at timestamptz not null default now()
);
