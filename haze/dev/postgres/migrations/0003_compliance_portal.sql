create table if not exists haze_compliance_challenges (
    challenge_id bytea primary key,
    nonce text not null,
    domain text not null,
    uri text not null,
    statement text not null,
    wallet bytea not null,
    application_id bytea not null,
    expires_at timestamptz not null,
    consumed boolean not null default false,
    created_at timestamptz not null default now()
);

create table if not exists haze_compliance_sessions (
    session_hash bytea primary key,
    wallet bytea not null,
    application_id bytea not null,
    role text not null,
    grant_id bytea not null,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create table if not exists haze_compliance_grants (
    grant_id bytea primary key,
    wallet bytea not null,
    application_id bytea not null,
    role text not null,
    granted_fields text[] not null,
    denied_fields text[] not null,
    revoked boolean not null default false,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create table if not exists haze_compliance_cases (
    case_id text primary key,
    title text not null,
    application_id bytea not null,
    transaction_hash bytea not null,
    granted_fields text[] not null,
    denied_fields text[] not null,
    status text not null,
    created_at timestamptz not null default now()
);

create table if not exists haze_compliance_exports (
    export_id bytea primary key,
    case_id text not null,
    record_id bytea not null,
    subject bytea not null,
    token_id bytea not null,
    fields jsonb not null,
    signature bytea not null,
    signing_key_id text not null,
    expires_at timestamptz not null,
    created_at timestamptz not null default now()
);

create table if not exists haze_compliance_access_log (
    seq bigserial primary key,
    prev_hash bytea not null,
    entry_hash bytea not null,
    name text not null,
    application_id bytea not null,
    case_id text,
    wallet bytea not null,
    fields text not null,
    allowed boolean not null,
    at timestamptz not null default now()
);
