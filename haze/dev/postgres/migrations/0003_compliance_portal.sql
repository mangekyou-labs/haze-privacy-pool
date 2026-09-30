create table if not exists haze_compliance_challenges (
    challenge_id bytea primary key,
    nonce text not null,
    domain text not null,
    uri text not null,
    statement text not null,
    message text not null,
    issued_at timestamptz not null default now(),
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
    chain_id bigint not null,
    pool bytea not null,
    application_id bytea not null,
    transaction_hash bytea not null,
    log_index bigint not null,
    block_number bigint not null,
    block_hash bytea,
    status text not null,
    confirmations bigint not null default 0,
    required_confirmations bigint not null default 12,
    assigned_auditor bytea,
    amount text,
    asset text,
    event_timestamp timestamptz,
    policy_version integer,
    witness_data jsonb,
    granted_fields text[] not null,
    denied_fields text[] not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (chain_id, transaction_hash, log_index)
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
