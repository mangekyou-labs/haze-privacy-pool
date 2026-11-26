alter table haze_compliance_grants
    add column if not exists assigned_cases text[] not null default '{}';

alter table haze_compliance_challenges
    add column if not exists issued_at timestamptz not null default now(),
    add column if not exists message text not null default '';

alter table haze_compliance_exports
    add column if not exists provenance jsonb not null default '{}';

alter table haze_compliance_cases
    add column if not exists block_number bigint not null default 0,
    add column if not exists block_hash bytea,
    add column if not exists log_index bigint,
    add column if not exists confirmations bigint not null default 0,
    add column if not exists sync_status text not null default 'synced',
    add column if not exists integrity_status text not null default 'pending',
    add column if not exists observed_at timestamptz not null default now(),
    add column if not exists finalized_at timestamptz,
    add column if not exists orphaned boolean not null default false;

create unique index if not exists haze_compliance_cases_event_key
    on haze_compliance_cases (transaction_hash, log_index)
    where log_index is not null;

create table if not exists haze_compliance_case_assignments (
    grant_id bytea not null references haze_compliance_grants(grant_id),
    case_id text not null references haze_compliance_cases(case_id),
    assigned_at timestamptz not null default now(),
    primary key (grant_id, case_id)
);

create table if not exists haze_compliance_evidence (
    chain_id bigint not null,
    pool bytea not null,
    application_id bytea not null,
    transaction_hash bytea not null,
    log_index bigint not null,
    block_number bigint not null,
    block_hash bytea not null,
    action smallint not null,
    authorized_user bytea not null,
    pool_version bytea not null,
    audit_data_commitment bytea not null,
    audit_ciphertext_hash bytea not null,
    action_reference bytea not null,
    envelope bytea not null,
    key_version bigint not null,
    observed_at timestamptz not null default now(),
    finality_status text not null default 'observed',
    integrity_status text not null default 'pending',
    orphaned boolean not null default false,
    payload jsonb not null default '{}',
    primary key (chain_id, pool, transaction_hash, log_index)
);

create index if not exists haze_compliance_evidence_application_block
    on haze_compliance_evidence (application_id, block_number);

create table if not exists haze_compliance_poller_checkpoints (
    poller_id text primary key,
    chain_id bigint not null,
    pool bytea not null,
    application_id bytea not null,
    next_block bigint not null,
    last_block_hash bytea,
    last_success_at timestamptz,
    last_error jsonb,
    consecutive_failures integer not null default 0,
    healthy boolean not null default false,
    updated_at timestamptz not null default now()
);

create table if not exists haze_compliance_access_log_heads (
    application_id bytea primary key,
    sequence bigint not null,
    entry_hash bytea not null,
    updated_at timestamptz not null default now()
);

alter table haze_compliance_access_log
    add column if not exists application_sequence bigint;

update haze_compliance_access_log
set application_sequence = ranked.application_sequence
from (
    select seq, row_number() over (partition by application_id order by seq) as application_sequence
    from haze_compliance_access_log
) ranked
where haze_compliance_access_log.seq = ranked.seq
  and haze_compliance_access_log.application_sequence is null;

alter table haze_compliance_access_log
    alter column application_sequence set not null;

create unique index if not exists haze_compliance_access_log_application_sequence
    on haze_compliance_access_log (application_id, application_sequence);

create table if not exists haze_compliance_export_counters (
    application_id bytea primary key,
    value bigint not null default 0,
    updated_at timestamptz not null default now()
);

create sequence if not exists haze_compliance_runtime_id_seq;
