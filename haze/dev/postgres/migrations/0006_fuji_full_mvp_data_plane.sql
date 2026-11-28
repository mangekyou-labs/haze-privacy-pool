-- Migration 0006: Fuji Full MVP Data Plane
-- Extends PostgreSQL schema for hosted identity, gatekeeper, indexer, and multi-version compliance governance.

create table if not exists haze_organizations (
    org_id text primary key,
    name text not null,
    created_at timestamptz not null default now()
);

create table if not exists haze_identities (
    subject text primary key,
    org_id text references haze_organizations(org_id),
    email text,
    role text not null,
    created_at timestamptz not null default now()
);

create table if not exists haze_identity_memberships (
    application_id bytea not null,
    wallet bytea not null,
    role text not null, -- 'pool-user', 'application-admin', 'application-auditor', 'governance-operator', 'super-auditor'
    org_id text references haze_organizations(org_id),
    subject text,
    email text,
    granted_fields text[] default array[]::text[],
    enrolled_at timestamptz not null default now(),
    primary key (application_id, wallet, role),
    constraint chk_institutional_membership check (
        (role = 'pool-user') or
        (role in ('application-admin', 'application-auditor', 'governance-operator', 'super-auditor') and org_id is not null and subject is not null)
    )
);

create index if not exists idx_haze_identity_memberships_wallet on haze_identity_memberships(wallet);
create index if not exists idx_haze_identity_memberships_app on haze_identity_memberships(application_id);

create table if not exists haze_auth_challenges (
    challenge_id bytea primary key,
    nonce text not null,
    wallet bytea not null,
    application_id bytea not null,
    role text not null, -- 'pool-user', 'application-admin', 'application-auditor', 'governance-operator', 'super-auditor'
    chain_id bigint not null default 43113,
    domain text not null,
    uri text not null,
    statement text not null,
    message text not null,
    oidc_subject text,
    oidc_issuer text,
    expires_at timestamptz not null,
    consumed boolean not null default false,
    consumed_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists idx_haze_auth_challenges_nonce on haze_auth_challenges(nonce);
create index if not exists idx_haze_auth_challenges_wallet on haze_auth_challenges(wallet);

create table if not exists haze_auth_sessions (
    session_hash bytea primary key,
    wallet bytea not null,
    application_id bytea not null,
    role text not null, -- 'pool-user', 'application-admin', 'application-auditor', 'governance-operator', 'super-auditor'
    org_id text references haze_organizations(org_id),
    oidc_subject text,
    challenge_id bytea,
    expires_at timestamptz not null,
    revoked boolean not null default false,
    revoked_at timestamptz,
    created_at timestamptz not null default now(),
    constraint chk_institutional_session check (
        (role = 'pool-user') or
        (role in ('application-admin', 'application-auditor', 'governance-operator', 'super-auditor') and org_id is not null and oidc_subject is not null)
    )
);

create index if not exists idx_haze_auth_sessions_wallet on haze_auth_sessions(wallet);
create index if not exists idx_haze_auth_sessions_app on haze_auth_sessions(application_id);
create index if not exists idx_haze_auth_sessions_role on haze_auth_sessions(role);

create table if not exists haze_wallet_bindings (
    wallet bytea primary key,
    subject text not null references haze_identities(subject),
    siwe_signature bytea not null,
    bound_at timestamptz not null default now()
);

create table if not exists haze_applications (
    application_id bytea primary key,
    org_id text references haze_organizations(org_id),
    admin_wallet bytea not null,
    gatekeeper_signer bytea not null,
    policy_authority bytea not null,
    audit_public_key bytea not null,
    audit_key_version int not null default 1,
    membership_root bytea not null,
    membership_version bigint not null default 1,
    manifest_uri text not null,
    manifest_hash bytea not null,
    policy_profile bytea not null,
    status text not null default 'active', -- active, suspended, retired
    created_at timestamptz not null default now()
);

create table if not exists haze_application_members (
    application_id bytea not null references haze_applications(application_id),
    member_wallet bytea not null,
    leaf_index bigint not null,
    leaf_hash bytea not null,
    enrolled_at timestamptz not null default now(),
    primary key (application_id, member_wallet)
);

create table if not exists haze_policy_roots (
    policy_version bigint not null,
    root_type text not null, -- application_membership, global_blocklist
    root_hash bytea not null,
    artifact_hash bytea not null,
    active boolean not null default false,
    scheduled_at timestamptz not null default now(),
    activated_at timestamptz,
    primary key (policy_version, root_type)
);

create table if not exists haze_protocol_versions (
    version_tag bytea primary key,
    artifact_hash bytea not null,
    manifest_uri text not null,
    support_until timestamptz not null,
    is_active boolean not null default false,
    scheduled_at timestamptz not null default now(),
    activated_at timestamptz
);

create table if not exists haze_governance_proposals (
    proposal_id bigint primary key,
    proposer bytea not null,
    target bytea not null,
    value numeric not null default 0,
    calldata bytea not null,
    executed boolean not null default false,
    approvals_count int not null default 1,
    created_at timestamptz not null default now(),
    executed_at timestamptz
);

create table if not exists haze_proposal_approvals (
    proposal_id bigint not null references haze_governance_proposals(proposal_id),
    approver bytea not null,
    approved_at timestamptz not null default now(),
    primary key (proposal_id, approver)
);

create table if not exists haze_indexed_events (
    event_id text primary key,
    chain_id bigint not null default 43113,
    block_number bigint not null,
    block_hash bytea not null default '\x00',
    tx_hash bytea not null,
    log_index int not null,
    block_timestamp timestamptz not null default now(),
    event_type text not null, -- PrivateTransaction, EmergencyExitRequested, EmergencyExitExecuted
    pool_address bytea not null,
    application_id bytea not null,
    action int not null,
    action_reference bytea not null,
    canonical boolean not null default true,
    finality_status text not null default 'unconfirmed', -- 'unconfirmed', 'pending_finality', 'confirmed', 'orphaned'
    public_amount numeric not null default 0,
    public_recipient bytea,
    output_commitment_0 bytea,
    output_commitment_1 bytea,
    input_nullifier_0 bytea,
    input_nullifier_1 bytea,
    recipient_ciphertext_0 bytea,
    recipient_ciphertext_1 bytea,
    audit_ciphertext bytea,
    audit_data_commitment bytea,
    audit_ciphertext_hash bytea,
    confirmed boolean not null default false,
    created_at timestamptz not null default now(),
    constraint uq_event_provenance unique (chain_id, block_number, tx_hash, log_index)
);

create index if not exists idx_haze_indexed_events_tx_hash on haze_indexed_events(tx_hash);
create index if not exists idx_haze_indexed_events_app on haze_indexed_events(application_id);
create index if not exists idx_haze_indexed_events_pool on haze_indexed_events(pool_address);
create unique index if not exists idx_haze_indexed_events_canonical_action_ref on haze_indexed_events(action_reference) where canonical = true;

-- Ensure application isolation check
create or replace function check_case_application_isolation()
returns trigger as $$
begin
    if NEW.application_id is null then
        raise exception 'APPLICATION_ISOLATION_VIOLATION: case must bind application_id';
    end if;
    return NEW;
end;
$$ language plpgsql;

drop trigger if exists trg_case_app_isolation on haze_compliance_cases;
create trigger trg_case_app_isolation
before insert or update on haze_compliance_cases
for each row execute function check_case_application_isolation();
