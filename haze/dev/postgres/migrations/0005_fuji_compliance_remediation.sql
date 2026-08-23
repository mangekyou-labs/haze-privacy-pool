-- Migration 0005: Fuji Compliance Remediation (D8.R8)
-- Adds explicit CaseScope semantics, composite constraints, disclosure receipts, and optimized indexes.

-- 1. Add scope_kind to grants and backfill
alter table haze_compliance_grants
    add column if not exists scope_kind text not null default 'all_application_cases';

update haze_compliance_grants
set scope_kind = case
    when cardinality(assigned_cases) > 0 then 'explicit_cases'
    else 'all_application_cases'
end
where scope_kind = 'all_application_cases';

-- 2. Populate case assignments table for any explicit grants
insert into haze_compliance_case_assignments (grant_id, case_id)
select g.grant_id, unnest(g.assigned_cases)
from haze_compliance_grants g
where cardinality(g.assigned_cases) > 0
on conflict do nothing;

-- 3. Composite unique index on (application_id, case_id)
create unique index if not exists haze_compliance_cases_application_case_id
    on haze_compliance_cases (application_id, case_id);

-- 4. Active grants lookup index
create index if not exists haze_compliance_grants_active_lookup
    on haze_compliance_grants (wallet, application_id, revoked, expires_at);

-- 5. Session expiry index
create index if not exists haze_compliance_sessions_expiry
    on haze_compliance_sessions (session_hash, expires_at);

-- 6. Case lookup index
create index if not exists haze_compliance_cases_application_block
    on haze_compliance_cases (application_id, block_number, case_id);

-- 7. Evidence lookup index
create index if not exists haze_compliance_evidence_application_tx
    on haze_compliance_evidence (application_id, transaction_hash);

-- 8. Access log wallet history index
create index if not exists haze_compliance_access_log_wallet_history
    on haze_compliance_access_log (application_id, wallet, application_sequence);

-- 9. Disclosure verification receipts table
create table if not exists haze_compliance_disclosure_receipts (
    receipt_id bytea primary key,
    session_hash bytea not null references haze_compliance_sessions(session_hash) on delete cascade,
    application_id bytea not null,
    case_id text not null,
    evidence_digest bytea not null,
    disclosed_fields jsonb not null,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    constraint haze_compliance_disclosure_receipts_session_app_case_digest unique (session_hash, application_id, case_id, evidence_digest)
);

create index if not exists haze_compliance_disclosure_receipts_lookup
    on haze_compliance_disclosure_receipts (session_hash, application_id, case_id, expires_at);
