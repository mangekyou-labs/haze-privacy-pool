-- Migration 0007: Reconcile Indexed Provenance & Canonical Action Reference Invariant
-- Replaces (chain_id, pool_address, tx_hash, log_index) with block-aware provenance (chain_id, block_number, tx_hash, log_index)
-- Replaces unconditional action_reference uniqueness with a canonical-only partial index.

-- 1. Drop old constraints on haze_indexed_events if they exist
alter table haze_indexed_events drop constraint if exists uq_event_provenance;
alter table haze_indexed_events drop constraint if exists haze_indexed_events_action_reference_key;

-- 2. Add block-aware event provenance unique constraint
alter table haze_indexed_events add constraint uq_event_provenance unique (chain_id, block_number, tx_hash, log_index);

-- 3. Replace action_reference index with canonical-only uniqueness index
drop index if exists idx_haze_indexed_events_action_ref;
drop index if exists idx_haze_indexed_events_canonical_action_ref;
create unique index if not exists idx_haze_indexed_events_canonical_action_ref on haze_indexed_events(action_reference) where canonical = true;
