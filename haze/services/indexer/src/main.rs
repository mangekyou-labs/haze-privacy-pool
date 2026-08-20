#![forbid(unsafe_code)]

//! Finality-aware auditability indexer process boundary.
//!
//! T4.2 ships the ingestion library. A live HTTP listener is not required
//! for the unit suite; `Indexer::ingest` / `Indexer::sync` are the
//! `/v1/events` semantic.

fn main() {}
