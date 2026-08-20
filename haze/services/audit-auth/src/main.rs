#![forbid(unsafe_code)]

//! Institutional audit authorization process boundary.
//!
//! T4.3 ships the authorization library. A live HTTP listener is not required
//! for the unit suite; `AuditAuth::challenge`, `AuditAuth::token`,
//! `AuditAuth::create_case`, `AuditAuth::update_case`, `AuditAuth::delegate`,
//! `AuditAuth::revoke`, and `AuditAuth::authorize` are the `/v1/auth/*` and
//! `/v1/cases` semantic.

fn main() {}
