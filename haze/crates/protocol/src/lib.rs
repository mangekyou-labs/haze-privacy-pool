#![forbid(unsafe_code)]
#![recursion_limit = "256"]

//! Canonical protocol encodings for the Haze Avalanche Compliant Pool.

pub mod abi;
pub mod action;
pub mod address;
pub mod audit;
pub mod cbor;
pub mod ceremony;
pub mod config;
pub mod domain;
pub mod eip712;
pub mod emergency;
pub mod envelope;
pub mod error;
pub mod field;
pub mod hkdf;
pub mod hpke;
pub mod keccak;
pub mod merkle;
pub mod note;
pub mod ops;
pub mod params;
pub mod policy;
pub mod poseidon;
pub mod providers;
pub mod public_inputs;
pub mod registry;
pub mod slot;
pub mod spend;
pub mod vectors;
pub mod verifier;

pub use error::{ProtocolError, Result};

/// Stable product identifier used by manifests and compatibility checks.
pub const PRODUCT_ID: &str = "haze-avalanche-compliant-pool";

/// Chain family implemented by this product workspace.
pub const CHAIN_FAMILY: &str = "avalanche-c-chain";
