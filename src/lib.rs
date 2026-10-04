#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::similar_names
)]

//! Core backend library for the vault password manager, shared by the CLI and GUI.

pub mod crypto;
pub mod error;
pub mod vault;

pub use vault::{Entry, Vault};
