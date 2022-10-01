#![warn(clippy::all)]

mod service;
pub use crate::service::{AwsSigV4VerifierService, XmlErrorMapper};
