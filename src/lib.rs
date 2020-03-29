#![feature(backtrace)]

//! The `aws_sig_verify` crate provides AWS SigV4 _verification_ routines.
//! This *is not* the library you want if you just want to call AWS services
//! or other services that use AWS SigV4 signatures.
//! [Rusoto](https://github.com/rusoto/rusoto) already has a library, 
//! [rusoto_signature](https://docs.rs/rusoto_signature/), that provides this
//! functionality.
//!
//! If you are attempting to perform AWS SigV4 verification using AWS-vended
//! credentials, this library also ___will not work for you___. You need the
//! caller's secret key (or a derivative), and AWS does not allow this for
//! obvious reasons. Instead, you should be using [API Gateway with IAM
//! authentication](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html).
//!
//! On the other hand, if you have your own ecosystem of AWS-like credentials
//! and are developing mock-AWS services or just really like AWS SigV4 but
//! can't run within AWS, this library _might_ be for you.

extern crate chrono;
extern crate hex;
extern crate lazy_static;
extern crate regex;
extern crate ring;

mod chronoutil;
mod signature;
mod hmac;
pub use crate::signature::{
    AWSSigV4Algorithm, AWSSigV4, ErrorKind, IAMAssumedRoleDetails,
    IAMGroupDetails, IAMRoleDetails, IAMUserDetails, Principal, PrincipalType,
    Request, SignatureError, SigningKeyFn, SigningKeyKind,
    normalize_uri_path_component, canonicalize_uri_path,
    normalize_query_parameters
};

#[cfg(test)]
mod unittest;
