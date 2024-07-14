//! The `aws_sig_verify` crate provides AWS SigV4 _verification_ routines. This *is not* the library you want if you
//! just want to call AWS services or other services that use AWS SigV4 signatures.
//! [Rusoto](https://github.com/rusoto/rusoto) already has a library,
//! [rusoto_signature](https://docs.rs/rusoto_signature/), that provides this functionality.
//!
//! If you are attempting to perform AWS SigV4 verification using AWS-vended credentials, this library also
//! ___will not work for you___. You need the caller's secret key (or a derivative), and AWS does not allow this for
//! obvious reasons. Instead, you should be using [API Gateway with IAM
//! authentication](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html).
//!
//! On the other hand, if you have your own ecosystem of AWS-like credentials and are developing mock-AWS services or
//! just really like AWS SigV4 but can't run within AWS, this library _might_ be for you.
//!
//! # Workflow
//! This assumes you have a complete HTTP request (headers _and_ body) already. As a result, you may not be able to
//! implement this as a middleware layer for a web server—those typically only provide the headers. Having the body is
//! required for almost all modes of AWS SigV4.
//!
//! The typical workflow is:
//! 1. Convert an HTTP `Request` object into a scratchstack `Request` object.
//! 2. Create a `GetSigningKeyRequest` from this `Request`.
//! 3. Call your service to obtain the principal and signing key for this request.
//! 4. Verify the request using `sigv4_verify` or `sigv4_verify_at`.
//!
//! ## Example
//! ```rust
//! use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
//! use http::Request;
//! use scratchstack_aws_principal::PrincipalActor;
//! use scratchstack_aws_signature::{
//!     Request as SigRequest, SigningKey, SigningKeyKind, get_signing_key_fn, sigv4_verify_at,
//! };
//! use std::error::Error;
//! use tower::Service;
//!
//! const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
//! const SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
//! const ACCOUNT_ID: &str = "123456789012";
//! const PARTITION: &str = "aws";
//! const PATH: &str = "/engineering/";
//! const REGION: &str = "us-east-1";
//! const SERVICE: &str = "example";
//! const USER_NAME: &str = "user";
//! const USER_ID: &str = "AIDAQXZEAEXAMPLEUSER";
//!
//! // The date for which the signature calculation was made.
//! #[allow(deprecated)]
//! const TEST_TIMESTAMP: DateTime<Utc> = DateTime::<Utc>::from_naive_utc_and_offset(
//!     NaiveDateTime::new(
//!         NaiveDate::from_ymd(2021, 1, 1),
//!         NaiveTime::from_hms(0, 0, 0)),
//!     Utc
//! );
//!
//! // This is a mock function that returns a static secret key converted into the requested type
//! // of signing key. For actual use, you would call out to a database or other service to obtain
//! // a signing key.
//! async fn get_signing_key(
//!     kind: SigningKeyKind,
//!     access_key: String,
//!     _session_token: Option<String>,
//!     req_date: NaiveDate,
//!     region: String,
//!     service: String)
//! -> Result<(PrincipalActor, SigningKey), Box<(dyn Error + Send + Sync)>> {
//!     assert!(access_key == ACCESS_KEY);
//!     let signing_key = SigningKey {
//!         kind: SigningKeyKind::KSecret,
//!         key: SECRET_KEY.as_bytes().to_vec()
//!     };
//!     let signing_key = signing_key.try_derive(kind, &req_date, &region, &service)?;
//!     let principal = PrincipalActor::user(PARTITION, ACCOUNT_ID, PATH, USER_NAME, USER_ID)?;
//!     Ok((principal, signing_key))
//! }
//!
//! # tokio_test::block_on(async {
//! // Normally this would come from your web framework.
//! let req = Request::get("https://example.com")
//!     .header("Host", "example.com")
//!     .header("X-Amz-Date", "20210101T000000Z")
//!     .header("Authorization", "AWS4-HMAC-SHA256 \
//! Credential=AKIAIOSFODNN7EXAMPLE/20210101/us-east-1/example/aws4_request, \
//! SignedHeaders=host;x-amz-date, \
//! Signature=3ea4679d2ecf5a8293e1fb10298c82988f024a2e937e9b37876b34bb119da0bc")
//!     .body(())
//!     .unwrap();
//!
//! // Extract the header parts; the body is not used in this example.
//! let parts = req.into_parts().0;
//!
//! // Convert this into a scratchstack Request.
//! let sig_req = SigRequest::from_http_request_parts(&parts, None);
//!
//! // Create a request to obtain a signing key. Here, we're asking for a SigningKeyKing::KSigning
//! // key type which is the most secure; if the key is leaked, an attacker can only sign requests
//! // for the given date, region, and service.
//! let get_signing_key_req = sig_req.to_get_signing_key_request(
//!     SigningKeyKind::KSigning, REGION, SERVICE).unwrap();
//! let (_principal, signing_key) = get_signing_key_fn(get_signing_key)
//!     .call(get_signing_key_req).await.unwrap();
//!
//! // Normally you would use `sigv4_verify` instead of `sigv4_verify_at`.
//! // We're pinning this to a specific date for testing purposes.
//! sigv4_verify_at(&sig_req, &signing_key, &TEST_TIMESTAMP, None, REGION, SERVICE).unwrap();
//! # });
//! ```
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::missing_crate_level_docs)]

mod chronoutil;
mod hmac;
mod signature;
pub use crate::signature::{
    canonicalize_uri_path, get_signing_key_fn, is_rfc3986_unreserved, normalize_query_parameters,
    normalize_uri_path_component, sigv4_get_expected_signature, sigv4_verify, sigv4_verify_at, GetSigningKey,
    GetSigningKeyFn, GetSigningKeyRequest, Request, SignatureError, SigningKey, SigningKeyKind,
};

#[cfg(test)]
mod unittest;

#[cfg(test)]
mod aws4;
