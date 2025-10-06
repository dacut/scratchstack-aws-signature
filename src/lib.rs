//! AWS API request signatures verification routines.
//!
//! The `scratchstack_aws_signature` crate provides
//! AWS [SigV4](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
//! _validation_ routines. This *is not* the library you want if you just want to call AWS services
//! or other services that use AWS SigV4 signatures. [Rusoto](https://github.com/rusoto/rusoto)
//! already has a library, [rusoto_signature](https://docs.rs/rusoto_signature/), that provides
//! this functionality.
//!
//! If you are attempting to perform AWS SigV4 verification using AWS-vended credentials, this
//! library also ___will not work for you___. You need the caller's secret key (or a derivative),
//! and AWS does not allow this for obvious reasons. Instead, you should be using [API Gateway with
//! IAM authentication](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html).
//!
//! On the other hand, if you have your own ecosystem of AWS-like credentials and are developing
//! mock-AWS services or other services that need to use AWS SigV4, this _might_ be the right
//! crate for you.
//!
//! Users migrating from version 0.10 to 0.11 should consult the [migration guide][migration].
//!
//! # Feature flags
//! This crate has one feature flag:
//! * `unstable`: Allows access to unstable APIs (structs, traits, functions) such as
//!   [`canonical::normalize_uri_path_component`]. These APIs are not needed for normal use of
//!   this crate; they are provided for others exploring AWS SigV4 internals.
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
//! use scratchstack_aws_principal::{Principal, User};
//! use scratchstack_aws_signature::{
//!     service_for_signing_key_fn, sigv4_validate_request, GetSigningKeyRequest,
//!     GetSigningKeyResponse, KSecretKey, SignatureOptions, NO_ADDITIONAL_SIGNED_HEADERS,
//! };
//! use std::str::FromStr;
//! use tower::{BoxError, Service};
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
//!     request: GetSigningKeyRequest)
//! -> Result<GetSigningKeyResponse, BoxError> {
//!     assert_eq!(request.access_key(), ACCESS_KEY);
//!     assert_eq!(request.region(), REGION);
//!     assert_eq!(request.service(), SERVICE);
//!     let user = User::new(PARTITION, ACCOUNT_ID, PATH, USER_NAME)?;
//!     let secret_key = KSecretKey::from_str(SECRET_KEY).unwrap();
//!     let signing_key = secret_key.to_ksigning(request.request_date(), REGION, SERVICE);
//!     Ok(GetSigningKeyResponse::builder()
//!            .principal(user)
//!            .signing_key(signing_key)
//!            .build()?)
//! }
//!
//! // Wrap `get_signing_key` in a `tower::Service`.
//! let mut get_signing_key_service = service_for_signing_key_fn(get_signing_key);
//!
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
//! // The headers that _must_ be signed (beyond the default SigV4 headers) for this service.
//! // In this case, we're not requiring any additional headers.
//! let signed_headers = NO_ADDITIONAL_SIGNED_HEADERS;
//!
//! // Signature options for the request. Defaults are typically used, except for S3.
//! let signature_options = SignatureOptions::default();
//!
//! # tokio_test::block_on(async {
//! // Validate the request.
//! let (parts, body, auth) = sigv4_validate_request(
//!     req, &REGION, &SERVICE, &mut get_signing_key_service, TEST_TIMESTAMP, &signed_headers,
//!     signature_options).await.unwrap();
//!
//! // The principal we expect to be associated with the request.
//! let expected_principal: Principal = User::new(PARTITION, ACCOUNT_ID, PATH, USER_NAME)
//!     .unwrap()
//!     .into();
//! assert_eq!(auth.principal(), &expected_principal);
//! # });
//! ```
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(rustdoc::missing_crate_level_docs)]

mod chronoutil;
mod crypto;
mod error;
mod signature;
mod signing_key;

#[cfg(feature = "streaming")]
pub mod async_spooled_tempfile;
pub mod auth;
#[cfg(feature = "streaming")]
pub mod buffered_body;
pub mod canonical;

pub use {
    error::*, scratchstack_aws_principal as principal, scratchstack_errors as errors, signature::*, signing_key::*,
};

#[doc(inline)]
pub use canonical::{
    ConstSignedHeaderRequirements, SignedHeaderRequirements, SliceSignedHeaderRequirements,
    VecSignedHeaderRequirements, NO_ADDITIONAL_SIGNED_HEADERS,
};

#[cfg(doc)]
pub mod migration;

#[cfg(test)]
mod aws4;
