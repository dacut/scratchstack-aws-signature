//! # Migrating from 0.10 to 0.11
//!
//! Version 0.11 brings significant changes to the scratchstack-aws-signature crate. These changes
//! are intended to make the crate more ergonomic (easier for consumers to use) and more efficient
//! (less copying of data).
//!
//! Unfortunately, this means that the 0.11 version is not backwards compatible with the 0.10
//! version.
//!
//! ## Changes
//!
//! ### Elimination of `Request` type.
//! The main change is the elimination of the `scratchstack_aws_signature::Request` type. Instead,
//! `http::Request` is used directly and there is no longer a need to copy data from one `Request`
//! type to the other.
//!
//! With this, there is also no need to use the
//! [`GetSigningKeyRequest`][crate::GetSigningKeyRequest] type in the
//! validation code. (This type is used to pass get signing key requests.)
//!
//! This sample code from 0.10:
//! ```ignore
//! let http_req = http::Request::get("https://example.com").body(())?;
//! let sig_req = scratchstack_aws_signature::Request::from_http_request_parts(
//!     &http_req.into_parts().0, None);
//! let gsk_req = sig_req.to_get_signing_request(SigningKeyKind::KSigning, REGION, SERVICE)?;
//! let (principal, signing_key) = get_signing_key_service.call(gsk_req).await?;
//! sig4_verify(&sig_req, &signing_key, None, REGION, SERVICE)?;
//! ```
//!
//! Would be written in 0.11:
//! ```ignore
//! let http_req = http::Request::get("https://example.com").body(())?;
//! let (parts, body, auth) = sigv4_validate_request(
//!     req, &REGION, &SERVICE, &mut get_signing_key_service, Utc::now(),
//!     NO_ADDITIONAL_SIGNED_HEADERS, SignatureOptions::default())?;
//! ```
//!
//! ### Compile-time key type checking
//! In 0.10, keys of different types were all stored as the `SigningKey` type with a discriminator,
//! `SigningKeyKind`, indicating the underlying key type at runtime. This made it impossible to
//! use compile-time checks to ensure that the correct key type was used.
//!
//! In 0.11, the `SigningKey` type has been replaced with a distinct key type for each key type:
//! * [`KSecretKey`][crate::KSecretKey]: The raw secret key prefixed with `"AWS4"`.
//! * [`KDateKey`](crate::KDateKey): Key derived `KSecretKey` and the current UTC date.
//! * [`KRegionKey`](crate::KRegionKey): Key derived from `KDateKey` and the region.
//! * [`KServiceKey`](crate::KServiceKey): Key derived from `KRegionKey` and the service.
//! * [`KSigningKey`](crate::KSigningKey): Key derived from `KServiceKey` and the string
//!   "aws4_request".
//!
//! These types have fixed sizes. [`KSecretKey`][crate::KSecretKey] has a const parameter that
//! specifies the maximum secret key size (including the `"AWS4"` prefix), which defaults to 44
//! (the size of AWS-issued secret keys).
//! 
//! ### Signing key functions changed
//! Previously, `get_signing_key_fn()` was used to convert a function into a
//! [Tower `Service`][tower::Service] that could be used to get signing keys. This is now called
//! [`service_for_signing_key_fn()`][crate::service_for_signing_key_fn].
//! 
//! In addition, the signature of the function passed in has changed. Previously, parameters to
//! the function were broken out separately:
//! ```ignore
//! async fn get_signing_key(
//!    kind: SigningKeyKind,
//!    access_key: String,
//!    session_token: Option<String>,
//!    request_date: DateTime<Utc>,
//!    region: String,
//!    service: String)
//! -> Result<(PrincipalActor, SigningKey), SignatureError>
//! ```
//! 
//! These parameters are now encapsulated in the (non-exhaustive)
//! [`GetSigningKeyRequest`][crate::GetSigningKeyRequest] type, and the tuple of
//! `(PrincipalActor, SigningKey)` is now encapsulated in the
//! [`GetSigningKeyResponse`][crate::GetSigningKeyResponse] type. The function signature is now:
//! ```
//! # use scratchstack_aws_signature::{GetSigningKeyRequest, GetSigningKeyResponse};
//! use tower::BoxError;
//! 
//! async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError>
//! # {
//! # Ok(GetSigningKeyResponse::default())
//! # }
//! ```
//! 
//! Both of these types have builder APIs to construct them.
//! 
//! ### Principal types updated
//! This crate uses the [`Principal`][scratchstack_aws_principal::Principal] type from
//! scratchstack_aws_principal v0.4. Previously, the `PrincipalActor` from v0.3 of that crate was
//! used. In v0.4, only actor principals are supported; v0.3 attempted to support both actor and
//! policy principals, but this was riddled with implementation errors.
//! 
//! ### Type-dependencies from other crates exposed
//! This crate now uses types two other crates in its APIs: [`scratchstack_aws_principal`] and
//! [`scratchstack_errors`]. To reduce the possibility of accidentally using a different version
//! of these crates, they are re-exported here under `principal` and `errors` modules, respectively.

use std::str::FromStr;
