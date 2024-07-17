//! Migrating from 0.10 to 0.11
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
//! These types have fixed sizes. KSecretKey has a const parameter that specifies the maximum secret
//! key size (including the `"AWS4"` prefix), which defaults to 44 (the size of AWS-issued secret
//! keys).

use std::str::FromStr;
