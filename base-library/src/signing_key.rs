use {
    crate::crypto::hmac_sha256,
    chrono::{Date, Utc},
    ring::digest::SHA256_OUTPUT_LEN,
    scratchstack_aws_principal::Principal,
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        future::Future,
    },
    tower::{service_fn, util::ServiceFn, BoxError},
};

/// String included at the end of the AWS SigV4 credential scope
const AWS4_REQUEST: &str = "aws4_request";

/// A raw AWS secret key (`kSecret`).
#[derive(Clone, PartialEq, Eq)]
pub struct KSecretKey {
    /// The secret key prefixed with AWS4.
    prefixed_key: Vec<u8>,
}

/// The `kDate` key: an AWS secret key, prefixed with "AWS4", then HMAC-SHA256 hashed with the date.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KDateKey {
    /// The raw key.
    key: [u8; SHA256_OUTPUT_LEN],
}

/// The `kRegion` key: an AWS `kDate` key, HMAC-SHA256 hashed with the region.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KRegionKey {
    /// The raw key.
    key: [u8; SHA256_OUTPUT_LEN],
}

/// The `kService` key: an AWS `kRegion` key, HMAC-SHA256 hashed with the service.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KServiceKey {
    /// The raw key.
    key: [u8; SHA256_OUTPUT_LEN],
}

/// The `kSigning` key: an AWS `kService` key, HMAC-SHA256 hashed with the "aws4_request" string.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KSigningKey {
    /// The raw key.
    key: [u8; SHA256_OUTPUT_LEN],
}

impl AsRef<[u8]> for KSecretKey {
    fn as_ref(&self) -> &[u8] {
        // Remove the AWS4 prefix
        &self.prefixed_key.as_slice()[4..]
    }
}

impl AsRef<[u8; SHA256_OUTPUT_LEN]> for KDateKey {
    fn as_ref(&self) -> &[u8; SHA256_OUTPUT_LEN] {
        &self.key
    }
}

impl AsRef<[u8; SHA256_OUTPUT_LEN]> for KRegionKey {
    fn as_ref(&self) -> &[u8; SHA256_OUTPUT_LEN] {
        &self.key
    }
}

impl AsRef<[u8; SHA256_OUTPUT_LEN]> for KServiceKey {
    fn as_ref(&self) -> &[u8; SHA256_OUTPUT_LEN] {
        &self.key
    }
}

impl AsRef<[u8; SHA256_OUTPUT_LEN]> for KSigningKey {
    fn as_ref(&self) -> &[u8; SHA256_OUTPUT_LEN] {
        &self.key
    }
}

impl Debug for KSecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KSecretKey")
    }
}

impl Debug for KDateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KDateKey")
    }
}

impl Debug for KRegionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KRegionKey")
    }
}

impl Debug for KServiceKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KServiceKey")
    }
}

impl Debug for KSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KSigningKey")
    }
}

impl Display for KSecretKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KSecretKey")
    }
}

impl Display for KDateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KDateKey")
    }
}

impl Display for KRegionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KRegionKey")
    }
}

impl Display for KServiceKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KServiceKey")
    }
}

impl Display for KSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("KSigningKey")
    }
}

impl KSecretKey {
    /// Create a new `KSecretKey` from a raw AWS secret key.
    pub fn from_str(raw: &str) -> Self {
        let mut prefixed_key = Vec::with_capacity(4 + raw.len());
        prefixed_key.extend_from_slice(b"AWS4");
        prefixed_key.extend_from_slice(raw.as_bytes());
        Self {
            prefixed_key,
        }
    }

    /// Create a new `KDateKey` from this `KSecretKey` and a date.
    pub fn to_kdate(&self, date: Date<Utc>) -> KDateKey {
        let date = date.format("%Y%m%d").to_string();
        let date = date.as_bytes();
        let key = hmac_sha256(self.prefixed_key.as_slice(), date);
        let mut key_bytes = [0; SHA256_OUTPUT_LEN];
        key_bytes.copy_from_slice(key.as_ref());
        KDateKey {
            key: key_bytes,
        }
    }

    /// Creeate a new `KRegionKey` from this `KSecretKey`, a date, and a region.
    pub fn to_kregion(&self, date: Date<Utc>, region: &str) -> KRegionKey {
        self.to_kdate(date).to_kregion(region)
    }

    /// Creeate a new `KServiceKey` from this `KSecretKey`, a date, a region, and a service.
    pub fn to_kservice(&self, date: Date<Utc>, region: &str, service: &str) -> KServiceKey {
        self.to_kdate(date).to_kservice(region, service)
    }

    /// Creeate a new `KSigningKey` from this `KSecretKey`, a date, a region, and a service.
    pub fn to_ksigning(&self, date: Date<Utc>, region: &str, service: &str) -> KSigningKey {
        self.to_kdate(date).to_ksigning(region, service)
    }
}

impl KDateKey {
    /// Create a new `KRegionKey` from this `KDateKey` and a region.
    pub fn to_kregion(&self, region: &str) -> KRegionKey {
        let region = region.as_bytes();
        let key = hmac_sha256(self.key.as_slice(), region);
        let mut key_bytes = [0; SHA256_OUTPUT_LEN];
        key_bytes.copy_from_slice(key.as_ref());
        KRegionKey {
            key: key_bytes,
        }
    }

    /// Create a new `KServiceKey` from this `KDateKey`, a region, and a service.
    pub fn to_kservice(&self, region: &str, service: &str) -> KServiceKey {
        self.to_kregion(region).to_kservice(service)
    }

    /// Create a new `KSigningKey` from this `KDateKey`, a region, and a service.
    pub fn to_ksigning(&self, region: &str, service: &str) -> KSigningKey {
        self.to_kregion(region).to_ksigning(service)
    }
}

impl KRegionKey {
    /// Create a new `KServiceKey` from this `KRegionKey` and a service.
    pub fn to_kservice(&self, service: &str) -> KServiceKey {
        let service = service.as_bytes();
        let key = hmac_sha256(self.key.as_slice(), service);
        let mut key_bytes = [0; SHA256_OUTPUT_LEN];
        key_bytes.copy_from_slice(key.as_ref());
        KServiceKey {
            key: key_bytes,
        }
    }

    /// Create a new `KSigningKey` from this `KRegionKey` and a service.
    pub fn to_ksigning(&self, service: &str) -> KSigningKey {
        self.to_kservice(service).to_ksigning()
    }
}

impl KServiceKey {
    /// Create a new `KSigningKey` from this `KServiceKey`.
    pub fn to_ksigning(&self) -> KSigningKey {
        let key = hmac_sha256(self.key.as_slice(), AWS4_REQUEST.as_bytes());
        let mut key_bytes = [0; SHA256_OUTPUT_LEN];
        key_bytes.copy_from_slice(key.as_ref());
        KSigningKey {
            key: key_bytes,
        }
    }
}

/// A request for a signing key of a given kind for the specified request.
pub struct GetSigningKeyRequest {
    pub access_key: String,
    pub session_token: Option<String>,
    pub request_date: Date<Utc>,
    pub region: String,
    pub service: String,
}

// A trait alias that describes how we obtain a signing key of a given type given a request. If you need to encapsulate
// additional data (e.g. a database connection) to look up a key, use this to implement a struct.
//
// This requires the trait_alias feature to be stabilized and is commented out until then.
// https://github.com/rust-lang/rust/issues/41517
//
// I find trait bounds annoying since they have to be repeated everywhere.
//
// pub trait GetSigningKey<F> = Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError> + Send + 'static;

/// Create a Service that wraps a function that can produce a signing key.
pub fn service_for_signing_key_fn<F, Fut>(f: F) -> ServiceFn<F>
where
    F: FnOnce(GetSigningKeyRequest) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(Principal, KSigningKey), BoxError>> + Send + 'static,
{
    service_fn(f)
}
