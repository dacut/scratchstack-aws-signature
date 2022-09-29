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
#[derive(Clone, Debug)]
pub struct GetSigningKeyRequest {
    pub access_key: String,
    pub session_token: Option<String>,
    pub request_date: Date<Utc>,
    pub region: String,
    pub service: String,
}

/// A response from the signing key provider.
#[derive(Clone, Debug)]
pub struct GetSigningKeyResponse {
    pub signing_key: KSigningKey,
    pub principal: Principal,
}

impl Default for GetSigningKeyResponse {
    fn default() -> Self {
        Self {
            signing_key: KSigningKey {
                key: [0; SHA256_OUTPUT_LEN],
            },
            principal: Principal::new(vec![]),
        }
    }
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
    Fut: Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send + 'static,
{
    service_fn(f)
}

#[cfg(test)]
mod tests {
    use {
        crate::{GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey},
        chrono::{Date, NaiveDate, Utc},
        scratchstack_aws_principal::{AssumedRole, Principal},
    };

    #[test_log::test]
    fn test_signing_key_derived() {
        let date = Date::from_utc(NaiveDate::from_ymd(2015, 8, 30), Utc);

        let ksecret1a = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let ksecret1b = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let ksecret2 = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCZEXAMPLEKEY");

        assert_eq!(ksecret1a, ksecret1b);
        assert_eq!(ksecret1a, ksecret1a.clone());
        assert_ne!(ksecret1a, ksecret2);
        assert_eq!(format!("{:?}", ksecret1a).as_str(), "KSecretKey");
        assert_eq!(format!("{}", ksecret1a).as_str(), "KSecretKey");
        assert_eq!(ksecret1a.as_ref(), b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");

        let kdate1a = ksecret1a.to_kdate(date);
        let kdate1b = ksecret1b.to_kdate(date);
        let kdate2 = ksecret2.to_kdate(date);
        assert_eq!(
            kdate1a.as_ref(),
            &[
                0x01u8, 0x38u8, 0xc7u8, 0xa6u8, 0xcbu8, 0xd6u8, 0x0au8, 0xa7u8, 0x27u8, 0xb2u8, 0xf6u8, 0x53u8, 0xa5u8,
                0x22u8, 0x56u8, 0x74u8, 0x39u8, 0xdfu8, 0xb9u8, 0xf3u8, 0xe7u8, 0x2bu8, 0x21u8, 0xf9u8, 0xb2u8, 0x59u8,
                0x41u8, 0xa4u8, 0x2fu8, 0x04u8, 0xa7u8, 0xcdu8
            ]
        );
        assert_eq!(kdate1a, kdate1b);
        assert_eq!(kdate1a, kdate1a.clone());
        assert_ne!(kdate1a, kdate2);
        assert_eq!(format!("{:?}", kdate1a).as_str(), "KDateKey");
        assert_eq!(format!("{}", kdate1a).as_str(), "KDateKey");

        let kregion1a = kdate1a.to_kregion("us-east-1");
        let kregion1b = kdate1b.to_kregion("us-east-1");
        let kregion2 = kdate2.to_kregion("us-east-1");
        assert_eq!(
            kregion1a.as_ref(),
            &[
                0xf3u8, 0x3du8, 0x58u8, 0x08u8, 0x50u8, 0x4bu8, 0xf3u8, 0x48u8, 0x12u8, 0xe5u8, 0xfau8, 0xdeu8, 0x63u8,
                0x30u8, 0x8bu8, 0x42u8, 0x4bu8, 0x24u8, 0x4cu8, 0x59u8, 0x18u8, 0x9bu8, 0xe2u8, 0xa5u8, 0x91u8, 0xddu8,
                0x22u8, 0x82u8, 0xc7u8, 0xcbu8, 0x56u8, 0x3fu8
            ]
        );
        assert_eq!(kregion1a, kregion1b);
        assert_eq!(kregion1a, kregion1a.clone());
        assert_ne!(kregion1a, kregion2);
        assert_eq!(format!("{:?}", kregion1a).as_str(), "KRegionKey");
        assert_eq!(format!("{}", kregion1a).as_str(), "KRegionKey");

        let kservice1a = kregion1a.to_kservice("example");
        let kservice1b = kregion1b.to_kservice("example");
        let kservice2 = kregion2.to_kservice("example");
        assert_eq!(
            kservice1a.as_ref(),
            &[
                0xc6u8, 0x0cu8, 0xc4u8, 0xb1u8, 0xd0u8, 0x34u8, 0xc7u8, 0x57u8, 0x34u8, 0x8fu8, 0x2cu8, 0x67u8, 0x30u8,
                0x04u8, 0xc1u8, 0x89u8, 0x08u8, 0xbbu8, 0xa9u8, 0xa4u8, 0x6fu8, 0xa1u8, 0xdbu8, 0x87u8, 0xa9u8, 0x83u8,
                0x50u8, 0xf2u8, 0x7eu8, 0x7bu8, 0x2du8, 0xf6u8
            ]
        );
        assert_eq!(kservice1a, kservice1b);
        assert_eq!(kservice1a, kservice1a.clone());
        assert_ne!(kservice1a, kservice2);
        assert_eq!(format!("{:?}", kservice1a).as_str(), "KServiceKey");
        assert_eq!(format!("{}", kservice1a).as_str(), "KServiceKey");

        let ksigning1a = kservice1a.to_ksigning();
        let ksigning1b = kservice1b.to_ksigning();
        let ksigning2 = kservice2.to_ksigning();
        assert_eq!(
            ksigning1a.as_ref(),
            &[
                0x43u8, 0x1cu8, 0xc9u8, 0xefu8, 0x58u8, 0x76u8, 0x28u8, 0x7du8, 0xbbu8, 0x92u8, 0x5du8, 0x4bu8, 0xa4u8,
                0x62u8, 0x9fu8, 0x45u8, 0x90u8, 0x02u8, 0xadu8, 0x1du8, 0x26u8, 0xb7u8, 0xc7u8, 0x51u8, 0x60u8, 0x1bu8,
                0xb2u8, 0x04u8, 0xe1u8, 0x17u8, 0x18u8, 0xb8u8
            ]
        );
        assert_eq!(ksigning1a, ksigning1b);
        assert_eq!(ksigning1a, ksigning1a.clone());
        assert_ne!(ksigning1a, ksigning2);
        assert_eq!(format!("{:?}", ksigning1a).as_str(), "KSigningKey");
        assert_eq!(format!("{}", ksigning1a).as_str(), "KSigningKey");

        assert_eq!(ksecret1a.to_kregion(date, "us-east-1"), kregion1a);
        assert_eq!(ksecret1a.to_kservice(date, "us-east-1", "example"), kservice1a);
        assert_eq!(ksecret1a.to_ksigning(date, "us-east-1", "example"), ksigning1a);

        assert_eq!(kdate1a.to_kservice("us-east-1", "example"), kservice1a);
        assert_eq!(kdate1a.to_ksigning("us-east-1", "example"), ksigning1a);

        assert_eq!(kregion1a.to_kservice("example"), kservice1a);
    }

    #[test_log::test]
    fn test_gsk_derived() {
        let date = Date::from_utc(NaiveDate::from_ymd(2015, 8, 30), Utc);

        let gsk_req1a = GetSigningKeyRequest {
            access_key: "AKIDEXAMPLE".to_string(),
            session_token: Some("token".to_string()),
            request_date: date,
            region: "us-east-1".to_string(),
            service: "example".to_string(),
        };

        // Make sure we can debug print the request.
        let _ = format!("{:?}", gsk_req1a);

        // Make sure clones are field-by-field equal.
        let gsk_req1b = gsk_req1a.clone();
        assert_eq!(gsk_req1a.access_key, gsk_req1b.access_key);
        assert_eq!(gsk_req1a.session_token, gsk_req1b.session_token);
        assert_eq!(gsk_req1a.request_date, gsk_req1b.request_date);
        assert_eq!(gsk_req1a.region, gsk_req1b.region);
        assert_eq!(gsk_req1a.service, gsk_req1b.service);

        let gsk_resp1a = GetSigningKeyResponse {
            signing_key: KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").to_ksigning(
                date,
                "us-east-1",
                "example",
            ),
            principal: Principal::new(vec![AssumedRole::new("aws", "123456789012", "role", "session").unwrap().into()]),
        };

        // Make sure we can debug print the response.
        let _ = format!("{:?}", gsk_resp1a);

        // Make sure clones are field-by-field equal.
        let gsk_resp1b = gsk_resp1a.clone();
        assert_eq!(gsk_resp1a.signing_key, gsk_resp1b.signing_key);
        assert_eq!(gsk_resp1a.principal, gsk_resp1b.principal);
    }

    #[test_log::test]
    fn test_gsk_reponse_derived() {
        let response: GetSigningKeyResponse = Default::default();
        assert_eq!(response.signing_key.as_ref(), &[0u8; 32]);
    }
}
