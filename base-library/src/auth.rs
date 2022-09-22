//! AWS API request signatures verification routines.
//!
//! This is essentially the server-side complement of [rusoto_signature](https://crates.io/crates/rusoto_signature)
//! but follows the implementation of [python-aws-sig](https://github.com/dacut/python-aws-sig).
//!
//! This implements the AWS [SigV4](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
//! and [SigV4S3](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html)
//! algorithms.
//!

use {
    crate::{crypto::hmac_sha256, GetSigningKeyRequest, KSigningKey, SignatureError},
    chrono::{DateTime, Duration, Utc},
    derive_builder::Builder,
    log::trace,
    ring::digest::SHA256_OUTPUT_LEN,
    scratchstack_aws_principal::Principal,
    std::future::Future,
    subtle::ConstantTimeEq,
    tower::{BoxError, Service, ServiceExt},
};

/// Algorithm for AWS SigV4
const AWS4_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";

/// String included at the end of the AWS SigV4 credential scope
const AWS4_REQUEST: &str = "aws4_request";

/// Compact ISO8601 format used for the string to sign.
const ISO8601_COMPACT_FORMAT: &str = "%Y%m%dT%H%M%SZ";

/// Length of an ISO8601 date string in the UTC time zone.
const ISO8601_UTC_LENGTH: usize = 16;

/// Error message: `"Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term,"`
const MSG_CREDENTIAL_MUST_HAVE_FIVE_PARTS: &str =
    "Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term,";

/// Error message: `"The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details."`
const MSG_REQUEST_SIGNATURE_MISMATCH: &str = "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.";

/// SHA-256 of an empty string.
const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Length of a SHA-256 hex string.
const SHA256_HEX_LENGTH: usize = SHA256_EMPTY.len();

/// Low-level structure for performing AWS SigV4 authentication after a canonical request has been generated.
#[derive(Builder, Clone, Debug, Default)]
#[builder(derive(Debug))]
pub struct SigV4Authenticator {
    /// The SHA-256 hash of the canonical request.
    canonical_request_sha256: [u8; SHA256_OUTPUT_LEN],

    /// The credential passed into the request, in the form of `keyid/date/region/service/aws4_request`.
    /// This is allowed to be invalid upon creation since the validation of the credential is performed _after_ the
    /// validation of the request timestamp.
    credential: String,

    /// The optional session token.
    #[builder(setter(into, strip_option), default)]
    session_token: Option<String>,

    /// The signature passed into the request.
    signature: String,

    /// The timestamp of the request, from either `X-Amz-Date` query string/header or the `Date` header.
    request_timestamp: DateTime<Utc>,
}

impl SigV4Authenticator {
    /// Create a builder for `SigV4Authenticator`.
    pub fn builder() -> SigV4AuthenticatorBuilder {
        SigV4AuthenticatorBuilder::default()
    }

    /// Retrieve the SHA-256 hash of the canonical request.
    #[inline]
    pub fn canonical_request_sha256(&self) -> [u8; SHA256_OUTPUT_LEN] {
        self.canonical_request_sha256
    }

    /// Retrieve the credential passed into the request, in the form of `keyid/date/region/service/aws4_request`.
    #[inline]
    pub fn credential(&self) -> &str {
        &self.credential
    }

    /// Retrieve the optional session token.
    #[inline]
    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }

    /// Retrieve the signature passed into the request.
    #[inline]
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Retrieve the timestamp of the request.
    #[inline]
    pub fn request_timestamp(&self) -> DateTime<Utc> {
        self.request_timestamp
    }

    /// Verify the request parameters make sense for the region, service, and specified timestamp.
    /// This must be called successfully before calling [validate_signature].
    fn prevalidate(
        &self,
        region: &str,
        service: &str,
        server_timestamp: DateTime<Utc>,
        allowed_mismatch: Duration,
    ) -> Result<(), SignatureError> {
        let req_ts = self.request_timestamp;
        let min_ts = server_timestamp.checked_sub_signed(allowed_mismatch).unwrap_or(server_timestamp);
        let max_ts = server_timestamp.checked_add_signed(allowed_mismatch).unwrap_or(server_timestamp);

        // Rule 10: Make sure date isn't expired...
        if req_ts < min_ts {
            return Err(SignatureError::SignatureDoesNotMatch(Some(format!(
                "Signature expired: {} is now earlier than {} ({} - {}.)",
                req_ts.format(ISO8601_COMPACT_FORMAT),
                min_ts.format(ISO8601_COMPACT_FORMAT),
                server_timestamp.format(ISO8601_COMPACT_FORMAT),
                duration_to_string(allowed_mismatch)
            ))));
        }

        // Rule 11: ... or too far into the future.
        if req_ts > max_ts {
            return Err(SignatureError::SignatureDoesNotMatch(Some(format!(
                "Signature expired: {} is now later than {} ({} + {}.)",
                req_ts.format(ISO8601_COMPACT_FORMAT),
                max_ts.format(ISO8601_COMPACT_FORMAT),
                server_timestamp.format(ISO8601_COMPACT_FORMAT),
                duration_to_string(allowed_mismatch)
            ))));
        }

        // Rule 12: Credential scope must have exactly five elements.
        let credential_parts = self.credential.split('/').collect::<Vec<&str>>();
        if credential_parts.len() != 5 {
            return Err(SignatureError::IncompleteSignature(format!(
                "{} got '{}'",
                MSG_CREDENTIAL_MUST_HAVE_FIVE_PARTS, self.credential
            )));
        }

        let cscope_date = credential_parts[1];
        let cscope_region = credential_parts[2];
        let cscope_service = credential_parts[3];
        let cscope_term = credential_parts[4];

        // Rule 13: Credential scope must be correct for the region/service/date.
        let mut cscope_errors = Vec::new();
        if cscope_region != region {
            cscope_errors.push(format!("Credential should be scoped to a valid region not '{}'", region));
        }

        if cscope_service != service {
            cscope_errors.push(format!("Credential should be scoped to correct service: '{}'", service));
        }

        if cscope_term != AWS4_REQUEST {
            cscope_errors.push(format!(
                "Credential should be scoped with a valid terminator: 'aws4_request', not '{}'",
                cscope_term
            ));
        }

        let expected_cscope_date = req_ts.format("%Y%m%d").to_string();
        if cscope_date != expected_cscope_date {
            cscope_errors.push(format!("Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP: '{}' != '{}', from '{}'", cscope_date, expected_cscope_date, req_ts.format(ISO8601_COMPACT_FORMAT)));
        }

        if !cscope_errors.is_empty() {
            return Err(SignatureError::SignatureDoesNotMatch(Some(cscope_errors.join(" "))));
        }

        Ok(())
    }

    /// Return the signing key (`kSigning` from the [AWS documentation](https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html))
    /// for the re
    async fn get_signing_key<S, F>(
        &self,
        region: &str,
        service: &str,
        get_signing_key: &mut S,
    ) -> Result<(Principal, KSigningKey), SignatureError>
    where
        S: Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError, Future = F> + Send,
        F: Future<Output = Result<(Principal, KSigningKey), BoxError>> + Send,
    {
        let access_key = self.credential.split('/').next().expect("prevalidate must been called first").to_string();

        let req = GetSigningKeyRequest {
            access_key,
            session_token: self.session_token.clone(),
            request_date: self.request_timestamp.date(),
            region: region.to_string(),
            service: service.to_string(),
        };

        match get_signing_key.ready().await?.call(req).await {
            Ok(key) => Ok(key),
            Err(e) => match e.downcast::<SignatureError>() {
                Ok(sig_err) => Err(*sig_err),
                Err(e) => Err(SignatureError::InternalServiceError(e)),
            },
        }
    }

    pub(crate) fn get_string_to_sign(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            AWS4_HMAC_SHA256.len() + 1 + ISO8601_UTC_LENGTH + 1 + self.credential.len() + 1 + SHA256_HEX_LENGTH,
        );
        let hashed_canonical_request = hex::encode(self.canonical_request_sha256);

        // Remove the access key from the credential to get the credential scope. This requires that prevalidate() has
        // been called.
        let cscope = self.credential.splitn(2, '/').nth(1).expect("prevalidate should have been called first");

        result.extend(AWS4_HMAC_SHA256.as_bytes());
        result.push(b'\n');
        result.extend(self.request_timestamp.format(ISO8601_COMPACT_FORMAT).to_string().as_bytes());
        result.push(b'\n');
        result.extend(cscope.as_bytes());
        result.push(b'\n');
        result.extend(hashed_canonical_request.as_bytes());
        result
    }

    /// Validate the request signature.
    pub async fn validate_signature<S, F>(
        &self,
        region: &str,
        service: &str,
        server_timestamp: DateTime<Utc>,
        allowed_mismatch: Duration,
        get_signing_key: &mut S,
    ) -> Result<Principal, SignatureError>
    where
        S: Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError, Future = F> + Send,
        F: Future<Output = Result<(Principal, KSigningKey), BoxError>> + Send,
    {
        self.prevalidate(region, service, server_timestamp, allowed_mismatch)?;
        let string_to_sign = self.get_string_to_sign();
        trace!("String to sign: {:?}", String::from_utf8_lossy(string_to_sign.as_ref()));
        let (principal, signing_key) = self.get_signing_key(region, service, get_signing_key).await?;
        let expected_signature = hex::encode(hmac_sha256(signing_key.as_ref(), string_to_sign.as_ref()));
        let expected_signature_bytes = expected_signature.as_bytes();
        let signature_bytes = self.signature.as_bytes();
        let is_equal: bool = signature_bytes.ct_eq(expected_signature_bytes).into();
        if !is_equal {
            trace!("Signature mismatch: expected '{}', got '{}'", expected_signature, self.signature);
            Err(SignatureError::SignatureDoesNotMatch(Some(MSG_REQUEST_SIGNATURE_MISMATCH.to_string())))
        } else {
            Ok(principal)
        }
    }
}

#[allow(dead_code)] // used in tests
impl SigV4AuthenticatorBuilder {
    pub(crate) fn get_credential(&self) -> &Option<String> {
        &self.credential
    }

    pub(crate) fn get_signature(&self) -> &Option<String> {
        &self.signature
    }

    pub(crate) fn get_session_token(&self) -> &Option<Option<String>> {
        &self.session_token
    }

    pub(crate) fn get_request_timestamp(&self) -> &Option<DateTime<Utc>> {
        &self.request_timestamp
    }
}

fn duration_to_string(duration: Duration) -> String {
    let secs = duration.num_seconds();
    if secs % 60 == 0 {
        format!("{} min", duration.num_minutes())
    } else {
        format!("{} sec", secs)
    }
}
