//! AWS API request signatures verification routines.
//!
//! This implements the AWS [SigV4](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
//! and [SigV4S3](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html)
//! server-side validation algorithms.
//!
//! **Stability of this module is not guaranteed except for items exposed at the crate root**.
//! The functions and types are subject to change in minor/patch versions. This is exposed for
//! testing purposes only.

use {
    crate::{
        crypto::{hmac_sha256, SHA256_OUTPUT_LEN},
        GetSigningKeyRequest, GetSigningKeyResponse, SignatureError,
    },
    chrono::{DateTime, Duration, Utc},
    derive_builder::Builder,
    log::{debug, trace},
    qualifier_attr::qualifiers,
    scratchstack_aws_principal::{Principal, SessionData},
    std::{
        fmt::{Debug, Formatter, Result as FmtResult},
        future::Future,
    },
    subtle::ConstantTimeEq,
    tower::{BoxError, Service, ServiceExt},
};

/// Algorithm for AWS SigV4
const AWS4_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";

/// String included at the end of the AWS SigV4 credential scope
const AWS4_REQUEST: &str = "aws4_request";

/// Compact ISO8601 format used for the string to sign.
pub(crate) const ISO8601_COMPACT_FORMAT: &str = "%Y%m%dT%H%M%SZ";

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
#[derive(Builder, Clone, Default)]
#[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
#[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
#[builder(derive(Debug))]
pub struct SigV4Authenticator {
    /// The SHA-256 hash of the canonical request.
    canonical_request_sha256: [u8; SHA256_OUTPUT_LEN],

    /// The credential passed into the request, in the form of `keyid/date/region/service/aws4_request`.
    /// The date must reflect that of the request timestamp in `YYYYMMDD` format, not the server's
    /// date. Timestamp validation is performed separately.
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

    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn builder() -> SigV4AuthenticatorBuilder {
        SigV4AuthenticatorBuilder::default()
    }

    /// Retrieve the SHA-256 hash of the canonical request.

    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn canonical_request_sha256(&self) -> [u8; SHA256_OUTPUT_LEN] {
        self.canonical_request_sha256
    }

    /// Retrieve the credential passed into the request, in the form of `keyid/date/region/service/aws4_request`.

    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn credential(&self) -> &str {
        &self.credential
    }

    /// Retrieve the optional session token.

    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }

    /// Retrieve the signature passed into the request.

    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn signature(&self) -> &str {
        &self.signature
    }

    /// Retrieve the timestamp of the request.

    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    #[inline(always)]
    fn request_timestamp(&self) -> DateTime<Utc> {
        self.request_timestamp
    }

    /// Verify the request parameters make sense for the region, service, and specified timestamp.
    /// This must be called successfully before calling [validate_signature][Self::validate_signature].

    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    pub fn prevalidate(
        &self,
        region: &str,
        service: &str,
        server_timestamp: DateTime<Utc>,
        allowed_mismatch: Duration,
    ) -> Result<(), SignatureError> {
        let req_ts = self.request_timestamp();
        let min_ts = server_timestamp.checked_sub_signed(allowed_mismatch).unwrap_or(server_timestamp);
        let max_ts = server_timestamp.checked_add_signed(allowed_mismatch).unwrap_or(server_timestamp);

        // Rule 10: Make sure date isn't expired...
        if req_ts < min_ts {
            trace!("prevalidate: request timestamp {} is before minimum timestamp {}", req_ts, min_ts);
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
            trace!("prevalidate: request timestamp {} is after maximum timestamp {}", req_ts, max_ts);
            return Err(SignatureError::SignatureDoesNotMatch(Some(format!(
                "Signature not yet current: {} is still later than {} ({} + {}.)",
                req_ts.format(ISO8601_COMPACT_FORMAT),
                max_ts.format(ISO8601_COMPACT_FORMAT),
                server_timestamp.format(ISO8601_COMPACT_FORMAT),
                duration_to_string(allowed_mismatch)
            ))));
        }

        // Rule 12: Credential scope must have exactly five elements.
        let credential_parts = self.credential().split('/').collect::<Vec<&str>>();
        if credential_parts.len() != 5 {
            trace!("prevalidate: credential has {} parts, expected 5", credential_parts.len());
            return Err(SignatureError::IncompleteSignature(format!(
                "{} got '{}'",
                MSG_CREDENTIAL_MUST_HAVE_FIVE_PARTS,
                self.credential()
            )));
        }

        let cscope_date = credential_parts[1];
        let cscope_region = credential_parts[2];
        let cscope_service = credential_parts[3];
        let cscope_term = credential_parts[4];

        // Rule 13: Credential scope must be correct for the region/service/date.
        let mut cscope_errors = Vec::new();
        if cscope_region != region {
            trace!("prevalidate: credential region '{}' does not match expected region '{}'", cscope_region, region);
            cscope_errors.push(format!("Credential should be scoped to a valid region, not '{}'.", cscope_region));
        }

        if cscope_service != service {
            trace!(
                "prevalidate: credential service '{}' does not match expected service '{}'",
                cscope_service,
                service
            );
            cscope_errors.push(format!("Credential should be scoped to correct service: '{}'.", service));
        }

        if cscope_term != AWS4_REQUEST {
            trace!(
                "prevalidate: credential terminator '{}' does not match expected terminator '{}'",
                cscope_term,
                AWS4_REQUEST
            );
            cscope_errors.push(format!(
                "Credential should be scoped with a valid terminator: 'aws4_request', not '{}'.",
                cscope_term
            ));
        }

        let expected_cscope_date = req_ts.format("%Y%m%d").to_string();
        if cscope_date != expected_cscope_date {
            trace!(
                "prevalidate: credential date '{}' does not match expected date '{}'",
                cscope_date,
                expected_cscope_date
            );
            cscope_errors.push(format!("Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP: '{}' != '{}', from '{}'.", cscope_date, expected_cscope_date, req_ts.format(ISO8601_COMPACT_FORMAT)));
        }

        if !cscope_errors.is_empty() {
            return Err(SignatureError::SignatureDoesNotMatch(Some(cscope_errors.join(" "))));
        }

        Ok(())
    }

    /// Return the signing key (`kSigning` from the [AWS documentation](https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html))
    /// for the request.

    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    async fn get_signing_key<S, F>(
        &self,
        region: &str,
        service: &str,
        get_signing_key: &mut S,
    ) -> Result<GetSigningKeyResponse, SignatureError>
    where
        S: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError, Future = F> + Send,
        F: Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send,
    {
        let access_key = self.credential().split('/').next().expect("prevalidate must been called first").to_string();

        let req = GetSigningKeyRequest::builder()
            .access_key(access_key)
            .session_token(self.session_token().map(|x| x.to_string()))
            .request_date(self.request_timestamp().date_naive())
            .region(region)
            .service(service)
            .build()
            .expect("All fields set");

        match get_signing_key.oneshot(req).await {
            Ok(key) => {
                trace!("get_signing_key: got signing key");
                Ok(key)
            }
            Err(e) => {
                debug!("get_signing_key: error getting signing key: {}", e);
                match e.downcast::<SignatureError>() {
                    Ok(sig_err) => Err(*sig_err),
                    Err(e) => Err(SignatureError::InternalServiceError(e)),
                }
            }
        }
    }

    /// Return the string to sign for the request.

    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    fn get_string_to_sign(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(
            AWS4_HMAC_SHA256.len() + 1 + ISO8601_UTC_LENGTH + 1 + self.credential().len() + 1 + SHA256_HEX_LENGTH,
        );
        let hashed_canonical_request = hex::encode(self.canonical_request_sha256());

        // Remove the access key from the credential to get the credential scope. This requires that prevalidate() has
        // been called.
        let cscope = self.credential().split_once('/').map(|x| x.1).expect("prevalidate should have been called first");

        result.extend(AWS4_HMAC_SHA256.as_bytes());
        result.push(b'\n');
        result.extend(self.request_timestamp().format(ISO8601_COMPACT_FORMAT).to_string().as_bytes());
        result.push(b'\n');
        result.extend(cscope.as_bytes());
        result.push(b'\n');
        result.extend(hashed_canonical_request.as_bytes());
        result
    }

    /// Validate the request signature.

    #[cfg_attr(any(doc, feature = "unstable"), qualifiers(pub))]
    #[cfg_attr(not(any(doc, feature = "unstable")), qualifiers(pub(crate)))]
    pub async fn validate_signature<S, F>(
        &self,
        region: &str,
        service: &str,
        server_timestamp: DateTime<Utc>,
        allowed_mismatch: Duration,
        get_signing_key: &mut S,
    ) -> Result<SigV4AuthenticatorResponse, SignatureError>
    where
        S: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError, Future = F> + Send,
        F: Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send,
    {
        self.prevalidate(region, service, server_timestamp, allowed_mismatch)?;
        let string_to_sign = self.get_string_to_sign();
        trace!("String to sign:\n{}", String::from_utf8_lossy(string_to_sign.as_ref()));
        let response = self.get_signing_key(region, service, get_signing_key).await?;
        let expected_signature = hex::encode(hmac_sha256(response.signing_key().as_ref(), string_to_sign.as_ref()));
        let expected_signature_bytes = expected_signature.as_bytes();
        let signature_bytes = self.signature().as_bytes();
        let is_equal: bool = signature_bytes.ct_eq(expected_signature_bytes).into();
        if !is_equal {
            trace!("Signature mismatch: expected '{}', got '{}'", expected_signature, self.signature());
            Err(SignatureError::SignatureDoesNotMatch(Some(MSG_REQUEST_SIGNATURE_MISMATCH.to_string())))
        } else {
            Ok(response.into())
        }
    }
}

impl Debug for SigV4Authenticator {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("SigV4Authenticator")
            .field("canonical_request_sha256", &hex::encode(self.canonical_request_sha256()))
            .field("session_token", &self.session_token())
            .field("signature", &self.signature())
            .field("request_timestamp", &self.request_timestamp())
            .finish()
    }
}

impl SigV4AuthenticatorBuilder {
    /// Retrieve the credential passed into the request.
    pub fn get_credential(&self) -> Option<&str> {
        self.credential.as_deref()
    }

    /// Retrieve the signature passed into the request.
    pub fn get_signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }

    /// Retrieve the session token passed into the request.
    pub fn get_session_token(&self) -> Option<&str> {
        self.session_token.as_ref()?.as_deref()
    }
}

/// Upon successful authentication of a signature, this is returned to convey the principal, session data, and possibly
/// policies associated with the request.
///
/// SigV4AuthenticatorResponse structs are immutable. Use [SigV4AuthenticatorResponseBuilder] to construct a new
/// response.
#[derive(Builder, Clone, Debug)]
pub struct SigV4AuthenticatorResponse {
    /// The principal actors of the request.
    #[builder(setter(into), default)]
    principal: Principal,

    /// The session data associated with the principal.
    #[builder(setter(into), default)]
    session_data: SessionData,
}

impl SigV4AuthenticatorResponse {
    /// Create a [SigV4AuthenticatorResponseBuilder] to construct a [SigV4AuthenticatorResponse].
    #[inline]
    pub fn builder() -> SigV4AuthenticatorResponseBuilder {
        SigV4AuthenticatorResponseBuilder::default()
    }

    /// Retrieve the principal actors of the request.
    #[inline]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Retrieve the session data associated with the principal.
    #[inline]
    pub fn session_data(&self) -> &SessionData {
        &self.session_data
    }
}

impl From<GetSigningKeyResponse> for SigV4AuthenticatorResponse {
    fn from(request: GetSigningKeyResponse) -> Self {
        SigV4AuthenticatorResponse {
            principal: request.principal,
            session_data: request.session_data,
        }
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

#[cfg(test)]
mod tests {
    use {
        super::duration_to_string,
        crate::{
            auth::{SigV4Authenticator, SigV4AuthenticatorBuilder, SigV4AuthenticatorResponse},
            crypto::SHA256_OUTPUT_LEN,
            service_for_signing_key_fn, GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, SignatureError,
        },
        chrono::{DateTime, Duration, NaiveDate, NaiveDateTime, NaiveTime, Utc},
        log::LevelFilter,
        scratchstack_aws_principal::{Principal, User},
        std::{error::Error, fs::File, str::FromStr},
        tower::BoxError,
    };

    fn init() {
        let _ = env_logger::builder().is_test(true).filter_level(LevelFilter::Trace).try_init();
    }

    #[test]
    fn test_derived() {
        init();
        let epoch = DateTime::<Utc>::from_timestamp(0, 0).expect("failed to create epoch DateTime");
        let test_time = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2015, 8, 30).expect("failed to create NaiveDate 2015-08-30"),
                NaiveTime::from_hms_opt(12, 36, 0).expect("failed to create NaiveTime 12:36:00"),
            ),
            Utc,
        );
        let auth1: SigV4Authenticator = Default::default();
        assert_eq!(
            auth1.canonical_request_sha256().as_slice(),
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
        );
        assert!(auth1.credential().is_empty());
        assert!(auth1.session_token().is_none());
        assert!(auth1.signature().is_empty());
        assert_eq!(auth1.request_timestamp(), epoch);

        let sha256: [u8; 32] = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
            29, 30, 31,
        ];
        let auth2 = SigV4AuthenticatorBuilder::default()
            .canonical_request_sha256(sha256)
            .credential("AKIA1/20151231/us-east-1/example/aws4_request".to_string())
            .session_token("token".to_string())
            .signature("1234".to_string())
            .request_timestamp(test_time)
            .build()
            .expect("failed to build SigV4Authenticator");

        assert_eq!(
            auth2.canonical_request_sha256().as_slice(),
            &[
                0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                28, 29, 30, 31,
            ]
        );
        assert_eq!(auth2.credential(), "AKIA1/20151231/us-east-1/example/aws4_request");
        assert_eq!(auth2.session_token(), Some("token"));
        assert_eq!(auth2.signature(), "1234");
        assert_eq!(auth2.request_timestamp(), test_time);

        assert_eq!(auth2.credential(), auth2.clone().credential());
        let _ = format!("{:?}", auth2);
    }

    async fn get_signing_key(request: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
        if let Some(token) = request.session_token() {
            match token {
                "internal-service-error" => {
                    return Err("internal service error".into());
                }
                "invalid" => {
                    return Err(Box::new(SignatureError::InvalidClientTokenId(
                        "The security token included in the request is invalid".to_string(),
                    )))
                }
                "io-error" => {
                    let e = File::open("/00Hi1i6V4qad5nF/6KPlcyW4H9miTOD02meLgTaV09O2UToMPTE9j6sNmHZ/08EzM4qOs8bYOINWJ9RheQVadpgixRTh0VjcwpVPoo1Rh4gNAJhS4cj/this-path/does//not/exist").unwrap_err();
                    return Err(Box::new(SignatureError::from(e)));
                }
                "expired" => {
                    return Err(Box::new(SignatureError::ExpiredToken(
                        "The security token included in the request is expired".to_string(),
                    )))
                }
                _ => (),
            }
        }

        match request.access_key() {
            "AKIDEXAMPLE" => {
                let principal = Principal::from(vec![User::new("aws", "123456789012", "/", "test")
                    .expect("failed to create test User")
                    .into()]);
                let k_secret = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
                    .expect("failed to parse KSecretKey from string");
                let k_signing = k_secret.to_ksigning(request.request_date(), request.region(), request.service());

                let response = GetSigningKeyResponse::builder()
                    .principal(principal)
                    .signing_key(k_signing)
                    .build()
                    .expect("failed to build GetSigningKeyResponse");
                Ok(response)
            }
            _ => Err(Box::new(SignatureError::InvalidClientTokenId(
                "The AWS access key provided does not exist in our records".to_string(),
            ))),
        }
    }

    #[tokio::test]
    async fn test_error_ordering() {
        init();

        // Test that the error ordering is correct.
        let creq_sha256: [u8; SHA256_OUTPUT_LEN] = [0; SHA256_OUTPUT_LEN];
        let test_timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2015, 8, 30).expect("failed to create NaiveDate 2015-08-30"),
                NaiveTime::from_hms_opt(12, 36, 0).expect("failed to create NaiveTime 12:36:00"),
            ),
            Utc,
        );
        let outdated_timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2015, 8, 30).expect("failed to create NaiveDate 2015-08-30"),
                NaiveTime::from_hms_opt(12, 20, 59).expect("failed to create NaiveTime 12:20:59"),
            ),
            Utc,
        );
        let future_timestamp = DateTime::<Utc>::from_naive_utc_and_offset(
            NaiveDateTime::new(
                NaiveDate::from_ymd_opt(2015, 8, 30).expect("failed to create NaiveDate 2015-08-30"),
                NaiveTime::from_hms_opt(12, 51, 1).expect("failed to create NaiveTime 12:51:01"),
            ),
            Utc,
        );
        let get_signing_key_svc = service_for_signing_key_fn(get_signing_key);
        let mismatch = Duration::minutes(15);

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20130101/wrong-region/wrong-service".to_string())
            .session_token("expired")
            .signature("invalid".to_string())
            .request_timestamp(outdated_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let e = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap_err();

        if let SignatureError::SignatureDoesNotMatch(ref msg) = e {
            assert_eq!(
                msg.as_ref().expect("expected SignatureDoesNotMatch message present"),
                "Signature expired: 20150830T122059Z is now earlier than 20150830T122100Z (20150830T123600Z - 15 min.)"
            );
            assert_eq!(e.error_code(), "SignatureDoesNotMatch");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20130101/wrong-region/wrong-service".to_string())
            .session_token("expired")
            .signature("invalid".to_string())
            .request_timestamp(future_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let e = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap_err();

        if let SignatureError::SignatureDoesNotMatch(ref msg) = e {
            assert_eq!(
                msg.as_ref().expect("expected SignatureDoesNotMatch message present"),
                "Signature not yet current: 20150830T125101Z is still later than 20150830T125100Z (20150830T123600Z + 15 min.)"
            );
            assert_eq!(e.error_code(), "SignatureDoesNotMatch");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20130101/wrong-region/wrong-service".to_string())
            .session_token("expired")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let e = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap_err();

        if let SignatureError::IncompleteSignature(_) = e {
            assert_eq!(
                e.to_string(),
                "Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term, got 'AKIDFOO/20130101/wrong-region/wrong-service'"
            );
            assert_eq!(e.error_code(), "IncompleteSignature");
            assert_eq!(e.http_status(), 400);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20130101/wrong-region/wrong-service/aws5_request".to_string())
            .session_token("expired")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let e = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap_err();

        if let SignatureError::SignatureDoesNotMatch(_) = e {
            assert_eq!(
                e.to_string(),
                "Credential should be scoped to a valid region, not 'wrong-region'. Credential should be scoped to correct service: 'example'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'. Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP: '20130101' != '20150830', from '20150830T123600Z'."
            );
            assert_eq!(e.error_code(), "SignatureDoesNotMatch");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("invalid")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let e = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap_err();

        if let SignatureError::InvalidClientTokenId(_) = e {
            assert_eq!(e.to_string(), "The security token included in the request is invalid");
            assert_eq!(e.error_code(), "InvalidClientTokenId");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("expired")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let e = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap_err();

        if let SignatureError::ExpiredToken(_) = e {
            assert_eq!(e.to_string(), "The security token included in the request is expired");
            assert_eq!(e.error_code(), "ExpiredToken");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("internal-service-error")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let e = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap_err();

        if let SignatureError::InternalServiceError(ref err) = e {
            assert_eq!(format!("{:?}", err), r#""internal service error""#);
            assert_eq!(e.to_string(), "internal service error");
            assert_eq!(e.error_code(), "InternalFailure");
            assert_eq!(e.http_status(), 500);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("io-error")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let e = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap_err();

        if let SignatureError::IO(_) = e {
            let e_string = e.to_string();
            assert!(
                e_string.contains("No such file or directory")
                    || e_string.contains("The system cannot find the file specified"),
                "Error message: {:#?}",
                e_string
            );
            assert_eq!(e.error_code(), "InternalFailure");
            assert_eq!(e.http_status(), 500);
            assert!(e.source().is_some());
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDFOO/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("ok")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let e = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap_err();

        if let SignatureError::InvalidClientTokenId(_) = e {
            assert_eq!(e.to_string(), "The AWS access key provided does not exist in our records");
            assert_eq!(e.error_code(), "InvalidClientTokenId");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDEXAMPLE/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("ok")
            .signature("invalid".to_string())
            .request_timestamp(test_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let e = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap_err();

        if let SignatureError::SignatureDoesNotMatch(_) = e {
            assert_eq!(e.to_string(), "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.");
            assert_eq!(e.error_code(), "SignatureDoesNotMatch");
            assert_eq!(e.http_status(), 403);
        } else {
            panic!("Unexpected error: {:?}", e);
        }

        let auth = SigV4Authenticator::builder()
            .canonical_request_sha256(creq_sha256)
            .credential("AKIDEXAMPLE/20150830/us-east-1/example/aws4_request".to_string())
            .session_token("ok")
            .signature("88bf1ccb1e3e4df7bb2ed6d89bcd8558d6770845007e1a5c392ac9edce0d5deb".to_string())
            .request_timestamp(test_timestamp)
            .build()
            .expect("failed to build SigV4Authenticator");

        let _ = auth
            .validate_signature("us-east-1", "example", test_timestamp, mismatch, &mut get_signing_key_svc.clone())
            .await
            .unwrap();
    }

    #[test]
    fn test_duration_formatting() {
        init();
        assert_eq!(duration_to_string(Duration::seconds(32)).as_str(), "32 sec");
        assert_eq!(duration_to_string(Duration::seconds(60)).as_str(), "1 min");
        assert_eq!(duration_to_string(Duration::seconds(61)).as_str(), "61 sec");
        assert_eq!(duration_to_string(Duration::seconds(600)).as_str(), "10 min");
    }

    #[test_log::test]
    fn test_response_builder() {
        let response =
            SigV4AuthenticatorResponse::builder().build().expect("failed to build SigV4AuthenticatorResponse");
        assert!(response.principal().is_empty());
        assert!(response.session_data().is_empty());

        let response2 = response.clone();
        assert_eq!(format!("{:?}", response), format!("{:?}", response2));
    }
}
