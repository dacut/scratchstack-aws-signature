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
#[derive(Builder, Clone, Default)]
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

        // Rule 9: Make sure date isn't expired...
        if req_ts < min_ts {
            return Err(SignatureError::SignatureDoesNotMatch(Some(format!(
                "Signature expired: {} is now earlier than {} ({} - {}.)",
                req_ts.format(ISO8601_COMPACT_FORMAT),
                min_ts.format(ISO8601_COMPACT_FORMAT),
                server_timestamp.format(ISO8601_COMPACT_FORMAT),
                duration_to_string(allowed_mismatch)
            ))));
        }

        // Rule 10: ... or too far into the future.
        if req_ts > max_ts {
            return Err(SignatureError::SignatureDoesNotMatch(Some(format!(
                "Signature expired: {} is now later than {} ({} + {}.)",
                req_ts.format(ISO8601_COMPACT_FORMAT),
                max_ts.format(ISO8601_COMPACT_FORMAT),
                server_timestamp.format(ISO8601_COMPACT_FORMAT),
                duration_to_string(allowed_mismatch)
            ))));
        }

        // Rule 11: Credential scope must have exactly five elements.
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

        // Rule 12: Credential scope must be correct for the region/service/date.
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

fn duration_to_string(duration: Duration) -> String {
    let secs = duration.num_seconds();
    if secs % 60 == 0 {
        format!("{} min", duration.num_minutes())
    } else {
        format!("{} sec", secs)
    }
}

// /// Return the expected signature for a request.
// pub fn sigv4_get_expected_signature<A1, A2>(
//     req: &Request,
//     signing_key: &SigningKey,
//     region: A1,
//     service: A2,
// ) -> Result<String, SignatureError>
// where
//     A1: AsRef<str>,
//     A2: AsRef<str>,
// {
//     let k_signing = signing_key.to_ksigning_key(&(req.get_request_date()?), &region, &service);
//     let string_to_sign = req.get_string_to_sign(&region, &service)?;
//     trace!("String to sign: {:?}", from_utf8(string_to_sign.as_ref()));

//     Ok(hex::encode(hmac_sha256(&k_signing.key, &string_to_sign).as_ref()))
// }

// /// Verify a SigV4 request. This verifies that the request timestamp is not beyond the allowed timestamp mismatch
// /// against the current time, and that the request signature matches our expected signature.
// pub fn sigv4_verify<A1, A2>(
//     req: &Request,
//     signing_key: &SigningKey,
//     allowed_mismatch: Option<Duration>,
//     region: A1,
//     service: A2,
// ) -> Result<(), SignatureError>
// where
//     A1: AsRef<str>,
//     A2: AsRef<str>,
// {
//     sigv4_verify_at(req, signing_key, &Utc::now(), allowed_mismatch, region, service)
// }

#[cfg(test2)]
mod tests {
    use {
        crate::{
            canonical::{canonicalize_uri_path, normalize_uri_path_component, query_string_to_normalized_map},
            SigV4Authenticator, SignatureError, SigningKey, SigningKeyKind,
        },
        chrono::{Date, NaiveDate, Utc},
        http::{
            header::{HeaderMap, HeaderValue},
            uri::{PathAndQuery, Uri},
        },
        scratchstack_aws_principal::{Principal, User},
        test_log::{self, test},
    };

    const TEST_REGION: &str = "us-east-1";
    const TEST_SERVICE: &str = "service";

    macro_rules! expect_err {
        ($test:expr, $expected:ident) => {
            match $test {
                Ok(e) => panic!("Expected Err({}); got Ok({:?})", stringify!($expected), e),
                Err(e) => match e {
                    SignatureError::$expected {
                        ..
                    } => format!("{}", &e),
                    _ => {
                        eprintln!("Expected {}; got {:?}: {}", stringify!($expected), &e, &e);
                        ($test).unwrap(); // panic
                        panic!();
                    }
                },
            }
        };
    }

    #[test]
    fn canonicalize_uri_path_empty() {
        assert_eq!(canonicalize_uri_path("").unwrap(), "/".to_string());
        assert_eq!(canonicalize_uri_path("/").unwrap(), "/".to_string());
    }

    #[test]
    fn canonicalize_valid() {
        assert_eq!(canonicalize_uri_path("/hello/world").unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello///world").unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/./world").unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/foo/../world").unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/%77%6F%72%6C%64").unwrap(), "/hello/world".to_string());
        assert_eq!(canonicalize_uri_path("/hello/w*rld").unwrap(), "/hello/w%2Arld".to_string());
        assert_eq!(canonicalize_uri_path("/hello/w%2arld").unwrap(), "/hello/w%2Arld".to_string());
        assert_eq!(canonicalize_uri_path("/hello/w+rld").unwrap(), "/hello/w%20rld".to_string());
    }

    #[test]
    fn canonicalize_invalid() {
        let e = expect_err!(canonicalize_uri_path("hello/world"), InvalidURIPath);
        assert_eq!(e.to_string(), "Path is not absolute: hello/world");
        expect_err!(canonicalize_uri_path("/hello/../../world"), InvalidURIPath);
    }

    #[test]
    fn normalize_valid1() {
        let result = query_string_to_normalized_map("Hello=World&foo=bar&baz=bomb&foo=2");
        let v = result.unwrap();
        let hello = v.get("Hello").unwrap();
        assert_eq!(hello.len(), 1);
        assert_eq!(hello[0], "World");

        let foo = v.get("foo").unwrap();
        assert_eq!(foo.len(), 2);
        assert_eq!(foo[0], "bar");
        assert_eq!(foo[1], "2");

        let baz = v.get("baz").unwrap();
        assert_eq!(baz.len(), 1);
        assert_eq!(baz[0], "bomb");
    }

    #[test]
    fn normalize_empty() {
        let result = query_string_to_normalized_map("Hello=World&&foo=bar");
        let v = result.unwrap();
        let hello = v.get("Hello").unwrap();

        assert_eq!(hello.len(), 1);
        assert_eq!(hello[0], "World");

        let foo = v.get("foo").unwrap();
        assert_eq!(foo.len(), 1);
        assert_eq!(foo[0], "bar");

        assert!(v.get("").is_none());
    }

    #[test]
    fn normalize_invalid_hex() {
        let e = expect_err!(normalize_uri_path_component("abcd%yy"), InvalidURIPath);
        assert!(e.starts_with("Invalid URI path:"));
        expect_err!(normalize_uri_path_component("abcd%yy"), InvalidURIPath);
        expect_err!(normalize_uri_path_component("abcd%0"), InvalidURIPath);
        expect_err!(normalize_uri_path_component("abcd%"), InvalidURIPath);
        assert_eq!(normalize_uri_path_component("abcd%65").unwrap(), "abcde");
    }

    const VALID_AUTH_HEADER: &str = "AWS4-HMAC-SHA256 \
    Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
    SignedHeaders=host;x-amz-date, \
    Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea";

    macro_rules! run_auth_test_expect_kind {
        ($auth_str:expr, $expected:ident) => {{
            let e = run_auth_test_get_err($auth_str).await;
            match e {
                SignatureError::$expected {
                    ..
                } => format!("{}", e),
                _ => panic!("Expected {}; got {:?}: {}", stringify!($expected), &e, &e),
            }
        }};
    }

    macro_rules! run_auth_test {
        ($auth_str:expr) => {
            run_auth_test_expect_kind!($auth_str, MalformedSignature)
        };
    }

    async fn run_auth_test_get_err_get_signing_key(
        kind: SigningKeyKind,
        _access_key_id: String,
        _session_token: Option<String>,
        req_date: Date<Utc>,
        region: String,
        service: String,
    ) -> Result<(Principal, SigningKey), SignatureError> {
        let k_secret = SigningKey {
            kind: SigningKeyKind::KSecret,
            key: b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
        };

        let principal = Principal::from(User::new("aws", "123456789012", "/", "test").unwrap());
        Ok((principal, k_secret.derive(kind, &req_date, region, service)))
    }

    async fn run_auth_test_get_err(auth_str: &str) -> SignatureError {
        let mut headers = HeaderMap::<HeaderValue>::with_capacity(3);
        headers.insert("authorization", HeaderValue::from_str(auth_str).unwrap());
        headers.insert("host", HeaderValue::from_static("example.amazonaws.com"));
        headers.insert("x-amz-date", HeaderValue::from_static("20150830T123600Z"));

        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = SigV4Authenticator {
            request_method: "GET".to_string(),
            uri,
            headers,
            body: None,
        };

        let test_date = Date::<Utc>::from_utc(NaiveDate::from_ymd(2015, 8, 30), Utc);
        let (_principal, k_signing) = run_auth_test_get_err_get_signing_key(
            SigningKeyKind::KSigning,
            "".to_string(),
            None,
            test_date,
            TEST_REGION.to_string(),
            TEST_SERVICE.to_string(),
        )
        .await
        .unwrap();

        sigv4_verify(&request, &k_signing, None, TEST_REGION, TEST_SERVICE).unwrap_err()
    }

    #[tokio::test]
    #[test_log::test]
    async fn test_wrong_auth_algorithm() {
        assert_eq!(
            run_auth_test_expect_kind!("AWS3-ZZZ Credential=12345", MissingAuthenticationToken),
            "Request is missing Authentication Token"
        );
    }

    #[tokio::test]
    #[test_log::test]
    async fn test_multiple_algorithms() {
        let mut headers = HeaderMap::<HeaderValue>::with_capacity(2);
        headers.append("authorization", HeaderValue::from_static("Basic foobar"));
        headers.append(
            "authorization",
            HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678"),
        );

        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request {
            request_method: "GET".to_string(),
            uri,
            headers,
            body: None,
        };

        let params = request.get_authorization_header_parameters().unwrap();
        assert_eq!(params.get("Credential").unwrap(), "1234");
        assert_eq!(params.get("SignedHeaders").unwrap(), "date;host");
        assert_eq!(params.get("Signature").unwrap(), "5678");
    }

    #[tokio::test]
    #[test_log::test]
    async fn duplicate_query_parameter() {
        let headers = HeaderMap::new();

        let request = Request {
            request_method: "GET".to_string(),
            uri: Uri::builder()
                .path_and_query(PathAndQuery::from_static("/?X-Amz-Signature=1234&X-Amz-Signature=1234"))
                .build()
                .unwrap(),
            headers,
            body: None,
        };

        let e = expect_err!(request.get_request_signature(), MultipleParameterValues);
        assert_eq!(format!("{}", e), "Multiple values for query parameter: X-Amz-Signature");
    }

    #[test]
    #[test_log::test]
    fn missing_header() {
        let mut headers = HeaderMap::<HeaderValue>::with_capacity(1);
        headers.insert("authorization", HeaderValue::from_static(""));

        let request = Request {
            request_method: "GET".to_string(),
            uri: Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap(),
            headers,
            body: None,
        };

        expect_err!(request.get_authorization_header_parameters(), MissingHeader);
    }

    #[test]
    #[test_log::test]
    fn missing_date() {
        let mut headers = HeaderMap::<HeaderValue>::with_capacity(2);
        headers.insert("authorization", HeaderValue::from_static(VALID_AUTH_HEADER));
        headers.insert("host", HeaderValue::from_static("localhost"));

        let request = Request {
            request_method: "GET".to_string(),
            uri: Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap(),
            headers,
            body: None,
        };

        let e = expect_err!(request.get_signed_headers(), MissingHeader);
        assert_eq!(format!("{}", e), "Missing header: x-amz-date");
    }

    #[test]
    #[test_log::test]
    fn invalid_date() {
        let mut headers = HeaderMap::<HeaderValue>::with_capacity(2);
        headers.insert("authorization", HeaderValue::from_static(VALID_AUTH_HEADER));
        headers.insert("date", HeaderValue::from_static("zzzzzzzzz"));

        let request = Request {
            request_method: "GET".to_string(),
            uri: Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap(),
            headers,
            body: None,
        };

        let e = expect_err!(request.get_request_timestamp(), MalformedHeader);
        assert_eq!(format!("{}", e), "Malformed header: Date is not a valid timestamp");

        let mut headers = HeaderMap::<HeaderValue>::with_capacity(2);
        headers.insert("authorization", HeaderValue::from_static(VALID_AUTH_HEADER));

        let request = Request {
            request_method: "GET".to_string(),
            uri: Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap(),
            headers,
            body: None,
        };

        expect_err!(request.get_request_timestamp(), MissingHeader);

        let headers = HeaderMap::new();
        let request = Request {
            request_method: "GET".to_string(),
            uri: Uri::builder().path_and_query(PathAndQuery::from_static("/?X-Amz-Date=zzzz")).build().unwrap(),
            headers,
            body: None,
        };

        let e = expect_err!(request.get_request_timestamp(), MalformedQueryString);
        assert_eq!(format!("{}", e), "Malformed query parameter: X-Amz-Date is not a valid timestamp");
    }

    /// Check for query parameters without a value, e.g. ?Key2&
    /// https://github.com/dacut/scratchstack-aws-signature/issues/2
    #[test]
    fn normalize_query_parameters_missing_value() {
        let result = query_string_to_normalized_map("Key1=Value1&Key2&Key3=Value3");
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result["Key1"], vec!["Value1"]);
        assert_eq!(result["Key2"], vec![""]);
        assert_eq!(result["Key3"], vec!["Value3"]);
    }
}
