use {
    crate::{
        auth::SigV4AuthenticatorResponse, body::IntoRequestBytes, canonical::CanonicalRequest, constants::*,
        GetSigningKeyRequest, GetSigningKeyResponse, SignedHeaderRequirements,
    },
    bytes::Bytes,
    chrono::{DateTime, Duration, Utc},
    http::request::{Parts, Request},
    log::trace,
    std::future::Future,
    tower::{BoxError, Service},
};

/// Options that can be used to configure the signature service.
#[derive(Clone, Copy, Debug)]
pub struct SignatureOptions {
    /// Canonicalize requests according to S3 rules.
    pub s3: bool,

    /// Fold `application/x-www-form-urlencoded` bodies into the query string.
    pub url_encode_form: bool,

    /// The allowed mismatch between the request timestamp and the server timestamp.
    pub allowed_mismatch: Duration,
}

impl Default for SignatureOptions {
    fn default() -> Self {
        Self {
            s3: false,
            url_encode_form: false,
            allowed_mismatch: Duration::minutes(ALLOWED_MISMATCH_MINUTES),
        }
    }
}

impl SignatureOptions {
    /// Create a `SignatureOptions` suitable for use with services that treat
    /// `application/x-www-form-urlencoded` bodies as part of the query string.
    ///
    /// Some AWS services require this behavior. This typically happens when a query string is too
    /// long to fit in the URL, so a `GET` request is transformed into a `POST` request with the
    /// query string passed as an HTML form.
    ///
    /// This sets `s3` to `false` and `url_encode_form` to `true`.
    pub const fn url_encode_form() -> Self {
        Self {
            s3: false,
            url_encode_form: true,
            allowed_mismatch: Duration::minutes(ALLOWED_MISMATCH_MINUTES),
        }
    }

    /// Create a `SignatureOptions` suitable for use with S3-type authentication.
    ///
    /// This sets `s3` to `true` and `url_encode_form` to `false`, resulting in AWS SigV4S3-style
    /// canonicalization.
    pub const S3: Self = Self {
        s3: true,
        url_encode_form: false,
        allowed_mismatch: Duration::minutes(ALLOWED_MISMATCH_MINUTES),
    };
}

/// Validate an AWS SigV4 request.
///
/// This takes in an HTTP [`Request`] along with other service-specific parameters. If the
/// validation is successful (i.e. the request is properly signed with a known access key), this
/// returns:
/// * The request headers (as HTTP [`Parts`]).
/// * The request body (as a [`Bytes`] object, which is empty if no body was provided).
/// * The [response from the authenticator][SigV4AuthenticatorResponse], which contains the
///   principal and other session data.
///
/// # Parameters
/// * `request` - The HTTP [`Request`] to validate.
/// * `region` - The AWS region in which the request is being made.
/// * `service` - The AWS service to which the request is being made.
/// * `get_signing_key` - A service that can provide the signing key for the request.
/// * `server_timestamp` - The timestamp of the server when the request was received. Usually this
///   is the current time, `Utc::now()`.
/// * `required_headers` - The headers that are required to be signed in the request in addition to
///   the default SigV4 headers. If none, use
///   [`NO_ADDITIONAL_SIGNED_HEADERS`][crate::NO_ADDITIONAL_SIGNED_HEADERS].
/// * `options` - [`SignatureOptions`]` that affect the behavior of the signature validation. For
///   most services, use `SignatureOptions::default()`.
///
/// # Errors
/// This function returns a [`SignatureError`][crate::SignatureError] if the HTTP request is
/// malformed or the request was not properly signed. The validation follows the
/// [AWS Auth Error Ordering](https://github.com/dacut/scratchstack-aws-signature/blob/main/docs/AWS%20Auth%20Error%20Ordering.pdf)
/// document.
pub async fn sigv4_validate_request<B, G, F, S>(
    request: Request<B>,
    region: &str,
    service: &str,
    get_signing_key: &mut G,
    server_timestamp: DateTime<Utc>,
    required_headers: &S,
    options: SignatureOptions,
) -> Result<(Parts, Bytes, SigV4AuthenticatorResponse), BoxError>
where
    B: IntoRequestBytes,
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError, Future = F> + Send,
    F: Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send,
    S: SignedHeaderRequirements,
{
    let (parts, body) = request.into_parts();
    let body = body.into_request_bytes().await?;
    let (canonical_request, parts, body) = CanonicalRequest::from_request_parts(parts, body, options)?;
    trace!("Created canonical request: {canonical_request:?}");
    let auth = canonical_request.get_authenticator(required_headers)?;
    trace!("Created authenticator: {auth:?}");
    let sigv4_response =
        auth.validate_signature(region, service, server_timestamp, options.allowed_mismatch, get_signing_key).await?;

    Ok((parts, body, sigv4_response))
}

/// Validate AWS SigV4 S3-style request headers with a body hash. This is used when the request
/// body has not been sent yet (e.g. to respond to a request with an `Expect: 100-Continue` header).
///
/// This takes in a reference to an HTTP [`Request`] and a body hash along with other
/// authentication service-specific parameters. If the validation is successful (i.e. the request
/// is properly signed with a known access key), this returns:
/// * The [response from the authenticator][SigV4AuthenticatorResponse], which contains the
///   principal and other session data.
/// * The [signing key][crate::KSigningKey] used to sign the request. This may be needed for later
///   signature validation of `aws-chunked` body chunks.
///
/// # Parameters
/// * `request` - The HTTP [`Request`] to validate.
/// * `body_hash` - The hash of the request body. For S3 PutObject requests, this is the
///   `x-amz-content-sha256` header value, which may have special non-SHA-256 values like
///   `UNSIGNED-PAYLOAD`.
/// * `region` - The AWS region in which the request is being made.
/// * `service` - The AWS service to which the request is being made.
/// * `get_signing_key` - A service that can provide the signing key for the request.
/// * `server_timestamp` - The timestamp of the server when the request was received. Usually this
///   is the current time, `Utc::now()`.
/// * `required_headers` - The headers that are required to be signed in the request in addition to
///   the default SigV4 headers. If none, use
///   [`NO_ADDITIONAL_SIGNED_HEADERS`][crate::NO_ADDITIONAL_SIGNED_HEADERS].
/// * `options` - [`SignatureOptions`]` that affect the behavior of the signature validation. For
///   most services, use `SignatureOptions::default()`.
///
/// # Errors
/// This function returns a [`SignatureError`][crate::SignatureError] if the HTTP request is
/// malformed or the request was not properly signed. The validation follows the
/// [AWS Auth Error Ordering](https://github.com/dacut/scratchstack-aws-signature/blob/main/docs/AWS%20Auth%20Error%20Ordering.pdf)
/// document.
#[allow(clippy::too_many_arguments)]
pub async fn sigv4_validate_streaming_headers<B, G, F, S>(
    request: &Request<B>,
    body_hash: &str,
    region: &str,
    service: &str,
    get_signing_key: &mut G,
    server_timestamp: DateTime<Utc>,
    required_headers: &S,
    options: SignatureOptions,
) -> Result<GetSigningKeyResponse, BoxError>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError, Future = F> + Send,
    F: Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send,
    S: SignedHeaderRequirements,
{
    let canonical_request = CanonicalRequest::from_request_and_body_hash(request, body_hash, options)?;
    trace!("Created canonical request: {canonical_request:?}");
    let auth = canonical_request.get_authenticator(required_headers)?;
    trace!("Created authenticator: {auth:?}");

    // Obtain the signing key for the request.
    let gsk_response = auth.get_signing_key(region, service, get_signing_key).await?;

    // This will validate the signature; on success, this returns nothing.
    auth.validate_signature_with_key(
        region,
        service,
        server_timestamp,
        options.allowed_mismatch,
        gsk_response.signing_key(),
    )?;

    // The response from the get_signing_key call contains the principal and session
    // information, along with the key needed to validate parts of the body.
    Ok(gsk_response)
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            auth::SigV4AuthenticatorResponse, constants::*, service_for_signing_key_fn, sigv4_validate_request,
            sigv4_validate_streaming_headers, GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, SignatureError,
            SignatureOptions, SignedHeaderRequirements, VecSignedHeaderRequirements, NO_ADDITIONAL_SIGNED_HEADERS,
        },
        bytes::Bytes,
        chrono::{DateTime, Duration, NaiveDate, Utc},
        http::{
            method::Method,
            request::{Parts, Request},
            uri::{PathAndQuery, Uri},
        },
        lazy_static::lazy_static,
        scratchstack_aws_principal::{Principal, User},
        scratchstack_errors::ServiceError,
        std::{borrow::Cow, future::Future, str::FromStr},
        tower::BoxError,
    };

    lazy_static! {
        static ref TEST_TIMESTAMP: DateTime<Utc> = DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2015, 8, 30).unwrap().and_hms_opt(12, 36, 0).unwrap(),
            Utc
        );
    }

    macro_rules! expect_err {
        ($test:expr, $expected:ident) => {
            match $test {
                Ok(ref v) => panic!("Expected Err({}); got Ok({:?})", stringify!($expected), v),
                Err(e) => match e.downcast::<SignatureError>() {
                    Ok(e) => {
                        let e_string = e.to_string();
                        let e_debug = format!("{:?}", e);
                        match *e {
                            SignatureError::$expected(_) => e_string,
                            _ => panic!("Expected {}; got {}: {}", stringify!($expected), e_debug, e_string),
                        }
                    }
                    Err(ref other) => panic!("Expected {}; got {:#?}: {}", stringify!($expected), &other, &other),
                },
            }
        };
    }

    macro_rules! run_auth_test_expect_kind {
        ($auth_str:expr, $expected:ident) => {
            expect_err!(run_auth_test($auth_str).await, $expected)
        };
    }

    const VALID_AUTH_HEADER: &str = "AWS4-HMAC-SHA256 \
    Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
    SignedHeaders=host;x-amz-date, \
    Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea";

    fn make_get_signing_key_fn(
        secret_key: &str,
    ) -> impl Fn(
        GetSigningKeyRequest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send>> {
        let secret_key = secret_key.to_string();
        move |req: GetSigningKeyRequest| {
            let secret_key = secret_key.clone();
            Box::pin(async move {
                let k_secret = KSecretKey::from_str(secret_key.as_str()).unwrap();
                let k_signing = k_secret.to_ksigning(req.request_date(), req.region(), req.service());

                let principal = Principal::from(vec![User::new("aws", "123456789012", "/", "test").unwrap().into()]);
                Ok(GetSigningKeyResponse::builder().principal(principal).signing_key(k_signing).build().unwrap())
            })
        }
    }

    async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
        let k_secret = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY").unwrap();
        let k_signing = k_secret.to_ksigning(req.request_date(), req.region(), req.service());

        let principal = Principal::from(vec![User::new("aws", "123456789012", "/", "test").unwrap().into()]);
        Ok(GetSigningKeyResponse::builder().principal(principal).signing_key(k_signing).build().unwrap())
    }

    async fn run_auth_test(auth_str: &str) -> Result<(Parts, Bytes, SigV4AuthenticatorResponse), BoxError> {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", auth_str)
            .header("host", "example.amazonaws.com")
            .header("x-amz-date", "20150830T123600Z")
            .body(())
            .unwrap();
        let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);
        sigv4_validate_request(
            request,
            TEST_REGION,
            TEST_SERVICE,
            &mut get_signing_key_svc,
            *TEST_TIMESTAMP,
            &NO_ADDITIONAL_SIGNED_HEADERS,
            SignatureOptions::url_encode_form(),
        )
        .await
    }

    #[test_log::test(tokio::test)]
    async fn test_wrong_auth_algorithm() {
        assert_eq!(
            run_auth_test_expect_kind!("AWS3-ZZZ Credential=12345", IncompleteSignature),
            "Unsupported AWS 'algorithm': 'AWS3-ZZZ'."
        );
    }

    #[test_log::test(tokio::test)]
    async fn missing_date() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let mut gsk_service = service_for_signing_key_fn(get_signing_key);
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", VALID_AUTH_HEADER)
            .header("host", "localhost")
            .body(())
            .unwrap();
        let e = expect_err!(
            sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut gsk_service,
                *TEST_TIMESTAMP,
                &NO_ADDITIONAL_SIGNED_HEADERS,
                SignatureOptions::url_encode_form()
            )
            .await,
            IncompleteSignature
        );
        assert_eq!(
            e.as_str(),
            r#"Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256"#
        );
    }

    #[test_log::test(tokio::test)]
    async fn invalid_date() {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let mut gsk_service = service_for_signing_key_fn(get_signing_key);
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", VALID_AUTH_HEADER)
            .header("date", "zzzzzzzzz")
            .body(())
            .unwrap();
        let e = expect_err!(
            sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut gsk_service,
                *TEST_TIMESTAMP,
                &NO_ADDITIONAL_SIGNED_HEADERS,
                SignatureOptions::url_encode_form()
            )
            .await,
            IncompleteSignature
        );
        assert_eq!(
            e.as_str(),
            r#"Date must be in ISO-8601 'basic format'. Got 'zzzzzzzzz'. See http://en.wikipedia.org/wiki/ISO_8601"#
        );
    }

    struct PathAndQuerySimulate {
        data: Bytes,
        _query: u16,
    }

    #[test_log::test(tokio::test)]
    async fn error_ordering_auth_header() {
        for i in 0..22 {
            let fake_path = "/aaa?aaa".to_string();
            let mut pq = PathAndQuery::from_maybe_shared(fake_path).unwrap();
            let pq_path = Bytes::from_static("/aaa?a%yy".as_bytes());
            let get_signing_key_svc = service_for_signing_key_fn(get_signing_key);

            if i == 0 {
                unsafe {
                    // Rewrite the path to be invalid. This can't be done with the normal PathAndQuery API.
                    let pq_ptr: *mut PathAndQuerySimulate = &mut pq as *mut PathAndQuery as *mut PathAndQuerySimulate;
                    (*pq_ptr).data = pq_path;
                }
            }

            let uri = Uri::builder().path_and_query(pq).build().unwrap();
            let mut builder = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header("x-amz-request-id", "12345")
                .header("ETag", "ABCD");

            if i > 1 {
                builder = builder.header(
                    "authorization",
                    match i {
                        2 => "AWS5-HMAC-SHA256 FooBar, BazBurp",
                        3 => "AWS4-HMAC-SHA256 FooBar, BazBurp",
                        4 => "AWS4-HMAC-SHA256 Foo=Bar, Baz=Burp",
                        5 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE",
                        6 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF",
                        7..=8 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=bar",
                        9 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=host;x-amz-date",
                        10 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;host;x-amz-date",
                        11 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date",
                        12..=15 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        16 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/foobar/wrong-region/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        17 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/wrong-region/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        18 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        19 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        20 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        _ => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=0e669f2a32894c33e1214831b3605dbc6e14c1708872c55d4b04a6c10a20de40, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                    },
                );
            }

            match i {
                0..=7 => (),
                8..=12 => builder = builder.header("x-amz-date", "2015/08/30T12/36/00Z"),
                13 => builder = builder.header("x-amz-date", "20150830T122059Z"),
                14 => builder = builder.header("x-amz-date", "20150830T125101Z"),
                _ => builder = builder.header("x-amz-date", "20150830T122100Z"),
            }

            let request = builder.body(()).unwrap();
            let mut required_headers = VecSignedHeaderRequirements::default();
            required_headers.add_always_present("Content-Type");
            required_headers.add_always_present("Qwerty");
            required_headers.add_if_in_request("Foo");
            required_headers.add_if_in_request("Bar");
            required_headers.add_if_in_request("ETag");
            required_headers.add_prefix("x-amz");
            required_headers.add_prefix("a-am2");
            required_headers.remove_always_present("QWERTY");
            required_headers.remove_if_in_request("BAR");
            required_headers.remove_prefix("A-am2");

            let result = sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut get_signing_key_svc.clone(),
                *TEST_TIMESTAMP,
                &required_headers,
                SignatureOptions::url_encode_form(),
            )
            .await;

            if i >= 21 {
                assert!(result.is_ok());
            } else {
                let e = result.unwrap_err();
                assert!(e.source().is_none());
                let e = e.downcast_ref::<SignatureError>().expect("Expected SignatureError");
                match (i, e) {
                    (0, SignatureError::MalformedQueryString(_)) => {
                        assert_eq!(e.to_string().as_str(), "Illegal hex character in escape % pattern: %yy")
                    }
                    (1, SignatureError::MissingAuthenticationToken(_)) => {
                        assert_eq!(e.to_string().as_str(), "Request is missing Authentication Token")
                    }
                    (2, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Unsupported AWS 'algorithm': 'AWS5-HMAC-SHA256'.")
                    }
                    (3, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "'FooBar' not a valid key=value pair (missing equal-sign) in Authorization header: 'AWS4-HMAC-SHA256 FooBar, BazBurp'")
                    }
                    (4, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Authorization header requires 'Credential' parameter. Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256")
                    }
                    (5, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256")
                    }
                    (6, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256")
                    }
                    (7, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256")
                    }
                    (8, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'Host' or ':authority' must be a 'SignedHeader' in the AWS Authorization."
                        )
                    }
                    (9, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'Content-Type' must be a 'SignedHeader' in the AWS Authorization."
                        )
                    }
                    (10, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "'ETag' must be a 'SignedHeader' in the AWS Authorization.")
                    }
                    (11, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'x-amz-request-id' must be a 'SignedHeader' in the AWS Authorization."
                        )
                    }
                    (12, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Date must be in ISO-8601 'basic format'. Got '2015/08/30T12/36/00Z'. See http://en.wikipedia.org/wiki/ISO_8601")
                    }
                    (13, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "Signature expired: 20150830T122059Z is now earlier than 20150830T122100Z (20150830T123600Z - 15 min.)")
                    }
                    (14, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "Signature not yet current: 20150830T125101Z is still later than 20150830T125100Z (20150830T123600Z + 15 min.)")
                    }
                    (15, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term, got 'AKIDEXAMPLE'")
                    }
                    (16, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "Credential should be scoped to a valid region, not 'wrong-region'. Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'. Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP: 'foobar' != '20150830', from '20150830T122100Z'.")
                    }
                    (17, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "Credential should be scoped to a valid region, not 'wrong-region'. Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'.")
                    }
                    (18, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'.")
                    }
                    (19, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'."
                        )
                    }
                    (20, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.")
                    }
                    _ => panic!("Incorrect error returned on run {}: {:?}", i, e),
                }
            }
        }
    }

    #[test_log::test(tokio::test)]
    async fn error_ordering_auth_header_streaming_body() {
        for i in 0..22 {
            let fake_path = "/aaa?aaa".to_string();
            let mut pq = PathAndQuery::from_maybe_shared(fake_path).unwrap();
            let pq_path = Bytes::from_static("/aaa?a%yy".as_bytes());
            let get_signing_key_svc = service_for_signing_key_fn(get_signing_key);

            if i == 0 {
                unsafe {
                    // Rewrite the path to be invalid. This cannot be done with the normal PathAndQuery API.
                    let pq_ptr: *mut PathAndQuerySimulate = &mut pq as *mut PathAndQuery as *mut PathAndQuerySimulate;
                    (*pq_ptr).data = pq_path;
                }
            }

            let uri = Uri::builder().path_and_query(pq).build().unwrap();
            let mut builder = Request::builder()
                .method(Method::GET)
                .uri(uri)
                .header("x-amz-request-id", "12345")
                .header("ETag", "ABCD");

            if i > 1 {
                builder = builder.header(
                    "authorization",
                    match i {
                        2 => "AWS5-HMAC-SHA256 FooBar, BazBurp",
                        3 => "AWS4-HMAC-SHA256 FooBar, BazBurp",
                        4 => "AWS4-HMAC-SHA256 Foo=Bar, Baz=Burp",
                        5 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE",
                        6 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF",
                        7..=8 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=bar",
                        9 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=host;x-amz-date",
                        10 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;host;x-amz-date",
                        11 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date",
                        12..=15 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        16 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/foobar/wrong-region/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        17 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/wrong-region/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        18 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/wrong-service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        19 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws5_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        20 => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=ABCDEF, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                        _ => "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=07758ff72d5726780290f484e5f7d1c026f36067d3656435e99e2391e1818c54, SignedHeaders=content-type;etag;host;x-amz-date;x-amz-request-id",
                    },
                );
            }

            match i {
                0..=7 => (),
                8..=12 => builder = builder.header("x-amz-date", "2015/08/30T12/36/00Z"),
                13 => builder = builder.header("x-amz-date", "20150830T122059Z"),
                14 => builder = builder.header("x-amz-date", "20150830T125101Z"),
                _ => builder = builder.header("x-amz-date", "20150830T122100Z"),
            }

            let body = Bytes::from_static(b"{}");

            let request = builder.body(body).unwrap();
            let mut required_headers =
                VecSignedHeaderRequirements::new(&["Content-Type", "Qwerty"], &["Foo", "Bar", "ETag"], &["x-amz"]);
            required_headers.remove_always_present("QWERTY");
            assert!(!required_headers.always_present().contains(&Cow::Borrowed("Qwerty")));
            required_headers.remove_if_in_request("BAR");
            required_headers.remove_prefix("A-am2");
            let result = sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut get_signing_key_svc.clone(),
                *TEST_TIMESTAMP,
                &required_headers,
                SignatureOptions::url_encode_form(),
            )
            .await;

            if i >= 21 {
                assert!(result.is_ok());
            } else {
                let e = result.unwrap_err();
                assert!(e.source().is_none());
                let e = e.downcast::<SignatureError>().unwrap();
                match (i, &*e) {
                    (0, SignatureError::MalformedQueryString(_)) => {
                        assert_eq!(e.to_string().as_str(), "Illegal hex character in escape % pattern: %yy");
                        assert_eq!(e.error_code(), "MalformedQueryString");
                        assert_eq!(e.http_status(), 400);
                    }
                    (1, SignatureError::MissingAuthenticationToken(_)) => {
                        assert_eq!(e.to_string().as_str(), "Request is missing Authentication Token");
                        assert_eq!(e.error_code(), "MissingAuthenticationToken");
                        assert_eq!(e.http_status(), 400);
                    }
                    (2, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Unsupported AWS 'algorithm': 'AWS5-HMAC-SHA256'.");
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (3, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "'FooBar' not a valid key=value pair (missing equal-sign) in Authorization header: 'AWS4-HMAC-SHA256 FooBar, BazBurp'");
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (4, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Authorization header requires 'Credential' parameter. Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256");
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (5, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256");
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (6, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256");
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (7, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. Authorization=AWS4-HMAC-SHA256");
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (8, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'Host' or ':authority' must be a 'SignedHeader' in the AWS Authorization."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (9, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'Content-Type' must be a 'SignedHeader' in the AWS Authorization."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (10, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "'ETag' must be a 'SignedHeader' in the AWS Authorization.");
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (11, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "'x-amz-request-id' must be a 'SignedHeader' in the AWS Authorization."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (12, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Date must be in ISO-8601 'basic format'. Got '2015/08/30T12/36/00Z'. See http://en.wikipedia.org/wiki/ISO_8601");
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (13, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "Signature expired: 20150830T122059Z is now earlier than 20150830T122100Z (20150830T123600Z - 15 min.)");
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (14, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "Signature not yet current: 20150830T125101Z is still later than 20150830T125100Z (20150830T123600Z + 15 min.)");
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (15, SignatureError::IncompleteSignature(_)) => {
                        assert_eq!(e.to_string().as_str(), "Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term, got 'AKIDEXAMPLE'");
                        assert_eq!(e.error_code(), "IncompleteSignature");
                        assert_eq!(e.http_status(), 400);
                    }
                    (16, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "Credential should be scoped to a valid region, not 'wrong-region'. Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'. Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP: 'foobar' != '20150830', from '20150830T122100Z'.");
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (17, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "Credential should be scoped to a valid region, not 'wrong-region'. Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'.");
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (18, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "Credential should be scoped to correct service: 'service'. Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'.");
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (19, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(
                            e.to_string().as_str(),
                            "Credential should be scoped with a valid terminator: 'aws4_request', not 'aws5_request'."
                        );
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    (20, SignatureError::SignatureDoesNotMatch(_)) => {
                        assert_eq!(e.to_string().as_str(), "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.");
                        assert_eq!(e.error_code(), "SignatureDoesNotMatch");
                        assert_eq!(e.http_status(), 403);
                    }
                    _ => panic!("Incorrect error returned on run {}: {:?}", i, e),
                }
            }
        }
    }

    #[test_log::test]
    fn test_signature_options() {
        assert!(!SignatureOptions::default().s3);
        assert!(!SignatureOptions::default().url_encode_form);

        let opt1 = SignatureOptions::S3;
        let opt2 = SignatureOptions {
            s3: true,
            ..Default::default()
        };
        let opt3 = opt1;
        let opt4 = opt1;
        assert_eq!(opt1.s3, opt2.s3);
        assert_eq!(opt1.s3, opt3.s3);
        assert_eq!(opt1.s3, opt4.s3);
        assert_eq!(opt1.url_encode_form, opt2.url_encode_form);
        assert_eq!(opt1.url_encode_form, opt3.url_encode_form);
        assert_eq!(opt1.url_encode_form, opt4.url_encode_form);
        assert!(opt1.s3);
        assert!(!opt1.url_encode_form);

        assert_eq!(format!("{:?}", opt1), "SignatureOptions { s3: true, url_encode_form: false, allowed_mismatch: TimeDelta { secs: 900, nanos: 0 } }");
    }

    #[test_log::test(tokio::test)]
    async fn test_canonicalization_forms() {
        let mut get_signing_key_svc = service_for_signing_key_fn(get_signing_key);

        // Regular, non-S3 request.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/a/path/../to//something") // Becomes /a/to/something.
            .header("Host", "example.amazonaws.com")
            .header("X-Amz-Date", "20150830T123600Z")
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=444cab3690e122afc941d086f06cfbc82c1b4f5c553e32ac81e7629a82ff3831, SignedHeaders=host;x-amz-date")
            .body(())
            .unwrap();

        assert!(sigv4_validate_request(
            req,
            "us-east-1",
            "service",
            &mut get_signing_key_svc,
            *TEST_TIMESTAMP,
            &NO_ADDITIONAL_SIGNED_HEADERS,
            SignatureOptions::default()
        )
        .await
        .is_ok());

        // S3 request.
        let req = Request::builder()
            .method(Method::GET)
            .uri("/a/path/../to//something") // Remains as /a/path/../to//something
            .header("Host", "example.amazonaws.com")
            .header("X-Amz-Date", "20150830T123600Z")
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, Signature=b475de2c96e7bfdfe03bd784d948218730ef62f48ac8bb9f2922af9a44f8657c, SignedHeaders=host;x-amz-date")
            .body(())
            .unwrap();

        assert!(sigv4_validate_request(
            req,
            "us-east-1",
            "service",
            &mut get_signing_key_svc,
            *TEST_TIMESTAMP,
            &NO_ADDITIONAL_SIGNED_HEADERS,
            SignatureOptions::S3,
        )
        .await
        .is_ok());
    }

    #[test_log::test(tokio::test)]
    async fn test_validate_streaming_headers() {
        // Taken from https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
        let req = Request::builder()
            .method(Method::PUT)
            .uri("https://s3.amazonaws.com/examplebucket/chunkObject.txt")
            .header("Host", "s3.amazonaws.com")
            .header("x-amz-date", "20130524T000000Z")
            .header("x-amz-storage-class", "REDUCED_REDUNDANCY")
            .header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
            .header("Content-Encoding", "aws-chunked")
            .header("x-amz-decoded-content-length", "66560")
            .header("Content-Length", "66824")
            .header("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class,Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9")
            .body(Bytes::new())
            .unwrap();

        let timestamp = DateTime::from_naive_utc_and_offset(
            NaiveDate::from_ymd_opt(2013, 5, 24)
                .expect("Failed to convert 2013-05-24 to a NaiveDate")
                .and_hms_opt(0, 0, 0)
                .expect("Failed to convert 2013-05-24T00:00:00 to a NaiveDateTime"),
            Utc,
        );

        let mut signature_options = SignatureOptions::S3;
        signature_options.allowed_mismatch = Duration::MAX;

        // This S3 example secret key is subtly different than the standard example signing key;
        // The + is replaced with a second /.
        let mut get_signing_key_svc =
            service_for_signing_key_fn(make_get_signing_key_fn("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        let mut required_headers = VecSignedHeaderRequirements::default();
        required_headers.add_always_present("content-encoding");
        required_headers.add_always_present("content-length");
        required_headers.add_always_present("host");
        required_headers.add_always_present("x-amz-content-sha256");
        required_headers.add_always_present("x-amz-date");
        required_headers.add_always_present("x-amz-decoded-content-length");
        required_headers.add_always_present("x-amz-storage-class");
        sigv4_validate_streaming_headers(
            &req,
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
            "us-east-1",
            "s3",
            &mut get_signing_key_svc,
            timestamp,
            &required_headers,
            signature_options,
        )
        .await
        .expect("Failed to validate streaming headers");
    }
}
