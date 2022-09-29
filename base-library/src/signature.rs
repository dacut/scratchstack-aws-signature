use {
    crate::{CanonicalRequest, GetSigningKeyRequest, GetSigningKeyResponse, SignedHeaderRequirements},
    async_trait::async_trait,
    bytes::{Bytes, BytesMut},
    chrono::{DateTime, Duration, Utc},
    futures::stream::StreamExt,
    http::request::{Parts, Request},
    hyper::body::Body as HyperBody,
    scratchstack_aws_principal::Principal,
    std::{error::Error, future::Future},
    tower::{BoxError, Service},
};

/// Default allowed timestamp mismatch in minutes.
const ALLOWED_MISMATCH_MINUTES: i64 = 15;

pub async fn sigv4_validate_request<B, S, F>(
    request: Request<B>,
    region: &str,
    service: &str,
    get_signing_key: &mut S,
    server_timestamp: DateTime<Utc>,
    required_headers: &SignedHeaderRequirements,
) -> Result<(Parts, Bytes, Principal), BoxError>
where
    B: IntoRequestBytes,
    S: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError, Future = F> + Send,
    F: Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send,
{
    let (parts, body) = request.into_parts();
    let body = body.into_request_bytes().await?;
    let (canonical_request, parts, body) = CanonicalRequest::from_request_parts(parts, body)?;
    let auth = canonical_request.get_authenticator(required_headers)?;
    let principal = auth
        .validate_signature(
            region,
            service,
            server_timestamp,
            Duration::minutes(ALLOWED_MISMATCH_MINUTES),
            get_signing_key,
        )
        .await?;

    Ok((parts, body, principal))
}

#[async_trait]
pub trait IntoRequestBytes {
    async fn into_request_bytes(self) -> Result<Bytes, Box<dyn Error + Send + Sync>>;
}

#[async_trait]
impl IntoRequestBytes for () {
    async fn into_request_bytes(self) -> Result<Bytes, Box<dyn Error + Send + Sync>> {
        Ok(Bytes::new())
    }
}

#[async_trait]
impl IntoRequestBytes for Bytes {
    async fn into_request_bytes(self) -> Result<Bytes, Box<dyn Error + Send + Sync>> {
        Ok(self)
    }
}

#[async_trait]
impl IntoRequestBytes for HyperBody {
    async fn into_request_bytes(mut self) -> Result<Bytes, Box<dyn Error + Send + Sync>> {
        let mut body_bytes = BytesMut::new();
        while let Some(chunk) = self.next().await {
            body_bytes.extend_from_slice(&chunk?);
        }

        Ok(body_bytes.freeze())
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            service_for_signing_key_fn, sigv4_validate_request, GetSigningKeyRequest, GetSigningKeyResponse,
            KSecretKey, SignatureError, SignedHeaderRequirements,
        },
        bytes::Bytes,
        chrono::{DateTime, NaiveDate, Utc},
        http::{
            method::Method,
            request::{Parts, Request},
            uri::{PathAndQuery, Uri},
        },
        hyper::body::Body as HyperBody,
        lazy_static::lazy_static,
        scratchstack_aws_principal::{Principal, User},
        std::{convert::Infallible, mem::transmute},
        tower::BoxError,
    };

    const TEST_REGION: &str = "us-east-1";
    const TEST_SERVICE: &str = "service";

    lazy_static! {
        static ref TEST_TIMESTAMP: DateTime<Utc> =
            DateTime::from_local(NaiveDate::from_ymd(2015, 8, 30).and_hms(12, 36, 0), Utc);
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

    async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
        let k_secret = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let k_sigining = k_secret.to_ksigning(req.request_date, req.region.as_str(), req.service.as_str());

        let principal = Principal::from(vec![User::new("aws", "123456789012", "/", "test").unwrap().into()]);
        Ok(GetSigningKeyResponse {
            principal,
            signing_key: k_sigining,
        })
    }

    async fn run_auth_test(auth_str: &str) -> Result<(Parts, Bytes, Principal), BoxError> {
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
        let required_headers = SignedHeaderRequirements::empty();
        sigv4_validate_request(
            request,
            TEST_REGION,
            TEST_SERVICE,
            &mut get_signing_key_svc,
            *TEST_TIMESTAMP,
            &required_headers,
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
        let required_headers = SignedHeaderRequirements::empty();
        let e = expect_err!(
            sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut gsk_service,
                *TEST_TIMESTAMP,
                &required_headers
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
        let required_headers = SignedHeaderRequirements::empty();
        let e = expect_err!(
            sigv4_validate_request(
                request,
                TEST_REGION,
                TEST_SERVICE,
                &mut gsk_service,
                *TEST_TIMESTAMP,
                &required_headers
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
                    // Rewrite the path to be invalid.
                    let pq_ptr: *mut PathAndQuerySimulate = transmute(&mut pq);
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
            let mut required_headers = SignedHeaderRequirements::empty();
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
                    // Rewrite the path to be invalid.
                    let pq_ptr: *mut PathAndQuerySimulate = transmute(&mut pq);
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

            let body = futures::stream::once(async { Result::<Bytes, Infallible>::Ok(Bytes::from_static(b"{}")) });
            let request = builder.body(HyperBody::wrap_stream(body)).unwrap();
            let mut required_headers = SignedHeaderRequirements::new(
                vec!["Content-Type".into(), "Qwerty".into()],
                vec!["Foo".into(), "Bar".into(), "ETag".into()],
                vec!["x-amz".into()],
            );
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
}
