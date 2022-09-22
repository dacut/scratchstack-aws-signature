use {
    crate::{CanonicalRequest, GetSigningKeyRequest, GetSigningKeyResponse, SignatureError},
    bytes::{Bytes, BytesMut},
    chrono::{DateTime, Duration, Utc},
    futures::stream::{Stream, StreamExt},
    http::request::{Parts, Request},
    hyper::body::Body as HyperBody,
    scratchstack_aws_principal::Principal,
    std::{error::Error, future::Future},
    tower::{BoxError, Service},
};

/// Default allowed timestamp mismatch in minutes.
const ALLOWED_MISMATCH_MINUTES: i64 = 15;

/// Validate an AWS SigV4 signature for a request without a body.
pub async fn sigv4_validate_request_empty<S, F>(
    request: Request<()>,
    region: &str,
    service: &str,
    get_signing_key: &mut S,
    server_timestamp: DateTime<Utc>,
) -> Result<(Parts, (), Principal), SignatureError>
where
    S: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError, Future = F> + Send,
    F: Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send,
{
    let (parts, _) = request.into_parts();
    let body = Bytes::new();
    let (canonical_request, parts, _) = CanonicalRequest::from_request_parts(parts, body)?;
    let auth = canonical_request.get_authenticator()?;
    let principal = auth
        .validate_signature(
            region,
            service,
            server_timestamp,
            Duration::minutes(ALLOWED_MISMATCH_MINUTES),
            get_signing_key,
        )
        .await?;

    Ok((parts, (), principal))
}

/// Validate an AWS SigV4 signature for a request with a static `Bytes` body.
pub async fn sigv4_validate_request_bytes<S, F>(
    request: Request<Bytes>,
    region: &str,
    service: &str,
    get_signing_key: &mut S,
    server_timestamp: DateTime<Utc>,
) -> Result<(Parts, Bytes, Principal), SignatureError>
where
    S: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError, Future = F> + Send,
    F: Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send,
{
    let (parts, body) = request.into_parts();
    let (canonical_request, parts, body) = CanonicalRequest::from_request_parts(parts, body)?;
    let auth = canonical_request.get_authenticator()?;
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

/// Validate an AWS SigV4 signature for a request with a Hyper streaming body.
pub async fn sigv4_validate_request_hyper_stream<S, F>(
    request: Request<HyperBody>,
    region: &str,
    service: &str,
    get_signing_key: &mut S,
    server_timestamp: DateTime<Utc>,
) -> Result<(Parts, Bytes, Principal), Box<dyn Error + Send + Sync>>
where
    S: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError, Future = F> + Send,
    F: Future<Output = Result<GetSigningKeyResponse, BoxError>> + Send,
{
    let (parts, mut body) = request.into_parts();
    let size_hint = Stream::size_hint(&body);
    let size_hint = size_hint.1.unwrap_or(size_hint.0);
    let mut body_bytes = BytesMut::with_capacity(size_hint);
    while let Some(chunk) = body.next().await {
        body_bytes.extend(chunk?);
    }

    let (canonical_request, parts, body) = CanonicalRequest::from_request_parts(parts, body_bytes.into())?;
    let auth = canonical_request.get_authenticator()?;
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

#[cfg(test)]
mod tests {
    use {
        crate::{
            service_for_signing_key_fn, sigv4_validate_request_empty, GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey,
            SignatureError,
        },
        chrono::{DateTime, NaiveDate, Utc},
        http::{
            method::Method,
            request::Request,
            uri::{PathAndQuery, Uri},
        },
        lazy_static::lazy_static,
        scratchstack_aws_principal::{Principal, User},
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
                Err(ref e) => match e {
                    SignatureError::$expected(_) => e.to_string(),
                    _ => panic!("Expected {}; got {:#?}: {}", stringify!($expected), &e, &e),
                },
            }
        };
    }

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

    const VALID_AUTH_HEADER: &str = "AWS4-HMAC-SHA256 \
    Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
    SignedHeaders=host;x-amz-date, \
    Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea";

    async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
        let k_secret = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
        let k_sigining = k_secret.to_ksigning(req.request_date, req.region.as_str(), req.service.as_str());

        let principal = Principal::from(User::new("aws", "123456789012", "/", "test").unwrap());
        Ok(GetSigningKeyResponse{principal, signing_key: k_sigining})
    }

    async fn run_auth_test_get_err(auth_str: &str) -> SignatureError {
        let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header("authorization", auth_str)
            .header("host", "example.amazonaws.com")
            .header("x-amz-date", "20150830T123600Z")
            .body(())
            .unwrap();
        let mut get_sigining_key_svc = service_for_signing_key_fn(get_signing_key);
        sigv4_validate_request_empty(request, TEST_REGION, TEST_SERVICE, &mut get_sigining_key_svc, *TEST_TIMESTAMP)
            .await
            .unwrap_err()
    }

    #[test_log::test(tokio::test)]
    async fn test_wrong_auth_algorithm() {
        assert_eq!(
            run_auth_test_expect_kind!("AWS3-ZZZ Credential=12345", IncompleteSignature),
            "Unsupported AWS 'algorithm': 'AWS3-ZZZ'"
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
            sigv4_validate_request_empty(request, TEST_REGION, TEST_SERVICE, &mut gsk_service, *TEST_TIMESTAMP).await,
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
            sigv4_validate_request_empty(request, TEST_REGION, TEST_SERVICE, &mut gsk_service, *TEST_TIMESTAMP).await,
            IncompleteSignature
        );
        assert_eq!(
            e.as_str(),
            r#"Date must be in ISO-8601 'basic format'. Got 'zzzzzzzzz'. See http://en.wikipedia.org/wiki/ISO_8601"#
        );
    }
}
// end tests -- do not delete; needed for coverage.
