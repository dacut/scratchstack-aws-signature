use {
    crate::{CanonicalRequest, GetSigningKeyRequest, KSigningKey, SignatureError},
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

/// Validate an AWS SigV4 signature for a request with a static `Bytes` body.
pub async fn sigv4_validate_request_bytes<S, F>(
    request: Request<Bytes>,
    region: &str,
    service: &str,
    get_signing_key: &mut S,
    server_timestamp: DateTime<Utc>,
) -> Result<(Parts, Bytes, Principal), SignatureError>
where
    S: Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError, Future = F> + Send,
    F: Future<Output = Result<(Principal, KSigningKey), BoxError>> + Send,
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
    S: Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError, Future = F> + Send,
    F: Future<Output = Result<(Principal, KSigningKey), BoxError>> + Send,
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
