use {
    chrono::Duration,
    futures::stream::StreamExt,
    http::request::Parts,
    hyper::{
        body::{Body, Bytes},
        Error as HyperError, Request, Response,
    },
    log::{debug, warn},
    scratchstack_aws_principal::PrincipalActor,
    scratchstack_aws_signature::{
        sigv4_verify, GetSigningKeyRequest, Request as AwsSigVerifyRequest, SigningKey, SigningKeyKind,
    },
    std::{
        any::type_name,
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    },
    tower::{buffer::Buffer, BoxError, Service, ServiceExt},
};

/// AWSSigV4VerifierService implements a Hyper service that authenticates a request against AWS SigV4 signing protocol.
#[derive(Clone)]
pub struct AwsSigV4VerifierService<G, S>
where
    G: Service<GetSigningKeyRequest, Response = (PrincipalActor, SigningKey)> + Clone + Send + 'static,
    G::Future: Send,
    G::Error: Into<BoxError> + Send + Sync,
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError> + Send + Sync,
{
    pub signing_key_kind: SigningKeyKind,
    pub allowed_mismatch: Option<Duration>,
    pub region: String,
    pub service: String,
    pub get_signing_key: Buffer<G, GetSigningKeyRequest>,
    pub implementation: Buffer<S, Request<Body>>,
}

impl<G, S> AwsSigV4VerifierService<G, S>
where
    G: Service<GetSigningKeyRequest, Response = (PrincipalActor, SigningKey)> + Clone + Send + 'static,
    G::Future: Send,
    G::Error: Into<BoxError> + Send + Sync,
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError> + Send + Sync,
{
    pub fn new<S1, S2>(region: S1, service: S2, get_signing_key: G, implementation: S) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        AwsSigV4VerifierService {
            signing_key_kind: SigningKeyKind::KSigning,
            allowed_mismatch: Some(Duration::minutes(5)),
            region: region.into(),
            service: service.into(),
            get_signing_key: Buffer::new(get_signing_key, 10),
            implementation: Buffer::new(implementation, 10),
        }
    }
}

impl<G, S> Debug for AwsSigV4VerifierService<G, S>
where
    G: Service<GetSigningKeyRequest, Response = (PrincipalActor, SigningKey)> + Clone + Send + 'static,
    G::Future: Send,
    G::Error: Into<BoxError> + Send + Sync,
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError> + Send + Sync,
{
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("AwsSigV4VerifierService")
            .field("region", &self.region)
            .field("service", &self.service)
            .field("get_signing_key", &type_name::<G>())
            .field("implementation", &type_name::<S>())
            .finish()
    }
}

impl<G, S> Display for AwsSigV4VerifierService<G, S>
where
    G: Service<GetSigningKeyRequest, Response = (PrincipalActor, SigningKey)> + Clone + Send + 'static,
    G::Future: Send,
    G::Error: Into<BoxError> + Send + Sync,
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError> + Send + Sync,
{
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Debug::fmt(self, f)
    }
}

// impl<S, GSK> AwsSigV4VerifierService<S, GSK>
// where
//     S: Service<Request<Body>, Response=Response<Body>> + Send + Sync + 'static,
//     S::Error: From<HyperError>,
//     GSK: GetSigningKey + Clone + Send + Sync + 'static,
//     GSK::Future: Send + Sync,
// {
//     async fn handle_call(&mut self, req: Request<Body>) -> Result<Response<Body>, <Self as Service<Request<Body>>>::Error> {
//     }
// }

impl<G, S> Service<Request<Body>> for AwsSigV4VerifierService<G, S>
where
    G: Service<GetSigningKeyRequest, Response = (PrincipalActor, SigningKey)> + Clone + Send + 'static,
    G::Future: Send,
    G::Error: Into<BoxError> + Send + Sync,
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError> + Send + Sync,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, BoxError>> + Send>>;

    fn poll_ready(&mut self, c: &mut Context) -> Poll<Result<(), Self::Error>> {
        match self.get_signing_key.poll_ready(c) {
            Poll::Ready(r) => match r {
                Ok(()) => match self.implementation.poll_ready(c) {
                    Poll::Ready(r) => match r {
                        Ok(()) => Poll::Ready(Ok(())),
                        Err(e) => Poll::Ready(Err(e)),
                    },
                    Poll::Pending => Poll::Pending,
                },
                Err(e) => Poll::Ready(Err(e)),
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let (parts, body) = req.into_parts();
        let allowed_mismatch = self.allowed_mismatch;
        let region = self.region.clone();
        let service = self.service.clone();
        let signing_key_kind = self.signing_key_kind;
        let get_signing_key = self.get_signing_key.clone();
        let implementation = self.implementation.clone();

        Box::pin(handle_call(
            parts,
            body,
            allowed_mismatch,
            region,
            service,
            get_signing_key,
            signing_key_kind,
            implementation,
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_call<G, S>(
    mut parts: Parts,
    body: Body,
    allowed_mismatch: Option<Duration>,
    region: String,
    service: String,
    get_signing_key: Buffer<G, GetSigningKeyRequest>,
    signing_key_kind: SigningKeyKind,
    implementation: Buffer<S, Request<Body>>,
) -> Result<Response<Body>, BoxError>
where
    G: Service<GetSigningKeyRequest, Response = (PrincipalActor, SigningKey)> + Clone + Send + 'static,
    G::Future: Send,
    G::Error: Into<BoxError> + Send + Sync,
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError> + Send + Sync,
{
    debug!("Request: {} {}", parts.method, parts.uri);
    debug!("Request headers:");
    for (key, value) in &parts.headers {
        let value_disp = value.to_str().unwrap_or("<INVALID>");
        debug!("{}: {}", key, value_disp);
    }

    // We need the actual body in order to compute the signature.
    match body_to_bytes(body).await {
        Err(e) => Err(e.into()),
        Ok(body) => {
            let aws_req = AwsSigVerifyRequest::from_http_request_parts(&parts, Some(body.clone()));
            let sig_req = match aws_req.to_get_signing_key_request(signing_key_kind, &region, &service) {
                Ok(sig_req) => Some(sig_req),
                Err(e) => {
                    warn!("Failed to generate a GetSigningKeyRequest request from Request: {:?}", e);
                    None
                }
            };
            if let Some(sig_req) = sig_req {
                match get_signing_key.oneshot(sig_req).await {
                    Ok((principal, signing_key)) => {
                        debug!("Get signing key returned principal {:?}", principal);
                        match sigv4_verify(&aws_req, &signing_key, allowed_mismatch, &region, &service) {
                            Ok(()) => {
                                debug!("Signature verified; adding principal to request: {:?}", principal);
                                parts.extensions.insert(principal);
                            }
                            Err(e) => warn!("Signature mismatch: {:?}", e),
                        }
                    }
                    Err(e) => warn!("Get signing key failed: {:?}", e),
                }
            }

            let new_body = Bytes::copy_from_slice(&body);
            let new_req = Request::from_parts(parts, Body::from(new_body));
            match implementation.oneshot(new_req).await {
                Ok(r) => Ok(r),
                Err(e) => Err(e),
            }
        }
    }
}

async fn body_to_bytes(mut body: Body) -> Result<Vec<u8>, HyperError> {
    let mut result = Vec::<u8>::new();

    loop {
        match body.next().await {
            None => break,
            Some(chunk_result) => match chunk_result {
                Ok(chunk) => result.append(&mut chunk.to_vec()),
                Err(e) => return Err(e),
            },
        }
    }

    Ok(result)
}
