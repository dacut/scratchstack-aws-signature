use {
    chrono::Utc,
    hyper::{body::Body, Request, Response},
    scratchstack_aws_principal::Principal,
    scratchstack_aws_signature::{sigv4_validate_request_hyper_stream, GetSigningKeyRequest, KSigningKey},
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
    G: Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError> + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError> + Send + Sync,
{
    pub region: String,
    pub service: String,
    pub get_signing_key: Buffer<G, GetSigningKeyRequest>,
    pub implementation: Buffer<S, Request<Body>>,
}

impl<G, S> AwsSigV4VerifierService<G, S>
where
    G: Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError> + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError> + Send + Sync,
{
    pub fn new(region: &str, service: &str, get_signing_key: G, implementation: S) -> Self {
        AwsSigV4VerifierService {
            region: region.to_string(),
            service: service.to_string(),
            get_signing_key: Buffer::new(get_signing_key, 10),
            implementation: Buffer::new(implementation, 10),
        }
    }
}

impl<G, S> Debug for AwsSigV4VerifierService<G, S>
where
    G: Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError> + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
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
    G: Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError> + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError> + Send + Sync,
{
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Debug::fmt(self, f)
    }
}

impl<G, S> Service<Request<Body>> for AwsSigV4VerifierService<G, S>
where
    G: Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError> + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
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
        let region = self.region.clone();
        let service = self.service.clone();
        let get_signing_key = self.get_signing_key.clone();
        let implementation = self.implementation.clone();

        Box::pin(handle_call(req, region, service, get_signing_key, implementation))
    }
}

async fn handle_call<G, S>(
    request: Request<Body>,
    region: String,
    service: String,
    mut get_signing_key: Buffer<G, GetSigningKeyRequest>,
    implementation: Buffer<S, Request<Body>>,
) -> Result<Response<Body>, BoxError>
where
    G: Service<GetSigningKeyRequest, Response = (Principal, KSigningKey), Error = BoxError> + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>> + Send + 'static,
    S::Future: Send,
    S::Error: Into<BoxError> + Send + Sync,
{
    let mut gsk = get_signing_key.ready().await?;
    let (mut parts, body, principal) =
        sigv4_validate_request_hyper_stream(request, region.as_str(), service.as_str(), &mut gsk, Utc::now()).await?;
    let body = Body::from(body);
    parts.extensions.insert(principal);
    let req = Request::from_parts(parts, body);
    implementation.oneshot(req).await
}
