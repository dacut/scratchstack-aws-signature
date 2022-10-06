use {
    async_trait::async_trait,
    bytes::Bytes,
    chrono::Utc,
    hyper::{body::Body, Request, Response},
    quick_xml::{events::BytesText, writer::Writer as XmlWriter},
    scratchstack_aws_signature::{
        sigv4_validate_request, GetSigningKeyRequest, GetSigningKeyResponse, SignatureError, SignatureOptions,
        SignedHeaderRequirements,
    },
    scratchstack_errors::ServiceError,
    std::{
        any::type_name,
        error::Error,
        fmt::{Debug, Formatter, Result as FmtResult},
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    },
    tower::{BoxError, Service, ServiceExt},
};

/// AWSSigV4VerifierService implements a Hyper service that authenticates a request against AWS SigV4 signing protocol.
#[derive(Clone)]
pub struct AwsSigV4VerifierService<G, S, E>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
{
    pub region: String,
    pub service: String,
    pub signed_header_requirements: SignedHeaderRequirements,
    pub get_signing_key: G,
    pub implementation: S,
    pub error_handler: E,
}

impl<G, S, E> AwsSigV4VerifierService<G, S, E>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
{
    pub fn new(
        region: &str,
        service: &str,
        signed_header_requirements: SignedHeaderRequirements,
        get_signing_key: G,
        implementation: S,
        error_handler: E,
    ) -> Self {
        AwsSigV4VerifierService {
            region: region.to_string(),
            service: service.to_string(),
            signed_header_requirements,
            get_signing_key,
            implementation,
            error_handler,
        }
    }
}

impl<G, S, E> Debug for AwsSigV4VerifierService<G, S, E>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
{
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("AwsSigV4VerifierService")
            .field("region", &self.region)
            .field("service", &self.service)
            .field("get_signing_key", &type_name::<G>())
            .field("implementation", &type_name::<S>())
            .field("error_handler", &type_name::<E>())
            .finish()
    }
}

impl<G, S, E> Service<Request<Body>> for AwsSigV4VerifierService<G, S, E>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
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
        let signed_header_requirements = self.signed_header_requirements.clone();
        let get_signing_key = self.get_signing_key.clone();
        let implementation = self.implementation.clone();
        let error_handler = self.error_handler.clone();

        Box::pin(handle_call(
            req,
            region,
            service,
            signed_header_requirements,
            get_signing_key,
            implementation,
            error_handler,
        ))
    }
}

async fn handle_call<G, S, E>(
    req: Request<Body>,
    region: String,
    service: String,
    signed_header_requirements: SignedHeaderRequirements,
    mut get_signing_key: G,
    implementation: S,
    error_handler: E,
) -> Result<Response<Body>, BoxError>
where
    G: Service<GetSigningKeyRequest, Response = GetSigningKeyResponse, Error = BoxError> + Clone + Send + 'static,
    G::Future: Send,
    S: Service<Request<Body>, Response = Response<Body>, Error = BoxError> + Clone + Send + 'static,
    S::Future: Send,
    E: ErrorMapper,
{
    let result = sigv4_validate_request(
        req,
        region.as_str(),
        service.as_str(),
        &mut get_signing_key,
        Utc::now(),
        &signed_header_requirements,
        SignatureOptions::url_encode_form(),
    )
    .await;

    match result {
        Ok((mut parts, body, principal)) => {
            let body = Body::from(body);
            parts.extensions.insert(principal);
            let req = Request::from_parts(parts, body);
            implementation.oneshot(req).await.map_err(Into::into)
        }
        Err(e) => error_handler.map_error(e).await,
    }
}

#[async_trait]
pub trait ErrorMapper: Clone + Send + 'static {
    async fn map_error(self, error: BoxError) -> Result<Response<Body>, BoxError>;
}

#[derive(Clone)]
pub struct XmlErrorMapper {
    namespace: String,
}

impl XmlErrorMapper {
    pub fn new(namespace: &str) -> Self {
        XmlErrorMapper {
            namespace: namespace.to_string(),
        }
    }
}

#[async_trait]
impl ErrorMapper for XmlErrorMapper {
    async fn map_error(self, e: BoxError) -> Result<Response<Body>, BoxError> {
        match e.downcast::<SignatureError>() {
            Ok(e) => {
                let error_type = if e.http_status().as_u16() >= 500 {
                    "Receiver"
                } else {
                    "Sender"
                };
                let buffer = Vec::with_capacity(1024);
                let mut xml = XmlWriter::new_with_indent(buffer, b' ', 4);
                xml.create_element("ErrorResponse")
                    .with_attribute(("xmlns", self.namespace.as_str()))
                    .write_inner_content(|xml| {
                        xml.create_element("Error").write_inner_content(|xml| {
                            xml.create_element("Type").write_text_content(BytesText::new(error_type))?;
                            xml.create_element("Code").write_text_content(BytesText::new(e.error_code()))?;
                            let message = e.to_string();
                            if !message.is_empty() {
                                xml.create_element("Message").write_text_content(BytesText::new(message.as_str()))?;
                            }
                            Ok(())
                        })?;
                        Ok(())
                    })?;
                let mut xml = xml.into_inner();
                xml.push(b'\n');
                let body = Body::from(Bytes::from(xml));
                let result: Result<Response<Body>, Box<dyn Error + Send + Sync>> = Response::builder()
                    .status(e.http_status())
                    .header("Content-Type", "text/xml; charset=utf-8")
                    .body(body)
                    .map_err(Into::into);
                result
            }
            Err(any) => Err(any),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        crate::{AwsSigV4VerifierService, XmlErrorMapper},
        futures::stream::StreamExt,
        http::StatusCode,
        hyper::{
            client::{connect::dns::GaiResolver, HttpConnector},
            server::conn::AddrStream,
            service::{make_service_fn, service_fn},
            Body, Request, Response, Server,
        },
        log::info,
        rusoto_core::{DispatchSignedRequest, HttpClient, Region},
        rusoto_credential::AwsCredentials,
        rusoto_signature::SignedRequest,
        scratchstack_aws_principal::{Principal, SessionData, User},
        scratchstack_aws_signature::{
            service_for_signing_key_fn, GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, SignatureError,
            SignedHeaderRequirements,
        },
        std::{
            convert::Infallible,
            future::Future,
            net::{Ipv6Addr, SocketAddr, SocketAddrV6},
            pin::Pin,
            task::{Context, Poll},
            time::Duration,
        },
        tower::{BoxError, Service},
    };

    const TEST_ACCESS_KEY: &str = "AKIDEXAMPLE";
    const TEST_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    #[test_log::test(tokio::test)]
    async fn test_fn_wrapper() {
        let sigfn = service_for_signing_key_fn(get_creds_fn);
        let wrapped = service_fn(hello_response);
        let make_svc = make_service_fn(|_socket: &AddrStream| async move {
            let err_handler = XmlErrorMapper::new("service_namespace");
            let verifier_svc = AwsSigV4VerifierService::new(
                "local",
                "service",
                SignedHeaderRequirements::empty(),
                sigfn,
                wrapped,
                err_handler,
            );
            // Make sure we can debug print the verifier service.
            let _ = format!("{:?}", verifier_svc);
            Ok::<_, Infallible>(verifier_svc)
        });
        let server = Server::bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))).serve(make_svc);
        let addr = server.local_addr();
        let port = match addr {
            SocketAddr::V6(sa) => sa.port(),
            SocketAddr::V4(sa) => sa.port(),
        };
        info!("Server listening on port {}", port);
        let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
        connector.set_connect_timeout(Some(Duration::from_millis(10)));
        let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
        match server
            .with_graceful_shutdown(async {
                let region = Region::Custom {
                    name: "local".to_owned(),
                    endpoint: format!("http://[::1]:{}", port),
                };
                let mut sr = SignedRequest::new("GET", "service", &region, "/");
                sr.sign(&AwsCredentials::new(TEST_ACCESS_KEY, TEST_SECRET_KEY, None, None));
                match client.dispatch(sr, Some(Duration::from_millis(100))).await {
                    Ok(r) => {
                        eprintln!("Response from server: {:?}", r.status);

                        let mut body = r.body;
                        while let Some(b_result) = body.next().await {
                            match b_result {
                                Ok(bytes) => eprint!("{:?}", bytes),
                                Err(e) => {
                                    eprintln!("Error while ready body: {:?}", e);
                                    break;
                                }
                            }
                        }
                        eprintln!();
                        assert_eq!(r.status, StatusCode::OK);
                    }
                    Err(e) => panic!("Error from server: {:?}", e),
                };
            })
            .await
        {
            Ok(()) => println!("Server shutdown normally"),
            Err(e) => panic!("Server shutdown with error {:?}", e),
        }
    }

    #[test_log::test(tokio::test)]
    async fn test_svc_wrapper() {
        let make_svc = SpawnDummyHelloService {};
        let server = Server::bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5938, 0, 0))).serve(make_svc);
        let addr = server.local_addr();
        let port = match addr {
            SocketAddr::V6(sa) => sa.port(),
            SocketAddr::V4(sa) => sa.port(),
        };
        info!("Server listening on port {}", port);
        let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
        connector.set_connect_timeout(Some(Duration::from_millis(10)));
        let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
        let mut status = StatusCode::OK;
        match server
            .with_graceful_shutdown(async {
                let region = Region::Custom {
                    name: "local".to_owned(),
                    endpoint: format!("http://[::1]:{}", port),
                };
                let mut sr = SignedRequest::new("GET", "service", &region, "/");
                sr.sign(&AwsCredentials::new(TEST_ACCESS_KEY, TEST_SECRET_KEY, None, None));
                match client.dispatch(sr, Some(Duration::from_millis(100))).await {
                    Ok(r) => {
                        eprintln!("Response from server: {:?}", r.status);

                        let mut body = r.body;
                        while let Some(b_result) = body.next().await {
                            match b_result {
                                Ok(bytes) => eprint!("{:?}", bytes),
                                Err(e) => {
                                    eprintln!("Error while ready body: {:?}", e);
                                    break;
                                }
                            }
                        }
                        eprintln!();
                        status = r.status;
                    }
                    Err(e) => panic!("Error from server: {:?}", e),
                };
            })
            .await
        {
            Ok(()) => println!("Server shutdown normally"),
            Err(e) => panic!("Server shutdown with error {:?}", e),
        }

        assert_eq!(status, StatusCode::OK);
    }

    #[test_log::test(tokio::test)]
    async fn test_svc_wrapper_bad_creds() {
        let make_svc = SpawnDummyHelloService {};
        let server = Server::bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))).serve(make_svc);
        let addr = server.local_addr();
        let port = match addr {
            SocketAddr::V6(sa) => sa.port(),
            SocketAddr::V4(sa) => sa.port(),
        };
        info!("Server listening on port {}", port);
        let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
        connector.set_connect_timeout(Some(Duration::from_millis(100)));
        let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
        match server
            .with_graceful_shutdown(async {
                let region = Region::Custom {
                    name: "local".to_owned(),
                    endpoint: format!("http://[::1]:{}", port),
                };
                let mut sr = SignedRequest::new("GET", "service", &region, "/");
                sr.sign(&AwsCredentials::new(TEST_ACCESS_KEY, "WRONGKEY", None, None));
                match client.dispatch(sr, Some(Duration::from_millis(100))).await {
                    Ok(r) => {
                        eprintln!("Response from server: {:?}", r.status);

                        let mut body = Vec::with_capacity(1024);
                        let mut body_stream = r.body;
                        while let Some(b_result) = body_stream.next().await {
                            match b_result {
                                Ok(bytes) => {
                                    eprint!("{:?}", bytes);
                                    body.extend_from_slice(&bytes);
                                },
                                Err(e) => {
                                    eprintln!("Error while ready body: {:?}", e);
                                    break;
                                }
                            }
                        }
                        eprintln!();
                        assert_eq!(r.status, 403);
                        let body_str = String::from_utf8(body).unwrap();
                        assert_eq!(&body_str, r#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
    <Error>
        <Type>Sender</Type>
        <Code>SignatureDoesNotMatch</Code>
        <Message>The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.</Message>
    </Error>
</ErrorResponse>
"#);
                    }
                    Err(e) => panic!("Error from server: {:?}", e),
                };
            })
            .await
        {
            Ok(()) => println!("Server shutdown normally"),
            Err(e) => panic!("Server shutdown with error {:?}", e),
        }
    }

    #[test_log::test(tokio::test)]
    async fn test_svc_wrapper_backend_failure() {
        let make_svc = SpawnBadBackendService {};
        let server = Server::bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))).serve(make_svc);
        let addr = server.local_addr();
        let port = match addr {
            SocketAddr::V6(sa) => sa.port(),
            SocketAddr::V4(sa) => sa.port(),
        };
        info!("Server listening on port {}", port);
        let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
        connector.set_connect_timeout(Some(Duration::from_millis(100)));
        let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
        match server
            .with_graceful_shutdown(async {
                let region = Region::Custom {
                    name: "local".to_owned(),
                    endpoint: format!("http://[::1]:{}", port),
                };
                let mut sr = SignedRequest::new("GET", "service", &region, "/");
                sr.sign(&AwsCredentials::new(TEST_ACCESS_KEY, TEST_SECRET_KEY, None, None));
                match client.dispatch(sr, Some(Duration::from_millis(100))).await {
                    Ok(r) => panic!("Expected an error, got {}", r.status),
                    Err(e) => eprintln!("Got expected server error: {:?}", e),
                };
            })
            .await
        {
            Ok(()) => println!("Server shutdown normally"),
            Err(e) => panic!("Server shutdown with error {:?}", e),
        }
    }

    async fn get_creds_fn(request: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
        if request.access_key == TEST_ACCESS_KEY {
            let k_secret = KSecretKey::from_str(TEST_SECRET_KEY);
            let k_signing =
                k_secret.to_ksigning(request.request_date, request.region.as_str(), request.service.as_str());
            let principal = Principal::from(vec![User::new("aws", "123456789012", "/", "test").unwrap().into()]);
            Ok(GetSigningKeyResponse {
                principal,
                session_data: SessionData::default(),
                signing_key: k_signing,
            })
        } else {
            Err(Box::new(SignatureError::InvalidClientTokenId(
                "The AWS access key provided does not exist in our records".to_string(),
            )))
        }
    }

    async fn hello_response(_req: Request<Body>) -> Result<Response<Body>, BoxError> {
        Ok(Response::new(Body::from("Hello world")))
    }

    #[derive(Clone)]
    struct SpawnDummyHelloService {}
    impl Service<&AddrStream> for SpawnDummyHelloService {
        type Response = AwsSigV4VerifierService<GetDummyCreds, HelloService, XmlErrorMapper>;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _c: &mut Context) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _addr: &AddrStream) -> Self::Future {
            Box::pin(async move {
                Ok(AwsSigV4VerifierService::new(
                    "local",
                    "service",
                    SignedHeaderRequirements::empty(),
                    GetDummyCreds {},
                    HelloService {},
                    XmlErrorMapper::new("https://sts.amazonaws.com/doc/2011-06-15/"),
                ))
            })
        }
    }

    #[derive(Clone)]
    struct GetDummyCreds {}

    impl GetDummyCreds {
        async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
            if let Some(ref token) = req.session_token {
                match token.as_str() {
                    "invalid" => {
                        return Err(Box::new(SignatureError::InvalidClientTokenId(
                            "The security token included in the request is invalid".to_string(),
                        )))
                    }
                    "expired" => {
                        return Err(Box::new(SignatureError::ExpiredToken(
                            "The security token included in the request is expired".to_string(),
                        )))
                    }
                    _ => (),
                }
            }

            if req.access_key == TEST_ACCESS_KEY {
                let k_secret = KSecretKey::from_str(TEST_SECRET_KEY);
                let signing_key = k_secret.to_ksigning(req.request_date, req.region.as_str(), req.service.as_str());
                let principal = Principal::from(vec![User::new("aws", "123456789012", "/", "test").unwrap().into()]);
                Ok(GetSigningKeyResponse {
                    principal,
                    session_data: SessionData::default(),
                    signing_key,
                })
            } else {
                Err(SignatureError::InvalidClientTokenId(
                    "The AWS access key provided does not exist in our records".to_string(),
                )
                .into())
            }
        }
    }

    impl Service<GetSigningKeyRequest> for GetDummyCreds {
        type Response = GetSigningKeyResponse;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _c: &mut Context) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future {
            Box::pin(async move { GetDummyCreds::get_signing_key(req).await })
        }
    }

    #[derive(Clone)]
    struct HelloService {}
    impl Service<Request<Body>> for HelloService {
        type Response = Response<Body>;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _c: &mut Context) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            Box::pin(async move {
                let (parts, _body) = req.into_parts();
                let principal = parts.extensions.get::<Principal>();

                let (status, body) = match principal {
                    Some(principal) => (StatusCode::OK, format!("Hello {:?}", principal)),
                    None => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
                };

                match Response::builder().status(status).header("Content-Type", "text/plain").body(Body::from(body)) {
                    Ok(r) => Ok(r),
                    Err(e) => {
                        eprintln!("Response builder: error: {:?}", e);
                        Err(e.into())
                    }
                }
            })
        }
    }

    #[derive(Clone)]
    struct SpawnBadBackendService {}
    impl Service<&AddrStream> for SpawnBadBackendService {
        type Response = AwsSigV4VerifierService<BadGetCredsService, HelloService, XmlErrorMapper>;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _c: &mut Context) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _addr: &AddrStream) -> Self::Future {
            Box::pin(async move {
                Ok(AwsSigV4VerifierService::new(
                    "local",
                    "service",
                    SignedHeaderRequirements::empty(),
                    BadGetCredsService {
                        calls: 0,
                    },
                    HelloService {},
                    XmlErrorMapper::new("service-ns"),
                ))
            })
        }
    }

    #[derive(Clone)]
    struct BadGetCredsService {
        calls: usize,
    }

    impl Service<GetSigningKeyRequest> for BadGetCredsService {
        type Response = GetSigningKeyResponse;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
            self.calls += 1;
            match self.calls {
                0..=1 => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                _ => Poll::Ready(Err(Box::new(String::from_utf8(b"\x80".to_vec()).unwrap_err()))),
            }
        }

        fn call(&mut self, _req: GetSigningKeyRequest) -> Self::Future {
            Box::pin(async move { Err(SignatureError::InternalServiceError("Internal Failure".into()).into()) })
        }
    }
}
