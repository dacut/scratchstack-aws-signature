#![warn(clippy::all)]

mod service;
pub use crate::service::AwsSigV4VerifierService;

#[cfg(test)]
mod tests {
    use {
        crate::AwsSigV4VerifierService,
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
        scratchstack_aws_principal::{Principal, User},
        scratchstack_aws_signature::{
            service_for_signing_key_fn, GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey, SignatureError,
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

    #[test_log::test(tokio::test)]
    async fn test_fn_wrapper() {
        let sigfn = service_for_signing_key_fn(get_creds_fn);
        let wrapped = service_fn(hello_response);
        let make_svc = make_service_fn(|_socket: &AddrStream| async move {
            Ok::<_, Infallible>(AwsSigV4VerifierService::new("local", "service", sigfn, wrapped))
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
                sr.sign(&AwsCredentials::new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", None, None));
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
                sr.sign(&AwsCredentials::new("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", None, None));
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
                sr.sign(&AwsCredentials::new("AKIDEXAMPLE", "WRONGKEY", None, None));
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
                        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
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

    async fn get_creds_fn(request: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
        if request.access_key == "AKIDEXAMPLE" {
            let k_secret = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
            let k_signing =
                k_secret.to_ksigning(request.request_date, request.region.as_str(), request.service.as_str());
            let principal = Principal::from(vec![User::new("aws", "123456789012", "/", "test").unwrap().into()]);
            Ok(GetSigningKeyResponse {
                principal,
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
        type Response = AwsSigV4VerifierService<GetDummyCreds, HelloService>;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _c: &mut Context) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _addr: &AddrStream) -> Self::Future {
            Box::pin(
                async move { Ok(AwsSigV4VerifierService::new("local", "service", GetDummyCreds {}, HelloService {})) },
            )
        }
    }

    #[derive(Clone)]
    struct GetDummyCreds {}
    impl Service<GetSigningKeyRequest> for GetDummyCreds {
        type Response = GetSigningKeyResponse;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _c: &mut Context) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future {
            Box::pin(async move {
                if req.access_key == "AKIDEXAMPLE" {
                    let k_secret = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
                    let signing_key = k_secret.to_ksigning(req.request_date, req.region.as_str(), req.service.as_str());
                    let principal =
                        Principal::from(vec![User::new("aws", "123456789012", "/", "test").unwrap().into()]);
                    Ok(GetSigningKeyResponse {
                        principal,
                        signing_key,
                    })
                } else {
                    Err(SignatureError::InvalidClientTokenId(
                        "The AWS access key provided does not exist in our records".to_string(),
                    )
                    .into())
                }
            })
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
}
