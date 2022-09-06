mod service;
pub use crate::service::AwsSigV4VerifierService;

#[cfg(test)]
mod tests {
    use crate::AwsSigV4VerifierService;
    use chrono::{Date, Utc};
    use futures::stream::StreamExt;
    use http::StatusCode;
    use hyper::{
        client::{connect::dns::GaiResolver, HttpConnector},
        server::conn::AddrStream,
        service::{make_service_fn, service_fn},
        Body, Request, Response, Server,
    };
    use log::debug;
    use rusoto_core::{DispatchSignedRequest, HttpClient, Region};
    use rusoto_credential::AwsCredentials;
    use rusoto_signature::SignedRequest;
    use scratchstack_aws_principal::PrincipalActor;
    use scratchstack_aws_signature::{
        get_signing_key_fn, GetSigningKeyRequest, SignatureError, SigningKey, SigningKeyKind,
    };
    use std::{
        convert::Infallible,
        future::Future,
        net::{Ipv6Addr, SocketAddr, SocketAddrV6},
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use test_env_log;
    use tokio;
    use tower::{BoxError, Service};

    #[test_log::test(tokio::test)]
    async fn test_fn_wrapper() {
        let sigfn = get_signing_key_fn(get_creds_fn);
        let wrapped = service_fn(hello_response);
        let make_svc = make_service_fn(|_socket: &AddrStream| async move {
            Ok::<_, Infallible>(AwsSigV4VerifierService::new("local", "service", sigfn, wrapped))
        });

        let server = Server::bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5937, 0, 0))).serve(make_svc);
        let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
        connector.set_connect_timeout(Some(Duration::from_millis(10)));
        let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
        match server
            .with_graceful_shutdown(async {
                let region = Region::Custom {
                    name: "local".to_owned(),
                    endpoint: "http://[::1]:5937".to_owned(),
                };
                let mut sr = SignedRequest::new("GET", "service", &region, "/");
                sr.sign(&AwsCredentials::new(
                    "AKIDEXAMPLE",
                    "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                    None,
                    None,
                ));
                match client.dispatch(sr, Some(Duration::from_millis(100))).await {
                    Ok(r) => {
                        eprintln!("Response from server: {:?}", r.status);

                        let mut body = r.body;
                        loop {
                            match body.next().await {
                                Some(b_result) => match b_result {
                                    Ok(bytes) => eprint!("{:?}", bytes),
                                    Err(e) => {
                                        eprintln!("Error while ready body: {:?}", e);
                                        break;
                                    }
                                },
                                None => break,
                            }
                        }
                        eprintln!();
                        assert_eq!(r.status, StatusCode::OK);
                    }
                    Err(e) => panic!("Error from server: {:?}", e),
                };

                ()
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
        let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
        connector.set_connect_timeout(Some(Duration::from_millis(10)));
        let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
        let mut status = StatusCode::OK;
        match server
            .with_graceful_shutdown(async {
                let region = Region::Custom {
                    name: "local".to_owned(),
                    endpoint: "http://[::1]:5938".to_owned(),
                };
                let mut sr = SignedRequest::new("GET", "service", &region, "/");
                sr.sign(&AwsCredentials::new(
                    "AKIDEXAMPLE",
                    "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                    None,
                    None,
                ));
                match client.dispatch(sr, Some(Duration::from_millis(100))).await {
                    Ok(r) => {
                        eprintln!("Response from server: {:?}", r.status);

                        let mut body = r.body;
                        loop {
                            match body.next().await {
                                Some(b_result) => match b_result {
                                    Ok(bytes) => eprint!("{:?}", bytes),
                                    Err(e) => {
                                        eprintln!("Error while ready body: {:?}", e);
                                        break;
                                    }
                                },
                                None => break,
                            }
                        }
                        eprintln!();
                        status = r.status;
                    }
                    Err(e) => panic!("Error from server: {:?}", e),
                };

                ()
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
        let server = Server::bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5939, 0, 0))).serve(make_svc);
        let mut connector = HttpConnector::new_with_resolver(GaiResolver::new());
        connector.set_connect_timeout(Some(Duration::from_millis(10)));
        let client = HttpClient::<HttpConnector<GaiResolver>>::from_connector(connector);
        match server
            .with_graceful_shutdown(async {
                let region = Region::Custom {
                    name: "local".to_owned(),
                    endpoint: "http://[::1]:5939".to_owned(),
                };
                let mut sr = SignedRequest::new("GET", "service", &region, "/");
                sr.sign(&AwsCredentials::new("AKIDEXAMPLE", "WRONGKEY", None, None));
                match client.dispatch(sr, Some(Duration::from_millis(100))).await {
                    Ok(r) => {
                        eprintln!("Response from server: {:?}", r.status);

                        let mut body = r.body;
                        loop {
                            match body.next().await {
                                Some(b_result) => match b_result {
                                    Ok(bytes) => eprint!("{:?}", bytes),
                                    Err(e) => {
                                        eprintln!("Error while ready body: {:?}", e);
                                        break;
                                    }
                                },
                                None => break,
                            }
                        }
                        eprintln!();
                        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
                    }
                    Err(e) => panic!("Error from server: {:?}", e),
                };

                ()
            })
            .await
        {
            Ok(()) => println!("Server shutdown normally"),
            Err(e) => panic!("Server shutdown with error {:?}", e),
        }
    }

    async fn get_creds_fn(
        signing_key_kind: SigningKeyKind,
        access_key: String,
        _session_token: Option<String>,
        request_date: Date<Utc>,
        region: String,
        service: String,
    ) -> Result<(PrincipalActor, SigningKey), SignatureError> {
        if access_key == "AKIDEXAMPLE" {
            let k_secret = SigningKey {
                kind: SigningKeyKind::KSecret,
                key: b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
            };

            let principal = PrincipalActor::user("aws", "123456789012", "/", "test", "AIDAAAAAAAAAAAAAAAAA").unwrap();
            Ok((principal, k_secret.derive(signing_key_kind, &request_date, region, service)))
        } else {
            Err(SignatureError::UnknownAccessKey {
                access_key: access_key,
            }
            .into())
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
        type Response = (PrincipalActor, SigningKey);
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _c: &mut Context) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future {
            Box::pin(async move {
                if req.access_key == "AKIDEXAMPLE" {
                    let k_secret = SigningKey {
                        kind: SigningKeyKind::KSecret,
                        key: b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
                    };
                    debug!("secret key: {:?} {:02x?}", k_secret, &k_secret.key);

                    let principal =
                        PrincipalActor::user("aws", "123456789012", "/", "test", "AIDAAAAAAAAAAAAAAAAA").unwrap();
                    let derived = k_secret.derive(req.signing_key_kind, &req.request_date, req.region, req.service);
                    debug!("derived key: {:?} {:02x?}", derived, &derived.key);
                    Ok((principal, derived))
                } else {
                    Err(SignatureError::UnknownAccessKey {
                        access_key: req.access_key,
                    }
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
                let principal = parts.extensions.get::<PrincipalActor>();

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
