#![no_main]
use {
    arbitrary::Arbitrary,
    bytes::Bytes,
    chrono::{DateTime, NaiveDate, Utc},
    http::{Method, Request, Uri},
    libfuzzer_sys::{Corpus, fuzz_target},
    scratchstack_aws_principal::{Principal, User},
    scratchstack_aws_signature::{
        service_for_signing_key_fn, sigv4_validate_request, GetSigningKeyRequest, GetSigningKeyResponse, KSecretKey,
        SignedHeaderRequirements,
    },
    tokio::runtime::Builder as RuntimeBuilder,
    tower::BoxError,
};

#[derive(Arbitrary, Debug)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Trace,
    Connect,
    Patch,
}

impl From<HttpMethod> for Method {
    fn from(method: HttpMethod) -> Self {
        match method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
            HttpMethod::Put => Method::PUT,
            HttpMethod::Delete => Method::DELETE,
            HttpMethod::Head => Method::HEAD,
            HttpMethod::Options => Method::OPTIONS,
            HttpMethod::Trace => Method::TRACE,
            HttpMethod::Connect => Method::CONNECT,
            HttpMethod::Patch => Method::PATCH,
        }
    }
}

#[derive(Arbitrary, Debug)]
struct ValidateInput {
    method: HttpMethod,
    uri: String,
    body: Vec<u8>,
    region: String,
    service: String,
    always_present: Vec<String>,
    if_in_request: Vec<String>,
    prefixes: Vec<String>,
}

async fn get_signing_key(req: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
    let k_secret = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    let k_sigining = k_secret.to_ksigning(req.request_date, req.region.as_str(), req.service.as_str());

    let principal = Principal::from(vec![User::new("aws", "123456789012", "/", "test").unwrap().into()]);

    Ok(GetSigningKeyResponse {
        principal,
        signing_key: k_sigining,
    })
}

fuzz_target!(|data: ValidateInput| -> Corpus {
    let result = run_target(data);
    result.map(|_| Corpus::Keep).unwrap_or(Corpus::Reject)
});

fn run_target(data: ValidateInput) -> Result<(), BoxError> {
    let region = data.region;
    let service = data.service;
    let server_timestamp = DateTime::from_utc(NaiveDate::from_ymd(2015, 8, 30).and_hms(12, 36, 0), Utc);
    let mut gsk = service_for_signing_key_fn(get_signing_key);
    let required_headers = SignedHeaderRequirements::new(data.always_present, data.if_in_request, data.prefixes);
    let uri = Uri::from_maybe_shared(data.uri)?;
    let method: Method = data.method.into();
    let request = Request::builder().method(method).uri(uri).body(Bytes::from(data.body))?;
    let rt = RuntimeBuilder::new_current_thread().enable_all().build()?;
    rt.block_on(async move{
        let _ = sigv4_validate_request(request, region.as_str(), service.as_str(), &mut gsk, server_timestamp, &required_headers).await;
        Ok(())
    })
}