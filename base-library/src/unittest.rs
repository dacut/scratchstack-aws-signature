use {
    super::signature::{
        canonicalize_uri_path, normalize_query_parameters, normalize_uri_path_component, sigv4_verify, Request,
        SignatureError, SigningKey, SigningKeyKind,
    },
    std::fmt::Write,
};

use {
    super::chronoutil::ParseISO8601,
    chrono::{Date, DateTime, Datelike, NaiveDate, Timelike, Utc},
    http::{
        header::{HeaderMap, HeaderValue},
        uri::{PathAndQuery, Uri},
    },
    scratchstack_aws_principal::PrincipalActor,
    test_log::{self, test},
};

const TEST_REGION: &str = "us-east-1";
const TEST_SERVICE: &str = "service";

#[test]
fn check_iso8601_error_handling() {
    match DateTime::parse_from_iso8601("blatantly-wrong") {
        Ok(_) => panic!("Expected a ParseError"),
        Err(_) => 1,
    };

    match DateTime::parse_from_iso8601("2001-01-001T00:00:00Z") {
        Ok(_) => panic!("Expected a ParseError"),
        Err(_) => 1,
    };
}

#[test]
fn check_principal_formats() {
    let principal = PrincipalActor::user("aws", "123456789012", "/", "test", "AIDAAAAAAAAAAAAAAAAA").unwrap();
    let mut s = String::new();
    write!(s, "{}", principal).expect("must succeed");
    assert_eq!(s, "arn:aws:iam::123456789012:user/test");

    let principal = PrincipalActor::user("aws", "123456789012", "/path/", "test", "AIDAAAAAAAAAAAAAAAAA").unwrap();
    let mut s = String::new();
    write!(s, "{}", principal).expect("must succeed");
    assert_eq!(s, "arn:aws:iam::123456789012:user/path/test");

    let principal = PrincipalActor::group("aws", "123456789012", "/path/", "test", "AGPAAAAAAAAAAAAAAAAA").unwrap();
    let mut s = String::new();
    write!(s, "{}", principal).expect("must succeed");
    assert_eq!(s, "arn:aws:iam::123456789012:group/path/test");

    let principal = PrincipalActor::role("aws", "123456789012", "/path/", "test", "AROAAAAAAAAAAAAAAAAA").unwrap();
    let mut s = String::new();
    write!(s, "{}", principal).expect("must succeed");
    assert_eq!(s, "arn:aws:iam::123456789012:role/path/test");

    let principal = PrincipalActor::assumed_role("aws", "123456789012", "test", "MyTestSession", 0, 3600).unwrap();
    let mut s = String::new();
    write!(s, "{}", principal).expect("must succeed");
    assert_eq!(s, "arn:aws:sts::123456789012:assumed-role/test/MyTestSession");
}

#[test]
fn check_iso8601_tz_formats() {
    let dt = DateTime::parse_from_iso8601("2001-02-03T15:16:17.000123456Z").unwrap();
    assert_eq!((dt.year(), dt.month(), dt.day()), (2001, 2, 3));
    assert_eq!((dt.hour(), dt.minute(), dt.second()), (15, 16, 17));
    assert_eq!(dt.nanosecond(), 123456);
    assert_eq!(dt.timezone().utc_minus_local(), 0);

    let dt = DateTime::parse_from_iso8601("2001-02-03T15:16:17.123Z").unwrap();
    assert_eq!((dt.year(), dt.month(), dt.day()), (2001, 2, 3));
    assert_eq!((dt.hour(), dt.minute(), dt.second()), (15, 16, 17));
    assert_eq!(dt.nanosecond(), 123000000);
    assert_eq!(dt.timezone().utc_minus_local(), 0);

    let dt = DateTime::parse_from_iso8601("2001-02-03T15:16:17.123456789123Z").unwrap();
    assert_eq!((dt.year(), dt.month(), dt.day()), (2001, 2, 3));
    assert_eq!((dt.hour(), dt.minute(), dt.second()), (15, 16, 17));
    assert_eq!(dt.nanosecond(), 123456789);
    assert_eq!(dt.timezone().utc_minus_local(), 0);

    let dt = DateTime::parse_from_iso8601("2001-02-03T15:16:17-02:45").unwrap();
    assert_eq!((dt.year(), dt.month(), dt.day()), (2001, 2, 3));
    assert_eq!((dt.hour(), dt.minute(), dt.second()), (15, 16, 17));
    assert_eq!(dt.timezone().utc_minus_local(), ((2 * 60) + 45) * 60);
}

macro_rules! expect_err {
    ($test:expr, $expected:ident) => {
        match $test {
            Ok(e) => panic!("Expected Err({}); got Ok({:?})", stringify!($expected), e),
            Err(e) => match e {
                SignatureError::$expected {
                    ..
                } => format!("{}", &e),
                _ => {
                    eprintln!("Expected {}; got {:?}: {}", stringify!($expected), &e, &e);
                    ($test).unwrap(); // panic
                    panic!();
                }
            },
        }
    };
}

#[test]
fn canonicalize_uri_path_empty() {
    assert_eq!(canonicalize_uri_path("").unwrap(), "/".to_string());
    assert_eq!(canonicalize_uri_path("/").unwrap(), "/".to_string());
}

#[test]
fn canonicalize_valid() {
    assert_eq!(canonicalize_uri_path("/hello/world").unwrap(), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path("/hello///world").unwrap(), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path("/hello/./world").unwrap(), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path("/hello/foo/../world").unwrap(), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path("/hello/%77%6F%72%6C%64").unwrap(), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path("/hello/w*rld").unwrap(), "/hello/w%2Arld".to_string());
    assert_eq!(canonicalize_uri_path("/hello/w%2arld").unwrap(), "/hello/w%2Arld".to_string());
    assert_eq!(canonicalize_uri_path("/hello/w+rld").unwrap(), "/hello/w%20rld".to_string());
}

#[test]
fn canonicalize_invalid() {
    let e = expect_err!(canonicalize_uri_path("hello/world"), InvalidURIPath);
    assert_eq!(e.to_string(), "Path is not absolute: hello/world");
    expect_err!(canonicalize_uri_path("/hello/../../world"), InvalidURIPath);
}

#[test]
fn normalize_valid1() {
    let result = normalize_query_parameters("Hello=World&foo=bar&baz=bomb&foo=2");
    let v = result.unwrap();
    let hello = v.get("Hello").unwrap();
    assert_eq!(hello.len(), 1);
    assert_eq!(hello[0], "World");

    let foo = v.get("foo").unwrap();
    assert_eq!(foo.len(), 2);
    assert_eq!(foo[0], "bar");
    assert_eq!(foo[1], "2");

    let baz = v.get("baz").unwrap();
    assert_eq!(baz.len(), 1);
    assert_eq!(baz[0], "bomb");
}

#[test]
fn normalize_empty() {
    let result = normalize_query_parameters("Hello=World&&foo=bar");
    let v = result.unwrap();
    let hello = v.get("Hello").unwrap();

    assert_eq!(hello.len(), 1);
    assert_eq!(hello[0], "World");

    let foo = v.get("foo").unwrap();
    assert_eq!(foo.len(), 1);
    assert_eq!(foo[0], "bar");

    assert!(v.get("").is_none());
}

#[test]
fn normalize_invalid_hex() {
    let e = expect_err!(normalize_uri_path_component("abcd%yy"), InvalidURIPath);
    assert!(e.starts_with("Invalid URI path:"));
    expect_err!(normalize_uri_path_component("abcd%yy"), InvalidURIPath);
    expect_err!(normalize_uri_path_component("abcd%0"), InvalidURIPath);
    expect_err!(normalize_uri_path_component("abcd%"), InvalidURIPath);
    assert_eq!(normalize_uri_path_component("abcd%65").unwrap(), "abcde");
}

const _AUTH_HEADER1: &str = "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;x-amz-date, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea";

#[test]
fn duplicate_headers() {
    let mut headers = HeaderMap::<HeaderValue>::with_capacity(3);
    headers.append("authorization", HeaderValue::from_static(_AUTH_HEADER1));
    headers.append("authorization", HeaderValue::from_static(_AUTH_HEADER1));
    headers.append("x-amz-date", HeaderValue::from_static("20150830T123600Z"));

    let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
    let request = Request {
        request_method: "GET".to_string(),
        uri,
        headers,
        body: None,
    };

    let e = expect_err!(request.get_authorization_header_parameters(), MultipleHeaderValues);
    assert_eq!(format!("{}", e), "Multiple values for header: authorization");
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

macro_rules! run_auth_test {
    ($auth_str:expr) => {
        run_auth_test_expect_kind!($auth_str, MalformedSignature)
    };
}

async fn run_auth_test_get_err_get_signing_key(
    kind: SigningKeyKind,
    _access_key_id: String,
    _session_token: Option<String>,
    req_date: Date<Utc>,
    region: String,
    service: String,
) -> Result<(PrincipalActor, SigningKey), SignatureError> {
    let k_secret = SigningKey {
        kind: SigningKeyKind::KSecret,
        key: b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
    };

    let principal = PrincipalActor::user("aws", "123456789012", "/", "test", "AIDAAAAAAAAAAAAAAAAA").unwrap();
    Ok((principal, k_secret.derive(kind, &req_date, region, service)))
}

async fn run_auth_test_get_err(auth_str: &str) -> SignatureError {
    let mut headers = HeaderMap::<HeaderValue>::with_capacity(3);
    headers.insert("authorization", HeaderValue::from_str(auth_str).unwrap());
    headers.insert("host", HeaderValue::from_static("example.amazonaws.com"));
    headers.insert("x-amz-date", HeaderValue::from_static("20150830T123600Z"));

    let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
    let request = Request {
        request_method: "GET".to_string(),
        uri,
        headers,
        body: None,
    };

    let test_date = Date::<Utc>::from_utc(NaiveDate::from_ymd(2015, 8, 30), Utc);
    let (_principal, k_signing) = run_auth_test_get_err_get_signing_key(
        SigningKeyKind::KSigning,
        "".to_string(),
        None,
        test_date,
        TEST_REGION.to_string(),
        TEST_SERVICE.to_string(),
    )
    .await
    .unwrap();

    sigv4_verify(&request, &k_signing, None, TEST_REGION, TEST_SERVICE).unwrap_err()
}

#[tokio::test]
#[test_log::test]
async fn test_missing_auth_parameters() {
    assert_eq!(
        run_auth_test!("AWS4-HMAC-SHA256 "),
        "Malformed signature: invalid Authorization header: missing parameters"
    );
}

#[tokio::test]
#[test_log::test]
async fn test_missing_auth_signed_headers() {
    assert_eq!(
        run_auth_test!(
            "\
AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"
        ),
        "Malformed signature: invalid Authorization header: missing SignedHeaders"
    );
}

#[tokio::test]
#[test_log::test]
async fn test_missing_auth_credential() {
    assert_eq!(
        run_auth_test!(
            "\
AWS4-HMAC-SHA256 \
SignedHeaders=host;x-amz-date, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"
        ),
        "Malformed signature: invalid Authorization header: missing Credential"
    );
}

#[tokio::test]
#[test_log::test]
async fn test_duplicate_auth_credential() {
    assert_eq!(
        run_auth_test!(
            "\
AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;x-amz-date, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"
        ),
        "Malformed signature: invalid Authorization header: duplicate field Credential"
    );
}

#[tokio::test]
#[test_log::test]
async fn test_missing_auth_signature() {
    assert_eq!(
        run_auth_test!(
            "\
AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;x-amz-date"
        ),
        "Malformed signature: invalid Authorization header: missing Signature"
    );
}

#[tokio::test]
#[test_log::test]
async fn test_missing_auth_eq() {
    assert_eq!(
        run_auth_test!(
            "\
AWS4-HMAC-SHA256 \
Credential/AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;x-amz-date, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"
        ),
        "Malformed signature: invalid Authorization header: missing '='"
    );
}

#[tokio::test]
#[test_log::test]
async fn test_noncanonical_signed_headers() {
    assert_eq!(
        run_auth_test!(
            "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=x-amz-date;host, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"
        ),
        "Malformed signature: SignedHeaders is not canonicalized"
    );
}

#[tokio::test]
#[test_log::test]
async fn test_wrong_auth_algorithm() {
    assert_eq!(run_auth_test_expect_kind!("AWS3-ZZZ Credential=12345", MissingHeader), "Missing header: authorization");
}

#[tokio::test]
#[test_log::test]
async fn test_multiple_algorithms() {
    let mut headers = HeaderMap::<HeaderValue>::with_capacity(2);
    headers.append("authorization", HeaderValue::from_static("Basic foobar"));
    headers.append(
        "authorization",
        HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678"),
    );

    let uri = Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap();
    let request = Request {
        request_method: "GET".to_string(),
        uri,
        headers,
        body: None,
    };

    let params = request.get_authorization_header_parameters().unwrap();
    assert_eq!(params.get("Credential").unwrap(), "1234");
    assert_eq!(params.get("SignedHeaders").unwrap(), "date;host");
    assert_eq!(params.get("Signature").unwrap(), "5678");
}

#[tokio::test]
#[test_log::test]
async fn duplicate_query_parameter() {
    let headers = HeaderMap::new();

    let request = Request {
        request_method: "GET".to_string(),
        uri: Uri::builder()
            .path_and_query(PathAndQuery::from_static("/?X-Amz-Signature=1234&X-Amz-Signature=1234"))
            .build()
            .unwrap(),
        headers,
        body: None,
    };

    let e = expect_err!(request.get_request_signature(), MultipleParameterValues);
    assert_eq!(format!("{}", e), "Multiple values for query parameter: X-Amz-Signature");
}

#[test]
#[test_log::test]
fn missing_header() {
    let mut headers = HeaderMap::<HeaderValue>::with_capacity(1);
    headers.insert("authorization", HeaderValue::from_static(""));

    let request = Request {
        request_method: "GET".to_string(),
        uri: Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap(),
        headers,
        body: None,
    };

    expect_err!(request.get_authorization_header_parameters(), MissingHeader);
}

#[test]
#[test_log::test]
fn missing_date() {
    let mut headers = HeaderMap::<HeaderValue>::with_capacity(2);
    headers.insert("authorization", HeaderValue::from_static(_AUTH_HEADER1));
    headers.insert("host", HeaderValue::from_static("localhost"));

    let request = Request {
        request_method: "GET".to_string(),
        uri: Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap(),
        headers,
        body: None,
    };

    let e = expect_err!(request.get_signed_headers(), MissingHeader);
    assert_eq!(format!("{}", e), "Missing header: x-amz-date");
}

#[test]
#[test_log::test]
fn invalid_date() {
    let mut headers = HeaderMap::<HeaderValue>::with_capacity(2);
    headers.insert("authorization", HeaderValue::from_static(_AUTH_HEADER1));
    headers.insert("date", HeaderValue::from_static("zzzzzzzzz"));

    let request = Request {
        request_method: "GET".to_string(),
        uri: Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap(),
        headers,
        body: None,
    };

    let e = expect_err!(request.get_request_timestamp(), MalformedHeader);
    assert_eq!(format!("{}", e), "Malformed header: Date is not a valid timestamp");

    let mut headers = HeaderMap::<HeaderValue>::with_capacity(2);
    headers.insert("authorization", HeaderValue::from_static(_AUTH_HEADER1));

    let request = Request {
        request_method: "GET".to_string(),
        uri: Uri::builder().path_and_query(PathAndQuery::from_static("/")).build().unwrap(),
        headers,
        body: None,
    };

    expect_err!(request.get_request_timestamp(), MissingHeader);

    let headers = HeaderMap::new();
    let request = Request {
        request_method: "GET".to_string(),
        uri: Uri::builder().path_and_query(PathAndQuery::from_static("/?X-Amz-Date=zzzz")).build().unwrap(),
        headers,
        body: None,
    };

    let e = expect_err!(request.get_request_timestamp(), MalformedQueryString);
    assert_eq!(format!("{}", e), "Malformed query parameter: X-Amz-Date is not a valid timestamp");
}

/// Check for query parameters without a value, e.g. ?Key2&
/// https://github.com/dacut/scratchstack-aws-signature/issues/2
#[test]
fn normalize_query_parameters_missing_value() {
    let result = normalize_query_parameters("Key1=Value1&Key2&Key3=Value3");
    assert!(result.is_ok());
    let result = result.unwrap();
    assert_eq!(result["Key1"], vec!["Value1"]);
    assert_eq!(result["Key2"], vec![""]);
    assert_eq!(result["Key3"], vec!["Value3"]);
}
