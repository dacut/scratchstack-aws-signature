use super::signature::{
    canonicalize_uri_path, normalize_query_parameters, normalize_uri_path_component, AWSSigV4, AWSSigV4Algorithm,
    ErrorKind, Principal, Request, SignatureError, SigningKeyKind,
};

use super::chronoutil::ParseISO8601;
use chrono::{DateTime, Datelike, Timelike};
use std::collections::HashMap;
use std::fmt::Write;

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
    let principal = Principal::create_user(
        "aws".to_string(),
        "123456789012".to_string(),
        "/".to_string(),
        "test".to_string(),
        "AIDAIAAAAAAAAAAAAAAAA".to_string(),
    );
    let mut s = String::new();
    write!(s, "{}", principal).expect("must succeed");
    assert_eq!(s, "arn:aws:iam::123456789012:user/test");

    let principal = Principal::create_user(
        "aws".to_string(),
        "123456789012".to_string(),
        "/path/".to_string(),
        "test".to_string(),
        "AIDAIAAAAAAAAAAAAAAAA".to_string(),
    );
    let mut s = String::new();
    write!(s, "{}", principal).expect("must succeed");
    assert_eq!(s, "arn:aws:iam::123456789012:user/path/test");

    let principal = Principal::create_group(
        "aws".to_string(),
        "123456789012".to_string(),
        "/path/".to_string(),
        "test".to_string(),
        "AIGAIAAAAAAAAAAAAAAAA".to_string(),
    );
    let mut s = String::new();
    write!(s, "{}", principal).expect("must succeed");
    assert_eq!(s, "arn:aws:iam::123456789012:group/path/test");

    let principal = Principal::create_role(
        "aws".to_string(),
        "123456789012".to_string(),
        "/path/".to_string(),
        "test".to_string(),
        "AIGAIAAAAAAAAAAAAAAAA".to_string(),
    );
    let mut s = String::new();
    write!(s, "{}", principal).expect("must succeed");
    assert_eq!(s, "arn:aws:iam::123456789012:role/path/test");

    let principal = Principal::create_assumed_role(
        "aws".to_string(),
        "123456789012".to_string(),
        "/path/".to_string(),
        "test".to_string(),
        "MyTestSession".to_string(),
    );
    let mut s = String::new();
    write!(s, "{}", principal).expect("must succeed");
    assert_eq!(s, "arn:aws:iam::123456789012:assumed-role/path/test/MyTestSession");
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
    ($test:expr, $expected:pat) => {
        match $test {
            Ok(e) => panic!("Expected Err({}); got Ok({:?})", stringify!($expected), e),
            Err(e) => match &e.kind {
                $expected => format!("{}", &e),
                _ => {
                    eprintln!("Expected {}; got ErrorKind::{:?}: {}", stringify!($expected), &e.kind, &e);
                    ($test).unwrap(); // panic
                    panic!();
                }
            },
        }
    };
}

#[test]
fn canonicalize_uri_path_empty() {
    assert_eq!(canonicalize_uri_path(&"").unwrap(), "/".to_string());
    assert_eq!(canonicalize_uri_path(&"/").unwrap(), "/".to_string());
}

#[test]
fn canonicalize_valid() {
    assert_eq!(canonicalize_uri_path(&"/hello/world").unwrap(), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello///world").unwrap(), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/./world").unwrap(), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/foo/../world").unwrap(), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/%77%6F%72%6C%64").unwrap(), "/hello/world".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/w*rld").unwrap(), "/hello/w%2Arld".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/w%2arld").unwrap(), "/hello/w%2Arld".to_string());
    assert_eq!(canonicalize_uri_path(&"/hello/w+rld").unwrap(), "/hello/w%20rld".to_string());
}

#[test]
fn canonicalize_invalid() {
    let e = expect_err!(canonicalize_uri_path(&"hello/world"), ErrorKind::InvalidURIPath);
    assert!(format!("{}", e).starts_with("Invalid URI path:"));

    expect_err!(canonicalize_uri_path(&"/hello/../../world"), ErrorKind::InvalidURIPath);
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
    let e = expect_err!(normalize_uri_path_component("abcd%yy"), ErrorKind::InvalidURIPath);
    assert!(format!("{}", e).starts_with("Invalid URI path:"));

    expect_err!(normalize_uri_path_component("abcd%yy"), ErrorKind::InvalidURIPath);

    expect_err!(normalize_uri_path_component("abcd%0"), ErrorKind::InvalidURIPath);

    expect_err!(normalize_uri_path_component("abcd%"), ErrorKind::InvalidURIPath);

    assert_eq!(normalize_uri_path_component("abcd%65").unwrap(), "abcde");
}

const _AUTH_HEADER1: &str = "AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;x-amz-date, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea";

#[test]
fn duplicate_headers() {
    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        vec![_AUTH_HEADER1.as_bytes().to_vec(), _AUTH_HEADER1.as_bytes().to_vec()],
    );
    headers.insert("x-amz-date".to_string(), vec!["20150830T123600Z".as_bytes().to_vec()]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: "".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    let e = expect_err!(sig.get_authorization_header_parameters(&request), ErrorKind::MultipleHeaderValues);
    assert_eq!(format!("{}", e), "Multiple values for header: authorization");
}

macro_rules! run_auth_test_expect_kind {
    ($auth_str:expr, $expected:pat) => {{
        let e = run_auth_test_get_err($auth_str);
        match &e.kind {
            $expected => format!("{}", e),
            _ => panic!("Expected {}; got ErrorKind::{:?}: {}", stringify!($expected), &e.kind, &e),
        }
    }};
}

macro_rules! run_auth_test {
    ($auth_str:expr) => {
        run_auth_test_expect_kind!($auth_str, ErrorKind::MalformedSignature)
    };
}

fn run_auth_test_get_err(auth_str: &str) -> SignatureError {
    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers.insert("authorization".to_string(), vec![auth_str.as_bytes().to_vec()]);
    headers.insert("host".to_string(), vec!["example.amazonaws.com".as_bytes().to_vec()]);
    headers.insert("x-amz-date".to_string(), vec!["20150830T123600Z".as_bytes().to_vec()]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: "".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    let get_signing_key = |kind: SigningKeyKind,
                           access_key_id: &str,
                           _session_token: Option<&str>,
                           _req_date_opt: Option<&str>,
                           _region_opt: Option<&str>,
                           _service_opt: Option<&str>| {
        let k_secret = "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".as_bytes();
        let principal = Principal::create_user(
            "aws".to_string(),
            "123456789012".to_string(),
            "/".to_string(),
            "test".to_string(),
            "AIDAIAAAAAAAAAAAAAAAA".to_string(),
        );

        match kind {
            SigningKeyKind::KSecret => Ok((principal, k_secret.to_vec())),
            _ => Err(SignatureError::new(ErrorKind::UnknownAccessKey, access_key_id)),
        }
    };

    sig.verify(&request, SigningKeyKind::KSecret, get_signing_key, None).unwrap_err()
}

#[test]
fn test_missing_auth_parameters() {
    assert_eq!(
        run_auth_test!("AWS4-HMAC-SHA256 "),
        "Malformed signature: invalid Authorization header: missing parameters"
    );
}

#[test]
fn test_missing_auth_signed_headers() {
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

#[test]
fn test_missing_auth_credential() {
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

#[test]
fn test_duplicate_auth_credential() {
    assert_eq!(
        run_auth_test!(
            "\
AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;x-amz-date, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"
        ),
        "Malformed signature: invalid Authorization header: duplicate key Credential"
    );
}

#[test]
fn test_missing_auth_signature() {
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

#[test]
fn test_missing_auth_eq() {
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

#[test]
fn test_noncanonical_signed_headers() {
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

#[test]
fn test_wrong_auth_algorithm() {
    assert_eq!(
        run_auth_test_expect_kind!("AWS3-ZZZ Credential=12345", ErrorKind::MissingHeader),
        "Missing header: authorization"
    );
}

#[test]
fn test_multiple_algorithms() {
    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        vec![
            b"Basic foobar".to_vec(),
            b"AWS4-HMAC-SHA256 Credential=1234, SignedHeaders=date;host, Signature=5678".to_vec(),
        ],
    );

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: "".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();
    let params = sig.get_authorization_header_parameters(&request).unwrap();
    assert_eq!(params.get("Credential").unwrap(), "1234");
    assert_eq!(params.get("SignedHeaders").unwrap(), "date;host");
    assert_eq!(params.get("Signature").unwrap(), "5678");
}

#[test]
fn duplicate_query_parameter() {
    let headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "X-Amz-Signature=1234&X-Amz-Signature=1234".to_string(),
        headers: headers,
        body: "".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    let e = expect_err!(sig.get_request_signature(&request), ErrorKind::MultipleParameterValues);
    assert_eq!(format!("{}", e), "Multiple values for query parameter: X-Amz-Signature");
}

#[test]
fn non_utf8_header() {
    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        vec![vec![
            b'A', b'W', b'S', b'4', b'-', b'H', b'M', b'A', b'C', b'-', b'S', b'H', b'A', b'2', b'5', b'6', b' ', 0x80,
            0x80,
        ]],
    );

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: "".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    expect_err!(sig.get_authorization_header_parameters(&request), ErrorKind::MalformedHeader);
}

#[test]
fn missing_header() {
    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers.insert("authorization".to_string(), vec![]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: "".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    expect_err!(sig.get_authorization_header_parameters(&request), ErrorKind::MissingHeader);
}

#[test]
fn missing_date() {
    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers.insert("authorization".to_string(), vec![_AUTH_HEADER1.as_bytes().to_vec()]);
    headers.insert("host".to_string(), vec!["localhost".as_bytes().to_vec()]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: "".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    let e = expect_err!(sig.get_signed_headers(&request), ErrorKind::MissingHeader);
    assert_eq!(format!("{}", e), "Missing header: x-amz-date");
}

#[test]
fn invalid_date() {
    let mut headers1: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers1.insert("authorization".to_string(), vec![_AUTH_HEADER1.as_bytes().to_vec()]);
    headers1.insert("date".to_string(), vec!["zzzzzzzzz".as_bytes().to_vec()]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers1,
        body: "".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();
    let e = expect_err!(sig.get_request_timestamp(&request), ErrorKind::MalformedHeader);
    assert_eq!(format!("{}", e), "Malformed header: date");

    let mut headers2: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers2.insert("authorization".to_string(), vec![_AUTH_HEADER1.as_bytes().to_vec()]);
    headers2.insert("date".to_string(), vec![]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers2,
        body: "".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();
    expect_err!(sig.get_request_timestamp(&request), ErrorKind::MissingHeader);

    let headers3: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "X-Amz-Date=zzzz".to_string(),
        headers: headers3,
        body: "".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();
    let e = expect_err!(sig.get_request_timestamp(&request), ErrorKind::MalformedParameter);
    assert_eq!(format!("{}", e), "Malformed query parameter: X-Amz-Date");
}
