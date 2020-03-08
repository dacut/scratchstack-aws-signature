use super::signature::{
    AWSSigV4, AWSSigV4Algorithm, ErrorKind, Request, SigningKeyKind,
    SignatureError, canonicalize_uri_path, normalize_query_parameters,
    normalize_uri_path_component,
};

use chrono::{DateTime, Datelike, Timelike};
use super::chronoutil::ParseISO8601;
use std::collections::HashMap;

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
            Ok(e) => panic!(format!(
                "Expected Err({}); got Ok({:?})",
                stringify!($expected),
                e
            )),
            Err(e) => match e.kind {
                $expected => e,
                _ => {
                    eprintln!(
                        "Expected {}; got ErrorKind::{:?}: {}",
                        stringify!($expected), e.kind, e);
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
    assert_eq!(
        canonicalize_uri_path(&"/hello/world").unwrap(),
        "/hello/world".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello///world").unwrap(),
        "/hello/world".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/./world").unwrap(),
        "/hello/world".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/foo/../world").unwrap(),
        "/hello/world".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/%77%6F%72%6C%64").unwrap(),
        "/hello/world".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/w*rld").unwrap(),
        "/hello/w%2Arld".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/w%2arld").unwrap(),
        "/hello/w%2Arld".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/w+rld").unwrap(),
        "/hello/w%20rld".to_string()
    );
}

#[test]
fn canonicalize_invalid() {
    let e = expect_err!(
        canonicalize_uri_path(&"hello/world"),
        ErrorKind::InvalidURIPath
    );
    assert!(format!("{}", e).starts_with("Invalid URI path:"));

    expect_err!(
        canonicalize_uri_path(&"/hello/../../world"),
        ErrorKind::InvalidURIPath
    );
}

#[test]
fn normalize_valid1() {
    let result =
        normalize_query_parameters("Hello=World&foo=bar&baz=bomb&foo=2");
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
    let e = expect_err!(
        normalize_uri_path_component("abcd%yy"),
        ErrorKind::InvalidURIPath
    );
    assert!(format!("{}", e).starts_with("Invalid URI path:"));

    expect_err!(
        normalize_uri_path_component("abcd%yy"),
        ErrorKind::InvalidURIPath
    );

    expect_err!(
        normalize_uri_path_component("abcd%0"),
        ErrorKind::InvalidURIPath
    );

    expect_err!(
        normalize_uri_path_component("abcd%"),
        ErrorKind::InvalidURIPath
    );

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
        vec![_AUTH_HEADER1.as_bytes().to_vec(), _AUTH_HEADER1.as_bytes().to_vec()]);
    headers.insert(
        "x-amz-date".to_string(),
        vec!["20150830T123600Z".as_bytes().to_vec()]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: &"".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    let e = expect_err!(
        sig.get_authorization_header_parameters(&request),
        ErrorKind::MultipleHeaderValues);
    assert_eq!(format!("{}", e), "Multiple values for header: authorization");
}

fn run_auth_test(auth_str: &str) -> String {
    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        vec![auth_str.as_bytes().to_vec()]);
    headers.insert(
        "host".to_string(),
        vec!["example.amazonaws.com".as_bytes().to_vec()]);
    headers.insert(
        "x-amz-date".to_string(),
        vec!["20150830T123600Z".as_bytes().to_vec()]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: &"".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    let get_signing_key = |
        kind: &SigningKeyKind,
        access_key_id: &str,
        _session_token: Option<&str>,
        _req_date_opt: Option<&str>,
        _region_opt: Option<&str>,
        _service_opt: Option<&str>
    | {
        let k_secret = "AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".as_bytes();
        match kind {
            SigningKeyKind::KSecret => Ok(k_secret.to_vec()),
            _ => Err(SignatureError::new(
                ErrorKind::UnknownAccessKey, access_key_id))
        }
    };

    let e = expect_err!(
        sig.verify(&request, &SigningKeyKind::KSecret, &get_signing_key, None),
        ErrorKind::MalformedSignature);

    format!("{}", e)
}

#[test]
fn test_missing_auth_signed_headers() {
    assert_eq!(run_auth_test("\
AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"),
        "Malformed signature: invalid Authorization header: missing SignedHeaders");
}

#[test]
fn test_missing_auth_credential() {
    assert_eq!(run_auth_test("\
AWS4-HMAC-SHA256 \
SignedHeaders=host;x-amz-date, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"),
        "Malformed signature: invalid Authorization header: missing Credential");
}

#[test]
fn test_duplicate_auth_credential() {
    assert_eq!(run_auth_test("\
AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;x-amz-date, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"),
        "Malformed signature: invalid Authorization header: duplicate key Credential");
}

#[test]
fn test_missing_auth_signature() {
    assert_eq!(run_auth_test("\
AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;x-amz-date"),
        "Malformed signature: invalid Authorization header: missing Signature");
}

#[test]
fn test_missing_auth_eq() {
    assert_eq!(run_auth_test("\
AWS4-HMAC-SHA256 \
Credential/AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=host;x-amz-date, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"),
        "Malformed signature: invalid Authorization header: missing '='");
}

#[test]
fn test_noncanonical_signed_headers() {
    assert_eq!(run_auth_test("AWS4-HMAC-SHA256 \
Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
SignedHeaders=x-amz-date;host, \
Signature=c9d5ea9f3f72853aea855b47ea873832890dbdd183b4468f858259531a5138ea"),
        "Malformed signature: SignedHeaders is not canonicalized");
}

#[test]
fn duplicate_query_parameter() {
    let headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "X-Amz-Signature=1234&X-Amz-Signature=1234".to_string(),
        headers: headers,
        body: &"".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    let e = expect_err!(
        sig.get_request_signature(&request),
        ErrorKind::MultipleParameterValues);
    assert_eq!(format!("{}", e), "Multiple values for query parameter: X-Amz-Signature");
}


#[test]
fn non_utf8_header() {
    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        vec![vec![0x80, 0x80]]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: &"".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    expect_err!(
        sig.get_authorization_header_parameters(&request),
        ErrorKind::MalformedHeader);
}

#[test]
fn missing_header() {
    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        vec![]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: &"".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    expect_err!(
        sig.get_authorization_header_parameters(&request),
        ErrorKind::MissingHeader);
}

#[test]
fn missing_date() {
    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        vec![_AUTH_HEADER1.as_bytes().to_vec()]);
    headers.insert(
        "host".to_string(),
        vec!["localhost".as_bytes().to_vec()]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers,
        body: &"".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();

    let e = expect_err!(
        sig.get_signed_headers(&request),
        ErrorKind::MissingHeader);
    assert_eq!(format!("{}", e), "Missing header: x-amz-date");
}

#[test]
fn invalid_date() {
    let mut headers1: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers1.insert(
        "authorization".to_string(),
        vec![_AUTH_HEADER1.as_bytes().to_vec()]);
    headers1.insert(
        "date".to_string(),
        vec!["zzzzzzzzz".as_bytes().to_vec()]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers1,
        body: &"".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();
    let e = expect_err!(
        sig.get_request_timestamp(&request),
        ErrorKind::MalformedHeader);
    assert_eq!(format!("{}", e), "Malformed header: date");

    let mut headers2: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    headers2.insert(
        "authorization".to_string(),
        vec![_AUTH_HEADER1.as_bytes().to_vec()]);
    headers2.insert(
        "date".to_string(),
        vec![]);

    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "".to_string(),
        headers: headers2,
        body: &"".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();
    expect_err!(
        sig.get_request_timestamp(&request),
        ErrorKind::MissingHeader);

    let headers3: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    let request = Request {
        request_method: "GET".to_string(),
        uri_path: "/".to_string(),
        query_string: "X-Amz-Date=zzzz".to_string(),
        headers: headers3,
        body: &"".as_bytes().to_vec(),
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let sig = AWSSigV4::new();
    let e = expect_err!(
        sig.get_request_timestamp(&request),
        ErrorKind::MalformedParameter);
    assert_eq!(format!("{}", e), "Malformed query parameter: X-Amz-Date");
}