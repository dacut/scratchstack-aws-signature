use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::str::from_utf8;

extern crate aws_sig_verify;
use aws_sig_verify::{
    derive_key_from_secret_key, AWSSigV4, AWSSigV4Algorithm, Principal, Request, SignatureError, SigningKeyKind,
};

#[test]
fn get_header_key_duplicate_get_header_key_duplicate() {
    run("get-header-key-duplicate/get-header-key-duplicate");
}

#[test]
fn get_header_value_multiline_get_header_value_multiline() {
    run("get-header-value-multiline/get-header-value-multiline");
}

#[test]
fn get_header_value_order_get_header_value_order() {
    run("get-header-value-order/get-header-value-order");
}

#[test]
fn get_header_value_trim_get_header_value_trim() {
    run("get-header-value-trim/get-header-value-trim");
}

#[test]
fn get_unreserved_get_unreserved() {
    run("get-unreserved/get-unreserved");
}

#[test]
fn get_utf8_get_utf8() {
    run("get-utf8/get-utf8");
}

#[test]
fn get_vanilla_empty_query_key_get_vanilla_empty_query_key() {
    run("get-vanilla-empty-query-key/get-vanilla-empty-query-key");
}

#[test]
fn get_vanilla_query_order_key_case_get_vanilla_query_order_key_case() {
    run("get-vanilla-query-order-key-case/get-vanilla-query-order-key-case");
}

#[test]
fn get_vanilla_query_order_key_get_vanilla_query_order_key() {
    run("get-vanilla-query-order-key/get-vanilla-query-order-key");
}

#[test]
fn get_vanilla_query_order_value_get_vanilla_query_order_value() {
    run("get-vanilla-query-order-value/get-vanilla-query-order-value");
}

#[test]
fn get_vanilla_query_unreserved_get_vanilla_query_unreserved() {
    run("get-vanilla-query-unreserved/get-vanilla-query-unreserved");
}

#[test]
fn get_vanilla_query_get_vanilla_query() {
    run("get-vanilla-query/get-vanilla-query");
}

#[test]
fn get_vanilla_utf8_query_get_vanilla_utf8_query() {
    run("get-vanilla-utf8-query/get-vanilla-utf8-query");
}

#[test]
fn get_vanilla_get_vanilla() {
    run("get-vanilla/get-vanilla");
}

#[test]
fn normalize_path_get_relative_relative_get_relative_relative() {
    run("normalize-path/get-relative-relative/get-relative-relative");
}

#[test]
fn normalize_path_get_relative_get_relative() {
    run("normalize-path/get-relative/get-relative");
}

#[test]
fn normalize_path_get_slash_dot_slash_get_slash_dot_slash() {
    run("normalize-path/get-slash-dot-slash/get-slash-dot-slash");
}

#[test]
fn normalize_path_get_slash_pointless_dot_get_slash_pointless_dot() {
    run("normalize-path/get-slash-pointless-dot/get-slash-pointless-dot");
}

#[test]
fn normalize_path_get_slash_get_slash() {
    run("normalize-path/get-slash/get-slash");
}

#[test]
fn normalize_path_get_slashes_get_slashes() {
    run("normalize-path/get-slashes/get-slashes");
}

#[test]
fn normalize_path_get_space_get_space() {
    run("normalize-path/get-space/get-space");
}

#[test]
fn post_header_key_case_post_header_key_case() {
    run("post-header-key-case/post-header-key-case");
}

#[test]
fn post_header_key_sort_post_header_key_sort() {
    run("post-header-key-sort/post-header-key-sort");
}

#[test]
fn post_header_value_case_post_header_value_case() {
    run("post-header-value-case/post-header-value-case");
}

#[test]
fn post_sts_token_post_sts_header_after_post_sts_header_after() {
    run("post-sts-token/post-sts-header-after/post-sts-header-after");
}

#[test]
fn post_sts_token_post_sts_header_before_post_sts_header_before() {
    run("post-sts-token/post-sts-header-before/post-sts-header-before");
}

#[test]
fn post_vanilla_empty_query_value_post_vanilla_empty_query_value() {
    run("post-vanilla-empty-query-value/post-vanilla-empty-query-value");
}

#[test]
fn post_vanilla_query_post_vanilla_query() {
    run("post-vanilla-query/post-vanilla-query");
}

#[test]
fn post_vanilla_post_vanilla() {
    run("post-vanilla/post-vanilla");
}

#[test]
fn post_x_www_form_urlencoded_parameters_post_x_www_form_urlencoded_parameters() {
    run("post-x-www-form-urlencoded-parameters/post-x-www-form-urlencoded-parameters");
}

/*
This test is disabled for now -- it does not seem to encode the signed request
properly.

#[test]
fn post_x_www_form_urlencoded_post_x_www_form_urlencoded() {
    run("post-x-www-form-urlencoded/post-x-www-form-urlencoded");
}
*/

fn run(basename: &str) {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut req_path = PathBuf::new();
    req_path.push(manifest_dir);
    req_path.push("tests");
    req_path.push("aws-sig-v4-test-suite");
    req_path.push(basename);

    let mut sreq_path = PathBuf::new();
    sreq_path.push(&req_path);
    sreq_path.set_extension("sreq");

    let mut creq_path = PathBuf::new();
    creq_path.push(&req_path);
    creq_path.set_extension("creq");

    let mut sts_path = PathBuf::new();
    sts_path.push(&req_path);
    sts_path.set_extension("sts");

    let sreq = File::open(&sreq_path).expect(&format!("Failed to open {:?}", sreq_path));
    let mut sreq_r = BufReader::new(sreq);

    let mut method_line_full: String = String::new();
    sreq_r.read_line(&mut method_line_full).expect(&format!("No method line in {:?}", sreq_path));
    let method_line = method_line_full.trim_end();
    let muq_and_ver: Vec<&str> = method_line.rsplitn(2, " ").collect();
    assert_eq!(muq_and_ver.len(), 2, "muq_and_ver.len() != 2, method_line={}, {:?}", method_line, sreq_path);

    let muq_parts: Vec<&str> = muq_and_ver[1].splitn(2, " ").collect();
    assert_eq!(
        muq_parts.len(),
        2,
        "muq_parts.len() != 2, method_line={}, muq_and_ver={:?}, \
         muq_parts={:?}, {:?}",
        method_line,
        muq_and_ver,
        muq_parts,
        sreq_path
    );

    let method = muq_parts[0];
    let uri_and_query: Vec<&str> = muq_parts[1].splitn(2, "?").collect();
    let uri: String;
    let query: String;

    if uri_and_query.len() == 2 {
        uri = uri_and_query[0].to_string();
        query = uri_and_query[1].to_string();
    } else {
        uri = uri_and_query[0].to_string();
        query = "".to_string()
    }

    let mut headers: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    let mut line_full: String = String::new();
    let mut last_key: Option<String> = None;

    while let Ok(n_read) = sreq_r.read_line(&mut line_full) {
        if n_read <= 0 {
            break;
        }

        let line = line_full.trim_end();
        if line.len() == 0 {
            break;
        }

        let key;
        let value;

        if line.starts_with(" ") || line.starts_with("\t") {
            key = last_key.unwrap();
            value = line.trim_start();
        } else {
            let parts: Vec<&str> = line.splitn(2, ":").collect();
            assert_eq!(parts.len(), 2, "Malformed header line: {} in {:?}", line, sreq_path);

            key = parts[0].to_lowercase();
            value = parts[1].trim();
        }

        last_key = Some((&key).to_string());

        if let Some(ref mut existing) = headers.get_mut(&key) {
            existing.push(value.as_bytes().to_vec());
        } else {
            let mut value_list: Vec<Vec<u8>> = Vec::new();
            value_list.push(value.as_bytes().to_vec());
            headers.insert(key, value_list);
        }

        line_full.clear();
    }

    let mut body: Vec<u8> = Vec::new();
    sreq_r.read_to_end(&mut body).unwrap();

    let request = Request {
        request_method: method.to_string(),
        uri_path: uri,
        query_string: query,
        headers: headers,
        body: body,
        region: "us-east-1".to_string(),
        service: "service".to_string(),
    };

    let mut creq = File::open(&creq_path).expect(&format!("Failed to open {:?}", creq_path));
    let mut expected_canonical_request = Vec::new();
    creq.read_to_end(&mut expected_canonical_request).unwrap();
    expected_canonical_request.retain(|c| *c != b'\r');

    let mut sts = File::open(&sts_path).expect(&format!("Failed to open {:?}", sts_path));
    let mut expected_string_to_sign = Vec::new();
    sts.read_to_end(&mut expected_string_to_sign).unwrap();
    expected_string_to_sign.retain(|c| *c != b'\r');

    let sig = AWSSigV4::new();

    let canonical_request =
        sig.get_canonical_request(&request).expect(&format!("Failed to get canonical request: {:?}", sreq_path));
    let string_to_sign =
        sig.get_string_to_sign(&request).expect(&format!("Failed to get string to sign: {:?}", sreq_path));

    assert_eq!(from_utf8(&canonical_request), from_utf8(&expected_canonical_request), "Failed on {:?}", sreq_path);
    assert_eq!(from_utf8(&string_to_sign), from_utf8(&expected_string_to_sign), "Failed on {:?}", sreq_path);

    sig.verify(&request, SigningKeyKind::KSecret, get_signing_key, None)
        .expect(&format!("Signature verification failed: {:?}", sreq_path));

    sig.verify(&request, SigningKeyKind::KDate, get_signing_key, None)
        .expect(&format!("Signature verification failed: {:?}", sreq_path));

    sig.verify(&request, SigningKeyKind::KRegion, get_signing_key, None)
        .expect(&format!("Signature verification failed: {:?}", sreq_path));

    sig.verify(&request, SigningKeyKind::KService, get_signing_key, None)
        .expect(&format!("Signature verification failed: {:?}", sreq_path));

    sig.verify(&request, SigningKeyKind::KSigning, get_signing_key, None)
        .expect(&format!("Signature verification failed: {:?}", sreq_path));
}

fn get_signing_key(
    kind: SigningKeyKind,
    _access_key_id: &str,
    _session_token: Option<&str>,
    req_date: &str,
    region: &str,
    service: &str,
) -> Result<(Principal, Vec<u8>), SignatureError> {
    let secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".as_bytes();
    let principal = Principal::create_user(
        "aws".to_string(),
        "123456789012".to_string(),
        "/".to_string(),
        "test".to_string(),
        "AIDAIAAAAAAAAAAAAAAAA".to_string(),
    );

    let signing_key = derive_key_from_secret_key(secret_key, kind, req_date, region, service);
    Ok((principal, signing_key))
}
