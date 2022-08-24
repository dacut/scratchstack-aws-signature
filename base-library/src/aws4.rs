use chrono::{Date, DateTime, Duration, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use http::{
    header::{HeaderMap, HeaderName, HeaderValue},
    uri::{PathAndQuery, Uri},
};
use log::debug;
use scratchstack_aws_principal::PrincipalActor;
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader, Read},
    path::PathBuf,
    str::from_utf8,
};
use tower::Service;

use crate::{get_signing_key_fn, sigv4_verify_at, Request, SignatureError, SigningKey, SigningKeyKind};
use test_env_log;

const TEST_REGION: &str = "us-east-1";
const TEST_SERVICE: &str = "service";

#[tokio::test]
#[test_env_log::test]
async fn get_header_key_duplicate_get_header_key_duplicate() {
    run("get-header-key-duplicate/get-header-key-duplicate").await;
}

// Canonical request is contrary to RFC 2616
// #[tokio::test]
// #[test_env_log::test]
// async fn get_header_value_multiline_get_header_value_multiline() {
//     run("get-header-value-multiline/get-header-value-multiline").await;
// }

#[tokio::test]
#[test_env_log::test]
async fn get_header_value_order_get_header_value_order() {
    run("get-header-value-order/get-header-value-order").await;
}

#[tokio::test]
#[test_env_log::test]
async fn get_header_value_trim_get_header_value_trim() {
    run("get-header-value-trim/get-header-value-trim").await;
}

#[tokio::test]
#[test_env_log::test]
async fn get_unreserved_get_unreserved() {
    run("get-unreserved/get-unreserved").await;
}

// This encoding issue is taken care of by the frontend.
// #[tokio::test]
// #[test_env_log::test]
// async fn get_utf8_get_utf8() {
//     run("get-utf8/get-utf8").await;
// }

#[tokio::test]
#[test_env_log::test]
async fn get_vanilla_empty_query_key_get_vanilla_empty_query_key() {
    run("get-vanilla-empty-query-key/get-vanilla-empty-query-key").await;
}

#[tokio::test]
#[test_env_log::test]
async fn get_vanilla_query_order_key_case_get_vanilla_query_order_key_case() {
    run("get-vanilla-query-order-key-case/get-vanilla-query-order-key-case").await;
}

#[tokio::test]
#[test_env_log::test]
async fn get_vanilla_query_order_key_get_vanilla_query_order_key() {
    run("get-vanilla-query-order-key/get-vanilla-query-order-key").await;
}

#[tokio::test]
#[test_env_log::test]
async fn get_vanilla_query_order_value_get_vanilla_query_order_value() {
    run("get-vanilla-query-order-value/get-vanilla-query-order-value").await;
}

#[tokio::test]
#[test_env_log::test]
async fn get_vanilla_query_unreserved_get_vanilla_query_unreserved() {
    run("get-vanilla-query-unreserved/get-vanilla-query-unreserved").await;
}

#[tokio::test]
#[test_env_log::test]
async fn get_vanilla_query_get_vanilla_query() {
    run("get-vanilla-query/get-vanilla-query").await;
}

// This encoding issue is taken care of/rejected by the frontend.
// #[tokio::test]
// #[test_env_log::test]
// async fn get_vanilla_utf8_query_get_vanilla_utf8_query() {
//     run("get-vanilla-utf8-query/get-vanilla-utf8-query").await;
// }

#[tokio::test]
#[test_env_log::test]
async fn get_vanilla_get_vanilla() {
    run("get-vanilla/get-vanilla").await;
}

#[tokio::test]
#[test_env_log::test]
async fn normalize_path_get_relative_relative_get_relative_relative() {
    run("normalize-path/get-relative-relative/get-relative-relative").await;
}

#[tokio::test]
#[test_env_log::test]
async fn normalize_path_get_relative_get_relative() {
    run("normalize-path/get-relative/get-relative").await;
}

#[tokio::test]
#[test_env_log::test]
async fn normalize_path_get_slash_dot_slash_get_slash_dot_slash() {
    run("normalize-path/get-slash-dot-slash/get-slash-dot-slash").await;
}

#[tokio::test]
#[test_env_log::test]
async fn normalize_path_get_slash_pointless_dot_get_slash_pointless_dot() {
    run("normalize-path/get-slash-pointless-dot/get-slash-pointless-dot").await;
}

#[tokio::test]
#[test_env_log::test]
async fn normalize_path_get_slash_get_slash() {
    run("normalize-path/get-slash/get-slash").await;
}

#[tokio::test]
#[test_env_log::test]
async fn normalize_path_get_slashes_get_slashes() {
    run("normalize-path/get-slashes/get-slashes").await;
}

// This encoding issue is taken care of by the HTTP frontend.
// #[tokio::test]
// #[test_env_log::test]
// async fn normalize_path_get_space_get_space() {
//     run("normalize-path/get-space/get-space").await;
// }

#[tokio::test]
#[test_env_log::test]
async fn post_header_key_case_post_header_key_case() {
    run("post-header-key-case/post-header-key-case").await;
}

#[tokio::test]
#[test_env_log::test]
async fn post_header_key_sort_post_header_key_sort() {
    run("post-header-key-sort/post-header-key-sort").await;
}

#[tokio::test]
#[test_env_log::test]
async fn post_header_value_case_post_header_value_case() {
    run("post-header-value-case/post-header-value-case").await;
}

#[tokio::test]
#[test_env_log::test]
async fn post_sts_token_post_sts_header_after_post_sts_header_after() {
    run("post-sts-token/post-sts-header-after/post-sts-header-after").await;
}

#[tokio::test]
#[test_env_log::test]
async fn post_sts_token_post_sts_header_before_post_sts_header_before() {
    run("post-sts-token/post-sts-header-before/post-sts-header-before").await;
}

#[tokio::test]
#[test_env_log::test]
async fn post_vanilla_empty_query_value_post_vanilla_empty_query_value() {
    run("post-vanilla-empty-query-value/post-vanilla-empty-query-value").await;
}

#[tokio::test]
#[test_env_log::test]
async fn post_vanilla_query_post_vanilla_query() {
    run("post-vanilla-query/post-vanilla-query").await;
}

#[tokio::test]
#[test_env_log::test]
async fn post_vanilla_post_vanilla() {
    run("post-vanilla/post-vanilla").await;
}

#[tokio::test]
#[test_env_log::test]
async fn post_x_www_form_urlencoded_parameters_post_x_www_form_urlencoded_parameters() {
    run("post-x-www-form-urlencoded-parameters/post-x-www-form-urlencoded-parameters").await;
}

/*
This test is disabled for now -- it does not seem to encode the signed request
properly.

#[tokio::test]
#[test_env_log::test]
async fn post_x_www_form_urlencoded_post_x_www_form_urlencoded() {
    run("post-x-www-form-urlencoded/post-x-www-form-urlencoded").await;
}
*/

async fn run(basename: &str) {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut req_path = PathBuf::new();
    req_path.push(manifest_dir);
    req_path.push("src");
    req_path.push("aws-sig-v4-test-suite");
    req_path.push(basename);

    // The signed request calculated by AWS for verification.
    let mut sreq_path = PathBuf::new();
    sreq_path.push(&req_path);
    sreq_path.set_extension("sreq");

    // Read the signed request file and generate our request format from it.
    let sreq = File::open(&sreq_path).expect(&format!("Failed to open {:?}", sreq_path));
    let request = parse_file(sreq, &sreq_path);

    // The canonical request calculated by AWS for verification.
    let mut creq_path = PathBuf::new();
    creq_path.push(&req_path);
    creq_path.set_extension("creq");

    let mut creq = File::open(&creq_path).expect(&format!("Failed to open {:?}", creq_path));
    let mut expected_canonical_request = Vec::new();
    creq.read_to_end(&mut expected_canonical_request).unwrap();
    expected_canonical_request.retain(|c| *c != b'\r'); // Remove carriage returns (not newlines)

    // The string-to-sign calculated by AWS for verification.
    let mut sts_path = PathBuf::new();
    sts_path.push(&req_path);
    sts_path.set_extension("sts");

    let mut sts = File::open(&sts_path).expect(&format!("Failed to open {:?}", sts_path));
    let mut expected_string_to_sign = Vec::new();
    sts.read_to_end(&mut expected_string_to_sign).unwrap();
    expected_string_to_sign.retain(|c| *c != b'\r'); // Remove carriage returns (not newlines)

    // Compare the canonical request we calculate vs that from AWS.
    let canonical_request =
        request.get_canonical_request().expect(&format!("Failed to get canonical request: {:?}", sreq_path));
    assert_eq!(from_utf8(&canonical_request), from_utf8(&expected_canonical_request), "Failed on {:?}", sreq_path);

    // Compare the string-to-sign we calculate vs that from AWS.
    let string_to_sign = request
        .get_string_to_sign(TEST_REGION, TEST_SERVICE)
        .expect(&format!("Failed to get string to sign: {:?}", sreq_path));
    assert_eq!(from_utf8(&string_to_sign), from_utf8(&expected_string_to_sign), "Failed on {:?}", sreq_path);

    // Create a service for getting the signing key.
    let mut signing_key_svc = get_signing_key_fn(get_signing_key);

    let test_time = DateTime::<Utc>::from_utc(
        NaiveDateTime::new(NaiveDate::from_ymd(2015, 8, 30), NaiveTime::from_hms(12, 36, 0)),
        Utc,
    );
    let mismatch = Some(Duration::seconds(300));

    // Create a GetSigningKeyRequest from our existing request.
    let req_date = request.get_request_date().unwrap();
    let gsk_req = request.to_get_signing_key_request(SigningKeyKind::KSecret, TEST_REGION, TEST_SERVICE).unwrap();
    let (_principal, k_secret) = signing_key_svc.call(gsk_req).await.unwrap();

    sigv4_verify_at(&request, &k_secret, &test_time, mismatch, TEST_REGION, TEST_SERVICE)
        .expect(&format!("Signature verification failed: {:?}", sreq_path));

    let k_date = k_secret.to_kdate_key(&req_date);
    sigv4_verify_at(&request, &k_date, &test_time, mismatch, TEST_REGION, TEST_SERVICE)
        .expect(&format!("Signature verification failed: {:?}", sreq_path));

    let k_region = k_date.to_kregion_key(&req_date, TEST_REGION);
    sigv4_verify_at(&request, &k_region, &test_time, mismatch, TEST_REGION, TEST_SERVICE)
        .expect(&format!("Signature verification failed: {:?}", sreq_path));

    let k_service = k_region.to_kservice_key(&req_date, TEST_REGION, TEST_SERVICE);
    sigv4_verify_at(&request, &k_service, &test_time, mismatch, TEST_REGION, TEST_SERVICE)
        .expect(&format!("Signature verification failed: {:?}", sreq_path));

    let k_signing = k_service.to_ksigning_key(&req_date, TEST_REGION, TEST_SERVICE);
    sigv4_verify_at(&request, &k_signing, &test_time, mismatch, TEST_REGION, TEST_SERVICE)
        .expect(&format!("Signature verification failed: {:?}", sreq_path));
}

async fn get_signing_key(
    kind: SigningKeyKind,
    _access_key_id: String,
    _session_token: Option<String>,
    req_date: Date<Utc>,
    region: String,
    service: String,
) -> Result<(PrincipalActor, SigningKey), SignatureError> {
    let k_secret = SigningKey {
        kind: SigningKeyKind::KSecret,
        key: b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_vec(),
    };

    let principal = PrincipalActor::user("aws", "123456789012", "/", "test", "AIDAAAAAAAAAAAAAAAAA").unwrap();
    Ok((principal, k_secret.derive(kind, &req_date, region, service)))
}

fn parse_file(f: File, filename: &PathBuf) -> Request {
    let mut reader = BufReader::new(f);

    let mut method_line_full: String = String::new();
    reader.read_line(&mut method_line_full).expect(&format!("No method line in {:?}", filename));
    let method_line: String = method_line_full.trim_end().to_string();
    let muq_and_ver: Vec<&str> = method_line.rsplitn(2, " ").collect();
    assert_eq!(muq_and_ver.len(), 2, "muq_and_ver.len() != 2, method_line={}, {:?}", method_line, filename);
    let muq = muq_and_ver[1].to_string();

    let muq_parts: Vec<&str> = muq.splitn(2, " ").collect();
    assert_eq!(
        muq_parts.len(),
        2,
        "muq_parts.len() != 2, method_line={:#?}, muq={:#?} muq_and_ver={:?}, \
         muq_parts={:?}, {:?}",
        method_line,
        muq,
        muq_and_ver,
        muq_parts,
        filename
    );

    let method = muq_parts[0].to_string();
    let path_query_str = muq_parts[1].to_string();
    let pq = match PathAndQuery::from_maybe_shared(path_query_str.clone()) {
        Ok(pq) => pq,
        Err(e) => panic!("Invalid path/query str: {:#?}: {:?}", path_query_str, e),
    };
    let uri = Uri::builder().path_and_query(pq).build().unwrap();

    let mut headers = HeaderMap::new();
    let mut line_full: String = String::new();
    let mut current: Option<(String, Vec<u8>)> = None;

    while let Ok(n_read) = reader.read_line(&mut line_full) {
        debug!("Considering line: {:#?}", line_full);
        if n_read <= 0 {
            break;
        }

        let line = line_full.trim_end();
        if line.len() == 0 {
            break;
        }

        if line.starts_with(" ") || line.starts_with("\t") {
            // Continuation of previous header.
            debug!("Line continues existing header: {:?}", current);
            assert!(current.is_some());
            let (key, mut value) = current.unwrap();
            let mut trimmed_line: Vec<u8> = line.as_bytes().to_vec();
            value.append(&mut vec![b' ']);
            value.append(&mut trimmed_line);
            current = Some((key, value));
        } else {
            debug!("Line is a new header: current={:?}", current);
            let parts: Vec<&str> = line.splitn(2, ":").collect();
            assert_eq!(parts.len(), 2, "Malformed header line: {} in {:?}", line, filename);

            // New header line. If there's an existing header line (looking for a continuation), append it to the
            // headers.
            if let Some((key, value)) = current {
                debug!("Pushing current header: {:#?}: {:#?}", key, from_utf8(&value).unwrap());
                let v_str: &[u8] = &value;
                let hv = HeaderValue::from_bytes(v_str);
                let hv = match hv {
                    Ok(hv) => hv,
                    Err(e) => panic!("Invalid header value: {:?}: {}", from_utf8(&value).unwrap(), e),
                };
                headers.append(HeaderName::from_bytes(key.as_str().as_bytes()).unwrap(), hv);
            }

            let key = parts[0].to_string();
            let value = parts[1].trim();
            current = Some((key, value.as_bytes().to_vec()));
        }
        debug!("current now {:#?}", current);
        line_full = String::new();
    }

    if let Some((key, value)) = current {
        debug!("Pushing unfinished header: {:#?}: {:#?}", key, from_utf8(&value).unwrap());
        headers
            .append(HeaderName::from_bytes(key.as_str().as_bytes()).unwrap(), HeaderValue::from_bytes(&value).unwrap());
    }

    let mut body: Vec<u8> = Vec::new();
    reader.read_to_end(&mut body).unwrap();

    Request {
        request_method: method.to_string(),
        uri: uri,
        headers: headers,
        body: Some(body),
    }
}
