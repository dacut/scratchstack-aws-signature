use {
    crate::{
        service_for_signing_key_fn, sigv4_validate_request, CanonicalRequest, GetSigningKeyRequest,
        GetSigningKeyResponse, KSecretKey, SignatureOptions, SignedHeaderRequirements,
    },
    bytes::{Bytes, BytesMut},
    chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc},
    http::{
        header::HeaderValue,
        method::Method,
        request::Request,
        uri::{PathAndQuery, Uri},
        version::Version as HttpVersion,
    },
    log::debug,
    scratchstack_aws_principal::{Principal, User},
    std::{
        env,
        fs::File,
        io::{BufRead, BufReader, Read, Seek},
        path::PathBuf,
        str::from_utf8,
    },
    tower::BoxError,
};

const TEST_REGION: &str = "us-east-1";
const TEST_SERVICE: &str = "service";

#[test_log::test(tokio::test)]
async fn get_header_key_duplicate_get_header_key_duplicate() {
    run("get-header-key-duplicate/get-header-key-duplicate").await;
}

// Canonical request is contrary to RFC 2616
// #[tokio::test]
// #[test_log::test]
// async fn get_header_value_multiline_get_header_value_multiline() {
//     run("get-header-value-multiline/get-header-value-multiline").await;
// }

#[test_log::test(tokio::test)]
async fn get_header_value_order_get_header_value_order() {
    run("get-header-value-order/get-header-value-order").await;
}

#[test_log::test(tokio::test)]
async fn get_header_value_trim_get_header_value_trim() {
    run("get-header-value-trim/get-header-value-trim").await;
}

#[test_log::test(tokio::test)]
async fn get_unreserved_get_unreserved() {
    run("get-unreserved/get-unreserved").await;
}

// This encoding issue is taken care of by the frontend.
// #[test_log::test(tokio::test)]
// async fn get_utf8_get_utf8() {
//     run("get-utf8/get-utf8").await;
// }

#[test_log::test(tokio::test)]
async fn get_vanilla_empty_query_key_get_vanilla_empty_query_key() {
    run("get-vanilla-empty-query-key/get-vanilla-empty-query-key").await;
}

#[test_log::test(tokio::test)]
async fn get_vanilla_query_order_key_case_get_vanilla_query_order_key_case() {
    run("get-vanilla-query-order-key-case/get-vanilla-query-order-key-case").await;
}

#[test_log::test(tokio::test)]
async fn get_vanilla_query_order_key_get_vanilla_query_order_key() {
    run("get-vanilla-query-order-key/get-vanilla-query-order-key").await;
}

#[test_log::test(tokio::test)]
async fn get_vanilla_query_order_value_get_vanilla_query_order_value() {
    run("get-vanilla-query-order-value/get-vanilla-query-order-value").await;
}

#[test_log::test(tokio::test)]
async fn get_vanilla_query_unreserved_get_vanilla_query_unreserved() {
    run("get-vanilla-query-unreserved/get-vanilla-query-unreserved").await;
}

#[test_log::test(tokio::test)]
async fn get_vanilla_query_get_vanilla_query() {
    run("get-vanilla-query/get-vanilla-query").await;
}

// This encoding issue is taken care of/rejected by the frontend.
// #[test_log::test(tokio::test)]
// async fn get_vanilla_utf8_query_get_vanilla_utf8_query() {
//     run("get-vanilla-utf8-query/get-vanilla-utf8-query").await;
// }

#[test_log::test(tokio::test)]
async fn get_vanilla_get_vanilla() {
    run("get-vanilla/get-vanilla").await;
}

#[test_log::test(tokio::test)]
async fn normalize_path_get_relative_relative_get_relative_relative() {
    run("normalize-path/get-relative-relative/get-relative-relative").await;
}

#[test_log::test(tokio::test)]
async fn normalize_path_get_relative_get_relative() {
    run("normalize-path/get-relative/get-relative").await;
}

#[test_log::test(tokio::test)]
async fn normalize_path_get_slash_dot_slash_get_slash_dot_slash() {
    run("normalize-path/get-slash-dot-slash/get-slash-dot-slash").await;
}

#[test_log::test(tokio::test)]
async fn normalize_path_get_slash_pointless_dot_get_slash_pointless_dot() {
    run("normalize-path/get-slash-pointless-dot/get-slash-pointless-dot").await;
}

#[test_log::test(tokio::test)]
async fn normalize_path_get_slash_get_slash() {
    run("normalize-path/get-slash/get-slash").await;
}

#[test_log::test(tokio::test)]
async fn normalize_path_get_slashes_get_slashes() {
    run("normalize-path/get-slashes/get-slashes").await;
}

// This encoding issue is taken care of by the HTTP frontend.
// #[test_log::test(tokio::test)]
// async fn normalize_path_get_space_get_space() {
//     run("normalize-path/get-space/get-space").await;
// }

#[test_log::test(tokio::test)]
async fn post_header_key_case_post_header_key_case() {
    run("post-header-key-case/post-header-key-case").await;
}

#[test_log::test(tokio::test)]
async fn post_header_key_sort_post_header_key_sort() {
    run("post-header-key-sort/post-header-key-sort").await;
}

#[test_log::test(tokio::test)]
async fn post_header_value_case_post_header_value_case() {
    run("post-header-value-case/post-header-value-case").await;
}

#[test_log::test(tokio::test)]
async fn post_sts_token_post_sts_header_after_post_sts_header_after() {
    run("post-sts-token/post-sts-header-after/post-sts-header-after").await;
}

#[test_log::test(tokio::test)]
async fn post_sts_token_post_sts_header_before_post_sts_header_before() {
    run("post-sts-token/post-sts-header-before/post-sts-header-before").await;
}

#[test_log::test(tokio::test)]
async fn post_vanilla_empty_query_value_post_vanilla_empty_query_value() {
    run("post-vanilla-empty-query-value/post-vanilla-empty-query-value").await;
}

#[test_log::test(tokio::test)]
async fn post_vanilla_query_post_vanilla_query() {
    run("post-vanilla-query/post-vanilla-query").await;
}

#[test_log::test(tokio::test)]
async fn post_vanilla_post_vanilla() {
    run("post-vanilla/post-vanilla").await;
}

#[test_log::test(tokio::test)]
async fn post_x_www_form_urlencoded_parameters_post_x_www_form_urlencoded_parameters() {
    run("post-x-www-form-urlencoded-parameters/post-x-www-form-urlencoded-parameters").await;
}

/*
This test is disabled for now -- it does not seem to encode the signed request
properly.

#[test_log::test(tokio::test)]
async fn post_x_www_form_urlencoded_post_x_www_form_urlencoded() {
    run("post-x-www-form-urlencoded/post-x-www-form-urlencoded").await;
}
*/

#[allow(clippy::expect_fun_call)]
async fn run(basename: &str) {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .unwrap_or(env::current_dir().unwrap().to_string_lossy().to_string() + "/base-library");
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
    let (parts, body) = request.into_parts();
    let (canonical, parts, body) =
        CanonicalRequest::from_request_parts(parts, body, SignatureOptions::url_encode_form())
            .expect("Failed to parse request");

    // The canonical request calculated by AWS for verification.
    let mut creq_path = PathBuf::new();
    creq_path.push(&req_path);
    creq_path.set_extension("creq");

    let mut creq = File::open(&creq_path).expect(&format!("Failed to open {:?}", creq_path));
    let mut expected_canonical_request = Vec::new();
    creq.read_to_end(&mut expected_canonical_request).unwrap();
    expected_canonical_request.retain(|c| *c != b'\r'); // Remove carriage returns (not newlines)

    // Check the canonical request.
    let req = SignedHeaderRequirements::default();
    let auth_params = canonical.get_auth_parameters(&req).expect("Failed to get auth parameters");
    let canonical_request = canonical.canonical_request(&auth_params.signed_headers);
    assert_eq!(
        String::from_utf8_lossy(canonical_request.as_slice()),
        String::from_utf8_lossy(expected_canonical_request.as_slice()),
        "Canonical request does not match on {:?}",
        creq_path
    );
    debug!(
        "Canonical request matches on {:?}:\n---------\n{}\n--------",
        creq_path,
        String::from_utf8_lossy(canonical_request.as_slice())
    );

    // The string-to-sign calculated by AWS for verification.
    let mut sts_path = PathBuf::new();
    sts_path.push(&req_path);
    sts_path.set_extension("sts");

    let mut sts = File::open(&sts_path).expect(&format!("Failed to open {sts_path:?}"));
    let mut expected_string_to_sign = Vec::new();
    sts.read_to_end(&mut expected_string_to_sign).unwrap();
    expected_string_to_sign.retain(|c| *c != b'\r'); // Remove carriage returns (not newlines)

    // Compare the string-to-sign we calculate vs that from AWS.
    let sigv4_auth =
        canonical.get_authenticator_from_auth_parameters(auth_params).expect("Failed to get authenticator");
    let string_to_sign = sigv4_auth.get_string_to_sign();
    assert_eq!(from_utf8(&string_to_sign), from_utf8(&expected_string_to_sign), "Failed on {sreq_path:?}");

    debug!(
        "String to sign matches on {sreq_path:?}\n--------\n{}\n--------",
        String::from_utf8_lossy(string_to_sign.as_slice())
    );

    // Create a service for getting the signing key.
    let mut signing_key_svc = service_for_signing_key_fn(get_signing_key);

    let test_time = DateTime::<Utc>::from_naive_utc_and_offset(
        NaiveDateTime::new(NaiveDate::from_ymd_opt(2015, 8, 30).unwrap(), NaiveTime::from_hms_opt(12, 36, 0).unwrap()),
        Utc,
    );

    // Create a GetSigningKeyRequest from our existing request.
    debug!("body: {:?}", body);
    let request = Request::from_parts(parts, body);
    let required_headers = SignedHeaderRequirements::default();
    sigv4_validate_request(
        request,
        TEST_REGION,
        TEST_SERVICE,
        &mut signing_key_svc,
        test_time,
        &required_headers,
        SignatureOptions::url_encode_form(),
    )
    .await
    .expect(&format!("Failed to validate request: {:?}", sreq_path));
}

async fn get_signing_key(request: GetSigningKeyRequest) -> Result<GetSigningKeyResponse, BoxError> {
    let principal = Principal::from(User::new("aws", "123456789012", "/", "test").unwrap());
    let k_secret = KSecretKey::from_str("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    let k_signing = k_secret.to_ksigning(request.request_date(), request.region(), request.service());

    let response = GetSigningKeyResponse::builder().principal(principal).signing_key(k_signing).build().unwrap();
    Ok(response)
}

#[allow(clippy::expect_fun_call)]
fn parse_file(f: File, filename: &PathBuf) -> Request<Bytes> {
    let size = if let Ok(metadata) = f.metadata() {
        metadata.len() as i64
    } else {
        65536
    };

    let mut reader = BufReader::new(f);
    let builder = Request::builder();

    let mut method_line = Vec::with_capacity(256);
    reader.read_until(b'\n', &mut method_line).expect(&format!("No method line in {:?}", filename));
    assert!(!method_line.is_empty());
    assert_eq!(method_line[method_line.len() - 1], b'\n');
    method_line.pop(); // Remove newline
    let method_line_str = String::from_utf8_lossy(method_line.as_slice()).to_string();
    let mut muq_and_ver = method_line.rsplitn(2, |c| *c == b' '); // muq = method uri query
    let ver = muq_and_ver.next().expect(format!("No version in {}", method_line_str).as_str());
    let builder = builder.version(parse_http_version(ver));
    let muq = muq_and_ver.next().expect(format!("No method/uri/query in {}", method_line_str).as_str());

    let mut muq_parts = muq.splitn(2, |c| *c == b' ');
    let method = muq_parts.next().expect(format!("No method in {}", method_line_str).as_str());
    let method = Method::from_bytes(method).expect(format!("Invalid method in {}", method_line_str).as_str());
    let builder = builder.method(method);

    let path_query_str = muq_parts.next().expect(format!("No path/query in {}", method_line_str).as_str());
    let path_query_str = BytesMut::from(path_query_str);
    let pq = PathAndQuery::from_maybe_shared(path_query_str)
        .expect(format!("Invalid path/query str: {}", method_line_str).as_str());
    let mut builder = builder.uri(Uri::from(pq));

    let mut line_full: String = String::new();
    let mut current: Option<(String, Vec<u8>)> = None;

    while let Ok(_n_read) = reader.read_line(&mut line_full) {
        debug!("Considering line: {:#?}", line_full);
        let line = line_full.trim_end();
        if line.is_empty() {
            break;
        }

        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous header.
            debug!("Line continues existing header: {:?}", current);
            assert!(current.is_some());
            let (key, mut value) = current.unwrap();
            let mut trimmed_line: Vec<u8> = line.as_bytes().to_vec();
            value.append(&mut vec![b' ']);
            value.append(&mut trimmed_line);
            current = Some((key, value));
        } else {
            debug!("Line is a new header: current={}", debug_current(&current));
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            assert_eq!(parts.len(), 2, "Malformed header line: {} in {:?}", line, filename);

            // New header line. If there's an existing header line (looking for a continuation), append it to the
            // headers.
            if let Some((key, value)) = current {
                debug!("Pushing current header: {}: {}", key, String::from_utf8_lossy(&value));
                let v_str: &[u8] = &value;
                let hv = HeaderValue::from_bytes(v_str);
                let hv = match hv {
                    Ok(hv) => hv,
                    Err(e) => panic!("Invalid header value: {:?}: {}", from_utf8(&value).unwrap(), e),
                };

                builder = builder.header(key, hv);
            }

            let key = parts[0].to_string();
            let value = parts[1].trim();
            current = Some((key, value.as_bytes().to_vec()));
        }
        line_full = String::new();
    }

    if let Some((key, value)) = current {
        debug!("Pushing unfinished header: {:#?}: {:#?}", key, from_utf8(&value).unwrap());
        builder = builder.header(key, value);
    }

    let current_pos = reader.stream_position().unwrap_or(0) as i64;
    let expected_body_size = (size - current_pos).max(1024);
    let mut body = Vec::with_capacity(expected_body_size as usize);
    reader.read_to_end(&mut body).unwrap();
    let body: Bytes = body.into();

    builder.body(body).expect("Failed to build request")
}

fn parse_http_version(ver: &[u8]) -> HttpVersion {
    match ver {
        b"HTTP/1.0" => HttpVersion::HTTP_10,
        b"HTTP/1.1" => HttpVersion::HTTP_11,
        b"HTTP/2.0" => HttpVersion::HTTP_2,
        b"HTTP/3.0" => HttpVersion::HTTP_3,
        _ => panic!("Unknown HTTP version: {}", String::from_utf8_lossy(ver)),
    }
}

fn debug_current(current: &Option<(String, Vec<u8>)>) -> String {
    match current {
        None => "None".to_string(),
        Some((key, value)) => match String::from_utf8(value.to_vec()) {
            Ok(utf8_value) => format!("{}: {}", key, utf8_value),
            Err(_) => format!("{}: {:?}", key, value),
        },
    }
}
