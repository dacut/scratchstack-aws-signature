//! Common constants used throughout the crate.
//!
//! This was consolidated here because we started redefining this in separate modules accidentally.
//! This helps ensure the entire crate is on the same page about these constant values. If a value
//! is spelled incorrectly, at least it can be fixed in one spot.
//!
//! Tests that are testing the content of an error code or message should not use these constants;
//! they should use hard-coded strings so the tests are also testing for misspellings.
//!
//! Please keep this file organized alphabetically. (This can be a bit hard with comments, etc.)

/// Default allowed timestamp mismatch in minutes.
pub(crate) const ALLOWED_MISMATCH_MINUTES: i64 = 15;

/// Content-Type string for HTML forms
pub(crate) const APPLICATION_X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

/// Algorithm for AWS SigV4
pub(crate) const AWS4_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";

/// Algorithm for AWS SigV4 (bytes)
pub(crate) const AWS4_HMAC_SHA256_BYTES: &[u8] = b"AWS4-HMAC-SHA256";

/// String included at the end of the AWS SigV4 credential scope
pub(crate) const AWS4_REQUEST: &str = "aws4_request";

/// Content-Type parameter for specifying the character set
pub(crate) const CHARSET: &str = "charset";

/// Signature field for the access key
pub(crate) const CREDENTIAL: &[u8] = b"Credential";

/// Error code: DuplicateHeaderAndQueryParameter
pub(crate) const ERR_CODE_DUPLICATE_HEADER_AND_QUERY_PARAMETER: &str = "DuplicateHeaderAndQueryParameter";

/// Error code: ExpiredToken
pub(crate) const ERR_CODE_EXPIRED_TOKEN: &str = "ExpiredToken";

/// Error code: InternalFailure
pub(crate) const ERR_CODE_INTERNAL_FAILURE: &str = "InternalFailure";

/// Error code: InvalidContentType (non-AWS standard)
pub(crate) const ERR_CODE_INVALID_CONTENT_TYPE: &str = "InvalidContentType";

/// Error code: InvalidBodyEncoding
pub(crate) const ERR_CODE_INVALID_BODY_ENCODING: &str = "InvalidBodyEncoding";

/// Error code: InvalidClientTokenId
pub(crate) const ERR_CODE_INVALID_CLIENT_TOKEN_ID: &str = "InvalidClientTokenId";

/// Error code: IncompleteSignature
pub(crate) const ERR_CODE_INCOMPLETE_SIGNATURE: &str = "IncompleteSignature";

/// Error code: InvalidRequestMethod (non-AWS standard)
pub(crate) const ERR_CODE_INVALID_REQUEST_METHOD: &str = "InvalidRequestMethod";

/// Error code: InvalidURIPath
pub(crate) const ERR_CODE_INVALID_URI_PATH: &str = "InvalidURIPath";

/// Error code: MalformedHeader
pub(crate) const ERR_CODE_MALFORMED_HEADER: &str = "MalformedHeader";

/// Error code: MalformedQueryString
pub(crate) const ERR_CODE_MALFORMED_QUERY_STRING: &str = "MalformedQueryString";

/// Error code: MissingAuthenticationToken
pub(crate) const ERR_CODE_MISSING_AUTHENTICATION_TOKEN: &str = "MissingAuthenticationToken";

/// Error code: MissingRequiredHeader
pub(crate) const ERR_CODE_MISSING_REQUIRED_HEADER: &str = "MissingRequiredHeader";

/// Error code: SignatureDoesNotMatch
pub(crate) const ERR_CODE_SIGNATURE_DOES_NOT_MATCH: &str = "SignatureDoesNotMatch";

/// Error message: Key too long
pub(crate) const ERR_MSG_KEY_TOO_LONG: &str = "Key too long";

/// Error message: Key too short
pub(crate) const ERR_MSG_KEY_TOO_SHORT: &str = "Key too short";

/// Header for `authorization`
pub(crate) const HDR_AUTHORIZATION: &str = "authorization";

/// Header for `content-length`
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const HDR_CONTENT_LENGTH: &str = "content-length";

/// Header for `content-type`
pub(crate) const HDR_CONTENT_TYPE: &str = "content-type";

/// Header for `date`
pub(crate) const HDR_DATE: &str = "date";

/// Header for `expect`
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const HDR_EXPECT: &str = "expect";

/// Header for `transfer-encoding`
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const HDR_TRANSFER_ENCODING: &str = "transfer-encoding";

/// Header for `x-amz-content-sha256`
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const HDR_X_AMZ_CONTENT_SHA256: &str = "x-amz-content-sha256";

/// Header for delivering the alternate date
pub(crate) const HDR_X_AMZ_DATE: &str = "x-amz-date";

/// Header for the decoded content length of a streamed S3 payload
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const HDR_X_AMZ_DECODED_CONTENT_LENGTH: &str = "x-amz-decoded-content-length";

/// Header for delivering the session token
pub(crate) const HDR_X_AMZ_SECURITY_TOKEN: &str = "x-amz-security-token";

/// Uppercase hex digits.
pub(crate) const HEX_DIGITS_UPPER: [u8; 16] =
    [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E', b'F'];

/// Compact ISO8601 format used for the string to sign.
pub(crate) const ISO8601_COMPACT_FORMAT: &str = "%Y%m%dT%H%M%SZ";

/// Short date format
pub(crate) const ISO8601_DATE_FORMAT: &str = "%Y%m%d";

/// Length of an ISO8601 date string in the UTC time zone.
pub(crate) const ISO8601_UTC_LENGTH: usize = 16;

/// The default length of an AWS secret key, including the "AWS4" prefix.
pub(crate) static KSECRETKEY_LENGTH: usize = 44;

/// Error message: `"Authorization header requires 'Credential' parameter."`
pub(crate) const MSG_AUTH_HEADER_REQ_CREDENTIAL: &str = "Authorization header requires 'Credential' parameter.";

/// Error message: `"Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header."`
pub(crate) const MSG_AUTH_HEADER_REQ_DATE: &str =
    "Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header.";

/// Error message: `"Authorization header requires 'Signature' parameter."`
pub(crate) const MSG_AUTH_HEADER_REQ_SIGNATURE: &str = "Authorization header requires 'Signature' parameter.";

/// Error message: `"Authorization header requires 'SignedHeaders' parameter."`
pub(crate) const MSG_AUTH_HEADER_REQ_SIGNED_HEADERS: &str = "Authorization header requires 'SignedHeaders' parameter.";

/// Error message: `"Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term,"`
pub(crate) const MSG_CREDENTIAL_MUST_HAVE_FIVE_PARTS: &str =
    "Credential must have exactly 5 slash-delimited elements, e.g. keyid/date/region/service/term,";

/// Error message: `"The request contains a query parameter that duplicates a header value."`
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const MSG_DUPLICATE_HEADER_AND_QUERY_PARAMETER: &str =
    "The request contains a query parameter that duplicates a header value.";

/// Error message: `"'Host' or ':authority' must be a 'SignedHeader' in the AWS Authorization."`
pub(crate) const MSG_HOST_AUTHORITY_MUST_BE_SIGNED: &str =
    "'Host' or ':authority' must be a 'SignedHeader' in the AWS Authorization.";

/// Error message: `"Illegal hex character in escape % pattern: %"`
pub(crate) const MSG_ILLEGAL_HEX_CHAR: &str = "Illegal hex character in escape % pattern: %";

/// Error message: `"Incomplete trailing escape % sequence"`
pub(crate) const MSG_INCOMPLETE_TRAILING_ESCAPE: &str = "Incomplete trailing escape % sequence";

/// Error message: `"Invalid x-amz-content-sha256 value"`
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const MSG_INVALID_XACS_VALUE: &str = "Invalid x-amz-content-sha256 value";

/// Error message: `"Internal Service Error"`
pub(crate) const MSG_INTERNAL_SERVICE_ERROR: &str = "Internal Service Error";

/// Error message: `"Malformed X-Amz-Content-Sha256 header value"`
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const MSG_MALFORMED_XACS_HEADER_VALUE: &str = "Malformed X-Amz-Content-Sha256 header value";

/// Error message: `"Malformed X-Amz-Content-Sha256 query parameter"`
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const MSG_MALFORMED_XACS_QUERY_PARAMETER: &str = "Malformed X-Amz-Content-Sha256 query parameter";

/// Error message: `"AWS query-string parameters must include 'X-Amz-Credential'"`
pub(crate) const MSG_QUERY_STRING_MUST_INCLUDE_CREDENTIAL: &str =
    "AWS query-string parameters must include 'X-Amz-Credential'.";

/// Error message: `"AWS query-string parameters must include 'X-Amz-Sigature'"`
pub(crate) const MSG_QUERY_STRING_MUST_INCLUDE_SIGNATURE: &str =
    "AWS query-string parameters must include 'X-Amz-Signature'.";

/// Error message: `"AWS query-string parameters must include 'X-Amz-SignedHeaders'"`
pub(crate) const MSG_QUERY_STRING_MUST_INCLUDE_SIGNED_HEADERS: &str =
    "AWS query-string parameters must include 'X-Amz-SignedHeaders'.";

/// Error message: `"AWS query-string parameters must include 'X-Amz-Date'"`
pub(crate) const MSG_QUERY_STRING_MUST_INCLUDE_DATE: &str = "AWS query-string parameters must include 'X-Amz-Date'.";

/// Error message: `"Re-examine the query-string parameters."`
pub(crate) const MSG_REEXAMINE_QUERY_STRING_PARAMS: &str = "Re-examine the query-string parameters.";

/// Error message: `"Request is missing Authentication Token"`
pub(crate) const MSG_REQUEST_MISSING_AUTH_TOKEN: &str = "Request is missing Authentication Token";

/// Error message: `"Request is missing the X-Amz-Content-Sha256 header or query parameter"`
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const MSG_REQUEST_MISSING_XACS: &str =
    "Request is missing the X-Amz-Content-Sha256 header or query parameter";

/// Error message: `"The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details."`
pub(crate) const MSG_REQUEST_SIGNATURE_MISMATCH: &str = "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.";

/// Error message: `"Unsupported AWS 'algorithm': "`
pub(crate) const MSG_UNSUPPORTED_ALGORITHM: &str = "Unsupported AWS 'algorithm': ";

/// Query parameter for the signature algorithm
pub(crate) const QP_X_AMZ_ALGORITHM: &str = "X-Amz-Algorithm";

/// Query parameter for delivering the access key
pub(crate) const QP_X_AMZ_CREDENTIAL: &str = "X-Amz-Credential";

/// Query parameter for delivering the date
pub(crate) const QP_X_AMZ_DATE: &str = "X-Amz-Date";

/// Query parameter for delivering the expiration time of a presigned URL
pub(crate) const QP_X_AMZ_EXPIRES: &str = "X-Amz-Expires";

/// Query parameter for delivering the session token
pub(crate) const QP_X_AMZ_SECURITY_TOKEN: &str = "X-Amz-Security-Token";

/// Query parameter for delivering the signature
pub(crate) const QP_X_AMZ_SIGNATURE: &str = "X-Amz-Signature";

/// Query parameter specifying the signed headers
pub(crate) const QP_X_AMZ_SIGNED_HEADERS: &str = "X-Amz-SignedHeaders";

/// SHA-256 of an empty string.
pub(crate) const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Length of a SHA-256 hex string.
pub(crate) const SHA256_HEX_LENGTH: usize = SHA256_EMPTY.len();

/// The length of a SHA-256 digest in bytes.
pub(crate) const SHA256_OUTPUT_LEN: usize = 32;

/// Signature field for the signature itself
pub(crate) const SIGNATURE: &[u8] = b"Signature";

/// Authorization header parameter specifying the signed headers
pub(crate) const SIGNED_HEADERS: &[u8] = b"SignedHeaders";

/// The region to use for testing.
#[cfg(test)]
pub(crate) const TEST_REGION: &str = "us-east-1";

/// The service to use for testing.
#[cfg(test)]
pub(crate) const TEST_SERVICE: &str = "service";

/// Token used for `x-amz-content-sha256` when the payload is streamed and signed with SigV4a
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const XACS_STREAMING_AWS4_ECDSA_P256_SHA256_PAYLOAD: &str = "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD";

/// Token used for `x-amz-content-sha256` when the payload is streamed and signed with SigV4a and has trailers
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const XACS_STREAMING_AWS4_ECDSA_P256_SHA256_PAYLOAD_TRAILER: &str =
    "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD-TRAILER";

/// Token used for `x-amz-content-sha256` when the payload is streamed and SigV4 signed
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const XACS_STREAMING_AWS4_HMAC_SHA256_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";

/// Token used for `x-amz-content-sha256` when the payload is streamed and SigV4 signed and has trailers
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const XACS_STREAMING_AWS4_HMAC_SHA256_PAYLOAD_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";

/// Token used for `x-amz-content-sha256` when the payload is streamed and unsigned and has
/// trailers
#[allow(dead_code)] // XXX: Will this be needed? (S3-specific)
pub(crate) const XACS_STREAMING_UNSIGNED_PAYLOAD_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

/// Token used for `x-amz-content-sha256` when the payload is unsigned
pub(crate) const XACS_UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
