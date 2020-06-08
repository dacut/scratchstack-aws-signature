//! AWS API request signatures verification routines.
//!
//! This is essentially the server-side complement of [rusoto_signature](https://crates.io/crates/rusoto_signature)
//! but follows the implementation of [python-aws-sig](https://github.com/dacut/python-aws-sig).
//!
//! This implements the AWS [SigV4](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
//! and [SigV4S3](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html)
//! algorithms.
//!
use std::collections::{BTreeMap, HashMap};
use std::convert::From;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::io;
use std::io::Write;
use std::str::from_utf8;
use std::vec::Vec;

use chrono::{DateTime, Duration, Utc};
use hex;
use lazy_static::lazy_static;
use regex::Regex;
use ring::digest::{digest, SHA256};

use crate::chronoutil::ParseISO8601;
use crate::hmac::hmac_sha256;

/// Content-Type string for HTML forms
const APPLICATION_X_WWW_FORM_URLENCODED: &str =
    "application/x-www-form-urlencoded";

/// Algorithm for AWS SigV4
const AWS4_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";

/// Algorithm for AWS SigV4 plus a following space
const AWS4_HMAC_SHA256_SPACE: &str = "AWS4-HMAC-SHA256 ";

/// String included at the end of the AWS SigV4 credential scope
const AWS4_REQUEST: &str = "aws4_request";

/// Header parameter for the authorization
const AUTHORIZATION: &str = "authorization";

/// Content-Type parameter for specifying the character set
const CHARSET: &str = "charset";

/// Signature field for the access key
const CREDENTIAL: &str = "Credential";

/// Header field for the content type
const CONTENT_TYPE: &str = "content-type";

/// Header parameter for the date
const DATE: &str = "date";

/// Compact ISO8601 format used for the string to sign
const ISO8601_COMPACT_FORMAT: &str = "%Y%m%dT%H%M%SZ";

/// SHA-256 of an empty string.
const SHA256_EMPTY: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Signature field for the signature itself
const SIGNATURE: &str = "Signature";

/// Authorization header parameter specifying the signed headers
const SIGNEDHEADERS: &str = "SignedHeaders";

/// Query parameter for delivering the access key
const X_AMZ_CREDENTIAL: &str = "X-Amz-Credential";

/// Query parameter for delivering the date
const X_AMZ_DATE: &str = "X-Amz-Date";

/// Header for delivering the alternate date
const X_AMZ_DATE_LOWER: &str = "x-amz-date";

/// Query parameter for delivering the session token
const X_AMZ_SECURITY_TOKEN: &str = "X-Amz-Security-Token";

/// Header for delivering the session token
const X_AMZ_SECURITY_TOKEN_LOWER: &str = "x-amz-security-token";

/// Query parameter for delivering the signature
const X_AMZ_SIGNATURE: &str = "X-Amz-Signature";

/// Query parameter specifying the signed headers
const X_AMZ_SIGNEDHEADERS: &str = "X-Amz-SignedHeaders";

lazy_static! {
    /// Multiple slash pattern for condensing URIs
    static ref MULTISLASH: Regex = Regex::new("//+").unwrap();

    /// Multiple space pattern for condensing header values
    static ref MULTISPACE: Regex = Regex::new("  +").unwrap();
}

/// Error returned when an attempt at validating an AWS SigV4 signature
/// fails.
#[derive(Debug)]
pub struct SignatureError {
    /// The kind of error encountered.
    pub kind: ErrorKind,

    /// Details about the error.
    pub detail: String,
}

/// The possible reasons for an AWS SigV4 signature validation to fail;
/// returned as part of SignatureError.
#[derive(Debug)]
pub enum ErrorKind {
    /// Validation failed due to an underlying I/O error.
    IO(io::Error),

    /// The request body used an unsupported character set encoding. Currently
    /// only UTF-8 is supported.
    InvalidBodyEncoding,

    /// The request signature specified an invalid credential -- either the
    /// access key was not specified, or the credential scope (in the form
    /// <code>_date_/_region_/_service_/aws4_request</code>) did not match
    /// the expected value for the server.
    InvalidCredential,

    /// The signature passed in the request did not match the calculated
    /// signature value.
    InvalidSignature,

    /// The URI path includes invalid components. This can be a malformed
    /// hex encoding (e.g. `%0J`), a non-absolute URI path (`foo/bar`), or a
    /// URI path that attempts to navigate above the root (`/x/../../../y`).
    InvalidURIPath,

    /// An HTTP header was malformed -- the value could not be decoded as
    /// UTF-8, or the header was empty and this is not allowed (e.g. the
    /// `content-type` header), or the header could not be parsed
    /// (e.g., the `date` header is not a valid date).
    MalformedHeader,

    /// A query parameter was malformed -- the value could not be decoded as
    /// UTF-8, or the parameter was empty and this is not allowed (e.g. a
    /// signature parameter), or the parameter could not be parsed
    /// (e.g., the `X-Amz-Date` parameter is not a valid date).
    MalformedParameter,

    /// The AWS SigV4 signature was malformed in some way. This can include
    /// invalid timestamp formats, missing authorization components, or
    /// unparseable components.
    MalformedSignature,

    /// A required HTTP header (and its equivalent in the query string) is
    /// missing.
    MissingHeader,

    /// A required query parameter is missing. This is used internally in the
    /// library; external callers only see `MissingHeader`.
    MissingParameter,

    /// An HTTP header that can be specified only once was specified multiple
    /// times.
    MultipleHeaderValues,

    /// A query parameter that can be specified only once was specified
    /// multiple times.
    MultipleParameterValues,

    /// The timestamp in the request is out of the allowed range.
    TimestampOutOfRange,

    /// The access key specified in the request is unknown.
    UnknownAccessKey,

    /// The signature algorithm requested by the caller is unknown. This library
    /// only supports the `AWS4-HMAC-SHA256` algorithm.
    UnknownSignatureAlgorithm,
}

impl SignatureError {
    pub fn new(kind: ErrorKind, detail: &str) -> Self {
        Self {
            kind,
            detail: detail.to_string(),
        }
    }
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            ErrorKind::IO(ref e) => e.fmt(f),
            ErrorKind::InvalidBodyEncoding => {
                write!(f, "Invalid body encoding: {}", self.detail)
            }
            ErrorKind::InvalidCredential => {
                write!(f, "Invalid credential: {}", self.detail)
            }
            ErrorKind::InvalidSignature => {
                write!(f, "Invalid request signature: {}", self.detail)
            }
            ErrorKind::InvalidURIPath => {
                write!(f, "Invalid URI path: {}", self.detail)
            }
            ErrorKind::MalformedHeader => {
                write!(f, "Malformed header: {}", self.detail)
            }
            ErrorKind::MalformedParameter => {
                write!(f, "Malformed query parameter: {}", self.detail)
            }
            ErrorKind::MalformedSignature => {
                write!(f, "Malformed signature: {}", self.detail)
            }
            ErrorKind::MissingHeader => {
                write!(f, "Missing header: {}", self.detail)
            }
            ErrorKind::MissingParameter => {
                write!(f, "Missing query parameter: {}", self.detail)
            }
            ErrorKind::MultipleHeaderValues => {
                write!(f, "Multiple values for header: {}", self.detail)
            }
            ErrorKind::MultipleParameterValues => write!(
                f,
                "Multiple values for query parameter: {}",
                self.detail
            ),
            ErrorKind::TimestampOutOfRange => {
                write!(f, "Request timestamp out of range: {}", self.detail)
            }
            ErrorKind::UnknownAccessKey => {
                write!(f, "Unknown access key: {}", self.detail)
            }
            ErrorKind::UnknownSignatureAlgorithm => {
                write!(f, "Unknown signature algorithm: {}", self.detail)
            }
        }
    }
}

impl error::Error for SignatureError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.kind {
            ErrorKind::IO(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SignatureError {
    fn from(e: std::io::Error) -> SignatureError {
        let msg = e.to_string();
        SignatureError::new(ErrorKind::IO(e), &msg)
    }
}

/// The types of signing key available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningKeyKind {
    /// KSecret: secret key prepended with "AWS4". Avoid using.
    KSecret,

    /// KDate: HMAC(KSecret, requestDate)
    KDate,

    /// KRegion: HMAC(KDate, region)
    KRegion,

    /// KService: HMAC(KRegion, service)
    KService,

    /// KSigning: HMAC(KService, "aws4_request"). Preferred.
    KSigning,
}

impl fmt::Display for SigningKeyKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SigningKeyKind::KSecret => write!(f, "KSecret"),
            SigningKeyKind::KDate => write!(f, "KDate"),
            SigningKeyKind::KRegion => write!(f, "KRegion"),
            SigningKeyKind::KService => write!(f, "KService"),
            SigningKeyKind::KSigning => write!(f, "KSigning"),
        }
    }
}

/// Principal for a given access key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// The partition this principal exists in.
    pub partition: String,

    /// Principal type -- role, assumed role, service, etc.
    pub principal_type: PrincipalType,
}

impl Principal {
    pub fn create_assumed_role(
        partition: String, account_id: String, path: String, name: String,
        session_name: String) -> Self
    {
        Self {
            partition: partition,
            principal_type: PrincipalType::AssumedRole(IAMAssumedRoleDetails {
                account_id: account_id,
                path: path,
                name: name,
                session_name: session_name,
            })
        }
    }

    pub fn create_group(
        partition: String, account_id: String, path: String, name: String,
        group_id: String) -> Self
    {
        Self {
            partition: partition,
            principal_type: PrincipalType::Group(IAMGroupDetails {
                account_id: account_id,
                path: path,
                name: name,
                group_id: group_id,
            })
        }
    }

    pub fn create_role(
        partition: String, account_id: String, path: String, name: String,
        role_id: String) -> Self
    {
        Self {
            partition: partition,
            principal_type: PrincipalType::Role(IAMRoleDetails {
                account_id: account_id,
                path: path,
                name: name,
                role_id: role_id,
            })
        }
    }

    pub fn create_user(
        partition: String, account_id: String, path: String, name: String,
        user_id: String) -> Self
    {
        Self {
            partition: partition,
            principal_type: PrincipalType::User(IAMUserDetails {
                account_id: account_id,
                path: path,
                name: name,
                user_id: user_id,
            })
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.principal_type {
            PrincipalType::Service(s) => write!(f, "{}", s),
            _ => write!(f, "arn:{}:iam::{}", self.partition, self.principal_type),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IAMAssumedRoleDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the pricnipal, case-insensitive.
    pub name: String,

    /// Session name for the assumed role.
    pub session_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IAMGroupDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the pricnipal, case-insensitive.
    pub name: String,

    /// Unique group id -- will change if principal name is reissued.
    pub group_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IAMRoleDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the pricnipal, case-insensitive.
    pub name: String,

    /// Unique role id -- will change if principal name is reissued.
    pub role_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IAMUserDetails {
    /// The account id (12 digits for AWS).
    pub account_id: String,

    /// Path, starting with a "/".
    pub path: String,

    /// Name of the pricnipal, case-insensitive.
    pub name: String,

    /// Unique user id -- will change if principal name is reissued.
    pub user_id: String,
}


/// Principal type
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalType {
    AssumedRole(IAMAssumedRoleDetails),
    Role(IAMRoleDetails),
    Group(IAMGroupDetails),
    User(IAMUserDetails),
    Service(String),
}

impl fmt::Display for PrincipalType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrincipalType::AssumedRole(ref d) => {
                write!(f, "{}:assumed-role{}{}/{}", d.account_id,
                       d.path, d.name, d.session_name)
            }
            PrincipalType::Group(ref d) => {
                write!(f, "{}:group{}{}", d.account_id, d.path, d.name)
            }
            PrincipalType::Role(ref d) => {
                write!(f, "{}:role{}{}", d.account_id, d.path, d.name)
            }
            PrincipalType::User(ref d) => {
                write!(f, "{}:user{}{}", d.account_id, d.path, d.name)
            }
            PrincipalType::Service(ref service_name) => {
                write!(f, "{}", service_name)
            }
        }
    }
}

/// The function that returns a signing key of a given type.
pub type SigningKeyFn = fn(
    SigningKeyKind,
    &str,           // access_key_id
    Option<&str>,   // token
    Option<&str>,   // request date
    Option<&str>,   // request region
    Option<&str>,   // service
) -> Result<(Principal, Vec<u8>), SignatureError>;

/// A data structure containing the elements of the request
/// (some client-supplied, some service-supplied) involved in the SigV4
/// verification process.
#[derive(Clone, Debug)]
pub struct Request {
    /// The request method (GET, PUT, POST) (client).
    pub request_method: String,

    /// The URI path being accessed (client).
    pub uri_path: String,

    /// The query string portion of the URI (client).
    pub query_string: String,

    /// The HTTP headers sent with the request (client).
    pub headers: HashMap<String, Vec<Vec<u8>>>,

    /// The request body (if any) (client).
    pub body: Vec<u8>,

    /// The region the request was sent to (service).
    pub region: String,

    /// The service the request was sent to (service).
    pub service: String,
}

impl Request {
    /// Retrieve a header value, requiring exactly one value be present.
    fn get_header_one(&self, header: &str) -> Result<String, SignatureError> {
        match self.headers.get(header) {
            None => Err(SignatureError::new(ErrorKind::MissingHeader, header)),
            Some(ref values) => match values.len() {
                0 => {
                    Err(SignatureError::new(ErrorKind::MissingHeader, header))
                }
                1 => match from_utf8(&values[0]) {
                    Ok(ref s) => Ok(s.to_string()),
                    Err(_) => Err(SignatureError::new(
                        ErrorKind::MalformedHeader,
                        header,
                    )),
                },
                _ => Err(SignatureError::new(
                    ErrorKind::MultipleHeaderValues,
                    header,
                )),
            },
        }
    }

    /// The query parameters from the request, normalized, in a mapping format.
    fn get_query_parameters(
        &self,
    ) -> Result<HashMap<String, Vec<String>>, SignatureError> {
        normalize_query_parameters(&self.query_string)
    }

    /// Retrieve a query parameter, requiring exactly one value be present.
    fn get_query_param_one(
        &self,
        parameter: &str,
    ) -> Result<String, SignatureError> {
        match self.get_query_parameters()?.get(parameter) {
            None => Err(SignatureError::new(
                ErrorKind::MissingParameter,
                parameter,
            )),
            Some(ref values) => match values.len() {
                0 => Err(SignatureError::new(
                    ErrorKind::MissingParameter,
                    parameter,
                )),
                1 => Ok(values[0].to_string()),
                _ => Err(SignatureError::new(
                    ErrorKind::MultipleParameterValues,
                    parameter,
                )),
            },
        }
    }

    /// Get the content type and character set used in the body
    fn get_content_type_and_charset(
        &self,
    ) -> Result<(String, String), SignatureError> {
        let content_type_opts = self.get_header_one(CONTENT_TYPE)?;

        let mut parts = content_type_opts.split(";");
        let content_type = match parts.next() {
            Some(ref s) => s.trim(),
            None => {
                return Err(SignatureError::new(
                    ErrorKind::MalformedHeader,
                    "content-type header is empty",
                ))
            }
        };

        for option in parts {
            let opt_trim = option.trim();
            let opt_parts: Vec<&str> = opt_trim.splitn(2, "=").collect();

            if opt_parts.len() == 2 && opt_parts[0] == CHARSET {
                return Ok((
                    content_type.to_string(),
                    opt_parts[1].trim().to_lowercase(),
                ));
            }
        }

        return Ok((content_type.to_string(), "utf-8".to_string()));
    }
}

/// Trait for calculating various attributes of a SigV4 signature according
/// to variants of the SigV4 algorithm.
pub trait AWSSigV4Algorithm {
    /// The canonicalized URI path for a request.
    fn get_canonical_uri_path(
        &self,
        req: &Request,
    ) -> Result<String, SignatureError> {
        canonicalize_uri_path(&req.uri_path)
    }

    /// The canonical query string from the query parameters.
    ///
    /// This takes the query_string from the request, merges it with the body
    /// if the request has a body of type `application/x-www-form-urlencoded`,
    /// and orders the parameters.
    fn get_canonical_query_string(
        &self,
        req: &Request,
    ) -> Result<String, SignatureError> {
        let query_parameters = req.get_query_parameters()?;
        let mut results = Vec::new();

        for (key, values) in query_parameters.iter() {
            // Don't include the signature itself.
            if key != X_AMZ_SIGNATURE {
                for value in values.iter() {
                    results.push(format!("{}={}", key, value));
                }
            }
        }

        if let Ok((content_type, charset)) = req.get_content_type_and_charset()
        {
            if content_type == APPLICATION_X_WWW_FORM_URLENCODED {
                if charset != "utf-8" && charset != "utf8" {
                    return Err(SignatureError::new(
                        ErrorKind::InvalidBodyEncoding,
                        &format!(
                            "application/x-www-form-urlencoded body \
                             uses unsupported charset {}",
                            charset
                        ),
                    ));
                }

                // Parse the body as a URL string
                let body_utf8 =
                    match from_utf8(&req.body) {
                        Ok(s) => s,
                        Err(_) => return Err(SignatureError::new(
                            ErrorKind::InvalidBodyEncoding,
                            "application/x-www-form-urlencoded body contains \
                             invalid UTF-8 characters",
                        )),
                    };

                let body_normalized = normalize_query_parameters(body_utf8)?;
                for (key, values) in body_normalized.iter() {
                    for value in values.iter() {
                        results.push(format!("{}={}", key, value));
                    }
                }
            }
        }

        results.sort_unstable();
        Ok(results.join("&").to_string())
    }

    /// The parameters from the Authorization header (only -- not the query
    /// parameter). If the Authorization header is not present or is not an
    /// AWS SigV4 header, an Err(SignatureError) is returned.
    fn get_authorization_header_parameters(
        &self,
        req: &Request,
    ) -> Result<HashMap<String, String>, SignatureError> {
        let auth_headers_opt = req.headers.get(AUTHORIZATION);
        let aws4_hmac_sha256_u8: &[u8] = AWS4_HMAC_SHA256.as_ref();
        let aws4_hmac_sha256_v8: &Vec<u8> = &aws4_hmac_sha256_u8.to_vec();
        let aws4_hmac_sha256_space_u8: &[u8] = AWS4_HMAC_SHA256_SPACE.as_ref();
        let aws4_hmac_sha256_space_v8: &Vec<u8> = &aws4_hmac_sha256_space_u8.to_vec();

        match auth_headers_opt {
            None => Err(SignatureError::new(ErrorKind::MissingHeader, AUTHORIZATION)),
            Some(auth_headers) => {
                let mut parameters_opt: Option<&str> = None;

                // Multiple Authorization headers may be present, but only one may be
                // of type AWS4-HMAC-SHA256.
                for auth_header in auth_headers {
                    if auth_header != aws4_hmac_sha256_v8 && ! auth_header.starts_with(aws4_hmac_sha256_space_u8) {
                        continue;
                    }

                    if parameters_opt.is_some() {
                        return Err(SignatureError::new(
                            ErrorKind::MultipleHeaderValues,
                            AUTHORIZATION));
                    }

                    if auth_header == aws4_hmac_sha256_v8 || auth_header == aws4_hmac_sha256_space_v8 {
                        // No parameters -- fail fast here.
                        return Err(SignatureError::new(
                            ErrorKind::MalformedSignature,
                            "invalid Authorization header: missing parameters"));
                    }

                    match from_utf8(&auth_header[AWS4_HMAC_SHA256_SPACE.len()..]) {
                        Err(_) => return Err(SignatureError::new(
                            ErrorKind::MalformedHeader,
                            "Authorization header is not valid UTF-8")),
                        Ok(ref p) => parameters_opt = Some(p),
                    }
                }

                match parameters_opt {
                    None => Err(SignatureError::new(
                        ErrorKind::MissingHeader, AUTHORIZATION)),
                    Some(parameters) => 
                        split_authorization_header_parameters(&parameters),
                }
            }
        }
    }

    /// Returns a sorted dictionary containing the signed header names and
    /// their values.
    fn get_signed_headers(
        &self,
        req: &Request,
    ) -> Result<BTreeMap<String, Vec<Vec<u8>>>, SignatureError> {
        // See if the signed headers are listed in the query string.
        let qp_result = req.get_query_param_one(X_AMZ_SIGNEDHEADERS);
        let ah_result;
        let ah_signedheaders;

        let signed_headers = match qp_result {
            Ok(ref sh) => sh,
            Err(e) => match e.kind {
                ErrorKind::MissingParameter => {
                    ah_result = self.get_authorization_header_parameters(req);
                    match ah_result {
                        Err(e) => return Err(e),
                        Ok(ref ahp) => {
                            ah_signedheaders = ahp.get(SIGNEDHEADERS);
                            if let None = ah_signedheaders {
                                return Err(SignatureError::new(
                                    ErrorKind::MalformedSignature,
                                    "invalid Authorization header: \
                                    missing SignedHeaders",
                                ));
                            }

                            ah_signedheaders.unwrap()
                        }
                    }
                }
                _ => return Err(e),
            },
        };

        // Header names are separated by semicolons.
        let parts: Vec<String> =
            signed_headers.split(';').map(|s| s.to_string()).collect();

        // Make sure the signed headers list is canonicalized. For security
        // reasons, we consider it an error if it isn't.
        let mut canonicalized = parts.clone();
        canonicalized.sort_unstable_by(|a, b| {
            a.to_lowercase().partial_cmp(&b.to_lowercase()).unwrap()
        });

        if parts != canonicalized {
            return Err(SignatureError::new(
                ErrorKind::MalformedSignature,
                "SignedHeaders is not canonicalized",
            ));
        }

        let mut result = BTreeMap::<String, Vec<Vec<u8>>>::new();
        for header in canonicalized.iter() {
            match req.headers.get(header) {
                None => {
                    return Err(SignatureError::new(
                        ErrorKind::MissingHeader,
                        header,
                    ))
                }
                Some(ref value) => {
                    result.insert(header.to_string(), value.to_vec());
                }
            }
        }

        Ok(result)
    }

    /// The timestamp of the request.
    ///
    /// This returns the first value found from:
    ///
    /// * The `X-Amz-Date` query parameter.
    /// * The `X-Amz-Date` HTTP header.
    /// * The `Date` HTTP header.
    ///
    /// The timestamp _should_ be in ISO 8601 `YYYYMMDDTHHMMSSZ` format
    /// without milliseconds (_must_ per  [AWS documentation](https://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html)).
    /// However, the AWS SigV4 test suite includes a variety of date formats,
    /// including RFC 2822, RFC 3339, and ISO 8601. This routine allows all
    /// of these formats.
    fn get_request_timestamp(
        &self,
        req: &Request,
    ) -> Result<DateTime<Utc>, SignatureError> {
        let date_str;

        let qp_date_result = req.get_query_param_one(X_AMZ_DATE);
        let h_amz_date_result;
        let h_reg_date_result;
        let mut malformed_kind = ErrorKind::MalformedParameter;
        let mut date_header = X_AMZ_DATE;

        date_str = match qp_date_result {
            Ok(dstr) => dstr,
            Err(e) => match e.kind {
                ErrorKind::MissingParameter => {
                    malformed_kind = ErrorKind::MalformedHeader;
                    date_header = X_AMZ_DATE_LOWER;
                    h_amz_date_result = req.get_header_one(X_AMZ_DATE_LOWER);
                    match h_amz_date_result {
                        Ok(dstr) => dstr,
                        Err(e) => match e.kind {
                            ErrorKind::MissingHeader => {
                                date_header = DATE;
                                h_reg_date_result = req.get_header_one(DATE);
                                h_reg_date_result?
                            }
                            _ => return Err(e),
                        },
                    }
                }
                _ => return Err(e),
            },
        };

        let dt_fixed;
        let dt_rfc2822_result = DateTime::parse_from_rfc2822(&date_str);
        let dt_rfc3339_result = DateTime::parse_from_rfc3339(&date_str);
        let dt_iso8601_result = DateTime::parse_from_iso8601(&date_str);

        // Try to match against the HTTP date format first.
        dt_fixed = if let Ok(ref d) = dt_rfc2822_result {
            d
        } else if let Ok(ref d) = dt_rfc3339_result {
            d
        } else if let Ok(ref d) = dt_iso8601_result {
            d
        } else {
            return Err(SignatureError::new(
                malformed_kind, date_header));
        };

        Ok(dt_fixed.with_timezone(&Utc))
    }

    /// The scope of the credentials to use, as calculated by the service's
    /// region and name, but using the timestamp of the request.
    ///
    /// The result is a string in the form `YYYYMMDD/region/service/aws4_request`.
    fn get_credential_scope(
        &self,
        req: &Request,
    ) -> Result<String, SignatureError> {
        let ts = self.get_request_timestamp(req)?;
        let date = ts.date().format("%Y%m%d");
        Ok(format!(
            "{}/{}/{}/{}",
            date, req.region, req.service, AWS4_REQUEST
        ))
    }

    /// The access key used to sign the request.
    ///
    /// If the credential scope does not match our expected credential scope,
    /// a SignatureError is returned.
    fn get_access_key(&self, req: &Request) -> Result<String, SignatureError> {
        let qp_result = req.get_query_param_one(X_AMZ_CREDENTIAL);
        let auth_headers;

        let credential = match qp_result {
            Ok(ref c) => c,
            Err(e) => match e.kind {
                ErrorKind::MissingParameter => {
                    auth_headers =
                        self.get_authorization_header_parameters(req)?;
                    match auth_headers.get(CREDENTIAL) {
                        Some(c) => c,
                        None => {
                            return Err(SignatureError::new(
                                ErrorKind::MalformedSignature,
                                "invalid Authorization header: missing \
                                 Credential",
                            ))
                        }
                    }
                }
                _ => return Err(e),
            },
        };

        let parts: Vec<&str> = credential.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(SignatureError::new(
                ErrorKind::InvalidCredential,
                "Malformed credential",
            ));
        }

        let access_key = parts[0];
        let request_scope = parts[1];
        let server_scope = self.get_credential_scope(req)?;
        if request_scope == server_scope {
            Ok(access_key.to_string())
        } else {
            Err(SignatureError::new(
                ErrorKind::InvalidCredential,
                &format!(
                    "Invalid credential scope: Expected {} instead of {}",
                    server_scope, request_scope
                ),
            ))
        }
    }

    /// The session token sent with the access key.
    ///
    /// Session tokens are used only for temporary credentials. If a long-term
    /// credential was used, the result is `Ok(None)`.
    fn get_session_token(
        &self,
        req: &Request,
    ) -> Result<Option<String>, SignatureError> {
        let qp_result = req.get_query_param_one(X_AMZ_SECURITY_TOKEN);
        let h_result;

        match qp_result {
            Ok(token) => Ok(Some(token)),
            Err(e) => match e.kind {
                ErrorKind::MissingParameter => {
                    h_result = req.get_header_one(X_AMZ_SECURITY_TOKEN_LOWER);
                    match h_result {
                        Ok(token) => Ok(Some(token)),
                        Err(e) => match e.kind {
                            ErrorKind::MissingParameter => Ok(None),
                            _ => Err(e),
                        },
                    }
                }
                _ => Err(e),
            },
        }
    }

    /// The signature passed into the request.
    fn get_request_signature(
        &self,
        req: &Request,
    ) -> Result<String, SignatureError> {
        match req.get_query_param_one(X_AMZ_SIGNATURE) {
            Ok(sig) => Ok(sig),
            Err(e) => match e.kind {
                ErrorKind::MissingParameter => {
                    let ah: HashMap<String, String> =
                        self.get_authorization_header_parameters(req)?;
                    match ah.get(SIGNATURE) {
                        Some(c) => Ok(c.to_string()),
                        None => Err(SignatureError::new(
                            ErrorKind::MalformedSignature,
                            "invalid Authorization header: missing \
                             Signature",
                        )),
                    }
                }
                _ => Err(e),
            },
        }
    }

    /// The AWS SigV4 canonical request given parameters from the HTTP request,
    /// as outlined in the [AWS documentation](http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html).
    ///
    /// The canonical request is:
    /// ```text
    ///     request_method + '\n' +
    ///     canonical_uri_path + '\n' +
    ///     canonical_query_string + '\n' +
    ///     signed_headers + '\n' +
    ///     sha256(body).hexdigest()
    /// ```
    fn get_canonical_request(
        &self,
        req: &Request,
    ) -> Result<Vec<u8>, SignatureError> {
        let mut result = Vec::<u8>::new();
        let mut header_keys = Vec::<u8>::new();
        let canonical_uri_path = self.get_canonical_uri_path(req)?;
        let canonical_query_string = self.get_canonical_query_string(req)?;
        let body_hex_digest = self.get_body_digest(req)?;

        result.write(req.request_method.as_bytes())?;
        result.push(b'\n');
        result.write(canonical_uri_path.as_bytes())?;
        result.push(b'\n');
        result.write(canonical_query_string.as_bytes())?;
        result.push(b'\n');

        let mut is_first_key = true;

        for (key, values) in self.get_signed_headers(req)? {
            let key_bytes = key.as_bytes();

            result.write(key_bytes)?;
            result.push(b':');

            let mut is_first_value = true;
            for ref value in values {
                if is_first_value {
                    is_first_value = false;
                } else {
                    result.push(b',');
                }

                let value_collapsed_space =
                    MULTISPACE.replace_all(from_utf8(value).unwrap(), " ");
                result.write(value_collapsed_space.as_bytes())?;
            }
            result.push(b'\n');

            if is_first_key {
                is_first_key = false;
            } else {
                header_keys.push(b';');
            }

            header_keys.write(key_bytes)?;
        }

        result.push(b'\n');
        result.append(&mut header_keys);
        result.push(b'\n');

        match req.get_content_type_and_charset() {
            Ok((content_type, _))
                if content_type == APPLICATION_X_WWW_FORM_URLENCODED =>
            {
                result.write(SHA256_EMPTY.as_bytes())?
            }
            _ => result.write(body_hex_digest.as_bytes())?,
        };

        Ok(result)
    }

    /// The SHA-256 hex digest of the body.
    fn get_body_digest(
        &self,
        req: &Request,
    ) -> Result<String, SignatureError> {
        Ok(hex::encode(digest(&SHA256, &req.body).as_ref()))
    }

    /// The string to sign for the request.
    fn get_string_to_sign(
        &self,
        req: &Request,
    ) -> Result<Vec<u8>, SignatureError> {
        let mut result = Vec::new();
        let timestamp = self.get_request_timestamp(req)?;
        let credential_scope = self.get_credential_scope(req)?;
        let canonical_request = self.get_canonical_request(req)?;

        result.write(AWS4_HMAC_SHA256.as_bytes())?;
        result.push(b'\n');
        write!(&mut result, "{}", timestamp.format(ISO8601_COMPACT_FORMAT))?;
        result.push(b'\n');
        result.write(credential_scope.as_bytes())?;
        result.push(b'\n');
        result.write(
            hex::encode(digest(&SHA256, &canonical_request).as_ref())
                .as_bytes(),
        )?;

        Ok(result)
    }

    /// The principal and expected signature for the request.
    fn get_expected_signature(
        &self,
        req: &Request,
        signing_key_kind: SigningKeyKind,
        signing_key_fn: SigningKeyFn) -> Result<(Principal, String), SignatureError>
    {
        let access_key = self.get_access_key(req)?;
        let session_token_result = self.get_session_token(req);
        let session_token = match session_token_result {
            Ok(tok) => tok,
            Err(e) => match e.kind {
                ErrorKind::MissingParameter | ErrorKind::MissingHeader => None,
                _ => return Err(e),
            },
        };

        let timestamp = self.get_request_timestamp(req)?;
        let req_date = format!("{}", timestamp.date().format("%Y%m%d"));

        let (principal, key) = signing_key_fn(
            signing_key_kind,
            &access_key,
            session_token.as_ref().map(String::as_ref),
            Some(&req_date),
            Some(&req.region),
            Some(&req.service),
        )?;
        let string_to_sign = self.get_string_to_sign(req)?;

        let k_signing = get_signing_key(signing_key_kind, &key, &req_date, &req.region, &req.service);

        Ok((principal, hex::encode(
                hmac_sha256(k_signing.as_ref(), &string_to_sign).as_ref())))
    }

    /// Verify that the request timestamp is not beyond the allowed timestamp
    /// mismatch and that the request signature matches our expected
    /// signature.
    ///
    /// This version allows you to specify the server timestamp for testing.
    /// For normal use, use `verify()`.
    fn verify_at(
        &self,
        req: &Request,
        signing_key_kind: SigningKeyKind,
        signing_key_fn: SigningKeyFn,
        server_timestamp: &DateTime<Utc>,
        allowed_mismatch: Option<Duration>,
    ) -> Result<Principal, SignatureError> {
        if let Some(mm) = allowed_mismatch {
            let req_ts = self.get_request_timestamp(req)?;
            let min_ts = server_timestamp
                .checked_sub_signed(mm)
                .unwrap_or(*server_timestamp);
            let max_ts = server_timestamp
                .checked_add_signed(mm)
                .unwrap_or(*server_timestamp);

            if req_ts < min_ts || req_ts > max_ts {
                return Err(SignatureError::new(
                    ErrorKind::TimestampOutOfRange,
                    &format!(
                        "minimum {}, maximum {}, received {}",
                        min_ts, max_ts, req_ts
                    ),
                ));
            }
        }

        let (principal, expected_sig) = self.get_expected_signature(
            &req, signing_key_kind, signing_key_fn)?;
        let request_sig = self.get_request_signature(&req)?;

        if expected_sig != request_sig {
            Err(SignatureError::new(
                ErrorKind::InvalidSignature,
                &format!(
                    "Expected {} instead of {}",
                    expected_sig, request_sig
                ),
            ))
        } else {
            Ok(principal)
        }
    }

    /// Verify that the request timestamp is not beyond the allowed timestamp
    /// mismatch and that the request signature matches our expected
    /// signature.
    fn verify(
        &self,
        req: &Request,
        signing_key_kind: SigningKeyKind,
        signing_key_fn: SigningKeyFn,
        allowed_mismatch: Option<Duration>,
    ) -> Result<Principal, SignatureError> {
        self.verify_at(
            req, signing_key_kind, signing_key_fn, &Utc::now(), allowed_mismatch)
    }
}

/// The implementation of the standard AWS SigV4 algorithm.
#[derive(Clone, Copy, Debug)]
pub struct AWSSigV4 {}

impl AWSSigV4 {
    pub fn new() -> Self {
        Self {}
    }

    /// Verify that the request timestamp is not beyond the allowed timestamp
    /// mismatch and that the request signature matches our expected
    /// signature.
    pub fn verify(
        &self,
        req: &Request,
        signing_key_kind: SigningKeyKind,
        signing_key_fn: SigningKeyFn,
        allowed_mismatch: Option<Duration>,
    ) -> Result<Principal, SignatureError> {
        AWSSigV4Algorithm::verify(
            self, req, signing_key_kind, signing_key_fn, allowed_mismatch)
    }
}

impl AWSSigV4Algorithm for AWSSigV4 {}

/// Indicates whether the specified byte is RFC3986 unreserved -- i.e., can
/// be represented without being percent-encoded, e.g. '?' -> '%3F'.
pub fn is_rfc3986_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || c == b'-'
        || c == b'.'
        || c == b'_'
        || c == b'~'
}

/// Normalize the path component according to RFC 3986.  This performs the
/// following operations:
/// * Alpha, digit, and the symbols `-`, `.`, `_`, and `~` (unreserved
///   characters) are left alone.
/// * Characters outside this range are percent-encoded.
/// * Percent-encoded values are upper-cased (`%2a` becomes `%2A`)
/// * Percent-encoded values in the unreserved space (`%41`-`%5A`, `%61`-`%7A`,
///   `%30`-`%39`, `%2D`, `%2E`, `%5F`, `%7E`) are converted to normal
///   characters.
///
/// If a percent encoding is incomplete, an error is returned.
pub fn normalize_uri_path_component(
    path_component: &str,
) -> Result<String, SignatureError> {
    let path_component = path_component.as_bytes();
    let mut i = 0;
    let ref mut result = Vec::<u8>::new();

    while i < path_component.len() {
        let c = path_component[i];

        if is_rfc3986_unreserved(c) {
            result.push(c);
            i += 1;
        } else if c == b'%' {
            if i + 2 >= path_component.len() {
                // % encoding would go beyond end of string; return an error.
                return Err(SignatureError::new(
                    ErrorKind::InvalidURIPath,
                    "Incomplete hex encoding"));
            }

            let hex_digits = &path_component[i + 1..i + 3];
            match hex::decode(hex_digits) {
                Ok(value) => {
                    assert_eq!(value.len(), 1);
                    let c = value[0];

                    if is_rfc3986_unreserved(c) {
                        result.push(c);
                    } else {
                        // Rewrite the hex-escape so it's always upper-cased.
                        write!(result, "%{:02X}", c)?;
                    }
                    i += 3;
                }
                Err(_) => {
                    return Err(SignatureError::new(
                        ErrorKind::InvalidURIPath,
                        &format!("Invalid hex encoding: {:?}", hex_digits),
                    ))
                }
            }
        } else if c == b'+' {
            // Plus-encoded space. Convert this to %20.
            result.write(b"%20")?;
            i += 1;
        } else {
            // Character should have been encoded.
            write!(result, "%{:02X}", c)?;
            i += 1;
        }
    }

    Ok(from_utf8(result.as_slice()).unwrap().to_string())
}

/// Normalizes the specified URI path, removing redundant slashes and relative
/// path components.
pub fn canonicalize_uri_path(
    uri_path: &str,
) -> Result<String, SignatureError> {
    // Special case: empty path is converted to '/'; also short-circuit the
    // usual '/' path here.
    if uri_path == "" || uri_path == "/" {
        return Ok("/".to_string());
    }

    // All other paths must be abolute.
    if !uri_path.starts_with("/") {
        return Err(SignatureError::new(
            ErrorKind::InvalidURIPath,
            &format!("Path is not absolute: {}", uri_path),
        ));
    }

    // Replace double slashes; this makes it easier to handle slashes at the
    // end.
    let uri_path = MULTISLASH.replace_all(uri_path, "/");

    // Examine each path component for relative directories.
    let mut components: Vec<String> =
        uri_path.split("/").map(|s| s.to_string()).collect();
    let mut i = 1; // Ignore the leading "/"
    while i < components.len() {
        let component = normalize_uri_path_component(&components[i])?;

        if component == "." {
            // Relative path: current directory; remove this.
            components.remove(i);

        // Don't increment i; with the deletion, we're now pointing to
        // the next element in the path.
        } else if component == ".." {
            // Relative path: parent directory.  Remove this and the previous
            // component.

            if i <= 1 {
                // This isn't allowed at the beginning!
                return Err(SignatureError::new(
                    ErrorKind::InvalidURIPath,
                    &format!(
                        "Relative path entry '..' navigates above root: \
                         {}",
                        uri_path
                    ),
                ));
            }

            components.remove(i - 1);
            components.remove(i - 1);

            // Since we've deleted two components, we need to back up one to
            // examine what's now the next component.
            i -= 1;
        } else {
            // Leave it alone; proceed to the next component.
            components[i] = component;
            i += 1;
        }
    }

    assert!(components.len() > 0);
    match components.len() {
        1 => Ok("/".to_string()),
        _ => Ok(components.join("/")),
    }
}

/// Normalize the query parameters by normalizing the keys and values of each
/// parameter and return a `HashMap` mapping each key to a *vector* of values
/// (since it is valid for a query parameters to appear multiple times).
///
/// The order of the values matches the order that they appeared in the query
/// string -- this is important for SigV4 validation.
pub fn normalize_query_parameters(
    query_string: &str,
) -> Result<HashMap<String, Vec<String>>, SignatureError> {
    if query_string.len() == 0 {
        return Ok(HashMap::new());
    }

    // Split the query string into parameters on '&' boundaries.
    let components = query_string.split("&");
    let mut result = HashMap::<String, Vec<String>>::new();

    for component in components {
        if component.len() == 0 {
            // Empty component; skip it.
            continue;
        }

        // Split the parameter into key and value portions on the '='
        let parts: Vec<&str> = component.splitn(2, "=").collect();
        let key = parts[0];
        let value = if parts.len() > 0 { parts[1] } else { "" };

        // Normalize the key and value.
        let norm_key = normalize_uri_path_component(key)?;
        let norm_value = normalize_uri_path_component(value)?;

        // If we already have a value for this key, append to it; otherwise,
        // create a new vector containing the value.
        if let Some(result_value) = result.get_mut(&norm_key) {
            result_value.push(norm_value);
        } else {
            result.insert(norm_key, vec![norm_value]);
        }
    }

    Ok(result)
}

/// Split Authorization header parameters from key=value parts into a HashMap.
pub fn split_authorization_header_parameters(
    parameters: &str
) -> Result<HashMap<String, String>, SignatureError> {
    let mut result = HashMap::<String, String>::new();
    for parameter in parameters.split(',') {
        let parts: Vec<&str> = parameter.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(SignatureError::new(
                ErrorKind::MalformedSignature,
                "invalid Authorization header: missing '='",
            ));
        }

        let key = parts[0].trim_start().to_string();
        let value = parts[1].trim_end().to_string();

        if result.contains_key(&key) {
            return Err(SignatureError::new(
                ErrorKind::MalformedSignature,
                &format!(
                    "invalid Authorization header: duplicate \
                        key {}",
                    key
                ),
            ));
        }

        result.insert(key, value);
    }

    Ok(result)
}


/// Return the signing key given a possibly non-final signing key.
pub fn get_signing_key<'a>(
    signing_key_kind: SigningKeyKind,
    key: &'a [u8],
    req_date: &'a str,
    region: &'a str,
    service: &'a str
) -> [u8; 32] {
    match signing_key_kind {
        SigningKeyKind::KSigning => key.try_into(),
        _ => {
            let k_service = get_kservice_key(signing_key_kind, key, req_date, region, service);
            hmac_sha256(k_service.as_ref(), AWS4_REQUEST.as_bytes()).as_ref().try_into()
        }
    }.expect("Invalid HMAC-SHA256 length")
}

pub fn get_kservice_key<'a>(
    signing_key_kind: SigningKeyKind,
    key: &'a [u8],
    req_date: &'a str,
    region: &'a str,
    service: &'a str
) -> [u8; 32] {
    match signing_key_kind {
        SigningKeyKind::KService => key.try_into(),
        _ => {
            let k_region = get_kregion_key(signing_key_kind, key, req_date, region);
            hmac_sha256(k_region.as_ref(), service.as_bytes()).as_ref().try_into()
        }
    }.expect("Invalid HMAC-SHA256 length")
}

pub fn get_kregion_key<'a> (
    signing_key_kind: SigningKeyKind,
    key: &'a [u8],
    req_date: &'a str,
    region: &'a str,
) -> [u8; 32] {
    match signing_key_kind {
        SigningKeyKind::KRegion => key.try_into(),
        _ => {
            let k_date = get_kdate_key(signing_key_kind, key, req_date);
            hmac_sha256(k_date.as_ref(), region.as_bytes()).as_ref().try_into()
        }
    }.expect("Invalid HMAC-SHA256 length")
}

pub fn get_kdate_key<'a>(
    signing_key_kind: SigningKeyKind,
    key: &'a [u8],
    req_date: &'a str,
) -> [u8; 32] {
    match signing_key_kind {
        SigningKeyKind::KDate => key.try_into(),
        _ => {
            // key is KSecret == AWS4 + secret key.
            // KDate = HMAC(KSecret + req_date)
            hmac_sha256(&key, req_date.as_bytes()).as_ref().try_into()
        }
    }.expect("Invalid HMAC-SHA256 length")
}
