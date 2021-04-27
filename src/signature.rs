//! AWS API request signatures verification routines.
//!
//! This is essentially the server-side complement of [rusoto_signature](https://crates.io/crates/rusoto_signature)
//! but follows the implementation of [python-aws-sig](https://github.com/dacut/python-aws-sig).
//!
//! This implements the AWS [SigV4](http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
//! and [SigV4S3](https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html)
//! algorithms.
//!
use std::{
    any::type_name,
    collections::{BTreeMap, HashMap},
    convert::{From, Into},
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    future::Future,
    io::{Error as IOError, Write},
    str::from_utf8,
    task::{Context, Poll},
};

use chrono::{Date, DateTime, Duration, Utc};
use hex;
use http::{
    header::{HeaderMap, HeaderValue},
    request::Parts,
    Uri,
};
use lazy_static::lazy_static;
use log::trace;
use regex::Regex;
use ring::digest::{digest, SHA256};
use scratchstack_aws_principal::PrincipalActor;
use tower::{BoxError, Service};

use crate::chronoutil::parse_date_str;
use crate::hmac::hmac_sha256;

/// Content-Type string for HTML forms
const APPLICATION_X_WWW_FORM_URLENCODED: &str = "application/x-www-form-urlencoded";

/// Algorithm for AWS SigV4
const AWS4_HMAC_SHA256: &str = "AWS4-HMAC-SHA256";

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
const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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

    /// Pattern for the start of an AWS4 signature Authorization header.
    static ref AWS4_HMAC_SHA256_RE: Regex = Regex::new(r"\s*AWS4-HMAC-SHA256(?:\s+|$)").unwrap();
}

/// Error returned when an attempt at validating an AWS SigV4 signature fails.
#[derive(Debug)]
pub enum SignatureError {
    /// Validation failed due to an underlying I/O error.
    IO(IOError),

    /// The request body used an unsupported character set encoding. Currently only UTF-8 is supported.
    InvalidBodyEncoding {
        message: String,
    },

    /// The request signature specified an invalid credential -- either the access key was not specified, or the
    /// credential scope (in the form `<code>_date_/_region_/_service_/aws4_request</code>`) did not match the
    /// expected value for the server.
    InvalidCredential {
        message: String,
    },

    /// The secret key contains invalid bytes.
    InvalidSecretKey,

    /// The signature passed in the request did not match the calculated signature value.
    InvalidSignature {
        message: String,
    },

    /// The type of signing key is incorrect for this operation.
    InvalidSigningKeyKind {
        message: String,
    },

    /// The URI path includes invalid components. This can be a malformed hex encoding (e.g. `%0J`), a non-absolute
    /// URI path (`foo/bar`), or a URI path that attempts to navigate above the root (`/x/../../../y`).
    InvalidURIPath {
        message: String,
    },

    /// An HTTP header was malformed -- the value could not be decoded as UTF-8, or the header was empty and this is
    /// not allowed (e.g. the `content-type` header), or the header could not be parsed (e.g., the `date` header is
    /// not a valid date).
    MalformedHeader {
        message: String,
    },

    /// A query parameter was malformed -- the value could not be decoded as UTF-8, or the parameter was empty and
    /// this is not allowed (e.g. a signature parameter), or the parameter could not be parsed (e.g., the `X-Amz-Date`
    ///  parameter is not a valid date).
    MalformedParameter {
        message: String,
    },

    /// The AWS SigV4 signature was malformed in some way. This can include invalid timestamp formats, missing
    /// authorization components, or unparseable components.
    MalformedSignature {
        message: String,
    },

    /// A required HTTP header (and its equivalent in the query string) is missing.
    MissingHeader {
        header: String,
    },

    /// A required query parameter is missing. This is used internally in the library; external callers only see
    /// `MissingHeader`.
    MissingParameter {
        parameter: String,
    },

    /// An HTTP header that can be specified only once was specified multiple times.
    MultipleHeaderValues {
        header: String,
    },

    /// A query parameter that can be specified only once was specified multiple times.
    MultipleParameterValues {
        parameter: String,
    },

    /// The timestamp in the request is out of the allowed range.
    TimestampOutOfRange {
        minimum: DateTime<Utc>,
        maximum: DateTime<Utc>,
        received: DateTime<Utc>,
    },

    /// The access key specified in the request is unknown.
    UnknownAccessKey {
        access_key: String,
    },

    /// The signature algorithm requested by the caller is unknown. This library only supports the `AWS4-HMAC-SHA256`
    /// algorithm.
    UnknownSignatureAlgorithm {
        algorithm: String,
    },
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::IO(ref e) => Display::fmt(e, f),
            Self::InvalidBodyEncoding {
                message,
            } => write!(f, "Invalid body encoding: {}", message),
            Self::InvalidCredential {
                message,
            } => write!(f, "Invalid credential: {}", message),
            Self::InvalidSecretKey => write!(f, "Invalid secret key"),
            Self::InvalidSignature {
                message,
            } => write!(f, "Invalid request signature: {}", message),
            Self::InvalidSigningKeyKind {
                message,
            } => write!(f, "Invalid signing key kind: {}", message),
            Self::InvalidURIPath {
                message,
            } => write!(f, "Invalid URI path: {}", message),
            Self::MalformedHeader {
                message,
            } => write!(f, "Malformed header: {}", message),
            Self::MalformedParameter {
                message,
            } => write!(f, "Malformed query parameter: {}", message),
            Self::MalformedSignature {
                message,
            } => write!(f, "Malformed signature: {}", message),
            Self::MissingHeader {
                header,
            } => write!(f, "Missing header: {}", header),
            Self::MissingParameter {
                parameter,
            } => write!(f, "Missing query parameter: {}", parameter),
            Self::MultipleHeaderValues {
                header,
            } => write!(f, "Multiple values for header: {}", header),
            Self::MultipleParameterValues {
                parameter,
            } => write!(f, "Multiple values for query parameter: {}", parameter),
            Self::TimestampOutOfRange {
                minimum,
                maximum,
                received,
            } => {
                write!(
                    f,
                    "Request timestamp out of range: minimum={}, maximum={}, received={}",
                    minimum, maximum, received
                )
            }
            Self::UnknownAccessKey {
                access_key,
            } => write!(f, "Unknown access key: {}", access_key),
            Self::UnknownSignatureAlgorithm {
                algorithm,
            } => write!(f, "Unknown signature algorithm: {}", algorithm),
        }
    }
}

impl Error for SignatureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IO(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<IOError> for SignatureError {
    fn from(e: IOError) -> SignatureError {
        SignatureError::IO(e)
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

impl Display for SigningKeyKind {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            SigningKeyKind::KSecret => write!(f, "KSecret"),
            SigningKeyKind::KDate => write!(f, "KDate"),
            SigningKeyKind::KRegion => write!(f, "KRegion"),
            SigningKeyKind::KService => write!(f, "KService"),
            SigningKeyKind::KSigning => write!(f, "KSigning"),
        }
    }
}

/// A signing key of some type.
#[derive(Clone)]
pub struct SigningKey {
    pub kind: SigningKeyKind,
    pub key: Vec<u8>,
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("SigningKey")
            .field("kind", &self.kind)
            .field("key", &format!("<{} bytes>", self.key.len()))
            .finish()
    }
}

impl SigningKey {
    /// Convert this key into the specified kind of key.
    ///
    /// This function returns an error if the existing key cannot be derived into the dervied key kind.
    pub fn try_derive<R, S>(
        &self,
        derived_key_kind: SigningKeyKind,
        req_date: &Date<Utc>,
        region: R,
        service: S,
    ) -> Result<Self, SignatureError>
    where
        R: AsRef<str>,
        S: AsRef<str>,
    {
        match derived_key_kind {
            SigningKeyKind::KSigning => Ok(self.to_ksigning_key(&req_date, &region, &service)),
            SigningKeyKind::KService => self.try_to_kservice_key(&req_date, &region, &service),
            SigningKeyKind::KRegion => self.try_to_kregion_key(&req_date, &region),
            SigningKeyKind::KDate => self.try_to_kdate_key(&req_date),
            SigningKeyKind::KSecret => match self.kind {
                SigningKeyKind::KSecret => Ok(self.clone()),
                _ => Err(SignatureError::InvalidSigningKeyKind {
                    message: format!("Cannot derive {} key from {} key", derived_key_kind, self.kind),
                }),
            },
        }
    }

    /// Return a KService key given a KService, KRegion, KDate, or KSecret key.
    ///
    /// This function returns an error if given a KSigning key.
    pub fn try_to_kservice_key<R, S>(&self, req_date: &Date<Utc>, region: R, service: S) -> Result<Self, SignatureError>
    where
        R: AsRef<str>,
        S: AsRef<str>,
    {
        match self.kind {
            SigningKeyKind::KService => Ok(self.clone()),
            SigningKeyKind::KRegion | SigningKeyKind::KDate | SigningKeyKind::KSecret => {
                let k_region = self.to_kregion_key(&req_date, &region);
                Ok(Self {
                    kind: SigningKeyKind::KService,
                    key: hmac_sha256(&k_region.key, service.as_ref().as_bytes()).as_ref().to_vec(),
                })
            }
            _ => Err(SignatureError::InvalidSigningKeyKind {
                message: format!("Can't derive KService key from {}", self.kind),
            }),
        }
    }

    /// Return a KRegion key given a KRegion, KDate, or KSecret key.
    ///
    /// This function returns an error if given a KSigning or KService key.
    pub fn try_to_kregion_key<R>(&self, req_date: &Date<Utc>, region: R) -> Result<Self, SignatureError>
    where
        R: AsRef<str>,
    {
        match self.kind {
            SigningKeyKind::KRegion => Ok(self.clone()),
            SigningKeyKind::KDate | SigningKeyKind::KSecret => {
                let k_date = self.to_kdate_key(req_date);
                Ok(Self {
                    kind: SigningKeyKind::KRegion,
                    key: hmac_sha256(&k_date.key, region.as_ref().as_bytes()).as_ref().to_vec(),
                })
            }
            _ => Err(SignatureError::InvalidSigningKeyKind {
                message: format!("Can't derive KRegion key from {}", self.kind),
            }),
        }
    }

    /// Return a KDate key given a KDate or KSecret key.
    ///
    /// This function returns an error if given a KRegion, KSigning, or KService key.
    pub fn try_to_kdate_key(&self, req_date: &Date<Utc>) -> Result<Self, SignatureError> {
        match self.kind {
            // Already the same type.
            SigningKeyKind::KDate => Ok(self.clone()),

            // key is KSecret == AWS4 + secret key.
            // KDate = HMAC(KSecret + req_date)
            SigningKeyKind::KSecret => {
                let ymd = format!("{}", req_date.format("%Y%m%d"));
                let k_secret_str = match from_utf8(&self.key) {
                    Ok(s) => s,
                    Err(_) => return Err(SignatureError::InvalidSecretKey),
                };
                Ok(SigningKey {
                    kind: SigningKeyKind::KDate,
                    key: hmac_sha256(format!("AWS4{}", k_secret_str).as_bytes(), ymd.as_bytes()).as_ref().to_vec(),
                })
            }

            _ => Err(SignatureError::InvalidSigningKeyKind {
                message: format!("Can't derive KDate key from {}", self.kind),
            }),
        }
    }

    /// Convert this key into the specified kind of key.
    ///
    /// This function panics if the existing key cannot be derived into the dervied key kind. Use `try_derive` for
    /// a non-panicking version.
    pub fn derive<R, S>(&self, derived_key_kind: SigningKeyKind, req_date: &Date<Utc>, region: R, service: S) -> Self
    where
        R: AsRef<str>,
        S: AsRef<str>,
    {
        match self.try_derive(derived_key_kind, &req_date, &region, &service) {
            Ok(s) => s,
            Err(e) => panic!("{}", e),
        }
    }

    /// Return a KSigning key given a KSigning, KService, KRegion, KDate, or KSecret key.
    ///
    /// This function is infallible (does not panic).
    pub fn to_ksigning_key<R, S>(&self, req_date: &Date<Utc>, region: R, service: S) -> Self
    where
        R: AsRef<str>,
        S: AsRef<str>,
    {
        match self.kind {
            SigningKeyKind::KSigning => self.clone(),
            _ => {
                let k_service = self.to_kservice_key(&req_date, &region, &service);
                Self {
                    kind: SigningKeyKind::KSigning,
                    key: hmac_sha256(&k_service.key, AWS4_REQUEST.as_bytes()).as_ref().to_vec(),
                }
            }
        }
    }

    /// Return a KService key given a KService, KRegion, KDate, or KSecret key.
    ///
    /// This function panics an error if given a KSigning key. Use `try_to_kservice_key` for a non-panicking version,.
    pub fn to_kservice_key<R, S>(&self, req_date: &Date<Utc>, region: R, service: S) -> Self
    where
        R: AsRef<str>,
        S: AsRef<str>,
    {
        match self.try_to_kservice_key(&req_date, &region, &service) {
            Ok(s) => s,
            Err(e) => panic!("{}", e),
        }
    }

    /// Return a KRegion key given a KRegion, KDate, or KSecret key.
    ///
    /// This function panics if given a KSigning or KService key. Use `try_to_kregion_key` for a for a non-panicking
    /// version.
    pub fn to_kregion_key<R>(&self, req_date: &Date<Utc>, region: R) -> Self
    where
        R: AsRef<str>,
    {
        match self.try_to_kregion_key(&req_date, &region) {
            Ok(s) => s,
            Err(e) => panic!("{}", e),
        }
    }

    /// Return a KDate key given a KDate or KSecret key.
    ///
    /// This function panics if given a KRegion, KSigning, or KService key. Use `try_to_kdate_key` for a non-panicking
    /// version.
    pub fn to_kdate_key(&self, req_date: &Date<Utc>) -> Self {
        match self.try_to_kdate_key(&req_date) {
            Ok(s) => s,
            Err(e) => panic!("{}", e),
        }
    }
}

/// A trait bound that describes how we obtain a signing key of a given type given a request. If you need to encapsulate
/// additional data (e.g. a database connection) to look up a key, use this to implement a struct.
pub trait GetSigningKey {}

pub struct GetSigningKeyRequest {
    pub signing_key_kind: SigningKeyKind,
    pub access_key: String,
    pub session_token: Option<String>,
    pub request_date: Date<Utc>,
    pub region: String,
    pub service: String,
}

impl<F, E> GetSigningKey
    for dyn Service<GetSigningKeyRequest, Response = (PrincipalActor, SigningKey), Error = E, Future = F>
where
    F: Future<Output = Result<(PrincipalActor, SigningKey), SignatureError>> + Send + Sync,
    E: Into<BoxError>,
{
}

#[derive(Clone, Copy)]
pub struct GetSigningKeyFn<F> {
    f: F,
}

/// Wrap an async function taking a signing request and returns a result into a `GetSigningKey` trait implementation.
///
/// The function signature should look like:
/// `async fn ..(kind: SigningKeyKind, access_key: String, session_token: Option<String>, request_date: Date<Utc>,
/// region: String, service: String) -> Result<(PrincipalActor, SigningKey), SignatureError>`
pub fn get_signing_key_fn<F>(f: F) -> GetSigningKeyFn<F> {
    GetSigningKeyFn {
        f,
    }
}

impl<F> Debug for GetSigningKeyFn<F> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("GetSigningKeyFn").field("f", &format_args!("{}", type_name::<F>())).finish()
    }
}

impl<F, Fut, E> Service<GetSigningKeyRequest> for GetSigningKeyFn<F>
where
    F: FnMut(SigningKeyKind, String, Option<String>, Date<Utc>, String, String) -> Fut,
    Fut: Future<Output = Result<(PrincipalActor, SigningKey), E>> + Send + Sync,
    E: Into<BoxError>,
{
    type Response = (PrincipalActor, SigningKey);
    type Error = E;
    type Future = Fut;

    fn poll_ready(&mut self, _cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: GetSigningKeyRequest) -> Self::Future {
        (self.f)(req.signing_key_kind, req.access_key, req.session_token, req.request_date, req.region, req.service)
    }
}

/// A data structure containing the elements of the request (some client-supplied, some service-supplied) involved in
/// the SigV4 verification process.
#[derive(Debug)]
pub struct Request {
    /// The request method (GET, PUT, POST) (client).
    pub request_method: String,

    /// The URI path being accessed (client).
    pub uri: Uri,

    /// The HTTP headers sent with the request (client).
    pub headers: HeaderMap<HeaderValue>,

    /// The request body (if any) (client).
    pub body: Option<Vec<u8>>,
}

impl Request {
    /// Create a Request from an HTTP request.
    pub fn from_http_request_parts(parts: &Parts, body: Option<Vec<u8>>) -> Self {
        Self {
            request_method: parts.method.as_str().to_string(),
            uri: parts.uri.clone(),
            headers: parts.headers.clone(),
            body: body,
        }
    }

    pub fn to_get_signing_key_request<A1, A2>(
        &self,
        signing_key_kind: SigningKeyKind,
        region: A1,
        service: A2,
    ) -> Result<GetSigningKeyRequest, SignatureError>
    where
        A1: AsRef<str>,
        A2: AsRef<str>,
    {
        Ok(GetSigningKeyRequest {
            signing_key_kind: signing_key_kind,
            access_key: self.get_access_key(&region, &service)?,
            session_token: self.get_session_token()?,
            request_date: self.get_request_date()?,
            region: region.as_ref().to_string(),
            service: service.as_ref().to_string(),
        })
    }

    /// Retrieve a header value, requiring exactly one value be present.
    pub(crate) fn get_header_one<S: Into<String>>(&self, header: S) -> Result<String, SignatureError> {
        let header = header.into();
        let mut iter = self.headers.get_all(&header).iter();
        match iter.next() {
            None => Err(SignatureError::MissingHeader {
                header: header.to_string(),
            }),
            Some(value) => match iter.next() {
                None => match from_utf8(value.as_bytes()) {
                    Ok(ref s) => Ok(s.to_string()),
                    Err(_) => Err(SignatureError::MalformedHeader {
                        message: format!("{} cannot does not contain valid UTF-8", header),
                    }),
                },
                Some(_) => Err(SignatureError::MultipleHeaderValues {
                    header: header.to_string(),
                }),
            },
        }
    }

    /// The query parameters from the request, normalized, in a mapping format.
    pub(crate) fn get_query_parameters(&self) -> Result<HashMap<String, Vec<String>>, SignatureError> {
        match self.uri.query() {
            Some(s) => normalize_query_parameters(s),
            None => Ok(HashMap::new()),
        }
    }

    /// Retrieve a query parameter, requiring exactly one value be present.
    pub(crate) fn get_query_param_one(&self, parameter: &str) -> Result<String, SignatureError> {
        match self.get_query_parameters()?.get(parameter) {
            None => Err(SignatureError::MissingParameter {
                parameter: parameter.to_string(),
            }),
            Some(ref values) => match values.len() {
                0 => Err(SignatureError::MissingParameter {
                    parameter: parameter.to_string(),
                }),
                1 => Ok(values[0].to_string()),
                _ => Err(SignatureError::MultipleParameterValues {
                    parameter: parameter.to_string(),
                }),
            },
        }
    }

    /// Get the content type and character set used in the body
    pub(crate) fn get_content_type_and_charset(&self) -> Result<(String, String), SignatureError> {
        let content_type_opts = self.get_header_one(CONTENT_TYPE)?;

        let mut parts = content_type_opts.split(";");
        let content_type = match parts.next() {
            Some(ref s) => s.trim(),
            None => {
                return Err(SignatureError::MalformedHeader {
                    message: "content-type header is empty".to_string(),
                })
            }
        };

        for option in parts {
            let opt_trim = option.trim();
            let opt_parts: Vec<&str> = opt_trim.splitn(2, "=").collect();

            if opt_parts.len() == 2 && opt_parts[0] == CHARSET {
                return Ok((content_type.to_string(), opt_parts[1].trim().to_lowercase()));
            }
        }

        return Ok((content_type.to_string(), "utf-8".to_string()));
    }

    /// The canonicalized URI path for a request.
    pub(crate) fn get_canonical_uri_path(&self) -> Result<String, SignatureError> {
        canonicalize_uri_path(&self.uri.path())
    }

    /// The canonical query string from the query parameters.
    ///
    /// This takes the query_string from the request, merges it with the body if the request has a body of type
    /// `application/x-www-form-urlencoded`, and orders the parameters.
    pub(crate) fn get_canonical_query_string(&self) -> Result<String, SignatureError> {
        let query_parameters = self.get_query_parameters()?;
        let mut results = Vec::new();

        for (key, values) in query_parameters.iter() {
            // Don't include the signature itself.
            if key != X_AMZ_SIGNATURE {
                for value in values.iter() {
                    results.push(format!("{}={}", key, value));
                }
            }
        }

        if let Ok((content_type, charset)) = self.get_content_type_and_charset() {
            if content_type == APPLICATION_X_WWW_FORM_URLENCODED {
                if charset != "utf-8" && charset != "utf8" {
                    return Err(SignatureError::InvalidBodyEncoding {
                        message: format!("application/x-www-form-urlencoded body uses unsupported charset {}", charset),
                    });
                }

                // Parse the body as a URL string
                let body_utf8 = match &self.body {
                    None => "",
                    Some(body) => match from_utf8(&body) {
                        Ok(s) => s,
                        Err(_) => {
                            return Err(SignatureError::InvalidBodyEncoding {
                                message: "application/x-www-form-urlencoded body contains invalid UTF-8 characters"
                                    .to_string(),
                            });
                        }
                    },
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

    /// The parameters from the Authorization header (only -- not the query parameter). If the Authorization header is not present
    /// or is not an AWS SigV4 header, an Err(SignatureError) is returned.
    pub(crate) fn get_authorization_header_parameters(&self) -> Result<HashMap<String, String>, SignatureError> {
        let auth_headers = self.headers.get_all(AUTHORIZATION);
        let mut parameters_opt: Option<&str> = None;

        let mut auth_iter = auth_headers.iter();
        loop {
            match auth_iter.next() {
                None => break,
                Some(auth_header) => match auth_header.to_str() {
                    Ok(auth_header) => {
                        if let Some(captures) = AWS4_HMAC_SHA256_RE.captures(auth_header) {
                            if parameters_opt.is_some() {
                                return Err(SignatureError::MultipleHeaderValues {
                                    header: AUTHORIZATION.to_string(),
                                });
                            }

                            parameters_opt = Some(auth_header.split_at(captures.get(0).unwrap().end()).1);
                            trace!("parameters_opt set to {:?}; captures={:?}", parameters_opt, captures);
                        } else {
                            trace!("Not SigV4: {:?}", auth_header);
                        }
                    }
                    Err(_) => (),
                },
            }
        }

        match parameters_opt {
            None => Err(SignatureError::MissingHeader {
                header: AUTHORIZATION.to_string(),
            }),
            Some(parameters) => {
                if parameters.len() == 0 {
                    Err(SignatureError::MalformedSignature {
                        message: format!("invalid Authorization header: missing parameters"),
                    })
                } else {
                    let result = split_authorization_header_parameters(&parameters)?;
                    if result.get(CREDENTIAL).is_none() {
                        Err(SignatureError::MalformedSignature {
                            message: format!("invalid Authorization header: missing Credential"),
                        })
                    } else if result.get(SIGNATURE).is_none() {
                        Err(SignatureError::MalformedSignature {
                            message: format!("invalid Authorization header: missing Signature"),
                        })
                    } else if result.get(SIGNEDHEADERS).is_none() {
                        Err(SignatureError::MalformedSignature {
                            message: format!("invalid Authorization header: missing SignedHeaders"),
                        })
                    } else {
                        Ok(result)
                    }
                }
            }
        }
    }

    /// Returns a sorted dictionary containing the signed header names and their values.
    pub(crate) fn get_signed_headers(&self) -> Result<BTreeMap<String, Vec<Vec<u8>>>, SignatureError> {
        // See if the signed headers are listed in the query string.
        let qp_result = self.get_query_param_one(X_AMZ_SIGNEDHEADERS);
        let ah_result;
        let ah_signedheaders;

        let signed_headers = match qp_result {
            Ok(ref sh) => sh,
            Err(e) => match e {
                SignatureError::MissingParameter {
                    ..
                } => {
                    ah_result = self.get_authorization_header_parameters();
                    match ah_result {
                        Err(e) => return Err(e),
                        Ok(ref ahp) => {
                            ah_signedheaders = ahp.get(SIGNEDHEADERS);
                            match ah_signedheaders {
                                None => {
                                    return Err(SignatureError::MalformedSignature {
                                        message: "invalid Authorization header: missing SignedHeaders".to_string(),
                                    })
                                }
                                Some(headers) => headers,
                            }
                        }
                    }
                }
                _ => return Err(e),
            },
        };

        // Header names are separated by semicolons.
        let parts: Vec<String> = signed_headers.split(';').map(|s| s.to_string()).collect();

        // Make sure the signed headers list is canonicalized. For security reasons, we consider it an error if it isn't.
        let mut canonicalized = parts.clone();
        canonicalized.sort_unstable_by(|a, b| a.to_lowercase().partial_cmp(&b.to_lowercase()).unwrap());

        if parts != canonicalized {
            return Err(SignatureError::MalformedSignature {
                message: "SignedHeaders is not canonicalized".to_string(),
            });
        }

        let mut result = BTreeMap::<String, Vec<Vec<u8>>>::new();
        for header in canonicalized.iter() {
            let mut header_values = Vec::new();
            let mut v_iter = self.headers.get_all(header).iter();

            while let Some(ref value) = v_iter.next() {
                match from_utf8(value.as_bytes()) {
                    Ok(value) => header_values.push(value.as_bytes().to_vec()),
                    Err(_) => {
                        return Err(SignatureError::MalformedHeader {
                            message: format!("Header {} contains invalid UTF-8 characters", header),
                        })
                    }
                }
            }
            if header_values.len() == 0 {
                return Err(SignatureError::MissingHeader {
                    header: header.to_string(),
                });
            }

            result.insert(header.to_string(), header_values);
        }

        Ok(result)
    }

    /// The date of the request.
    pub(crate) fn get_request_date(&self) -> Result<Date<Utc>, SignatureError> {
        let timestamp = self.get_request_timestamp()?;
        Ok(timestamp.date())
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
    /// without milliseconds (_must_ per [AWS documentation](https://docs.aws.amazon.com/general/latest/gr/sigv4-date-handling.html)).
    /// However, the AWS SigV4 test suite includes a variety of date formats,
    /// including RFC 2822, RFC 3339, and ISO 8601. This routine allows all
    /// of these formats.
    pub(crate) fn get_request_timestamp(&self) -> Result<DateTime<Utc>, SignatureError> {
        // It turns out that unrolling this logic is the most straightforward way to return sensible error messages.

        match self.get_query_param_one(X_AMZ_DATE) {
            Ok(date_str) => parse_date_str(
                &date_str,
                SignatureError::MalformedParameter {
                    message: "X-Amz-Date is not a valid timestamp".to_string(),
                },
            ),
            Err(e) => match e {
                SignatureError::MissingParameter {
                    ..
                } => match self.get_header_one(X_AMZ_DATE_LOWER) {
                    Ok(date_str) => parse_date_str(
                        &date_str,
                        SignatureError::MalformedHeader {
                            message: "X-Amz-Date is not a valid timestamp".to_string(),
                        },
                    ),
                    Err(e) => match e {
                        SignatureError::MissingHeader {
                            ..
                        } => match self.get_header_one(DATE) {
                            Ok(date_str) => parse_date_str(
                                &date_str,
                                SignatureError::MalformedHeader {
                                    message: "Date is not a valid timestamp".to_string(),
                                },
                            ),
                            Err(e) => Err(e),
                        },
                        _ => Err(e),
                    },
                },
                _ => Err(e),
            },
        }
    }

    /// The scope of the credentials to use, as calculated by the service's region and name, but using the timestamp
    /// of the request.
    ///
    /// The result is a string in the form `YYYYMMDD/region/service/aws4_request`.
    pub(crate) fn get_credential_scope<A1, A2>(&self, region: A1, service: A2) -> Result<String, SignatureError>
    where
        A1: AsRef<str>,
        A2: AsRef<str>,
    {
        let ts = self.get_request_timestamp()?;
        let date = ts.date().format("%Y%m%d");
        Ok(format!("{}/{}/{}/{}", date, region.as_ref(), service.as_ref(), AWS4_REQUEST))
    }

    /// The access key used to sign the request.
    ///
    /// If the credential scope does not match our expected credential scope, a SignatureError is returned.
    pub(crate) fn get_access_key<A1, A2>(&self, region: A1, service: A2) -> Result<String, SignatureError>
    where
        A1: AsRef<str>,
        A2: AsRef<str>,
    {
        let qp_result = self.get_query_param_one(X_AMZ_CREDENTIAL);
        let auth_headers;

        let credential = match qp_result {
            Ok(ref c) => c,
            Err(e) => match e {
                SignatureError::MissingParameter {
                    ..
                } => {
                    auth_headers = self.get_authorization_header_parameters()?;
                    match auth_headers.get(CREDENTIAL) {
                        Some(c) => c,
                        None => {
                            trace!("auth_headers={:?}", auth_headers);
                            return Err(SignatureError::MalformedSignature {
                                message: "invalid Authorization header: missing Credential".to_string(),
                            });
                        }
                    }
                }
                _ => return Err(e),
            },
        };

        let parts: Vec<&str> = credential.splitn(2, '/').collect();
        if parts.len() != 2 {
            return Err(SignatureError::InvalidCredential {
                message: "Malformed credential".to_string(),
            });
        }

        let access_key = parts[0];
        let request_scope = parts[1];
        let server_scope = self.get_credential_scope(region, service)?;
        if request_scope == server_scope {
            Ok(access_key.to_string())
        } else {
            Err(SignatureError::InvalidCredential {
                message: format!("Invalid credential scope: Expected {} instead of {}", server_scope, request_scope),
            })
        }
    }

    /// The session token sent with the access key.
    ///
    /// Session tokens are used only for temporary credentials. If a long-term credential was used, the result
    /// is `Ok(None)`.
    pub(crate) fn get_session_token(&self) -> Result<Option<String>, SignatureError> {
        let qp_result = self.get_query_param_one(X_AMZ_SECURITY_TOKEN);

        match qp_result {
            Ok(token) => Ok(Some(token)),
            Err(e) => match e {
                SignatureError::MissingParameter {
                    ..
                } => match self.get_header_one(X_AMZ_SECURITY_TOKEN_LOWER) {
                    Ok(token) => Ok(Some(token)),
                    Err(e) => match e {
                        SignatureError::MissingHeader {
                            ..
                        } => Ok(None),
                        _ => Err(e),
                    },
                },
                _ => Err(e),
            },
        }
    }

    /// The signature passed into the request.
    pub(crate) fn get_request_signature(&self) -> Result<String, SignatureError> {
        match self.get_query_param_one(X_AMZ_SIGNATURE) {
            Ok(sig) => Ok(sig),
            Err(e) => match e {
                SignatureError::MissingParameter {
                    ..
                } => {
                    let ah: HashMap<String, String> = self.get_authorization_header_parameters()?;
                    match ah.get(SIGNATURE) {
                        Some(c) => Ok(c.to_string()),
                        None => Err(SignatureError::MalformedSignature {
                            message: "invalid Authorization header: missing Signature".to_string(),
                        }),
                    }
                }
                _ => Err(e),
            },
        }
    }

    /// The AWS SigV4 canonical request given parameters from the HTTP request, as outlined in the
    /// [AWS documentation](http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html).
    ///
    /// The canonical request is:
    /// ```text
    ///     request_method + '\n' +
    ///     canonical_uri_path + '\n' +
    ///     canonical_query_string + '\n' +
    ///     signed_headers + '\n' +
    ///     sha256(body).hexdigest()
    /// ```
    pub(crate) fn get_canonical_request(&self) -> Result<Vec<u8>, SignatureError> {
        let mut result = Vec::<u8>::new();
        let mut header_keys = Vec::<u8>::new();
        let canonical_uri_path = self.get_canonical_uri_path()?;
        let canonical_query_string = self.get_canonical_query_string()?;
        let body_hex_digest = self.get_body_digest()?;

        result.write(self.request_method.as_bytes())?;
        result.push(b'\n');
        result.write(canonical_uri_path.as_bytes())?;
        result.push(b'\n');
        result.write(canonical_query_string.as_bytes())?;
        result.push(b'\n');

        let mut is_first_key = true;

        for (key, values) in self.get_signed_headers()? {
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

                let value_collapsed_space = MULTISPACE.replace_all(from_utf8(value).unwrap(), " ");
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

        match self.get_content_type_and_charset() {
            Ok((content_type, _)) if content_type == APPLICATION_X_WWW_FORM_URLENCODED => {
                result.write(SHA256_EMPTY.as_bytes())?
            }
            _ => result.write(body_hex_digest.as_bytes())?,
        };

        Ok(result)
    }

    /// The SHA-256 hex digest of the body.
    pub(crate) fn get_body_digest(&self) -> Result<String, SignatureError> {
        match &self.body {
            None => Ok(SHA256_EMPTY.to_string()),
            Some(body) => Ok(hex::encode(digest(&SHA256, &body).as_ref())),
        }
    }

    /// The string to sign for the request.
    pub(crate) fn get_string_to_sign<A1, A2>(&self, region: A1, service: A2) -> Result<Vec<u8>, SignatureError>
    where
        A1: AsRef<str>,
        A2: AsRef<str>,
    {
        let mut result = Vec::new();
        let timestamp = self.get_request_timestamp()?;
        let credential_scope = self.get_credential_scope(region, service)?;
        let canonical_request = self.get_canonical_request()?;
        trace!("Credential scope: {:?}", credential_scope);
        trace!("Canonical request: {:?}", from_utf8(canonical_request.as_ref()));

        result.write(AWS4_HMAC_SHA256.as_bytes())?;
        result.push(b'\n');
        write!(&mut result, "{}", timestamp.format(ISO8601_COMPACT_FORMAT))?;
        result.push(b'\n');
        result.write(credential_scope.as_bytes())?;
        result.push(b'\n');
        result.write(hex::encode(digest(&SHA256, &canonical_request).as_ref()).as_bytes())?;

        Ok(result)
    }
}

/// Return the expected signature for a request.
pub fn sigv4_get_expected_signature<A1, A2>(
    req: &Request,
    signing_key: &SigningKey,
    region: A1,
    service: A2,
) -> Result<String, SignatureError>
where
    A1: AsRef<str>,
    A2: AsRef<str>,
{
    let k_signing = signing_key.to_ksigning_key(&(req.get_request_date()?), &region, &service);
    let string_to_sign = req.get_string_to_sign(&region, &service)?;
    trace!("String to sign: {:?}", from_utf8(string_to_sign.as_ref()));

    Ok(hex::encode(hmac_sha256(&k_signing.key, &string_to_sign).as_ref()))
}

/// Verify a SigV4 request at a particular point-in-time. This verifies that the request timestamp is not beyond the
/// allowed timestamp mismatch against the specified point-in-time, and that the request signature matches our expected
/// signature.
///
/// This is mainly for unit testing. For general purpose use, use `sigv4_verify`.
pub fn sigv4_verify_at<A1, A2>(
    req: &Request,
    signing_key: &SigningKey,
    server_timestamp: &DateTime<Utc>,
    allowed_mismatch: Option<Duration>,
    region: A1,
    service: A2,
) -> Result<(), SignatureError>
where
    A1: AsRef<str>,
    A2: AsRef<str>,
{
    if let Some(mm) = allowed_mismatch {
        let req_ts = req.get_request_timestamp()?;
        let min_ts = server_timestamp.checked_sub_signed(mm).unwrap_or(*server_timestamp);
        let max_ts = server_timestamp.checked_add_signed(mm).unwrap_or(*server_timestamp);

        if req_ts < min_ts || req_ts > max_ts {
            return Err(SignatureError::TimestampOutOfRange {
                minimum: min_ts,
                maximum: max_ts,
                received: req_ts,
            });
        }
    }

    let request_sig = req.get_request_signature()?;
    let expected_sig = sigv4_get_expected_signature(&req, &signing_key, &region, &service)?;

    if expected_sig != request_sig {
        Err(SignatureError::InvalidSignature {
            message: format!("Expected {} instead of {}", expected_sig, request_sig),
        })
    } else {
        Ok(())
    }
}

/// Verify a SigV4 request. This verifies that the request timestamp is not beyond the allowed timestamp mismatch
/// against the current time, and that the request signature matches our expected signature.
pub fn sigv4_verify<A1, A2>(
    req: &Request,
    signing_key: &SigningKey,
    allowed_mismatch: Option<Duration>,
    region: A1,
    service: A2,
) -> Result<(), SignatureError>
where
    A1: AsRef<str>,
    A2: AsRef<str>,
{
    sigv4_verify_at(req, signing_key, &Utc::now(), allowed_mismatch, region, service)
}

/// Indicates whether the specified byte is RFC3986 unreserved -- i.e., can be represented without being
/// percent-encoded, e.g. '?' -> '%3F'.
pub fn is_rfc3986_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_' || c == b'~'
}

/// Normalize the path component according to RFC 3986.  This performs the following operations:
/// * Alpha, digit, and the symbols `-`, `.`, `_`, and `~` (unreserved characters) are left alone.
/// * Characters outside this range are percent-encoded.
/// * Percent-encoded values are upper-cased (`%2a` becomes `%2A`)
/// * Percent-encoded values in the unreserved space (`%41`-`%5A`, `%61`-`%7A`, `%30`-`%39`, `%2D`, `%2E`, `%5F`,
///   `%7E`) are converted to normal characters.
///
/// If a percent encoding is incomplete, an error is returned.
pub fn normalize_uri_path_component(path_component: &str) -> Result<String, SignatureError> {
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
                return Err(SignatureError::InvalidURIPath {
                    message: "Incomplete hex encoding".to_string(),
                });
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
                    return Err(SignatureError::InvalidURIPath {
                        message: format!("Invalid hex encoding: {:?}", hex_digits),
                    })
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

/// Normalizes the specified URI path, removing redundant slashes and relative path components.
pub fn canonicalize_uri_path(uri_path: &str) -> Result<String, SignatureError> {
    // Special case: empty path is converted to '/'; also short-circuit the usual '/' path here.
    if uri_path == "" || uri_path == "/" {
        return Ok("/".to_string());
    }

    // All other paths must be abolute.
    if !uri_path.starts_with("/") {
        return Err(SignatureError::InvalidURIPath {
            message: format!("Path is not absolute: {}", uri_path),
        });
    }

    // Replace double slashes; this makes it easier to handle slashes at the end.
    let uri_path = MULTISLASH.replace_all(uri_path, "/");

    // Examine each path component for relative directories.
    let mut components: Vec<String> = uri_path.split("/").map(|s| s.to_string()).collect();
    let mut i = 1; // Ignore the leading "/"
    while i < components.len() {
        let component = normalize_uri_path_component(&components[i])?;

        if component == "." {
            // Relative path: current directory; remove this.
            components.remove(i);

            // Don't increment i; with the deletion, we're now pointing to the next element in the path.
        } else if component == ".." {
            // Relative path: parent directory.  Remove this and the previous component.

            if i <= 1 {
                // This isn't allowed at the beginning!
                return Err(SignatureError::InvalidURIPath {
                    message: format!("Relative path entry '..' navigates above root: {}", uri_path),
                });
            }

            components.remove(i - 1);
            components.remove(i - 1);

            // Since we've deleted two components, we need to back up one to examine what's now the next component.
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

/// Normalize the query parameters by normalizing the keys and values of each parameter and return a `HashMap` mapping
/// each key to a *vector* of values (since it is valid for a query parameters to appear multiple times).
///
/// The order of the values matches the order that they appeared in the query string -- this is important for SigV4
/// validation.
pub fn normalize_query_parameters(query_string: &str) -> Result<HashMap<String, Vec<String>>, SignatureError> {
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
        let value = if parts.len() > 0 {
            parts[1]
        } else {
            ""
        };

        // Normalize the key and value.
        let norm_key = normalize_uri_path_component(key)?;
        let norm_value = normalize_uri_path_component(value)?;

        // If we already have a value for this key, append to it; otherwise, create a new vector containing the value.
        if let Some(result_value) = result.get_mut(&norm_key) {
            result_value.push(norm_value);
        } else {
            result.insert(norm_key, vec![norm_value]);
        }
    }

    Ok(result)
}

/// Split Authorization header parameters from key=value parts into a HashMap.
pub fn split_authorization_header_parameters(parameters: &str) -> Result<HashMap<String, String>, SignatureError> {
    trace!("split_authorization_header_parameters: parameters={:?}", parameters);
    let mut result = HashMap::<String, String>::new();
    for parameter in parameters.split(',') {
        let parts: Vec<&str> = parameter.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(SignatureError::MalformedSignature {
                message: "invalid Authorization header: missing '='".to_string(),
            });
        }

        let key = parts[0].trim_start().to_string();
        let value = parts[1].trim_end().to_string();

        if result.contains_key(&key) {
            return Err(SignatureError::MalformedSignature {
                message: format!("invalid Authorization header: duplicate field {}", key),
            });
        }

        result.insert(key, value);
    }

    Ok(result)
}
