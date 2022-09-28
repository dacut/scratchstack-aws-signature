use {
    http::status::StatusCode,
    std::{
        error::Error,
        fmt::{Display, Formatter, Result as FmtResult},
        io::Error as IOError,
    },
};

/// Error returned when an attempt at validating an AWS SigV4 signature fails.
#[derive(Debug)]
pub enum SignatureError {
    /// The security token included with the request is expired.
    ExpiredToken(/* message */ String),

    /// Validation failed due to an underlying I/O error.
    IO(IOError),

    /// Validation failed due to an internal service error.
    InternalServiceError(Box<dyn Error + Send + Sync>),

    /// The request body used an unsupported character set encoding. Currently only UTF-8 is supported.
    InvalidBodyEncoding(/* message */ String),

    /// The AWS access key provided does not exist in our records.
    InvalidClientTokenId(/* message */ String),

    /// The request signature does not conform to AWS standards. Sample messages:  
    /// `Authorization header requires 'Credential' parameter. Authorization=...`  
    /// `Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header.`  
    /// `Date must be in ISO-8601 'basic format'. Got '...'. See http://en.wikipedia.org/wiki/ISO_8601`  
    /// `Unsupported AWS 'algorithm': 'AWS4-HMAC-SHA512'`
    IncompleteSignature(/* message */ String),

    /// The request signature specified an invalid credential -- either the access key was not specified, or the
    /// credential scope (in the form `<code>_date_/_region_/_service_/aws4_request</code>`) did not match the
    /// expected value for the server.
    InvalidCredential(/* message */ String),

    /// The URI path includes invalid components. This can be a malformed hex encoding (e.g. `%0J`), a non-absolute
    /// URI path (`foo/bar`), or a URI path that attempts to navigate above the root (`/x/../../../y`).
    InvalidURIPath(/* message */ String),

    /// An HTTP header was malformed -- the value could not be decoded as UTF-8, or the header was empty and this is
    /// not allowed (e.g. the `content-type` header), or the header could not be parsed (e.g., the `date` header is
    /// not a valid date).
    MalformedHeader(/* message */ String),

    /// A query parameter was malformed -- the value could not be decoded as UTF-8, or the parameter was empty and
    /// this is not allowed (e.g. a signature parameter), or the parameter could not be parsed (e.g., the `X-Amz-Date`
    /// parameter is not a valid date).
    ///
    /// `Incomplete trailing escape % sequence`
    MalformedQueryString(/* message */ String),

    /// The request must contain either a valid (registered) AWS access key ID or X.509 certificate. Sample messages:  
    /// `Request is missing Authentication Token`  
    MissingAuthenticationToken(/* message */ String),

    /// Signature did not match the calculated signature value.
    /// Example messages:  
    /// `The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.`  
    /// `Signature expired: 20210502T144040Z is now earlier than 20210502T173143Z (20210502T174643Z - 15 min.)`  
    /// `Signature not yet current: 20210502T183640Z is still later than 20210502T175140Z (20210502T173640Z + 15 min.)`
    SignatureDoesNotMatch(Option</* message */ String>),
}

impl SignatureError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ExpiredToken(_) => "ExpiredToken",
            Self::IO(_) | Self::InternalServiceError(_) => "InternalServiceError",
            Self::InvalidBodyEncoding(_) => "InvalidBodyEncoding",
            Self::InvalidClientTokenId(_) => "InvalidClientTokenId",
            Self::IncompleteSignature(_) => "IncomlpeteSignature",
            Self::InvalidCredential(_) => "InvalidCredential",
            Self::InvalidURIPath(_) => "InvalidURIPath",
            Self::MalformedHeader(_) => "MalformedHeader",
            Self::MalformedQueryString(_) => "MalformedQueryString",
            Self::MissingAuthenticationToken(_) => "MissingAuthenticationToken",
            Self::SignatureDoesNotMatch(_) => "SignatureDoesNotMatch",
        }
    }

    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::InvalidBodyEncoding(_)
            | Self::MalformedHeader(_)
            | Self::MalformedQueryString(_)
            | Self::MissingAuthenticationToken(_) => StatusCode::BAD_REQUEST,
            Self::IO(_) | Self::InternalServiceError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::ExpiredToken(msg) => f.write_str(msg),
            Self::IO(ref e) => Display::fmt(e, f),
            Self::InternalServiceError(ref e) => Display::fmt(e, f),
            Self::InvalidBodyEncoding(msg) => f.write_str(msg),
            Self::InvalidClientTokenId(msg) => f.write_str(msg),
            Self::IncompleteSignature(msg) => f.write_str(msg),
            Self::InvalidCredential(msg) => f.write_str(msg),
            Self::InvalidURIPath(msg) => f.write_str(msg),
            Self::MalformedHeader(msg) => f.write_str(msg),
            Self::MalformedQueryString(msg) => f.write_str(msg),
            Self::MissingAuthenticationToken(msg) => f.write_str(msg),
            Self::SignatureDoesNotMatch(msg) => {
                if let Some(msg) = msg {
                    f.write_str(msg)
                } else {
                    Ok(())
                }
            }
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

impl From<Box<dyn Error + Send + Sync>> for SignatureError {
    fn from(e: Box<dyn Error + Send + Sync>) -> SignatureError {
        match e.downcast::<SignatureError>() {
            Ok(sig_err) => *sig_err,
            Err(e) => SignatureError::InternalServiceError(e),
        }
    }
}
