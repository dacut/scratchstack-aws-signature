use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    io::Error as IOError,
};

/// Error returned when an attempt at validating an AWS SigV4 signature fails.
#[derive(Debug)]
pub enum SignatureError {
    /// The security token included with the request is expired.
    ExpiredToken,

    /// Validation failed due to an underlying I/O error.
    IO(IOError),

    /// Validation failed due to an internal service error.
    InternalServiceError(Box<dyn Error + Send + Sync>),

    /// The request body used an unsupported character set encoding. Currently only UTF-8 is supported.
    InvalidBodyEncoding(/* message */ String),

    /// The AWS access key provided does not exist in our records.
    InvalidClientTokenId,

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

    /// The secret key contains invalid bytes.
    InvalidSecretKey,

    /// The type of signing key is incorrect for this operation.
    InvalidSigningKeyKind(/* message */ String),

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

    /// The AWS SigV4 signature was malformed in some way. This can include invalid timestamp formats, missing
    /// authorization components, or unparseable components.
    MalformedSignature(/* message */ String),

    /// The request must contain either a valid (registered) AWS access key ID or X.509 certificate. Sample messages:  
    /// `Request is missing Authentication Token`  
    MissingAuthenticationToken(/* message */ String),

    /// A required HTTP header (and its equivalent in the query string) is missing.
    MissingHeader(/* message */ String),

    /// A required query parameter is missing. This is used internally in the library; external callers only see
    /// `MissingHeader`.
    MissingParameter(/* message */ String),

    /// An HTTP header that can be specified only once was specified multiple times.
    MultipleHeaderValues(/* message */ String),

    /// A query parameter that can be specified only once was specified multiple times.
    MultipleParameterValues(/* message */ String),

    /// Signature did not match the calculated signature value.
    /// Example messages:  
    /// `The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.`  
    /// `Signature expired: 20210502T144040Z is now earlier than 20210502T173143Z (20210502T174643Z - 15 min.)`  
    /// `Signature not yet current: 20210502T183640Z is still later than 20210502T175140Z (20210502T173640Z + 15 min.)`
    SignatureDoesNotMatch(Option</* message */ String>),
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::ExpiredToken => write!(f, "The security token included with the request is expired"),
            Self::IO(ref e) => Display::fmt(e, f),
            Self::InternalServiceError(ref e) => Display::fmt(e, f),
            Self::InvalidBodyEncoding(msg) => f.write_str(msg),
            Self::InvalidClientTokenId => write!(f, "The security token included in the request is invalid"),
            Self::IncompleteSignature(msg) => f.write_str(msg),
            Self::InvalidCredential(msg) => f.write_str(msg),
            Self::InvalidSecretKey => write!(f, "Invalid secret key"),
            Self::InvalidSigningKeyKind(msg) => f.write_str(msg),
            Self::InvalidURIPath(msg) => f.write_str(msg),
            Self::MalformedHeader(msg) => f.write_str(msg),
            Self::MalformedQueryString(msg) => f.write_str(msg),
            Self::MalformedSignature(msg) => f.write_str(msg),
            Self::MissingHeader(msg) => f.write_str(msg),
            Self::MissingAuthenticationToken(msg) => f.write_str(msg),
            Self::MissingParameter(msg) => f.write_str(msg),
            Self::MultipleHeaderValues(msg) => f.write_str(msg),
            Self::MultipleParameterValues(msg) => f.write_str(msg),
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
