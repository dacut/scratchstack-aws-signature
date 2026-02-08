use {
    crate::constants::*,
    http::status::StatusCode,
    scratchstack_errors::ServiceError,
    std::{
        error::Error,
        fmt::{Display, Formatter, Result as FmtResult},
        io::Error as IOError,
    },
};

/// Error returned when an attempt at validating an AWS SigV4 signature fails.
#[derive(Debug)]
#[non_exhaustive]
pub enum SignatureError {
    /// The request contains a query parameter that duplicates a header value.
    DuplicateHeaderAndQueryParameter(/* message */ String),

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

    /// The content-type of the request is unsupported.
    InvalidContentType(/* message */ String),

    /// Invalid request method.
    InvalidRequestMethod(/* message */ String),

    /// The request signature does not conform to AWS standards. Sample messages:  
    /// `Authorization header requires 'Credential' parameter. Authorization=...`  
    /// `Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header.`  
    /// `Date must be in ISO-8601 'basic format'. Got '...'. See http://en.wikipedia.org/wiki/ISO_8601`  
    /// `Unsupported AWS 'algorithm': 'AWS4-HMAC-SHA512'`
    IncompleteSignature(/* message */ String),

    /// The URI path includes invalid components. This can be a malformed hex encoding (e.g. `%0J`), a non-absolute
    /// URI path (`foo/bar`), or a URI path that attempts to navigate above the root (`/x/../../../y`).
    InvalidURIPath(/* message */ String),

    /// A header was malformed -- the value could not be decoded as ASCII; the header was empty and this is not
    /// allowed (e.g. an `authorization` header); or the header could not be parsed (e.g., the `x-amz-date` header
    /// is not a valid date).
    MalformedHeader(/* message */ String),

    /// A query parameter was malformed -- the value could not be decoded as UTF-8; the parameter was empty and
    /// this is not allowed (e.g. a signature parameter); or the parameter could not be parsed (e.g., the `X-Amz-Date`
    /// parameter is not a valid date).
    ///
    /// `Incomplete trailing escape % sequence`
    MalformedQueryString(/* message */ String),

    /// The request must contain either a valid (registered) AWS access key ID or X.509 certificate. Sample messages:  
    /// `Request is missing Authentication Token`  
    MissingAuthenticationToken(/* message */ String),

    /// The request is missing a required header.
    MissingRequiredHeader(/* message */ String),

    /// Signature did not match the calculated signature value.
    /// Example messages:  
    /// `The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.`  
    /// `Signature expired: 20210502T144040Z is now earlier than 20210502T173143Z (20210502T174643Z - 15 min.)`  
    /// `Signature not yet current: 20210502T183640Z is still later than 20210502T175140Z (20210502T173640Z + 15 min.)`
    SignatureDoesNotMatch(Option</* message */ String>),
}

impl SignatureError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::DuplicateHeaderAndQueryParameter(_) => ERR_CODE_DUPLICATE_HEADER_AND_QUERY_PARAMETER,
            Self::ExpiredToken(_) => ERR_CODE_EXPIRED_TOKEN,
            Self::IO(_) | Self::InternalServiceError(_) => ERR_CODE_INTERNAL_FAILURE,
            Self::InvalidBodyEncoding(_) => ERR_CODE_INVALID_BODY_ENCODING,
            Self::InvalidClientTokenId(_) => ERR_CODE_INVALID_CLIENT_TOKEN_ID,
            Self::InvalidContentType(_) => ERR_CODE_INVALID_CONTENT_TYPE,
            Self::InvalidRequestMethod(_) => ERR_CODE_INVALID_REQUEST_METHOD,
            Self::IncompleteSignature(_) => ERR_CODE_INCOMPLETE_SIGNATURE,
            Self::InvalidURIPath(_) => ERR_CODE_INVALID_URI_PATH,
            Self::MalformedHeader(_) => ERR_CODE_MALFORMED_HEADER,
            Self::MalformedQueryString(_) => ERR_CODE_MALFORMED_QUERY_STRING,
            Self::MissingAuthenticationToken(_) => ERR_CODE_MISSING_AUTHENTICATION_TOKEN,
            Self::MissingRequiredHeader(_) => ERR_CODE_MISSING_REQUIRED_HEADER,
            Self::SignatureDoesNotMatch(_) => ERR_CODE_SIGNATURE_DOES_NOT_MATCH,
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            Self::DuplicateHeaderAndQueryParameter(_)
            | Self::IncompleteSignature(_)
            | Self::InvalidBodyEncoding(_)
            | Self::InvalidRequestMethod(_)
            | Self::InvalidURIPath(_)
            | Self::MalformedHeader(_)
            | Self::MalformedQueryString(_)
            | Self::MissingAuthenticationToken(_)
            | Self::MissingRequiredHeader(_) => StatusCode::BAD_REQUEST,
            Self::IO(_) | Self::InternalServiceError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::FORBIDDEN,
        }
    }
}

impl ServiceError for SignatureError {
    fn error_code(&self) -> &'static str {
        SignatureError::error_code(self)
    }

    fn http_status(&self) -> StatusCode {
        SignatureError::http_status(self)
    }
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::DuplicateHeaderAndQueryParameter(msg) => f.write_str(msg),
            Self::ExpiredToken(msg) => f.write_str(msg),
            Self::IO(ref e) => Display::fmt(e, f),
            Self::InternalServiceError(ref e) => Display::fmt(e, f),
            Self::InvalidBodyEncoding(msg) => f.write_str(msg),
            Self::InvalidClientTokenId(msg) => f.write_str(msg),
            Self::InvalidContentType(msg) => f.write_str(msg),
            Self::InvalidRequestMethod(msg) => f.write_str(msg),
            Self::IncompleteSignature(msg) => f.write_str(msg),
            Self::InvalidURIPath(msg) => f.write_str(msg),
            Self::MalformedHeader(msg) => f.write_str(msg),
            Self::MalformedQueryString(msg) => f.write_str(msg),
            Self::MissingAuthenticationToken(msg) => f.write_str(msg),
            Self::MissingRequiredHeader(msg) => f.write_str(msg),
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

/// Error returned by `KSecretKey::from_str` when the secret key cannot fit in the expected size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyLengthError {
    /// The key is too long.
    TooLong,
    /// The key is too short.
    TooShort,
}

impl Display for KeyLengthError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            KeyLengthError::TooLong => f.write_str(ERR_MSG_KEY_TOO_LONG),
            KeyLengthError::TooShort => f.write_str(ERR_MSG_KEY_TOO_SHORT),
        }
    }
}

impl Error for KeyLengthError {}

#[cfg(test)]
mod tests {
    use {crate::SignatureError, std::error::Error};

    #[test_log::test]
    fn test_from() {
        // This just exercises a few codepaths that aren't usually exercised.
        let utf8_error = Box::new(String::from_utf8(b"\x80".to_vec()).unwrap_err());
        let e: SignatureError = (utf8_error as Box<dyn Error + Send + Sync + 'static>).into();
        assert_eq!(e.error_code(), "InternalFailure");
        assert_eq!(e.http_status(), 500);

        let e = SignatureError::MalformedQueryString("foo".to_string());
        let e2 = SignatureError::from(Box::new(e) as Box<dyn Error + Send + Sync + 'static>);
        assert_eq!(e2.to_string(), "foo");
        assert_eq!(e2.error_code(), "MalformedQueryString");

        let e = SignatureError::InvalidContentType("Invalid content type: image/jpeg".to_string());
        assert_eq!(e.error_code(), "InvalidContentType");
        assert_eq!(e.http_status(), 403); // Should be 400, but AWS returns 403.
        assert_eq!(format!("{}", e), "Invalid content type: image/jpeg");

        let e = SignatureError::InvalidRequestMethod("Invalid request method: DELETE".to_string());
        assert_eq!(e.error_code(), "InvalidRequestMethod");
        assert_eq!(e.http_status(), 400);
        assert_eq!(format!("{}", e), "Invalid request method: DELETE");
    }
}
