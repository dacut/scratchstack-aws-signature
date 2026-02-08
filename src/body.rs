//! HTTP request body handling utilities.
use {bytes::Bytes, std::future::Future, tower::BoxError};

/// A trait for converting various body types into a [`Bytes`] object.
///
/// This requires reading the entire body into memory.
pub trait IntoRequestBytes {
    /// Convert this object into a [`Bytes`] object.
    fn into_request_bytes(self) -> impl Future<Output = Result<Bytes, BoxError>> + Send + Sync;
}

/// Convert the unit type `()` into an empty [`Bytes`] object.
impl IntoRequestBytes for () {
    /// Convert the unit type `()` into an empty [`Bytes`] object.
    ///
    /// This is infalliable.
    async fn into_request_bytes(self) -> Result<Bytes, BoxError> {
        Ok(Bytes::new())
    }
}

/// Convert a `Vec<u8>` into a [`Bytes`] object.
impl IntoRequestBytes for Vec<u8> {
    /// Convert a `Vec<u8>` into a [`Bytes`] object.
    ///
    /// This is infalliable.
    async fn into_request_bytes(self) -> Result<Bytes, BoxError> {
        Ok(Bytes::from(self))
    }
}

/// Identity transformation: return the [`Bytes`] object as-is.
impl IntoRequestBytes for Bytes {
    /// Identity transformation: return the [`Bytes`] object as-is.
    ///
    /// This is infalliable.
    async fn into_request_bytes(self) -> Result<Bytes, BoxError> {
        Ok(self)
    }
}
