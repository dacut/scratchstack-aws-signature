
use ring::hmac::sign;


#[cfg(feature = "ring-014")]
use ring::hmac::{Signature,SigningKey};

#[cfg(feature = "ring-014")]
use ring::digest::SHA256;

/// Wrapper function to form a HMAC-SHA256 operation using ring-0.14.
#[cfg(feature = "ring-014")]
pub fn hmac_sha256(key: &[u8], value: &[u8]) -> Signature {
    let hkey = SigningKey::new(&SHA256, key.as_ref());
    sign(&hkey, value)
}

#[cfg(not(feature = "ring-014"))]
use ring::hmac::{HMAC_SHA256,Key,Tag};

/// Wrapper function to form a HMAC-SHA256 operation using ring-0.15+.
#[cfg(not(feature = "ring-014"))]
pub fn hmac_sha256(key: &[u8], value: &[u8]) -> Tag {
    let hkey = Key::new(HMAC_SHA256, key.as_ref());
    sign(&hkey, value)
}
