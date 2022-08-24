use ring::hmac::{sign, Key, Tag, HMAC_SHA256};

/// Wrapper function to form a HMAC-SHA256 operation using ring-0.15+.
pub fn hmac_sha256(key: &[u8], value: &[u8]) -> Tag {
    let hkey = Key::new(HMAC_SHA256, key);
    sign(&hkey, value)
}
