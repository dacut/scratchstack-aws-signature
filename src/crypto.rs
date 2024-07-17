use ring::{
    digest::{digest, Digest, SHA256},
    hmac::{sign, Key, Tag, HMAC_SHA256},
};

/// Wrapper function to form a HMAC-SHA256 operation using ring.
#[inline(always)]
pub(crate) fn hmac_sha256(key: &[u8], value: &[u8]) -> Tag {
    let hkey = Key::new(HMAC_SHA256, key);
    sign(&hkey, value)
}

#[inline(always)]
pub(crate) fn sha256(value: &[u8]) -> Digest {
    digest(&SHA256, value)
}

#[inline(always)]
pub(crate) fn sha256_hex(value: &[u8]) -> String {
    hex::encode(sha256(value).as_ref())
}
