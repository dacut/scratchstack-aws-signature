use {
    crate::constants::*,
    hmac::{Hmac, Mac},
    sha2::{Digest, Sha256},
};

/// Wrapper function to form a HMAC-SHA256 operation.
#[inline(always)]
pub(crate) fn hmac_sha256(key: &[u8], value: &[u8]) -> [u8; SHA256_OUTPUT_LEN] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take arbitrary key lengths");
    mac.update(value);
    mac.finalize().into_bytes().into()
}

#[inline(always)]
pub(crate) fn sha256(value: &[u8]) -> [u8; SHA256_OUTPUT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher.finalize().into()
}

#[inline(always)]
pub(crate) fn sha256_hex(value: &[u8]) -> String {
    hex::encode(sha256(value).as_ref())
}
