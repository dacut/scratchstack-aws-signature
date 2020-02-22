#![feature(backtrace)]

extern crate chrono;
extern crate hex;
extern crate lazy_static;
extern crate regex;
extern crate ring;

mod chronoutil;
mod signature;
pub use crate::signature::{AWSSigV4Algorithm, AWSSigV4, ErrorKind, Request, SignatureError};

#[cfg(test)]
mod unittest;
