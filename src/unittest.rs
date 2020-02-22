use super::signature::{
    canonicalize_uri_path, normalize_query_parameters, ErrorKind,
};

macro_rules! expect_err {
    ($test:expr, $expected:pat) => {
        match $test {
            Ok(e) => panic!(format!(
                "Expected Err({}); got Ok({:?})",
                stringify!($expected),
                e
            )),
            Err(e) => match e.kind {
                $expected => (),
                _ => panic!(format!(
                    "Expected ErrorKind::{:?}; got ErrorKind::{:?}",
                    stringify!($expected),
                    e.kind
                )),
            },
        }
    };
}

#[test]
fn canonicalize_uri_path_empty() {
    assert_eq!(canonicalize_uri_path(&"").unwrap(), "/".to_string());
    assert_eq!(canonicalize_uri_path(&"/").unwrap(), "/".to_string());
}

#[test]
fn canonicalize_valid() {
    assert_eq!(
        canonicalize_uri_path(&"/hello/world").unwrap(),
        "/hello/world".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello///world").unwrap(),
        "/hello/world".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/./world").unwrap(),
        "/hello/world".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/foo/../world").unwrap(),
        "/hello/world".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/%77%6F%72%6C%64").unwrap(),
        "/hello/world".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/w*rld").unwrap(),
        "/hello/w%2Arld".to_string()
    );
    assert_eq!(
        canonicalize_uri_path(&"/hello/w%2arld").unwrap(),
        "/hello/w%2Arld".to_string()
    );
}

#[test]
fn canonicalize_invalid() {
    expect_err!(
        canonicalize_uri_path(&"hello/world"),
        ErrorKind::InvalidURIPath
    );
    expect_err!(
        canonicalize_uri_path(&"/hello/../../world"),
        ErrorKind::InvalidURIPath
    );
}

#[test]
fn normalize_valid1() {
    let result =
        normalize_query_parameters("Hello=World&foo=bar&baz=bomb&foo=2");
    let v = result.unwrap();
    let hello = v.get("Hello").unwrap();
    assert_eq!(hello.len(), 1);
    assert_eq!(hello[0], "World");

    let foo = v.get("foo").unwrap();
    assert_eq!(foo.len(), 2);
    assert_eq!(foo[0], "bar");
    assert_eq!(foo[1], "2");

    let baz = v.get("baz").unwrap();
    assert_eq!(baz.len(), 1);
    assert_eq!(baz[0], "bomb");
}

#[test]
fn normalize_empty() {
    let result = normalize_query_parameters("Hello=World&&foo=bar");
    let v = result.unwrap();
    let hello = v.get("Hello").unwrap();

    assert_eq!(hello.len(), 1);
    assert_eq!(hello[0], "World");

    let foo = v.get("foo").unwrap();
    assert_eq!(foo.len(), 1);
    assert_eq!(foo[0], "bar");

    assert!(v.get("").is_none());
}
