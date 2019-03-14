use openssl::error::Error;

openssl_errors::openssl_errors! {
    library Test("test library") {
        functions {
            FOO("function foo");
            BAR("function bar");
        }

        reasons {
            NO_MILK("out of milk");
            NO_BACON("out of bacon");
        }
    }
}

#[test]
fn basic() {
    openssl_errors::put_error!(Test::FOO, Test::NO_MILK);

    let error = Error::get().unwrap();
    assert_eq!(error.library().unwrap(), "test library");
    assert_eq!(error.function().unwrap(), "function foo");
    assert_eq!(error.reason().unwrap(), "out of milk");
    assert_eq!(error.file(), "openssl-errors/tests/test.rs");
    assert_eq!(error.line(), 19);
    assert_eq!(error.data(), None);
}

#[test]
fn static_data() {
    openssl_errors::put_error!(Test::BAR, Test::NO_BACON, "foobar");

    let error = Error::get().unwrap();
    assert_eq!(error.library().unwrap(), "test library");
    assert_eq!(error.function().unwrap(), "function bar");
    assert_eq!(error.reason().unwrap(), "out of bacon");
    assert_eq!(error.file(), "openssl-errors/tests/test.rs");
    assert_eq!(error.line(), 32);
    assert_eq!(error.data(), Some("foobar"));
}

#[test]
fn dynamic_data() {
    openssl_errors::put_error!(Test::BAR, Test::NO_MILK, "hello {}", "world");

    let error = Error::get().unwrap();
    assert_eq!(error.library().unwrap(), "test library");
    assert_eq!(error.function().unwrap(), "function bar");
    assert_eq!(error.reason().unwrap(), "out of milk");
    assert_eq!(error.file(), "openssl-errors/tests/test.rs");
    assert_eq!(error.line(), 45);
    assert_eq!(error.data(), Some("hello world"));
}
