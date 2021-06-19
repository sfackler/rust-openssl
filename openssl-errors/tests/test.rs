use cfg_if::cfg_if;
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
    // Replace Windows `\` separators with `/`
    assert_eq!(
        error.file().replace(r"\", "/"),
        "openssl-errors/tests/test.rs"
    );
    assert_eq!(error.line(), line!() - 11);
    cfg_if! {
        if #[cfg(ossl300)] {
            // https://github.com/openssl/openssl/issues/12530
            assert!(error.data() == None || error.data() == Some(""));
        } else {
            assert_eq!(error.data(), None);
        }
    }
}

#[test]
fn static_data() {
    openssl_errors::put_error!(Test::BAR, Test::NO_BACON, "foobar {{}}");

    let error = Error::get().unwrap();
    assert_eq!(error.library().unwrap(), "test library");
    assert_eq!(error.function().unwrap(), "function bar");
    assert_eq!(error.reason().unwrap(), "out of bacon");
    // Replace Windows `\` separators with `/`
    assert_eq!(
        error.file().replace(r"\", "/"),
        "openssl-errors/tests/test.rs"
    );
    assert_eq!(error.line(), line!() - 11);
    assert_eq!(error.data(), Some("foobar {}"));
}

#[test]
fn dynamic_data() {
    openssl_errors::put_error!(Test::BAR, Test::NO_MILK, "hello {}", "world");

    let error = Error::get().unwrap();
    assert_eq!(error.library().unwrap(), "test library");
    assert_eq!(error.function().unwrap(), "function bar");
    assert_eq!(error.reason().unwrap(), "out of milk");
    // Replace Windows `\` separators with `/`
    assert_eq!(
        error.file().replace(r"\", "/"),
        "openssl-errors/tests/test.rs"
    );
    assert_eq!(error.line(), line!() - 11);
    assert_eq!(error.data(), Some("hello world"));
}
