/// Macro which expands to one or another expression depending
/// on whether rust-openssl is compiled with ALPN support.
#[cfg(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110)))]
#[macro_export]
macro_rules! if_has_alpn {
    ($th:block else $el:block) => (
        $th
    );
    ($th:block) => (
        $th
    );
}

/// Macro which expands to one or another expression depending
/// on whether rust-openssl is compiled with ALPN support.
#[macro_export]
#[cfg(not(any(all(feature = "v102", ossl102), all(feature = "v110", ossl110))))]
macro_rules! if_has_alpn {
    ($th:block else $el:block) => (
        $el
    );
    ($th:block) => (
    );
}
