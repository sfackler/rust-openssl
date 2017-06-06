#[macro_use]
extern crate openssl;

/// Check macro is visible outside of crate.
/// Macro correctness is checked in tests inside of crate.
#[test]
fn test() {
    let v = if_has_alpn!({ 10 } else { 20 });
    assert!(v == 10 || v == 20);
}
