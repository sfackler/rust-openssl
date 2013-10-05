extern mod ssl;

#[test]
fn test_init_works() {
    ssl::init();
}
