extern mod ssl;

use ssl::{Sslv23, SslCtx};

#[test]
fn test_new_ctx() {
    SslCtx::new(Sslv23);
}
