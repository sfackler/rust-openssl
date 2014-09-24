use std::io::Writer;
use std::io::net::tcp::TcpStream;
use std::str;

use crypto::hash::{SHA256};
use ssl::{Sslv23, SslContext, SslStream, SslVerifyPeer};
use x509::{X509Generator, X509, DigitalSignature, KeyEncipherment, ClientAuth, ServerAuth, X509StoreContext};

#[test]
fn test_new_ctx() {
    SslContext::new(Sslv23).unwrap();
}

#[test]
fn test_new_sslstream() {
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    SslStream::new(&SslContext::new(Sslv23).unwrap(), stream).unwrap();
}

#[test]
fn test_verify_untrusted() {
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, None);
    match SslStream::new(&ctx, stream) {
        Ok(_) => fail!("expected failure"),
        Err(err) => println!("error {}", err)
    }
}

#[test]
fn test_verify_trusted() {
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, None);
    match ctx.set_CA_file("test/cert.pem") {
        None => {}
        Some(err) => fail!("Unexpected error {}", err)
    }
    match SslStream::new(&ctx, stream) {
        Ok(_) => (),
        Err(err) => fail!("Expected success, got {}", err)
    }
}

#[test]
fn test_verify_untrusted_callback_override_ok() {
    fn callback(_preverify_ok: bool, _x509_ctx: &X509StoreContext) -> bool {
        true
    }
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback));
    match SslStream::new(&ctx, stream) {
        Ok(_) => (),
        Err(err) => fail!("Expected success, got {}", err)
    }
}

#[test]
fn test_verify_untrusted_callback_override_bad() {
    fn callback(_preverify_ok: bool, _x509_ctx: &X509StoreContext) -> bool {
        false
    }
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback));
    assert!(SslStream::new(&ctx, stream).is_err());
}

#[test]
fn test_verify_trusted_callback_override_ok() {
    fn callback(_preverify_ok: bool, _x509_ctx: &X509StoreContext) -> bool {
        true
    }
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback));
    match ctx.set_CA_file("test/cert.pem") {
        None => {}
        Some(err) => fail!("Unexpected error {}", err)
    }
    match SslStream::new(&ctx, stream) {
        Ok(_) => (),
        Err(err) => fail!("Expected success, got {}", err)
    }
}

#[test]
fn test_verify_trusted_callback_override_bad() {
    fn callback(_preverify_ok: bool, _x509_ctx: &X509StoreContext) -> bool {
        false
    }
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback));
    match ctx.set_CA_file("test/cert.pem") {
        None => {}
        Some(err) => fail!("Unexpected error {}", err)
    }
    assert!(SslStream::new(&ctx, stream).is_err());
}

#[test]
fn test_verify_callback_load_certs() {
    fn callback(_preverify_ok: bool, x509_ctx: &X509StoreContext) -> bool {
        assert!(x509_ctx.get_current_cert().is_some());
        true
    }
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback));
    assert!(SslStream::new(&ctx, stream).is_ok());
}

#[test]
fn test_verify_trusted_get_error_ok() {
    fn callback(_preverify_ok: bool, x509_ctx: &X509StoreContext) -> bool {
        assert!(x509_ctx.get_error().is_none());
        true
    }
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback));
    match ctx.set_CA_file("test/cert.pem") {
        None => {}
        Some(err) => fail!("Unexpected error {}", err)
    }
    assert!(SslStream::new(&ctx, stream).is_ok());
}

#[test]
fn test_verify_trusted_get_error_err() {
    fn callback(_preverify_ok: bool, x509_ctx: &X509StoreContext) -> bool {
        assert!(x509_ctx.get_error().is_some());
        false
    }
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback));
    assert!(SslStream::new(&ctx, stream).is_err());
}

#[test]
fn test_write() {
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut stream = SslStream::new(&SslContext::new(Sslv23).unwrap(), stream).unwrap();
    stream.write("hello".as_bytes()).unwrap();
    stream.flush().unwrap();
    stream.write(" there".as_bytes()).unwrap();
    stream.flush().unwrap();
}

#[test]
fn test_read() {
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut stream = SslStream::new(&SslContext::new(Sslv23).unwrap(), stream).unwrap();
    stream.write("GET /\r\n\r\n".as_bytes()).unwrap();
    stream.flush().unwrap();
    let buf = stream.read_to_end().ok().expect("read error");
    print!("{}", str::from_utf8(buf.as_slice()));
}

#[test]
fn test_cert_gen() {
    let gen = X509Generator::new()
        .set_bitlength(2048)
        .set_valid_period(365*2)
        .set_CN("test_me")
        .set_sign_hash(SHA256)
        .set_usage([DigitalSignature, KeyEncipherment])
        .set_ext_usage([ClientAuth, ServerAuth]);

    let res = gen.generate();
    assert!(res.is_ok());
    // FIXME: check data in result to be correct, needs implementation
    // of X509 getters
}
