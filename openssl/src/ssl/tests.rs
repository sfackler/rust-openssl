use serialize::hex::FromHex;
use std::old_io::net::tcp::TcpStream;
use std::old_io::{Writer};
use std::thread;

use crypto::hash::Type::{SHA256};
use ssl::SslMethod::Sslv23;
use ssl::{SslContext, SslStream, VerifyCallback};
use ssl::SslVerifyMode::SslVerifyPeer;
use x509::{X509StoreContext};

#[test]
fn test_new_ctx() {
    SslContext::new(Sslv23).unwrap();
}

#[test]
fn test_new_sslstream() {
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    SslStream::new(&SslContext::new(Sslv23).unwrap(), stream).unwrap();
}

#[test]
fn test_verify_untrusted() {
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, None);
    match SslStream::new(&ctx, stream) {
        Ok(_) => panic!("expected failure"),
        Err(err) => println!("error {:?}", err)
    }
}

#[test]
fn test_verify_trusted() {
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, None);
    match ctx.set_CA_file(&Path::new("test/cert.pem")) {
        None => {}
        Some(err) => panic!("Unexpected error {:?}", err)
    }
    match SslStream::new(&ctx, stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err)
    }
}

#[test]
fn test_verify_untrusted_callback_override_ok() {
    fn callback(_preverify_ok: bool, _x509_ctx: &X509StoreContext) -> bool {
        true
    }
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback as VerifyCallback));
    match SslStream::new(&ctx, stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err)
    }
}

#[test]
fn test_verify_untrusted_callback_override_bad() {
    fn callback(_preverify_ok: bool, _x509_ctx: &X509StoreContext) -> bool {
        false
    }
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback as VerifyCallback));
    assert!(SslStream::new(&ctx, stream).is_err());
}

#[test]
fn test_verify_trusted_callback_override_ok() {
    fn callback(_preverify_ok: bool, _x509_ctx: &X509StoreContext) -> bool {
        true
    }
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback as VerifyCallback));
    match ctx.set_CA_file(&Path::new("test/cert.pem")) {
        None => {}
        Some(err) => panic!("Unexpected error {:?}", err)
    }
    match SslStream::new(&ctx, stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err)
    }
}

#[test]
fn test_verify_trusted_callback_override_bad() {
    fn callback(_preverify_ok: bool, _x509_ctx: &X509StoreContext) -> bool {
        false
    }
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback as VerifyCallback));
    match ctx.set_CA_file(&Path::new("test/cert.pem")) {
        None => {}
        Some(err) => panic!("Unexpected error {:?}", err)
    }
    assert!(SslStream::new(&ctx, stream).is_err());
}

#[test]
fn test_verify_callback_load_certs() {
    fn callback(_preverify_ok: bool, x509_ctx: &X509StoreContext) -> bool {
        assert!(x509_ctx.get_current_cert().is_some());
        true
    }
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback as VerifyCallback));
    assert!(SslStream::new(&ctx, stream).is_ok());
}

#[test]
fn test_verify_trusted_get_error_ok() {
    fn callback(_preverify_ok: bool, x509_ctx: &X509StoreContext) -> bool {
        assert!(x509_ctx.get_error().is_none());
        true
    }
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback as VerifyCallback));
    match ctx.set_CA_file(&Path::new("test/cert.pem")) {
        None => {}
        Some(err) => panic!("Unexpected error {:?}", err)
    }
    assert!(SslStream::new(&ctx, stream).is_ok());
}

#[test]
fn test_verify_trusted_get_error_err() {
    fn callback(_preverify_ok: bool, x509_ctx: &X509StoreContext) -> bool {
        assert!(x509_ctx.get_error().is_some());
        false
    }
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.set_verify(SslVerifyPeer, Some(callback as VerifyCallback));
    assert!(SslStream::new(&ctx, stream).is_err());
}

#[test]
fn test_verify_callback_data() {
    fn callback(_preverify_ok: bool, x509_ctx: &X509StoreContext, node_id: &Vec<u8>) -> bool {
        let cert = x509_ctx.get_current_cert();
        match cert {
            None => false,
            Some(cert) => {
                let fingerprint = cert.fingerprint(SHA256).unwrap();
                fingerprint.as_slice() == node_id.as_slice()
            }
        }
    }
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();

    // Node id was generated as SHA256 hash of certificate "test/cert.pem"
    // in DER format.
    // Command: openssl x509 -in test/cert.pem  -outform DER | openssl dgst -sha256
    // Please update if "test/cert.pem" will ever change
    let node_hash_str = "46e3f1a6d17a41ce70d0c66ef51cee2ab4ba67cac8940e23f10c1f944b49fb5c";
    let node_id = node_hash_str.from_hex().unwrap();
    ctx.set_verify_with_data(SslVerifyPeer, callback, node_id);
    ctx.set_verify_depth(1);

    match SslStream::new(&ctx, stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err)
    }
}

#[test]
fn test_get_ctx_options() {
    let mut ctx = SslContext::new(Sslv23).unwrap();
    ctx.get_options();
}

#[test]
fn test_set_ctx_options() {
    let mut ctx = SslContext::new(Sslv23).unwrap();
    let start_opts = ctx.get_options();
    let ssl_op_no_sslv3 = 0x02000000;
    let res = ctx.set_options(ssl_op_no_sslv3);
    assert_eq!(res, start_opts | ssl_op_no_sslv3);
}

#[test]
fn test_write() {
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut stream = SslStream::new(&SslContext::new(Sslv23).unwrap(), stream).unwrap();
    stream.write_all("hello".as_bytes()).unwrap();
    stream.flush().unwrap();
    stream.write_all(" there".as_bytes()).unwrap();
    stream.flush().unwrap();
}

#[test]
fn test_read() {
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut stream = SslStream::new(&SslContext::new(Sslv23).unwrap(), stream).unwrap();
    stream.write_all("GET /\r\n\r\n".as_bytes()).unwrap();
    stream.flush().unwrap();
    stream.read_to_end().ok().expect("read error");
}

#[test]
fn test_clone() {
    let stream = TcpStream::connect("127.0.0.1:15418").unwrap();
    let mut stream = SslStream::new(&SslContext::new(Sslv23).unwrap(), stream).unwrap();
    let mut stream2 = stream.clone();
    let _t = thread::spawn(move || {
        stream2.write_all("GET /\r\n\r\n".as_bytes()).unwrap();
        stream2.flush().unwrap();
    });
    stream.read_to_end().ok().expect("read error");
}
