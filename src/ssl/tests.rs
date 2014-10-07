use std::io::{File, Open, Write, Writer};
use std::io::net::tcp::TcpStream;
use std::num::FromStrRadix;
use std::str;

use crypto::hash::{SHA256};
use ssl::{Sslv23, SslContext, SslStream, SslVerifyPeer, SslVerifyNone};
use x509::{X509Generator, DigitalSignature, KeyEncipherment, ClientAuth, ServerAuth, X509StoreContext};

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

fn hash_str_to_vec(s: &str) -> Vec<u8> {
    let mut res = Vec::new();
    assert!(s.len() % 2 == 0, "Hash str should have len = 2 * n");
    for i in range(0, s.len() / 2) {
        let substr = s.slice(i, i + 2);
        let t: Option<u8> = FromStrRadix::from_str_radix(substr, 16);
        assert!(t.is_some(), "Hash str must contain only hex digits, i.e. [0-9a-f]");
        res.push(t.unwrap());
    }

    res
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
    let stream = TcpStream::connect("127.0.0.1", 15418).unwrap();
    let mut ctx = SslContext::new(Sslv23).unwrap();

    // Node id was generated as SHA256 hash of certificate "test/cert.pem"
    // in DER format.
    // Command: openssl x509 -in test/cert.pem  -outform DER | openssl dgst -sha256
    // Please update if "test/cert.pem" will ever change
    let node_hash_str = "6204f6617e1af7495394250655f43600cd483e2dfc2005e92d0fe439d0723c34";
    let node_id = hash_str_to_vec(node_hash_str);
    ctx.set_verify_with_data(SslVerifyNone, callback, node_id);
    ctx.set_verify_depth(1);

    match SslStream::new(&ctx, stream) {
        Ok(_) => (),
        Err(err) => fail!("Expected success, got {}", err)
    }
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

    let (cert, pkey) = res.unwrap();

    #[cfg(unix)]
    static NULL_PATH: &'static str = "/dev/null";
    #[cfg(windows)]
    static NULL_PATH: &'static str = "nul";

    let cert_path = Path::new(NULL_PATH);
    let mut file = File::open_mode(&cert_path, Open, Write).unwrap();
    assert!(cert.write_pem(&mut file).is_ok());

    let key_path = Path::new(NULL_PATH);
    let mut file = File::open_mode(&key_path, Open, Write).unwrap();
    assert!(pkey.write_pem(&mut file).is_ok());

    // FIXME: check data in result to be correct, needs implementation
    // of X509 getters
}

#[test]
fn test_bn_is_zero() {
    use ffi;
    use std::ptr;

    unsafe {
        let bn = ffi::BN_new();
        assert!(bn != ptr::null_mut());
        // Just make sure it is linked and resolved correctly
        ffi::BN_is_zero(bn);
    }
}
