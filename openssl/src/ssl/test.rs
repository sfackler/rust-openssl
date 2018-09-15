#![allow(unused_imports)]

use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::{self, BufReader};
use std::iter;
use std::mem;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering, ATOMIC_BOOL_INIT};
use std::thread;
use std::time::Duration;
use tempdir::TempDir;

use dh::Dh;
use hash::MessageDigest;
use ocsp::{OcspResponse, OcspResponseStatus};
use pkey::PKey;
use srtp::SrtpProfileId;
use ssl;
#[cfg(any(ossl110, ossl111, libressl261))]
use ssl::SslVersion;
use ssl::{
    Error, HandshakeError, MidHandshakeSslStream, ShutdownResult, ShutdownState, Ssl, SslAcceptor,
    SslConnector, SslContext, SslFiletype, SslMethod, SslSessionCacheMode, SslStream,
    SslVerifyMode, StatusType,
};
#[cfg(any(ossl102, ossl110))]
use x509::verify::X509CheckFlags;
use x509::{X509, X509Name, X509StoreContext, X509VerifyResult};

use std::net::UdpSocket;

static ROOT_CERT: &'static [u8] = include_bytes!("../../test/root-ca.pem");
static CERT: &'static [u8] = include_bytes!("../../test/cert.pem");
static KEY: &'static [u8] = include_bytes!("../../test/key.pem");

fn next_addr() -> SocketAddr {
    use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
    static PORT: AtomicUsize = ATOMIC_USIZE_INIT;
    let port = 15411 + PORT.fetch_add(1, Ordering::SeqCst);

    format!("127.0.0.1:{}", port).parse().unwrap()
}

struct Server {
    p: Child,
    _temp: TempDir,
}

impl Server {
    fn spawn(args: &[&str], input: Option<Box<FnMut(ChildStdin) + Send>>) -> (Server, SocketAddr) {
        let td = TempDir::new("openssl").unwrap();
        let cert = td.path().join("cert.pem");
        let key = td.path().join("key.pem");
        File::create(&cert).unwrap().write_all(CERT).unwrap();
        File::create(&key).unwrap().write_all(KEY).unwrap();

        let addr = next_addr();
        let mut child = Command::new("openssl")
            .arg("s_server")
            .arg("-accept")
            .arg(addr.port().to_string())
            .args(args)
            .arg("-cert")
            .arg(&cert)
            .arg("-key")
            .arg(&key)
            .arg("-no_dhe")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        if let Some(mut input) = input {
            thread::spawn(move || input(stdin));
        }
        (
            Server {
                p: child,
                _temp: td,
            },
            addr,
        )
    }

    fn new_tcp(args: &[&str]) -> (Server, TcpStream) {
        let (mut server, addr) = Server::spawn(args, None);
        for _ in 0..20 {
            match TcpStream::connect(&addr) {
                Ok(s) => return (server, s),
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    if let Some(exit_status) = server.p.try_wait().expect("try_wait") {
                        panic!("server exited: {}", exit_status);
                    }
                    thread::sleep(Duration::from_millis(100));
                }
                Err(e) => panic!("wut: {}", e),
            }
        }
        panic!("server never came online");
    }

    fn new() -> (Server, TcpStream) {
        Server::new_tcp(&["-www"])
    }

    #[allow(dead_code)]
    fn new_alpn() -> (Server, TcpStream) {
        Server::new_tcp(&[
            "-www",
            "-nextprotoneg",
            "http/1.1,spdy/3.1",
            "-alpn",
            "http/1.1,spdy/3.1",
        ])
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.p.kill();
        let _ = self.p.wait();
    }
}

macro_rules! run_test(
    ($module:ident, $blk:expr) => (
        #[cfg(test)]
        mod $module {
            use std::io;
            use std::io::prelude::*;
            use std::path::Path;
            use std::net::UdpSocket;
            use std::net::TcpStream;
            use ssl;
            use ssl::SslMethod;
            use ssl::{SslContext, Ssl, SslStream, SslVerifyMode, SslOptions};
            use hash::MessageDigest;
            use x509::{X509StoreContext, X509VerifyResult};
            #[cfg(any(ossl102, ossl110))]
            use x509::X509;
            #[cfg(any(ossl102, ossl110))]
            use x509::store::X509StoreBuilder;
            use hex::FromHex;
            use foreign_types::ForeignTypeRef;
            use super::Server;
            #[cfg(any(ossl102, ossl110))]
            use super::ROOT_CERT;

            #[test]
            fn sslv23() {
                let (_s, stream) = Server::new();
                $blk(SslMethod::tls(), stream);
            }
        }
    );
);

run_test!(new_ctx, |method, _| {
    SslContext::builder(method).unwrap();
});

run_test!(verify_untrusted, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);

    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => panic!("expected failure"),
        Err(err) => println!("error {:?}", err),
    }
});

run_test!(verify_trusted, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);

    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

#[cfg(any(ossl102, ossl110))]
run_test!(verify_trusted_with_set_cert, |method, stream| {
    let x509 = X509::from_pem(ROOT_CERT).unwrap();
    let mut store = X509StoreBuilder::new().unwrap();
    store.add_cert(x509).unwrap();

    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);

    match ctx.set_verify_cert_store(store.build()) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(verify_untrusted_callback_override_ok, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SslVerifyMode::PEER, |_, _| true);

    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(verify_untrusted_callback_override_bad, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SslVerifyMode::PEER, |_, _| false);

    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_err());
});

run_test!(verify_trusted_callback_override_ok, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SslVerifyMode::PEER, |_, _| true);

    match ctx.set_ca_file(&Path::new("test/cert.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(verify_trusted_callback_override_bad, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SslVerifyMode::PEER, |_, _| false);

    match ctx.set_ca_file(&Path::new("test/cert.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_err());
});

run_test!(verify_callback_load_certs, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SslVerifyMode::PEER, |_, x509_ctx| {
        assert!(x509_ctx.current_cert().is_some());
        true
    });

    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_ok());
});

run_test!(verify_trusted_get_error_ok, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SslVerifyMode::PEER, |_, x509_ctx| {
        assert!(x509_ctx.error() == X509VerifyResult::OK);
        true
    });

    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_ok());
});

run_test!(verify_trusted_get_error_err, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_verify_callback(SslVerifyMode::PEER, |_, x509_ctx| {
        assert_ne!(x509_ctx.error(), X509VerifyResult::OK);
        false
    });

    assert!(Ssl::new(&ctx.build()).unwrap().connect(stream).is_err());
});

run_test!(verify_callback_data, |method, stream| {
    let mut ctx = SslContext::builder(method).unwrap();

    // Node id was generated as SHA256 hash of certificate "test/cert.pem"
    // in DER format.
    // Command: openssl x509 -in test/cert.pem  -outform DER | openssl dgst -sha256
    // Please update if "test/cert.pem" will ever change
    let node_hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let node_id = Vec::from_hex(node_hash_str).unwrap();
    ctx.set_verify_callback(SslVerifyMode::PEER, move |_preverify_ok, x509_ctx| {
        let cert = x509_ctx.current_cert();
        match cert {
            None => false,
            Some(cert) => {
                let fingerprint = cert.digest(MessageDigest::sha1()).unwrap();
                node_id == &*fingerprint
            }
        }
    });
    ctx.set_verify_depth(1);

    match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }
});

run_test!(ssl_verify_callback, |method, stream| {
    use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

    static CHECKED: AtomicUsize = ATOMIC_USIZE_INIT;

    let ctx = SslContext::builder(method).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();

    let node_hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let node_id = Vec::from_hex(node_hash_str).unwrap();
    ssl.set_verify_callback(SslVerifyMode::PEER, move |_, x509| {
        CHECKED.store(1, Ordering::SeqCst);
        match x509.current_cert() {
            None => false,
            Some(cert) => {
                let fingerprint = cert.digest(MessageDigest::sha1()).unwrap();
                node_id == &*fingerprint
            }
        }
    });

    match ssl.connect(stream) {
        Ok(_) => (),
        Err(err) => panic!("Expected success, got {:?}", err),
    }

    assert_eq!(CHECKED.load(Ordering::SeqCst), 1);
});

// Make sure every write call translates to a write call to the underlying socket.
#[test]
fn test_write_hits_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let guard = thread::spawn(move || {
        let ctx = SslContext::builder(SslMethod::tls()).unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let mut stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();

        stream.write_all(b"hello").unwrap();
        stream
    });

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
        .unwrap();
    ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
        .unwrap();
    let stream = listener.accept().unwrap().0;
    let mut stream = Ssl::new(&ctx.build()).unwrap().accept(stream).unwrap();

    let mut buf = [0; 5];
    assert_eq!(5, stream.read(&mut buf).unwrap());
    assert_eq!(&b"hello"[..], &buf[..]);
    guard.join().unwrap();
}

#[test]
fn test_set_certificate_and_private_key() {
    let key = include_bytes!("../../test/key.pem");
    let key = PKey::private_key_from_pem(key).unwrap();
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_private_key(&key).unwrap();
    ctx.set_certificate(&cert).unwrap();

    assert!(ctx.check_private_key().is_ok());
}

run_test!(get_ctx_options, |method, _| {
    let ctx = SslContext::builder(method).unwrap();
    ctx.options();
});

run_test!(set_ctx_options, |method, _| {
    let mut ctx = SslContext::builder(method).unwrap();
    let opts = ctx.set_options(SslOptions::NO_TICKET);
    assert!(opts.contains(SslOptions::NO_TICKET));
});

run_test!(clear_ctx_options, |method, _| {
    let mut ctx = SslContext::builder(method).unwrap();
    ctx.set_options(SslOptions::ALL);
    let opts = ctx.clear_options(SslOptions::ALL);
    assert!(!opts.contains(SslOptions::ALL));
});

#[test]
fn test_write() {
    let (_s, stream) = Server::new();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();
    stream.write_all("hello".as_bytes()).unwrap();
    stream.flush().unwrap();
    stream.write_all(" there".as_bytes()).unwrap();
    stream.flush().unwrap();
}

#[test]
fn zero_length_buffers() {
    let (_s, stream) = Server::new();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();

    assert_eq!(stream.write(b"").unwrap(), 0);
    assert_eq!(stream.read(&mut []).unwrap(), 0);
}

run_test!(get_peer_certificate, |method, stream| {
    let ctx = SslContext::builder(method).unwrap();
    let stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();
    let cert = stream.ssl().peer_certificate().unwrap();
    let fingerprint = cert.digest(MessageDigest::sha1()).unwrap();
    let node_hash_str = "59172d9313e84459bcff27f967e79e6e9217e584";
    let node_id = Vec::from_hex(node_hash_str).unwrap();
    assert_eq!(node_id, &*fingerprint)
});

#[test]
fn test_read() {
    let (_s, tcp) = Server::new();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(tcp).unwrap();
    stream.write_all("GET /\r\n\r\n".as_bytes()).unwrap();
    stream.flush().unwrap();
    io::copy(&mut stream, &mut io::sink())
        .ok()
        .expect("read error");
}

#[test]
fn test_pending() {
    let (_s, tcp) = Server::new();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(tcp).unwrap();
    stream.write_all("GET /\r\n\r\n".as_bytes()).unwrap();
    stream.flush().unwrap();

    // wait for the response and read first byte...
    let mut buf = [0u8; 16 * 1024];
    stream.read(&mut buf[..1]).unwrap();

    let pending = stream.ssl().pending();
    let len = stream.read(&mut buf[1..]).unwrap();

    assert_eq!(pending, len);

    stream.read(&mut buf[..1]).unwrap();

    let pending = stream.ssl().pending();
    let len = stream.read(&mut buf[1..]).unwrap();
    assert_eq!(pending, len);
}

#[test]
fn test_state() {
    let (_s, tcp) = Server::new();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let stream = Ssl::new(&ctx.build()).unwrap().connect(tcp).unwrap();
    assert_eq!(stream.ssl().state_string(), "SSLOK ");
    assert_eq!(
        stream.ssl().state_string_long(),
        "SSL negotiation finished successfully"
    );
}

/// Tests that connecting with the client using ALPN, but the server not does not
/// break the existing connection behavior.
#[test]
#[cfg(any(ossl102, libressl261))]
fn test_connect_with_unilateral_alpn() {
    let (_s, stream) = Server::new();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    ctx.set_alpn_protos(b"\x08http/1.1\x08spdy/3.1").unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // Since the socket to which we connected is not configured to use ALPN,
    // there should be no selected protocol...
    assert!(stream.ssl().selected_alpn_protocol().is_none());
}

/// Tests that when both the client as well as the server use ALPN and their
/// lists of supported protocols have an overlap, the correct protocol is chosen.
#[test]
#[cfg(any(ossl102, libressl261))]
fn test_connect_with_alpn_successful_multiple_matching() {
    let (_s, stream) = Server::new_alpn();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    ctx.set_alpn_protos(b"\x08http/1.1\x08spdy/3.1").unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // The server prefers "http/1.1", so that is chosen, even though the client
    // would prefer "spdy/3.1"
    assert_eq!(b"http/1.1", stream.ssl().selected_alpn_protocol().unwrap());
}

/// Tests that when both the client as well as the server use ALPN and their
/// lists of supported protocols have an overlap -- with only ONE protocol
/// being valid for both.
#[test]
#[cfg(any(ossl102, libressl261))]
fn test_connect_with_alpn_successful_single_match() {
    let (_s, stream) = Server::new_alpn();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    ctx.set_alpn_protos(b"\x08spdy/3.1").unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    let stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // The client now only supports one of the server's protocols, so that one
    // is used.
    assert_eq!(b"spdy/3.1", stream.ssl().selected_alpn_protocol().unwrap());
}

/// Tests that when both the client as well as the server use SRTP and their
/// lists of supported protocols have an overlap -- with only ONE protocol
/// being valid for both.
#[test]
fn test_connect_with_srtp_ctx() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
        ctx.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")
            .unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();

        let mut buf = [0; 60];
        stream
            .ssl()
            .export_keying_material(&mut buf, "EXTRACTOR-dtls_srtp", None)
            .unwrap();

        stream.write_all(&[0]).unwrap();

        buf
    });

    let stream = TcpStream::connect(addr).unwrap();
    let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
    ctx.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")
        .unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    let mut buf = [1; 60];
    {
        let srtp_profile = stream.ssl().selected_srtp_profile().unwrap();
        assert_eq!("SRTP_AES128_CM_SHA1_80", srtp_profile.name());
        assert_eq!(SrtpProfileId::SRTP_AES128_CM_SHA1_80, srtp_profile.id());
    }
    stream
        .ssl()
        .export_keying_material(&mut buf, "EXTRACTOR-dtls_srtp", None)
        .expect("extract");

    stream.read_exact(&mut [0]).unwrap();

    let buf2 = guard.join().unwrap();

    assert_eq!(buf[..], buf2[..]);
}

/// Tests that when both the client as well as the server use SRTP and their
/// lists of supported protocols have an overlap -- with only ONE protocol
/// being valid for both.
#[test]
fn test_connect_with_srtp_ssl() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::dtls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let mut ssl = Ssl::new(&ctx.build()).unwrap();
        ssl.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")
            .unwrap();
        let mut profilenames = String::new();
        for profile in ssl.srtp_profiles().unwrap() {
            if profilenames.len() > 0 {
                profilenames.push(':');
            }
            profilenames += profile.name();
        }
        assert_eq!(
            "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32",
            profilenames
        );
        let mut stream = ssl.accept(stream).unwrap();

        let mut buf = [0; 60];
        stream
            .ssl()
            .export_keying_material(&mut buf, "EXTRACTOR-dtls_srtp", None)
            .unwrap();

        stream.write_all(&[0]).unwrap();

        buf
    });

    let stream = TcpStream::connect(addr).unwrap();
    let ctx = SslContext::builder(SslMethod::dtls()).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_tlsext_use_srtp("SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32")
        .unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    let mut buf = [1; 60];
    {
        let srtp_profile = stream.ssl().selected_srtp_profile().unwrap();
        assert_eq!("SRTP_AES128_CM_SHA1_80", srtp_profile.name());
        assert_eq!(SrtpProfileId::SRTP_AES128_CM_SHA1_80, srtp_profile.id());
    }
    stream
        .ssl()
        .export_keying_material(&mut buf, "EXTRACTOR-dtls_srtp", None)
        .expect("extract");

    stream.read_exact(&mut [0]).unwrap();

    let buf2 = guard.join().unwrap();

    assert_eq!(buf[..], buf2[..]);
}

/// Tests that when the `SslStream` is created as a server stream, the protocols
/// are correctly advertised to the client.
#[test]
#[cfg(any(ossl102, libressl261))]
fn test_alpn_server_advertise_multiple() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let localhost = listener.local_addr().unwrap();
    // We create a different context instance for the server...
    let listener_ctx = {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_alpn_select_callback(|_, client| {
            ssl::select_next_proto(b"\x08http/1.1\x08spdy/3.1", client).ok_or(ssl::AlpnError::NOACK)
        });
        assert!(
            ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
                .is_ok()
        );
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.build()
    };
    // Have the listener wait on the connection in a different thread.
    let guard = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut stream = Ssl::new(&listener_ctx).unwrap().accept(stream).unwrap();
        stream.write_all(&[0]).unwrap();
    });

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    ctx.set_alpn_protos(b"\x08spdy/3.1").unwrap();
    match ctx.set_ca_file(&Path::new("test/root-ca.pem")) {
        Ok(_) => {}
        Err(err) => panic!("Unexpected error {:?}", err),
    }
    // Now connect to the socket and make sure the protocol negotiation works...
    let stream = TcpStream::connect(localhost).unwrap();
    let mut stream = match Ssl::new(&ctx.build()).unwrap().connect(stream) {
        Ok(stream) => stream,
        Err(err) => panic!("Expected success, got {:?}", err),
    };
    // SPDY is selected since that's the only thing the client supports.
    assert_eq!(b"spdy/3.1", stream.ssl().selected_alpn_protocol().unwrap());
    let mut buf = [0];
    stream.read_exact(&mut buf).unwrap();

    guard.join().unwrap();
}

#[test]
#[cfg(any(ossl110))]
fn test_alpn_server_select_none_fatal() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let localhost = listener.local_addr().unwrap();
    // We create a different context instance for the server...
    let listener_ctx = {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_alpn_select_callback(|_, client| {
            ssl::select_next_proto(b"\x08http/1.1\x08spdy/3.1", client)
                .ok_or(ssl::AlpnError::ALERT_FATAL)
        });
        assert!(
            ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
                .is_ok()
        );
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.build()
    };
    // Have the listener wait on the connection in a different thread.
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        Ssl::new(&listener_ctx).unwrap().accept(stream).unwrap_err();
    });

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    ctx.set_alpn_protos(b"\x06http/2").unwrap();
    ctx.set_ca_file(&Path::new("test/root-ca.pem")).unwrap();
    let stream = TcpStream::connect(localhost).unwrap();
    Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap_err();
}

#[test]
#[cfg(any(ossl102, libressl261))]
fn test_alpn_server_select_none() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let localhost = listener.local_addr().unwrap();
    // We create a different context instance for the server...
    let listener_ctx = {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_alpn_select_callback(|_, client| {
            ssl::select_next_proto(b"\x08http/1.1\x08spdy/3.1", client).ok_or(ssl::AlpnError::NOACK)
        });
        assert!(
            ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
                .is_ok()
        );
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.build()
    };
    // Have the listener wait on the connection in a different thread.
    let guard = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut stream = Ssl::new(&listener_ctx).unwrap().accept(stream).unwrap();
        stream.write_all(&[0]).unwrap();
    });

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    ctx.set_alpn_protos(b"\x06http/2").unwrap();
    ctx.set_ca_file(&Path::new("test/root-ca.pem")).unwrap();
    // Now connect to the socket and make sure the protocol negotiation works...
    let stream = TcpStream::connect(localhost).unwrap();
    let mut stream = Ssl::new(&ctx.build()).unwrap().connect(stream).unwrap();

    // Since the protocols from the server and client don't overlap at all, no protocol is selected
    assert_eq!(None, stream.ssl().selected_alpn_protocol());

    let mut buf = [0];
    stream.read_exact(&mut buf).unwrap();

    guard.join().unwrap();
}

#[test]
#[should_panic(expected = "blammo")]
fn write_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("blammo");
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    let (_s, stream) = Server::new();
    let stream = ExplodingStream(stream);

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = Ssl::new(&ctx.build()).unwrap().connect(stream);
}

#[test]
#[should_panic(expected = "blammo")]
fn read_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("blammo");
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    let (_s, stream) = Server::new();
    let stream = ExplodingStream(stream);

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let _ = Ssl::new(&ctx.build()).unwrap().connect(stream);
}

#[test]
#[should_panic(expected = "blammo")]
fn flush_panic() {
    struct ExplodingStream(TcpStream);

    impl Read for ExplodingStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for ExplodingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("blammo");
        }
    }

    let (_s, stream) = Server::new();
    let stream = ExplodingStream(stream);

    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let mut stream = Ssl::new(&ctx.build())
        .unwrap()
        .connect(stream)
        .ok()
        .unwrap();
    let _ = stream.flush();
}

#[test]
fn refcount_ssl_context() {
    let mut ssl = {
        let ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ssl::Ssl::new(&ctx.build()).unwrap()
    };

    {
        let new_ctx_a = SslContext::builder(SslMethod::tls()).unwrap().build();
        let _new_ctx_b = ssl.set_ssl_context(&new_ctx_a);
    }
}

#[test]
#[cfg_attr(libressl250, ignore)]
#[cfg_attr(all(target_os = "macos", feature = "vendored"), ignore)]
fn default_verify_paths() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_default_verify_paths().unwrap();
    ctx.set_verify(SslVerifyMode::PEER);
    let ctx = ctx.build();
    let s = TcpStream::connect("google.com:443").unwrap();
    let mut ssl = Ssl::new(&ctx).unwrap();
    ssl.set_hostname("google.com").unwrap();
    let mut socket = ssl.connect(s).unwrap();

    socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut result = vec![];
    socket.read_to_end(&mut result).unwrap();

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
fn add_extra_chain_cert() {
    let cert = include_bytes!("../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.add_extra_chain_cert(cert).unwrap();
}

#[test]
#[cfg(any(ossl102, ossl110))]
#[cfg_attr(all(target_os = "macos", feature = "vendored"), ignore)]
fn verify_valid_hostname() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_default_verify_paths().unwrap();
    ctx.set_verify(SslVerifyMode::PEER);

    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.param_mut()
        .set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    ssl.param_mut().set_host("google.com").unwrap();
    ssl.set_hostname("google.com").unwrap();

    let s = TcpStream::connect("google.com:443").unwrap();
    let mut socket = ssl.connect(s).unwrap();

    socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut result = vec![];
    socket.read_to_end(&mut result).unwrap();

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
#[cfg(any(ossl102, ossl110))]
fn verify_invalid_hostname() {
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_default_verify_paths().unwrap();
    ctx.set_verify(SslVerifyMode::PEER);

    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.param_mut()
        .set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    ssl.param_mut().set_host("foobar.com").unwrap();

    let s = TcpStream::connect("google.com:443").unwrap();
    assert!(ssl.connect(s).is_err());
}

#[test]
#[cfg_attr(libressl250, ignore)]
#[cfg_attr(all(target_os = "macos", feature = "vendored"), ignore)]
fn connector_valid_hostname() {
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    let s = TcpStream::connect("google.com:443").unwrap();
    let mut socket = connector.connect("google.com", s).unwrap();

    socket.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut result = vec![];
    socket.read_to_end(&mut result).unwrap();

    println!("{}", String::from_utf8_lossy(&result));
    assert!(result.starts_with(b"HTTP/1.0"));
    assert!(result.ends_with(b"</HTML>\r\n") || result.ends_with(b"</html>"));
}

#[test]
#[cfg_attr(all(target_os = "macos", feature = "vendored"), ignore)]
fn connector_invalid_hostname() {
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    let s = TcpStream::connect("google.com:443").unwrap();
    assert!(connector.connect("foobar.com", s).is_err());
}

#[test]
#[cfg_attr(libressl250, ignore)]
#[cfg_attr(all(target_os = "macos", feature = "vendored"), ignore)]
fn connector_invalid_no_hostname_verification() {
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    let s = TcpStream::connect("google.com:443").unwrap();
    connector
        .configure()
        .unwrap()
        .verify_hostname(false)
        .connect("foobar.com", s)
        .unwrap();
}

#[test]
fn connector_no_hostname_still_verifies() {
    let (_s, tcp) = Server::new();

    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    assert!(
        connector
            .configure()
            .unwrap()
            .verify_hostname(false)
            .connect("fizzbuzz.com", tcp)
            .is_err()
    );
}

#[test]
fn connector_no_hostname_can_disable_verify() {
    let (_s, tcp) = Server::new();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_verify(SslVerifyMode::NONE);
    let connector = connector.build();

    connector
        .configure()
        .unwrap()
        .verify_hostname(false)
        .connect("foobar.com", tcp)
        .unwrap();
}

#[test]
fn connector_client_server_mozilla_intermediate() {
    let listener = TcpListener::bind("127.0.0.1:1234").unwrap();
    let port = listener.local_addr().unwrap().port();

    let t = thread::spawn(move || {
        let key = PKey::private_key_from_pem(KEY).unwrap();
        let cert = X509::from_pem(CERT).unwrap();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        let acceptor = acceptor.build();
        let stream = listener.accept().unwrap().0;
        let mut stream = acceptor.accept(stream).unwrap();

        stream.write_all(b"hello").unwrap();
    });

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    let connector = connector.build();

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut stream = connector.connect("foobar.com", stream).unwrap();

    let mut buf = [0; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(b"hello", &buf);

    t.join().unwrap();
}

#[test]
fn connector_client_server_mozilla_modern() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let t = thread::spawn(move || {
        let key = PKey::private_key_from_pem(KEY).unwrap();
        let cert = X509::from_pem(CERT).unwrap();
        let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        acceptor.set_private_key(&key).unwrap();
        acceptor.set_certificate(&cert).unwrap();
        let acceptor = acceptor.build();
        let stream = listener.accept().unwrap().0;
        let mut stream = acceptor.accept(stream).unwrap();

        stream.write_all(b"hello").unwrap();
    });

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_ca_file("test/root-ca.pem").unwrap();
    let connector = connector.build();

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut stream = connector.connect("foobar.com", stream).unwrap();

    let mut buf = [0; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(b"hello", &buf);

    t.join().unwrap();
}

#[test]
fn shutdown() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();

        stream.write_all(b"hello").unwrap();
        let mut buf = [0; 1];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
        assert_eq!(stream.shutdown().unwrap(), ShutdownResult::Received);
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    let mut buf = [0; 5];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(b"hello", &buf);

    assert_eq!(stream.get_shutdown(), ShutdownState::empty());
    assert_eq!(stream.shutdown().unwrap(), ShutdownResult::Sent);
    assert_eq!(stream.get_shutdown(), ShutdownState::SENT);
    assert_eq!(stream.shutdown().unwrap(), ShutdownResult::Received);
    assert_eq!(
        stream.get_shutdown(),
        ShutdownState::SENT | ShutdownState::RECEIVED
    );

    guard.join().unwrap();
}

#[test]
fn client_ca_list() {
    let names = X509Name::load_client_ca_file("test/root-ca.pem").unwrap();
    assert_eq!(names.len(), 1);

    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_client_ca_list(names);
}

#[test]
fn cert_store() {
    let (_s, tcp) = Server::new();

    let cert = X509::from_pem(ROOT_CERT).unwrap();

    let mut ctx = SslConnector::builder(SslMethod::tls()).unwrap();
    ctx.cert_store_mut().add_cert(cert).unwrap();
    let ctx = ctx.build();

    ctx.connect("foobar.com", tcp).unwrap();
}

#[test]
fn tmp_dh_callback() {
    static CALLED_BACK: AtomicBool = ATOMIC_BOOL_INIT;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_tmp_dh_callback(|_, _, _| {
            CALLED_BACK.store(true, Ordering::SeqCst);
            let dh = include_bytes!("../../test/dhparams.pem");
            Dh::params_from_pem(dh)
        });
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();
        stream.write_all(&[0]).unwrap();
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    // TLS 1.3 has no DH suites, so make sure we don't pick that version
    #[cfg(ossl111)]
    ctx.set_options(super::SslOptions::NO_TLSV1_3);
    ctx.set_cipher_list("EDH").unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    stream.read_exact(&mut [0]).unwrap();

    assert!(CALLED_BACK.load(Ordering::SeqCst));

    guard.join().unwrap();
}

#[test]
#[cfg(all(ossl101, not(ossl110)))]
fn tmp_ecdh_callback() {
    use ec::EcKey;
    use nid::Nid;

    static CALLED_BACK: AtomicBool = ATOMIC_BOOL_INIT;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_tmp_ecdh_callback(|_, _, _| {
            CALLED_BACK.store(true, Ordering::SeqCst);
            EcKey::from_curve_name(Nid::X9_62_PRIME256V1)
        });
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();
        stream.write_all(&[0]).unwrap();
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_cipher_list("ECDH").unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();
    stream.read_exact(&mut [0]).unwrap();

    assert!(CALLED_BACK.load(Ordering::SeqCst));

    guard.join().unwrap();
}

#[test]
fn tmp_dh_callback_ssl() {
    static CALLED_BACK: AtomicBool = ATOMIC_BOOL_INIT;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let mut ssl = Ssl::new(&ctx.build()).unwrap();
        ssl.set_tmp_dh_callback(|_, _, _| {
            CALLED_BACK.store(true, Ordering::SeqCst);
            let dh = include_bytes!("../../test/dhparams.pem");
            Dh::params_from_pem(dh)
        });
        let mut stream = ssl.accept(stream).unwrap();
        stream.write_all(&[0]).unwrap();
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    // TLS 1.3 has no DH suites, so make sure we don't pick that version
    #[cfg(ossl111)]
    ctx.set_options(super::SslOptions::NO_TLSV1_3);
    ctx.set_cipher_list("EDH").unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();
    stream.read_exact(&mut [0]).unwrap();

    assert!(CALLED_BACK.load(Ordering::SeqCst));

    guard.join().unwrap();
}

#[test]
#[cfg(all(ossl101, not(ossl110)))]
fn tmp_ecdh_callback_ssl() {
    use ec::EcKey;
    use nid::Nid;

    static CALLED_BACK: AtomicBool = ATOMIC_BOOL_INIT;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let mut ssl = Ssl::new(&ctx.build()).unwrap();
        ssl.set_tmp_ecdh_callback(|_, _, _| {
            CALLED_BACK.store(true, Ordering::SeqCst);
            EcKey::from_curve_name(Nid::X9_62_PRIME256V1)
        });
        let mut stream = ssl.accept(stream).unwrap();
        stream.write_all(&[0]).unwrap();
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_cipher_list("ECDH").unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();
    stream.read_exact(&mut [0]).unwrap();

    assert!(CALLED_BACK.load(Ordering::SeqCst));

    guard.join().unwrap();
}

#[test]
fn idle_session() {
    let ctx = SslContext::builder(SslMethod::tls()).unwrap().build();
    let ssl = Ssl::new(&ctx).unwrap();
    assert!(ssl.session().is_none());
}

#[test]
#[cfg_attr(libressl250, ignore)]
#[cfg_attr(all(target_os = "macos", feature = "vendored"), ignore)]
fn active_session() {
    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    let s = TcpStream::connect("google.com:443").unwrap();
    let socket = connector.connect("google.com", s).unwrap();
    let session = socket.ssl().session().unwrap();
    let len = session.master_key_len();
    let mut buf = vec![0; len - 1];
    let copied = session.master_key(&mut buf);
    assert_eq!(copied, buf.len());
    let mut buf = vec![0; len + 1];
    let copied = session.master_key(&mut buf);
    assert_eq!(copied, len);
}

#[test]
fn status_callbacks() {
    static CALLED_BACK_SERVER: AtomicBool = ATOMIC_BOOL_INIT;
    static CALLED_BACK_CLIENT: AtomicBool = ATOMIC_BOOL_INIT;

    let listener = TcpListener::bind("127.0.0.1:12345").unwrap();
    let port = listener.local_addr().unwrap().port();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_status_callback(|ssl| {
            CALLED_BACK_SERVER.store(true, Ordering::SeqCst);
            let response = OcspResponse::create(OcspResponseStatus::UNAUTHORIZED, None).unwrap();
            let response = response.to_der().unwrap();
            ssl.set_ocsp_status(&response).unwrap();
            Ok(true)
        }).unwrap();
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();
        stream.write_all(&[0]).unwrap();
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_status_callback(|ssl| {
        CALLED_BACK_CLIENT.store(true, Ordering::SeqCst);
        let response = OcspResponse::from_der(ssl.ocsp_status().unwrap()).unwrap();
        assert_eq!(response.status(), OcspResponseStatus::UNAUTHORIZED);
        Ok(true)
    }).unwrap();
    let mut ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.set_status_type(StatusType::OCSP).unwrap();
    let mut stream = ssl.connect(stream).unwrap();
    let mut buf = [0];
    stream.read_exact(&mut buf).unwrap();

    assert!(CALLED_BACK_SERVER.load(Ordering::SeqCst));
    assert!(CALLED_BACK_CLIENT.load(Ordering::SeqCst));

    guard.join().unwrap();
}

#[test]
fn new_session_callback() {
    static CALLED_BACK: AtomicBool = ATOMIC_BOOL_INIT;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_session_id_context(b"foo").unwrap();
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();
        stream.write_all(&[0]).unwrap();
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
    ctx.set_new_session_callback(|_, _| CALLED_BACK.store(true, Ordering::SeqCst));
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();
    stream.read_exact(&mut [0]).unwrap();

    assert!(CALLED_BACK.load(Ordering::SeqCst));

    guard.join().unwrap();
}

#[test]
fn keying_export() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let label = "EXPERIMENTAL test";
    let context = b"my context";

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();

        let mut buf = [0; 32];
        stream
            .ssl()
            .export_keying_material(&mut buf, label, Some(context))
            .unwrap();

        stream.write_all(&[0]).unwrap();

        buf
    });

    let stream = TcpStream::connect(addr).unwrap();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();

    let mut buf = [1; 32];
    stream
        .ssl()
        .export_keying_material(&mut buf, label, Some(context))
        .unwrap();

    stream.read_exact(&mut [0]).unwrap();

    let buf2 = guard.join().unwrap();

    assert_eq!(buf, buf2);
}

#[test]
#[cfg(any(ossl110, libressl261))]
fn no_version_overlap() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_max_proto_version(Some(SslVersion::TLS1_1)).unwrap();
        #[cfg(ossl110g)]
        assert_eq!(ctx.min_proto_version(), None);
        #[cfg(any(ossl110g, libressl270))]
        assert_eq!(ctx.max_proto_version(), Some(SslVersion::TLS1_1));
        let ssl = Ssl::new(&ctx.build()).unwrap();
        ssl.accept(stream).unwrap_err();
    });

    let stream = TcpStream::connect(addr).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.set_min_proto_version(Some(SslVersion::TLS1_2)).unwrap();
    #[cfg(any(ossl110g, libressl270))]
    assert_eq!(ctx.min_proto_version(), Some(SslVersion::TLS1_2));
    #[cfg(ossl110g)]
    assert_eq!(ctx.max_proto_version(), None);
    let ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.connect(stream).unwrap_err();

    guard.join().unwrap();
}

#[test]
#[cfg(ossl111)]
fn custom_extensions() {
    static FOUND_EXTENSION: AtomicBool = ATOMIC_BOOL_INIT;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.add_custom_ext(
            12345,
            ssl::ExtensionContext::CLIENT_HELLO,
            |_, _, _| -> Result<Option<&'static [u8]>, _> { unreachable!() },
            |_, _, data, _| {
                FOUND_EXTENSION.store(data == b"hello", Ordering::SeqCst);
                Ok(())
            },
        ).unwrap();
        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();
        stream.write_all(&[0]).unwrap();
    });

    let stream = TcpStream::connect(addr).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    ctx.add_custom_ext(
        12345,
        ssl::ExtensionContext::CLIENT_HELLO,
        |_, _, _| Ok(Some(b"hello")),
        |_, _, _, _| unreachable!(),
    ).unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();
    let mut stream = ssl.connect(stream).unwrap();
    stream.read_exact(&mut [0]).unwrap();

    guard.join().unwrap();
    assert!(FOUND_EXTENSION.load(Ordering::SeqCst));
}

fn _check_kinds() {
    fn is_send<T: Send>() {}
    fn is_sync<T: Sync>() {}

    is_send::<SslStream<TcpStream>>();
    is_sync::<SslStream<TcpStream>>();
}

#[test]
#[cfg(ossl111)]
fn stateless() {
    use super::SslOptions;

    #[derive(Debug)]
    struct MemoryStream {
        incoming: io::Cursor<Vec<u8>>,
        outgoing: Vec<u8>,
    }

    impl MemoryStream {
        pub fn new() -> Self {
            Self {
                incoming: io::Cursor::new(Vec::new()),
                outgoing: Vec::new(),
            }
        }

        pub fn extend_incoming(&mut self, data: &[u8]) {
            self.incoming.get_mut().extend_from_slice(data);
        }

        pub fn take_outgoing(&mut self) -> Outgoing {
            Outgoing(&mut self.outgoing)
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.incoming.read(buf)?;
            if self.incoming.position() == self.incoming.get_ref().len() as u64 {
                self.incoming.set_position(0);
                self.incoming.get_mut().clear();
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no data available",
                ));
            }
            Ok(n)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.outgoing.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub struct Outgoing<'a>(&'a mut Vec<u8>);

    impl<'a> Drop for Outgoing<'a> {
        fn drop(&mut self) {
            self.0.clear();
        }
    }

    impl<'a> ::std::ops::Deref for Outgoing<'a> {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.0
        }
    }

    impl<'a> AsRef<[u8]> for Outgoing<'a> {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    fn send(from: &mut MemoryStream, to: &mut MemoryStream) {
        to.extend_incoming(&from.take_outgoing());
    }

    fn hs<S: ::std::fmt::Debug>(
        stream: Result<SslStream<S>, HandshakeError<S>>,
    ) -> Result<SslStream<S>, MidHandshakeSslStream<S>> {
        match stream {
            Ok(stream) => Ok(stream),
            Err(HandshakeError::WouldBlock(stream)) => Err(stream),
            Err(e) => panic!("unexpected error: {:?}", e),
        }
    }

    //
    // Setup
    //

    let mut client_ctx = SslContext::builder(SslMethod::tls()).unwrap();
    client_ctx.clear_options(SslOptions::ENABLE_MIDDLEBOX_COMPAT);
    let client_stream = Ssl::new(&client_ctx.build()).unwrap();

    let mut server_ctx = SslContext::builder(SslMethod::tls()).unwrap();
    server_ctx
        .set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
        .unwrap();
    server_ctx
        .set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
        .unwrap();
    const COOKIE: &[u8] = b"chocolate chip";
    server_ctx.set_stateless_cookie_generate_cb(|_tls, buf| {
        buf[0..COOKIE.len()].copy_from_slice(COOKIE);
        Ok(COOKIE.len())
    });
    server_ctx.set_stateless_cookie_verify_cb(|_tls, buf| buf == COOKIE);
    let mut server_stream =
        ssl::SslStreamBuilder::new(Ssl::new(&server_ctx.build()).unwrap(), MemoryStream::new());

    //
    // Handshake
    //

    // Initial ClientHello
    let mut client_stream = hs(client_stream.connect(MemoryStream::new())).unwrap_err();
    send(client_stream.get_mut(), server_stream.get_mut());
    // HelloRetryRequest
    assert!(!server_stream.stateless().unwrap());
    send(server_stream.get_mut(), client_stream.get_mut());
    // Second ClientHello
    let mut client_stream = hs(client_stream.handshake()).unwrap_err();
    send(client_stream.get_mut(), server_stream.get_mut());
    // ServerHello
    assert!(server_stream.stateless().unwrap());
    let mut server_stream = hs(server_stream.accept()).unwrap_err();
    send(server_stream.get_mut(), client_stream.get_mut());
    // Finished
    let mut client_stream = hs(client_stream.handshake()).unwrap();
    send(client_stream.get_mut(), server_stream.get_mut());
    hs(server_stream.handshake()).unwrap();
}

#[cfg(not(osslconf = "OPENSSL_NO_PSK"))]
#[test]
fn psk_ciphers() {
    const CIPHER: &'static str = "PSK-AES128-CBC-SHA";
    const PSK: &[u8] = b"thisisaverysecurekey";
    const CLIENT_IDENT: &[u8] = b"thisisaclient";
    static CLIENT_CALLED: AtomicBool = ATOMIC_BOOL_INIT;
    static SERVER_CALLED: AtomicBool = ATOMIC_BOOL_INIT;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_cipher_list(CIPHER).unwrap();
        ctx.set_psk_server_callback(move |_, identity, psk| {
            assert!(identity.unwrap_or(&[]) == CLIENT_IDENT);
            psk[..PSK.len()].copy_from_slice(&PSK);
            SERVER_CALLED.store(true, Ordering::SeqCst);
            Ok(PSK.len())
        });
        let ssl = Ssl::new(&ctx.build()).unwrap();
        ssl.accept(stream).unwrap();
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
    // TLS 1.3 has no DH suites, and openssl isn't happy if the max version has no suites :(
    #[cfg(ossl111)]
    {
        ctx.set_options(super::SslOptions {
            bits: ::ffi::SSL_OP_NO_TLSv1_3,
        });
    }
    ctx.set_cipher_list(CIPHER).unwrap();
    ctx.set_psk_client_callback(move |_, _, identity, psk| {
        identity[..CLIENT_IDENT.len()].copy_from_slice(&CLIENT_IDENT);
        identity[CLIENT_IDENT.len()] = 0;
        psk[..PSK.len()].copy_from_slice(&PSK);
        CLIENT_CALLED.store(true, Ordering::SeqCst);
        Ok(PSK.len())
    });
    let ssl = Ssl::new(&ctx.build()).unwrap();
    ssl.connect(stream).unwrap();

    assert!(CLIENT_CALLED.load(Ordering::SeqCst) && SERVER_CALLED.load(Ordering::SeqCst));
}

#[test]
fn sni_callback_swapped_ctx() {
    static CALLED_BACK: AtomicBool = ATOMIC_BOOL_INIT;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_servername_callback(|_, _| {
            CALLED_BACK.store(true, Ordering::SeqCst);
            Ok(())
        });
        let mut ssl = Ssl::new(&ctx.build()).unwrap();

        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ssl.set_ssl_context(&ctx.build()).unwrap();

        let mut stream = ssl.accept(stream).unwrap();
        stream.write_all(&[0]).unwrap();
    });

    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();

    let mut stream = ssl.connect(stream).unwrap();
    stream.read_exact(&mut [0]).unwrap();

    assert!(CALLED_BACK.load(Ordering::SeqCst));

    guard.join().unwrap();
}

#[test]
#[cfg(ossl111)]
fn client_hello() {
    use ssl::ClientHelloResponse;

    static CALLED_BACK: AtomicBool = ATOMIC_BOOL_INIT;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let guard = thread::spawn(move || {
        let stream = listener.accept().unwrap().0;
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_certificate_file(&Path::new("test/cert.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_private_key_file(&Path::new("test/key.pem"), SslFiletype::PEM)
            .unwrap();
        ctx.set_client_hello_callback(|ssl, _| {
            assert!(!ssl.client_hello_isv2());
            assert_eq!(ssl.client_hello_legacy_version(), Some(SslVersion::TLS1_2));
            assert!(ssl.client_hello_random().is_some());
            assert!(ssl.client_hello_session_id().is_some());
            assert!(ssl.client_hello_ciphers().is_some());
            assert!(ssl.client_hello_compression_methods().is_some());

            CALLED_BACK.store(true, Ordering::SeqCst);
            Ok(ClientHelloResponse::SUCCESS)
        });

        let ssl = Ssl::new(&ctx.build()).unwrap();
        let mut stream = ssl.accept(stream).unwrap();
        stream.write_all(&mut [0]).unwrap();
    });

    let stream = TcpStream::connect(addr).unwrap();
    let ctx = SslContext::builder(SslMethod::tls()).unwrap();
    let ssl = Ssl::new(&ctx.build()).unwrap();

    let mut stream = ssl.connect(stream).unwrap();
    stream.read_exact(&mut [0]).unwrap();

    assert!(CALLED_BACK.load(Ordering::SeqCst));

    guard.join().unwrap();
}
